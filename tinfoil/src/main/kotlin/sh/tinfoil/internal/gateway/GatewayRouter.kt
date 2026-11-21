@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil.internal.gateway

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.HttpUrl
import okhttp3.Request
import okhttp3.MediaType
import okhttp3.Response
import okhttp3.ResponseBody
import okio.Buffer
import okio.BufferedSource
import okio.ForwardingSource
import okio.buffer
import sh.tinfoil.AttestationException
import sh.tinfoil.Catalog
import sh.tinfoil.ConfigurationException
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.ModelPin
import sh.tinfoil.Policy
import sh.tinfoil.NetworkException
import sh.tinfoil.Pin
import sh.tinfoil.RecoverableResponse
import sh.tinfoil.ReplicaVerification
import sh.tinfoil.TinfoilException
import sh.tinfoil.Transport
import sh.tinfoil.Verification
import sh.tinfoil.VerificationCheck
import sh.tinfoil.internal.Background
import sh.tinfoil.internal.EnclaveConnection
import sh.tinfoil.internal.Internals
import sh.tinfoil.internal.requireNotEmpty
import sh.tinfoil.internal.transport.AttestedSender
import sh.tinfoil.internal.transport.EhbpSealing
import sh.tinfoil.internal.transport.Origin
import sh.tinfoil.internal.transport.RecoverableCall
import sh.tinfoil.internal.transport.SettledBody
import sh.tinfoil.internal.transport.Urls
import sh.tinfoil.internal.transport.UserCacheSecret
import sh.tinfoil.internal.transport.closeQuietly
import sh.tinfoil.internal.verification.AttestationFetcher
import sh.tinfoil.internal.verification.AttestationVerifier
import sh.tinfoil.internal.verification.VerifierInputs
import sh.tinfoil.internal.verification.VerifierOptions
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.coroutineContext

/**
 * Which models a gateway client serves, and what the replicas of each are
 * verified against.
 *
 * The constructor checks the pins, and throws a [ConfigurationException] for
 * any that no verification could succeed with. It performs no I/O.
 */
internal class GatewayPolicy(
    pins: Map<String, ModelPin>,
    private val pinnedOnly: Boolean,
    /** The policy for the models that are not pinned, and for the pins that have none of their own. */
    policy: Policy,
    /** What builds a verifier from a config trust and a policy. */
    newVerifier: (VerifierOptions.ConfigTrust?, VerifierOptions.Policy) -> AttestationVerifier,
) {
    private class Pinned(val repo: String, val verifier: AttestationVerifier)

    /** The verifier for the models that are not pinned, and for the pins that have no policy of their own. */
    private val verifier: AttestationVerifier = newVerifier(null, VerifierInputs.policy(policy))

    private val pins: Map<String, Pinned>

    init {
        if (pinnedOnly && pins.isEmpty()) {
            throw ConfigurationException("pinned-only mode requires at least one model pin")
        }
        val checked = HashMap<String, Pinned>()
        for ((model, pin) in pins) {
            if (model.isBlank() || !pin.repo.startsWith(GatewayCatalog.TRUSTED_OWNER)) {
                throw ConfigurationException(
                    "model pin ${quote(model)} repository ${quote(pin.repo)} must belong to ${GatewayCatalog.TRUSTED_OWNER}",
                )
            }
            val verifier = try {
                val own = pin.policy?.let { newVerifier(null, VerifierInputs.policy(it)) } ?: verifier
                own.checkPinVerifiability(pinOf(pin.repo))
                own
            } catch (e: TinfoilException) {
                throw ConfigurationException("model ${quote(model)}: ${e.detail}")
            }
            checked[model] = Pinned(pin.repo, verifier)
        }
        this.pins = checked
    }

    /** Where a model's replicas are, and what they are verified as. */
    class Route(val hosts: List<String>, private val reference: String, private val pinnedModel: String?) {
        fun on(host: String): ReplicaKey = ReplicaKey(host, reference, pinnedModel)
    }

    /**
     * The replicas of [model] in [catalog], and what they are to be verified
     * against.
     *
     * A pinned model is verified against its pin, and the catalog must name
     * the pin's repository for it. Any other model is verified against the
     * repository that the catalog names, which [GatewayCatalog.isTrusted]
     * holds to a repository of Tinfoil's without a tag or a digest: for
     * such a model, the client trusts Tinfoil to say which of its
     * repositories serves which model name.
     *
     * @throws ConfigurationException if the client does not serve [model]:
     *   it is not pinned and only pinned models are served, or the catalog
     *   has no usable entry for it.
     * @throws AttestationException if the catalog names another repository
     *   for a pinned model than its pin does.
     */
    @Throws(TinfoilException::class)
    fun resolve(model: String, catalog: Catalog): Route {
        requireNamed(model)
        val pin = pins[model]
        if (pinnedOnly && pin == null) {
            throw ConfigurationException("model ${quote(model)} is not pinned")
        }
        val entry = catalog[model]
        if (entry == null || !GatewayCatalog.isTrusted(entry)) {
            throw ConfigurationException(
                "model ${quote(model)} has no valid bare ${GatewayCatalog.TRUSTED_OWNER} repository with replicas " +
                    "in the gateway catalog",
            )
        }
        if (pin == null) {
            return Route(entry.hosts, entry.repo, pinnedModel = null)
        }
        val repo = pin.repo.substringBefore('@')
        if (entry.repo != repo) {
            throw AttestationException(
                "model ${quote(model)}: expected repository ${quote(repo)}, gateway offered ${quote(entry.repo)}",
            )
        }
        return Route(entry.hosts, pin.repo, pinnedModel = model)
    }

    /** The trust policy that [replica] is verified under. */
    fun verifierFor(replica: ReplicaKey): AttestationVerifier = replica.pinnedModel?.let { pins[it]?.verifier } ?: verifier

    internal companion object {
        /**
         * Throws for a request that names no model. Nothing is looked up
         * for one: a catalog, which is not trusted, must not get to say
         * which replicas serve the requests whose model the client could
         * not read.
         */
        @Throws(ConfigurationException::class)
        fun requireNamed(model: String) {
            if (model.isBlank()) {
                throw ConfigurationException(
                    "the request names no model: name one in the \"model\" member of a JSON object body, " +
                        "in the model field of an upload, or in the ${GatewayRequest.MODEL_HEADER} header",
                )
            }
        }

        /**
         * What a replica is verified against, for a [reference] to one of
         * Tinfoil's repositories. Tinfoil owns the name both as a source
         * repository and as a registry project, so either satisfies it.
         */
        fun pinOf(reference: String): Pin = Pin(repo = reference, project = reference)
    }
}

/**
 * A replica as it is verified: where it is, what it is verified against,
 * and the pinned model whose policy applies, if any. One host can be
 * verified as several.
 */
internal data class ReplicaKey(val host: String, val reference: String, val pinnedModel: String?)

/**
 * Sends each request through the gateway, sealed to a verified replica of
 * the model that the request names.
 *
 * Neither the gateway nor its catalog is trusted. They say where a model's
 * replicas are; each replica is then verified against the model's
 * repository, through the gateway as a relay, before anything is sealed to
 * it, and a body is sealed only to the key of the verification that its
 * replica passed. The gateway forwards the sealed body, and can read the
 * request's method, URL and headers and nothing of its body.
 *
 * Creating one performs no I/O.
 */
internal class GatewayRouter private constructor(
    val baseUrl: HttpUrl,
    private val policy: GatewayPolicy,
    private val secret: UserCacheSecret,
    private val suppliedCatalog: (() -> Catalog)?,
    private val relay: String,
    private val internals: Internals,
    private val open: (ReplicaKey) -> EnclaveConnection,
) : AttestedSender {
    // Never cancelled, so that every call that is enqueued is answered.
    override val scope: CoroutineScope =
        CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(CALL_PARALLELISM) + CoroutineName("tinfoil-gateway-calls"))

    /** Runs the fetches of the catalog; cancelled when the client closes. */
    private val catalogScope: CoroutineScope =
        CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(1) + CoroutineName("tinfoil-gateway-catalog"))

    // Made here, so that closing the client always finds it. It holds no
    // thread or connection until it fetches.
    private val catalogFetcher: AttestationFetcher? =
        if (suppliedCatalog == null) GatewayCatalog.fetcher(internals.http) else null
    private val fetchedCatalog: CatalogCache? = catalogFetcher?.let { fetcher ->
        CatalogCache({ GatewayCatalog.fetch(relay, fetcher) }, catalogScope, internals.timeSource)
    }

    private val origin = Origin.of(baseUrl)
    private val lock = Any()

    // Guarded by lock. In the order of use, the least recent first.
    private val replicas = LinkedHashMap<ReplicaKey, Replica>(16, 0.75f, true)

    // Guarded by lock. Cache prefix to the replica that the gateway last sent it to.
    private val rerouted = HashMap<String, String>()
    private var closed = false

    /** One replica's verification state and sealed transport. */
    private class Replica(val connection: EnclaveConnection) {
        /** The models that requests sent to it named. It is safe to change from several threads. */
        val models: MutableSet<String> = ConcurrentHashMap.newKeySet()

        /**
         * How many callers are using the replica now: verifying it, or
         * exchanging a request whose response is not yet closed. Guarded by
         * the router's lock.
         */
        var users = 0
    }

    /**
     * The catalog's models that the policy serves, sorted, without
     * verifying any replica. Only the first fetch of a catalog can fail it.
     */
    @Throws(TinfoilException::class, CancellationException::class)
    suspend fun models(): List<String> {
        val catalog = catalogNow()
        return catalog.entries.keys
            .filter { model ->
                try {
                    policy.resolve(model, catalog)
                    true
                } catch (_: TinfoilException) {
                    false
                }
            }
            .sortedWith(CODE_POINT_ORDER)
    }

    /**
     * A verification, valid now, of a replica that serves [model]. Replicas
     * are tried in an order that is fixed for the model, so calling again
     * verifies the same replica while it stays valid.
     */
    @Throws(TinfoilException::class, CancellationException::class)
    suspend fun ensureVerified(model: String): Verification {
        checkOpen()
        GatewayPolicy.requireNamed(model)
        val route = policy.resolve(model, catalogNow())
        val (leased, verification) = firstVerified(route, rank(route.hosts, model, first = null), model)
        release(leased.second)
        return verification
    }

    /** The last successful verification of each replica that is kept, unchecked. */
    val current: List<ReplicaVerification>
        get() = synchronized(lock) { replicas.entries.map { it.key to it.value } }
            .mapNotNull { (key, replica) ->
                replica.connection.current?.let {
                    ReplicaVerification(key.host, replica.models.sorted(), key.reference, key.pinnedModel, it)
                }
            }
            .sortedWith(compareBy({ it.host }, { it.reference }, { it.pinnedModel.orEmpty() }))

    /**
     * Sends [request] sealed to a verified replica of the model that it
     * names, and returns the response with its body still to be read.
     *
     * The request is checked and prepared before any network I/O; see
     * [GatewayRequest.prepare]. Then a replica is chosen: the model's
     * replicas are ranked by the request's cache prefix, so that the
     * requests of one conversation go to one replica, or in a random order
     * without one, and the first that verifies is used. One that does not
     * verify, or that the caller's check rejects, is passed over for the
     * next, up to [MAX_REPLICAS_TRIED] of them.
     *
     * The gateway may answer that it sent the request to another replica,
     * which cannot open it. That replica is then verified in the same way,
     * and the request is sealed to it and sent again, if its body can be
     * written again, at most [MAX_REROUTES] times.
     *
     * @throws ConfigurationException for a request that is refused, a model
     *   that the client does not serve, and a closed client.
     * @throws NetworkException if no replica's attestation can be fetched,
     *   or the gateway keeps routing the request away from the replica that
     *   it was sealed to.
     * @throws AttestationException if no replica is to be trusted.
     */
    @Throws(IOException::class)
    override suspend fun send(request: Request, onCall: (Call) -> Unit): Response {
        checkOpen()
        // What the body says about itself is taken once, so that the body
        // that is examined here is the body that is sealed.
        val settled = SettledBody.settle(request)
        // Each replica makes these checks too; here they refuse a request
        // before its body is read, the catalog is, or a replica is verified.
        origin.requireDestinationOf(settled, "the gateway")
        EhbpSealing.checkRequest(settled, cleartext = false)
        // Reading and scanning a body is work for a background thread.
        val prepared = withContext(Background.dispatcher) { GatewayRequest.prepare(settled, secret.value) }
        checkOpen()
        val model = prepared.model
        // Before the catalog is read, which could otherwise serve it.
        GatewayPolicy.requireNamed(model)
        val route = policy.resolve(model, catalogNow())
        val prefix = prepared.cachePrefix
        val before = synchronized(lock) { rerouted[prefix] }
        val first = firstVerified(route, rank(route.hosts, prefix, before), model).first
        var key = first.first
        var replica: Replica? = first.second

        val body = prepared.request.body
        val replayable = body == null || (!body.isOneShot() && !body.isDuplex())
        var reroutes = 0
        // The replica is held from here until the response is closed, so
        // that it is not let go while the request is in flight.
        try {
            while (true) {
                // A caller that cancelled while a replica was verified must
                // not have its request, credentials included, sent.
                coroutineContext.ensureActive()
                val sealed = prepared.request.newBuilder().header(GatewayRequest.SEAL_HEADER, key.host).build()
                val sending = checkNotNull(replica)
                sending.models += model
                val response = sending.connection.send(sealed, onCall)
                val routed = response.header(GatewayRequest.SEAL_HEADER)
                if (response.code != PRECONDITION_FAILED || routed.isNullOrEmpty() || routed == key.host || !replayable) {
                    replica = null
                    return holding(response) { release(sending) }
                }
                response.closeQuietly()
                if (reroutes == MAX_REROUTES) {
                    throw NetworkException(
                        "gateway kept routing away from the enclave the request was sealed to (last: ${printable(routed)})",
                    )
                }
                reroutes++
                key = route.on(routed)
                replica?.let(::release)
                replica = null
                replica = try {
                    verified(key).first
                } catch (e: TinfoilException) {
                    throw e.prefixed("following gateway route to enclave ${printable(routed)}")
                }
                remember(prefix, routed)
            }
        } finally {
            replica?.let(::release)
        }
    }

    /**
     * [response], with a body that calls [released] once, when it is closed
     * or read to its end. A response without a body is released now.
     */
    private fun holding(response: Response, released: () -> Unit): Response {
        val body = response.body
        if (body == null) {
            released()
            return response
        }
        val once = AtomicBoolean()
        val release = {
            if (once.compareAndSet(false, true)) {
                released()
            }
        }
        val source = object : ForwardingSource(body.source()) {
            override fun read(sink: Buffer, byteCount: Long): Long {
                val read = try {
                    super.read(sink, byteCount)
                } catch (e: IOException) {
                    release()
                    throw e
                }
                if (read == -1L) {
                    release()
                }
                return read
            }

            override fun close() {
                try {
                    super.close()
                } finally {
                    release()
                }
            }
        }.buffer()
        val held = object : ResponseBody() {
            override fun contentType(): MediaType? = body.contentType()

            override fun contentLength(): Long = body.contentLength()

            override fun source(): BufferedSource = source
        }
        return response.newBuilder().body(held).build()
    }

    /** Sends [request] as [send] does, and returns the response with the recovery token of the request that it answers. */
    @Throws(IOException::class)
    suspend fun sendRecoverable(request: Request): RecoverableResponse {
        // A request that is sent again is sealed again, and the token is
        // that of the request that was answered: the last.
        var answered: Call? = null
        val response = send(request) { answered = it }
        return RecoverableResponse(response, (answered as? RecoverableCall)?.recoveryToken)
    }

    /**
     * Refuses later requests and verifications, ends the requests in flight
     * and a fetch of the catalog in progress, and closes every replica's
     * connections.
     */
    fun close() {
        val open = synchronized(lock) {
            if (closed) {
                return
            }
            closed = true
            replicas.values.toList()
        }
        // Each refuses its requests now, and closes its connections on a
        // background thread; so does the fetch of the catalog, since any
        // thread may call this.
        open.forEach { it.connection.close() }
        Background.run {
            catalogScope.cancel()
            catalogFetcher?.close()
        }
    }

    val isClosed: Boolean get() = synchronized(lock) { closed }

    private fun checkOpen() {
        if (isClosed) {
            throw closedError()
        }
    }

    /** The catalog as it is now, for a client that is open before and after the wait for it. */
    private suspend fun catalogNow(): Catalog {
        checkOpen()
        val catalog = fetchedCatalog?.get() ?: try {
            checkNotNull(suppliedCatalog).invoke()
        } catch (e: Exception) {
            throw ConfigurationException("the catalog function failed: ${e.message ?: e.javaClass.simpleName}", cause = e)
        }
        checkOpen()
        return catalog
    }

    /**
     * The first of [hosts], in order, that verifies as a replica of
     * [route], with its verification. At most [MAX_REPLICAS_TRIED] are
     * tried; if none verifies, the last failure is thrown.
     */
    private suspend fun firstVerified(
        route: GatewayPolicy.Route,
        hosts: List<String>,
        model: String,
    ): Pair<Pair<ReplicaKey, Replica>, Verification> {
        var failure: TinfoilException? = null
        for (host in hosts.take(MAX_REPLICAS_TRIED)) {
            coroutineContext.ensureActive()
            val key = route.on(host)
            try {
                val (replica, verification) = verified(key)
                return Pair(Pair(key, replica), verification)
            } catch (e: TinfoilException) {
                // A closed client is not a replica's failure.
                checkOpen()
                failure = e
            }
        }
        throw failure ?: ConfigurationException("model ${quote(model)} has no replicas")
    }

    /**
     * The replica [key] with a verification that is valid now, verifying
     * it first if there is none. A replica that has never verified is not
     * kept: the next request starts again with it. The caller holds the
     * replica that is returned, and has to [release] it.
     */
    private suspend fun verified(key: ReplicaKey): Pair<Replica, Verification> {
        var attempts = 0
        while (true) {
            // A new replica's options are checked by the verifier library,
            // which is not called on the caller's thread.
            val replica = Background.making(::release) { replica(key) }
            try {
                val verification = replica.connection.ensureVerified()
                checkOpen()
                return Pair(replica, verification)
            } catch (e: Throwable) {
                release(replica)
                if (e !is TinfoilException) {
                    throw e
                }
                checkOpen()
                // Another request's failure may have closed this one
                // before it was asked; that says nothing about the replica.
                val closedElsewhere = e is ConfigurationException && replica.connection.isClosed
                if (replica.connection.current == null) {
                    drop(key, replica)
                }
                if (!closedElsewhere || ++attempts >= MAX_REOPENS) {
                    throw e
                }
            }
        }
    }

    /**
     * The replica that is kept for [key], or a new one, which has verified
     * nothing yet, held for the caller.
     *
     * No more than [MAX_REPLICAS] are kept: when there are more, those that
     * no one is using are let go, the least recently used first. One that
     * is in use is never let go, so the client can keep more for as long as
     * that many are in use at once, which its callers bound.
     */
    private fun replica(key: ReplicaKey): Replica {
        val evicted = ArrayList<Replica>()
        val replica = synchronized(lock) {
            if (closed) {
                throw closedError()
            }
            val held = replicas[key] ?: Replica(open(key)).also { replicas[key] = it }
            held.users++
            val eldest = replicas.entries.iterator()
            while (replicas.size > MAX_REPLICAS && eldest.hasNext()) {
                val candidate = eldest.next().value
                if (candidate.users == 0) {
                    eldest.remove()
                    evicted += candidate
                }
            }
            held
        }
        evicted.forEach { it.connection.close() }
        return replica
    }

    private fun release(replica: Replica) {
        synchronized(lock) { replica.users-- }
    }

    private fun drop(key: ReplicaKey, replica: Replica) {
        synchronized(lock) {
            if (replicas[key] === replica) {
                replicas.remove(key)
            }
        }
        replica.connection.close()
    }

    private fun remember(prefix: String, host: String) {
        if (prefix.isEmpty()) {
            return
        }
        synchronized(lock) {
            if (rerouted.size >= MAX_REROUTED) {
                rerouted.clear()
            }
            rerouted[prefix] = host
        }
    }

    private fun closedError() = ConfigurationException("the client is closed")

    internal companion object {
        /** Tinfoil's gateway. */
        const val DEFAULT_BASE_URL: String = "https://inference-gateway.tinfoil.sh/v1/"

        /** How often one request follows the gateway to another replica. */
        const val MAX_REROUTES: Int = 3

        /** How many of a model's replicas are tried for one request, or one verification, before it fails. */
        const val MAX_REPLICAS_TRIED: Int = 16

        /**
         * How many replicas a client keeps connections and verifications
         * for, beyond those that are in use; the least recently used goes
         * first.
         */
        const val MAX_REPLICAS: Int = 256

        private const val MAX_REROUTED = 1024
        private const val MAX_REOPENS = 3
        private const val PRECONDITION_FAILED = 412
        private const val CALL_PARALLELISM = 64
        private const val MAX_PRINTED = 255

        /** Strings in the order of their code points, which is the order of their UTF-8 bytes. */
        private val CODE_POINT_ORDER = Comparator<String> { a, b ->
            var i = 0
            var j = 0
            var order = 0
            while (order == 0 && i < a.length && j < b.length) {
                val x = a.codePointAt(i)
                val y = b.codePointAt(j)
                order = x.compareTo(y)
                i += Character.charCount(x)
                j += Character.charCount(y)
            }
            if (order != 0) order else (a.length - i).compareTo(b.length - j)
        }

        /**
         * A router for the gateway at [baseUrl], with every option checked
         * and nothing fetched or verified.
         */
        @Throws(TinfoilException::class)
        fun create(
            modelPins: Map<String, ModelPin>,
            pinnedModelsOnly: Boolean,
            baseUrl: String?,
            policy: Policy,
            userCacheSecret: String?,
            verificationCheck: VerificationCheck?,
            onVerificationResult: ((Result<Verification>) -> Unit)?,
            catalog: (() -> Catalog)?,
            internals: Internals,
        ): GatewayRouter {
            val base = Urls.baseUrl(requireNotEmpty(baseUrl, "baseUrl") ?: DEFAULT_BASE_URL)
            if (!base.isHttps) {
                throw ConfigurationException("invalid base URL: the gateway base URL must use HTTPS")
            }
            // Attestation documents and the catalog come through the gateway.
            val authority = if (base.host.contains(':')) "[${base.host}]" else base.host
            val relay = if (base.port == HttpUrl.defaultPort(base.scheme)) authority else "$authority:${base.port}"
            Urls.requireRelay(relay)
            // The caller's map is read once, here.
            val gatewayPolicy = GatewayPolicy(HashMap(modelPins), pinnedModelsOnly, policy, internals.newVerifier)
            val secret = UserCacheSecret.orProcessDefault(userCacheSecret)
            val open = { replica: ReplicaKey ->
                EnclaveConnection.create(
                    enclave = replica.host,
                    pin = GatewayPolicy.pinOf(replica.reference),
                    transport = Transport.Ehbp(proxyUrl = base.toString()),
                    attestationRelay = relay,
                    verifier = gatewayPolicy.verifierFor(replica),
                    // The router scopes the cache itself.
                    cacheSecret = null,
                    verificationCheck = verificationCheck,
                    onVerificationResult = onVerificationResult,
                    internals = internals,
                )
            }
            return GatewayRouter(base, gatewayPolicy, secret, catalog, relay, internals, open)
        }

        /**
         * [hosts] in the order in which a request with the cache [prefix]
         * tries them: by a score that each host has for that prefix, the
         * highest first, so that a prefix keeps its order when hosts come
         * and go, and with [first] ahead of the rest if it is one of them.
         * Without a prefix the order is random.
         */
        fun rank(hosts: List<String>, prefix: String, first: String?): List<String> {
            if (prefix.isEmpty()) {
                return hosts.shuffled()
            }
            val sha256 = MessageDigest.getInstance("SHA-256")
            val ranked = hosts
                .map { host ->
                    val sum = sha256.digest("$prefix\u0000$host".toByteArray(Charsets.UTF_8))
                    var score = 0L
                    for (i in 0 until Long.SIZE_BYTES) {
                        score = (score shl 8) or (sum[i].toLong() and 0xff)
                    }
                    Pair(host, score)
                }
                .sortedWith { a, b -> java.lang.Long.compareUnsigned(b.second, a.second) }
                .mapTo(ArrayList()) { it.first }
            val index = if (first == null) -1 else ranked.indexOf(first)
            if (index > 0) {
                ranked.add(0, ranked.removeAt(index))
            }
            return ranked
        }

        /** [text], which someone else chose, as it can be shown in a message. */
        private fun printable(text: String): String =
            text.take(MAX_PRINTED).map { if (it in ' '..'~') it else '?' }.joinToString("")
    }
}

/** [text] in quotes, with what could not be read in a message escaped. */
private fun quote(text: String): String = buildString(text.length + 2) {
    append('"')
    for (c in text) {
        when {
            c == '"' || c == '\\' -> append('\\').append(c)
            c.isISOControl() -> append("\\u%04x".format(c.code))
            else -> append(c)
        }
    }
    append('"')
}

/** The same error, in the same category, with [context] ahead of its detail. */
private fun TinfoilException.prefixed(context: String): TinfoilException = when (this) {
    is ConfigurationException -> ConfigurationException("$context: $detail", cause = this)
    is NetworkException -> NetworkException("$context: $detail", status = status, cause = this)
    is AttestationException -> AttestationException("$context: $detail", layer = layer, cause = this)
}
