package sh.tinfoil.testing

import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import okio.Buffer
import org.bouncycastle.crypto.hpke.HPKE
import sh.tinfoil.ehbp.identity.ExportLabel
import sh.tinfoil.ehbp.identity.ExportLength
import sh.tinfoil.ehbp.identity.HPKERequestInfo
import sh.tinfoil.ehbp.identity.Identity
import sh.tinfoil.ehbp.identity.ResponseAEAD
import sh.tinfoil.ehbp.identity.deriveResponseKeys
import sh.tinfoil.ehbp.identity.newIdentity
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList

/*
 * The enclave's side of the sealing protocol, for tests only. The client
 * library that this SDK uses has no server side, so this one is put together
 * from that library's own primitives, as the library's tests do. Nothing
 * here is used outside tests.
 */

internal const val ENCAPSULATED_KEY_HEADER = "Ehbp-Encapsulated-Key"
internal const val RESPONSE_NONCE_HEADER = "Ehbp-Response-Nonce"
internal const val ENCLAVE_URL_HEADER = "X-Tinfoil-Enclave-Url"

internal fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

internal fun String.unhex(): ByteArray = ByteArray(length / 2) { substring(2 * it, 2 * it + 2).toInt(16).toByte() }

/** Whether [marker] occurs anywhere in these bytes, whole. */
internal fun ByteArray.containsText(marker: String): Boolean {
    val wanted = marker.toByteArray()
    require(wanted.size >= 8) { "a marker of a few bytes proves nothing" }
    return (0..size - wanted.size).any { start -> wanted.indices.all { this[start + it] == wanted[it] } }
}

/** One length-prefixed frame of a sealed body. */
internal fun lengthPrefixed(ciphertext: ByteArray): ByteArray =
    ByteBuffer.allocate(4 + ciphertext.size).putInt(ciphertext.size).put(ciphertext).array()

/** An HPKE key pair that an enclave holds, and that an attestation can endorse. */
internal class SealingKey {
    private val identity: Identity = newIdentity()

    /** The public key, as an attestation endorses it. */
    val publicKey: String = identity.marshalPublicKeyHex()

    /**
     * Opens a sealed request body with this key.
     *
     * @throws Exception if the body was not sealed to this key, or is not
     *   intact.
     */
    fun open(encapsulatedKey: String, sealed: ByteArray): OpenedRequest {
        val enc = encapsulatedKey.unhex()
        val recipient = HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM256)
            .setupBaseR(enc, identity.privateKey(), HPKERequestInfo.toByteArray())
        val plaintext = ByteArrayOutputStream()
        val frames = ByteBuffer.wrap(sealed)
        while (frames.hasRemaining()) {
            val length = frames.int
            if (length == 0) {
                continue
            }
            val ciphertext = ByteArray(length).also { frames.get(it) }
            plaintext.write(recipient.open(ByteArray(0), ciphertext))
        }
        return OpenedRequest(plaintext.toByteArray(), recipient.export(ExportLabel.toByteArray(), ExportLength), enc)
    }
}

/** A request body that an enclave opened, and what it needs to seal the response. */
internal class OpenedRequest(
    val plaintext: ByteArray,
    private val exported: ByteArray,
    private val enc: ByteArray,
) {
    /** Starts a sealed response. Each response has a nonce of its own. */
    fun respond(): SealedResponse {
        val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
        return SealedResponse(nonce.hex(), deriveResponseKeys(exported, enc, nonce).newResponseAEAD())
    }
}

/** Seals the pieces of one response body, in order. */
internal class SealedResponse(val nonce: String, private val aead: ResponseAEAD) {
    /** The next frame of the body, which carries [plaintext]. */
    fun frame(plaintext: ByteArray): ByteArray = lengthPrefixed(aead.seal(plaintext))

    fun frame(plaintext: String): ByteArray = frame(plaintext.toByteArray())
}

/** What a sealing server saw of one request. */
internal class Received(
    val request: RecordedRequest,
    /** The body as it was on the wire, with the HTTP framing removed. */
    val wire: ByteArray,
    /** The body that the enclave read: the opened plaintext, or the body itself if it was not sealed. */
    val plaintext: ByteArray?,
    private val opened: OpenedRequest?,
) {
    val sealed: Boolean get() = request.getHeader(ENCAPSULATED_KEY_HEADER) != null
    val text: String? get() = plaintext?.toString(Charsets.UTF_8)

    /** A response that is sealed if the request was, as an enclave answers. */
    fun reply(body: String, code: Int = 200, pieces: Int = 1): MockResponse {
        val response = MockResponse().setResponseCode(code)
        if (opened == null) {
            return response.setBody(body)
        }
        val sealing = opened.respond()
        val frames = Buffer()
        val size = maxOf(1, (body.length + pieces - 1) / pieces)
        body.chunked(size).forEach { frames.write(sealing.frame(it)) }
        return response.setHeader(RESPONSE_NONCE_HEADER, sealing.nonce).setBody(frames)
    }

    /** The parts of a sealed response, for a test that sends it damaged. */
    fun respond(): SealedResponse = checkNotNull(opened) { "the request was not sealed" }.respond()
}

/**
 * An enclave, or a proxy in front of one, that speaks the sealing protocol:
 * it opens sealed requests with [key], answers a body that it cannot open
 * as a real enclave does, and hands every request to [answer].
 */
internal class SealingDispatcher(
    private val key: () -> SealingKey,
    @Volatile var answer: (Received) -> MockResponse = { it.reply("ok") },
) : Dispatcher() {
    /** Every request that arrived, in order, including those that could not be opened. */
    val received = CopyOnWriteArrayList<Received>()

    override fun dispatch(request: RecordedRequest): MockResponse {
        val wire = request.body.clone().readByteArray()
        val encapsulated = request.getHeader(ENCAPSULATED_KEY_HEADER)
        if (encapsulated == null) {
            return Received(request, wire, wire, null).also { received += it }.let(answer)
        }
        val opened = try {
            key().open(encapsulated, wire)
        } catch (_: Exception) {
            received += Received(request, wire, null, null)
            return keyConfigProblem()
        }
        return Received(request, wire, opened.plaintext, opened).also { received += it }.let(answer)
    }

    companion object {
        /** What an enclave answers a body that is not sealed to a key that it holds. */
        fun keyConfigProblem(): MockResponse = MockResponse()
            .setResponseCode(422)
            .setHeader("Content-Type", "application/problem+json")
            .setBody("""{"type":"urn:ietf:params:ehbp:error:key-config","title":"key configuration mismatch"}""")
    }
}
