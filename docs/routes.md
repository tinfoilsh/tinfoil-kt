# Routes

## Choosing the route

`Client.create(apiKey)` says nothing about how requests reach the models, so
that the route can change. To choose the route, create one of the attested
HTTP clients of the `tinfoil` artifact and put an OpenAI client over it:

- `RouterHttpClient` sends to one of Tinfoil's routers, which it chooses and
  verifies when it is created;
- `EnclaveHttpClient` sends to an enclave that you name, verified under the
  trust that you name for it (see [What is trusted](verification.md#what-is-trusted));
- `GatewayHttpClient` sends through Tinfoil's gateway (see
  [Gateway](#gateway-experimental)).

```kotlin
import sh.tinfoil.RouterHttpClient
import sh.tinfoil.Transport
import sh.tinfoil.openai.Client
import sh.tinfoil.openai.TinfoilEvent

val router = RouterHttpClient.create {
    transport = Transport.Ehbp(proxyUrl = "https://proxy.example.com/")
    userCacheSecret = cacheSecret
}
val client = Client.create(router, apiKey) {
    tinfoilEvents = setOf(TinfoilEvent.WEB_SEARCH)
}
```

```kotlin
import sh.tinfoil.EnclaveHttpClient
import sh.tinfoil.Trust

val enclave = EnclaveHttpClient.create(
    enclave = "inference.tinfoil.sh",
    trust = Trust.RepoPin("tinfoilsh/confidential-model-router"),
)
val client = Client.create(enclave, apiKey) {
    apiPath = "/v1/"
}
println(enclave.currentVerification()?.verifiedFacts?.codeDigest)
```

Creating the OpenAI client does no network I/O: the HTTP client verified
its service when it was created, and verifies it again by itself. Requests
go to `apiPath`, `/v1/` by default, under the HTTP client's `baseUrl`: the
enclave's origin, `https://<enclave>/`, the proxy URL of `Transport.Ehbp`,
whose path is where the proxy is mounted, or the gateway's URL, which is
its origin, `https://inference-gateway.tinfoil.sh/` by default, or the URL
that it is mounted under, never the API path. An `apiPath` must be an
absolute path, and an empty one is refused: leave it unset for `/v1/`. The
OpenAI client does not own the HTTP client: close each, and one
HTTP client can serve several OpenAI clients, each with its own API key.
`Client.create(apiKey)` makes its own router client, and closes it with
itself.

## Gateway (experimental)

The gateway route is new, and its API may change or be removed in a later
release. Its classes are marked `@ExperimentalTinfoilApi`, and using them is
a compile error until the code opts in.

Tinfoil's gateway forwards each request to an enclave that serves the model
that the request names: a replica of that model. The gateway is not trusted
with what a request says. `GatewayHttpClient` picks a replica, verifies its
attestation, and seals the request's body to the key that the attestation
endorses, so the gateway forwards a body that it cannot read. It does read
everything else: the URL, the headers, the API key among them, and the name
of the model.

```kotlin
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.GatewayHttpClient
import sh.tinfoil.ModelPin
import sh.tinfoil.openai.Client

@OptIn(ExperimentalTinfoilApi::class)
suspend fun gateway(apiKey: String): Client {
    val gateway = GatewayHttpClient.create {
        modelPins = mapOf("deepseek-v4-1-flash" to ModelPin("tinfoilsh/confidential-deepseek-v4-1-flash"))
    }
    val client = Client.create(gateway, apiKey)
    println(gateway.models())
    return client
}
```

A gateway client serves only the models that its `modelPins` name, so it
requires at least one pin, and a request for any other model fails with a
`ConfigurationException` before any replica is contacted. A model's replicas
are verified against its pin's repository, and against one release of it if
the pin has a tag or a digest; the gateway's catalog must name that
repository for the model. A pin without a policy of its own takes the
client's `policy`.

The gateway client verifies each model's replicas separately, so its
`ensureVerified(model)` and `reverify(model)` take the model. `reverify`
verifies again the replica that `ensureVerified` would return for it. When
that replica fails with an `AttestationException`, its verification is
withdrawn and `reverify` moves on to the next replica, as `ensureVerified`
then does; any other failure keeps the replica's verification while it is
valid, and is thrown. `replicas()` returns an entry for each replica that
the client has tried to verify, with its host, the models requested through
it, its `current` verification, which follows the rule of
`currentVerification()` for that replica, and its `lastAttempt`.

A request has to name its model, so the calls of the OpenAI SDK that name
none, such as listing models, are refused; `GatewayHttpClient.models()` lists what
the client serves. A JSON body that names `model`, `user_cache_secret` or
`cache_salt` twice, or in another case, such as `Model`, is refused too,
since a server could read another member than the client did.
`userCacheSecret` scopes the prompt cache as it does for the other clients,
but on the chat, completions and responses requests the secret never leaves
the device: the client replaces it in the body with a salt that it derives
from it.
`GatewayHttpClient` is the HTTP client itself, and describes all of this.

## Without the OpenAI SDK

The HTTP clients of the `tinfoil` artifact are what the OpenAI clients send
through, and work without them. Each is an OkHttp `Call.Factory` that sends
a request only to the service that it verified:

```kotlin
import okhttp3.Request
import sh.tinfoil.EnclaveHttpClient
import sh.tinfoil.Trust

val client = EnclaveHttpClient.create(
    enclave = "inference.tinfoil.sh",
    trust = Trust.RepoPin("tinfoilsh/confidential-model-router"),
)

val request = Request.Builder()
    .url(client.baseUrl.resolve("v1/models")!!)
    .header("Authorization", "Bearer $apiKey")
    .build()
client.execute(request).use { response -> println(response.body!!.string()) }

client.close()
```
