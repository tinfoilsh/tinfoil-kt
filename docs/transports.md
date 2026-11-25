# Transports

A client protects its requests with the keys that the enclave's attestation
endorses, in one of two ways, which its `transport` option selects.

`Transport.Tls`, the default, pins every connection to the attested TLS
key. It protects the whole request and response, and needs a direct
connection to the enclave, so it takes no URL.

`Transport.Ehbp` seals request and response bodies to the attested HPKE key
with [EHBP](https://docs.tinfoil.sh/resources/ehbp), so that they stay
private through a proxy, its `proxyUrl`, or on a direct connection when that
is null:

```kotlin
val client = EnclaveHttpClient.create(
    enclave = "inference.tinfoil.sh",
    trust = Trust.RepoPin("tinfoilsh/confidential-model-router"),
) {
    transport = Transport.Ehbp(proxyUrl = "https://proxy.example.com/")
}
```

The proxy URL's path is where the proxy is mounted: request paths, and the
OpenAI clients' `v1/`, join under it whether or not it ends with `/`. A proxy
on the enclave's own origin is refused; leave `proxyUrl` null to connect
directly.

What this mode does not protect:

- **Only bodies are sealed.** The method, the URL and the headers of every
  request, an API key among them, are not: the proxy reads them and can
  change them. The proxy must therefore use HTTPS; `http://` is accepted only
  for `localhost` or a loopback IP address. A proxy on this machine is
  reached directly, whatever HTTP proxy the system is configured with.
- **A request without a body is not sealed, and neither is its response.**
  The same goes for a body that is empty: one that declares a length of
  zero, or one of undeclared length that writes nothing.
- Connections are validated as any HTTPS connection is, and are not pinned to
  the enclave's key: whoever holds a valid certificate for the host that you
  named, the proxy's or the enclave's own, reads what is not sealed. The
  router clients are the exception, because you do not name the router's
  host: without a proxy, their connections are pinned to the router's
  attested key in this mode too. With a proxy, which makes the connection to
  the router itself, the router that discovery chose is named to the proxy.
  An attestation document is not tied to the host that serves it, so the
  source of the router list, Tinfoil's or yours, is then trusted not to name
  a host that would pass on another router's attestation: such a host would
  receive the request headers, the API key among them, though not the
  sealed bodies.
- A response with an error status of 400 or above may come from the proxy and
  not from the enclave. A response that the enclave did not seal is
  authenticated by nothing.
- **A sealed response can be cut short without an error.** Every piece of a
  sealed body is authenticated, and a body that ends inside a piece fails the
  read. A body that ends between two pieces does not: the protocol does not
  mark the last piece, so a proxy can end a response early. What you read is
  the enclave's, but only its content shows that it is complete, such as the
  `[DONE]` event at the end of a stream, or JSON that parses.
- Protocol upgrades, such as WebSockets, and `CONNECT` are refused.
- A response that is marked as sealed has to show it: the read of its body
  fails unless a piece of it authenticates. An empty response that the
  enclave sealed is read as empty, except with an error status of 400 or
  above, where it is refused: the sealing library does not tell it there
  from one that only claims to be sealed.

Requests to a proxy carry `X-Tinfoil-Enclave-Url: https://<enclave>`, which
tells the proxy where to forward them. See `EnclaveHttpClient.execute` for
the full rules.

## Relays

By default, a client fetches each attestation document directly from the
enclave, and the router client fetches its list of candidate routers from
`https://atc.tinfoil.sh/routers`. The `fetchAttestation` option of the
enclave and router clients, and the `fetchRouterList` option of the router
client, change how they are obtained, so that, together with a proxy, a
client reaches only your own origin: for a device that should not reveal
its address to enclaves, or a network that allows one destination.

```kotlin
val client = RouterHttpClient.create {
    transport = Transport.Ehbp(proxyUrl = "https://app.example/tinfoil/proxy")
    fetchAttestation = AttestationRelay("https://app.example/tinfoil")
    fetchRouterList = RouterListRelay("https://app.example/tinfoil")
}
```

`AttestationRelay(url)` sends
`GET <url>/.well-known/tinfoil-attestation?nonce=<hex>&enclave=<host>`, which
the relay forwards to `https://<host>/.well-known/tinfoil-attestation?nonce=<hex>`,
returning the body unchanged. `RouterListRelay(url)` sends `GET <url>/routers`,
which the relay forwards to `https://atc.tinfoil.sh/routers`. A relay should
forward only to the enclave hosts that the application expects, so that it
is not an open proxy. A relay URL follows the rules of a proxy URL, and is
checked when the relay is made. Any other function can take either place:
`fetchAttestation = AttestationFetcher { host, nonce -> ... }`.

Neither option changes what is trusted. Every document is verified as a
fetched one is, and the list only proposes routers: discovery always runs,
tries a shuffled copy of the list, verifies each router that it tries, and
falls back to `inference.tinfoil.sh`. A fetcher's failure is a
`NetworkException` that keeps it as its cause, unless it is already one of
this SDK's exceptions, and a router list that cannot be obtained counts as
empty.

## Session recovery

With `Transport.Ehbp`, `executeRecoverable` returns a response together
with its session recovery token, which can open that one response again
later, without the client that sent the request. Use it for a response that
the server keeps and that can be fetched again after an interruption:

```kotlin
client.executeRecoverable(request).use { recoverable ->
    recoverable.recoveryToken?.let { store(it.toJson()) }   // before reading the body
    read(recoverable.response.body!!.source())
}

// Later, with the sealed response fetched again from where it is kept:
val plaintext = SessionRecoveryToken.fromJson(stored).decryptResponse(sealedResponse)
```

A token is secret key material for its response. Keep it in protected
storage, never log it, and delete it once the response has been read.
