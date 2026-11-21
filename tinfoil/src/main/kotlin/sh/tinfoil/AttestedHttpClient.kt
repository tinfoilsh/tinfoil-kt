package sh.tinfoil

import okhttp3.Call
import okhttp3.HttpUrl

/**
 * One of this SDK's attested HTTP clients: an [EnclaveHttpClient], a
 * [RouterHttpClient] or a [GatewayHttpClient]. It is sealed, so that a
 * library built on top of these clients, such as this SDK's OpenAI client,
 * can rely on every request that it sends through one being verified.
 */
public sealed interface AttestedHttpClient : Call.Factory, AutoCloseable {
    /**
     * The URL that requests are sent under, ending with `/`. Resolve
     * request paths against it, as in `baseUrl.resolve("v1/models")`.
     */
    public val baseUrl: HttpUrl
}
