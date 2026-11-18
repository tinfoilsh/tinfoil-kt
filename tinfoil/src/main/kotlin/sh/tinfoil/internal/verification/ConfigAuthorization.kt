package sh.tinfoil.internal.verification

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import sh.tinfoil.ConfigAuthorizer
import sh.tinfoil.ConfigEndorsement
import sh.tinfoil.internal.nullIfEmpty
import java.util.Base64

/**
 * Asks a [ConfigAuthorizer] about the config material that the verifier
 * library hands over as JSON. Returning approves the config, so every path
 * that is not the authorizer's own approval throws a [Rejection].
 */
internal object ConfigAuthorization {
    /**
     * What the library is told when a config is not approved. The library
     * reads the message later and from its own threads, so it is a fixed
     * string, and there is no stack trace to fill in.
     */
    class Rejection(message: String) : Exception(message, null, false, false)

    /**
     * Returns only if [authorizer] approves the config in [payload].
     *
     * Nothing that an authorizer throws can travel through the library to
     * the caller of a verification: whatever is thrown comes out as a
     * rejection that carries its message. So everything is caught, errors
     * included, and turned into a rejection that is safe to read.
     */
    @Throws(Rejection::class)
    fun authorize(authorizer: ConfigAuthorizer, payload: String?) {
        val endorsement = decodeEndorsement(payload)
        try {
            authorizer.authorize(endorsement)
        } catch (e: Throwable) {
            throw Rejection(describe(e))
        }
    }

    /**
     * Decodes the library's payload, in which every byte string is standard
     * base64 and a member that the document lacks is absent. A payload that
     * cannot be read rejects the config. The errors name the member and
     * never quote the payload, which is document material.
     */
    @Throws(Rejection::class)
    fun decodeEndorsement(payload: String?): ConfigEndorsement {
        val decoded = try {
            json.decodeFromString(Payload.serializer(), payload.orEmpty())
        } catch (_: SerializationException) {
            throw Rejection("unreadable config endorsement")
        } catch (_: IllegalArgumentException) {
            throw Rejection("unreadable config endorsement")
        }
        return ConfigEndorsement(
            config = bytes(decoded.config, "config"),
            reference = decoded.reference.nullIfEmpty(),
            sigstoreBundle = decoded.sigstoreBundle.nullIfEmpty()?.let { bytes(it, "sigstore_bundle") },
            issuerCertificate = decoded.issuerCertificateDer.nullIfEmpty()
                ?.let { bytes(it, "issuer_certificate_der") },
        )
    }

    private fun bytes(value: String, member: String): ByteArray =
        try {
            Base64.getDecoder().decode(value)
        } catch (_: IllegalArgumentException) {
            throw Rejection("config endorsement has an invalid $member")
        }

    /** The rejection's message: the thrown exception's own, or its type. */
    private fun describe(thrown: Throwable): String {
        val message = try {
            thrown.message
        } catch (_: Exception) {
            null
        }
        return if (message.isNullOrEmpty()) thrown.javaClass.name else message
    }

    // Members may be added to the payload, so one that is not named here is
    // ignored. Everything else is strict.
    private val json = Json { ignoreUnknownKeys = true }

    @Serializable
    private class Payload(
        val config: String,
        val reference: String? = null,
        @SerialName("sigstore_bundle") val sigstoreBundle: String? = null,
        @SerialName("issuer_certificate_der") val issuerCertificateDer: String? = null,
    )
}
