package sh.tinfoil.internal

import com.openai.core.ClientOptions
import sh.tinfoil.TinfoilEvent

/** The options of the OpenAI client that is put over an attested client. */
internal class OpenAISettings(
    val tinfoilEvents: Set<TinfoilEvent> = emptySet(),
    /** What the caller does to the OpenAI SDK's options builder, in the order in which it was given. */
    val configure: List<ClientOptions.Builder.() -> Unit> = emptyList(),
)
