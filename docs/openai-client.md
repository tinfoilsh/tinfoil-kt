# The OpenAI client

`Client`, in the artifact `tinfoil-openai`, is an OpenAI client for inference
over one of this SDK's attested HTTP clients. The [README](../README.md#quick-start)
shows how to create one; this page describes what it exposes and what it reads.

`client.openAI` is the client of the official
[OpenAI Java SDK](https://github.com/openai/openai-java), with blocking
calls, and `client.openAIAsync` is the same client with calls that return a
`CompletableFuture`, which a coroutine awaits with `await()`. Use them as
that SDK documents. The API key is passed in: no credential, URL or option
is taken from the environment or from system properties. (The OpenAI SDK
reads the variable `OPENAI_LOG` when its options are made, which this SDK
overrides with logging off, and it describes the platform in its
`X-Stainless-*` request headers, from the system properties `os.name`,
`os.arch`, `os.version` and `java.version`.)

A streamed response becomes a `Flow` with `asFlow()`. Events arrive as the
service sends them, and cancelling the collection cancels the request:

```kotlin
import sh.tinfoil.openai.asFlow

client.openAIAsync.chat().completions().createStreaming(params).asFlow().collect { chunk ->
    chunk.choices().forEach { choice -> choice.delta().content().ifPresent(::print) }
}
```

Other options of the OpenAI client are set on its own options builder, in
`openAI { }`:

```kotlin
val client = Client.create(apiKey) {
    openAI {
        maxRetries(1)
        timeout(Duration.ofMinutes(2))
    }
}
```

An HTTP client or a base URL that is set there is replaced, and so is one
that the OpenAI SDK reads from `OPENAI_BASE_URL`: the OpenAI client reaches
the network only through this SDK. The one way around that is
the OpenAI SDK's `withOptions`, on the client or on one of its services: a
client that it returns with another HTTP client sends its requests, and the
API key, without any of this SDK's protection.

For the route that the requests take, see [Routes](routes.md), and for the
exceptions that a call throws, see [Errors](verification.md#errors).
