package sh.tinfoil

/**
 * Marks an API of this SDK that is experimental: it may change or be removed
 * in any release, without the notice that the rest of the API gets.
 *
 * Using a marked declaration is a compile error until the use opts in, with
 * `@OptIn(ExperimentalTinfoilApi::class)` on the code that uses it or with
 * the compiler argument `-opt-in=sh.tinfoil.ExperimentalTinfoilApi`. It is an
 * error rather than a warning so that no code comes to depend on such an API
 * without its author having decided to.
 *
 * The gateway route is marked: [GatewayHttpClient] and the types that it
 * uses.
 */
@RequiresOptIn(
    level = RequiresOptIn.Level.ERROR,
    message = "This API is experimental. It may change or be removed in a later release.",
)
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.CONSTRUCTOR,
    AnnotationTarget.TYPEALIAS,
)
@MustBeDocumented
public annotation class ExperimentalTinfoilApi
