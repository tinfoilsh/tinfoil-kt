package sh.tinfoil

/**
 * Marks a declaration that exists only so that one of this SDK's artifacts
 * can use another: `tinfoil-openai` is built on `tinfoil` through these.
 *
 * **It is not for applications.** A marked declaration has no compatibility
 * promise at all: it changes or disappears whenever this SDK needs it to,
 * in any release, and is left out of the published API. The artifacts of
 * this SDK are released together, and each depends on exactly its own
 * version of the others, which is what makes that safe for them and for
 * nothing else.
 *
 * Using a marked declaration is a compile error until the use opts in.
 * Nothing that is marked changes what a client verifies or whom it trusts.
 */
@RequiresOptIn(
    level = RequiresOptIn.Level.ERROR,
    message = "This is internal to the Tinfoil SDK's own artifacts. It is not for applications, and may change or " +
        "be removed in any release.",
)
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.CONSTRUCTOR,
)
@MustBeDocumented
public annotation class InternalTinfoilApi
