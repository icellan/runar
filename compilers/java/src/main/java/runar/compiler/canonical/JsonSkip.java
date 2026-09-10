package runar.compiler.canonical;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a record component as compiler-internal: never written to the JSON
 * output, whatever its value. Used by in-memory-only flags that carry no
 * cross-tier wire representation (e.g.
 * {@link runar.compiler.ir.anf.LoadProp#preserve()}, the issue #109
 * {@code @embedAlways} DCE opt-out, which the Zig reference also keeps out of
 * the emitted ANF IR JSON).
 *
 * <p>Unlike {@link JsonOmitWhenFalse}, which only drops the {@code false} case,
 * this drops the component unconditionally so the cross-tier IR bytes stay
 * identical in both states. The Rust tier's equivalent is
 * {@code #[serde(default, skip)]}.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.RECORD_COMPONENT)
public @interface JsonSkip {
}
