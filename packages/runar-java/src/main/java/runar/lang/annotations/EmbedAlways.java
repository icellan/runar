package runar.lang.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Keeps a readonly field in the locking script although no method reads it —
 * the native Java spelling of the {@code @embedAlways} directive (N-093;
 * {@code .runar.ts} spells it as a {@code /** @embedAlways *&#47;} comment).
 *
 * <p>A readonly property that no method references is normally eliminated:
 * no constructor slot is emitted and its deploy-time value never reaches the
 * script. {@code @EmbedAlways} opts the field out of that elimination, for
 * deploy-time metadata an author intends to recover from the script later.
 * Analog of Go's {@code `runar:"readonly,embedAlways"`} struct tag option,
 * Rust's {@code #[embed_always]} attribute and Python's {@code EmbedAlways[T]}
 * wrapper. Only meaningful together with {@link Readonly} (or in a
 * {@code SmartContract}, whose fields are all readonly).
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface EmbedAlways {}
