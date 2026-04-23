package runar.compiler.canonical;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Overrides the JSON field name emitted by {@link Jcs} for a record
 * component. Used where the Java identifier cannot match the
 * conformance JSON name — either because of a reserved keyword
 * ({@code else}) or because the upstream schema chose a name Java
 * conventions frown on (e.g. {@code result_type}).
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.RECORD_COMPONENT)
public @interface JsonName {
    String value();
}
