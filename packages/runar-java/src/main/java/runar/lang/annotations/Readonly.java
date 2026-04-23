package runar.lang.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a {@code StatefulSmartContract} field as immutable across state
 * transitions. Analog of Python's {@code Readonly[T]} wrapper, Go's
 * {@code `runar:"readonly"`} struct tag, and Rust's {@code #[readonly]}
 * attribute.
 *
 * <p>All fields of a {@code SmartContract} (stateless) are implicitly
 * readonly — the annotation is redundant there but harmless.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface Readonly {}
