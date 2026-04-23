package runar.lang.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a contract method as a public spending entry point.
 *
 * <p>Analog of Python's {@code @public} decorator and Rust's
 * {@code #[public]} attribute. Methods without {@code @Public} are
 * treated as private helpers (inlined by the compiler).
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Public {}
