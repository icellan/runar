package runar.lang.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Optional marker for stateful contracts. The compiler derives
 * {@code parentClass = "StatefulSmartContract"} from the
 * {@code extends} clause, so this annotation is informational only —
 * useful for IDE/linter hints.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface Stateful {}
