package runar.integration.helpers;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/**
 * Composed annotation that marks a class as requiring the runtime
 * {@code -Drunar.integration=true} system property to be enabled.
 *
 * <p>Applied to {@link IntegrationBase} so all 31+ subclasses pick it up.
 * The {@code @Inherited} marker makes the standard reflective lookup
 * surface this on subclasses, complementing JUnit 5's own annotation
 * search up the class hierarchy. Even so, {@link IntegrationBase}
 * also re-checks the property inside {@code @BeforeAll} via
 * {@link org.junit.jupiter.api.Assumptions#assumeTrue} so that an
 * unset flag always produces a <em>skipped</em> outcome rather than an
 * {@code initializationError}.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@EnabledIfSystemProperty(named = "runar.integration", matches = "true")
public @interface RequiresIntegration {
}
