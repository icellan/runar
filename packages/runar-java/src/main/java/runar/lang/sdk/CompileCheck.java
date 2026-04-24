package runar.lang.sdk;

import java.util.List;

/**
 * In-test validator: runs Parse + Validate + Typecheck from
 * {@code runar.compiler.frontend.*} and returns a structured result.
 *
 * <p>M8 wiring: the compiler lives in a sibling Gradle project
 * ({@code compilers/java}) that is not yet on this SDK's runtime
 * classpath. The working design is to either (a) add a
 * {@code testImplementation project(":compilers:java")} once M3
 * lands, or (b) shell out to the {@code runar-java} binary via
 * {@link ProcessBuilder}. Until either is in place, {@link #check}
 * throws an {@link UnsupportedOperationException} pointing to M11 /
 * M18 where the wiring is finalised.
 */
public final class CompileCheck {

    private CompileCheck() {}

    public static CompileCheckResult check(String source, String filename) {
        throw new UnsupportedOperationException(
            "CompileCheck.check: wiring to compilers/java lands in M11 (compiler project depend) "
                + "or M18 (playground / Gradle composite)"
        );
    }

    public record CompileCheckResult(boolean ok, List<String> errors) {
        public CompileCheckResult {
            errors = errors == null ? List.of() : List.copyOf(errors);
        }
    }
}
