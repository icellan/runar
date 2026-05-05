package runar.compiler.frontend;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Resolves a per-format source file for a conformance fixture.
 *
 * After the source.json migration the per-format files no longer live inside
 * conformance/tests/&lt;fixture&gt;/ — they live under examples/ and source.json
 * maps each ".runar.&lt;ext&gt;" key to a relative path. Tests must read source.json
 * to find the actual file rather than hardcoding the legacy in-fixture path.
 *
 * Walks up from the test working directory to find the conformance/ root, so
 * the resolver works regardless of where Gradle invokes the test.
 */
final class ConformanceFixture {
    private ConformanceFixture() {}

    static Path resolve(String fixtureName, String ext) throws IOException {
        Path conformanceDir = locateConformanceDir();
        Path configPath = conformanceDir.resolve(fixtureName).resolve("source.json");
        if (!Files.exists(configPath)) {
            throw new IOException("source.json missing: " + configPath);
        }
        String body = Files.readString(configPath);
        Pattern pat = Pattern.compile(
            "\"" + Pattern.quote(ext) + "\"\\s*:\\s*\"([^\"]+)\""
        );
        Matcher m = pat.matcher(body);
        if (!m.find()) {
            throw new IOException(
                "source.json for fixture '" + fixtureName + "' has no entry for " + ext
            );
        }
        Path rel = Paths.get(m.group(1));
        return configPath.getParent().resolve(rel).normalize();
    }

    private static Path locateConformanceDir() throws IOException {
        Path cwd = Paths.get("").toAbsolutePath();
        for (Path p = cwd; p != null; p = p.getParent()) {
            Path candidate = p.resolve("conformance").resolve("tests");
            if (Files.isDirectory(candidate)) return candidate;
        }
        throw new IOException("conformance/tests directory not found above " + cwd);
    }
}
