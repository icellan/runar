package runar.integration.helpers;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import runar.lang.sdk.RunarArtifact;

/**
 * Compiles a contract source file to a {@link RunarArtifact} using the
 * TypeScript reference compiler via {@code npx tsx}.
 *
 * <p>Why the TS reference compiler? Every SDK in this repo (including
 * {@code runar-go}, {@code runar-rs}, {@code runar-py}) needs a <i>full</i>
 * artifact (ABI, stateFields, constructorSlots, codeSeparatorIndex,
 * ...) to deploy and call. The native-Java compiler at
 * {@code compilers/java} currently emits only the ANF IR and Bitcoin
 * Script hex via its CLI (M4 + M5); full artifact emission is not yet
 * wired (it lands in M8 along with the SDK integration).
 *
 * <p>To keep the integration suite unblocked today, we shell out to the
 * TS compiler — the canonical reference implementation that all six
 * other compilers are byte-matched against. Once M8 wires the full
 * artifact emitter into the Java compiler CLI, swap the subprocess for a
 * {@code runar-java --artifact ...} invocation.
 *
 * <p>The TS compiler is invoked through the project-local
 * {@code runar-cli} package (run via {@code npx tsx}), which expects a
 * file on disk. We write the source to a temp file named after the
 * logical file name so the parser dispatch picks the right frontend
 * (e.g. {@code .runar.java} routes to the Java parser, {@code .runar.ts}
 * to the TS parser).
 */
public final class ContractCompiler {

    private ContractCompiler() {}

    /**
     * Resolves the project root relative to {@code integration/java/}.
     * Running the tests from any working directory is supported because
     * Gradle sets {@code user.dir} to the Gradle project dir, not the
     * shell CWD.
     */
    public static Path projectRoot() {
        Path here = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        // integration/java -> ../../
        Path candidate = here.resolve("../..").normalize();
        // Heuristic: the project root contains packages/runar-java/.
        if (Files.isDirectory(candidate.resolve("packages/runar-java"))) {
            return candidate;
        }
        // Fallback: walk up until we find it (for direct IDE runs).
        Path p = here;
        for (int i = 0; i < 8 && p != null; i++) {
            if (Files.isDirectory(p.resolve("packages/runar-java"))) {
                return p;
            }
            p = p.getParent();
        }
        throw new IllegalStateException(
            "ContractCompiler: cannot locate project root from " + here
        );
    }

    /**
     * Compiles a contract source file relative to the project root
     * (e.g. {@code examples/java/src/main/java/runar/examples/p2pkh/P2PKH.runar.java})
     * and returns the parsed {@link RunarArtifact}.
     */
    public static RunarArtifact compileRelative(String relPath) {
        Path abs = projectRoot().resolve(relPath);
        if (!Files.exists(abs)) {
            throw new IllegalArgumentException(
                "ContractCompiler: source not found: " + abs
            );
        }
        return compileAbsolute(abs);
    }

    /**
     * Compiles a contract source file at an absolute path and returns
     * the parsed {@link RunarArtifact}. The file name's extension
     * (including the compound {@code .runar.X} pattern) selects the
     * parser frontend.
     */
    public static RunarArtifact compileAbsolute(Path absPath) {
        Path root = projectRoot();
        Path outDir;
        try {
            outDir = Files.createTempDirectory("runar-java-integration-");
        } catch (IOException e) {
            throw new RuntimeException("ContractCompiler: cannot create temp dir: " + e.getMessage(), e);
        }

        String fileName = absPath.getFileName().toString();
        // TS CLI strips the final extension, but we want the resulting JSON to be
        // predictable. For .runar.java sources the CLI writes "<Name>.runar.json".
        String baseName = fileName;
        int dot = baseName.lastIndexOf('.');
        if (dot > 0) baseName = baseName.substring(0, dot);

        List<String> cmd = new ArrayList<>();
        cmd.add("npx");
        cmd.add("tsx");
        cmd.add(root.resolve("packages/runar-cli/src/bin.ts").toString());
        cmd.add("compile");
        cmd.add(absPath.toString());
        cmd.add("-o");
        cmd.add(outDir.toString());

        ProcessBuilder pb = new ProcessBuilder(cmd)
            .directory(root.toFile())
            .redirectErrorStream(true);
        // Allow the tsx subprocess to find node on macOS / Linux paths.
        pb.environment().putIfAbsent("PATH", System.getenv("PATH"));

        StringBuilder output = new StringBuilder();
        int exit;
        try {
            Process p = pb.start();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    output.append(line).append('\n');
                }
            }
            exit = p.waitFor();
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("ContractCompiler: subprocess failed: " + e.getMessage(), e);
        }
        if (exit != 0) {
            throw new RuntimeException(
                "ContractCompiler: TS compiler failed (exit " + exit + "):\n" + output
            );
        }

        // The CLI writes <outDir>/<baseName>.json. For .runar.java, baseName
        // still contains the ".runar" suffix because we split on the last dot.
        File[] files = outDir.toFile().listFiles((dir, name) -> name.endsWith(".json"));
        if (files == null || files.length == 0) {
            throw new RuntimeException(
                "ContractCompiler: TS compiler produced no .json artifact in " + outDir
                    + "\nCompiler output:\n" + output
            );
        }
        // Deterministic pick: newest file (tests may re-use the same outDir).
        File artifactFile = files[0];
        for (File f : files) if (f.lastModified() > artifactFile.lastModified()) artifactFile = f;

        String json;
        try {
            json = Files.readString(artifactFile.toPath());
        } catch (IOException e) {
            throw new RuntimeException(
                "ContractCompiler: cannot read artifact " + artifactFile + ": " + e.getMessage(), e
            );
        }

        return RunarArtifact.fromJson(json);
    }
}
