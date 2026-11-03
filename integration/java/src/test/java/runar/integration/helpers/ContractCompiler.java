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
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.SimulatedSpend;

/**
 * Compiles a contract source file to a {@link RunarArtifact} using the
 * native Java compiler (compilers/java), in-process via
 * {@link SimulatedSpend#compile}.
 *
 * <p><b>F-276.</b> This class used to shell out to the TypeScript reference
 * compiler for every source, because compilers/java's CLI emitted only the
 * ANF IR and Bitcoin Script hex — no full deployable artifact (ABI,
 * stateFields, constructorSlots, codeSeparatorIndex, ...), so Java
 * integration was never actually exercising the native Java compiler on a
 * node. That gap closed when the CLI's {@code --emit-artifact} path (R-007)
 * started regrouping {@code fixedArray} state fields and constructor params
 * (N-086 / N-229), giving the Java compiler a full artifact.
 *
 * <p>An offline proof ({@code tests/f276-integration-source-parity.test.ts})
 * compiles every source path this integration suite references with both
 * the native Java compiler and the TS reference compiler and diffs the
 * resulting {@code script} hex: every one matches byte-for-byte. The one
 * exception is {@code StateCovenant} (both the {@code .java} and
 * {@code .ts} source) — the Java compiler deliberately refuses it, because
 * it calls {@code bbFieldMul}, a BabyBear builtin that is Go-only by
 * project policy (see CLAUDE.md "Go-only crypto codegen modules";
 * {@code conformance/tests/state-covenant/source.json} allowlists only
 * {@code ["go"]}). That one contract still compiles through the TS
 * reference compiler — a named, documented exception, not a silent
 * catch-all fallback.
 */
public final class ContractCompiler {

    private ContractCompiler() {}

    /**
     * Sources the native Java compiler refuses by design (see class
     * javadoc). Paths are project-root-relative, POSIX-separated. Compiled
     * via the TS reference compiler instead of the native Java compiler.
     */
    private static final Set<String> TS_REFERENCE_ONLY = Set.of(
        "examples/java/src/main/java/runar/examples/state-covenant/StateCovenant.runar.java",
        "examples/ts/state-covenant/StateCovenant.runar.ts"
    );

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
     * Process-wide cache: every test class compiles a small set of contracts,
     * and most {@code @Test} methods within a class re-compile the same
     * source. The cache amortises one compile per unique absolute path,
     * eliminating repeat compiler start-up cost.
     *
     * The cache lives for the lifetime of the test JVM (forked once per
     * Gradle test task). Concurrent {@code computeIfAbsent} ensures parallel
     * test execution doesn't fan-out into duplicate compiles.
     */
    private static final Map<Path, RunarArtifact> CACHE = new ConcurrentHashMap<>();

    /** Resolved tsx loader (file URL) — cached so the resolver runs once. */
    private static volatile String tsxLoaderUrl;

    /**
     * Compiles a contract source file relative to the project root
     * (e.g. {@code examples/java/src/main/java/runar/examples/p2pkh/P2PKH.runar.java})
     * and returns the parsed {@link RunarArtifact}.
     */
    public static RunarArtifact compileRelative(String relPath) {
        Path abs = projectRoot().resolve(relPath).normalize();
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
        Path key = absPath.toAbsolutePath().normalize();
        return CACHE.computeIfAbsent(key, ContractCompiler::doCompile);
    }

    /**
     * Compiles an out-of-tree source (a test's inline contract) with the TS
     * reference compiler. The second named exception: MerkleProofIntegrationTest
     * calls {@code merkleRootSha256}, a sha256-Merkle builtin the Java compiler
     * deliberately refuses (Go-only by project policy,
     * {@code conformance/tests/merkle-proof/source.json} allowlists only
     * {@code ["go"]}), so it cannot go through {@link #compileAbsolute}.
     */
    public static RunarArtifact compileAbsoluteWithTsReference(Path absPath) {
        Path key = absPath.toAbsolutePath().normalize();
        return CACHE.computeIfAbsent(key, ContractCompiler::doCompileWithTsReferenceCompiler);
    }

    private static RunarArtifact doCompile(Path absPath) {
        Path root = projectRoot();
        String relPath = root.relativize(absPath).toString().replace(File.separatorChar, '/');
        if (TS_REFERENCE_ONLY.contains(relPath)) {
            return doCompileWithTsReferenceCompiler(absPath);
        }
        try {
            return SimulatedSpend.compile(absPath);
        } catch (IOException e) {
            throw new RuntimeException(
                "ContractCompiler: native Java compile failed for " + absPath + ": " + e.getMessage(), e
            );
        }
    }

    /**
     * Compiles {@code absPath} with the TS reference compiler via
     * {@code node --import <tsx-loader>} running the project-local
     * {@code runar-cli} package. Reserved for the named exceptions in
     * {@link #TS_REFERENCE_ONLY} — see the class javadoc.
     */
    private static RunarArtifact doCompileWithTsReferenceCompiler(Path absPath) {
        Path root = projectRoot();
        Path outDir;
        try {
            outDir = Files.createTempDirectory("runar-java-integration-");
        } catch (IOException e) {
            throw new RuntimeException("ContractCompiler: cannot create temp dir: " + e.getMessage(), e);
        }

        List<String> cmd = new ArrayList<>();
        cmd.add("node");
        cmd.add("--import");
        cmd.add(getTsxLoader(root));
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

        // The CLI writes <outDir>/<baseName>.json.
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

    /**
     * Locate the tsx loader entry as a {@code file://} URL so it can be
     * passed to {@code node --import}. tsx is hoisted under
     * {@code conformance/node_modules} (pnpm doesn't dedupe to the repo
     * root). We probe the known locations and fall back to the literal
     * string {@code "tsx"} (which only resolves when run from a directory
     * whose node_modules contains tsx).
     */
    private static String getTsxLoader(Path root) {
        String cached = tsxLoaderUrl;
        if (cached != null) return cached;
        Path[] candidates = new Path[] {
            root.resolve("conformance/node_modules/tsx/dist/loader.mjs"),
            root.resolve("node_modules/tsx/dist/loader.mjs"),
            root.resolve("integration/ts/node_modules/tsx/dist/loader.mjs"),
        };
        for (Path p : candidates) {
            if (Files.exists(p)) {
                String url = p.toUri().toString();
                tsxLoaderUrl = url;
                return url;
            }
        }
        // Fall back to the bare specifier — Node will resolve it via the
        // working-directory node_modules tree.
        tsxLoaderUrl = "tsx";
        return "tsx";
    }
}
