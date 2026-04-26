package runar.lang.sdk.codegen;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.ForwardingJavaFileManager;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

import org.junit.jupiter.api.Test;

import runar.lang.sdk.RunarArtifact;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Cross-SDK codegen conformance runner — Java side.
 *
 * <p>Loads the shared fixtures from {@code conformance/sdk-codegen/fixtures/}
 * and asserts the typed wrapper this SDK generates contains every
 * structural element required by {@code conformance/sdk-codegen/MANIFEST.md},
 * then compiles the generated source in-memory to catch the kind of bug
 * (undefined-name in generated code) that pure string-pattern tests miss.
 */
class CodegenConformanceTest {

    private static final Path FIXTURES_DIR = locateFixturesDir();

    // ------------------------------------------------------------------
    // p2pkh.json — stateless + Sig param
    // ------------------------------------------------------------------

    @Test
    void p2pkhWrapperContainsRequiredElementsAndCompiles() throws Exception {
        String src = generate("p2pkh.json", "runar.conformance.p2pkh");

        // Structural elements — see MANIFEST.md §"p2pkh.json"
        assertContains(src, "public record P2PKHConstructorArgs(");
        assertContains(src, "public final class P2PKHContract");
        assertContains(src, "public static P2PKHContract fromUtxo(");
        assertContains(src, "public static P2PKHContract fromTxId(");
        assertContains(src, "public void connect(Provider provider, Signer signer)");
        assertContains(src, "public P2PKHContract attachInscription(Inscription insc)");
        assertContains(src, "public String getLockingScript()");
        assertContains(src, "public RunarContract.DeployOutcome deploy(BigInteger satoshis)");
        assertContains(src, "public RunarContract.CallOutcome unlock(PubKey pubKey");
        assertContains(src, "public PreparedCall prepareUnlock(PubKey pubKey");
        assertContains(src, "public RunarContract.CallOutcome finalizeUnlock(PreparedCall prepared, byte[] sig)");
        assertContains(src, "public record TerminalOutput(BigInteger satoshis, String address, String scriptHex)");
        assertFalse(src.contains("StatefulCallOptions"),
            "stateless contract must not emit a StatefulCallOptions record");

        // Compile-check
        compileInMemory("runar.conformance.p2pkh.P2PKHContract", src);
    }

    // ------------------------------------------------------------------
    // counter.json — stateful with non-terminal + terminal methods
    // ------------------------------------------------------------------

    @Test
    void counterWrapperContainsRequiredElementsAndCompiles() throws Exception {
        String src = generate("counter.json", "runar.conformance.counter");

        assertContains(src, "public record CounterConstructorArgs(");
        assertContains(src, "BigInteger count");
        assertContains(src, "public record CounterStatefulCallOptions(");
        assertContains(src, "BigInteger satoshis,");
        assertContains(src, "String changeAddress,");
        assertContains(src, "String changePubKey,");
        assertContains(src, "Map<String, Object> newState,");
        assertContains(src, "List<OutputSpec> outputs");
        assertContains(src, "public record OutputSpec(BigInteger satoshis, Map<String, Object> state)");
        assertContains(src, "public record TerminalOutput(BigInteger satoshis, String address, String scriptHex)");
        assertContains(src, "public final class CounterContract");
        assertContains(src, "public static CounterContract fromUtxo(");
        assertContains(src, "public static CounterContract fromTxId(");
        assertContains(src, "public void connect(Provider provider, Signer signer)");
        assertContains(src, "public RunarContract.CallOutcome increment(BigInteger amount, CounterStatefulCallOptions options)");
        assertContains(src, "public RunarContract.CallOutcome reset(List<TerminalOutput> outputs)");
        assertContains(src, "public BigInteger count()");

        compileInMemory("runar.conformance.counter.CounterContract", src);
    }

    // ------------------------------------------------------------------
    // simple.json — no constructor params
    // ------------------------------------------------------------------

    @Test
    void simpleWrapperContainsRequiredElementsAndCompiles() throws Exception {
        String src = generate("simple.json", "runar.conformance.simple");

        assertFalse(src.contains("SimpleConstructorArgs"),
            "no-args contract must not emit a ConstructorArgs record");
        assertContains(src, "public final class SimpleContract");
        assertContains(src, "public SimpleContract(RunarArtifact artifact)");
        assertContains(src, "public RunarContract.CallOutcome execute(");

        compileInMemory("runar.conformance.simple.SimpleContract", src);
    }

    // ------------------------------------------------------------------
    // stateful-escrow.json — stateful + multi-Sig (the dimension
    // counter.json does not cover).
    // ------------------------------------------------------------------

    @Test
    void escrowWrapperContainsStatefulSigCompanions() throws Exception {
        String src = generate("stateful-escrow.json", "runar.conformance.escrow");

        assertContains(src, "public record EscrowConstructorArgs(");
        // 3 ctor params
        assertContains(src, "PubKey buyer");
        assertContains(src, "PubKey seller");
        assertContains(src, "BigInteger amount");

        assertContains(src, "public record EscrowStatefulCallOptions(");
        assertContains(src, "public record OutputSpec(");
        assertContains(src, "public record TerminalOutput(");

        // Non-terminal stateful with single Sig: claim
        assertContains(src, "public RunarContract.CallOutcome claim(BigInteger amountToClaim, EscrowStatefulCallOptions options)");
        assertContains(src, "public PreparedCall prepareClaim(BigInteger amountToClaim, EscrowStatefulCallOptions options)");
        assertContains(src, "public RunarContract.CallOutcome finalizeClaim(PreparedCall prepared, byte[] buyerSig)");

        // Terminal stateful with two Sigs: release
        assertContains(src, "public RunarContract.CallOutcome release(List<TerminalOutput> outputs)");
        assertContains(src, "public PreparedCall prepareRelease(List<TerminalOutput> outputs)");
        // multi-Sig finalize: signature params appear in ABI order
        assertContains(src, "public RunarContract.CallOutcome finalizeRelease(PreparedCall prepared, byte[] buyerSig, byte[] sellerSig)");

        // State accessor
        assertContains(src, "public BigInteger amount()");

        compileInMemory("runar.conformance.escrow.EscrowContract", src);
    }

    // ------------------------------------------------------------------
    // inscribed.json — verifies attachInscription is callable from
    // user code, not just declared (compile-check at the call site).
    // ------------------------------------------------------------------

    @Test
    void inscribedWrapperAttachInscriptionTypeChecksAtCallSite() throws Exception {
        String src = generate("inscribed.json", "runar.conformance.inscribed");

        assertContains(src, "public record InscribedHolderConstructorArgs(");
        assertContains(src, "Addr owner");
        assertContains(src, "public final class InscribedHolderContract");
        assertContains(src, "public InscribedHolderContract attachInscription(Inscription insc)");
        // transfer + prepare/finalize companions (Sig-bearing)
        assertContains(src, "public RunarContract.CallOutcome transfer(PubKey pubKey, Addr newOwner");
        assertContains(src, "public PreparedCall prepareTransfer(");
        assertContains(src, "public RunarContract.CallOutcome finalizeTransfer(PreparedCall prepared, byte[] sig)");

        // Compile the wrapper alone first.
        compileInMemory("runar.conformance.inscribed.InscribedHolderContract", src);

        // Compile a tiny call-site harness that exercises attachInscription
        // with a real Inscription value — this catches the "method exists
        // but its signature has drifted" failure class that pure string
        // assertions miss.
        String callSite =
            "package runar.conformance.inscribed.callsite;\n"
            + "import runar.conformance.inscribed.InscribedHolderContract;\n"
            + "import runar.lang.sdk.Inscription;\n"
            + "import runar.lang.sdk.RunarArtifact;\n"
            + "import runar.lang.types.Addr;\n"
            + "public final class CallSite {\n"
            + "    public static void exercise(RunarArtifact artifact, Addr owner) {\n"
            + "        var args = new InscribedHolderContract.InscribedHolderConstructorArgs(owner);\n"
            + "        var wrapper = new InscribedHolderContract(artifact, args);\n"
            + "        wrapper.attachInscription(new Inscription(\"text/plain\", \"68656c6c6f\"));\n"
            + "    }\n"
            + "}\n";
        compileTwoSources(
            "runar.conformance.inscribed.InscribedHolderContract", src,
            "runar.conformance.inscribed.callsite.CallSite", callSite);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static String generate(String fixture, String pkg) throws Exception {
        Path file = FIXTURES_DIR.resolve(fixture);
        if (!Files.exists(file)) {
            fail("fixture missing: " + file
                + " — run conformance tests from a checkout that includes "
                + "conformance/sdk-codegen/fixtures/");
        }
        RunarArtifact artifact = RunarArtifact.fromJson(Files.readString(file));
        return TypedContractGenerator.generate(artifact, pkg);
    }

    private static Path locateFixturesDir() {
        // Tests can be launched from either packages/runar-java/ or the repo
        // root depending on how gradle was invoked. Try both.
        Path[] candidates = {
            Paths.get("../../conformance/sdk-codegen/fixtures").toAbsolutePath(),
            Paths.get("conformance/sdk-codegen/fixtures").toAbsolutePath(),
            Paths.get("../../../conformance/sdk-codegen/fixtures").toAbsolutePath(),
        };
        for (Path p : candidates) {
            if (Files.isDirectory(p)) return p;
        }
        // Fallback to relative — fixture loader will fail with a clear message.
        return Paths.get("../../conformance/sdk-codegen/fixtures");
    }

    private static void assertContains(String haystack, String needle) {
        assertTrue(haystack.contains(needle),
            "generated source missing required element:\n--- needle ---\n"
                + needle + "\n--- got ---\n" + haystack);
    }

    /** Compile two source files together so cross-file references type-check. */
    private static void compileTwoSources(
        String fqcn1, String source1,
        String fqcn2, String source2
    ) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull(compiler, "javax.tools.JavaCompiler not available — run on a JDK");

        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        StandardJavaFileManager stdManager = compiler.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8);
        configureClasspath(stdManager);

        InMemoryFileManager fileManager = new InMemoryFileManager(stdManager);
        List<JavaFileObject> files = List.of(
            new InMemorySourceFile(fqcn1, source1),
            new InMemorySourceFile(fqcn2, source2));
        List<String> options = Arrays.asList("-source", "17", "-target", "17");
        JavaCompiler.CompilationTask task = compiler.getTask(
            null, fileManager, diagnostics, options, null, files);

        boolean ok = task.call();
        if (!ok) {
            String errors = diagnostics.getDiagnostics().stream()
                .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
                .map(d -> d.getLineNumber() + ": " + d.getMessage(null))
                .collect(Collectors.joining("\n"));
            fail("conformance: cross-source compile failed:\n" + errors
                + "\n--- " + fqcn1 + " ---\n" + source1
                + "\n--- " + fqcn2 + " ---\n" + source2);
        }
    }

    private static void configureClasspath(StandardJavaFileManager stdManager) throws IOException {
        List<java.io.File> cpEntries = new ArrayList<>();
        for (Class<?> anchor : List.of(
            RunarArtifact.class,
            runar.lang.sdk.RunarContract.class,
            runar.lang.sdk.Provider.class,
            runar.lang.sdk.Signer.class,
            runar.lang.sdk.UTXO.class,
            runar.lang.sdk.PreparedCall.class,
            runar.lang.sdk.Inscription.class,
            runar.lang.types.ByteString.class,
            runar.lang.types.Addr.class,
            runar.lang.types.PubKey.class,
            runar.lang.types.Sig.class,
            TypedContractGenerator.class
        )) {
            java.security.CodeSource cs = anchor.getProtectionDomain().getCodeSource();
            if (cs == null || cs.getLocation() == null) continue;
            try {
                java.io.File f = new java.io.File(cs.getLocation().toURI());
                if (!cpEntries.contains(f)) cpEntries.add(f);
            } catch (Exception ignore) {
                // unreachable
            }
        }
        String runtimeCp = System.getProperty("java.class.path");
        if (runtimeCp != null) {
            for (String entry : runtimeCp.split(java.io.File.pathSeparator)) {
                if (entry.isEmpty()) continue;
                java.io.File f = new java.io.File(entry);
                if (!cpEntries.contains(f)) cpEntries.add(f);
            }
        }
        stdManager.setLocation(javax.tools.StandardLocation.CLASS_PATH, cpEntries);
    }

    private static Class<?> compileInMemory(String fqcn, String source) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull(compiler, "javax.tools.JavaCompiler not available — run on a JDK");

        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        StandardJavaFileManager stdManager = compiler.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8);
        configureClasspath(stdManager);

        InMemoryFileManager fileManager = new InMemoryFileManager(stdManager);
        JavaFileObject file = new InMemorySourceFile(fqcn, source);
        List<String> options = Arrays.asList("-source", "17", "-target", "17");
        JavaCompiler.CompilationTask task = compiler.getTask(
            null, fileManager, diagnostics, options, null, List.of(file));

        boolean ok = task.call();
        if (!ok) {
            String errors = diagnostics.getDiagnostics().stream()
                .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
                .map(d -> d.getLineNumber() + ": " + d.getMessage(null))
                .collect(Collectors.joining("\n"));
            fail("conformance: generated source for " + fqcn + " failed to compile:\n"
                + errors + "\n--- source ---\n" + source);
        }

        return Class.class;
    }

    private static final class InMemorySourceFile extends SimpleJavaFileObject {
        private final String source;

        InMemorySourceFile(String fqcn, String source) {
            super(URI.create("string:///" + fqcn.replace('.', '/') + Kind.SOURCE.extension), Kind.SOURCE);
            this.source = source;
        }

        @Override
        public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            return source;
        }
    }

    private static final class InMemoryClassFile extends SimpleJavaFileObject {
        final ByteArrayOutputStream buf = new ByteArrayOutputStream();

        InMemoryClassFile(String fqcn) {
            super(URI.create("bytes:///" + fqcn.replace('.', '/') + Kind.CLASS.extension), Kind.CLASS);
        }

        @Override
        public java.io.OutputStream openOutputStream() {
            return buf;
        }
    }

    private static final class InMemoryFileManager
        extends ForwardingJavaFileManager<StandardJavaFileManager> {

        final Map<String, InMemoryClassFile> classes = new HashMap<>();

        InMemoryFileManager(StandardJavaFileManager delegate) {
            super(delegate);
        }

        @Override
        public JavaFileObject getJavaFileForOutput(javax.tools.JavaFileManager.Location location,
                                                   String className,
                                                   JavaFileObject.Kind kind, javax.tools.FileObject sibling)
            throws IOException {
            if (kind == JavaFileObject.Kind.CLASS) {
                InMemoryClassFile f = new InMemoryClassFile(className);
                classes.put(className, f);
                return f;
            }
            return super.getJavaFileForOutput(location, className, kind, sibling);
        }
    }
}
