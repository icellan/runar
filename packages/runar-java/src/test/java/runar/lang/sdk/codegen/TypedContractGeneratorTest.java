package runar.lang.sdk.codegen;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.ForwardingJavaFileManager;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileManager;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

import org.junit.jupiter.api.Test;

import runar.lang.sdk.PreparedCall;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarArtifact.ABI;
import runar.lang.sdk.RunarArtifact.ABIConstructor;
import runar.lang.sdk.RunarArtifact.ABIMethod;
import runar.lang.sdk.RunarArtifact.ABIParam;
import runar.lang.sdk.RunarArtifact.StateField;
import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class TypedContractGeneratorTest {

    // ---------------------------------------------------------------------
    // P2PKH (stateless, has Sig param) — checks constructor record,
    // typed unlock(), prepareUnlock/finalizeUnlock companions.
    // ---------------------------------------------------------------------

    @Test
    void generatesExpectedP2pkhSource() {
        RunarArtifact artifact = buildP2PKHArtifact();
        String src = TypedContractGenerator.generate(artifact, "runar.generated.p2pkh");

        // Check the major shape elements (full golden is fragile across formatting changes;
        // assert each contract of the generated source instead).
        assertContains(src, "package runar.generated.p2pkh;");
        assertContains(src, "public final class P2PKHContract {");
        assertContains(src, "public record P2PKHConstructorArgs(");
        assertContains(src, "Addr pubKeyHash");
        assertContains(src, "public P2PKHContract(RunarArtifact artifact, P2PKHConstructorArgs args)");
        assertContains(src, "ctorArgs.add(args.pubKeyHash().toHex());");
        assertContains(src, "private P2PKHContract(RunarContract inner)");
        assertContains(src, "public static P2PKHContract fromUtxo(");
        assertContains(src, "public static P2PKHContract fromTxId(");
        assertContains(src, "public void connect(Provider provider, Signer signer)");
        assertContains(src, "public P2PKHContract attachInscription(Inscription insc)");
        assertContains(src, "public String getLockingScript()");
        assertContains(src, "public RunarContract.DeployOutcome deploy(BigInteger satoshis)");
        // Terminal method: stateless ⇒ outputs?: TerminalOutput[] (optional)
        assertContains(src, "public RunarContract.CallOutcome unlock(PubKey pubKey, List<TerminalOutput> outputs)");
        assertContains(src, "public RunarContract.CallOutcome unlock(PubKey pubKey)");
        // Sig is hidden — its slot is filled with null in the SDK args
        assertContains(src, "callArgs.add(null); // Sig auto-computed by SDK");
        assertContains(src, "callArgs.add(pubKey.toHex());");
        // prepare/finalize
        assertContains(src, "public PreparedCall prepareUnlock(PubKey pubKey, List<TerminalOutput> outputs)");
        assertContains(src, "public PreparedCall prepareUnlock(PubKey pubKey)");
        assertContains(src, "public RunarContract.CallOutcome finalizeUnlock(PreparedCall prepared, byte[] sig)");
        assertContains(src, "sigs.add(sig);");
        assertContains(src, "return inner.finalizeCall(prepared, sigs, provider);");
        // No stateful options surface for stateless contracts
        assertFalse(src.contains("StatefulCallOptions"),
            "stateless contract must not emit a StatefulCallOptions record");
    }

    @Test
    void generatedP2pkhCompilesCleanly() throws Exception {
        RunarArtifact artifact = buildP2PKHArtifact();
        String src = TypedContractGenerator.generate(artifact, "runar.generated.p2pkh");
        Class<?> cls = compileInMemory("runar.generated.p2pkh.P2PKHContract", src);
        assertEquals("P2PKHContract", cls.getSimpleName());
    }

    @Test
    void generatedConstructorTakesArtifactAndArgsRecord() throws Exception {
        RunarArtifact artifact = buildP2PKHArtifact();
        String src = TypedContractGenerator.generate(artifact, "runar.generated.p2pkh");
        Class<?> cls = compileInMemory("runar.generated.p2pkh.P2PKHContract", src);

        Constructor<?>[] ctors = cls.getDeclaredConstructors();
        // Public constructor (artifact, args) + private(RunarContract) factory
        // helper. assert by inspection.
        Constructor<?> publicCtor = null;
        for (Constructor<?> c : ctors) {
            if (java.lang.reflect.Modifier.isPublic(c.getModifiers())) {
                publicCtor = c; break;
            }
        }
        assertNotNull(publicCtor, "expected a public constructor");
        Class<?>[] params = publicCtor.getParameterTypes();
        assertEquals(2, params.length, "constructor should take (artifact, args)");
        assertEquals(RunarArtifact.class, params[0]);
        // Args record is a nested type on the wrapper itself
        assertEquals("P2PKHConstructorArgs", params[1].getSimpleName());
    }

    @Test
    void generatedP2pkhUnlockReturnsCallOutcomeWithoutSig() throws Exception {
        RunarArtifact artifact = buildP2PKHArtifact();
        String src = TypedContractGenerator.generate(artifact, "runar.generated.p2pkh");
        Class<?> cls = compileInMemory("runar.generated.p2pkh.P2PKHContract", src);

        // unlock(pubKey) — convenience overload (no outputs)
        Method unlock = cls.getDeclaredMethod("unlock", PubKey.class);
        assertEquals("CallOutcome", unlock.getReturnType().getSimpleName(),
            "stateless terminal methods now return CallOutcome (parity with TS CallResult)");

        for (Method m : cls.getDeclaredMethods()) {
            if ("unlock".equals(m.getName())) {
                assertFalse(Arrays.asList(m.getParameterTypes()).contains(Sig.class),
                    "unlock() must not declare a Sig parameter");
            }
        }
    }

    @Test
    void p2pkhExposesConnectAndFromFactories() throws Exception {
        RunarArtifact artifact = buildP2PKHArtifact();
        String src = TypedContractGenerator.generate(artifact, "runar.generated.p2pkh");
        Class<?> cls = compileInMemory("runar.generated.p2pkh.P2PKHContract", src);

        Method connect = cls.getDeclaredMethod("connect",
            runar.lang.sdk.Provider.class, runar.lang.sdk.Signer.class);
        assertEquals(void.class, connect.getReturnType());

        Method fromUtxo = cls.getDeclaredMethod("fromUtxo",
            RunarArtifact.class, runar.lang.sdk.UTXO.class);
        assertEquals(cls, fromUtxo.getReturnType(), "fromUtxo returns the wrapper type");

        Method fromTxId = cls.getDeclaredMethod("fromTxId",
            RunarArtifact.class, String.class, int.class, runar.lang.sdk.Provider.class);
        assertEquals(cls, fromTxId.getReturnType(), "fromTxId returns the wrapper type");
    }

    @Test
    void p2pkhPrepareAndFinalizeUnlockExist() throws Exception {
        RunarArtifact artifact = buildP2PKHArtifact();
        String src = TypedContractGenerator.generate(artifact, "runar.generated.p2pkh");
        Class<?> cls = compileInMemory("runar.generated.p2pkh.P2PKHContract", src);

        Method prepare = cls.getDeclaredMethod("prepareUnlock", PubKey.class);
        assertEquals(PreparedCall.class, prepare.getReturnType(),
            "prepareX returns PreparedCall");

        Method finalize_ = cls.getDeclaredMethod("finalizeUnlock", PreparedCall.class, byte[].class);
        assertEquals("CallOutcome", finalize_.getReturnType().getSimpleName(),
            "finalizeX returns CallOutcome");
    }

    // ---------------------------------------------------------------------
    // Counter (stateful, non-terminal increment + terminal reset)
    // ---------------------------------------------------------------------

    @Test
    void generatesTypedStatefulCounterWrapper() throws Exception {
        RunarArtifact artifact = buildCounterArtifact();
        String src = TypedContractGenerator.generate(artifact, "runar.generated.counter");
        Class<?> cls = compileInMemory("runar.generated.counter.CounterContract", src);

        // Stateful options struct
        assertContains(src, "public record CounterStatefulCallOptions(");
        assertContains(src, "BigInteger satoshis,");
        assertContains(src, "String changeAddress,");
        assertContains(src, "String changePubKey,");
        assertContains(src, "Map<String, Object> newState,");
        assertContains(src, "List<OutputSpec> outputs");

        // Non-terminal stateful method takes options
        Method increment = cls.getDeclaredMethod("increment",
            BigInteger.class, cls.getDeclaredClasses()[indexOfNested(cls, "CounterStatefulCallOptions")]);
        assertEquals("CallOutcome", increment.getReturnType().getSimpleName(),
            "stateful non-terminal must return CallOutcome");

        // Terminal stateful method takes outputs
        Method reset = cls.getDeclaredMethod("reset", List.class);
        assertEquals("CallOutcome", reset.getReturnType().getSimpleName(),
            "stateful terminal must return CallOutcome");

        // Convenience overload: increment(amount) (no options)
        Method incrementSimple = cls.getDeclaredMethod("increment", BigInteger.class);
        assertEquals("CallOutcome", incrementSimple.getReturnType().getSimpleName());

        // State accessor
        Method count = cls.getDeclaredMethod("count");
        assertEquals(BigInteger.class, count.getReturnType());
    }

    @Test
    void generatedCounterWrapperCompilesCleanly() throws Exception {
        RunarArtifact artifact = buildCounterArtifact();
        String src = TypedContractGenerator.generate(artifact, "runar.generated.counter");
        Class<?> cls = compileInMemory("runar.generated.counter.CounterContract", src);
        assertNotNull(cls);
    }

    @Test
    void counterIncrementHasPrepareAndFinalizeBecauseSigParamPresent() throws Exception {
        // The Counter increment() method here has a Sig param to exercise
        // prepare/finalize on a stateful non-terminal method.
        RunarArtifact artifact = buildCounterWithSigArtifact();
        String src = TypedContractGenerator.generate(artifact, "runar.generated.countersig");
        assertContains(src, "public PreparedCall prepareIncrement(");
        assertContains(src, "public RunarContract.CallOutcome finalizeIncrement(PreparedCall prepared, byte[] sig)");
        compileInMemory("runar.generated.countersig.CounterContract", src);
    }

    // ---------------------------------------------------------------------
    // No-args contract — confirms parameterless constructor path.
    // ---------------------------------------------------------------------

    @Test
    void noArgsContractEmitsParameterlessConstructor() throws Exception {
        RunarArtifact artifact = buildNoArgsArtifact();
        String src = TypedContractGenerator.generate(artifact, "runar.generated.simple");
        assertContains(src, "public SimpleContract(RunarArtifact artifact)");
        assertFalse(src.contains("SimpleConstructorArgs"),
            "no constructor params ⇒ no ConstructorArgs record");
        compileInMemory("runar.generated.simple.SimpleContract", src);
    }

    // ---------------------------------------------------------------------
    // Default-package overload
    // ---------------------------------------------------------------------

    @Test
    void generateWithDefaultPackageUsesRunarGeneratedContracts() {
        String src = TypedContractGenerator.generate(buildP2PKHArtifact());
        assertContains(src, "package runar.generated.contracts;");
    }

    // ---------------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------------

    private static RunarArtifact buildP2PKHArtifact() {
        ABIConstructor ctor = new ABIConstructor(List.of(
            new ABIParam("pubKeyHash", "Addr", null)
        ));
        ABIMethod unlock = new ABIMethod(
            "unlock",
            List.of(
                new ABIParam("sig", "Sig", null),
                new ABIParam("pubKey", "PubKey", null)
            ),
            true, null
        );
        return new RunarArtifact(
            "runar-v0.1.0", "0.1.0", "P2PKH",
            new ABI(ctor, List.of(unlock)),
            "a9007c7c9c69007c7cac69",
            "OP_HASH160 OP_0 OP_SWAP OP_SWAP OP_NUMEQUAL OP_VERIFY OP_0 OP_SWAP OP_SWAP OP_CHECKSIG OP_VERIFY",
            "2026-04-24T00:00:00Z",
            null, null, null, null, null
        );
    }

    /**
     * Stateful Counter, no-Sig variant: increment is non-terminal, reset is terminal.
     */
    private static RunarArtifact buildCounterArtifact() {
        ABIConstructor ctor = new ABIConstructor(List.of(
            new ABIParam("count", "bigint", null)
        ));
        ABIMethod increment = new ABIMethod(
            "increment",
            List.of(
                new ABIParam("amount", "bigint", null),
                new ABIParam("txPreimage", "SigHashPreimage", null),
                new ABIParam("_changePKH", "ByteString", null),
                new ABIParam("_changeAmount", "bigint", null)
            ),
            true,
            false
        );
        ABIMethod reset = new ABIMethod(
            "reset",
            List.of(
                new ABIParam("txPreimage", "SigHashPreimage", null)
            ),
            true,
            true
        );
        return new RunarArtifact(
            "runar-v0.1.0", "0.1.0", "Counter",
            new ABI(ctor, List.of(increment, reset)),
            "76009c63",
            "OP_DUP OP_0 OP_NUMEQUAL OP_IF",
            "2026-04-24T00:00:00Z",
            List.of(new StateField("count", "bigint", 0, null, null)),
            null, null, null, null
        );
    }

    /**
     * Stateful Counter where increment additionally has a Sig param, so
     * the generator emits prepare/finalize companions on a non-terminal
     * stateful method.
     */
    private static RunarArtifact buildCounterWithSigArtifact() {
        ABIConstructor ctor = new ABIConstructor(List.of(
            new ABIParam("count", "bigint", null)
        ));
        ABIMethod increment = new ABIMethod(
            "increment",
            List.of(
                new ABIParam("amount", "bigint", null),
                new ABIParam("sig", "Sig", null),
                new ABIParam("txPreimage", "SigHashPreimage", null),
                new ABIParam("_changePKH", "ByteString", null),
                new ABIParam("_changeAmount", "bigint", null)
            ),
            true,
            false
        );
        return new RunarArtifact(
            "runar-v0.1.0", "0.1.0", "Counter",
            new ABI(ctor, List.of(increment)),
            "76009c63",
            "OP_DUP OP_0 OP_NUMEQUAL OP_IF",
            "2026-04-24T00:00:00Z",
            List.of(new StateField("count", "bigint", 0, null, null)),
            null, null, null, null
        );
    }

    private static RunarArtifact buildNoArgsArtifact() {
        ABIConstructor ctor = new ABIConstructor(List.of());
        ABIMethod execute = new ABIMethod("execute", List.of(), true, null);
        return new RunarArtifact(
            "runar-v0.1.0", "0.1.0", "Simple",
            new ABI(ctor, List.of(execute)),
            "00",
            "OP_0",
            "2026-04-24T00:00:00Z",
            null, null, null, null, null
        );
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private static int indexOfNested(Class<?> outer, String simpleName) {
        Class<?>[] nested = outer.getDeclaredClasses();
        for (int i = 0; i < nested.length; i++) {
            if (simpleName.equals(nested[i].getSimpleName())) return i;
        }
        throw new AssertionError("nested class " + simpleName + " not found on " + outer.getName()
            + " (have: " + Arrays.stream(nested).map(Class::getSimpleName).toList() + ")");
    }

    private static void assertContains(String haystack, String needle) {
        assertTrue(haystack.contains(needle),
            "expected generated source to contain:\n--- needle ---\n" + needle
                + "\n--- got ---\n" + haystack);
    }

    // ---------------------------------------------------------------------
    // In-memory Java compilation harness (unchanged from prior version)
    // ---------------------------------------------------------------------

    private static Class<?> compileInMemory(String fqcn, String source) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull(compiler,
            "javax.tools.JavaCompiler not available — run tests on a JDK (not a JRE)");

        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        StandardJavaFileManager stdManager = compiler.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8);

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
                // unreachable in test context
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

        InMemoryFileManager fileManager = new InMemoryFileManager(stdManager);

        JavaFileObject file = new InMemorySourceFile(fqcn, source);
        List<String> options = Arrays.asList("-source", "17", "-target", "17");
        JavaCompiler.CompilationTask task = compiler.getTask(
            null, fileManager, diagnostics, options, null, List.of(file)
        );

        boolean ok = task.call();
        if (!ok) {
            String errors = diagnostics.getDiagnostics().stream()
                .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
                .map(d -> d.getLineNumber() + ": " + d.getMessage(null))
                .collect(Collectors.joining("\n"));
            fail("generated source failed to compile:\n" + errors + "\n--- source ---\n" + source);
        }

        InMemoryClassLoader loader = new InMemoryClassLoader(
            TypedContractGeneratorTest.class.getClassLoader(), fileManager.classes
        );
        return loader.loadClass(fqcn);
    }

    private static final class InMemorySourceFile extends SimpleJavaFileObject {
        private final String source;

        InMemorySourceFile(String fqcn, String source) {
            super(URI.create("string:///" + fqcn.replace('.', '/') + Kind.SOURCE.extension),
                Kind.SOURCE);
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
            super(URI.create("bytes:///" + fqcn.replace('.', '/') + Kind.CLASS.extension),
                Kind.CLASS);
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
        public JavaFileObject getJavaFileForOutput(Location location, String className,
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

    private static final class InMemoryClassLoader extends ClassLoader {
        private final Map<String, InMemoryClassFile> classes;

        InMemoryClassLoader(ClassLoader parent, Map<String, InMemoryClassFile> classes) {
            super(parent);
            this.classes = classes;
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            InMemoryClassFile f = classes.get(name);
            if (f == null) throw new ClassNotFoundException(name);
            byte[] bytes = f.buf.toByteArray();
            return defineClass(name, bytes, 0, bytes.length);
        }
    }

    @SuppressWarnings("unused")
    private static final Object KEEP_IMPORTS = Collections.unmodifiableList(new ArrayList<Object>());
}
