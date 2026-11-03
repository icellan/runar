package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CompileCheckTest {

    /* ------------------------------------------------------------------ */
    /* Happy-path: representative contracts in each format the dispatcher */
    /* must accept. Each one parses + validates + typechecks cleanly.      */
    /* ------------------------------------------------------------------ */

    private static final String VALID_JAVA = String.join(
        "\n",
        "package fixture;",
        "",
        "import runar.lang.SmartContract;",
        "import runar.lang.annotations.Public;",
        "import runar.lang.annotations.Readonly;",
        "import runar.lang.types.Addr;",
        "import runar.lang.types.PubKey;",
        "import runar.lang.types.Sig;",
        "",
        "import static runar.lang.Builtins.assertThat;",
        "import static runar.lang.Builtins.checkSig;",
        "import static runar.lang.Builtins.hash160;",
        "",
        "class P2PKH extends SmartContract {",
        "    @Readonly Addr pubKeyHash;",
        "    P2PKH(Addr pubKeyHash) {",
        "        super(pubKeyHash);",
        "        this.pubKeyHash = pubKeyHash;",
        "    }",
        "    @Public",
        "    void unlock(Sig sig, PubKey pubKey) {",
        "        assertThat(hash160(pubKey).equals(pubKeyHash));",
        "        assertThat(checkSig(sig, pubKey));",
        "    }",
        "}",
        ""
    );

    private static final String VALID_TS = String.join(
        "\n",
        "import { SmartContract, Sig, PubKey, Addr, hash160, checkSig, assert } from 'runar-lang';",
        "",
        "class P2PKH extends SmartContract {",
        "    readonly pubKeyHash: Addr;",
        "    constructor(pubKeyHash: Addr) {",
        "        super(pubKeyHash);",
        "        this.pubKeyHash = pubKeyHash;",
        "    }",
        "    public unlock(sig: Sig, pubKey: PubKey): void {",
        "        assert(hash160(pubKey) === this.pubKeyHash);",
        "        assert(checkSig(sig, pubKey));",
        "    }",
        "}",
        ""
    );

    @Test
    void checkAcceptsValidJavaContract() {
        assertDoesNotThrow(() -> CompileCheck.check(VALID_JAVA, "P2PKH.runar.java"));
    }

    @Test
    void checkAcceptsValidTypeScriptContract() {
        assertDoesNotThrow(() -> CompileCheck.check(VALID_TS, "P2PKH.runar.ts"));
    }

    @Test
    void runReadsFromDiskAndAcceptsValid(@TempDir Path tmp) throws IOException {
        Path file = tmp.resolve("P2PKH.runar.java");
        Files.writeString(file, VALID_JAVA);
        assertDoesNotThrow(() -> CompileCheck.run(file));
    }

    @Test
    void runAndCheckProduceSameOutcomeOnSameSource(@TempDir Path tmp) throws IOException {
        Path file = tmp.resolve("P2PKH.runar.java");
        Files.writeString(file, VALID_JAVA);
        assertDoesNotThrow(() -> CompileCheck.run(file));
        assertDoesNotThrow(() -> CompileCheck.check(VALID_JAVA, "P2PKH.runar.java"));
    }

    /* ------------------------------------------------------------------ */
    /* Parse-error path: malformed source must surface as CompileException */
    /* with a message that points at the parse failure, not a swallowed   */
    /* NullPointerException or UnsupportedOperationException.              */
    /* ------------------------------------------------------------------ */

    @Test
    void checkRejectsMalformedJava() {
        String bad = "this is not java {{{";
        CompileException ex = assertThrows(
            CompileException.class,
            () -> CompileCheck.check(bad, "Bad.runar.java")
        );
        assertTrue(ex.getMessage().toLowerCase().contains("parse"),
            "Expected message to mention parse, got: " + ex.getMessage());
        assertFalse(ex.errors().isEmpty(), "Expected at least one structured error");
    }

    @Test
    void checkRejectsTruncatedSource() {
        // Class declaration with no body — parser should reject.
        String bad = "package x; class Foo extends ";
        CompileException ex = assertThrows(
            CompileException.class,
            () -> CompileCheck.check(bad, "Trunc.runar.java")
        );
        assertNotNull(ex.errors());
    }

    /* ------------------------------------------------------------------ */
    /* Validate-error path: contract violates the Rúnar subset.            */
    /* ------------------------------------------------------------------ */

    @Test
    void checkRejectsContractMissingSuperCall() {
        String missingSuper = String.join(
            "\n",
            "package fixture;",
            "import runar.lang.SmartContract;",
            "import runar.lang.annotations.Public;",
            "import runar.lang.annotations.Readonly;",
            "import runar.lang.types.Addr;",
            "import runar.lang.types.PubKey;",
            "import runar.lang.types.Sig;",
            "import static runar.lang.Builtins.assertThat;",
            "import static runar.lang.Builtins.checkSig;",
            "import static runar.lang.Builtins.hash160;",
            "",
            "class P2PKH extends SmartContract {",
            "    @Readonly Addr pubKeyHash;",
            "    P2PKH(Addr pubKeyHash) {",
            "        this.pubKeyHash = pubKeyHash;",
            "    }",
            "    @Public",
            "    void unlock(Sig sig, PubKey pubKey) {",
            "        assertThat(hash160(pubKey).equals(pubKeyHash));",
            "        assertThat(checkSig(sig, pubKey));",
            "    }",
            "}",
            ""
        );

        CompileException ex = assertThrows(
            CompileException.class,
            () -> CompileCheck.check(missingSuper, "MissingSuper.runar.java")
        );
        assertFalse(ex.errors().isEmpty());
        // The validation pass complains about missing super(...) — match
        // either "super" or "constructor" wording without overspecifying.
        String msg = ex.getMessage().toLowerCase();
        assertTrue(
            msg.contains("super") || msg.contains("constructor"),
            "Expected message to reference super/constructor, got: " + ex.getMessage()
        );
    }

    @Test
    void checkRejectsPublicMethodWithoutTrailingAssert() {
        String noAssert = String.join(
            "\n",
            "package fixture;",
            "import runar.lang.SmartContract;",
            "import runar.lang.annotations.Public;",
            "import runar.lang.annotations.Readonly;",
            "import runar.lang.types.Addr;",
            "",
            "class C extends SmartContract {",
            "    @Readonly Addr a;",
            "    C(Addr a) {",
            "        super(a);",
            "        this.a = a;",
            "    }",
            "    @Public",
            "    void noop() {",
            "        // no trailing assert — Validate must reject",
            "    }",
            "}",
            ""
        );
        assertThrows(CompileException.class,
            () -> CompileCheck.check(noAssert, "NoAssert.runar.java"));
    }

    /* ------------------------------------------------------------------ */
    /* Typecheck-error path: call to a non-Rúnar function is rejected.     */
    /* ------------------------------------------------------------------ */

    @Test
    void checkRejectsCallToUnknownFunction() {
        String unknownCall = String.join(
            "\n",
            "package fixture;",
            "import runar.lang.SmartContract;",
            "import runar.lang.annotations.Public;",
            "import runar.lang.annotations.Readonly;",
            "import runar.lang.types.Addr;",
            "",
            "import static runar.lang.Builtins.assertThat;",
            "",
            "class C extends SmartContract {",
            "    @Readonly Addr a;",
            "    C(Addr a) {",
            "        super(a);",
            "        this.a = a;",
            "    }",
            "    @Public",
            "    void m() {",
            "        Math.floor(3.14);",
            "        assertThat(true);",
            "    }",
            "}",
            ""
        );
        // Either Validate or Typecheck rejects an unknown call. Don't
        // overspecify which pass complains; just assert it's rejected.
        assertThrows(CompileException.class,
            () -> CompileCheck.check(unknownCall, "Unknown.runar.java"));
    }

    /* ------------------------------------------------------------------ */
    /* run(Path) IO failure                                                */
    /* ------------------------------------------------------------------ */

    @Test
    void runRaisesIOExceptionWhenFileMissing(@TempDir Path tmp) {
        Path missing = tmp.resolve("does-not-exist.runar.java");
        assertThrows(IOException.class, () -> CompileCheck.run(missing));
    }

    /* ------------------------------------------------------------------ */
    /* CompileException carries structured error list                      */
    /* ------------------------------------------------------------------ */

    @Test
    void compileExceptionExposesErrorList() {
        String bad = "this won't parse {{{";
        CompileException ex = assertThrows(
            CompileException.class,
            () -> CompileCheck.check(bad, "Bad.runar.java")
        );
        assertNotNull(ex.errors());
        // Error list is immutable.
        assertThrows(UnsupportedOperationException.class,
            () -> ex.errors().add("mutated"));
    }

    @Test
    void compileExceptionMessageLeadsWithFileName() {
        String bad = "broken!!!";
        CompileException ex = assertThrows(
            CompileException.class,
            () -> CompileCheck.check(bad, "MyCustomFile.runar.java")
        );
        assertTrue(ex.getMessage().contains("MyCustomFile.runar.java"),
            "Expected file name in message, got: " + ex.getMessage());
    }

    /* ------------------------------------------------------------------ */
    /* Exact-match round-trip with on-disk example contract — proves the   */
    /* SDK's CompileCheck works against a real shipping artifact.          */
    /* ------------------------------------------------------------------ */

    @Test
    void checkAcceptsExampleP2PKHContract() throws IOException {
        Path example = Path.of(
            System.getProperty("user.dir"),
            "..",
            "..",
            "examples",
            "java",
            "src",
            "main",
            "java",
            "runar",
            "examples",
            "p2pkh",
            "P2PKH.runar.java"
        ).normalize();
        if (!Files.exists(example)) {
            // Examples module not available from this working dir; skip
            // gracefully but record that we tried.
            return;
        }
        assertDoesNotThrow(() -> CompileCheck.run(example));
    }

    /* ------------------------------------------------------------------ */
    /* N-131: CompileCheck.check/run call Validate.run(contract) and       */
    /* discard the warnings it returns, so a validator warning (e.g. an   */
    /* unreferenced readonly field DCE'd out of the on-chain script) never */
    /* surfaces through the Java SDK's compile check. checkWithWarnings   */
    /* (and runWithWarnings) must return that warning without changing    */
    /* check/run's void API or behaviour.                                 */
    /*                                                                     */
    /* What these tests prove: Validate.run's warning list reaches the    */
    /* caller through the new API for at least one concrete warning       */
    /* family (readonly-unused), is empty for a clean contract, and the   */
    /* existing void check()/run() still accept a warning-only contract   */
    /* exactly as before (no behaviour change to the pre-existing API).   */
    /*                                                                     */
    /* What they do NOT prove: that every other warning family Validate   */
    /* can emit (e.g. the sighash SINGLE-covenant warning, or any other   */
    /* d.isWarning() diagnostic) also surfaces — only this one path is    */
    /* exercised, though the fix is generic (it returns whatever          */
    /* Validate.run returns, not this specific message). They also don't  */
    /* prove anything about on-chain bytes: the warning text asserts that */
    /* DCE *will* strip the field per Validate's own diagnostic, not that */
    /* the emitted script bytes actually omit it (that's covered, if at  */
    /* all, by codegen/DCE tests elsewhere). Warning ordering and dedup   */
    /* across multiple simultaneous warnings are untested.                */
    /* ------------------------------------------------------------------ */

    private static final String VALID_JAVA_WITH_UNUSED_READONLY = String.join(
        "\n",
        "package fixture;",
        "",
        "import runar.lang.SmartContract;",
        "import runar.lang.annotations.Public;",
        "import runar.lang.annotations.Readonly;",
        "import runar.lang.types.Addr;",
        "import runar.lang.types.PubKey;",
        "import runar.lang.types.Sig;",
        "import java.math.BigInteger;",
        "",
        "import static runar.lang.Builtins.assertThat;",
        "import static runar.lang.Builtins.checkSig;",
        "import static runar.lang.Builtins.hash160;",
        "",
        "class P2PKH extends SmartContract {",
        "    @Readonly Addr pubKeyHash;",
        "    @Readonly BigInteger nonce;",
        "    P2PKH(Addr pubKeyHash, BigInteger nonce) {",
        "        super(pubKeyHash, nonce);",
        "        this.pubKeyHash = pubKeyHash;",
        "        this.nonce = nonce;",
        "    }",
        "    @Public",
        "    void unlock(Sig sig, PubKey pubKey) {",
        "        assertThat(hash160(pubKey).equals(pubKeyHash));",
        "        assertThat(checkSig(sig, pubKey));",
        "    }",
        "}",
        ""
    );

    @Test
    void checkWithWarningsSurfacesUnreferencedReadonlyFieldWarning() {
        List<String> warnings = CompileCheck.checkWithWarnings(
            VALID_JAVA_WITH_UNUSED_READONLY, "P2PKH.runar.java");
        assertFalse(warnings.isEmpty(), "Expected the unreferenced-readonly-field warning");
        assertTrue(
            warnings.stream().anyMatch(w -> w.contains("nonce") && w.contains("not referenced")),
            "Expected a warning about 'nonce' not being referenced, got: " + warnings
        );
    }

    @Test
    void checkWithWarningsReturnsEmptyListForCleanContract() {
        List<String> warnings = CompileCheck.checkWithWarnings(VALID_JAVA, "P2PKH.runar.java");
        assertTrue(warnings.isEmpty(), "Expected no warnings for a clean contract, got: " + warnings);
    }

    @Test
    void checkWithWarningsStillThrowsOnErrors() {
        String bad = "this is not java {{{";
        assertThrows(CompileException.class,
            () -> CompileCheck.checkWithWarnings(bad, "Bad.runar.java"));
    }

    @Test
    void checkStillAcceptsContractWithWarningsWithoutThrowing() {
        // The existing void API's behaviour must not change: a contract that
        // only produces a warning (no errors) still passes check()/run().
        assertDoesNotThrow(
            () -> CompileCheck.check(VALID_JAVA_WITH_UNUSED_READONLY, "P2PKH.runar.java"));
    }

    @Test
    void runWithWarningsSurfacesWarningFromDisk(@TempDir Path tmp) throws IOException {
        Path file = tmp.resolve("P2PKH.runar.java");
        Files.writeString(file, VALID_JAVA_WITH_UNUSED_READONLY);
        List<String> warnings = CompileCheck.runWithWarnings(file);
        assertTrue(
            warnings.stream().anyMatch(w -> w.contains("nonce") && w.contains("not referenced")),
            "Expected a warning about 'nonce' not being referenced, got: " + warnings
        );
    }

    @Test
    void runStillAcceptsContractWithWarningsWithoutThrowing(@TempDir Path tmp) throws IOException {
        Path file = tmp.resolve("P2PKH.runar.java");
        Files.writeString(file, VALID_JAVA_WITH_UNUSED_READONLY);
        assertDoesNotThrow(() -> CompileCheck.run(file));
    }

    @Test
    void roundTripsThroughCheckThenRun(@TempDir Path tmp) throws IOException {
        // 1) check(source, filename) succeeds
        assertDoesNotThrow(() -> CompileCheck.check(VALID_JAVA, "P2PKH.runar.java"));
        // 2) writing the same source to disk and running run() also succeeds
        Path file = tmp.resolve("P2PKH.runar.java");
        Files.writeString(file, VALID_JAVA);
        assertDoesNotThrow(() -> CompileCheck.run(file));
        // 3) modifying disk content to invalid still surfaces as CompileException
        Files.writeString(file, "garbage");
        assertThrows(CompileException.class, () -> CompileCheck.run(file));
        // 4) file size unchanged after check (no side-effects on source)
        long before = Files.size(file);
        try {
            CompileCheck.run(file);
        } catch (CompileException ignored) {
            // expected
        }
        assertEquals(before, Files.size(file));
    }
}
