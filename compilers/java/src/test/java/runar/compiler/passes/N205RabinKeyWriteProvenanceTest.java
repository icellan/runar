package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;

/**
 * N-205 — a stateful method must not write a spender-supplied value into a
 * MUTABLE property that verifyRabinSig uses as its public key (a), and the
 * {@code --ir} loader re-asserts F-286 + (a) on ANF input (b). Port of the TS
 * reference (02-validate.ts {@code checkRabinPubKeyProvenance} and
 * ir/rabin-key-provenance.ts).
 *
 * <p>What this proves: the Java-tier validator refuses the write shapes
 * (parameter, alias, compound assignment, ++, if-arm, addOutput slot, private
 * setter fed a parameter, key via a helper, a property feeding the key written
 * from a parameter) and accepts literal / property / non-key writes, on the TS,
 * Java and bare-Solidity surfaces; and the IR loader refuses a load_param key
 * and a load_param write into the key while loading the oracle-price golden.
 *
 * <p>What it does NOT prove: the other tiers or the full IR corpus
 * (conformance/negatives/ir-rabin-key-provenance.test.ts covers both), or
 * anything about an addRawOutput whose script bytes the spender supplies.
 */
class N205RabinKeyWriteProvenanceTest {

    private static String msg(String prop) {
        return "verifyRabinSig public key property '" + prop + "' may only be assigned a contract property or a literal "
            + "outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature";
    }

    private static final String DEFAULT_SETTLE = "verifyRabinSig(msg, sig, padding, this.key)";

    private static String wrap(String rotateBody, String extraMethods, String settleCheck) {
        return """
            import { StatefulSmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

            class C extends StatefulSmartContract {
              key: RabinPubKey;
              other: RabinPubKey;
              count: bigint;
              readonly backup: RabinPubKey;

              constructor(key: RabinPubKey, other: RabinPubKey, count: bigint, backup: RabinPubKey) {
                super(key, other, count, backup);
                this.key = key;
                this.other = other;
                this.count = count;
                this.backup = backup;
              }

              public settle(msg: ByteString, sig: RabinSig, padding: ByteString) {
                assert(%s);
              }

              public rotate(newKey: RabinPubKey, n: bigint) {
            %s
                assert(true);
              }
            %s
            }
            """.formatted(settleCheck, rotateBody, extraMethods);
    }

    private static String wrap(String rotateBody) {
        return wrap(rotateBody, "", DEFAULT_SETTLE);
    }

    private static final String SETTER = """
          private setKey(v: RabinPubKey): void {
            this.key = v;
          }
        """;

    private static final String CHECK = """
          private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
            return verifyRabinSig(m, s, p, k);
          }
        """;

    private static List<String> errorsOf(String source, String fileName) throws Exception {
        ContractNode c = ParserDispatch.parse(source, fileName);
        return Validate.runCollecting(c).errors();
    }

    private static void assertRefused(String source, String fileName, String prop) throws Exception {
        List<String> errs = errorsOf(source, fileName);
        assertTrue(errs.stream().anyMatch(e -> e.contains(msg(prop))), "expected N-205 refusal, got " + errs);
    }

    private static void assertAccepted(String source, String fileName) throws Exception {
        assertEquals(List.of(), errorsOf(source, fileName));
    }

    // -- refused ---------------------------------------------------------------

    @Test void assignedPublicParamRefused() throws Exception { assertRefused(wrap("    this.key = newKey;"), "C.runar.ts", "key"); }

    @Test void assignedAliasOfParamRefused() throws Exception {
        assertRefused(wrap("    const k = newKey;\n    this.key = k;"), "C.runar.ts", "key");
    }

    @Test void compoundAssignmentRefused() throws Exception { assertRefused(wrap("    this.key += n;"), "C.runar.ts", "key"); }

    @Test void incrementRefused() throws Exception { assertRefused(wrap("    this.key++;"), "C.runar.ts", "key"); }

    @Test void assignedInsideIfRefused() throws Exception {
        assertRefused(wrap("    if (n > 0n) {\n      this.key = newKey;\n    }"), "C.runar.ts", "key");
    }

    @Test void addOutputSlotRefused() throws Exception {
        assertRefused(wrap("    this.addOutput(1000n, newKey, this.other, this.count);"), "C.runar.ts", "key");
    }

    @Test void privateSetterFedParamRefused() throws Exception {
        assertRefused(wrap("    this.setKey(newKey);", SETTER, DEFAULT_SETTLE), "C.runar.ts", "key");
    }

    @Test void keyViaHelperThenWrittenFromParamRefused() throws Exception {
        assertRefused(wrap("    this.key = newKey;", CHECK, "this.check(msg, sig, padding, this.key)"), "C.runar.ts", "key");
    }

    @Test void propertyFeedingKeyWrittenFromParamRefused() throws Exception {
        assertRefused(wrap("    this.key = this.other;\n    this.other = newKey;"), "C.runar.ts", "other");
    }

    // -- accepted --------------------------------------------------------------

    @Test void literalAccepted() throws Exception { assertAccepted(wrap("    this.key = 1000003n;"), "C.runar.ts"); }

    @Test void readonlyPropertyAccepted() throws Exception { assertAccepted(wrap("    this.key = this.backup;"), "C.runar.ts"); }

    @Test void otherPropertyOnlyLiteralWrittenAccepted() throws Exception {
        assertAccepted(wrap("    this.key = this.other;\n    this.other = 7n;"), "C.runar.ts");
    }

    @Test void nonKeyStateFromParamAccepted() throws Exception {
        assertAccepted(wrap("    this.count = this.count + n;"), "C.runar.ts");
    }

    @Test void nonRabinMutableFromParamAccepted() throws Exception {
        assertAccepted(wrap("    this.other = newKey;"), "C.runar.ts");
    }

    @Test void keyInOwnAddOutputSlotAccepted() throws Exception {
        assertAccepted(wrap("    this.addOutput(1000n, this.key, this.other, n);"), "C.runar.ts");
    }

    @Test void privateSetterFedPropertyAccepted() throws Exception {
        assertAccepted(wrap("    this.setKey(this.backup);", SETTER, DEFAULT_SETTLE), "C.runar.ts");
    }

    // -- Java surface ------------------------------------------------------------

    private static String javaSource(String value) {
        return """
            package runar.examples;

            import runar.lang.StatefulSmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.types.ByteString;
            import runar.lang.types.RabinPubKey;
            import runar.lang.types.RabinSig;

            import static runar.lang.Builtins.assertThat;
            import static runar.lang.Builtins.verifyRabinSig;

            class C extends StatefulSmartContract {
                RabinPubKey key;

                C(RabinPubKey key) {
                    super(key);
                    this.key = key;
                }

                @Public
                void settle(ByteString msg, RabinSig sig, ByteString padding) {
                    assertThat(verifyRabinSig(msg, sig, padding, this.key));
                }

                @Public
                void rotate(RabinPubKey newKey) {
                    this.key = %s;
                    assertThat(true);
                }
            }
            """.formatted(value);
    }

    @Test void javaLiteralWriteAccepted() throws Exception { assertAccepted(javaSource("1000003"), "C.runar.java"); }

    @Test void javaParamWriteRefused() throws Exception { assertRefused(javaSource("newKey"), "C.runar.java", "key"); }

    // -- Solidity surface: bare property name on the left ------------------------

    private static String solBare(String value) {
        return """
            pragma runar ^0.1.0;
            contract C is StatefulSmartContract {
                RabinPubKey key;
                constructor(RabinPubKey _key) { key = _key; }
                function settle(bytes msg, RabinSig sig, bytes padding) public {
                    require(verifyRabinSig(msg, sig, padding, this.key));
                }
                function rotate(RabinPubKey newKey) public {
                    key = %s;
                    require(true);
                }
            }
            """.formatted(value);
    }

    @Test void solBareLiteralWriteAccepted() throws Exception { assertAccepted(solBare("1000003"), "C.runar.sol"); }

    @Test void solBareParamWriteRefused() throws Exception { assertRefused(solBare("newKey"), "C.runar.sol", "key"); }

    // -- (b) the --ir loader -----------------------------------------------------

    private static final String IR_PUBKEY =
        "IR validation: method 'settle': verifyRabinSig public key (4th argument) must be a contract property or a "
            + "literal; a spender-supplied Rabin modulus lets anyone forge a signature";

    private static String oracle() throws Exception {
        return Files.readString(Path.of("..", "..", "conformance", "tests", "oracle-price", "expected-ir.json"));
    }

    @Test
    void irOracleGoldenStillLoads() throws Exception {
        String ir = oracle();
        assertDoesNotThrow(() -> AnfLoader.parse(ir));
    }

    @Test
    void irLoadParamKeyRefused() throws Exception {
        String ir = mutateKeyToParam(oracle());
        RuntimeException e = assertThrows(RuntimeException.class, () -> AnfLoader.parse(ir));
        assertEquals(IR_PUBKEY, e.getMessage());
    }

    /** Rebinds the load_prop feeding settle's verifyRabinSig to {@code load_param price}. */
    private static String mutateKeyToParam(String ir) {
        int call = ir.indexOf("\"func\": \"verifyRabinSig\"");
        int lp = ir.lastIndexOf("\"load_prop\"", call);
        int nm = ir.indexOf("\"oraclePubKey\"", lp);
        assertTrue(call > 0 && lp > 0 && nm > lp && nm < call, "golden layout changed");
        String out = ir.substring(0, lp) + "\"load_param\"" + ir.substring(lp + "\"load_prop\"".length(), nm)
            + "\"price\"" + ir.substring(nm + "\"oraclePubKey\"".length());
        assertNotEquals(ir, out);
        return out;
    }
}
