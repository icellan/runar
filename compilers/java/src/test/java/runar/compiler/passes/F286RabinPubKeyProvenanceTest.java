package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;

/**
 * F-286 — verifyRabinSig's public key (4th argument) must come from the
 * contract, not the spender. A spender who picks the modulus forges any
 * message ({@code n = 1, sig = 0} passes real Spend), so the Java tier's
 * validator must refuse it with the diagnostic every tier shares, exactly as
 * the TS reference ({@code checkRabinPubKeyProvenance} in 02-validate.ts).
 *
 * <p>What this proves: the Java-tier validator refuses the spender-chosen
 * modulus shapes (public param, alias of a param, helper fed a param, alias
 * reassigned from a param, ternary, arithmetic, param in a nested for) and
 * still accepts the property / literal / alias / helper shapes, on the TS
 * surface and on the Java surface's bare-field spelling.
 *
 * <p>What it does NOT prove: on-chain behaviour (runar-testing's F-286 test
 * runs real Spend), the other tiers (conformance/negatives N220–N228), or a
 * hostile {@code --ir} input, which skips the frontend.
 */
class F286RabinPubKeyProvenanceTest {

    private static final String MSG =
        "verifyRabinSig public key (4th argument) must be a contract property or a literal; "
            + "a spender-supplied Rabin modulus lets anyone forge a signature";

    private static final String HELPER = """
          private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
            return verifyRabinSig(m, s, p, k);
          }
        """;

    private static final String CHAIN = """
          private outer(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
            const kk = k;
            return this.inner(m, s, p, kk);
          }
          private inner(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
            return verifyRabinSig(m, s, p, k);
          }
        """;

    private static String wrap(String body, String extraParams, String extraMethods) {
        return """
            import { SmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

            class C extends SmartContract {
              readonly pk: RabinPubKey;
              readonly pk2: RabinPubKey;

              constructor(pk: RabinPubKey, pk2: RabinPubKey) {
                super(pk, pk2);
                this.pk = pk;
                this.pk2 = pk2;
              }

              public settle(msg: ByteString, sig: RabinSig, padding: ByteString%s) {
            %s
              }
            %s
            }
            """.formatted(extraParams, body, extraMethods);
    }

    private static List<String> errorsOf(String source, String fileName) throws Exception {
        ContractNode c = ParserDispatch.parse(source, fileName);
        return Validate.runCollecting(c).errors();
    }

    private static void assertRefused(String source, String fileName) throws Exception {
        List<String> errs = errorsOf(source, fileName);
        assertTrue(errs.stream().anyMatch(e -> e.contains(MSG)), "expected F-286 refusal, got " + errs);
    }

    private static void assertAccepted(String source, String fileName) throws Exception {
        List<String> errs = errorsOf(source, fileName);
        assertEquals(List.of(), errs);
    }

    // -- refused (TS surface) ------------------------------------------------

    @Test
    void refusesPublicParam() throws Exception {
        assertRefused(wrap("    assert(verifyRabinSig(msg, sig, padding, n));", ", n: RabinPubKey", ""), "C.runar.ts");
    }

    @Test
    void refusesConstAliasOfParam() throws Exception {
        assertRefused(wrap("    const k = n;\n    assert(verifyRabinSig(msg, sig, padding, k));", ", n: RabinPubKey", ""), "C.runar.ts");
    }

    @Test
    void refusesLetReassignedFromParam() throws Exception {
        assertRefused(wrap("    let k = this.pk;\n    k = n;\n    assert(verifyRabinSig(msg, sig, padding, k));", ", n: RabinPubKey", ""), "C.runar.ts");
    }

    @Test
    void refusesHelperBoundToParam() throws Exception {
        assertRefused(wrap("    assert(this.check(msg, sig, padding, n));", ", n: RabinPubKey", HELPER), "C.runar.ts");
    }

    @Test
    void refusesHelperMixedSites() throws Exception {
        assertRefused(wrap(
            "    assert(this.check(msg, sig, padding, this.pk));\n    assert(this.check(msg, sig, padding, n));",
            ", n: RabinPubKey", HELPER), "C.runar.ts");
    }

    @Test
    void refusesTernary() throws Exception {
        assertRefused(wrap("    assert(verifyRabinSig(msg, sig, padding, sig > 0n ? this.pk : n));", ", n: RabinPubKey", ""), "C.runar.ts");
    }

    @Test
    void refusesArithmeticOnProperty() throws Exception {
        assertRefused(wrap("    assert(verifyRabinSig(msg, sig, padding, this.pk + 1n));", "", ""), "C.runar.ts");
    }

    @Test
    void refusesParamInForNestedInIf() throws Exception {
        assertRefused(wrap(
            "    if (sig > 0n) {\n      for (let i = 0n; i < 2n; i++) {\n        assert(verifyRabinSig(msg, sig, padding, n));\n      }\n    }\n    assert(true);",
            ", n: RabinPubKey", ""), "C.runar.ts");
    }

    // -- accepted (TS surface) -----------------------------------------------

    @Test
    void acceptsProperty() throws Exception {
        assertAccepted(wrap("    assert(verifyRabinSig(msg, sig, padding, this.pk));", "", ""), "C.runar.ts");
    }

    @Test
    void acceptsLiteral() throws Exception {
        assertAccepted(wrap("    assert(verifyRabinSig(msg, sig, padding, 1000003n));", "", ""), "C.runar.ts");
    }

    @Test
    void acceptsConstAliasOfProperty() throws Exception {
        assertAccepted(wrap("    const k = this.pk;\n    assert(verifyRabinSig(msg, sig, padding, k));", "", ""), "C.runar.ts");
    }

    @Test
    void acceptsLetReassignedOnlyFromProperties() throws Exception {
        assertAccepted(wrap(
            "    let k = this.pk;\n    if (sig > 0n) { k = this.pk2; }\n    assert(verifyRabinSig(msg, sig, padding, k));",
            "", ""), "C.runar.ts");
    }

    @Test
    void acceptsHelperBoundToPropertyAtEverySite() throws Exception {
        assertAccepted(wrap(
            "    assert(this.check(msg, sig, padding, this.pk));\n    assert(this.check(msg, sig, padding, this.pk2));",
            "", HELPER), "C.runar.ts");
    }

    @Test
    void acceptsTwoLevelHelperChain() throws Exception {
        assertAccepted(wrap("    assert(this.outer(msg, sig, padding, this.pk));", "", CHAIN), "C.runar.ts");
    }

    // -- Java surface: bare field ---------------------------------------------

    private static String javaSource(String params, String body) {
        return """
            package runar.examples;

            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.ByteString;
            import runar.lang.types.RabinPubKey;
            import runar.lang.types.RabinSig;

            import static runar.lang.Builtins.assertThat;
            import static runar.lang.Builtins.verifyRabinSig;

            class C extends SmartContract {
                @Readonly RabinPubKey pk;

                C(RabinPubKey pk) {
                    super(pk);
                    this.pk = pk;
                }

                @Public
                void settle(ByteString msg, RabinSig sig, ByteString padding%s) {
            %s
                }
            }
            """.formatted(params, body);
    }

    @Test
    void javaBareFieldAccepted() throws Exception {
        assertAccepted(javaSource("", "        assertThat(verifyRabinSig(msg, sig, padding, pk));"), "C.runar.java");
    }

    @Test
    void javaBareFieldLocalAliasAccepted() throws Exception {
        assertAccepted(javaSource("",
            "        RabinPubKey a = pk;\n        assertThat(verifyRabinSig(msg, sig, padding, a));"), "C.runar.java");
    }

    @Test
    void javaParamRefused() throws Exception {
        assertRefused(javaSource(", RabinPubKey n",
            "        assertThat(verifyRabinSig(msg, sig, padding, n));"), "C.runar.java");
    }

    @Test
    void javaLocalAliasOfParamRefused() throws Exception {
        assertRefused(javaSource(", RabinPubKey n",
            "        RabinPubKey a = n;\n        assertThat(verifyRabinSig(msg, sig, padding, a));"), "C.runar.java");
    }
}
