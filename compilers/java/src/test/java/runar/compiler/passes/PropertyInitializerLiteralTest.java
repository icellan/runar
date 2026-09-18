package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.canonical.Jcs;

/**
 * Audit C3 — property initializers are restricted to literal values.
 *
 * <p>{@code ts}, {@code go} and {@code java} enforced this; {@code rust},
 * {@code zig}, {@code python} and {@code ruby} did not — they compiled e.g.
 * {@code p: bigint = 1n + 2n;} and emitted a deployable locking script for a
 * program the language does not define.
 *
 * <p>Mirrors {@code packages/runar-compiler/src/__tests__/property-initializer-literal.test.ts}.
 */
class PropertyInitializerLiteralTest {

    /** The cross-tier diagnostic substring. */
    private static final String NON_LITERAL_INIT = "initializer must be a literal value";

    private static Validate.Result validateSource(String source, String fileName) throws Exception {
        ContractNode c = ParserDispatch.parse(source, fileName);
        return Validate.runCollecting(c);
    }

    private static void assertNonLiteralInitError(Validate.Result r) {
        assertTrue(
            r.errors().stream().anyMatch(m -> m.contains(NON_LITERAL_INIT)),
            "expected a non-literal-initializer error, got: " + r.errors()
        );
    }

    @Test
    void rejectsArithmeticPropertyInitializer() throws Exception {
        String src = """
            import { StatefulSmartContract, Addr } from 'runar-lang';

            class Bad extends StatefulSmartContract {
              count: bigint = 1n + 2n;
              readonly owner: Addr;

              constructor(owner: Addr) {
                super(owner);
                this.owner = owner;
              }

              public bump() {
                this.count = this.count + 1n;
              }
            }
            """;
        assertNonLiteralInitError(validateSource(src, "Bad.runar.ts"));
    }

    @Test
    void rejectsCallExpressionPropertyInitializer() throws Exception {
        String src = """
            import { StatefulSmartContract, Addr } from 'runar-lang';

            class Bad2 extends StatefulSmartContract {
              count: bigint = abs(-3n);
              readonly owner: Addr;

              constructor(owner: Addr) {
                super(owner);
                this.owner = owner;
              }

              public bump() {
                this.count = this.count + 1n;
              }
            }
            """;
        assertNonLiteralInitError(validateSource(src, "Bad2.runar.ts"));
    }

    @Test
    void acceptsLiteralPropertyInitializers() throws Exception {
        String src = """
            import { StatefulSmartContract, Addr, ByteString } from 'runar-lang';

            class Good extends StatefulSmartContract {
              count: bigint = 7n;
              flag: boolean = true;
              tag: ByteString = 'deadbeef';
              offset: bigint = -3n;
              readonly owner: Addr;

              constructor(owner: Addr) {
                super(owner);
                this.owner = owner;
              }

              public bump() {
                this.count = this.count + 1n;
              }
            }
            """;
        Validate.Result r = validateSource(src, "Good.runar.ts");
        assertTrue(r.errors().isEmpty(), "expected no errors, got: " + r.errors());
    }

    // ----------------------------------------------------------------------
    // `toByteString('<hex>')` IS the ByteStringLiteral production — see
    // spec/grammar.md section 11:
    //
    //     ByteStringLiteral = 'toByteString' '(' StringLiteral ')' ;
    //
    // 0e192af6 folded it in ANF lowering, which covers every EXPRESSION
    // position. A property INITIALIZER is not one: the validator runs on the
    // AST, BEFORE ANF lowering, and still saw a call node. The `.runar.rs`
    // surface needs exactly this spelling in exactly this position — the Rust
    // DSL writes initializers as assignments inside `init()` that the parser
    // LIFTS into PropertyNode.initializer, and a bare "1976a914" is a &str
    // that cannot be assigned to a ByteString (Vec<u8>).
    //
    // Both halves are asserted: accepting it in the validator alone yields a
    // property that validates and then loses its default, because
    // extractLiteralValue returns null for a call node.
    // ----------------------------------------------------------------------

    private static final String TO_BYTE_STRING_INIT = """
        import { SmartContract, Addr, ByteString, toByteString, assert } from 'runar-lang';

        class Wrapped extends SmartContract {
          readonly prefix: ByteString = toByteString('1976a914');
          readonly owner: Addr;

          constructor(owner: Addr) {
            super(owner);
            this.owner = owner;
          }

          public unlock(x: ByteString) {
            assert(x === this.prefix);
          }
        }
        """;

    @Test
    void acceptsToByteStringLiteralPropertyInitializer() throws Exception {
        Validate.Result r = validateSource(TO_BYTE_STRING_INIT, "Wrapped.runar.ts");
        assertTrue(r.errors().isEmpty(), "expected no errors, got: " + r.errors());
    }

    @Test
    void unwrapsToByteStringLiteralInitializerInAnf() throws Exception {
        ContractNode wrappedAst = ParserDispatch.parse(TO_BYTE_STRING_INIT, "Wrapped.runar.ts");
        AnfProgram wrapped = AnfLower.run(wrappedAst);

        String bareSource = TO_BYTE_STRING_INIT.replace("toByteString('1976a914')", "'1976a914'");
        AnfProgram bare = AnfLower.run(ParserDispatch.parse(bareSource, "Wrapped.runar.ts"));

        // Half two: a bare value, not a call node and not a dropped default.
        assertEquals(
            new BytesConst("1976a914"),
            wrapped.properties().get(0).initialValue(),
            "expected the initializer to unwrap to a bare ByteString value"
        );

        // ...and the whole program is indistinguishable from the bare
        // spelling, which is what keeps expected-ir.json from moving.
        assertEquals(
            Jcs.stringify(bare),
            Jcs.stringify(wrapped),
            "wrapped ANF must be byte-identical to the bare-literal ANF"
        );
    }

    @Test
    void rejectsToByteStringNonLiteralPropertyInitializer() throws Exception {
        // Not the ByteStringLiteral production — a real call, and a call is
        // not a literal. Guards the accept from widening into "any
        // toByteString call".
        String src = """
            import { SmartContract, Addr, ByteString, toByteString, assert } from 'runar-lang';

            class Bad3 extends SmartContract {
              readonly prefix: ByteString = toByteString(someIdent);
              readonly owner: Addr;

              constructor(owner: Addr) {
                super(owner);
                this.owner = owner;
              }

              public unlock(x: ByteString) {
                assert(x === this.prefix);
              }
            }
            """;
        assertNonLiteralInitError(validateSource(src, "Bad3.runar.ts"));
    }
}
