package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.BinOp;
import runar.compiler.ir.ast.ContractNode;

/**
 * D12 FE-F1 / FE-F4: operator lowering reads the operand family the type
 * checker records on the AST, never a heuristic.
 *
 * <p>The end-to-end shapes are covered by
 * {@code conformance/negatives/d12-typed-operand-lowering.test.ts}. These pin
 * what that suite cannot see: {@link AnfLower#run} re-runs the type checker
 * when it meets an untagged operator, so a pass that dropped a tag while
 * rebuilding a node would be silently repaired there. Here the tags are
 * checked directly after {@link ExpandFixedArrays}.
 */
class D12TypedOperandTest {

    private static final String FIXED_ARRAY_SRC = """
        import { StatefulSmartContract, assert, ByteString, sha256, Sha256, FixedArray } from 'runar-lang';
        class Tags extends StatefulSmartContract {
          ks: FixedArray<ByteString, 2>;
          ns: FixedArray<bigint, 3>;
          constructor(ks: FixedArray<ByteString, 2>, ns: FixedArray<bigint, 3>) { super(ks, ns); this.ks = ks; this.ns = ns; }
          public bump(i: bigint, j: bigint, h: Sha256) {
            const v = this.ks[i];
            assert(sha256(v + this.ks[j]) === h);
            assert(~v !== this.ks[j]);
            this.ns[i]++;
            this.ns[j] = this.ns[j] + 1n;
          }
        }
        """;

    @Test
    void parsersRecordNoFamilyAndTypecheckTagsEveryTypedOperator() throws Exception {
        ContractNode c = ParserDispatch.parse(FIXED_ARRAY_SRC, "Tags.runar.ts");
        assertTrue(AnfLower.hasUntypedOperator(c));
        assertEquals(List.of(), Typecheck.collect(c));
        assertFalse(AnfLower.hasUntypedOperator(c));
    }

    @Test
    void expandKeepsEveryTagAndStampsWhatItSynthesises() throws Exception {
        ContractNode c = ParserDispatch.parse(FIXED_ARRAY_SRC, "Tags.runar.ts");
        assertEquals(List.of(), Typecheck.collect(c));
        ContractNode expanded = ExpandFixedArrays.run(c);
        // The index dispatch (`i === 0`), the `++` desugar (`+ 1`) and every
        // rebuilt / cloned operator carry a family.
        assertFalse(AnfLower.hasUntypedOperator(expanded));
    }

    @Test
    void lowerTypechecksAnUntypedAstItselfAndRefusesWhatStaysUntyped() throws Exception {
        ContractNode ok = ParserDispatch.parse("""
            import { SmartContract, assert, ByteString } from 'runar-lang';
            class Ok extends SmartContract {
              constructor() { super(); }
              public unlock(c: boolean, a: ByteString, b: ByteString) { const x = c ? a : b; assert(x === b); }
            }
            """, "Ok.runar.ts");
        AnfProgram program = AnfLower.run(ok);
        boolean sawBytesEq = false;
        for (AnfMethod m : program.methods()) {
            for (AnfBinding b : m.body()) {
                if (b.value() instanceof BinOp op && op.op().equals("===")) {
                    assertEquals("bytes", op.resultType());
                    sawBytesEq = true;
                }
            }
        }
        assertTrue(sawBytesEq);

        // `a[0n]` has no type the checker can resolve: no family, so
        // lowering refuses rather than guessing OP_NUMEQUAL.
        ContractNode bad = ParserDispatch.parse("""
            import { SmartContract, assert, ByteString } from 'runar-lang';
            class Bad extends SmartContract {
              constructor() { super(); }
              public unlock(a: ByteString, b: ByteString) { assert(a[0n] === b); }
            }
            """, "Bad.runar.ts");
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> AnfLower.run(bad));
        assertTrue(e.getMessage().contains("carries no operand type from the type checker"), e.getMessage());
    }

    @Test
    void undeclaredHelperReturnTypeIsInferredWithTheFullEnvironment() throws Exception {
        // Defined AFTER its caller and returning a parameter: the old env-less
        // inference typed it `<unknown>`, and `===` fell back to numeric.
        ContractNode c = ParserDispatch.parse("""
            import { SmartContract, assert, ByteString } from 'runar-lang';
            class Inf extends SmartContract {
              constructor() { super(); }
              public unlock(a: ByteString, b: ByteString) { assert(this.id(a) === this.id(b)); }
              private id(v: ByteString) { return v; }
            }
            """, "Inf.runar.ts");
        assertEquals(List.of(), Typecheck.collect(c));
        assertFalse(AnfLower.hasUntypedOperator(c));
    }

    @Test
    void declaredReturnTypeIsEnforced() throws Exception {
        ContractNode c = ParserDispatch.parse("""
            import { SmartContract, assert } from 'runar-lang';
            class RetMismatch extends SmartContract {
              constructor() { super(); }
              private f(x: bigint): boolean { return x; }
              public unlock(x: bigint) { assert(this.f(x)); }
            }
            """, "RetMismatch.runar.ts");
        List<String> errors = Typecheck.collect(c);
        assertTrue(errors.stream().anyMatch(m -> m.contains(
            "Method 'f' returns 'bigint', which is not assignable to its declared return type 'boolean'")), errors.toString());
    }

    @Test
    void declaredVoidReturnTypeIsEnforced() throws Exception {
        ContractNode c = ParserDispatch.parse("""
            import { SmartContract, assert } from 'runar-lang';
            class VoidRet extends SmartContract {
              constructor() { super(); }
              private f(x: bigint): void { return x; }
              public unlock(x: bigint) { this.f(x); assert(x > 0n); }
            }
            """, "VoidRet.runar.ts");
        List<String> errors = Typecheck.collect(c);
        assertTrue(errors.stream().anyMatch(m -> m.contains(
            "Method 'f' returns 'bigint', which is not assignable to its declared return type 'void'")), errors.toString());
    }

    @Test
    void undeclaredHelperWhoseReturnsDoNotUnifyIsRefused() throws Exception {
        ContractNode c = ParserDispatch.parse("""
            import { SmartContract, assert } from 'runar-lang';
            class Mixed extends SmartContract {
              constructor() { super(); }
              private h(c: boolean) { if (c) { return 1n; } return true; }
              public unlock(c: boolean) { assert(this.h(c)); }
            }
            """, "Mixed.runar.ts");
        List<String> errors = Typecheck.collect(c);
        assertTrue(errors.stream().anyMatch(m -> m.contains(
            "Method 'h' returns values of incompatible types ('bigint', 'boolean'); declare its return type")),
            errors.toString());

        // Control: returns in one family unify (bigint), so nothing is refused.
        ContractNode ok = ParserDispatch.parse("""
            import { SmartContract, assert } from 'runar-lang';
            class Same extends SmartContract {
              constructor() { super(); }
              private h(c: boolean) { if (c) { return 1n; } return 2n; }
              public unlock(c: boolean) { assert(this.h(c) > 0n); }
            }
            """, "Same.runar.ts");
        assertEquals(List.of(), Typecheck.collect(ok));
    }
}
