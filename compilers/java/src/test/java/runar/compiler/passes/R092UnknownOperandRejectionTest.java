package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;

/**
 * R-092 / N-091 — the Java typechecker must not let {@code <unknown>} through
 * an operand position that requires a concrete type.
 *
 * <p>Six tiers derive a private helper's return type as {@code <unknown>} (no
 * {@code returnType} on {@code MethodNode}) and then REJECT the result in any
 * position that demands a bigint: {@code isBigintFamily("<unknown>")} is false
 * and there is no escape hatch. Java carried an extra {@code &&
 * !"<unknown>".equals(t)} conjunct at eight of those checks — arithmetic,
 * relational, shift, bitwise, unary {@code -}, unary {@code ~}, {@code ++}/{@code --}
 * and array index — so Java alone ACCEPTED programs the other six refuse:
 *
 * <pre>
 *   P6   this.h(x) + 1n        rejected x6, java emitted 768b7c9c
 *   P12  helper -> PubKey in '>'   rejected x6, java emitted 7c00ad007ca0
 * </pre>
 *
 * <p>P12 is the one that matters: a 33-byte push into {@code OP_GREATERTHAN}
 * succeeds post-Genesis and silently computes a meaningless comparison. The
 * fix therefore converges on the strict six, never the permissive one.
 *
 * <p>This is also the root of N-091 / R-085. {@code neverDeclared > 0n} infers
 * {@code <unknown>} for the undeclared identifier; with the relational guard in
 * place Java's FRONTEND accepted it and only stack lowering refused, exiting 70
 * where every other tier exits 65 — which meant {@code runar.lang.sdk.CompileCheck},
 * a frontend-only API, green-lit invalid Rúnar. The chain exercised below
 * ({@code ParserDispatch.parse -> Validate.run -> ExpandFixedArrays.run ->
 * Typecheck.run}) is exactly what {@code CompileCheck} runs.
 */
class R092UnknownOperandRejectionTest {

    /** The frontend chain `runar.lang.sdk.CompileCheck` runs, errors collected. */
    private static List<String> frontendErrors(String src, String file) throws Exception {
        ContractNode c = ParserDispatch.parse(src, file);
        Validate.run(c); // throws ValidationException on a validate-level error
        c = ExpandFixedArrays.run(c);
        return Typecheck.collect(c);
    }

    private static void assertRejected(String src, String file, String needle) throws Exception {
        List<String> errs = frontendErrors(src, file);
        assertFalse(
            errs.isEmpty(),
            "expected the Java frontend to REJECT " + file + "; it accepted it. "
                + "Six tiers reject this source — Java accepting it is the R-092 divergence."
        );
        assertTrue(
            errs.stream().anyMatch(e -> e.contains(needle)),
            "expected a diagnostic containing \"" + needle + "\", got " + errs
        );
        // Rejecting for a reason is the point: a bare non-empty list would also
        // be satisfied by an unrelated error, so the needle is load-bearing.
    }

    // ------------------------------------------------------------------
    // The two probes the audit compiled. Both must be rejected.
    // ------------------------------------------------------------------

    private static final String P6 = """
        import { SmartContract, assert } from 'runar-lang';
        export class P6 extends SmartContract {
          readonly a: bigint;
          constructor(a: bigint) { super(a); this.a = a; }
          private h(v: bigint): bigint { return v; }
          public go(x: bigint) { assert(this.h(x) + 1n === x); }
        }
        """;

    private static final String P12 = """
        import { SmartContract, assert, ByteString, PubKey, Sig, checkSig } from 'runar-lang';
        export class P12 extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          private hp(): PubKey { return this.pk; }
          public go(s: Sig, x: bigint) { assert(checkSig(s, this.hp())); assert(this.hp() > x); }
        }
        """;

    @Test
    void p6ArithmeticOperandOfUnknownTypeIsRejected() throws Exception {
        assertRejected(P6, "P6.runar.ts", "must be bigint");
    }

    @Test
    void p12RelationalOperandOfUnknownTypeIsRejected() throws Exception {
        assertRejected(P12, "P12.runar.ts", "must be bigint");
    }

    // ------------------------------------------------------------------
    // N-091 / R-085 — N07 must be refused by the FRONTEND, not by emit.
    // ------------------------------------------------------------------

    private static final String N07 = """
        import { SmartContract, assert } from 'runar-lang';
        export class N07 extends SmartContract {
          readonly a: bigint;
          constructor(a: bigint) { super(a); this.a = a; }
          public go(x: bigint) { assert(neverDeclared > 0n); }
        }
        """;

    @Test
    void n07UndeclaredVarIsRejectedByTheFrontend() throws Exception {
        assertRejected(N07, "N07-undeclared-var.runar.ts", "must be bigint");
    }

    // ------------------------------------------------------------------
    // One probe per guarded operand position, so a partial revert fails here.
    // ------------------------------------------------------------------

    /** Wraps a method body in a contract whose private helper returns `<unknown>`. */
    private static String withHelper(String body) {
        return """
            import { SmartContract, assert, ByteString, PubKey } from 'runar-lang';
            export class G extends SmartContract {
              readonly pk: PubKey;
              constructor(pk: PubKey) { super(pk); this.pk = pk; }
              private hp(): PubKey { return this.pk; }
              public go(x: bigint) { %s }
            }
            """.formatted(body);
    }

    @Test
    void shiftOperandOfUnknownTypeIsRejected() throws Exception {
        assertRejected(withHelper("assert((this.hp() << 1n) === x);"), "G.runar.ts", "must be bigint");
    }

    @Test
    void bitwiseOperandOfUnknownTypeIsRejected() throws Exception {
        assertRejected(
            withHelper("assert((this.hp() | 1n) === x);"), "G.runar.ts", "must be bigint or ByteString"
        );
    }

    @Test
    void unaryNegOperandOfUnknownTypeIsRejected() throws Exception {
        assertRejected(withHelper("assert(-this.hp() === x);"), "G.runar.ts", "unary '-' must be bigint");
    }

    @Test
    void unaryBitNotOperandOfUnknownTypeIsRejected() throws Exception {
        assertRejected(
            withHelper("assert(~this.hp() === x);"), "G.runar.ts", "'~' must be bigint or ByteString"
        );
    }

    /**
     * The array-index source, shared by the two tests below. Six tiers reject it
     * ("array index must be bigint, got 'unknown'"); see the second test for why
     * Java still does not.
     */
    private static final String IDX = """
        import { StatefulSmartContract, assert, PubKey } from 'runar-lang';
        import type { FixedArray } from 'runar-lang';
        export class G extends StatefulSmartContract {
          readonly pk: PubKey;
          cells: FixedArray<bigint, 3> = [0n, 0n, 0n];
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          private hp(): PubKey { return this.pk; }
          public go(x: bigint) { assert(this.cells[this.hp()] === x); this.cells[0] = 1n; }
        }
        """;

    @Test
    void arrayIndexOfUnknownTypeIsRejectedOnceTypecheckCanSeeTheIndex() throws Exception {
        // Typecheck WITHOUT the FixedArray expansion, which is the only state in
        // which an IndexAccessExpr still exists in the Java tree. This is the
        // direct gate on the removed guard at the IndexAccessExpr arm.
        ContractNode c = ParserDispatch.parse(IDX, "G.runar.ts");
        Validate.run(c);
        List<String> errs = Typecheck.collect(c);
        assertTrue(
            errs.stream().anyMatch(e -> e.contains("array index must be bigint")),
            "expected the index guard to fire on an <unknown> index, got " + errs
        );
    }

    /**
     * RESIDUAL DIVERGENCE, recorded rather than asserted away.
     *
     * <p>Removing the guard does NOT make Java reject this source through the
     * frontend chain, because Java runs {@code ExpandFixedArrays} BEFORE
     * {@code Typecheck} (Cli.java: Validate -> ExpandFixedArrays -> Typecheck).
     * A runtime index is rewritten into a ternary dispatch by the expansion, so
     * by the time the typechecker runs there is no IndexAccessExpr left to
     * check. The TypeScript reference typechecks BOTH before and after the
     * expansion (`index.ts`: parse -> validate -> typecheck -> expandFixedArrays
     * -> typecheck), which is why the other six tiers catch it.
     *
     * <p>That is a pass-ORDERING defect, not a guard defect, and fixing it means
     * teaching Java's typechecker to run over un-expanded FixedArray types —
     * deliberately out of scope here. This test pins the current behaviour so
     * the divergence cannot be forgotten: when the ordering is fixed, this test
     * fails and must be deleted in favour of the strict assertion.
     */
    @Test
    void arrayIndexOfUnknownTypeIsStillAcceptedByTheFullFrontend_passOrdering() throws Exception {
        assertTrue(
            frontendErrors(IDX, "G.runar.ts").isEmpty(),
            "Java's frontend now rejects the unknown array index — the pass-ordering "
                + "divergence is fixed, so replace this test with assertRejected(IDX, ...)."
        );
    }

    @Test
    void incrementOfUnknownTypeIsRejected() throws Exception {
        String src = """
            import { StatefulSmartContract, assert, PubKey } from 'runar-lang';
            export class G extends StatefulSmartContract {
              count: bigint;
              readonly pk: PubKey;
              constructor(count: bigint, pk: PubKey) { super(count, pk); this.count = count; this.pk = pk; }
              private hp(): PubKey { return this.pk; }
              public go() { let v = this.hp(); v++; this.count = this.count + 1n; }
            }
            """;
        assertRejected(src, "G.runar.ts", "++ operator requires bigint");
    }

    @Test
    void decrementOfUnknownTypeIsRejected() throws Exception {
        String src = """
            import { StatefulSmartContract, assert, PubKey } from 'runar-lang';
            export class G extends StatefulSmartContract {
              count: bigint;
              readonly pk: PubKey;
              constructor(count: bigint, pk: PubKey) { super(count, pk); this.count = count; this.pk = pk; }
              private hp(): PubKey { return this.pk; }
              public go() { let v = this.hp(); v--; this.count = this.count + 1n; }
            }
            """;
        assertRejected(src, "G.runar.ts", "-- operator requires bigint");
    }

    // ------------------------------------------------------------------
    // Controls. Removing a guard that turns out to be live on VALID code is
    // the whole risk of this change, so the probes all seven tiers accept are
    // asserted to still typecheck clean.
    // ------------------------------------------------------------------

    @Test
    void p4HelperResultBoundToATypedLocalStillCompiles() throws Exception {
        // `const y: bigint = this.h(x)` — the declared type carries, so the
        // comparison operand is bigint, not <unknown>. Accepted by all seven.
        String src = """
            import { SmartContract, assert } from 'runar-lang';
            export class P4 extends SmartContract {
              readonly a: bigint;
              constructor(a: bigint) { super(a); this.a = a; }
              private h(v: bigint) { return v; }
              public go(x: bigint) { const y: bigint = this.h(x); assert(y === x); }
            }
            """;
        assertTrue(frontendErrors(src, "P4.runar.ts").isEmpty(), "P4 must still typecheck clean");
    }

    @Test
    void helperResultInAnEqualityComparisonStillCompiles() throws Exception {
        // `===` compares via isSubtype, which is compatible with <unknown> by
        // construction. That guard is NOT what this change touches.
        String src = """
            import { SmartContract, assert, PubKey } from 'runar-lang';
            export class P21 extends SmartContract {
              readonly pk: PubKey;
              constructor(pk: PubKey) { super(pk); this.pk = pk; }
              private hp(): PubKey { return this.pk; }
              public go(p: PubKey) { assert(this.hp() === p); }
            }
            """;
        assertTrue(frontendErrors(src, "P21.runar.ts").isEmpty(), "P21 must still typecheck clean");
    }

    @Test
    void byteStringConcatOfHelperResultStillCompiles() throws Exception {
        // ByteString + ByteString short-circuits before the bigint check, and a
        // typed local keeps the operand concrete.
        String src = """
            import { SmartContract, assert, ByteString, sha256, Sha256 } from 'runar-lang';
            export class C extends SmartContract {
              readonly h: Sha256;
              constructor(h: Sha256) { super(h); this.h = h; }
              private hb(sb: ByteString): ByteString { return sb; }
              public go(sb: ByteString) { const b: ByteString = this.hb(sb); assert(sha256(b + b) === this.h); }
            }
            """;
        assertTrue(frontendErrors(src, "C.runar.ts").isEmpty(), "ByteString concat must still typecheck clean");
    }
}
