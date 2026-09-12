package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.Cli;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.stack.StackProgram;

/**
 * Port of the TypeScript reference test
 * {@code packages/runar-compiler/src/__tests__/n105-output-shape.test.ts}.
 *
 * <p>N-105 (2/2) — the rest of TypeScript's output-intrinsic CONTRACT: the
 * StatefulSmartContract gate, the arity of all three intrinsics, and the types
 * of addOutput's state values.
 *
 * <p>N-098 ported the satoshis check and N-105 (1/2) the scriptBytes check.
 * These three are the remainder, and each was a hole with an executed
 * consequence:
 *
 * <pre>
 *   this.addOutput(1000n)                  1352 hexchars — the state value is
 *     with one mutable property            simply MISSING from the
 *                                          continuation; the correct call
 *                                          emits 1362.
 *   this.addOutput(1000n, this.count, 5n)  1368 hexchars — the surplus value is
 *                                          appended to a state serialization
 *                                          the next spend deserializes by fixed
 *                                          offsets.
 *   this.addOutput(1000n, this.blob)       1362 hexchars, DIFFERENT bytes — the
 *     with count: bigint                   ByteString is serialized where an
 *                                          8-byte LE number belongs.
 *   this.addRawOutput(...) in a            152 hexchars — a "continuation" in a
 *     stateless SmartContract              contract that has no state.
 * </pre>
 *
 * <p>All four are the same class as N-098: the compiler does not refuse, it
 * emits a covenant that commits to the wrong thing.
 *
 * <p>Ported from the TypeScript reference, wording included. The rejection is
 * asserted through the SAME chain {@code runar.lang.sdk.CompileCheck} runs.
 *
 * <p>NOTE for this tier specifically: {@code ExpandFixedArrays} runs BEFORE
 * {@code Typecheck} here, and AFTER it in the other six. A contract with
 * FixedArray state therefore reaches this checker already split into scalar
 * siblings, so the arity it counts is the EXPANDED one and the carve-out the
 * other tiers need never fires. The Boardy case below pins that the outcome is
 * the same either way.
 */
class N105OutputShapeTest {

    private static final String HEAD =
        "import { StatefulSmartContract, ByteString, PubKey, assert } from 'runar-lang';\n"
        + "class C extends StatefulSmartContract {\n"
        + "  count: bigint;\n"
        + "  owner: PubKey;\n"
        + "  readonly base: bigint;\n"
        + "  readonly blob: ByteString;\n"
        + "  constructor(count: bigint, owner: PubKey, base: bigint, blob: ByteString) {\n"
        + "    super(count, owner, base, blob);\n"
        + "    this.count = count;\n"
        + "    this.owner = owner;\n"
        + "    this.base = base;\n"
        + "    this.blob = blob;\n"
        + "  }\n"
        + "  private anything(): bigint { return this.base; }\n";

    private static final String STATELESS_HEAD =
        "import { SmartContract, ByteString, assert } from 'runar-lang';\n"
        + "class C extends SmartContract {\n"
        + "  readonly base: bigint;\n"
        + "  readonly blob: ByteString;\n"
        + "  constructor(base: bigint, blob: ByteString) {\n"
        + "    super(base, blob);\n"
        + "    this.base = base;\n"
        + "    this.blob = blob;\n"
        + "  }\n";

    private static String stateful(String body) {
        return HEAD + body + "}\n";
    }

    private static String stateless(String body) {
        return STATELESS_HEAD + body + "}\n";
    }

    // --- REJECT: arity -----------------------------------------------------

    private static final String ARITY_TOO_FEW = stateful(
        "  public m(n: bigint, who: PubKey) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.owner = who;\n"
        + "    this.addOutput(1000n, this.count);\n"
        + "  }\n");

    private static final String ARITY_TOO_MANY = stateful(
        "  public m(n: bigint, who: PubKey) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.owner = who;\n"
        + "    this.addOutput(1000n, this.count, this.owner, 5n);\n"
        + "  }\n");

    private static final String RAW_ARITY_ONE = stateful(
        "  public m(n: bigint, who: PubKey) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.owner = who;\n"
        + "    this.addOutput(1000n, this.count, this.owner);\n"
        + "    this.addRawOutput(500n);\n"
        + "  }\n");

    private static final String RAW_ARITY_THREE = stateful(
        "  public m(n: bigint, who: PubKey) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.owner = who;\n"
        + "    this.addOutput(1000n, this.count, this.owner);\n"
        + "    this.addRawOutput(500n, this.blob, 7n);\n"
        + "  }\n");

    private static final String DATA_ARITY_THREE = stateful(
        "  public m(n: bigint, who: PubKey) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.owner = who;\n"
        + "    this.addOutput(1000n, this.count, this.owner);\n"
        + "    this.addDataOutput(500n, this.blob, 7n);\n"
        + "  }\n");

    // --- REJECT: state-value types -----------------------------------------

    private static final String STATE_VALUE_WRONG_TYPE = stateful(
        "  public m(n: bigint, who: PubKey) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.owner = who;\n"
        + "    this.addOutput(1000n, this.blob, this.owner);\n"
        + "  }\n");

    // --- REJECT: the StatefulSmartContract gate ----------------------------

    private static final String STATELESS_ADD_OUTPUT = stateless(
        "  public m(n: bigint) {\n"
        + "    this.addOutput(1000n, n);\n"
        + "    assert(n > 0n);\n"
        + "  }\n");

    private static final String STATELESS_ADD_RAW_OUTPUT = stateless(
        "  public m(n: bigint) {\n"
        + "    this.addRawOutput(1000n, this.blob);\n"
        + "    assert(n > 0n);\n"
        + "  }\n");

    private static final String STATELESS_ADD_DATA_OUTPUT = stateless(
        "  public m(n: bigint) {\n"
        + "    this.addDataOutput(1000n, this.blob);\n"
        + "    assert(n > 0n);\n"
        + "  }\n");

    // --- ACCEPT (over-rejection guards) ------------------------------------

    private static final String SHAPE_EXACT = stateful(
        "  public m(n: bigint, who: PubKey) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.owner = who;\n"
        + "    this.addOutput(1000n, this.count, this.owner);\n"
        + "  }\n");

    /**
     * A ByteString value in a PubKey state slot. {@code isSubtype} treats the
     * ByteString family as bidirectionally compatible, so TS ACCEPTS this and
     * every tier must keep accepting it — measured before this change, all
     * seven tiers compiled it to the same script. N-104: this tier's own
     * {@code isSubtype} did not always agree, which is why the state-value
     * check used to go through a private {@code outputStateValueMatches}. The
     * general predicate is the reference's now, and the helper is gone.
     */
    private static final String SHAPE_FAMILY_WIDENING = stateful(
        "  public m(n: bigint, b: ByteString) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(1000n, this.count, b);\n"
        + "  }\n");

    /**
     * A private helper's declared return type is discarded at parse time in
     * every tier, so this infers as {@code <unknown>}.
     */
    private static final String SHAPE_UNKNOWN_STATE_VALUE = stateful(
        "  public m(n: bigint, who: PubKey) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.owner = who;\n"
        + "    this.addOutput(1000n, this.anything(), this.owner);\n"
        + "  }\n");

    /** The one-mutable-property shape: the arity rule must be derived. */
    private static final String ONE_PROP =
        "import { StatefulSmartContract, ByteString, assert } from 'runar-lang';\n"
        + "class C extends StatefulSmartContract {\n"
        + "  count: bigint;\n"
        + "  readonly blob: ByteString;\n"
        + "  constructor(count: bigint, blob: ByteString) {\n"
        + "    super(count, blob);\n"
        + "    this.count = count;\n"
        + "    this.blob = blob;\n"
        + "  }\n"
        + "  public m(n: bigint) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(1000n, this.count);\n"
        + "    this.addRawOutput(500n, this.blob);\n"
        + "  }\n"
        + "}\n";

    /**
     * A FixedArray state property, from
     * {@code compilers/python/tests/test_r025_expand_fixed_arrays_field_preservation.py}
     * — checked into this repo and compiled by all six non-TS tiers. The
     * TypeScript reference rejects it ("expects 3 argument(s) ... got 5")
     * because its arity rule counts the DECLARED properties while the expansion
     * that follows splits them; that is a defect in the reference rule, not in
     * this source. It must keep compiling here.
     */
    private static final String FIXED_ARRAY_STATE =
        "import { StatefulSmartContract, assert } from 'runar-lang';\n"
        + "import type { FixedArray } from 'runar-lang';\n"
        + "class Boardy extends StatefulSmartContract {\n"
        + "  board: FixedArray<bigint, 3> = [0n, 0n, 0n];\n"
        + "  n: bigint;\n"
        + "  constructor(n: bigint) { super(n); this.n = n; }\n"
        + "  public bump(): void {"
        + " this.addOutput(1000n, this.board[0], this.board[1], this.board[2], this.n); }\n"
        + "}\n";

    // -----------------------------------------------------------------------

    /** The exact chain {@code runar.lang.sdk.CompileCheck} runs. */
    private static List<String> frontendErrors(String src) throws Exception {
        ContractNode c = ParserDispatch.parse(src, "C.runar.ts");
        Validate.run(c);
        c = ExpandFixedArrays.run(c);
        return Typecheck.collect(c);
    }

    private static void assertRejected(String src, String needle) throws Exception {
        List<String> errs = frontendErrors(src);
        assertFalse(errs.isEmpty(), "expected the Java frontend to REJECT this source");
        assertTrue(
            errs.stream().anyMatch(e -> e.contains(needle)),
            "expected a diagnostic containing \"" + needle + "\", got " + errs
        );
    }

    private static String hex(String src) throws Exception {
        ContractNode contract = ParserDispatch.parse(src, "C.runar.ts");
        Validate.run(contract);
        contract = ExpandFixedArrays.run(contract);
        Typecheck.run(contract);
        AnfProgram anf = AnfLower.run(contract);
        anf = Cli.optimizeAnf(anf, false); // fold-ON, the user-facing default
        StackProgram stack = StackLower.run(anf);
        return Emit.run(Peephole.run(stack));
    }

    // --- the defect --------------------------------------------------------

    @Test
    void addOutputArity() throws Exception {
        assertRejected(ARITY_TOO_FEW,
            "addOutput() expects 3 argument(s): satoshis + 2 state value(s), got 2");
        assertRejected(ARITY_TOO_MANY,
            "addOutput() expects 3 argument(s): satoshis + 2 state value(s), got 4");
    }

    @Test
    void rawAndDataOutputArity() throws Exception {
        assertRejected(RAW_ARITY_ONE,
            "addRawOutput() expects 2 arguments (satoshis, scriptBytes), got 1");
        assertRejected(RAW_ARITY_THREE,
            "addRawOutput() expects 2 arguments (satoshis, scriptBytes), got 3");
        assertRejected(DATA_ARITY_THREE,
            "addDataOutput() expects 2 arguments (satoshis, scriptBytes), got 3");
    }

    @Test
    void addOutputStateValueTypes() throws Exception {
        assertRejected(STATE_VALUE_WRONG_TYPE,
            "addOutput() argument 2 (count) must be 'bigint', got 'ByteString'");
    }

    @Test
    void outputIntrinsicsAreStatefulOnly() throws Exception {
        assertRejected(STATELESS_ADD_OUTPUT,
            "addOutput() is only available in StatefulSmartContract");
        assertRejected(STATELESS_ADD_RAW_OUTPUT,
            "addRawOutput() is only available in StatefulSmartContract");
        assertRejected(STATELESS_ADD_DATA_OUTPUT,
            "addDataOutput() is only available in StatefulSmartContract");
    }

    // --- controls ----------------------------------------------------------

    @Test
    void acceptedOutputShapes() throws Exception {
        for (String src : List.of(
                SHAPE_EXACT, SHAPE_FAMILY_WIDENING, SHAPE_UNKNOWN_STATE_VALUE)) {
            assertTrue(frontendErrors(src).isEmpty(), "a legal output shape was rejected");
            assertFalse(hex(src).isEmpty(), "compiled to an empty script");
        }
    }

    /**
     * Non-vacuity: the arity rule must be derived from the contract's mutable
     * properties, not hardcoded.
     */
    @Test
    void arityIsDerivedFromMutableProperties() throws Exception {
        assertFalse(hex(ONE_PROP).isEmpty());
        assertFalse(hex(SHAPE_EXACT).isEmpty());
    }

    @Test
    void fixedArrayStateStaysCompilable() throws Exception {
        assertTrue(frontendErrors(FIXED_ARRAY_STATE).isEmpty(),
            "a FixedArray-state contract must stay compilable");
        assertFalse(hex(FIXED_ARRAY_STATE).isEmpty());
    }
}
