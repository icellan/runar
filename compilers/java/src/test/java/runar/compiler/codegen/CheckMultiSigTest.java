package runar.compiler.codegen;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.JavaParser;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.stack.BigIntPushValue;
import runar.compiler.ir.stack.IfOp;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.PushValue;
import runar.compiler.ir.stack.StackMethod;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.StackProgram;
import runar.compiler.passes.AnfLower;
import runar.compiler.passes.Emit;
import runar.compiler.passes.ExpandFixedArrays;
import runar.compiler.passes.Peephole;
import runar.compiler.passes.StackLower;
import runar.compiler.passes.Typecheck;
import runar.compiler.passes.Validate;

/**
 * Dedicated unit tests for the Java {@code checkMultiSig} codegen.
 *
 * <p>The reference shape (mirrored across all 7 compilers) for
 * {@code checkMultiSig([sig1, sig2], [pk1, pk2, pk3])} is:
 *
 * <pre>
 *   OP_0 &lt;sig1&gt; &lt;sig2&gt; 2 &lt;pk1&gt; &lt;pk2&gt; &lt;pk3&gt; 3 OP_CHECKMULTISIG
 * </pre>
 *
 * Where:
 * <ul>
 *   <li>{@code OP_0} is the off-by-one dummy push required by Bitcoin's
 *       legacy CHECKMULTISIG implementation.</li>
 *   <li>{@code 2} ({@code OP_2}) is the count of signatures.</li>
 *   <li>{@code 3} ({@code OP_3}) is the count of public keys.</li>
 *   <li>{@code OP_CHECKMULTISIG} is byte {@code 0xae}.</li>
 * </ul>
 *
 * Audit GAP-036 (Section 4 / F11): Java was the only tier without a
 * dedicated checkMultiSig codegen test — the conformance fixture
 * {@code conformance/tests/multisig-2of3} exercises it transitively, but a
 * regression in {@code StackLower#lowerCheckMultiSig} would only surface
 * as a hex divergence in CI rather than a failed unit test inside the
 * Java compiler itself.
 */
class CheckMultiSigTest {

    /** Minimal 2-of-3 multisig fixture using the in-tree Java surface. */
    private static final String MULTISIG_2OF3_SRC = """
        package runar.examples.multisig2of3;

        import runar.lang.SmartContract;
        import runar.lang.annotations.Public;
        import runar.lang.annotations.Readonly;
        import runar.lang.types.PubKey;
        import runar.lang.types.Sig;

        import static runar.lang.Builtins.assertThat;
        import static runar.lang.Builtins.checkMultiSig;

        public class MultiSig2of3 extends SmartContract {
            @Readonly PubKey pk1;
            @Readonly PubKey pk2;
            @Readonly PubKey pk3;

            public MultiSig2of3(PubKey pk1, PubKey pk2, PubKey pk3) {
                super(pk1, pk2, pk3);
                this.pk1 = pk1;
                this.pk2 = pk2;
                this.pk3 = pk3;
            }

            @Public
            public void unlock(Sig sig1, Sig sig2) {
                assertThat(checkMultiSig(new Sig[]{sig1, sig2}, new PubKey[]{pk1, pk2, pk3}));
            }
        }
        """;

    /** 3-of-5 variant — used to verify the count pushes are derived from
     *  the array literals rather than hard-coded for the 2/3 case. */
    private static final String MULTISIG_3OF5_SRC = """
        package runar.examples.multisig3of5;

        import runar.lang.SmartContract;
        import runar.lang.annotations.Public;
        import runar.lang.annotations.Readonly;
        import runar.lang.types.PubKey;
        import runar.lang.types.Sig;

        import static runar.lang.Builtins.assertThat;
        import static runar.lang.Builtins.checkMultiSig;

        public class MultiSig3of5 extends SmartContract {
            @Readonly PubKey pk1;
            @Readonly PubKey pk2;
            @Readonly PubKey pk3;
            @Readonly PubKey pk4;
            @Readonly PubKey pk5;

            public MultiSig3of5(PubKey pk1, PubKey pk2, PubKey pk3, PubKey pk4, PubKey pk5) {
                super(pk1, pk2, pk3, pk4, pk5);
                this.pk1 = pk1;
                this.pk2 = pk2;
                this.pk3 = pk3;
                this.pk4 = pk4;
                this.pk5 = pk5;
            }

            @Public
            public void unlock(Sig sig1, Sig sig2, Sig sig3) {
                assertThat(checkMultiSig(
                    new Sig[]{sig1, sig2, sig3},
                    new PubKey[]{pk1, pk2, pk3, pk4, pk5}));
            }
        }
        """;

    // -------------------- pipeline helpers --------------------

    private static StackProgram compile(String src, String filename) {
        ContractNode contract = JavaParser.parse(src, filename);
        Validate.run(contract);
        contract = ExpandFixedArrays.run(contract);
        Typecheck.run(contract);
        AnfProgram anf = AnfLower.run(contract);
        return StackLower.run(anf);
    }

    private static StackMethod findMethod(StackProgram p, String name) {
        for (StackMethod m : p.methods()) {
            if (m.name().equals(name)) return m;
        }
        throw new IllegalArgumentException("method not found: " + name);
    }

    /** Recursively flatten ops, descending into IfOp branches. */
    private static List<StackOp> flatten(List<StackOp> ops) {
        List<StackOp> out = new ArrayList<>();
        for (StackOp op : ops) {
            out.add(op);
            if (op instanceof IfOp i) {
                if (i.thenBranch() != null) out.addAll(flatten(i.thenBranch()));
                if (i.elseBranch() != null) out.addAll(flatten(i.elseBranch()));
            }
        }
        return out;
    }

    private static int countOpcode(List<StackOp> flat, String code) {
        int n = 0;
        for (StackOp op : flat) {
            if (op instanceof OpcodeOp o && o.code().equals(code)) n++;
        }
        return n;
    }

    /** Count PushOps whose value equals the given small integer (e.g. 0, 2, 3). */
    private static int countIntPush(List<StackOp> flat, int value) {
        BigInteger target = BigInteger.valueOf(value);
        int n = 0;
        for (StackOp op : flat) {
            if (op instanceof PushOp p) {
                PushValue pv = p.value();
                if (pv instanceof BigIntPushValue b && b.value().equals(target)) {
                    n++;
                }
            }
        }
        return n;
    }

    // -------------------- 2-of-3 shape goldens --------------------

    @Test
    void multiSig2of3EmitsExactlyOneCheckMultiSig() {
        StackProgram p = compile(MULTISIG_2OF3_SRC, "MultiSig2of3.runar.java");
        StackMethod unlock = findMethod(p, "unlock");
        List<StackOp> flat = flatten(unlock.ops());
        assertEquals(1, countOpcode(flat, "OP_CHECKMULTISIG"),
            "exactly one OP_CHECKMULTISIG must be emitted");
        // Must NOT emit OP_CHECKMULTISIGVERIFY at the StackLower stage —
        // that fold belongs to Peephole and should not pre-empt the dispatch.
        assertEquals(0, countOpcode(flat, "OP_CHECKMULTISIGVERIFY"),
            "StackLower must emit OP_CHECKMULTISIG, not OP_CHECKMULTISIGVERIFY");
    }

    @Test
    void multiSig2of3EmitsOpZeroDummy() {
        // The Bitcoin CHECKMULTISIG off-by-one bug requires a leading OP_0
        // (push 0). Without it, the script will fail at runtime with a
        // signature-count mismatch.
        StackProgram p = compile(MULTISIG_2OF3_SRC, "MultiSig2of3.runar.java");
        StackMethod unlock = findMethod(p, "unlock");
        List<StackOp> flat = flatten(unlock.ops());
        assertTrue(countIntPush(flat, 0) >= 1,
            "expected at least one push(0) for the OP_0 dummy");
    }

    @Test
    void multiSig2of3EmitsCorrectCountPushes() {
        // 2 sigs and 3 pks: must push 2 (nSigs) and 3 (nPks).
        StackProgram p = compile(MULTISIG_2OF3_SRC, "MultiSig2of3.runar.java");
        StackMethod unlock = findMethod(p, "unlock");
        List<StackOp> flat = flatten(unlock.ops());
        assertTrue(countIntPush(flat, 2) >= 1,
            "expected push(2) for nSigs");
        assertTrue(countIntPush(flat, 3) >= 1,
            "expected push(3) for nPks");
    }

    // -------------------- 3-of-5 shape goldens --------------------

    @Test
    void multiSig3of5UsesCountsDerivedFromArrays() {
        // The 3-of-5 variant must push 3 (nSigs) and 5 (nPks) — proving
        // counts come from the array literal lengths, not hard-coded.
        StackProgram p = compile(MULTISIG_3OF5_SRC, "MultiSig3of5.runar.java");
        StackMethod unlock = findMethod(p, "unlock");
        List<StackOp> flat = flatten(unlock.ops());
        assertEquals(1, countOpcode(flat, "OP_CHECKMULTISIG"),
            "exactly one OP_CHECKMULTISIG must be emitted");
        assertTrue(countIntPush(flat, 3) >= 1,
            "expected push(3) for nSigs in 3-of-5");
        assertTrue(countIntPush(flat, 5) >= 1,
            "expected push(5) for nPks in 3-of-5");
    }

    @Test
    void multiSig3of5DiffersFromMultiSig2of3() {
        // Sanity: the two contracts must produce different stack programs.
        // If a regression caused the array-length lookup to silently fall
        // back to a default (e.g. 1), the two would converge.
        StackProgram p2 = compile(MULTISIG_2OF3_SRC, "MultiSig2of3.runar.java");
        StackProgram p3 = compile(MULTISIG_3OF5_SRC, "MultiSig3of5.runar.java");
        List<StackOp> ops2 = flatten(findMethod(p2, "unlock").ops());
        List<StackOp> ops3 = flatten(findMethod(p3, "unlock").ops());
        // 3-of-5 has more pubkeys → strictly more ops in the unlock body.
        assertTrue(ops3.size() > ops2.size(),
            "3-of-5 must produce a larger unlock body than 2-of-3; "
                + "got ops3=" + ops3.size() + ", ops2=" + ops2.size());
    }

    // -------------------- byte-level hex pin --------------------

    @Test
    void multiSig2of3HexContainsCheckMultiSigOpcodeByte() {
        // Drive the full pipeline (StackLower → Peephole → Emit) and assert
        // the resulting hex contains the OP_CHECKMULTISIG opcode byte (0xae)
        // OR its peephole-folded variant OP_CHECKMULTISIGVERIFY (0xaf, the
        // result of the OP_CHECKMULTISIG + OP_VERIFY peephole at
        // Peephole.java:147-148). We assert one OR the other, since the
        // surrounding `assertThat(checkMultiSig(...))` may trigger the fold.
        StackProgram stack = compile(MULTISIG_2OF3_SRC, "MultiSig2of3.runar.java");
        StackProgram folded = Peephole.run(stack);
        String hex = Emit.run(folded);
        assertFalse(hex.isEmpty(), "hex must not be empty");
        boolean hasMultiSig = hex.contains("ae");
        boolean hasMultiSigVerify = hex.contains("af");
        assertTrue(hasMultiSig || hasMultiSigVerify,
            "hex must contain OP_CHECKMULTISIG (ae) or OP_CHECKMULTISIGVERIFY (af); got:\n" + hex);
    }

    // -------------------- determinism --------------------

    @Test
    void multiSigLoweringIsDeterministic() {
        StackProgram a = compile(MULTISIG_2OF3_SRC, "MultiSig2of3.runar.java");
        StackProgram b = compile(MULTISIG_2OF3_SRC, "MultiSig2of3.runar.java");
        List<StackOp> opsA = flatten(findMethod(a, "unlock").ops());
        List<StackOp> opsB = flatten(findMethod(b, "unlock").ops());
        assertEquals(opsA.size(), opsB.size(),
            "checkMultiSig lowering op count must be deterministic");
    }
}
