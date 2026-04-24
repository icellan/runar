package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.stack.DropOp;
import runar.compiler.ir.stack.DupOp;
import runar.compiler.ir.stack.IfOp;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.OverOp;
import runar.compiler.ir.stack.PickOp;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.PushValue;
import runar.compiler.ir.stack.RollOp;
import runar.compiler.ir.stack.RotOp;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.SwapOp;

class PeepholeTest {

    // ---- 2-op rules ----

    @Test
    void pushDropRemovedAsDeadValue() {
        List<StackOp> r = Peephole.optimize(List.of(new PushOp(PushValue.of(7)), new DropOp()));
        assertEquals(0, r.size());
    }

    @Test
    void dupDropRemoved() {
        List<StackOp> r = Peephole.optimize(List.of(new DupOp(), new DropOp()));
        assertEquals(0, r.size());
    }

    @Test
    void swapSwapRemoved() {
        List<StackOp> r = Peephole.optimize(List.of(new SwapOp(), new SwapOp()));
        assertEquals(0, r.size());
    }

    @Test
    void push1AddBecomesOp1Add() {
        List<StackOp> r = Peephole.optimize(List.of(new PushOp(PushValue.of(1)), new OpcodeOp("OP_ADD")));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof OpcodeOp o && "OP_1ADD".equals(o.code()));
    }

    @Test
    void push1SubBecomesOp1Sub() {
        List<StackOp> r = Peephole.optimize(List.of(new PushOp(PushValue.of(1)), new OpcodeOp("OP_SUB")));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof OpcodeOp o && "OP_1SUB".equals(o.code()));
    }

    @Test
    void pushZeroAddIsIdentity() {
        List<StackOp> r = Peephole.optimize(List.of(new PushOp(PushValue.of(0)), new OpcodeOp("OP_ADD")));
        assertEquals(0, r.size());
    }

    @Test
    void pushZeroSubIsIdentity() {
        List<StackOp> r = Peephole.optimize(List.of(new PushOp(PushValue.of(0)), new OpcodeOp("OP_SUB")));
        assertEquals(0, r.size());
    }

    @Test
    void doubleOpNotCancels() {
        List<StackOp> r = Peephole.optimize(List.of(new OpcodeOp("OP_NOT"), new OpcodeOp("OP_NOT")));
        assertEquals(0, r.size());
    }

    @Test
    void doubleOpNegateCancels() {
        List<StackOp> r = Peephole.optimize(List.of(new OpcodeOp("OP_NEGATE"), new OpcodeOp("OP_NEGATE")));
        assertEquals(0, r.size());
    }

    @Test
    void equalVerifyFoldsToEqualVerify() {
        List<StackOp> r = Peephole.optimize(List.of(new OpcodeOp("OP_EQUAL"), new OpcodeOp("OP_VERIFY")));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof OpcodeOp o && "OP_EQUALVERIFY".equals(o.code()));
    }

    @Test
    void checksigVerifyFoldsToChecksigVerify() {
        List<StackOp> r = Peephole.optimize(List.of(new OpcodeOp("OP_CHECKSIG"), new OpcodeOp("OP_VERIFY")));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof OpcodeOp o && "OP_CHECKSIGVERIFY".equals(o.code()));
    }

    @Test
    void numequalVerifyFolds() {
        List<StackOp> r = Peephole.optimize(List.of(new OpcodeOp("OP_NUMEQUAL"), new OpcodeOp("OP_VERIFY")));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof OpcodeOp o && "OP_NUMEQUALVERIFY".equals(o.code()));
    }

    @Test
    void checkmultisigVerifyFolds() {
        List<StackOp> r = Peephole.optimize(List.of(new OpcodeOp("OP_CHECKMULTISIG"), new OpcodeOp("OP_VERIFY")));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof OpcodeOp o && "OP_CHECKMULTISIGVERIFY".equals(o.code()));
    }

    @Test
    void dupOpDropCancels() {
        List<StackOp> r = Peephole.optimize(List.of(new OpcodeOp("OP_DUP"), new OpcodeOp("OP_DROP")));
        assertEquals(0, r.size());
    }

    @Test
    void overOverBecomes2Dup() {
        List<StackOp> r = Peephole.optimize(List.of(new OverOp(), new OverOp()));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof OpcodeOp o && "OP_2DUP".equals(o.code()));
    }

    @Test
    void dropDropBecomes2Drop() {
        List<StackOp> r = Peephole.optimize(List.of(new DropOp(), new DropOp()));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof OpcodeOp o && "OP_2DROP".equals(o.code()));
    }

    @Test
    void push0Roll0Removed() {
        List<StackOp> r = Peephole.optimize(List.of(new PushOp(PushValue.of(0)), new RollOp(0)));
        assertEquals(0, r.size());
    }

    @Test
    void push1Roll1BecomesSwap() {
        List<StackOp> r = Peephole.optimize(List.of(new PushOp(PushValue.of(1)), new RollOp(1)));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof SwapOp);
    }

    @Test
    void push2Roll2BecomesRot() {
        List<StackOp> r = Peephole.optimize(List.of(new PushOp(PushValue.of(2)), new RollOp(2)));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof RotOp);
    }

    @Test
    void push0Pick0BecomesDup() {
        List<StackOp> r = Peephole.optimize(List.of(new PushOp(PushValue.of(0)), new PickOp(0)));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof DupOp);
    }

    @Test
    void push1Pick1BecomesOver() {
        List<StackOp> r = Peephole.optimize(List.of(new PushOp(PushValue.of(1)), new PickOp(1)));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof OverOp);
    }

    @Test
    void sha256Sha256BecomesHash256() {
        List<StackOp> r = Peephole.optimize(List.of(new OpcodeOp("OP_SHA256"), new OpcodeOp("OP_SHA256")));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof OpcodeOp o && "OP_HASH256".equals(o.code()));
    }

    @Test
    void push0NumequalBecomesNot() {
        List<StackOp> r = Peephole.optimize(List.of(new PushOp(PushValue.of(0)), new OpcodeOp("OP_NUMEQUAL")));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof OpcodeOp o && "OP_NOT".equals(o.code()));
    }

    // ---- 3-op rules ----

    @Test
    void pushPushAddFoldsToPush() {
        List<StackOp> r = Peephole.optimize(List.of(
            new PushOp(PushValue.of(5)),
            new PushOp(PushValue.of(7)),
            new OpcodeOp("OP_ADD")
        ));
        // After constant-fold: PUSH(12), but PUSH(12) (bigint 12) gets emitted later as OP_12.
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof PushOp p
            && p.value() instanceof runar.compiler.ir.stack.BigIntPushValue bi
            && bi.value().equals(BigInteger.valueOf(12)));
    }

    @Test
    void pushPushSubFoldsToPush() {
        List<StackOp> r = Peephole.optimize(List.of(
            new PushOp(PushValue.of(20)),
            new PushOp(PushValue.of(6)),
            new OpcodeOp("OP_SUB")
        ));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof PushOp p
            && p.value() instanceof runar.compiler.ir.stack.BigIntPushValue bi
            && bi.value().equals(BigInteger.valueOf(14)));
    }

    @Test
    void pushPushMulFoldsToPush() {
        List<StackOp> r = Peephole.optimize(List.of(
            new PushOp(PushValue.of(3)),
            new PushOp(PushValue.of(4)),
            new OpcodeOp("OP_MUL")
        ));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof PushOp p
            && p.value() instanceof runar.compiler.ir.stack.BigIntPushValue bi
            && bi.value().equals(BigInteger.valueOf(12)));
    }

    // ---- 4-op rules ----

    @Test
    void pushAddPushAddChainFolds() {
        List<StackOp> r = Peephole.optimize(List.of(
            new PushOp(PushValue.of(3)),
            new OpcodeOp("OP_ADD"),
            new PushOp(PushValue.of(5)),
            new OpcodeOp("OP_ADD")
        ));
        // The first two PushOp/Add/Push/Add window folds to PUSH(8) + OP_ADD.
        // Then peephole pass 2 sees PUSH(8) OP_ADD. PUSH(8) is not 0 or 1, so
        // nothing further happens — final is [PUSH(8), OP_ADD].
        assertEquals(2, r.size());
        assertTrue(r.get(0) instanceof PushOp);
        assertTrue(r.get(1) instanceof OpcodeOp o && "OP_ADD".equals(o.code()));
    }

    @Test
    void pushSubPushSubChainFolds() {
        List<StackOp> r = Peephole.optimize(List.of(
            new PushOp(PushValue.of(3)),
            new OpcodeOp("OP_SUB"),
            new PushOp(PushValue.of(5)),
            new OpcodeOp("OP_SUB")
        ));
        assertEquals(2, r.size());
        assertTrue(r.get(0) instanceof PushOp);
        assertTrue(r.get(1) instanceof OpcodeOp o && "OP_SUB".equals(o.code()));
    }

    // ---- Recursive if-branch optimisation ----

    @Test
    void ifBranchesAreOptimisedRecursively() {
        List<StackOp> thenB = new ArrayList<>();
        thenB.add(new SwapOp());
        thenB.add(new SwapOp());
        thenB.add(new OpcodeOp("OP_CHECKSIG"));
        thenB.add(new OpcodeOp("OP_VERIFY"));

        IfOp ifop = new IfOp(thenB);
        List<StackOp> r = Peephole.optimize(List.of(ifop));
        assertEquals(1, r.size());
        IfOp out = (IfOp) r.get(0);
        // Peephole should have killed the SWAP/SWAP and merged CHECKSIG+VERIFY.
        assertEquals(1, out.thenBranch().size(), "then-branch should reduce to a single op");
        assertTrue(out.thenBranch().get(0) instanceof OpcodeOp o && "OP_CHECKSIGVERIFY".equals(o.code()));
    }

    // ---- End-to-end: P2PKH reduces to SWAP-less form ----

    @Test
    void fullP2pkhPeepholeMatchesCanonicalHexLayout() {
        // SWAP SWAP SWAP SWAP OP_CHECKSIG OP_VERIFY  -> OP_CHECKSIGVERIFY
        List<StackOp> r = Peephole.optimize(List.of(
            new SwapOp(), new SwapOp(), new SwapOp(), new SwapOp(),
            new OpcodeOp("OP_CHECKSIG"), new OpcodeOp("OP_VERIFY")
        ));
        assertEquals(1, r.size());
        assertTrue(r.get(0) instanceof OpcodeOp o && "OP_CHECKSIGVERIFY".equals(o.code()));
    }
}
