package conformance

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	scriptflag "github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
)

// ---------------------------------------------------------------------------
// `split` followed by a read must resolve that read to the right stack slot.
//
// OP_SPLIT genuinely produces two stack items. Rúnar's `split(data, index)` is
// specified — spec/grammar.md, spec/type-system.md, and all seven typecheckers
// — as a single-valued `ByteString` returning the RIGHT half. Until the fix
// this file exists for, the lowering emitted a bare OP_SPLIT and recorded the
// left half as a nameless slot that nothing ever dropped. The model's depth
// then diverged from the runtime stack and the next `bringToTop` resolved to
// the wrong slot.
//
// WHAT THIS IS NOT. The orphaned slot does NOT reach the end of the script:
// the method epilogue's `cleanupExcessStack()` NIPs everything below the
// result, so a split that is the last thing a method does terminates with a
// clean stack and always has. That was measured, not assumed — the single-
// method shape compiled to `OP_ROT OP_ROT OP_SPLIT OP_ROT OP_EQUAL OP_NIP`,
// and the trailing NIP is the epilogue removing the left half. So no output was
// ever stuck and no funds were ever at risk. The `tailOnly` rows below assert
// that property rather than claiming it, so the fix cannot regress it by
// dropping one item too many.
//
// WHAT IT IS. Every shape that reads anything after the split — which is
// nearly every real contract — hits the desync. That surfaced as a compile
// abort (`Value 't11' not found on stack`), pinned on the compile side by
// conformance/split-stack-desync.test.ts. A compile abort is a guard, not a
// loss, but it made the builtin unusable: the only shape anyone had ever
// written is the one that happens to compile, which is why every fixture,
// every example and the fuzzer's own corpus missed it.
//
// A compile that now SUCCEEDS proves nothing on its own — a stack-model change
// that type-checks while leaving the runtime stack one item off is exactly the
// bug class this branch exists to catch. So these rows do not stop at
// compiling: they spend the compiled script on the go-sdk consensus
// interpreter, read back a value bound BEFORE the split alongside the split's
// own result, and require wrong values to be REJECTED.
//
// The compiler under test is TypeScript; the interpreter is the go-sdk
// consensus engine.
// ---------------------------------------------------------------------------

// splitResidueSource builds a stateless contract whose methods read values
// across a `split`, which is what no existing fixture did.
func splitResidueSource() string {
	return `import { SmartContract, assert, len, split } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class SplitResidue extends SmartContract {
  constructor() { super(); }

  /**
   * A binding made BEFORE the split is read AFTER it. With an orphaned slot
   * between them the read resolves to the wrong depth.
   */
  public priorBinding(data: ByteString, idx: bigint, expectedTail: ByteString, expectedLen: bigint): void {
    const n: bigint = len(data);
    const tail: ByteString = split(data, idx);
    assert(tail == expectedTail);
    assert(n == expectedLen);
  }

  /**
   * The shape the fuzzer's split arm produced on its first seeded run: a
   * short-circuit && after the split, which lowers to a branch whose residue
   * drain cannot tell the parent's orphaned slot from its own.
   */
  public branchAfterSplit(data: ByteString, idx: bigint, expectedTail: ByteString): void {
    const tail: ByteString = split(data, idx);
    assert(len(tail) >= 0n && len(data) >= 0n);
    assert(tail == expectedTail);
  }

  /**
   * The only shape that ever compiled: nothing follows the split. The
   * epilogue already cleaned up after it; these rows hold that so the fix
   * cannot drop one item too many and leave the result unreachable.
   */
  public tailOnly(data: ByteString, idx: bigint, expectedTail: ByteString): void {
    const tail: ByteString = split(data, idx);
    assert(tail == expectedTail);
  }
}
`
}

const (
	srPriorBinding     = 0
	srBranchAfterSplit = 1
	srTailOnly         = 2
)

// spendSplitResidue spends `method` of the SplitResidue contract under the
// standardness flag set a real node applies. Reports whether the interpreter
// ACCEPTED.
func spendSplitResidue(t *testing.T, method int, pushes ...string) bool {
	t.Helper()
	lockingHex, err := compileRúnarInline(splitResidueSource(), `{}`, "SplitResidue.runar.ts")
	if err != nil {
		t.Fatalf("compiling SplitResidue: %v", err)
	}
	unlocking := strings.Join(pushes, "") + encodePushInt(int64(method))
	return executeCleanStack(lockingHex, unlocking) == nil
}

// executeCleanStack runs a spend under exactly the config `executeScript` uses
// — post-Chronicle, fork-id — PLUS the one standardness flag `executeScript`
// omits. VerifyCleanStack is the whole point of this file: it is what a node
// applies, and a stray stack item makes the spend non-standard, so the output
// is neither relayed nor mined.
//
// go-sdk refuses VerifyCleanStack unless Bip16 is also set (thread.go:304), so
// it is passed too. Bip16 only changes evaluation for a locking script that is
// literally OP_HASH160 <20 bytes> OP_EQUAL; no Rúnar script has that shape, so
// it is inert here and the clean-stack check is the only behaviour it buys.
func executeCleanStack(lockingHex, unlockingHex string) error {
	locking, err := script.NewFromHex(lockingHex)
	if err != nil {
		return fmt.Errorf("invalid locking script hex: %w", err)
	}
	unlocking, err := script.NewFromHex(unlockingHex)
	if err != nil {
		return fmt.Errorf("invalid unlocking script hex: %w", err)
	}
	eng := interpreter.NewEngine()
	return eng.Execute(
		interpreter.WithScripts(locking, unlocking),
		interpreter.WithAfterChronicle(),
		interpreter.WithForkID(),
		interpreter.WithFlags(scriptflag.VerifyCleanStack|scriptflag.Bip16),
	)
}

// TestSplit_ReadAcrossSplit_Spends is the load-bearing row: a value bound
// before the split is read after it, and the whole thing has to spend under
// clean-stack. Before the lowering fix this did not even COMPILE.
func TestSplit_ReadAcrossSplit_Spends(t *testing.T) {
	const data = "aabbccdd" // 4 bytes

	if !spendSplitResidue(t, srPriorBinding,
		pushHexBytes(t, data), encodePushInt(2), pushHexBytes(t, "ccdd"), encodePushInt(4)) {
		t.Fatal("split followed by a read of an earlier binding did not spend under clean-stack")
	}

	// Teeth: the method must actually be checking both values, or the row above
	// would pass on a script that accepts anything.
	if spendSplitResidue(t, srPriorBinding,
		pushHexBytes(t, data), encodePushInt(2), pushHexBytes(t, "bbcc"), encodePushInt(4)) {
		t.Fatal("a wrong tail spent — the split result is not being compared")
	}
	if spendSplitResidue(t, srPriorBinding,
		pushHexBytes(t, data), encodePushInt(2), pushHexBytes(t, "ccdd"), encodePushInt(3)) {
		t.Fatal("a wrong length spent — the pre-split binding resolved to the wrong slot")
	}
}

// TestSplit_BranchAfterSplit_Spends covers the fuzzer's shape: a branch whose
// residue drain runs with the parent's orphaned slot in scope.
func TestSplit_BranchAfterSplit_Spends(t *testing.T) {
	const data = "aabbccdd"

	if !spendSplitResidue(t, srBranchAfterSplit,
		pushHexBytes(t, data), encodePushInt(2), pushHexBytes(t, "ccdd")) {
		t.Fatal("a branch after a split did not spend under clean-stack")
	}
	if spendSplitResidue(t, srBranchAfterSplit,
		pushHexBytes(t, data), encodePushInt(2), pushHexBytes(t, "aabb")) {
		t.Fatal("a wrong tail spent — the branch arm is not checking the split result")
	}
}

// TestSplit_TailOnly_LeavesCleanStack is the no-regression row: the shape that
// always compiled must still terminate with exactly one stack item.
func TestSplit_TailOnly_LeavesCleanStack(t *testing.T) {
	const data = "aabbccdd"

	for _, c := range []struct {
		name string
		data string
		idx  int64
		tail string
	}{
		// The two ends of the legal range plus the interior, mirroring
		// byte_builtins_execution_test.go's split table — the difference here
		// is the clean-stack flag.
		{"idx 0 binds the whole string", data, 0, "aabbccdd"},
		{"idx mid", data, 2, "ccdd"},
		{"idx == len binds the empty string", data, 4, ""},
		{"empty data at idx 0", "", 0, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if !spendSplitResidue(t, srTailOnly,
				pushHexBytes(t, c.data), encodePushInt(c.idx), pushHexBytes(t, c.tail)) {
				t.Fatalf("split(%q, %d) did not spend under clean-stack: the "+
					"lowering left the stack a different depth than the model "+
					"believes", c.data, c.idx)
			}
		})
	}
}

// TestByteBuiltins_Split_LeavesCleanStack pins the same requirement on the
// FIXTURE's own bytes, so the conformance corpus — and therefore all seven
// tiers, which are byte-identical on it — carries the property too. This row
// is GREEN before the fix as well: it is the control that says the fix did not
// buy clean-stack at the cost of breaking the shape that already worked.
func TestByteBuiltins_Split_LeavesCleanStack(t *testing.T) {
	args := `{"expectedDigest":"` + hex.EncodeToString(bbDigest[:]) +
		`","expectedRipemd":"` + hex.EncodeToString(bbRipemd) + `"}`
	lockingHex, err := compileRúnar("byte-builtins", args)
	if err != nil {
		t.Fatalf("compile byte-builtins: %v", err)
	}
	unlocking := pushHexBytes(t, "aabbccdd") + encodePushInt(2) + pushHexBytes(t, "ccdd") +
		encodePushInt(bbCheckSplit)
	if err := executeCleanStack(lockingHex, unlocking); err != nil {
		t.Fatalf("byte-builtins checkSplit no longer spends under clean-stack: %v", err)
	}
}
