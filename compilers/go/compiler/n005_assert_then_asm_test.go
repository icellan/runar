package compiler

// N-005 — an assert that is not the method's last binding must be lowered
// with OP_VERIFY.
//
// Stack lowering treated the LAST assert of a public method as terminal (its
// value left as the script result) even when a terminal asm() followed it.
// The asm pushed OP_1, the end-of-method cleanup NIPped the comparison away,
// and the method compiled to 012a9c5177 (<42> OP_NUMEQUAL OP_1 OP_NIP):
// spendable with ANY x. The hand-derived fixed script is 012a9d51
// (<42> OP_NUMEQUALVERIFY OP_1).
//
// Proves: this tier's bytes for the shape in both fold modes, and that a truly
// final assert still stays the method result. Does NOT prove on-chain
// behaviour — the Spend-engine proof for all seven tiers is
// packages/runar-testing/src/__tests__/n005-assert-then-asm-spend.test.ts.

import (
	"strings"
	"testing"
)

const n005AssertThenAsm = `import { UnsafeSmartContract, assert, asm } from 'runar-lang';

class AssertThenAsm extends UnsafeSmartContract {
  constructor() {
    super();
  }

  public unlock(x: bigint) {
    assert(x === 42n);
    asm({ body: '51', in_arity: 0, out_arity: 1 });
  }
}
`

const n005AsmThenAssert = `import { UnsafeSmartContract, assert, asm } from 'runar-lang';

class AsmThenAssert extends UnsafeSmartContract {
  constructor() {
    super();
  }

  public unlock(x: bigint) {
    asm({ body: '51', in_arity: 0, out_arity: 1 });
    assert(x === 42n);
  }
}
`

func n005Hex(t *testing.T, source string, disableFold bool) string {
	t.Helper()
	r := CompileFromSourceStrWithResult(source, "AssertThenAsm.runar.ts", CompileOptions{DisableConstantFolding: disableFold})
	if !r.Success || r.Artifact == nil {
		var msgs []string
		for _, d := range r.Diagnostics {
			msgs = append(msgs, d.Message)
		}
		t.Fatalf("compile failed: %s", strings.Join(msgs, "; "))
	}
	return r.Artifact.Script
}

func TestN005_AssertBeforeTerminalAsmIsVerified(t *testing.T) {
	for _, disableFold := range []bool{true, false} {
		got := n005Hex(t, n005AssertThenAsm, disableFold)
		if got == "012a9c5177" {
			t.Fatalf("fold-off=%v: assert left unenforced (pre-fix bytes %s)", disableFold, got)
		}
		if got != "012a9d51" {
			t.Fatalf("fold-off=%v: want 012a9d51 (<42> OP_NUMEQUALVERIFY OP_1), got %s", disableFold, got)
		}
	}
}

func TestN005_FinalAssertStaysTheResult(t *testing.T) {
	// OP_1 OP_SWAP <42> OP_NUMEQUAL (terminal, no OP_VERIFY) OP_NIP
	if got := n005Hex(t, n005AsmThenAssert, true); got != "517c012a9c77" {
		t.Fatalf("want 517c012a9c77, got %s", got)
	}
}
