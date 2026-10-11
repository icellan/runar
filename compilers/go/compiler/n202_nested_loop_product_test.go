// N-202: the source path bounds the PRODUCT of nested loop counts, not just
// each loop's own count.
//
// extractLoopShape caps one for-loop at ir.MaxLoopCount (10,000). Two loops of
// 9,000, one inside the other, each passed that cap while the unrolled work was
// 81,000,000 iterations. F-283 refuses the same nest on the --ir path, so a
// source contract compiled while its own emitted IR was refused on replay.
//
// Proves: on the Go source path a 101 x 100 nest is refused with the shared
// product diagnostic, also when the inner loop sits in an if arm, and a nest of
// exactly 10,000 still compiles. Each compile runs behind a watchdog, so a
// regression fails instead of hanging.
// Does not prove: the other tiers (conformance/negatives/n202-nested-loop-
// product-parity.test.ts), or loops reached through a private method call that
// stack lowering inlines later — the bound is per-method nesting in ANF, the
// same rule the --ir loader applies.
package compiler

import (
	"fmt"
	"testing"
	"time"
)

func n202NestedLoopSource(outer, inner int, inIfArm bool) string {
	innerLoop := fmt.Sprintf("for (let j = 0n; j < %dn; j++) { acc = acc + x; }", inner)
	if inIfArm {
		innerLoop = "if (x > 0n) { " + innerLoop + " }"
	}
	return fmt.Sprintf(`import { SmartContract, assert } from 'runar-lang';

export class NestedLoops extends SmartContract {
  constructor() { super(); }

  public unlock(x: bigint): void {
    let acc: bigint = 0n;
    for (let i = 0n; i < %dn; i++) { %s }
    assert(acc > x);
  }
}
`, outer, innerLoop)
}

func n202Compile(t *testing.T, src string) *CompileResult {
	t.Helper()
	done := make(chan *CompileResult, 1)
	go func() { done <- CompileFromSourceStrWithResult(src, "NestedLoops.runar.ts") }()
	select {
	case res := <-done:
		return res
	case <-time.After(60 * time.Second):
		t.Fatal("compile did not finish within 60s — nested loops are being unrolled unbounded")
		return nil
	}
}

const n202ProductDiag = "For loop unrolls to 100 iterations nested inside an enclosing loop of total count 101, " +
	"producing 10100 total iterations, exceeding the maximum loop count of 10000."

func TestN202_NestedLoopProductOverMax_IsRejected(t *testing.T) {
	for _, inIfArm := range []bool{false, true} {
		res := n202Compile(t, n202NestedLoopSource(101, 100, inIfArm))
		if res.Success {
			t.Fatalf("ifArm=%v: expected the 101 x 100 nest to be refused, got a successful compile", inIfArm)
		}
		if !diagnosticsMention(res, n202ProductDiag) {
			t.Errorf("ifArm=%v: expected diagnostic %q, got %v", inIfArm, n202ProductDiag, res.Diagnostics)
		}
	}
}

func TestN202_NestedLoopProductAtMax_StillCompiles(t *testing.T) {
	res := n202Compile(t, n202NestedLoopSource(100, 100, false))
	if !res.Success {
		t.Fatalf("expected the 100 x 100 nest to compile, got %v", res.Diagnostics)
	}
}
