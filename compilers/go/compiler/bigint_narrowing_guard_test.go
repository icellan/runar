// Package compiler — regression tests for CL-BUG-127 / R-013: the
// big.Int -> int narrowing family in the Go tier narrowed FIRST and
// range-checked SECOND, so every guard inspected an already-corrupted
// value.
//
// A for-loop bound outside the int64 range produced one of three silent
// wrong outcomes, never a diagnostic:
//
//	2^63      -> big.Int.Int64() == math.MinInt64 -> count negative ->
//	             ZERO iterations; the loop body vanished from the script.
//	2^64 + 10 -> big.Int.Int64() == 10 -> the loop unrolled 10 times,
//	             emitting a plausible script of the WRONG length.
//	10^20     -> big.Int.Int64() ~= 7.77e18 -> unbounded-memory hang.
//
// The contract these tests pin: an out-of-range loop bound is a
// compile-time diagnostic, and a valid loop still compiles to the exact
// same bytes it did before the guard existed.
package compiler

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// narrowingLoopSource builds a contract whose single public method
// unrolls a for loop with the given literal bound.
func narrowingLoopSource(bound string) string {
	return fmt.Sprintf(`import { SmartContract, assert } from 'runar-lang';

export class LoopBound extends SmartContract {
  constructor() { super(); }

  public unlock(x: bigint): void {
    let acc: bigint = 0n;
    for (let i = 0n; i < %sn; i++) {
      acc = acc + i;
    }
    assert(acc === x);
  }
}
`, bound)
}

// TestLoopBoundControl_StillCompilesByteIdentically is the control: a
// normal small bound must keep compiling, and to the exact bytes it
// produced before the range guard was added. These hex strings were
// captured at the pre-fix commit. If a guard ever changes them, the
// guard is not byte-neutral and the change is a codegen regression.
func TestLoopBoundControl_StillCompilesByteIdentically(t *testing.T) {
	cases := []struct {
		bound string
		hex   string
	}{
		{"3", "537c9c"},    // 0+1+2 = 3 -> OP_3 OP_SWAP OP_NUMEQUAL
		{"10", "012d7c9c"}, // 0+..+9 = 45 = 0x2d
	}
	for _, tc := range cases {
		for _, fold := range []bool{false, true} {
			res := CompileFromSourceStrWithResult(
				narrowingLoopSource(tc.bound),
				"LoopBound.runar.ts",
				CompileOptions{DisableConstantFolding: fold},
			)
			if !res.Success {
				t.Fatalf("bound=%s foldOff=%v: expected success, got diagnostics %v", tc.bound, fold, res.Diagnostics)
			}
			if res.ScriptHex != tc.hex {
				t.Errorf("bound=%s foldOff=%v: script hex changed\n  want %s\n  got  %s",
					tc.bound, fold, tc.hex, res.ScriptHex)
			}
		}
	}
}

// TestLoopBound_2Pow63_IsRejected covers outcome 1: Int64() wraps to
// MinInt64, the count goes negative, and the loop body silently
// disappears. Pre-fix this compiled to "007c9c" (OP_0 OP_SWAP
// OP_NUMEQUAL) — the accumulator never incremented.
func TestLoopBound_2Pow63_IsRejected(t *testing.T) {
	res := CompileFromSourceStrWithResult(narrowingLoopSource("9223372036854775808"), "LoopBound.runar.ts")
	assertLoopBoundRejected(t, res, "2^63")
}

// TestLoopBound_2Pow64Plus10_IsRejected covers outcome 2, the worst of
// the three: the bound wraps modulo 2^64 to 10 and the compiler emits a
// perfectly plausible 10-iteration script. Pre-fix this produced
// "012d7c9c" — byte-identical to a legitimate `i < 10n` loop, with no
// diagnostic to say the written bound was not the compiled one.
func TestLoopBound_2Pow64Plus10_IsRejected(t *testing.T) {
	src := narrowingLoopSource("18446744073709551626")
	res := CompileFromSourceStrWithResult(src, "LoopBound.runar.ts")
	assertLoopBoundRejected(t, res, "2^64+10")

	// Belt and braces: whatever happens, it must not silently agree with
	// the `i < 10n` contract.
	if res.Success && res.ScriptHex == "012d7c9c" {
		t.Fatal("bound 2^64+10 compiled to the same bytes as bound 10 — the modular wrap is still live")
	}
}

// TestLoopBound_10Pow20_IsRejectedWithoutHanging covers outcome 3:
// Int64() yields ~7.77e18, which the unroller tries to honour, wedging
// the compiler in unbounded-memory loop unrolling. Pre-fix this test
// did not fail — it never returned. The timeout below is what proves
// the fix: the diagnostic must arrive promptly.
func TestLoopBound_10Pow20_IsRejectedWithoutHanging(t *testing.T) {
	type outcome struct {
		res *CompileResult
	}
	done := make(chan outcome, 1)
	go func() {
		done <- outcome{CompileFromSourceStrWithResult(narrowingLoopSource("100000000000000000000"), "LoopBound.runar.ts")}
	}()
	select {
	case o := <-done:
		assertLoopBoundRejected(t, o.res, "10^20")
	case <-time.After(10 * time.Second):
		// Cannot t.Fatal from a wedged compile — the goroutine keeps
		// allocating — but the test binary is about to be torn down by
		// the package timeout anyway. Report the real defect.
		t.Fatal("bound 10^20 did not produce a diagnostic within 10s — the narrowed count is still driving loop unrolling")
	}
}

// TestLoopBound_ExceedingMaxLoopCount_IsRejectedOnSourcePath pins the
// second half of the fix. ir.MaxLoopCount (10000) existed in exactly one
// place and was enforced only on the `--ir` input path, so a source
// contract could ask for any in-int64 unroll count — 10^18 included,
// which IsInt64 alone does not stop. The bound now applies to source
// input too.
func TestLoopBound_ExceedingMaxLoopCount_IsRejectedOnSourcePath(t *testing.T) {
	res := CompileFromSourceStrWithResult(narrowingLoopSource("10001"), "LoopBound.runar.ts")
	if res.Success {
		t.Fatalf("expected a diagnostic for a 10001-iteration loop, got a successful compile (hex len %d)", len(res.ScriptHex))
	}
	if !diagnosticsMention(res, "10000") {
		t.Errorf("expected the diagnostic to name the maximum loop count, got %v", res.Diagnostics)
	}
}

// narrowingAsmSource builds an UnsafeSmartContract whose method carries a
// terminal asm({...}) with the given in_arity literal. in_arity drives the
// compiler's stack model, so a wrong value corrupts every subsequent stack
// slot computation — silently, since it never appears in the emitted bytes.
func narrowingAsmSource(inArity string) string {
	return fmt.Sprintf(`import { UnsafeSmartContract, asm } from 'runar-lang';

export class AsmArity extends UnsafeSmartContract {
  constructor() { super(); }

  public unlock(a: bigint, b: bigint): void {
    asm({ body: '93', in_arity: %s, out_arity: 1 });
  }
}
`, inArity)
}

// TestAsmInArity_ModularWrapIsRejected. asm() arities pass through TWO
// narrowings — `parseArityLiteral` (parser) and `int(bi.Value.Int64())`
// (ANF lowering) — and both truncated. Pre-fix, in_arity 2^64+2 compiled
// to hex "93", byte-identical to in_arity 2.
func TestAsmInArity_ModularWrapIsRejected(t *testing.T) {
	control := CompileFromSourceStrWithResult(narrowingAsmSource("2"), "AsmArity.runar.ts")
	if !control.Success {
		t.Fatalf("in_arity 2 must still compile, got %v", control.Diagnostics)
	}
	if control.ScriptHex != "93" {
		t.Errorf("in_arity 2 control script changed: want 93, got %s", control.ScriptHex)
	}

	res := CompileFromSourceStrWithResult(narrowingAsmSource("18446744073709551618"), "AsmArity.runar.ts")
	if res.Success {
		t.Fatalf("expected a diagnostic for in_arity 2^64+2, got a successful compile (hex %q)", res.ScriptHex)
	}
	if !diagnosticsMention(res, "in_arity") {
		t.Errorf("expected the diagnostic to name in_arity, got %v", res.Diagnostics)
	}
}

func assertLoopBoundRejected(t *testing.T, res *CompileResult, label string) {
	t.Helper()
	if res.Success {
		t.Fatalf("bound %s: expected a compile diagnostic, got a successful compile (hex %q)", label, res.ScriptHex)
	}
	if !diagnosticsMention(res, "loop") {
		t.Errorf("bound %s: expected a diagnostic mentioning the loop bound, got %v", label, res.Diagnostics)
	}
}

func diagnosticsMention(res *CompileResult, needle string) bool {
	for _, d := range res.Diagnostics {
		if strings.Contains(strings.ToLower(d.Message), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}
