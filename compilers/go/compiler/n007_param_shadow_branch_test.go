package compiler

// Port of packages/runar-compiler/src/__tests__/n007-param-shadow-branch-arm.test.ts.
//
// N-007 — a method parameter that shadows a MUTABLE property must stay the
// parameter inside an `if` / ternary arm.
//
// Issue #130 (stack layer): deserialize_state pushes each mutable property
// under its own name, so newLoweringContext renames a same-named method
// parameter's slot to `__param_<name>` and records it in renamedParams;
// lowerLoadParam resolves through that map.
//
// The defect: codegen/stack.go's lowerIf built thenCtx / elseCtx with
// newLoweringContext, whose renamedParams starts EMPTY. The arm's cloned stack
// still carries the `__param_<name>` slot, so a load_param inside the arm
// resolved the bare name to the deserialized PROPERTY slot — the stale
// on-chain state — instead of the caller's witness argument:
//
//	public set(count: bigint, flag: boolean) {
//	  if (flag) { assert(count == 5n); }     // arm read this.count (stale)
//	  this.count = count;
//	}
//
// With on-chain count = 5, set(7n, true) passed a guard the source says must
// fail. Real-engine proof:
// packages/runar-testing/src/__tests__/n007-param-shadow-branch-arm-vm.test.ts.
//
// Oracle (needs no reference tier): a parameter's NAME is not part of the
// program, so alpha-renaming count -> newCount must give byte-identical script.
//
// Proves: Go resolves a shadowing parameter to the same slot inside an if-then
// arm, an if-else arm and a ternary arm as for a non-colliding name, in both
// fold modes. Does NOT prove: that the renamed program is itself correct
// on-chain (the VM test), or anything about other tiers.

import (
	"regexp"
	"strings"
	"testing"
)

const n007Prelude = `import { StatefulSmartContract, assert } from 'runar-lang';

class Probe extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

`

const n007ThenArm = `  public set(count: bigint, flag: boolean) {
    if (flag) {
      assert(count == 5n);
    }
    this.count = count;
  }
}
`

const n007ElseArm = `  public set(count: bigint, flag: boolean) {
    if (flag) {
      assert(flag);
    } else {
      assert(count > 10n);
    }
    this.count = count;
  }
}
`

const n007TernaryArm = `  public set(count: bigint, flag: boolean) {
    const v: bigint = flag ? count + 1n : 0n;
    assert(v != 3n);
    this.count = count;
  }
}
`

// Control: the parameter is read only OUTSIDE any arm (already correct before
// the fix; pins that the oracle is not vacuous).
const n007NoArm = `  public set(count: bigint, flag: boolean) {
    assert(count != 3n);
    assert(flag);
    this.count = count;
  }
}
`

func n007AlphaRename(body string) string {
	body = strings.Replace(body, "set(count: bigint", "set(newCount: bigint", 1)
	body = strings.Replace(body, "this.count = count;", "this.count = newCount;", 1)
	body = strings.Replace(body, "(count ", "(newCount ", 1)
	body = strings.Replace(body, "? count ", "? newCount ", 1)
	return body
}

func n007Hex(t *testing.T, body string, disableFold bool) string {
	t.Helper()
	result := CompileFromSourceStrWithResult(n007Prelude+body, "Probe.runar.ts", CompileOptions{
		DisableConstantFolding: disableFold,
	})
	if !result.Success {
		var msgs []string
		for _, d := range result.Diagnostics {
			msgs = append(msgs, d.Message)
		}
		t.Fatalf("compilation failed: %v", msgs)
	}
	return result.ScriptHex
}

func TestN007ParamShadowBranchArm_AlphaEquivalent(t *testing.T) {
	bareCount := regexp.MustCompile(`(^|[^.\w])count\b`)
	cases := []struct{ label, body string }{
		{"then-arm", n007ThenArm},
		{"else-arm", n007ElseArm},
		{"ternary-arm", n007TernaryArm},
		{"control/no-arm", n007NoArm},
	}
	for _, tc := range cases {
		for _, disable := range []bool{true, false} {
			mode := "fold-on"
			if disable {
				mode = "fold-off"
			}
			t.Run(tc.label+"/"+mode, func(t *testing.T) {
				renamed := n007AlphaRename(tc.body)
				if bareCount.MatchString(renamed) {
					t.Fatalf("alpha-rename left a read of the shadowing name:\n%s", renamed)
				}
				got := n007Hex(t, tc.body, disable)
				want := n007Hex(t, renamed, disable)
				if got != want {
					t.Fatalf("%s: a parameter that shadows mutable property 'count' compiled differently from the renamed program — the arm read the deserialized state slot, not the witness argument\n got: %s\nwant: %s", tc.label, got, want)
				}
			})
		}
	}
}
