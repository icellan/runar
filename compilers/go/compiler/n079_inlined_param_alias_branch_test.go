package compiler

// NOTE ON THE FILE NAME: the peer tiers call this probe set
// "..._branch_arm"; this file deliberately stops at "_branch". Go's build
// system reads the last underscore-separated word of a file name as an
// implicit GOOS/GOARCH constraint, and `arm` IS a GOARCH — so
// `n079_..._branch_arm_test.go` is silently EXCLUDED from every build on a
// non-arm host (arm64 included). It compiles, `go vet` is clean, and
// `go test` reports ok with the tests never having run. Do not rename it back.
//
// Port of the TypeScript reference test
// packages/runar-compiler/src/__tests__/n079-inlined-param-alias-branch-arm.test.ts.
//
// N-079 — the inlined argument alias must survive into a branch arm.
//
// spec/semantics.md §6.3 defines a private method as source-level substitution
// at every call site. So this:
//
//	private pay(v: bigint): void { ...uses v... }
//	public  go(v: bigint) { this.pay(v * 2n); }
//
// and the hand-substituted program (`const a = v * 2n;` then the body with `a`
// in place of `v`) are the SAME program and must compile to the same script.
// That is an oracle needing no reference tier.
//
// The defect, in the five tiers that had it: inlinePrivateMethodCall pushes the
// caller's argument refs onto the CURRENT lowering context (pushParamAlias) and
// then lowers the private method's body into it. When that body contains an
// `if` / `for` / ternary, the arm is built by subContext() — a FRESH context.
// TS, Python, Zig, Ruby and Java did not copy the alias stack into it, so a
// read of the private's parameter inside the arm found no alias and fell
// through to load_param, resolving to the CALLER's same-named parameter instead
// of the argument that was passed in. The covenant's output amount became
// `v + 100` where the source says `(v * 2) + 100`.
//
// GO IS THE REFERENCE HERE and needs no change: subContext already deep-copies
// paramAliasStack, with a comment naming this exact hazard. This test pins Go
// to the seven-tier table so that a future edit to that copy is caught here
// rather than by a cross-tier divergence.
//
// Measured on the pre-fix HEAD, --disable-constant-folding:
//
//	               go   rust  python  zig  ruby  java  ts
//	hand-inlined   705   705    705   705   705   705  705
//	via helper     705   705    703   703   703   703  703
//
// The (byte length, sha256-of-hex) pairs below are the SEVEN-TIER agreed
// output; every tier pins the same table. The scripts are ~700 B (a stateful
// covenant — the ANF-level inliner only fires for a helper that emits outputs),
// so they are pinned by digest rather than inline.

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const n079Prelude = `import { StatefulSmartContract, assert } from "runar-lang";

class C extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

`

// The item's probe: a helper containing an `if`, called with `v * 2n`.
const n079IfArm = n079Prelude + `  private pay(v: bigint): void {
    let extra: bigint = 0n;
    if (v > 5n) {
      extra = v + 100n;
    } else {
      extra = v + 1n;
    }
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
`

// §6.3 control: the same program with the helper substituted by hand.
const n079IfArmManual = n079Prelude + `  public go(v: bigint) {
    this.count = this.count + 1n;
    const a: bigint = v * 2n;
    let extra: bigint = 0n;
    if (a > 5n) {
      extra = a + 100n;
    } else {
      extra = a + 1n;
    }
    this.addOutput(extra, this.count);
    assert(v >= 0n);
  }
}
`

// N-051 oracle: differs from n079IfArm ONLY inside the then-arm (+200 not +100).
const n079IfArm200 = n079Prelude + `  private pay(v: bigint): void {
    let extra: bigint = 0n;
    if (v > 5n) {
      extra = v + 200n;
    } else {
      extra = v + 1n;
    }
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
`

// Same hazard through a ternary arm.
const n079TernaryArm = n079Prelude + `  private pay(v: bigint): void {
    const extra: bigint = v > 5n ? v + 100n : v + 1n;
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
`

const n079TernaryArmManual = n079Prelude + `  public go(v: bigint) {
    this.count = this.count + 1n;
    const a: bigint = v * 2n;
    const extra: bigint = a > 5n ? a + 100n : a + 1n;
    this.addOutput(extra, this.count);
    assert(v >= 0n);
  }
}
`

// Same hazard through a `for` body — subContext() builds that too.
const n079LoopBody = n079Prelude + `  private pay(v: bigint): void {
    let acc: bigint = 0n;
    for (let i = 0; i < 3; i++) {
      acc = acc + v;
    }
    this.addOutput(acc, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
`

const n079LoopBodyManual = n079Prelude + `  public go(v: bigint) {
    this.count = this.count + 1n;
    const a: bigint = v * 2n;
    let acc: bigint = 0n;
    for (let i = 0; i < 3; i++) {
      acc = acc + a;
    }
    this.addOutput(acc, this.count);
    assert(v >= 0n);
  }
}
`

// Control: a helper with NO nested block at all. Must be byte-unchanged.
const n079NoIf = n079Prelude + `  private pay(v: bigint): void {
    const extra: bigint = v + 100n;
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
`

// Control: the parameter is read at STATEMENT level inside the helper, and the
// `if` in the helper does not read it. Must be byte-unchanged.
const n079StmtLevel = n079Prelude + `  private pay(v: bigint): void {
    const extra: bigint = v + 100n;
    let bump: bigint = 0n;
    if (this.count > 5n) {
      bump = 1n;
    } else {
      bump = 2n;
    }
    this.addOutput(extra + bump, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
`

// Control: the argument IS the caller's own parameter (`this.pay(v)`), so
// caller-param and argument coincide and the WRONG lowering computed the right
// VALUE. It was still a different script — 701 B in the five broken tiers where
// Go/Rust emitted 703 — because the arm re-issued load_param instead of reading
// the alias slot.
const n079Passthrough = n079Prelude + `  private pay(v: bigint): void {
    let extra: bigint = 0n;
    if (v > 5n) {
      extra = v + 100n;
    } else {
      extra = v + 1n;
    }
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v);
    assert(v >= 0n);
  }
}
`

func n079Digest(scriptHex string) string {
	sum := sha256.Sum256([]byte(scriptHex))
	return hex.EncodeToString(sum[:])
}

func n079CompileScriptHex(t *testing.T, source string, disableConstantFolding bool) string {
	t.Helper()
	return strings.ToLower(compileScriptHex(t, source, disableConstantFolding))
}

func TestN079InlinedParamAlias_SevenTierScript(t *testing.T) {
	cases := []struct {
		label   string
		source  string
		wantLen int
		wantSha string
	}{
		{"if-arm", n079IfArm, 705, "5b4b45b5cf4156695b412b132d4c302aab58770ec0bffe4b307d1bfce4f2d8a8"},
		{"if-arm-manual", n079IfArmManual, 705, "5b4b45b5cf4156695b412b132d4c302aab58770ec0bffe4b307d1bfce4f2d8a8"},
		{"if-arm-200", n079IfArm200, 706, "b9aaa48a3400eb488fba40c6e7898c4928aafdce60b0a85899572b80093477aa"},
		{"ternary-arm", n079TernaryArm, 691, "f6b2ae0526262ccee7adc71d1291bb8e0ae193de42c1a4e3936b782da95e3caf"},
		{"ternary-arm-manual", n079TernaryArmManual, 691, "f6b2ae0526262ccee7adc71d1291bb8e0ae193de42c1a4e3936b782da95e3caf"},
		{"loop-body", n079LoopBody, 698, "3692231cef9275b5a87f1f9f9b268f5a39cc3c4f37fe6354a1b57b2e8d356d55"},
		{"loop-body-manual", n079LoopBodyManual, 698, "3692231cef9275b5a87f1f9f9b268f5a39cc3c4f37fe6354a1b57b2e8d356d55"},
		{"no-if", n079NoIf, 683, "2807bc651b0cfac58c0a0835f42b39cf46ce28d1e64d1ba7421279ccfe6680ed"},
		{"stmt-level", n079StmtLevel, 701, "9f61cc84ac3a68d928a73a5f0bb9dc129b9bf7d0d3ca873c4f4bd0cbad214d62"},
		{"passthrough", n079Passthrough, 703, "5c30a0ad7a1e728ce44f723cefe1823ff9855b28a1d52ececf28c7715924adb0"},
	}

	for _, tc := range cases {
		for _, disable := range []bool{true, false} {
			mode := "fold-on"
			if disable {
				mode = "fold-off"
			}
			t.Run(tc.label+"/"+mode, func(t *testing.T) {
				got := n079CompileScriptHex(t, tc.source, disable)
				if len(got)/2 != tc.wantLen {
					t.Fatalf("script length diverged from the seven-tier agreed output: got %d B, want %d B",
						len(got)/2, tc.wantLen)
				}
				if sum := n079Digest(got); sum != tc.wantSha {
					t.Fatalf("script bytes diverged from the seven-tier agreed output\n got sha256: %s\nwant sha256: %s",
						sum, tc.wantSha)
				}
			})
		}
	}
}

// spec/semantics.md §6.3: inlining IS substitution, so the helper form and the
// hand-substituted program are the same program.
func TestN079HelperMatchesManualInline(t *testing.T) {
	cases := []struct {
		kind   string
		helper string
		manual string
	}{
		{"if", n079IfArm, n079IfArmManual},
		{"ternary", n079TernaryArm, n079TernaryArmManual},
		{"for", n079LoopBody, n079LoopBodyManual},
	}
	for _, tc := range cases {
		for _, disable := range []bool{true, false} {
			helper := n079CompileScriptHex(t, tc.helper, disable)
			manual := n079CompileScriptHex(t, tc.manual, disable)
			if helper != manual {
				t.Fatalf("helper with a nested %s diverged from the hand-inlined source (disableConstantFolding=%v)",
					tc.kind, disable)
			}
		}
	}
}

// The N-051 oracle, consulting no reference tier: two helper bodies that differ
// ONLY inside the arm must not compile to the same script.
func TestN079ArmReadsTheArgument(t *testing.T) {
	for _, disable := range []bool{true, false} {
		plus100 := n079CompileScriptHex(t, n079IfArm, disable)
		plus200 := n079CompileScriptHex(t, n079IfArm200, disable)
		if plus100 == plus200 {
			t.Fatalf("two helper bodies differing only inside the arm compiled to the same script (disableConstantFolding=%v)",
				disable)
		}
	}
}
