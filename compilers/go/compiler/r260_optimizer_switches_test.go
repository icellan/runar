package compiler

import (
	"strings"
	"testing"
)

// R-260 (CL-GAP-006): Go's CompileOptions had a switch for constant folding and
// none for the other two optimizers, while the TS tier has all three
// (`disableConstantFolding`, `disableEcOptimizer`, `disablePeephole` —
// packages/runar-compiler/src/index.ts:147,158,166).
//
// The finding rates it ergonomics, and that is the right rating: nothing is
// wrong with the output. What it costs is the bisection. When the seven tiers
// disagree on a byte, the first question is WHICH pass introduced it, and in TS
// you answer it by turning passes off one at a time. In Go you could turn off
// exactly one of the three, so the same divergence took a rebuild with an edited
// compiler to localise.
//
// These tests hold the two new switches to the only contract that matters for a
// debugging aid: OFF must be today's bytes exactly, and ON must actually change
// something — a flag that silently does nothing is worse than no flag, because
// it makes the pass look innocent.

// An EC expression the rules engine rewrites: `ec-mul-one` turns ecMul(p, 1n)
// into p, which removes a 256-iteration double-and-add loop. If the optimizer
// is off, the loop is emitted.
const r260ECSource = `
import { SmartContract, assert, ecMul, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';

class R260EC extends SmartContract {
  readonly pt: Point;

  constructor(pt: Point) {
    super(pt);
    this.pt = pt;
  }

  public unlock(expected: bigint) {
    const doubled = ecMul(this.pt, 1n);
    assert(ecPointX(doubled) === expected);
  }
}
`

// Plain arithmetic: enough stack shuffling for the peephole pass to have
// something to collapse, and no EC at all, so the two switches are measured
// independently.
const r260PeepholeSource = `
import { SmartContract, assert } from 'runar-lang';

class R260Peep extends SmartContract {
  readonly a: bigint;
  readonly b: bigint;

  constructor(a: bigint, b: bigint) {
    super(a, b);
    this.a = a;
    this.b = b;
  }

  public unlock(x: bigint, y: bigint) {
    const s = x + y;
    const t = s - y;
    const u = t + this.a;
    assert(u - this.a === this.b + x - this.b);
  }
}
`

func r260Compile(t *testing.T, src string, opts CompileOptions) string {
	t.Helper()
	res := CompileFromSourceStrWithResult(src, "R260.runar.ts", opts)
	if !res.Success {
		msgs := make([]string, 0, len(res.Diagnostics))
		for _, d := range res.Diagnostics {
			msgs = append(msgs, d.Message)
		}
		t.Fatalf("compile failed: %s", strings.Join(msgs, "\n"))
	}
	if res.Artifact == nil || len(res.Artifact.Script) == 0 {
		t.Fatal("compile succeeded with no script")
	}
	return string(res.Artifact.Script)
}

// The switches default to OFF, so the default path must be byte-identical to
// what it was before they existed. Every golden in conformance/ depends on it.
func TestR260_DefaultsAreUnchanged(t *testing.T) {
	zero := r260Compile(t, r260ECSource, CompileOptions{})
	explicit := r260Compile(t, r260ECSource, CompileOptions{
		DisableEcOptimizer: false,
		DisablePeephole:    false,
	})
	if zero != explicit {
		t.Fatalf("an explicitly-false switch changed the bytes: %d vs %d",
			len(zero), len(explicit))
	}
}

func TestR260_DisableEcOptimizerActuallyDisablesIt(t *testing.T) {
	on := r260Compile(t, r260ECSource, CompileOptions{})
	off := r260Compile(t, r260ECSource, CompileOptions{DisableEcOptimizer: true})

	if on == off {
		t.Fatal("DisableEcOptimizer changed nothing — `ecMul(p, 1n)` is an " +
			"ec-mul-one rewrite, so turning the pass off must leave the " +
			"multiply in the script. A switch that does nothing is worse " +
			"than no switch.")
	}
	if len(off) <= len(on) {
		t.Errorf("with the EC optimizer off the script should be LONGER "+
			"(the multiply survives); got on=%d off=%d", len(on), len(off))
	}
}

func TestR260_DisablePeepholeActuallyDisablesIt(t *testing.T) {
	on := r260Compile(t, r260PeepholeSource, CompileOptions{})
	off := r260Compile(t, r260PeepholeSource, CompileOptions{DisablePeephole: true})

	if on == off {
		t.Fatal("DisablePeephole changed nothing")
	}
	if len(off) <= len(on) {
		t.Errorf("with peephole off the script should be LONGER; got on=%d off=%d",
			len(on), len(off))
	}
}

// The three switches must compose: this is the shape a bisection actually uses.
func TestR260_AllThreeSwitchesCompose(t *testing.T) {
	all := r260Compile(t, r260ECSource, CompileOptions{
		DisableConstantFolding: true,
		DisableEcOptimizer:     true,
		DisablePeephole:        true,
	})
	none := r260Compile(t, r260ECSource, CompileOptions{})
	if all == none {
		t.Fatal("turning every optimizer off produced the fully-optimized bytes")
	}
}
