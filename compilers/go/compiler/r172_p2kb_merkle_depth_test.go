package compiler

import (
	"fmt"
	"strings"
	"testing"
)

// R-172 (GK-BUG-010): merkleRootPoseidon2KB advertised depth 1-64 and then
// refused anything over 32, from a function the author never called.
//
// codegen/stack.go lowerMerkleRootPoseidon2KB range-checks the constant:
//
//	if depth < 1 || depth > 64 {
//	    panic("merkleRootPoseidon2KB: depth must be between 1 and 64, got %d")
//	}
//
// while codegen/poseidon2_merkle.go EmitPoseidon2MerkleRoot, called a few lines
// later, refuses on a different interval:
//
//	if depth < 1 || depth > 32 {
//	    panic("EmitPoseidon2MerkleRoot: depth must be in [1, 32], got %d")
//	}
//
// So depths 33..64 pass the gate that claims to bound them and die in the
// emitter. Measured before the fix, via the CLI on a generated contract:
//
//	depth 32  exit 0, 1359695 hex chars
//	depth 33  exit 1  "EmitPoseidon2MerkleRoot: depth must be in [1, 32], got 33"
//	depth 64  exit 1  "EmitPoseidon2MerkleRoot: depth must be in [1, 32], got 64"
//	depth 65  exit 1  "merkleRootPoseidon2KB: depth must be between 1 and 64, got 65"
//
// Two things are wrong and only one of them is cosmetic. The diagnostic names
// an internal emitter instead of the builtin in the source, which is the
// cosmetic half. The load-bearing half is that the gate's own message tells the
// author 64 is allowed while the compiler will never emit above 32 — the two
// checks disagree, and the one the author is shown is the wrong one.
//
// 32 is the real limit: EmitPoseidon2MerkleRoot's roll counts grow
// quadratically in depth, which is why it draws the line there. The unreachable
// half of the caller's interval is what gets deleted, not the emitter's bound.
//
// The sibling builtin merkleRootSha256 keeps 1..64: emitMerkleRoot
// (codegen/merkle.go) carries no upper bound of its own, so for that family
// the caller's interval is the only one and it is honest.

// True when the message states 64 as the permitted maximum, in either of the
// two spellings the codebase uses for a depth interval.
func r172OffersSixtyFourAsTheLimit(msg string) bool {
	return strings.Contains(msg, "and 64") || strings.Contains(msg, "1, 64")
}

func buildR172P2KBSource(depth int) string {
	var params, args []string
	for i := 0; i < 8; i++ {
		params = append(params, fmt.Sprintf("l%d: bigint", i))
		args = append(args, fmt.Sprintf("l%d", i))
	}
	for lvl := 0; lvl < depth; lvl++ {
		for i := 0; i < 8; i++ {
			params = append(params, fmt.Sprintf("s%d_%d: bigint", lvl, i))
			args = append(args, fmt.Sprintf("s%d_%d", lvl, i))
		}
	}
	params = append(params, "idx: bigint", "expected: bigint")
	args = append(args, "idx", fmt.Sprintf("%dn", depth))

	return fmt.Sprintf(`
import { SmartContract, assert, merkleRootPoseidon2KB } from 'runar-lang';

class P2KBDepth extends SmartContract {
  constructor() {
    super();
  }
  public verify(%s) {
    const root = merkleRootPoseidon2KB(%s);
    assert(root === expected);
  }
}
`, strings.Join(params, ", "), strings.Join(args, ", "))
}

// Every diagnostic joined, so an assertion about the message cannot pass by
// looking at only the first of several.
func r172Diagnostics(res *CompileResult) string {
	msgs := make([]string, 0, len(res.Diagnostics))
	for _, d := range res.Diagnostics {
		msgs = append(msgs, d.Message)
	}
	return strings.Join(msgs, "\n")
}

func r172Compile(t *testing.T, depth int) (string, error) {
	t.Helper()
	res := CompileFromSourceStrWithResult(buildR172P2KBSource(depth), "P2KBDepth.runar.ts")
	if !res.Success {
		return "", fmt.Errorf("%s", r172Diagnostics(res))
	}
	if res.Artifact == nil || len(res.Artifact.Script) == 0 {
		t.Fatalf("depth %d: compile reported success with no script", depth)
	}
	return string(res.Artifact.Script), nil
}

// The control. 32 is the documented maximum and must keep compiling — a fix
// that narrows the bound by breaking the largest legal depth is not a fix.
func TestR172_DepthThirtyTwoStillCompiles(t *testing.T) {
	script, err := r172Compile(t, 32)
	if err != nil {
		t.Fatalf("depth 32 must compile: %v", err)
	}
	if len(script) == 0 {
		t.Fatal("depth 32 produced an empty script")
	}
}

func TestR172_DepthOneStillCompiles(t *testing.T) {
	if _, err := r172Compile(t, 1); err != nil {
		t.Fatalf("depth 1 must compile: %v", err)
	}
}

// The finding. Every depth in the dead interval must be refused by the builtin
// the author wrote, naming the limit that actually holds.
func TestR172_DepthsAboveThirtyTwoAreRefusedByTheBuiltin(t *testing.T) {
	for _, depth := range []int{33, 40, 64} {
		_, err := r172Compile(t, depth)
		if err == nil {
			t.Fatalf("depth %d compiled; the emitter refuses above 32", depth)
		}
		msg := err.Error()

		if !strings.Contains(msg, "merkleRootPoseidon2KB") {
			t.Errorf("depth %d: the diagnostic must name the builtin the author called; got: %s",
				depth, msg)
		}
		if strings.Contains(msg, "EmitPoseidon2MerkleRoot") {
			t.Errorf("depth %d: the diagnostic names an internal emitter, not the source construct; got: %s",
				depth, msg)
		}
		if !strings.Contains(msg, "32") {
			t.Errorf("depth %d: the diagnostic must state the real limit (32); got: %s", depth, msg)
		}
		// "64" alone would also match the depth being reported, so the check
		// is against the way a LIMIT is spelled, not against the digits.
		if r172OffersSixtyFourAsTheLimit(msg) {
			t.Errorf("depth %d: the diagnostic still offers 64 as the limit, which the compiler will never emit; got: %s",
				depth, msg)
		}
	}
}

// Beyond the interval entirely — this already worked, and must keep working
// with the same corrected limit rather than reverting to the old message.
func TestR172_DepthBeyondSixtyFourStaysRefused(t *testing.T) {
	_, err := r172Compile(t, 65)
	if err == nil {
		t.Fatal("depth 65 compiled")
	}
	if !strings.Contains(err.Error(), "merkleRootPoseidon2KB") {
		t.Errorf("depth 65 diagnostic must name the builtin; got: %s", err)
	}
	if r172OffersSixtyFourAsTheLimit(err.Error()) {
		t.Errorf("depth 65 must be measured against 32, not 64; got: %s", err)
	}
}

// The sibling family is NOT narrowed: merkleRootSha256's emitter has no upper
// bound, so its caller-side 1..64 is the only limit and stays.
func TestR172_Sha256MerkleKeepsItsSixtyFourLimit(t *testing.T) {
	src := `
import { SmartContract, assert, merkleRootSha256 } from 'runar-lang';

class Sha256Merkle extends SmartContract {
  constructor() {
    super();
  }
  public verify(leaf: ByteString, proof: ByteString, idx: bigint, expected: ByteString) {
    assert(merkleRootSha256(leaf, proof, idx, 40n) === expected);
  }
}
`
	if res := CompileFromSourceStrWithResult(src, "Sha256Merkle.runar.ts"); !res.Success {
		t.Fatalf("merkleRootSha256 at depth 40 must still compile: %s", r172Diagnostics(res))
	}
}
