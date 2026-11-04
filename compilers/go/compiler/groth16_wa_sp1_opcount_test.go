package compiler

import (
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// ---------------------------------------------------------------------------
// The real SP1 v6.0.0 proof through the CompileGroth16WA (MSM-binding)
// verifier, with and without vk.json pinnedPublicInputs (Ports #173).
//
// groth16_wa_pinned_test.go exercises pinning against a synthetic
// known-discrete-log key, which is what makes its forgeries real. This file
// covers the other half: the production SP1 key and proof, executed on the
// go-sdk interpreter, plus the counted-op budget that motivated #173.
//
// Counted ops: the go-sdk interpreter (like SV Node) increments its
// maxops counter for EVERY opcode above OP_16 it reads, executed branch or
// not, and resets it per script. The verifier is straight-line (no loops), so
// an accepted spend's counted total for the locking script is exactly the
// number of non-push opcodes in it; lockedCountedOps computes that statically
// instead of paying for a per-step debugger over ~1M steps.
// ---------------------------------------------------------------------------

// maxOpsPerScriptPolicy is SV Node's maxopsperscriptpolicy as Teranode /
// Arcade (GoBDK) run it. A spend over it is non-standard and is not relayed.
const maxOpsPerScriptPolicy = 1_000_000

func lockedCountedOps(t *testing.T, art *Artifact) int {
	t.Helper()
	owner := groth16TestKey(0x11)
	chunks, err := script.DecodeScriptHex(groth16DeployedLockHex(t, art, owner.PubKey().Compressed()))
	if err != nil {
		t.Fatalf("decode locking script: %v", err)
	}
	n := 0
	for _, c := range chunks {
		if c.Op > script.Op16 {
			n++
		}
	}
	return n
}

func sp1RawProof(t *testing.T) bn254witness.Proof {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "..", "tests", "vectors", "sp1", "v6.0.0", "groth16_raw_proof.hex"))
	if err != nil {
		t.Fatalf("resolve SP1 raw proof path: %v", err)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read SP1 raw proof: %v", err)
	}
	proof, err := bn254witness.ParseSP1RawProof(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("ParseSP1RawProof: %v", err)
	}
	return proof
}

// sp1Witness builds the MSM-layout witness for the SP1 v6.0.0 proof with the
// given witness public-input scalars.
func sp1Witness(t *testing.T, pubs []*big.Int) *bn254witness.Witness {
	t.Helper()
	vk, err := bn254witness.LoadSP1VKFromFile(sp1VKPath(t))
	if err != nil {
		t.Fatalf("LoadSP1VKFromFile: %v", err)
	}
	w, err := bn254witness.BuildFromProofWithInputs(vk, sp1RawProof(t), pubs)
	if err != nil {
		t.Fatalf("BuildFromProofWithInputs: %v", err)
	}
	return w
}

// TestSP1v6_MSMVerifier_PinnedSP1Constants: the genuine SP1 v6.0.0 proof is
// ACCEPTED by both the unpinned verifier and the one whose vk.json pins the
// three SP1 constants (vkey hash, exit code, vk root = slots 0, 2, 3); the
// pinned verifier is under maxopsperscriptpolicy and strictly cheaper; and a
// witness whose pinned slot (0) lies — prepared_inputs still the genuine one —
// is REJECTED.
func TestSP1v6_MSMVerifier_PinnedSP1Constants(t *testing.T) {
	pubs := sp1PublicInputs(t)

	unpinned, err := CompileGroth16WA(sp1VKPath(t), Groth16WAOpts{PublicInputs: pubs})
	if err != nil {
		t.Fatalf("CompileGroth16WA (unpinned): %v", err)
	}
	if err := executeArtifactWithWitness(t, unpinned, sp1Witness(t, pubs)); err != nil {
		t.Fatalf("genuine SP1 v6 proof REJECTED by the unpinned MSM verifier: %v", err)
	}
	unpinnedOps := lockedCountedOps(t, unpinned)

	path := writePinnedVK(t, sp1VKPath(t), pinsFrom(pubs, 0, 2, 3))
	pinned, err := CompileGroth16WA(path, Groth16WAOpts{PublicInputs: pubs})
	if err != nil {
		t.Fatalf("CompileGroth16WA (pinned 0,2,3): %v", err)
	}
	if err := executeArtifactWithWitness(t, pinned, sp1Witness(t, pubs)); err != nil {
		t.Fatalf("genuine SP1 v6 proof REJECTED by the pinned MSM verifier: %v", err)
	}
	pinnedOps := lockedCountedOps(t, pinned)

	t.Logf("SP1 v6 MSM verifier: unpinned %d counted ops / %d bytes; pinned(0,2,3) %d counted ops / %d bytes",
		unpinnedOps, len(unpinned.Script)/2, pinnedOps, len(pinned.Script)/2)
	if pinnedOps >= unpinnedOps {
		t.Fatalf("pinning slots 0,2,3 did not reduce counted ops (%d >= %d)", pinnedOps, unpinnedOps)
	}
	if pinnedOps > maxOpsPerScriptPolicy {
		t.Fatalf("pinned SP1 v6 verifier needs %d counted ops, over the %d maxopsperscriptpolicy", pinnedOps, maxOpsPerScriptPolicy)
	}

	// The lying witness: slot 0 bumped by one in the scalars only. The
	// unpinned verifier is the control that the same witness shape still
	// parses and reaches verification (it rejects too, via its MSM / --pub
	// checks); the pinned verifier must reject on its own pin.
	lie := sp1Witness(t, pubs)
	lie.PublicInputs[0] = new(big.Int).Add(pubs[0], big.NewInt(1))
	if err := executeArtifactWithWitness(t, pinned, lie); err == nil {
		t.Fatal("FORGERY ACCEPTED: a witness whose pinned slot 0 differs from the vk.json pin verified")
	}
}

// TestSP1v6_MSMVerifier_UnpinnedUnderOpsPolicy: the static-depth modulus fetch
// alone (no pins) must bring the unpinned SP1 v6 MSM verifier under SV Node's
// maxopsperscriptpolicy. On main before #173, every field op fetched the
// modulus with OP_DEPTH OP_1SUB OP_PICK (three counted ops) and the verifier
// was over the limit.
func TestSP1v6_MSMVerifier_UnpinnedUnderOpsPolicy(t *testing.T) {
	pubs := sp1PublicInputs(t)
	art, err := CompileGroth16WA(sp1VKPath(t), Groth16WAOpts{PublicInputs: pubs})
	if err != nil {
		t.Fatalf("CompileGroth16WA: %v", err)
	}
	ops := lockedCountedOps(t, art)
	t.Logf("unpinned SP1 v6 MSM verifier: %d counted ops", ops)
	if ops > maxOpsPerScriptPolicy {
		t.Fatalf("unpinned SP1 v6 MSM verifier needs %d counted ops, over the %d maxopsperscriptpolicy", ops, maxOpsPerScriptPolicy)
	}
}
