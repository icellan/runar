package compiler

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/icellan/runar/compilers/go/codegen"
)

// ---------------------------------------------------------------------------
// Pinned public inputs (Groth16Config.PinnedPublicInputs).
//
// A vk.json may carry
//
//	"pinnedPublicInputs": {"0": "<decimal>", "2": "0", "3": "<decimal>"}
//
// Each pinned slot's MSM term pinned_i · IC[i+1] is folded into the
// accumulator's starting point at compile time and the on-chain work for that
// slot drops from an unrolled scalar multiplication to one OP_EQUALVERIFY
// against the pinned scalar. Unpinned slots are multiplied on-chain exactly as
// before.
//
// The tests use the synthetic verifying key from groth16_wa_binding_test.go,
// whose discrete logs are known, so a mathematically VALID proof can be
// minted for any public-input vector. That is what makes the negative cases
// real attacks rather than malformed witnesses.
// ---------------------------------------------------------------------------

// writePinnedVK copies vk.json to a temp file with a pinnedPublicInputs map
// added (keys are slot indices; values decimal scalars).
func writePinnedVK(t *testing.T, srcPath string, pins map[int]*big.Int) string {
	t.Helper()
	return writePinnedVKRaw(t, srcPath, func(m map[string]string) {
		for i, v := range pins {
			m[strconv.Itoa(i)] = v.String()
		}
	})
}

func writePinnedVKRaw(t *testing.T, srcPath string, fill func(map[string]string)) string {
	t.Helper()
	raw, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read %s: %v", srcPath, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", srcPath, err)
	}
	pinned := map[string]string{}
	fill(pinned)
	doc["pinnedPublicInputs"] = pinned
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal pinned vk.json: %v", err)
	}
	path := filepath.Join(t.TempDir(), "pinned.vk.json")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write pinned vk.json: %v", err)
	}
	return path
}

func pinsFrom(pubs []*big.Int, slots ...int) map[int]*big.Int {
	m := map[int]*big.Int{}
	for _, s := range slots {
		m[s] = new(big.Int).Set(pubs[s])
	}
	return m
}

// TestPinnedPublicInputs_ConfigParsing: the loader fills exactly the slots
// named in vk.json, leaves the rest nil, and refuses malformed entries.
func TestPinnedPublicInputs_ConfigParsing(t *testing.T) {
	s := newSynthGroth16(t)

	t.Run("absent field leaves every slot nil", func(t *testing.T) {
		cfg, err := LoadGroth16WAConfigForTests(s.vkPath)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		for i, p := range cfg.PinnedPublicInputs {
			if p != nil {
				t.Fatalf("slot %d pinned to %s without a pinnedPublicInputs field", i, p)
			}
		}
	})

	t.Run("named slots are filled, including zero", func(t *testing.T) {
		path := writePinnedVK(t, s.vkPath, map[int]*big.Int{0: big.NewInt(5), 2: big.NewInt(0), 3: big.NewInt(9)})
		cfg, err := LoadGroth16WAConfigForTests(path)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		want := map[int]int64{0: 5, 2: 0, 3: 9}
		for i := 0; i < 5; i++ {
			got := cfg.PinnedPublicInputs[i]
			if w, ok := want[i]; ok {
				if got == nil || got.Int64() != w {
					t.Fatalf("slot %d: got %v, want %d", i, got, w)
				}
			} else if got != nil {
				t.Fatalf("slot %d: got %v, want nil (unpinned)", i, got)
			}
		}
	})

	bad := []struct {
		name string
		fill func(map[string]string)
		want string
	}{
		{"slot index out of range", func(m map[string]string) { m["5"] = "1" }, "slot index"},
		{"slot key not an integer", func(m map[string]string) { m["x"] = "1" }, "slot index"},
		{"scalar not decimal", func(m map[string]string) { m["0"] = "abc" }, "scalar"},
		{"scalar negative", func(m map[string]string) { m["0"] = "-1" }, "scalar"},
		{"scalar equal to r", func(m map[string]string) { m["0"] = fr.Modulus().String() }, "scalar"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			path := writePinnedVKRaw(t, s.vkPath, tc.fill)
			_, err := LoadGroth16WAConfigForTests(path)
			if err == nil {
				t.Fatalf("expected an error for %s; loader accepted it", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error should mention %q; got: %v", tc.want, err)
			}
		})
	}
}

// TestPinnedPublicInputs_HonestProofAcceptedAndScriptShrinks: folding is
// correct (a valid proof of the pinned statement still verifies, for pinned
// sets that include zero-valued and nonzero slots, and for all five) and
// actually removes code (the script is smaller than the unpinned build).
func TestPinnedPublicInputs_HonestProofAcceptedAndScriptShrinks(t *testing.T) {
	s := newSynthGroth16(t)
	honest := honestPublicInputs(t)
	proof := s.proofFor(honest)
	s.sanityCheck(t, proof, honest)

	unpinned, err := CompileGroth16WA(s.vkPath, Groth16WAOpts{PublicInputs: honest})
	if err != nil {
		t.Fatalf("CompileGroth16WA (unpinned): %v", err)
	}
	layout := detectLayout(t, unpinned, s.vk, proof, honest)
	if layout != layoutMSM {
		t.Fatalf("pinning only applies to the MSM-binding layout, but the artifact wants %s", layout)
	}

	cases := []struct {
		name  string
		slots []int
	}{
		{"sp1 constants (0, 2, 3)", []int{0, 2, 3}},
		{"single nonzero slot", []int{1}},
		{"single zero slot", []int{4}},
		{"all five", []int{0, 1, 2, 3, 4}},
	}
	prevLen := len(unpinned.Script)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writePinnedVK(t, s.vkPath, pinsFrom(honest, tc.slots...))
			art, err := CompileGroth16WA(path, Groth16WAOpts{PublicInputs: honest})
			if err != nil {
				t.Fatalf("CompileGroth16WA (pinned %v): %v", tc.slots, err)
			}
			w := buildWitness(t, layoutMSM, s.vk, proof, honest)
			if err := executeArtifactWithWitness(t, art, w); err != nil {
				t.Fatalf("honest proof of the pinned statement was REJECTED with slots %v pinned: %v", tc.slots, err)
			}
			if len(art.Script) >= prevLen {
				t.Fatalf("pinning slots %v did not shrink the script (%d >= %d hex chars)", tc.slots, len(art.Script), prevLen)
			}
			t.Logf("pinned %v: %d hex chars (unpinned %d)", tc.slots, len(art.Script), prevLen)
		})
	}
}

// TestPinnedPublicInputs_RejectsProofOfADifferentPinnedValue is the
// negative case. The attacker holds a VALID proof for a statement whose
// pinned slot differs from the compiled-in value, and tries three spends:
//
//  1. honest witness for their own statement: the pinned-slot equality check
//     must reject it;
//  2. the same proof and prepared_inputs but with the witness scalars
//     swapped to the pinned values, so every per-scalar check passes: the
//     folded accumulator must then disagree with their prepared_inputs;
//  3. a statement that differs only in an UNPINNED slot, scalars swapped
//     back: the on-chain scalar multiplication for that slot must still bind.
//
// Each spend is first shown to be a valid proof off-chain, so a rejection is
// the verifier's doing, not a broken witness.
func TestPinnedPublicInputs_RejectsProofOfADifferentPinnedValue(t *testing.T) {
	s := newSynthGroth16(t)
	honest := honestPublicInputs(t)
	honestProof := s.proofFor(honest)
	s.sanityCheck(t, honestProof, honest)

	pinnedSlots := []int{0, 2, 3}
	path := writePinnedVK(t, s.vkPath, pinsFrom(honest, pinnedSlots...))
	art, err := CompileGroth16WA(path, Groth16WAOpts{PublicInputs: honest})
	if err != nil {
		t.Fatalf("CompileGroth16WA: %v", err)
	}

	// Control: the honest spend passes.
	if err := executeArtifactWithWitness(t, art, buildWitness(t, layoutMSM, s.vk, honestProof, honest)); err != nil {
		t.Fatalf("control: honest spend rejected: %v", err)
	}

	bump := func(slot int) []*big.Int {
		pubs := make([]*big.Int, len(honest))
		for i := range honest {
			pubs[i] = new(big.Int).Set(honest[i])
		}
		pubs[slot] = new(big.Int).Add(pubs[slot], big.NewInt(1))
		return pubs
	}

	t.Run("attacker statement differs in a pinned slot, honest witness for it", func(t *testing.T) {
		attacker := bump(0)
		proof := s.proofFor(attacker)
		s.sanityCheck(t, proof, attacker)
		w := buildWitness(t, layoutMSM, s.vk, proof, attacker)
		if err := executeArtifactWithWitness(t, art, w); err == nil {
			t.Fatal("FORGERY ACCEPTED: a valid proof for a different value of a pinned public input verified")
		}
	})

	t.Run("attacker statement differs in a pinned slot, witness scalars lie", func(t *testing.T) {
		attacker := bump(0)
		proof := s.proofFor(attacker)
		s.sanityCheck(t, proof, attacker)
		w := buildWitness(t, layoutMSM, s.vk, proof, attacker)
		// prepared_inputs still encodes the attacker's vector; the declared
		// scalars are the pinned ones so every equality check passes.
		for i := range w.PublicInputs {
			w.PublicInputs[i] = new(big.Int).Set(honest[i])
		}
		if err := executeArtifactWithWitness(t, art, w); err == nil {
			t.Fatal("FORGERY ACCEPTED: the folded accumulator did not bind prepared_inputs to the pinned value")
		}
	})

	t.Run("attacker statement differs in an unpinned slot, witness scalars lie", func(t *testing.T) {
		attacker := bump(1)
		proof := s.proofFor(attacker)
		s.sanityCheck(t, proof, attacker)
		w := buildWitness(t, layoutMSM, s.vk, proof, attacker)
		for i := range w.PublicInputs {
			w.PublicInputs[i] = new(big.Int).Set(honest[i])
		}
		if err := executeArtifactWithWitness(t, art, w); err == nil {
			t.Fatal("FORGERY ACCEPTED: an unpinned slot stopped binding once other slots were pinned")
		}
	})
}

// TestPinnedPublicInputs_StatefulContractPath: the Rúnar-source path
// (CompileFromSource with Groth16WAVKey) reads the same vk.json, so a
// contract that asserts on Groth16PublicInput(0) still compiles with that
// slot pinned, and the pinned build is smaller.
func TestPinnedPublicInputs_StatefulContractPath(t *testing.T) {
	vkPath := sp1VKPath(t)
	pubs := sp1PublicInputs(t)
	pinnedPath := writePinnedVK(t, vkPath, pinsFrom(pubs, 0, 2, 3))

	source := `
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type PinnedCheck struct {
	runar.StatefulSmartContract

	Pinned  runar.Bigint ` + "`" + `runar:"readonly"` + "`" + `
	Counter runar.Bigint
}

func (c *PinnedCheck) Advance(nextCounter runar.Bigint) {
	runar.AssertGroth16WitnessAssistedWithMSM()
	runar.Assert(runar.Groth16PublicInput(0) == c.Pinned)
	c.Counter = nextCounter
}
`
	srcPath := filepath.Join(t.TempDir(), "PinnedCheck.runar.go")
	if err := os.WriteFile(srcPath, []byte(source), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	compile := func(vk string) string {
		art, err := CompileFromSource(srcPath, CompileOptions{Groth16WAVKey: vk})
		if err != nil {
			t.Fatalf("compile with %s: %v", vk, err)
		}
		return art.Script
	}
	unpinned := compile(vkPath)
	pinned := compile(pinnedPath)
	if len(pinned) >= len(unpinned) {
		t.Fatalf("pinned contract script is not smaller: %d >= %d hex chars", len(pinned), len(unpinned))
	}
	t.Logf("stateful contract: pinned %d, unpinned %d hex chars", len(pinned), len(unpinned))
}

// TestPinnedPublicInputs_StandaloneChecksEachSlotOnce: the groth16-wa
// backend pins all five inputs with --pub. A slot the vk.json also pins has
// already been checked inside the MSM binding, so the backend's own pass must
// only drop it, not compare it a second time.
func TestPinnedPublicInputs_StandaloneChecksEachSlotOnce(t *testing.T) {
	pubs := []*big.Int{big.NewInt(7), big.NewInt(11), big.NewInt(0), big.NewInt(13), big.NewInt(0)}
	count := func(ops []codegen.StackOp, code string) int {
		n := 0
		for _, op := range ops {
			if op.Op == "opcode" && op.Code == code {
				n++
			}
		}
		return n
	}

	none := emitGroth16PublicInputPins(nil, pubs, [5]*big.Int{})
	if got := count(none, "OP_EQUALVERIFY"); got != 5 {
		t.Fatalf("no vk.json pins: expected 5 OP_EQUALVERIFY, got %d", got)
	}
	if got := count(none, "OP_DROP"); got != 1 {
		t.Fatalf("no vk.json pins: expected 1 OP_DROP (the truthy marker), got %d", got)
	}

	var byConfig [5]*big.Int
	byConfig[0], byConfig[2], byConfig[3] = pubs[0], pubs[2], pubs[3]
	some := emitGroth16PublicInputPins(nil, pubs, byConfig)
	if got := count(some, "OP_EQUALVERIFY"); got != 2 {
		t.Fatalf("slots 0,2,3 pinned by vk.json: expected 2 OP_EQUALVERIFY, got %d", got)
	}
	if got := count(some, "OP_DROP"); got != 4 {
		t.Fatalf("slots 0,2,3 pinned by vk.json: expected 4 OP_DROP (marker + 3 slots), got %d", got)
	}
	// Every slot is consumed exactly once either way, so the stack effect
	// of the two forms is identical: 6 items in, 1 out.
	if len(some) != len(none)-3*1 { // each skipped slot: push+EQUALVERIFY (2 ops) becomes DROP (1 op)
		t.Fatalf("expected %d ops with three slots skipped, got %d", len(none)-3, len(some))
	}

	// End to end: the honest proof still verifies with the duplicate checks
	// gone (the pinned builds in the other tests go through this path), and
	// the standalone artifact is smaller than it would be with both checks.
	s := newSynthGroth16(t)
	honest := honestPublicInputs(t)
	proof := s.proofFor(honest)
	s.sanityCheck(t, proof, honest)
	path := writePinnedVK(t, s.vkPath, pinsFrom(honest, 0, 2, 3))
	art, err := CompileGroth16WA(path, Groth16WAOpts{PublicInputs: honest})
	if err != nil {
		t.Fatalf("CompileGroth16WA: %v", err)
	}
	if err := executeArtifactWithWitness(t, art, buildWitness(t, layoutMSM, s.vk, proof, honest)); err != nil {
		t.Fatalf("honest proof rejected once the duplicate pin checks were removed: %v", err)
	}
	// A spend whose witness lies about a vk.json-pinned slot must still be
	// caught by the single remaining check inside the MSM binding.
	w := buildWitness(t, layoutMSM, s.vk, proof, honest)
	w.PublicInputs[0] = new(big.Int).Add(w.PublicInputs[0], big.NewInt(1))
	if err := executeArtifactWithWitness(t, art, w); err == nil {
		t.Fatal("a witness scalar that disagrees with the vk.json pin was accepted after the backend's own check was dropped")
	}
}

// TestPinnedPublicInputs_StandaloneRejectsConflictingPub: a vk.json pin and
// the --pub value for the same slot must agree, or the verifier could never
// accept any proof. That is refused at compile time.
func TestPinnedPublicInputs_StandaloneRejectsConflictingPub(t *testing.T) {
	s := newSynthGroth16(t)
	honest := honestPublicInputs(t)
	conflict := map[int]*big.Int{0: new(big.Int).Add(honest[0], big.NewInt(1))}
	path := writePinnedVK(t, s.vkPath, conflict)
	_, err := CompileGroth16WA(path, Groth16WAOpts{PublicInputs: honest})
	if err == nil {
		t.Fatal("CompileGroth16WA accepted a --pub value that contradicts the vk.json pin for the same slot")
	}
	if !strings.Contains(err.Error(), "pinnedPublicInputs") || !strings.Contains(err.Error(), "public input 0") {
		t.Fatalf("error should name the slot and the field; got: %v", err)
	}
	// Agreeing values compile.
	path = writePinnedVK(t, s.vkPath, pinsFrom(honest, 0))
	if _, err := CompileGroth16WA(path, Groth16WAOpts{PublicInputs: honest}); err != nil {
		t.Fatalf("CompileGroth16WA with an agreeing pin: %v", err)
	}
}

// TestPinnedPublicInputs_RejectedOnNonMSMPath: the plain witness-assisted
// verifier (AssertGroth16WitnessAssisted, no MSM binding) never sees the
// public-input scalars and cannot enforce a pin. A vk.json that pins inputs
// is refused for such a method rather than silently ignored; the same vk.json
// is accepted by the MSM variant and the unpinned vk.json by both.
func TestPinnedPublicInputs_RejectedOnNonMSMPath(t *testing.T) {
	vkPath := sp1VKPath(t)
	pubs := sp1PublicInputs(t)
	pinnedPath := writePinnedVK(t, vkPath, pinsFrom(pubs, 0, 2, 3))

	write := func(name, assertCall string) string {
		source := `
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type ` + name + ` struct {
	runar.SmartContract
}

func (c *` + name + `) Verify() {
	runar.` + assertCall + `()
	runar.Assert(true)
}
`
		p := filepath.Join(t.TempDir(), name+".runar.go")
		if err := os.WriteFile(p, []byte(source), 0o644); err != nil {
			t.Fatalf("write source: %v", err)
		}
		return p
	}
	raw := write("RawPinned", "AssertGroth16WitnessAssisted")
	msm := write("MSMPinned", "AssertGroth16WitnessAssistedWithMSM")

	_, err := CompileFromSource(raw, CompileOptions{Groth16WAVKey: pinnedPath})
	if err == nil {
		t.Fatal("a pinned vk.json was accepted for AssertGroth16WitnessAssisted, where the pin cannot be enforced")
	}
	if !strings.Contains(err.Error(), "pinnedPublicInputs") || !strings.Contains(err.Error(), "WithMSM") {
		t.Fatalf("error should name the field and point at the MSM variant; got: %v", err)
	}
	if _, err := CompileFromSource(raw, CompileOptions{Groth16WAVKey: vkPath}); err != nil {
		t.Fatalf("unpinned vk.json on the raw variant should compile: %v", err)
	}
	if _, err := CompileFromSource(msm, CompileOptions{Groth16WAVKey: pinnedPath}); err != nil {
		t.Fatalf("pinned vk.json on the MSM variant should compile: %v", err)
	}
}
