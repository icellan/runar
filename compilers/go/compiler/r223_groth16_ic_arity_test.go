package compiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R-223 (CL-GAP-080): loadGroth16WAConfig pads the IC array to six points with
// (0, 0) when the verifying key carries fewer, and its own comment says why that
// is dangerous — "the MSM variant is only sound for 5-public-input circuits".
// The finding adds that `numPubInputs` "is computed at :157 and recorded in
// metadata but NEVER compared against 5".
//
// The comparison exists today (validateGroth16PublicInputs, the
// `numPubInputs != groth16MSMArity` arm), and CompileGroth16WA runs it BEFORE
// building the config. So the padding is unreachable through this entry point:
// a VK with 4 IC entries is 3 public inputs, which the arity check refuses, and
// a VK with 8 is 7, refused the same way.
//
// "Unreachable because a check upstream fires first" is exactly the kind of
// claim that stops being true when someone reorders two statements. These tests
// pin the ORDER by its observable consequence: a short or long VK must be
// refused by ARITY, naming the counts — not accepted with silent (0, 0) points
// standing in for the missing ones, which would verify a proof against a
// verifying key nobody chose.

// writeVKWithICCount copies the real SP1 verifying key, resizes its IC array to
// `n` entries, and returns the path. Everything else about the key is untouched,
// so the only thing under test is the IC count.
func r223VKWithICCount(t *testing.T, n int) string {
	t.Helper()
	raw, err := os.ReadFile(sp1VKPath(t))
	if err != nil {
		t.Fatalf("read SP1 VK: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse SP1 VK: %v", err)
	}
	ic, ok := doc["ic"].([]any)
	if !ok {
		t.Fatal("SP1 VK has no IC array — the fixture shape changed")
	}
	if len(ic) != 6 {
		t.Fatalf("expected the SP1 fixture to carry 6 IC entries, got %d", len(ic))
	}

	resized := make([]any, 0, n)
	for i := 0; i < n; i++ {
		resized = append(resized, ic[i%len(ic)])
	}
	doc["ic"] = resized
	// The fixture also records the count; keep the document self-consistent so
	// the test is about IC arity and not about a contradictory field.
	doc["numPubInputs"] = n - 1

	out := filepath.Join(t.TempDir(), "resized.groth16.vk.json")
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-encode VK: %v", err)
	}
	if err := os.WriteFile(out, encoded, 0o644); err != nil {
		t.Fatalf("write VK: %v", err)
	}
	return out
}

// The control: the real key still compiles. Without it, a change that refuses
// every VK would satisfy both cases below.
func TestR223_TheRealVKStillCompiles(t *testing.T) {
	art, err := CompileGroth16WA(sp1VKPath(t), Groth16WAOpts{PublicInputs: sp1PublicInputs(t)})
	if err != nil {
		t.Fatalf("the SP1 VK must compile: %v", err)
	}
	if art == nil || len(art.Script) == 0 {
		t.Fatal("no script emitted")
	}
}

func TestR223_AShortVKIsRefusedByArityNotPadded(t *testing.T) {
	// 4 IC entries = 3 public inputs. The MSM binding is only sound at 5.
	vk := r223VKWithICCount(t, 4)
	_, err := CompileGroth16WA(vk, Groth16WAOpts{PublicInputs: sp1PublicInputs(t)})
	if err == nil {
		t.Fatal("a 3-public-input VK compiled: the missing IC points were padded " +
			"with (0, 0) and the verifier now checks a statement nobody chose")
	}
	// The assertion is on the ARITY check specifically, not on any refusal that
	// happens to mention a 5. An earlier version of this test asked only for
	// "public input" and a "5", and passed on the DIFFERENT error that fires
	// when the pinned-input count disagrees with the key ("pinned 5 public
	// inputs but the verifying key declares 3") — which would still have been
	// green with the arity check deleted.
	assertRefusedByMSMArity(t, err)
}

// The sentence only the `numPubInputs != groth16MSMArity` arm produces.
func assertRefusedByMSMArity(t *testing.T, err error) {
	t.Helper()
	const want = "on-chain MSM binding supports exactly 5"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("expected the MSM-arity refusal (%q); got: %s", want, err)
	}
}

func TestR223_ALongVKIsRefusedByArityToo(t *testing.T) {
	// 8 IC entries = 7 public inputs; the extra points would be dropped.
	vk := r223VKWithICCount(t, 8)
	_, err := CompileGroth16WA(vk, Groth16WAOpts{PublicInputs: sp1PublicInputs(t)})
	if err == nil {
		t.Fatal("a 7-public-input VK compiled: IC[6..] are silently ignored by the " +
			"6-point MSM binding")
	}
	assertRefusedByMSMArity(t, err)
}

// F-184 (CL-BUG-221/222/223): the tests above pin the arity gate on the
// standalone backend (CompileGroth16WA). The LIBRARY path —
// CompileOptions.Groth16WAVKey -> buildLowerOptions -> loadGroth16WAConfig —
// never called validateGroth16PublicInputs, so a Mode-3 contract embedding the
// MSM-binding preamble compiled against a non-5-public-input VK with the
// missing IC slots zero-filled (a short key) or the extra ones dropped (a long
// key). The gate now lives in loadGroth16WAConfig, which every entry point
// passes through.
//
// Proves: a well-formed SP1-shaped VK with 3 or 6 public inputs is refused by
// the MSM-arity check (same sentence as the standalone backend) through the
// public library API, and the real 5-input key still compiles there.
// Does not prove: anything about the soundness of the 5-input MSM binding
// itself, or about on-chain execution — no script is run here.
const f184MSMSource = `
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type F184MSM struct {
	runar.StatefulSmartContract

	Pinned  runar.Bigint ` + "`" + `runar:"readonly"` + "`" + `
	Counter runar.Bigint
}

func (c *F184MSM) Advance(nextCounter runar.Bigint) {
	runar.AssertGroth16WitnessAssistedWithMSM()
	runar.Assert(runar.Groth16PublicInput(0) == c.Pinned)
	c.Counter = nextCounter
}
`

func f184CompileMSM(t *testing.T, vkPath string) error {
	t.Helper()
	src := filepath.Join(t.TempDir(), "F184MSM.runar.go")
	if err := os.WriteFile(src, []byte(f184MSMSource), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	art, err := CompileFromSource(src, CompileOptions{Groth16WAVKey: vkPath})
	if err == nil && (art == nil || len(art.Script) == 0) {
		t.Fatal("compile returned no error but no script")
	}
	return err
}

func TestF184_LibraryPath_RealVKStillCompiles(t *testing.T) {
	if err := f184CompileMSM(t, sp1VKPath(t)); err != nil {
		t.Fatalf("the SP1 VK must compile through CompileOptions.Groth16WAVKey: %v", err)
	}
}

func TestF184_LibraryPath_ShortVKIsRefusedByArity(t *testing.T) {
	// 4 IC entries = 3 public inputs: IC[4], IC[5] would be zero-filled.
	err := f184CompileMSM(t, r223VKWithICCount(t, 4))
	if err == nil {
		t.Fatal("a 3-public-input VK compiled through CompileOptions.Groth16WAVKey: " +
			"IC[4] and IC[5] were padded with (0, 0)")
	}
	assertRefusedByMSMArity(t, err)
}

func TestF184_LibraryPath_LongVKIsRefusedByArity(t *testing.T) {
	// 7 IC entries = 6 public inputs: IC[6] would be silently dropped.
	err := f184CompileMSM(t, r223VKWithICCount(t, 7))
	if err == nil {
		t.Fatal("a 6-public-input VK compiled through CompileOptions.Groth16WAVKey: " +
			"IC[6] was silently dropped by the 6-point MSM binding")
	}
	assertRefusedByMSMArity(t, err)
}
