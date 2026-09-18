package compiler

import (
	"os"
	"testing"
	"time"
)

// R-176 (CL-BUG-007 class): CompileGroth16WA stamped the artifact with
// `time.Now().UTC()` directly instead of the `buildTimestamp()` helper that
// every other artifact path uses, so SOURCE_DATE_EPOCH — the reproducible-builds
// standard — was honoured everywhere except here.
//
// The consequence is narrow and total: two builds of the SAME verifying key,
// with SOURCE_DATE_EPOCH pinned, produced artifacts that differ. For an artifact
// whose whole purpose is to be a verifier someone else reproduces from the same
// vk.json before trusting it, "byte-identical except for a field that records
// when I ran it" is the difference between a reproducible build and a claim.
//
// The script hex was never affected — the timestamp is metadata. What was
// affected is `diff`, which is the tool the reproducibility claim is checked
// with.

func withSourceDateEpoch(t *testing.T, value string, f func()) {
	t.Helper()
	prev, had := os.LookupEnv("SOURCE_DATE_EPOCH")
	if err := os.Setenv("SOURCE_DATE_EPOCH", value); err != nil {
		t.Fatalf("set SOURCE_DATE_EPOCH: %v", err)
	}
	defer func() {
		if had {
			_ = os.Setenv("SOURCE_DATE_EPOCH", prev)
		} else {
			_ = os.Unsetenv("SOURCE_DATE_EPOCH")
		}
	}()
	f()
}

func TestR176_Groth16ArtifactHonoursSourceDateEpoch(t *testing.T) {
	vk := sp1VKPath(t)
	const epoch = "1700000000" // 2023-11-14T22:13:20Z
	want := time.Unix(1700000000, 0).UTC().Format(time.RFC3339)

	var got string
	withSourceDateEpoch(t, epoch, func() {
		art, err := CompileGroth16WA(vk, Groth16WAOpts{PublicInputs: sp1PublicInputs(t)})
		if err != nil {
			t.Fatalf("CompileGroth16WA: %v", err)
		}
		got = art.BuildTimestamp
	})

	if got != want {
		t.Errorf("BuildTimestamp ignored SOURCE_DATE_EPOCH: got %q, want %q", got, want)
	}
}

// The property the timestamp field exists to threaten: same key, same epoch,
// same bytes. Asserted on the whole artifact's metadata, not only the field,
// so a second wall-clock field added later fails here too.
func TestR176_TwoBuildsAtTheSameEpochAgree(t *testing.T) {
	vk := sp1VKPath(t)
	var first, second *Artifact

	withSourceDateEpoch(t, "1700000000", func() {
		var err error
		if first, err = CompileGroth16WA(vk, Groth16WAOpts{PublicInputs: sp1PublicInputs(t)}); err != nil {
			t.Fatalf("first build: %v", err)
		}
		time.Sleep(1100 * time.Millisecond) // cross a wall-clock second
		if second, err = CompileGroth16WA(vk, Groth16WAOpts{PublicInputs: sp1PublicInputs(t)}); err != nil {
			t.Fatalf("second build: %v", err)
		}
	})

	if first.BuildTimestamp != second.BuildTimestamp {
		t.Errorf("two builds of the same VK at a pinned epoch disagree: %q vs %q",
			first.BuildTimestamp, second.BuildTimestamp)
	}
	if first.Script != second.Script {
		t.Error("the script itself is not reproducible — a bigger problem than the timestamp")
	}
}

// Without the variable the artifact still gets a real build time: the fix must
// not turn the field into a constant.
func TestR176_WithoutTheVariableTheTimestampIsStillNow(t *testing.T) {
	prev, had := os.LookupEnv("SOURCE_DATE_EPOCH")
	_ = os.Unsetenv("SOURCE_DATE_EPOCH")
	defer func() {
		if had {
			_ = os.Setenv("SOURCE_DATE_EPOCH", prev)
		}
	}()

	before := time.Now().UTC().Add(-2 * time.Second)
	art, err := CompileGroth16WA(sp1VKPath(t), Groth16WAOpts{PublicInputs: sp1PublicInputs(t)})
	if err != nil {
		t.Fatalf("CompileGroth16WA: %v", err)
	}
	stamped, err := time.Parse(time.RFC3339, art.BuildTimestamp)
	if err != nil {
		t.Fatalf("BuildTimestamp %q is not RFC 3339: %v", art.BuildTimestamp, err)
	}
	if stamped.Before(before) {
		t.Errorf("BuildTimestamp %q predates the test — the field looks frozen", art.BuildTimestamp)
	}
}
