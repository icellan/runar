package compiler

import (
	"os"
	"path/filepath"
	"testing"
)

// fatalReporter is the slice of testing.TB the fixture helpers use, so a test
// can substitute a recorder and observe Fatalf without failing itself.
type fatalReporter interface {
	Helper()
	Fatalf(format string, args ...any)
}

// requireFixtureFile fails the test when path is missing.
func requireFixtureFile(t fatalReporter, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fixture %s is missing (%v): a moved or renamed fixture must fail the suite, not skip it", path, err)
	}
}

// requireConformanceSource returns the .runar.ts source path of a conformance
// fixture, failing the test when the fixture cannot be resolved.
func requireConformanceSource(t fatalReporter, testName string) string {
	t.Helper()
	source, ok := conformanceSourcePath(testName)
	if !ok {
		t.Fatalf("conformance fixture %q has no resolvable .runar.ts source under %s: a moved or renamed fixture must fail the suite, not skip it",
			testName, conformanceDir())
	}
	return source
}

type recordedFatal struct{ msg string }

type fatalRecorder struct{ fatalCalled bool }

func (r *fatalRecorder) Helper() {}
func (r *fatalRecorder) Fatalf(format string, args ...any) {
	r.fatalCalled = true
	panic(recordedFatal{msg: format})
}

func callRecovering(f func()) (fataled bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(recordedFatal); !ok {
				panic(r)
			}
			fataled = true
		}
	}()
	f()
	return false
}

// TestFixtureHelpers_MissingFixtureFailsNotSkips (N-478) proves that the
// helpers behind the compiler's source-reading tests call Fatalf, not Skip,
// when a conformance/example fixture path does not exist, so a moved or
// renamed fixture turns the suite red instead of silently green. It does not
// prove that every call site uses the helpers; that is enforced by review of
// the call sites (the former t.Skip("... source not found") lines are gone).
func TestFixtureHelpers_MissingFixtureFailsNotSkips(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-fixture.runar.go")

	t.Run("requireFixtureFile fatals on a nonexistent path", func(t *testing.T) {
		if !callRecovering(func() { requireFixtureFile(&fatalRecorder{}, missing) }) {
			t.Fatal("requireFixtureFile returned normally for a nonexistent path")
		}
	})

	t.Run("requireFixtureFile accepts an existing file", func(t *testing.T) {
		present := filepath.Join(t.TempDir(), "present.runar.go")
		if err := os.WriteFile(present, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if callRecovering(func() { requireFixtureFile(&fatalRecorder{}, present) }) {
			t.Fatal("requireFixtureFile fataled for an existing file")
		}
	})

	t.Run("requireConformanceSource fatals on an unknown fixture", func(t *testing.T) {
		if !callRecovering(func() { requireConformanceSource(&fatalRecorder{}, "n478-no-such-fixture") }) {
			t.Fatal("requireConformanceSource returned normally for an unknown fixture")
		}
	})

	t.Run("requireConformanceSource resolves a real fixture", func(t *testing.T) {
		var got string
		if callRecovering(func() { got = requireConformanceSource(&fatalRecorder{}, "basic-p2pkh") }) {
			t.Fatal("requireConformanceSource fataled for basic-p2pkh")
		}
		if got == "" {
			t.Fatal("empty path for basic-p2pkh")
		}
	})
}
