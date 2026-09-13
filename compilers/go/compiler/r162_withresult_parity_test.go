package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R-162 (CL-BUG-132): CompileFromSourceWithResult and
// CompileFromSourceStrWithResult were 165 lines each, line-for-line identical
// to one another except for how they acquire the source, and both had drifted
// from the canonical CompileFromProgram path.
//
// The drift that BITES is the Groth16 one: both *WithResult paths rebuilt
// codegen.LowerToStackOptions from scratch and set only SP1FriParams, so a
// caller who supplied CompileOptions.Groth16WAVKey got
//
//	method "Advance" calls assertGroth16WitnessAssisted but no Groth16WAConfig
//	was supplied to the codegen (set CompileOptions.Groth16WAVKey to a SP1
//	vk.json path)
//
// — told to set the option they had just set. CompileFromSource, which the CLI
// uses, wires it correctly, which is why the CLI never saw this.
//
// These tests pin the three API surfaces to the same behaviour rather than
// pinning the duplicated code, so the duplication can be collapsed (or come
// back) without the tests caring.
const r162Groth16Source = `
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type R162VKCheck struct {
	runar.StatefulSmartContract

	Pinned  runar.Bigint ` + "`" + `runar:"readonly"` + "`" + `
	Counter runar.Bigint
}

func (c *R162VKCheck) Advance(nextCounter runar.Bigint) {
	runar.AssertGroth16WitnessAssistedWithMSM()
	runar.Assert(runar.Groth16PublicInput(0) == c.Pinned)
	c.Counter = nextCounter
}
`

func r162WriteSource(t *testing.T) string {
	t.Helper()
	srcPath := filepath.Join(t.TempDir(), "R162VKCheck.runar.go")
	if err := os.WriteFile(srcPath, []byte(r162Groth16Source), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	return srcPath
}

// The canonical path. This one always worked; it is the control that proves
// the contract and the vk.json are good, so a failure below is the API's.
func TestR162_CanonicalPathWiresTheSuppliedVK(t *testing.T) {
	vkPath := sp1VKPath(t)
	art, err := CompileFromSource(r162WriteSource(t), CompileOptions{Groth16WAVKey: vkPath})
	if err != nil {
		t.Fatalf("CompileFromSource with a supplied VK failed: %v", err)
	}
	if art == nil || len(art.Script) == 0 {
		t.Fatal("CompileFromSource produced no script")
	}
}

func TestR162_WithResultWiresTheSuppliedVK(t *testing.T) {
	vkPath := sp1VKPath(t)
	res := CompileFromSourceWithResult(r162WriteSource(t), CompileOptions{Groth16WAVKey: vkPath})

	for _, d := range res.Diagnostics {
		if strings.Contains(d.Message, "no Groth16WAConfig was supplied") {
			t.Fatalf("the supplied Groth16WAVKey was dropped: %s", d.Message)
		}
	}
	if !res.Success {
		t.Fatalf("CompileFromSourceWithResult failed with a supplied VK: %v", res.Diagnostics)
	}
	if res.Artifact == nil || len(res.Artifact.Script) == 0 {
		t.Fatal("CompileFromSourceWithResult produced no script")
	}
}

func TestR162_StrWithResultWiresTheSuppliedVK(t *testing.T) {
	vkPath := sp1VKPath(t)
	res := CompileFromSourceStrWithResult(
		r162Groth16Source, "R162VKCheck.runar.go", CompileOptions{Groth16WAVKey: vkPath})

	for _, d := range res.Diagnostics {
		if strings.Contains(d.Message, "no Groth16WAConfig was supplied") {
			t.Fatalf("the supplied Groth16WAVKey was dropped: %s", d.Message)
		}
	}
	if !res.Success {
		t.Fatalf("CompileFromSourceStrWithResult failed with a supplied VK: %v", res.Diagnostics)
	}
	if res.Artifact == nil || len(res.Artifact.Script) == 0 {
		t.Fatal("CompileFromSourceStrWithResult produced no script")
	}
}

// All three APIs must emit the SAME bytes for the same input and options.
// This is the assertion that keeps a future divergence from being invisible:
// the Groth16 preamble is byte-sensitive to the VK, so a dropped VK cannot
// produce a matching script.
func TestR162_AllThreeAPIsAgreeOnTheBytes(t *testing.T) {
	vkPath := sp1VKPath(t)
	srcPath := r162WriteSource(t)
	opts := CompileOptions{Groth16WAVKey: vkPath}

	art, err := CompileFromSource(srcPath, opts)
	if err != nil {
		t.Fatalf("CompileFromSource: %v", err)
	}
	withResult := CompileFromSourceWithResult(srcPath, opts)
	if !withResult.Success {
		t.Fatalf("CompileFromSourceWithResult: %v", withResult.Diagnostics)
	}
	strResult := CompileFromSourceStrWithResult(r162Groth16Source, "R162VKCheck.runar.go", opts)
	if !strResult.Success {
		t.Fatalf("CompileFromSourceStrWithResult: %v", strResult.Diagnostics)
	}

	if string(art.Script) != string(withResult.Artifact.Script) {
		t.Errorf("CompileFromSource and CompileFromSourceWithResult disagree: %d vs %d bytes",
			len(art.Script), len(withResult.Artifact.Script))
	}
	if string(art.Script) != string(strResult.Artifact.Script) {
		t.Errorf("CompileFromSource and CompileFromSourceStrWithResult disagree: %d vs %d bytes",
			len(art.Script), len(strResult.Artifact.Script))
	}
}

// Divergence (3), in the other direction: the issue-#109 embedAlways DCE
// warning ran ONLY in the *WithResult paths, so the canonical
// CompileFromSourceCollectingWarnings emitted none. A readonly field that no
// method reads is dropped by DCE, and every API that reports warnings at all
// must say so.
const r162DCESource = `
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type R162DCECheck struct {
	runar.SmartContract

	Unused runar.Bigint ` + "`" + `runar:"readonly"` + "`" + `
	Limit  runar.Bigint ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *R162DCECheck) Unlock(x runar.Bigint) {
	runar.Assert(x < c.Limit)
}
`

func TestR162_DCEWarningReachesEveryWarningAPI(t *testing.T) {
	srcPath := filepath.Join(t.TempDir(), "R162DCECheck.runar.go")
	if err := os.WriteFile(srcPath, []byte(r162DCESource), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	res := CompileFromSourceWithResult(srcPath)
	if !res.Success {
		t.Fatalf("compile failed: %v", res.Diagnostics)
	}
	foundInResult := false
	for _, d := range res.Diagnostics {
		if strings.Contains(d.Message, "eliminated by DCE") {
			foundInResult = true
		}
	}
	if !foundInResult {
		t.Fatal("CompileFromSourceWithResult lost the embedAlways DCE warning")
	}

	_, warnings, err := CompileFromSourceCollectingWarnings(srcPath)
	if err != nil {
		t.Fatalf("CompileFromSourceCollectingWarnings: %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w.Message, "eliminated by DCE") {
			found = true
		}
	}
	if !found {
		t.Fatalf("CompileFromSourceCollectingWarnings emitted no DCE warning; got %d warnings: %v",
			len(warnings), warnings)
	}
}
