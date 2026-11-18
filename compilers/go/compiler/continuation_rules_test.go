package compiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/frontend"
)

// #199 (release-trap warning) and D18 (dropped-continuation error), Go tier.
// Corpora are the cross-tier ones in conformance/negatives/, shared with the
// other six tiers and the conformance gates (gk-frontend-parity.test.ts,
// ir-release-trap.test.ts). Mirrors packages/runar-compiler/src/passes/continuation-rules.ts.

type continuationCase struct {
	Name, File, Src, Warning, Error string
	WarningAbsent                   string `json:"warning_absent"`
}

func continuationCorpus(t *testing.T, name string) map[string][]continuationCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "negatives", name))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string][]continuationCase{}
	for k, v := range doc {
		var cases []continuationCase
		if json.Unmarshal(v, &cases) == nil {
			out[k] = cases
		}
	}
	return out
}

func contDiags(diags []frontend.Diagnostic, severity frontend.Severity) []string {
	var out []string
	for _, d := range diags {
		if d.Severity == severity {
			out = append(out, d.Message)
		}
	}
	return out
}

func contContains(list []string, want string) bool {
	for _, s := range list {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

func TestReleaseTrapWarning199(t *testing.T) {
	corpus := continuationCorpus(t, "release-trap-cases.json")
	if len(corpus["warn"]) < 3 || len(corpus["nowarn"]) < 3 {
		t.Fatalf("corpus too small: %d warn, %d nowarn", len(corpus["warn"]), len(corpus["nowarn"]))
	}
	for _, c := range corpus["warn"] {
		t.Run("warn/"+c.Name, func(t *testing.T) {
			r := CompileFromSourceStrWithResult(c.Src, c.File, CompileOptions{DisableConstantFolding: true})
			if !r.Success {
				t.Fatalf("refused: %v", contDiags(r.Diagnostics, frontend.SeverityError))
			}
			if !contContains(contDiags(r.Diagnostics, frontend.SeverityWarning), c.Warning) {
				t.Fatalf("missing warning %q; got %v", c.Warning, contDiags(r.Diagnostics, frontend.SeverityWarning))
			}
		})
	}
	for _, c := range corpus["nowarn"] {
		t.Run("nowarn/"+c.Name, func(t *testing.T) {
			r := CompileFromSourceStrWithResult(c.Src, c.File, CompileOptions{DisableConstantFolding: true})
			if !r.Success {
				t.Fatalf("refused: %v", contDiags(r.Diagnostics, frontend.SeverityError))
			}
			if contContains(contDiags(r.Diagnostics, frontend.SeverityWarning), c.WarningAbsent) {
				t.Fatalf("unexpected warning %q", c.WarningAbsent)
			}
		})
	}
}

func TestDroppedContinuationD18Source(t *testing.T) {
	corpus := continuationCorpus(t, "dropped-continuation-cases.json")
	if len(corpus["refuse"]) < 5 || len(corpus["accept"]) < 3 {
		t.Fatalf("corpus too small: %d refuse, %d accept", len(corpus["refuse"]), len(corpus["accept"]))
	}
	for _, c := range corpus["refuse"] {
		t.Run("refuse/"+c.Name, func(t *testing.T) {
			r := CompileFromSourceStrWithResult(c.Src, c.File, CompileOptions{DisableConstantFolding: true})
			if r.Success {
				t.Fatal("accepted")
			}
			if !contContains(contDiags(r.Diagnostics, frontend.SeverityError), c.Error) {
				t.Fatalf("missing error %q; got %v", c.Error, contDiags(r.Diagnostics, frontend.SeverityError))
			}
		})
	}
	for _, c := range corpus["accept"] {
		t.Run("accept/"+c.Name, func(t *testing.T) {
			r := CompileFromSourceStrWithResult(c.Src, c.File, CompileOptions{DisableConstantFolding: true})
			if !r.Success {
				t.Fatalf("refused: %v", contDiags(r.Diagnostics, frontend.SeverityError))
			}
		})
	}
}

// D18 on the --ir path: CompileFromIRBytes skips typecheck, so the loader
// re-derives the rule from the ANF. Each refuse source is lowered with
// validate / typecheck skipped (the IR a pre-D18 frontend emitted); each
// accept source's own ANF must still compile.
func TestDroppedContinuationD18IR(t *testing.T) {
	corpus := continuationCorpus(t, "dropped-continuation-cases.json")
	for _, c := range corpus["refuse"] {
		t.Run("refuse/"+c.Name, func(t *testing.T) {
			parsed := frontend.ParseSource([]byte(c.Src), c.File)
			if parsed.Contract == nil {
				t.Fatalf("parse: %v", parsed.ErrorStrings())
			}
			// Pass 3b, as the real pipeline runs it before ANF lowering.
			expanded := frontend.ExpandFixedArrays(parsed.Contract)
			if len(expanded.Errors) > 0 {
				t.Fatalf("expand-fixed-arrays: %v", expanded.Errors)
			}
			program, err := lowerToANFRecovering(expanded.Contract)
			if err != nil {
				// The lowerer itself refuses a write inside an output-declaring
				// branch: that refusal is this case's expected outcome here, and
				// its IR shape is hand-built below instead.
				if strings.Contains(err.Error(), "both declares outputs and assigns contract properties") {
					return
				}
				t.Fatal(err)
			}
			data, err := json.Marshal(program)
			if err != nil {
				t.Fatal(err)
			}
			s := string(data)
			if !strings.Contains(s, `"update_prop"`) || !(strings.Contains(s, `"add_raw_output"`) || strings.Contains(s, `"add_output"`)) {
				t.Fatalf("lowered IR is not a dropped-continuation shape")
			}
			_, err = CompileFromIRBytes(data)
			if err == nil {
				t.Fatal("--ir accepted")
			}
			if !strings.Contains(err.Error(), c.Error) {
				t.Fatalf("want %q, got %v", c.Error, err)
			}
		})
	}
	// The per-path shape only a hand-written IR can carry: the accepted
	// terminal-branch-writes-nothing program with an update_prop added to its
	// raw-output branch (mirrors writeOnRawBranchIr in ir-release-trap.test.ts).
	t.Run("refuse/ir-write-on-raw-branch-sibling-add-output", func(t *testing.T) {
		var base, want continuationCase
		for _, c := range corpus["accept"] {
			if c.Name == "terminal-branch-writes-nothing" {
				base = c
			}
		}
		for _, c := range corpus["refuse"] {
			if c.Name == "write-on-raw-branch-sibling-add-output" {
				want = c
			}
		}
		if base.Src == "" || want.Error == "" {
			t.Fatal("corpus cases missing")
		}
		r := CompileFromSourceStrWithResult(base.Src, base.File, CompileOptions{DisableConstantFolding: true})
		if !r.Success || r.ANF == nil {
			t.Fatalf("source refused: %v", contDiags(r.Diagnostics, frontend.SeverityError))
		}
		raw, err := json.Marshal(r.ANF)
		if err != nil {
			t.Fatal(err)
		}
		var prog map[string]any
		if err := json.Unmarshal(raw, &prog); err != nil {
			t.Fatal(err)
		}
		hasRaw := func(bs []any) bool {
			for _, b := range bs {
				if b.(map[string]any)["value"].(map[string]any)["kind"] == "add_raw_output" {
					return true
				}
			}
			return false
		}
		patched := false
		for _, m := range prog["methods"].([]any) {
			mm := m.(map[string]any)
			if mm["name"] != "pay" {
				continue
			}
			for _, b := range mm["body"].([]any) {
				v := b.(map[string]any)["value"].(map[string]any)
				then, _ := v["then"].([]any)
				if patched || v["kind"] != "if" || !hasRaw(then) {
					continue
				}
				v["then"] = append([]any{
					map[string]any{"name": "d18w0", "value": map[string]any{"kind": "load_const", "value": 7}},
					map[string]any{"name": "d18w1", "value": map[string]any{"kind": "update_prop", "name": "count", "value": "d18w0"}},
				}, then...)
				patched = true
			}
		}
		if !patched {
			t.Fatal("no raw-output if arm to patch")
		}
		data, err := json.Marshal(prog)
		if err != nil {
			t.Fatal(err)
		}
		_, err = CompileFromIRBytes(data)
		if err == nil {
			t.Fatal("--ir accepted")
		}
		if !strings.Contains(err.Error(), want.Error) {
			t.Fatalf("want %q, got %v", want.Error, err)
		}
	})
	for _, c := range corpus["accept"] {
		t.Run("accept/"+c.Name, func(t *testing.T) {
			r := CompileFromSourceStrWithResult(c.Src, c.File, CompileOptions{DisableConstantFolding: true})
			if !r.Success || r.ANF == nil {
				t.Fatalf("source refused: %v", contDiags(r.Diagnostics, frontend.SeverityError))
			}
			data, err := json.Marshal(r.ANF)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := CompileFromIRBytes(data, CompileOptions{DisableConstantFolding: true}); err != nil {
				t.Fatalf("--ir refused: %v", err)
			}
		})
	}
}
