package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// N-194 — CompileFromSourceCollectingWarnings / CompileSourceToIRCollectingWarnings
// (and their thin wrappers CompileFromSource / CompileSourceToIR) take a
// CompileOptions that carries ParseOnly / ValidateOnly / TypecheckOnly, but
// never read those three fields: mergeOptions(opts) was computed only after
// passes 1-4 already ran, and nothing downstream checked it. So a caller
// asking either entry point to stop after parse/validate/typecheck got the
// full artifact (or a later-pass error) anyway — the exact gap F-217 fixed
// in the Rust tier's sibling APIs (compile_from_source_str_with_options /
// compile_source_str_to_ir_with_options), which now reject the option up
// front instead of silently running every later pass.
//
// Fix: both functions merge options as their first statement and reject
// ParseOnly/ValidateOnly/TypecheckOnly before pass 1 runs, naming the
// option and pointing at CompileFromSourceStrWithResult (or
// CompileFromSourceWithResult) — the one API in this tier that CAN
// represent "stopped successfully after an earlier pass, no artifact yet"
// (its CompileResult has no Ok/Err split; Success + partial fields cover
// the case these plain (*Artifact, ..., error) / (*ir.ANFProgram, ...,
// error) signatures cannot).
//
// Proves: on both affected entry points, setting one of the three options
// is rejected before any pass runs — in particular, a ParseOnly caller
// never sees a validation-pass error leak through (the exact failure mode
// in the bug report), and a TypecheckOnly caller on an otherwise-VALID
// contract no longer gets silently compiled all the way through to a full
// IR/artifact. Also proves CompileFromSourceStrWithResult, the dedicated
// partial-compilation API, is unaffected by this change.
//
// Does not prove anything about CompileFromProgram / CompileFromIR (they
// start from an already-lowered ANF program — passes 1-3 are already
// behind them, so ParseOnly/ValidateOnly/TypecheckOnly are meaningless
// there and out of scope for this item), nor about any CLI flag: audited,
// no Go CLI flag sets these three fields on the opts passed into either
// affected function today (`--parse-only` bypasses CompileOptions
// entirely via ParseAndValidateOnly, confirmed by grep across the repo).

// n194ParseableButValidationInvalid parses fine (valid Rúnar Go-DSL syntax)
// but fails validation: a SmartContract property must be readonly; Owner
// here is not.
const n194ParseableButValidationInvalid = `
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type N194Invalid struct {
	runar.SmartContract

	Owner runar.Bigint
}

func (c *N194Invalid) Spend() {
	runar.Assert(c.Owner > 0)
}
`

// n194ValidSource is fully valid: parses, validates, and typechecks clean.
const n194ValidSource = `
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type N194Valid struct {
	runar.SmartContract

	Owner runar.Bigint ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *N194Valid) Spend() {
	runar.Assert(c.Owner > 0)
}
`

// n194WriteSource writes src to a fresh scratch directory and returns the
// file path. Deliberately NOT t.TempDir(): that embeds the test name in the
// path, and several of this file's test names contain the exact option name
// ("ParseOnly", "ValidateOnly", "TypecheckOnly") under assertion — a path
// built from t.Name() would make `strings.Contains(err.Error(), "ParseOnly")`
// true just because the error wraps a path, regardless of whether the fix
// actually ran. A neutral-prefixed dir keeps the option-name match tied to
// the rejection message, not to the test's own name.
func n194WriteSource(t *testing.T, name, src string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "n194-scratch-")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	return path
}

// Control: confirms the fixture really is parseable-but-validation-invalid
// under default options. If this fails, the red assertions below are
// vacuous (the fixture, not the option, would be what fails).
func TestN194_ControlFixtureIsValidationInvalidNotParseInvalid(t *testing.T) {
	path := n194WriteSource(t, "N194Invalid.runar.go", n194ParseableButValidationInvalid)
	_, _, err := CompileFromSourceCollectingWarnings(path)
	if err == nil {
		t.Fatal("fixture must fail compilation under default options")
	}
	if !strings.Contains(err.Error(), "validation errors") || !strings.Contains(err.Error(), "must be readonly") {
		t.Fatalf("expected a validation error, got: %v", err)
	}
}

// The item's testable assertion verbatim: setting ParseOnly on a
// validation-invalid contract must not surface a validation error (and
// before the fix it did, because ParseOnly was never checked).
func TestN194_ParseOnlyRejectedOnCollectingWarnings(t *testing.T) {
	path := n194WriteSource(t, "N194Invalid.runar.go", n194ParseableButValidationInvalid)
	artifact, _, err := CompileFromSourceCollectingWarnings(path, CompileOptions{ParseOnly: true})
	if err == nil {
		t.Fatal("ParseOnly must be rejected, not silently ignored")
	}
	if artifact != nil {
		t.Fatal("ParseOnly must not surface a full artifact")
	}
	if strings.Contains(err.Error(), "validation errors") {
		t.Fatalf("ParseOnly leaked a validation-pass error instead of being rejected up front: %v", err)
	}
	if !strings.Contains(err.Error(), "ParseOnly") {
		t.Fatalf("rejection message should name the unsupported option: %v", err)
	}
}

// Same option, same fixture, through the plain CompileFromSource wrapper
// (what every CLI/SDK caller that passes CompileOptions directly actually
// calls).
func TestN194_ParseOnlyRejectedOnCompileFromSource(t *testing.T) {
	path := n194WriteSource(t, "N194Invalid.runar.go", n194ParseableButValidationInvalid)
	artifact, err := CompileFromSource(path, CompileOptions{ParseOnly: true})
	if err == nil {
		t.Fatal("ParseOnly must be rejected, not silently ignored")
	}
	if artifact != nil {
		t.Fatal("ParseOnly must not surface a full artifact")
	}
	if !strings.Contains(err.Error(), "ParseOnly") {
		t.Fatalf("rejection message should name the unsupported option: %v", err)
	}
}

// ValidateOnly on the sibling IR-producing entry point, same fixture.
func TestN194_ValidateOnlyRejectedOnCompileSourceToIRCollectingWarnings(t *testing.T) {
	path := n194WriteSource(t, "N194Invalid.runar.go", n194ParseableButValidationInvalid)
	program, _, err := CompileSourceToIRCollectingWarnings(path, CompileOptions{ValidateOnly: true})
	if err == nil {
		t.Fatal("ValidateOnly must be rejected, not silently ignored")
	}
	if program != nil {
		t.Fatal("ValidateOnly must not surface an ANF program")
	}
	if !strings.Contains(err.Error(), "ValidateOnly") {
		t.Fatalf("rejection message should name the unsupported option: %v", err)
	}
}

// TypecheckOnly on a fully VALID contract via CompileSourceToIR. Before the
// fix this compiled all the way through passes 1-4 and returned a real
// ANFProgram with a nil error, silently ignoring the option — the cleanest
// demonstration that the option was dropped, since nothing here fails for
// any OTHER reason.
func TestN194_TypecheckOnlyRejectedOnValidContract(t *testing.T) {
	path := n194WriteSource(t, "N194Valid.runar.go", n194ValidSource)
	program, err := CompileSourceToIR(path, CompileOptions{TypecheckOnly: true})
	if err == nil {
		t.Fatal("TypecheckOnly must be rejected on a valid contract, not silently ignored")
	}
	if program != nil {
		t.Fatal("TypecheckOnly must not surface an ANF program")
	}
	if !strings.Contains(err.Error(), "TypecheckOnly") {
		t.Fatalf("rejection message should name the unsupported option: %v", err)
	}
}

// Regression guard: the dedicated partial-compilation API
// (CompileFromSourceStrWithResult) is unaffected — it already honors
// ParseOnly by returning a successful partial CompileResult with no error
// diagnostics and the parsed contract present.
func TestN194_WithResultAPIStillHonorsParseOnly(t *testing.T) {
	res := CompileFromSourceStrWithResult(
		n194ParseableButValidationInvalid, "N194Invalid.runar.go", CompileOptions{ParseOnly: true})
	if !res.Success {
		t.Fatalf("CompileFromSourceStrWithResult must still stop successfully after parse: %v", res.Diagnostics)
	}
	if res.Contract == nil {
		t.Fatal("CompileFromSourceStrWithResult must still return the parsed contract")
	}
}
