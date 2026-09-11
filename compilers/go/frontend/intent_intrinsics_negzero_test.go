package frontend

import (
	"encoding/json"
	"strings"
	"testing"
)

// N-060 — a `-0` index evades the literal gate and silently DELETES the
// covenant.
//
// The typecheck index gate in typecheck.go accepts `UnaryExpr{"-",
// BigIntLiteral}` only so that a negative index reports "must be >= 0" instead
// of the misleading "must be an integer literal". `-0` negates to `0`, so it
// passes that bound check — but ANF lowering matches on a BARE BigIntLiteral
// and, finding a UnaryExpr, falls through to `load_const ""`: no witness
// param, no hash assertion, NO COVENANT, and no diagnostic. A contract whose
// whole purpose is the covenant compiles to a script that does not carry it.
//
// Mirrors compilers/rust/tests/intent_intrinsics_bounds.rs (R-068).

const epsNegZeroSrc = `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
	runar.StatefulSmartContract
	H     runar.ByteString
	Count runar.Bigint
}

func (c *Cov) Bind() {
	s := runar.ExtractPrevOutputScript(-0, c.H)
	runar.Assert(runar.Len(s) > 0)
	c.Count = c.Count + 1
}
`

const ropNegZeroSrc = `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
	runar.StatefulSmartContract
	PKH   runar.ByteString
	Amt   runar.Bigint
	Count runar.Bigint
}

func (c *Cov) Pay() {
	runar.RequireOutputP2PKH(-0, c.PKH, c.Amt)
	c.Count = c.Count + 1
}
`

// anfJSONForNegZero parses/typechecks/lowers and returns the serialised ANF.
// Returns ok=false when typecheck rejected the source.
func anfJSONForNegZero(t *testing.T, source string) (string, bool) {
	t.Helper()
	result := ParseSource([]byte(source), "Test.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	if len(TypeCheck(result.Contract).Errors) > 0 {
		return "", false
	}
	program := LowerToANF(result.Contract)
	b, err := json.Marshal(program)
	if err != nil {
		t.Fatalf("serialize ANF: %v", err)
	}
	return string(b), true
}

func TestExtractPrevOutputScript_NegativeZeroIndex_Rejects(t *testing.T) {
	expectIntrinsicTypeError(t, epsNegZeroSrc, "must be an integer literal")
}

func TestRequireOutputP2PKH_NegativeZeroIndex_Rejects(t *testing.T) {
	expectIntrinsicTypeError(t, ropNegZeroSrc, "must be an integer literal")
}

// The funds-safety half of the pair: a `-0` index must never reach codegen,
// because when it does the intrinsic lowers to a bare empty-string constant
// and the covenant it was supposed to install is simply absent.
func TestNegativeZeroIndex_NeverSilentlyDropsTheCovenant(t *testing.T) {
	for _, tc := range []struct{ label, src string }{
		{"extractPrevOutputScript", epsNegZeroSrc},
		{"requireOutputP2PKH", ropNegZeroSrc},
	} {
		jsonStr, lowered := anfJSONForNegZero(t, tc.src)
		if !lowered {
			continue
		}
		t.Errorf("%s(-0, ...) compiled with NO diagnostic; covenant markers present: _prevOutScript_=%v _serialisedOutputs=%v",
			tc.label,
			strings.Contains(jsonStr, "_prevOutScript_"),
			strings.Contains(jsonStr, "_serialisedOutputs"))
	}
}

// Controls — the valid forms must keep lowering exactly as before.

func TestNegZeroControl_LiteralZeroIndexStillInstallsTheCovenant(t *testing.T) {
	eps := strings.Replace(epsNegZeroSrc, "ExtractPrevOutputScript(-0,", "ExtractPrevOutputScript(0,", 1)
	jsonStr, lowered := anfJSONForNegZero(t, eps)
	if !lowered {
		t.Fatal("valid eps contract must lower")
	}
	if !strings.Contains(jsonStr, "_prevOutScript_0") {
		t.Error("extractPrevOutputScript(0, ...) must still auto-inject its witness param")
	}

	rop := strings.Replace(ropNegZeroSrc, "RequireOutputP2PKH(-0,", "RequireOutputP2PKH(1,", 1)
	jsonStr, lowered = anfJSONForNegZero(t, rop)
	if !lowered {
		t.Fatal("valid rop contract must lower")
	}
	if !strings.Contains(jsonStr, "_serialisedOutputs") {
		t.Error("requireOutputP2PKH(1, ...) must still auto-inject _serialisedOutputs")
	}
}

func TestNegZeroControl_PlainNegativeIndexStillReportsTheBoundMessage(t *testing.T) {
	src := strings.Replace(epsNegZeroSrc, "ExtractPrevOutputScript(-0,", "ExtractPrevOutputScript(-3,", 1)
	expectIntrinsicTypeError(t, src, "must be >= 0")
}
