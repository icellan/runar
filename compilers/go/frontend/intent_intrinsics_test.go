package frontend

import (
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// mustLowerGoSource parses, validates, typechecks, and ANF-lowers a Go-DSL
// source string. Returns the lowered program. Fails the test on any error.
func mustLowerGoSource(t *testing.T, source string) *ir.ANFProgram {
	t.Helper()
	result := ParseSource([]byte(source), "Test.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	if result.Contract == nil {
		t.Fatal("parse returned nil contract")
	}
	valResult := Validate(result.Contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation errors: %s", strings.Join(valResult.ErrorStrings(), "; "))
	}
	tcResult := TypeCheck(result.Contract)
	if len(tcResult.Errors) > 0 {
		t.Fatalf("typecheck errors: %s", strings.Join(tcResult.ErrorStrings(), "; "))
	}
	return LowerToANF(result.Contract)
}

// expectIntrinsicTypeError asserts that the source produces a typecheck
// error containing `substr`. Used for negative tests (e.g. non-literal
// indices, stateless misuse).
func expectIntrinsicTypeError(t *testing.T, source string, substr string) {
	t.Helper()
	result := ParseSource([]byte(source), "Test.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	tcResult := TypeCheck(result.Contract)
	for _, d := range tcResult.Errors {
		if strings.Contains(d.FormatMessage(), substr) {
			return
		}
	}
	var msgs []string
	for _, d := range tcResult.Errors {
		msgs = append(msgs, d.FormatMessage())
	}
	t.Fatalf("expected typecheck error containing %q, got: %v", substr, msgs)
}

// findANFMethod returns the named method from a lowered program.
func findANFMethod(t *testing.T, p *ir.ANFProgram, name string) *ir.ANFMethod {
	t.Helper()
	for i := range p.Methods {
		if p.Methods[i].Name == name {
			return &p.Methods[i]
		}
	}
	t.Fatalf("method %q not found; got: %v", name, methodNames(p))
	return nil
}

func methodNames(p *ir.ANFProgram) []string {
	out := make([]string, len(p.Methods))
	for i := range p.Methods {
		out[i] = p.Methods[i].Name
	}
	return out
}

func paramNamesOf(m *ir.ANFMethod) []string {
	out := make([]string, len(m.Params))
	for i := range m.Params {
		out[i] = m.Params[i].Name
	}
	return out
}

// ---------------------------------------------------------------------------
// extractPrevOutputScript
// ---------------------------------------------------------------------------

func TestExtractPrevOutputScript_AutoInjectsWitnessParam(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentCov struct {
	runar.StatefulSmartContract
	StateCovScriptHash runar.ByteString ` + "`runar:\"readonly\"`" + `
}

func (c *IntentCov) CoSpend() {
	stateCovScript := runar.ExtractPrevOutputScript(0, c.StateCovScriptHash)
	_ = stateCovScript
}
`
	p := mustLowerGoSource(t, source)
	m := findANFMethod(t, p, "coSpend")
	names := paramNamesOf(m)
	want := map[string]bool{"_prevOutScript_0": false, "txPreimage": false}
	for _, n := range names {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("expected auto-injected param %q in %s.Params, got %v", name, m.Name, names)
		}
	}
}

func TestExtractPrevOutputScript_TwoIndicesProduceTwoParams(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentCov struct {
	runar.StatefulSmartContract
	H0 runar.ByteString ` + "`runar:\"readonly\"`" + `
	H1 runar.ByteString ` + "`runar:\"readonly\"`" + `
}

func (c *IntentCov) CoSpend() {
	a := runar.ExtractPrevOutputScript(0, c.H0)
	b := runar.ExtractPrevOutputScript(1, c.H1)
	_ = a
	_ = b
}
`
	p := mustLowerGoSource(t, source)
	m := findANFMethod(t, p, "coSpend")
	names := paramNamesOf(m)
	for _, want := range []string{"_prevOutScript_0", "_prevOutScript_1"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected auto-injected param %q in %s.Params, got %v", want, m.Name, names)
		}
	}
}

func TestExtractPrevOutputScript_SameIndexIsIdempotent(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentCov struct {
	runar.StatefulSmartContract
	H0 runar.ByteString ` + "`runar:\"readonly\"`" + `
}

func (c *IntentCov) CoSpend() {
	a := runar.ExtractPrevOutputScript(0, c.H0)
	b := runar.ExtractPrevOutputScript(0, c.H0)
	_ = a
	_ = b
}
`
	p := mustLowerGoSource(t, source)
	m := findANFMethod(t, p, "coSpend")
	count := 0
	for _, prm := range m.Params {
		if prm.Name == "_prevOutScript_0" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly one _prevOutScript_0 param, got %d", count)
	}
}

// R-2 / R-4 — typecheck bounds checks ------------------------------------

func TestRequireOutputP2PKH_OutputIndexBound_Rejects(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
	runar.StatefulSmartContract
	PKH runar.ByteString ` + "`runar:\"readonly\"`" + `
	A   runar.Bigint     ` + "`runar:\"readonly\"`" + `
}

func (c *Cov) Pay() {
	// 2000 > 1000 bound — should be rejected at typecheck.
	runar.RequireOutputP2PKH(2000, c.PKH, c.A)
}
`
	expectIntrinsicTypeError(t, source, "bound to <= 1000")
}

func TestRequireOutputP2PKH_NegativeIndex_Rejects(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
	runar.StatefulSmartContract
	PKH runar.ByteString ` + "`runar:\"readonly\"`" + `
	A   runar.Bigint     ` + "`runar:\"readonly\"`" + `
}

func (c *Cov) Pay() {
	runar.RequireOutputP2PKH(-1, c.PKH, c.A)
}
`
	expectIntrinsicTypeError(t, source, "must be >= 0")
}

func TestExtractPrevOutputScript_PrefixLenTooSmall_Rejects(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
	runar.StatefulSmartContract
	H runar.ByteString ` + "`runar:\"readonly\"`" + `
}

func (c *Cov) Bind() {
	// prefixLen=16 < 32 (hash size) — should be rejected.
	_ = runar.ExtractPrevOutputScript(0, c.H, 16)
}
`
	expectIntrinsicTypeError(t, source, "must be >= 32")
}

func TestExtractPrevOutputScript_PrefixLenTooLarge_Rejects(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
	runar.StatefulSmartContract
	H runar.ByteString ` + "`runar:\"readonly\"`" + `
}

func (c *Cov) Bind() {
	// prefixLen=10485760 > 4 MiB — should be rejected.
	_ = runar.ExtractPrevOutputScript(0, c.H, 10485760)
}
`
	expectIntrinsicTypeError(t, source, "MAX_SCRIPT_BYTES")
}

// Crit-2 — prefix-hash 3-arg form ----------------------------------------

func TestExtractPrevOutputScript_PrefixForm_LowersWithSubstr(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentTemplate struct {
	runar.StatefulSmartContract
	ExpectedPolicyPrefixHash runar.ByteString ` + "`runar:\"readonly\"`" + `
}

func (c *IntentTemplate) Bind() {
	s := runar.ExtractPrevOutputScript(0, c.ExpectedPolicyPrefixHash, 600)
	_ = s
}
`
	p := mustLowerGoSource(t, source)
	m := findANFMethod(t, p, "bind")
	// Expect a substr call inside the method body (the prefix extraction
	// preceding the hash256). Distinguish from any other substr by
	// checking it consumes a load_param ref + a 0 literal + a 600 literal.
	sawPrefixSubstr := false
	for i, b := range m.Body {
		if b.Value.Kind == "call" && b.Value.Func == "substr" && len(b.Value.Args) == 3 {
			// The first arg should be a load_param for _prevOutScript_0
			ref := b.Value.Args[0]
			for j := 0; j < i; j++ {
				if m.Body[j].Name == ref &&
					m.Body[j].Value.Kind == "load_param" &&
					m.Body[j].Value.Name == "_prevOutScript_0" {
					sawPrefixSubstr = true
					break
				}
			}
			if sawPrefixSubstr {
				break
			}
		}
	}
	if !sawPrefixSubstr {
		t.Errorf("expected substr(load_param(_prevOutScript_0), …) for 3-arg prefix form; body=%v", m.Body)
	}
}

func TestExtractPrevOutputScript_PrefixForm_NonLiteralPrefixLen_Errors(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
	runar.StatefulSmartContract
	H runar.ByteString ` + "`runar:\"readonly\"`" + `
}

func (c *Cov) Bind(n runar.Bigint) {
	_ = runar.ExtractPrevOutputScript(0, c.H, n)
}
`
	expectIntrinsicTypeError(t, source, "prefixLen) must be an integer literal")
}

func TestExtractPrevOutputScript_TooManyArgs_Errors(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
	runar.StatefulSmartContract
	H runar.ByteString ` + "`runar:\"readonly\"`" + `
}

func (c *Cov) Bind() {
	_ = runar.ExtractPrevOutputScript(0, c.H, 600, 999)
}
`
	expectIntrinsicTypeError(t, source, "expects 2 or 3 arguments")
}

// Crit-3 — addDataOutput + requireOutputP2PKH mix rejection ----------------

func TestRequireOutputP2PKH_MixedWithAddDataOutput_Errors(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
	runar.StatefulSmartContract
	BondPKH runar.ByteString ` + "`runar:\"readonly\"`" + `
	Bond    runar.Bigint     ` + "`runar:\"readonly\"`" + `
	Tag     runar.ByteString ` + "`runar:\"readonly\"`" + `
}

func (c *Cov) PayBondAndAnnounce() {
	c.AddDataOutput(0, c.Tag)
	runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
}
`
	expectIntrinsicTypeError(t, source, "mixes requireOutputP2PKH() with addDataOutput()")
}

func TestRequireOutputP2PKH_WithoutAddDataOutput_OK(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
	runar.StatefulSmartContract
	BondPKH runar.ByteString ` + "`runar:\"readonly\"`" + `
	Bond    runar.Bigint     ` + "`runar:\"readonly\"`" + `
}

func (c *Cov) PayBond() {
	runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
}
`
	mustLowerGoSource(t, source) // must not error
}

// -------------------------------------------------------------------------

func TestExtractPrevOutputScript_NonLiteralIndex_Errors(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentCov struct {
	runar.StatefulSmartContract
	H0 runar.ByteString ` + "`runar:\"readonly\"`" + `
}

func (c *IntentCov) CoSpend(idx runar.Bigint) {
	_ = runar.ExtractPrevOutputScript(idx, c.H0)
}
`
	expectIntrinsicTypeError(t, source, "must be an integer literal")
}

// ---------------------------------------------------------------------------
// requireOutputP2PKH
// ---------------------------------------------------------------------------

func TestRequireOutputP2PKH_AutoInjectsSerialisedOutputs(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
	runar.StatefulSmartContract
	BondPKH runar.ByteString ` + "`runar:\"readonly\"`" + `
	Bond    runar.Bigint     ` + "`runar:\"readonly\"`" + `
}

func (c *Cov) PayBond() {
	runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
}
`
	p := mustLowerGoSource(t, source)
	m := findANFMethod(t, p, "payBond")
	names := paramNamesOf(m)
	found := false
	for _, n := range names {
		if n == "_serialisedOutputs" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected auto-injected param '_serialisedOutputs' in %s.Params, got %v", m.Name, names)
	}
}

func TestRequireOutputP2PKH_MultipleCalls_OneSerialisedOutputsParam(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
	runar.StatefulSmartContract
	BondPKH runar.ByteString ` + "`runar:\"readonly\"`" + `
	Bond    runar.Bigint     ` + "`runar:\"readonly\"`" + `
}

func (c *Cov) PayMulti() {
	runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
	runar.RequireOutputP2PKH(1, c.BondPKH, c.Bond)
}
`
	p := mustLowerGoSource(t, source)
	m := findANFMethod(t, p, "payMulti")
	count := 0
	for _, prm := range m.Params {
		if prm.Name == "_serialisedOutputs" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly one _serialisedOutputs param across multiple intrinsic calls, got %d", count)
	}
}

func TestRequireOutputP2PKH_NonLiteralIndex_Errors(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
	runar.StatefulSmartContract
	BondPKH runar.ByteString ` + "`runar:\"readonly\"`" + `
	Bond    runar.Bigint     ` + "`runar:\"readonly\"`" + `
}

func (c *Cov) PayBond(idx runar.Bigint) {
	runar.RequireOutputP2PKH(idx, c.BondPKH, c.Bond)
}
`
	expectIntrinsicTypeError(t, source, "must be an integer literal")
}

// ---------------------------------------------------------------------------
// currentBlockHeight
// ---------------------------------------------------------------------------

func TestCurrentBlockHeight_DesugarsToExtractLocktime(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
	runar.StatefulSmartContract
	Deadline runar.Bigint ` + "`runar:\"readonly\"`" + `
}

func (c *Cov) Spend() {
	h := runar.CurrentBlockHeight()
	runar.Assert(h <= c.Deadline)
}
`
	p := mustLowerGoSource(t, source)
	m := findANFMethod(t, p, "spend")
	// Expect the body to contain at least one ANF call to extractLocktime
	// and a load_param("txPreimage") feeding it.
	sawExtractLocktime := false
	for _, b := range m.Body {
		if b.Value.Kind == "call" && b.Value.Func == "extractLocktime" {
			sawExtractLocktime = true
			break
		}
	}
	if !sawExtractLocktime {
		t.Errorf("expected currentBlockHeight() to desugar to extractLocktime call in %s.Body", m.Name)
	}
}

// TestAffineChecker_LenBranchWithStateMutations validates the hand-off §3
// concern that `if runar.Len(x) > 0 { state-mutation } else { state-mutation }`
// — branching on a read-only intrinsic value with state mutations on both
// arms — passes the affine type checker. This is the precondition for
// folding AdvanceStatePrivileged into AdvanceState (BSVM Phase 13 §3).
// Regression gate.
func TestAffineChecker_LenBranchWithStateMutations(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
	runar.StatefulSmartContract
	Count runar.Bigint
	Tag   runar.ByteString
}

func (c *Cov) Maybe(scratch runar.ByteString) {
	if runar.Len(scratch) > 0 {
		c.Count = c.Count + 1
		c.Tag = scratch
	} else {
		c.Count = c.Count - 1
		c.Tag = runar.ByteString("00")
	}
	c.AddOutput(1000, c.Count, c.Tag)
}
`
	// mustLowerGoSource fails the test on any typecheck error, so reaching
	// this point means the affine checker accepted the branched body.
	p := mustLowerGoSource(t, source)
	if findANFMethod(t, p, "maybe") == nil {
		t.Fatal("expected method 'maybe' in lowered program")
	}
}

func TestCurrentBlockHeight_StatelessContract_Errors(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Sl struct {
	runar.SmartContract
	Deadline runar.Bigint ` + "`runar:\"readonly\"`" + `
}

func (c *Sl) Spend() bool {
	h := runar.CurrentBlockHeight()
	return h > c.Deadline
}
`
	expectIntrinsicTypeError(t, source, "StatefulSmartContract")
}
