package compiler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/frontend"
	"github.com/icellan/runar/compilers/go/ir"
)

// D25 — the contract-level continuation binding (frontend/continuation_binding.go):
// classification, the SINGLE default, the hidden spent-outpoint field, the
// diagnostics, and the --ir check. Port of
// packages/runar-compiler/src/__tests__/d25-continuation-binding.test.ts. The
// executed twin-input theft lives in conformance/d25_twin_input_test.go.

const d25Stateful = `import { StatefulSmartContract, assert, checkSig, extractAmount, extractOutputHash, hash256 } from 'runar-lang';
import type { PubKey, Sig, Sha256 } from 'runar-lang';
`

func d25Counter(incDirective, decDirective string) string {
	return d25Stateful + `
class Counter extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  ` + incDirective + `
  public increment() { this.count++; }
  ` + decDirective + `
  public decrement() { assert(this.count > 0n); this.count--; }
}`
}

const d25Mixed = d25Stateful + `
class MixedPot extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count++; }
  public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }
}`

func d25Compile(src, name string) *CompileResult {
	return CompileFromSourceStrWithResult(src, name+".runar.ts")
}

func d25OK(t *testing.T, src, name string) *CompileResult {
	t.Helper()
	r := d25Compile(src, name)
	if !r.Success || r.Artifact == nil {
		var msgs []string
		for _, d := range r.Diagnostics {
			msgs = append(msgs, d.Message)
		}
		t.Fatalf("%s must compile: %s", name, strings.Join(msgs, "; "))
	}
	return r
}

func d25AbiMode(t *testing.T, r *CompileResult, method string) *int {
	t.Helper()
	for _, m := range r.Artifact.ABI.Methods {
		if m.Name == method {
			return m.SigHashType
		}
	}
	t.Fatalf("no ABI method %s", method)
	return nil
}

func d25WantMode(t *testing.T, r *CompileResult, method string, want int) {
	t.Helper()
	got := d25AbiMode(t, r, method)
	if got == nil || *got != want {
		t.Fatalf("%s sigHashType: got %v, want 0x%x", method, got, want)
	}
}

func d25WantNoMode(t *testing.T, r *CompileResult, method string) {
	t.Helper()
	if got := d25AbiMode(t, r, method); got != nil {
		t.Fatalf("%s sigHashType: got 0x%x, want none", method, *got)
	}
}

func d25StateNames(r *CompileResult) []string {
	var out []string
	for _, f := range r.Artifact.StateFields {
		out = append(out, f.Name)
	}
	return out
}

func d25Walk(bs []ir.ANFBinding, f func(b *ir.ANFBinding)) {
	for i := range bs {
		f(&bs[i])
		v := &bs[i].Value
		for _, n := range [][]ir.ANFBinding{v.Then, v.Else, v.Body} {
			d25Walk(n, f)
		}
	}
}

func d25HasDiag(r *CompileResult, sev frontend.Severity, substr string) bool {
	for _, d := range r.Diagnostics {
		if d.Severity == sev && strings.Contains(d.Message, substr) {
			return true
		}
	}
	return false
}

// ---- class 1 ---------------------------------------------------------------

func TestD25_Class1_DefaultsToSingleAndDropsChangeParams(t *testing.T) {
	r := d25OK(t, d25Counter("", ""), "Counter")
	d25WantMode(t, r, "increment", 0x43)
	d25WantMode(t, r, "decrement", 0x43)
	if got := strings.Join(d25StateNames(r), ","); got != "count" {
		t.Fatalf("state fields: %s", got)
	}
	for _, m := range r.Artifact.ABI.Methods {
		var names []string
		for _, p := range m.Params {
			names = append(names, p.Name)
		}
		if strings.Join(names, ",") != "_newAmount,txPreimage" {
			t.Fatalf("%s params: %v", m.Name, names)
		}
	}
}

func TestD25_Class1_AllAcpBecomesSingleAcp(t *testing.T) {
	d := "/** @sighash ALL|ANYONECANPAY|FORKID */"
	d25WantMode(t, d25OK(t, d25Counter(d, d), "Counter"), "increment", 0xc3)
}

func TestD25_Class1_KeepsExplicitSingleAcp(t *testing.T) {
	d := "/** @sighash SINGLE|ANYONECANPAY|FORKID */"
	d25WantMode(t, d25OK(t, d25Counter(d, ""), "Counter"), "increment", 0xc3)
}

func TestD25_Class1_RefusesExplicitAllSibling(t *testing.T) {
	r := d25Compile(d25Counter("", "/** @sighash ALL|FORKID */"), "Counter")
	if r.Success {
		t.Fatal("an explicit ALL|FORKID sibling must be refused")
	}
	if !d25HasDiag(r, frontend.SeverityError, "method 'decrement': @sighash ALL|FORKID") {
		t.Fatalf("missing D25 error; got %v", r.Diagnostics)
	}
	if !d25HasDiag(r, frontend.SeverityError, frontend.ExplicitAllSiblingMessage("decrement")) {
		t.Fatalf("diagnostic text differs from the shared message; got %v", r.Diagnostics)
	}
}

func TestD25_Class1_TerminalMethodKeepsAll(t *testing.T) {
	src := d25Stateful + `
class Box extends StatefulSmartContract {
  count: bigint;
  readonly owner: PubKey;
  constructor(count: bigint, owner: PubKey) { super(count, owner); this.count = count; this.owner = owner; }
  public bump() { this.count++; }
  public close(sig: Sig) { assert(checkSig(sig, this.owner)); }
}`
	r := d25OK(t, src, "Box")
	d25WantMode(t, r, "bump", 0x43)
	d25WantNoMode(t, r, "close")
}

// ---- class 2 ---------------------------------------------------------------

func TestD25_Class2_AppendsZeroSha256FieldLast(t *testing.T) {
	r := d25OK(t, d25Mixed, "MixedPot")
	if got := strings.Join(d25StateNames(r), ","); got != "count,"+frontend.TwinBindingField {
		t.Fatalf("state fields: %s", got)
	}
	var ctor []string
	for _, p := range r.Artifact.ABI.Constructor.Params {
		ctor = append(ctor, p.Name)
	}
	if strings.Join(ctor, ",") != "count" {
		t.Fatalf("constructor params: %v", ctor)
	}
	var prop *ir.ANFProperty
	for i := range r.ANF.Properties {
		if r.ANF.Properties[i].Name == frontend.TwinBindingField {
			prop = &r.ANF.Properties[i]
		}
	}
	if prop == nil || prop.Type != "Sha256" || prop.InitialValue != strings.Repeat("00", 32) {
		t.Fatalf("binding property: %+v", prop)
	}
	d25WantNoMode(t, r, "increment")
	d25WantNoMode(t, r, "bump")
}

func TestD25_Class2_WritesAndAppendsTheBinding(t *testing.T) {
	r := d25OK(t, d25Mixed, "MixedPot")
	var inc, bump *ir.ANFMethod
	for i := range r.ANF.Methods {
		switch r.ANF.Methods[i].Name {
		case "increment":
			inc = &r.ANF.Methods[i]
		case "bump":
			bump = &r.ANF.Methods[i]
		}
	}
	wrote := false
	d25Walk(inc.Body, func(b *ir.ANFBinding) {
		if b.Value.Kind == "update_prop" && b.Value.Name == frontend.TwinBindingField {
			wrote = true
		}
	})
	if !wrote {
		t.Fatal("increment must write the binding field")
	}
	var outs []*ir.ANFBinding
	d25Walk(bump.Body, func(b *ir.ANFBinding) {
		if b.Value.Kind == "add_output" {
			outs = append(outs, b)
		}
	})
	if len(outs) != 1 || len(outs[0].Value.StateValues) != 2 {
		t.Fatalf("bump add_output: %d outputs", len(outs))
	}
}

func TestD25_Class2_MutateOnlyReadingOutputHashIsBound(t *testing.T) {
	src := d25Stateful + `
class Peek extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public bump(h: Sha256) { assert(extractOutputHash(this.txPreimage) !== h); this.count++; }
}`
	r := d25OK(t, src, "Peek")
	d25WantNoMode(t, r, "bump")
	if got := strings.Join(d25StateNames(r), ","); got != "count,"+frontend.TwinBindingField {
		t.Fatalf("state fields: %s", got)
	}
}

func TestD25_Class2_FieldNameIsReserved(t *testing.T) {
	src := d25Stateful + `
class X extends StatefulSmartContract {
  _spentOutpointHash: bigint;
  constructor(_spentOutpointHash: bigint) { super(_spentOutpointHash); this._spentOutpointHash = _spentOutpointHash; }
  public bump() { this._spentOutpointHash++; }
}`
	r := d25Compile(src, "X")
	if r.Success {
		t.Fatal("must not compile")
	}
	if !d25HasDiag(r, frontend.SeverityError, "'_spentOutpointHash' is reserved") {
		t.Fatalf("missing reserved-name diagnostic: %v", r.Diagnostics)
	}
}

// ---- class 3 ---------------------------------------------------------------

func d25Pot(body string) string {
	return d25Stateful + `
class Pot extends StatefulSmartContract {
  count: bigint;
  readonly owner: PubKey;
  constructor(count: bigint, owner: PubKey) { super(count, owner); this.count = count; this.owner = owner; }
  public bump(sig: Sig) { ` + body + ` }
}`
}

func d25CountWarn(r *CompileResult) int {
	n := 0
	for _, d := range r.Diagnostics {
		if d.Severity == frontend.SeverityWarning && strings.Contains(d.Message, "twin-input aliasing") {
			n++
		}
	}
	return n
}

func TestD25_Class3_WarnsOnUnsignedValueConservingAddOutput(t *testing.T) {
	r := d25OK(t, d25Pot("this.addOutput(extractAmount(this.txPreimage), this.count + 1n);"), "Pot")
	if n := d25CountWarn(r); n != 1 {
		t.Fatalf("want 1 twin-input aliasing warning, got %d (%v)", n, r.Diagnostics)
	}
	if !d25HasDiag(r, frontend.SeverityWarning, frontend.UnsignedAddOutputMessage("bump")) {
		t.Fatalf("warning text differs from the shared message")
	}
	if got := strings.Join(d25StateNames(r), ","); got != "count" {
		t.Fatalf("state fields: %s", got)
	}
	d25WantNoMode(t, r, "bump")
}

func TestD25_Class3_FollowsLocalFromExtractAmount(t *testing.T) {
	r := d25OK(t, d25Pot("const v: bigint = extractAmount(this.txPreimage); this.addOutput(v, this.count + 1n);"), "Pot")
	if d25CountWarn(r) == 0 {
		t.Fatal("want a twin-input aliasing warning")
	}
}

func TestD25_Class3_NoWarningWhenSigned(t *testing.T) {
	r := d25OK(t, d25Pot("assert(checkSig(sig, this.owner)); this.addOutput(extractAmount(this.txPreimage), this.count + 1n);"), "Pot")
	if d25CountWarn(r) != 0 {
		t.Fatal("a signed method must not be warned about")
	}
}

// ---- --ir --------------------------------------------------------------------

// d25AnfOf compiles and returns a deep copy of the frontend ANF (via JSON, the
// --ir wire format).
func d25AnfJSON(t *testing.T, src, name string) []byte {
	t.Helper()
	r := d25OK(t, src, name)
	raw, err := json.Marshal(r.ANF)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func d25Load(t *testing.T, raw []byte) *ir.ANFProgram {
	t.Helper()
	p, err := ir.LoadIRFromBytes(raw)
	if err != nil {
		t.Fatalf("load IR: %v", err)
	}
	return p
}

func d25CompileProgram(p *ir.ANFProgram) error {
	_, err := CompileFromProgram(p, CompileOptions{DisableConstantFolding: true})
	return err
}

func TestD25_IR_AcceptsFrontendIROfEveryClass(t *testing.T) {
	for _, c := range []struct{ src, name string }{{d25Counter("", ""), "Counter"}, {d25Mixed, "MixedPot"}} {
		if _, err := CompileFromIRBytes(d25AnfJSON(t, c.src, c.name)); err != nil {
			t.Fatalf("%s frontend IR must compile: %v", c.name, err)
		}
	}
}

func TestD25_IR_RefusesMutateOnlyUnderAll(t *testing.T) {
	p := d25Load(t, d25AnfJSON(t, d25Counter("", ""), "Counter"))
	for i := range p.Methods {
		if p.Methods[i].Name == "decrement" {
			p.Methods[i].SigHashType = nil
		}
	}
	err := d25CompileProgram(p)
	if err == nil || !strings.Contains(err.Error(), "IR validation") {
		t.Fatalf("want an IR validation refusal, got %v", err)
	}
}

func TestD25_IR_RefusesMixedWithoutTheField(t *testing.T) {
	p := d25Load(t, d25AnfJSON(t, d25Mixed, "MixedPot"))
	var props []ir.ANFProperty
	for _, x := range p.Properties {
		if x.Name != frontend.TwinBindingField {
			props = append(props, x)
		}
	}
	p.Properties = props
	for mi := range p.Methods {
		m := &p.Methods[mi]
		drop := map[string]bool{}
		var roots []string
		d25Walk(m.Body, func(b *ir.ANFBinding) {
			if b.Value.Kind == "update_prop" && b.Value.Name == frontend.TwinBindingField {
				drop[b.Name] = true
				roots = append(roots, b.Value.ValueRef)
			}
			if b.Value.Kind == "add_output" {
				sv := b.Value.StateValues
				roots = append(roots, sv[len(sv)-1])
				b.Value.StateValues = sv[:len(sv)-1]
			}
		})
		byName := map[string]*ir.ANFValue{}
		d25Walk(m.Body, func(b *ir.ANFBinding) { byName[b.Name] = &b.Value })
		for _, h := range roots {
			sha := byName[h]
			eo := byName[sha.Args[0]]
			drop[h], drop[sha.Args[0]], drop[eo.Args[0]] = true, true, true
		}
		var body []ir.ANFBinding
		for _, b := range m.Body {
			if !drop[b.Name] {
				body = append(body, b)
			}
		}
		m.Body = body
	}
	err := d25CompileProgram(p)
	if err == nil || !strings.Contains(err.Error(), "not bound to its input") {
		t.Fatalf("want the D25 refusal, got %v", err)
	}
}

func TestD25_IR_RefusesAddOutputWithoutOutpointHash(t *testing.T) {
	p := d25Load(t, d25AnfJSON(t, d25Mixed, "MixedPot"))
	for mi := range p.Methods {
		if p.Methods[mi].Name != "bump" {
			continue
		}
		d25Walk(p.Methods[mi].Body, func(b *ir.ANFBinding) {
			if b.Value.Kind == "add_output" {
				b.Value.StateValues[1] = b.Value.StateValues[0]
			}
		})
	}
	err := d25CompileProgram(p)
	if err == nil || !strings.Contains(err.Error(), "every add_output must carry") {
		t.Fatalf("want the add_output refusal, got %v", err)
	}
}
