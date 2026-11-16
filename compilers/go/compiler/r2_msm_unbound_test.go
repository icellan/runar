package compiler

// R2-MSM-UNBOUND: a --source / --ir method that opens with
// assertGroth16WitnessAssistedWithMSM() and binds no public input compiled.
// The MSM preamble ties the prover-supplied prepared_inputs to the five
// witness scalars, but those scalars are the spender's choice: with no pin in
// the vk.json and no assertion on groth16PublicInput(i) in the body, the
// script accepts an honest proof of ANY statement (the GK-BUG-006 class, one
// level up). The standalone CompileGroth16WA already refused this via
// validateGroth16PublicInputs; the contract path did not.
//
// User decision: compile error unless the statement is bound by
//   - at least one slot pinned with pinnedPublicInputs in the vk.json, or
//   - a TOP-LEVEL statement of that method of the exact form
//     assert(groth16PublicInput(<0..4 literal>) == <fixed>) (either operand
//     order), where <fixed> is built only from literals, readonly contract
//     properties, operators and built-in calls over those: no method
//     parameter, no local, no mutable property, no other groth16PublicInput.
// `!=`, `<`, a check inside an if / loop, a conjunct of && and a private
// helper do not count (fail closed).
//
// Proves: the frontend (typecheck: --source, CompileSourceToIR and so
// runar.CompileCheck) and stack lowering (--ir) both refuse each unbound
// shape with the shared diagnostic; a pinned vk.json, a property-bound and a
// literal-bound body compile on both paths with folding on and off; the three
// integration contracts still compile (RollupGroth16WA only with a pinned
// vk.json, which is how its regtest test deploys it).
// Does not prove: anything about the runtime verifier (see the GK-BUG-005 /
// GK-GAP-009 execution tests and groth16_wa_binding_test.go).

import (
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/frontend"
	"github.com/icellan/runar/compilers/go/ir"
)

const r2MSMUnboundMsg = "does not bind the proved statement"

func r2MSMWriteContract(t *testing.T, name, body string) string {
	t.Helper()
	source := `
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type ` + name + ` struct {
	runar.SmartContract

	Pinned runar.Bigint ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *` + name + `) Verify(x runar.Bigint) {
	runar.AssertGroth16WitnessAssistedWithMSM()
` + body + `
}
`
	p := filepath.Join(t.TempDir(), name+".runar.go")
	if err := os.WriteFile(p, []byte(source), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	return p
}

func r2MSMRequireUnbound(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("R2-MSM-UNBOUND: %s compiled; nothing binds the proved statement", what)
	}
	if !strings.Contains(err.Error(), r2MSMUnboundMsg) || !strings.Contains(err.Error(), "'verify'") {
		t.Fatalf("%s: want the unbound-statement diagnostic naming method 'verify'; got: %v", what, err)
	}
}

// Bodies that bind nothing. Each follows the marker.
var r2MSMUnboundBodies = map[string]string{
	"marker_only":    "\trunar.Assert(x == 1)",
	"param_compared": "\trunar.Assert(runar.Groth16PublicInput(0) == x)",
	"self_compared":  "\trunar.Assert(runar.Groth16PublicInput(0) == runar.Groth16PublicInput(1))",
	"not_equal":      "\trunar.Assert(runar.Groth16PublicInput(0) != c.Pinned)",
	"less_than":      "\trunar.Assert(runar.Groth16PublicInput(0) < c.Pinned)",
	"inside_if":      "\tif x > 0 {\n\t\trunar.Assert(runar.Groth16PublicInput(0) == c.Pinned)\n\t}\n\trunar.Assert(x == 1)",
	"param_in_expr":  "\trunar.Assert(runar.Groth16PublicInput(0) == c.Pinned+x)",
	"conjunct":       "\trunar.Assert(x == 1 && runar.Groth16PublicInput(0) == c.Pinned)",
}

// Bodies that bind a public input. Each follows the marker.
var r2MSMBoundBodies = map[string]string{
	"property":         "\trunar.Assert(runar.Groth16PublicInput(0) == c.Pinned)",
	"property_flipped": "\trunar.Assert(c.Pinned == runar.Groth16PublicInput(3))",
	"literal":          "\trunar.Assert(runar.Groth16PublicInput(2) == 0)\n\trunar.Assert(x == 1)",
	"property_expr":    "\trunar.Assert(runar.Groth16PublicInput(1) == c.Pinned*2+1)",
}

func TestR2MSMUnbound_RefusedBySource(t *testing.T) {
	vkPath := sp1VKPath(t) // real SP1 v6 key, no pinnedPublicInputs
	for name, body := range r2MSMUnboundBodies {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			_, err := CompileFromSource(r2MSMWriteContract(t, "Unbound", body), CompileOptions{Groth16WAVKey: vkPath})
			r2MSMRequireUnbound(t, err, "--source "+name)
		})
	}
}

// TestR2MSMUnbound_RefusedByFrontend: CompileSourceToIR runs only parse /
// validate / typecheck (runar.CompileCheck runs the same three), so only the
// typecheck rule can refuse here. With no vk.json nothing is pinned.
func TestR2MSMUnbound_RefusedByFrontend(t *testing.T) {
	for name, body := range r2MSMUnboundBodies {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			_, err := CompileSourceToIR(r2MSMWriteContract(t, "UnboundFE", body))
			r2MSMRequireUnbound(t, err, "frontend "+name)
		})
	}
}

// TestR2MSMUnbound_TypeCheckOptions pins the frontend switch directly: the
// same unbound contract is refused by TypeCheck and accepted by
// TypeCheckWithOptions when the caller's vk.json pins a slot.
func TestR2MSMUnbound_TypeCheckOptions(t *testing.T) {
	path := r2MSMWriteContract(t, "UnboundTC", r2MSMUnboundBodies["marker_only"])
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parse := func() *frontend.ContractNode {
		r := frontend.ParseSource(src, path)
		if len(r.Errors) > 0 || r.Contract == nil {
			t.Fatalf("parse: %v", r.Errors)
		}
		return r.Contract
	}
	tc := frontend.TypeCheck(parse())
	if len(tc.Errors) == 0 || !strings.Contains(strings.Join(tc.ErrorStrings(), "\n"), r2MSMUnboundMsg) {
		t.Fatalf("TypeCheck must refuse the unbound method; got %v", tc.ErrorStrings())
	}
	tc = frontend.TypeCheckWithOptions(parse(), frontend.TypeCheckOptions{Groth16WAStatementPinned: true})
	if len(tc.Errors) != 0 {
		t.Fatalf("TypeCheckWithOptions(pinned) must accept the marker-only body; got %v", tc.ErrorStrings())
	}
}

// TestR2MSMUnbound_RefusedByIR covers the --ir path, which never runs the
// frontend: the ANF of an unbound body (lowered under a pinned vk.json, which
// the frontend accepts) is compiled with an unpinned one, and the ANF of a
// bound body has its property operand swapped for a method parameter.
func TestR2MSMUnbound_RefusedByIR(t *testing.T) {
	vkPath := sp1VKPath(t)
	pinnedVK := writePinnedVK(t, vkPath, map[int]*big.Int{2: big.NewInt(0)})

	t.Run("unbound_body_from_pinned_frontend", func(t *testing.T) {
		prog, err := CompileSourceToIR(r2MSMWriteContract(t, "IRUnbound", r2MSMUnboundBodies["marker_only"]),
			CompileOptions{Groth16WAVKey: pinnedVK})
		if err != nil {
			t.Fatalf("CompileSourceToIR (pinned vk): %v", err)
		}
		if _, err := CompileFromProgram(prog, CompileOptions{Groth16WAVKey: pinnedVK}); err != nil {
			t.Fatalf("control: the same IR must compile with the pinned vk.json: %v", err)
		}
		_, err = CompileFromProgram(prog, CompileOptions{Groth16WAVKey: vkPath})
		r2MSMRequireUnbound(t, err, "--ir marker-only body with an unpinned vk.json")
	})

	t.Run("property_swapped_for_param", func(t *testing.T) {
		prog, err := CompileSourceToIR(r2MSMWriteContract(t, "IRSwap", r2MSMBoundBodies["property"]))
		if err != nil {
			t.Fatalf("CompileSourceToIR: %v", err)
		}
		if _, err := CompileFromProgram(prog, CompileOptions{Groth16WAVKey: vkPath}); err != nil {
			t.Fatalf("control: the bound IR must compile: %v", err)
		}
		swapped := false
		for mi := range prog.Methods {
			for bi, b := range prog.Methods[mi].Body {
				if b.Value.Kind == "load_prop" && b.Value.Name == "pinned" {
					prog.Methods[mi].Body[bi].Value = ir.ANFValue{Kind: "load_param", Name: "x"}
					swapped = true
				}
			}
		}
		if !swapped {
			t.Fatal("premise: no load_prop pinned binding in the lowered program")
		}
		_, err = CompileFromProgram(prog, CompileOptions{Groth16WAVKey: vkPath})
		r2MSMRequireUnbound(t, err, "--ir body comparing groth16PublicInput(0) with a parameter")
	})

	t.Run("equality_turned_into_inequality", func(t *testing.T) {
		prog, err := CompileSourceToIR(r2MSMWriteContract(t, "IRNeq", r2MSMBoundBodies["property"]))
		if err != nil {
			t.Fatalf("CompileSourceToIR: %v", err)
		}
		flipped := false
		for mi := range prog.Methods {
			for bi, b := range prog.Methods[mi].Body {
				if b.Value.Kind == "bin_op" && b.Value.Op == "===" {
					prog.Methods[mi].Body[bi].Value.Op = "!=="
					flipped = true
				}
			}
		}
		if !flipped {
			t.Fatal("premise: no === bin_op in the lowered program")
		}
		_, err = CompileFromProgram(prog, CompileOptions{Groth16WAVKey: vkPath})
		r2MSMRequireUnbound(t, err, "--ir body asserting groth16PublicInput(0) !== pinned")
	})
}

// TestR2MSMUnbound_BoundCompiles: every accepted shape compiles from source
// and through an --emit-ir / --ir round trip, folding on and off.
func TestR2MSMUnbound_BoundCompiles(t *testing.T) {
	vkPath := sp1VKPath(t)
	pinnedVK := writePinnedVK(t, vkPath, map[int]*big.Int{2: big.NewInt(0)})
	type tc struct {
		body string
		vk   string
	}
	cases := map[string]tc{"pinned_vk_marker_only": {r2MSMUnboundBodies["marker_only"], pinnedVK}}
	for name, body := range r2MSMBoundBodies {
		cases[name] = tc{body, vkPath}
	}
	for name, c := range cases {
		name, c := name, c
		for _, fold := range []bool{true, false} {
			fold := fold
			mode := "fold_on"
			if !fold {
				mode = "fold_off"
			}
			t.Run(name+"/"+mode, func(t *testing.T) {
				opts := CompileOptions{Groth16WAVKey: c.vk, DisableConstantFolding: !fold}
				src := r2MSMWriteContract(t, "Bound", c.body)
				if _, err := CompileFromSource(src, opts); err != nil {
					t.Fatalf("--source: %v", err)
				}
				prog, err := CompileSourceToIR(src, opts)
				if err != nil {
					t.Fatalf("--emit-ir: %v", err)
				}
				if _, err := CompileFromProgram(prog, opts); err != nil {
					t.Fatalf("--ir: %v", err)
				}
			})
		}
	}
}

// TestR2MSMUnbound_IntegrationContractsCompile: the three Mode-3 integration
// contracts. RollupGroth16WA binds through the vk.json only, so it compiles
// with a pinned key and is refused with the bare SP1 key.
func TestR2MSMUnbound_IntegrationContractsCompile(t *testing.T) {
	vkPath := sp1VKPath(t)
	pinnedVK := writePinnedVK(t, vkPath, map[int]*big.Int{0: big.NewInt(7), 2: big.NewInt(0), 3: big.NewInt(9)})
	contract := func(name string) string {
		abs, err := filepath.Abs(filepath.Join("..", "..", "..", "integration", "go", "contracts", name+".runar.go"))
		if err != nil {
			t.Fatal(err)
		}
		return abs
	}
	for _, c := range []struct{ name, vk string }{
		{"StatelessGroth16WA", vkPath},
		{"RollupGroth16WAMSM", vkPath},
		{"RollupGroth16WA", pinnedVK},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if _, err := CompileFromSource(contract(c.name), CompileOptions{Groth16WAVKey: c.vk}); err != nil {
				t.Fatalf("%s must still compile: %v", c.name, err)
			}
		})
	}
	t.Run("RollupGroth16WA_unpinned_refused", func(t *testing.T) {
		_, err := CompileFromSource(contract("RollupGroth16WA"), CompileOptions{Groth16WAVKey: vkPath})
		if err == nil || !strings.Contains(err.Error(), r2MSMUnboundMsg) || !strings.Contains(err.Error(), "'advanceState'") {
			t.Fatalf("RollupGroth16WA with an unpinned vk.json must be refused as unbound; got: %v", err)
		}
	})
}

// r2MSMWriteStateful is a stateful contract with one readonly and one
// mutable property, for the mutable-property shapes below.
func r2MSMWriteStateful(t *testing.T, name, body string) string {
	t.Helper()
	source := `
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type ` + name + ` struct {
	runar.StatefulSmartContract

	Pinned  runar.Bigint ` + "`" + `runar:"readonly"` + "`" + `
	Counter runar.Bigint
}

func (c *` + name + `) Advance(x runar.Bigint) {
	runar.AssertGroth16WitnessAssistedWithMSM()
` + body + `
}
`
	p := filepath.Join(t.TempDir(), name+".runar.go")
	if err := os.WriteFile(p, []byte(source), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	return p
}

// TestR2MSMUnbound_MutablePropertyIsNotFixed: a mutable property is not a
// fixed value. `c.Counter = x` followed by an assert against c.Counter lets
// the spender pick x = pub_0, so it binds nothing; only readonly properties
// count (fail closed: a mutable state read is refused even unassigned).
func TestR2MSMUnbound_MutablePropertyIsNotFixed(t *testing.T) {
	vkPath := sp1VKPath(t)
	requireAdvance := func(t *testing.T, err error, what string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), r2MSMUnboundMsg) || !strings.Contains(err.Error(), "'advance'") {
			t.Fatalf("%s: want the unbound-statement diagnostic naming 'advance'; got: %v", what, err)
		}
	}
	bodies := map[string]string{
		"assigned_from_param": "\tc.Counter = x\n\trunar.Assert(runar.Groth16PublicInput(0) == c.Counter)",
		"mutable_state_read":  "\trunar.Assert(runar.Groth16PublicInput(0) == c.Counter)\n\tc.Counter = x",
	}
	for name, body := range bodies {
		name, body := name, body
		t.Run("source/"+name, func(t *testing.T) {
			_, err := CompileFromSource(r2MSMWriteStateful(t, "Mut", body), CompileOptions{Groth16WAVKey: vkPath})
			requireAdvance(t, err, "--source "+name)
		})
	}
	t.Run("readonly_control_compiles", func(t *testing.T) {
		src := r2MSMWriteStateful(t, "MutCtl", "\trunar.Assert(runar.Groth16PublicInput(0) == c.Pinned)\n\tc.Counter = x")
		if _, err := CompileFromSource(src, CompileOptions{Groth16WAVKey: vkPath}); err != nil {
			t.Fatalf("readonly-bound stateful method must compile: %v", err)
		}
	})
	// --ir: lower the readonly control, then retarget its load_prop to the
	// mutable property (the frontend never sees this program).
	t.Run("ir/load_prop_retargeted_to_mutable", func(t *testing.T) {
		prog, err := CompileSourceToIR(r2MSMWriteStateful(t, "MutIR", "\trunar.Assert(runar.Groth16PublicInput(0) == c.Pinned)\n\tc.Counter = x"))
		if err != nil {
			t.Fatalf("CompileSourceToIR: %v", err)
		}
		n := 0
		for mi := range prog.Methods {
			for bi, b := range prog.Methods[mi].Body {
				if b.Value.Kind == "load_prop" && b.Value.Name == "pinned" {
					prog.Methods[mi].Body[bi].Value.Name = "counter"
					n++
				}
			}
		}
		if n == 0 {
			t.Fatal("premise: no load_prop pinned in the lowered program")
		}
		_, err = CompileFromProgram(prog, CompileOptions{Groth16WAVKey: vkPath})
		requireAdvance(t, err, "--ir assert against a mutable property")
	})
	// --ir: a readonly property the IR writes. The IR validator already
	// refuses the write itself, before the binding rule is consulted.
	t.Run("ir/readonly_property_written", func(t *testing.T) {
		prog, err := CompileSourceToIR(r2MSMWriteStateful(t, "MutIRW", "\trunar.Assert(runar.Groth16PublicInput(0) == c.Pinned)\n\tc.Counter = x"))
		if err != nil {
			t.Fatalf("CompileSourceToIR: %v", err)
		}
		n := 0
		for mi := range prog.Methods {
			for bi, b := range prog.Methods[mi].Body {
				if b.Value.Kind == "update_prop" && b.Value.Name == "counter" {
					prog.Methods[mi].Body[bi].Value.Name = "pinned"
					n++
				}
			}
		}
		if n == 0 {
			t.Fatal("premise: no update_prop counter in the lowered program")
		}
		_, err = CompileFromProgram(prog, CompileOptions{Groth16WAVKey: vkPath})
		if err == nil || !strings.Contains(err.Error(), "cannot assign to readonly property 'pinned'") {
			t.Fatalf("--ir write to the readonly binding property must be refused; got: %v", err)
		}
	})
}

// TestR2MSMUnbound_PrevOutScriptIsNotFixed: extractPrevOutputScript(i, h[, n])
// reads an auto-injected unlocking parameter (_prevOutScript_<i>), the script
// of an input the spender picks. Its arguments being literals / readonly
// properties does not make its result fixed: with a prefix hash the suffix is
// free. The frontend counted it as a fixed built-in call while the ANF copy
// (which sees a load_param) refused it, so runar.CompileCheck accepted a
// method the compiler then refused (review of R2-MSM-UNBOUND).
func TestR2MSMUnbound_PrevOutScriptIsNotFixed(t *testing.T) {
	vkPath := sp1VKPath(t)
	for name, call := range map[string]string{
		"full_hash":   "extractPrevOutputScript(0, this.h)",
		"prefix_hash": "extractPrevOutputScript(0, this.h, 40n)",
	} {
		name, call := name, call
		t.Run(name, func(t *testing.T) {
			src := `import { SmartContract, assert, ByteString, groth16PublicInput, assertGroth16WitnessAssistedWithMSM, bin2num, extractPrevOutputScript } from 'runar-lang';

class PrevOut extends SmartContract {
  readonly h: ByteString;

  constructor(h: ByteString) {
    super(h);
    this.h = h;
  }

  public verify(x: bigint) {
    assertGroth16WitnessAssistedWithMSM();
    assert(groth16PublicInput(0) == bin2num(` + call + `));
    assert(x == 1n);
  }
}
`
			p := filepath.Join(t.TempDir(), "PrevOut.runar.ts")
			if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := CompileSourceToIR(p)
			r2MSMRequireUnbound(t, err, "frontend "+name)
			_, err = CompileFromSource(p, CompileOptions{Groth16WAVKey: vkPath})
			r2MSMRequireUnbound(t, err, "--source "+name)
		})
	}
}

// TestR2MSMUnbound_IRRebindingIsNotFixed: the --ir rule resolved a ref
// through the method's top-level bindings only, by name, at the assert. A
// local reassigned inside an if or loop arm, or a name re-bound at top level
// after the comparison read it, kept looking fixed, so these --ir programs
// compiled with an unpinned vk.json although the compared value is the
// parameter x (review of R2-MSM-UNBOUND). A name bound more than once in the
// method, or bound inside a nested arm, is never fixed.
func TestR2MSMUnbound_IRRebindingIsNotFixed(t *testing.T) {
	vkPath := sp1VKPath(t)
	pinnedVK := writePinnedVK(t, vkPath, map[int]*big.Int{2: big.NewInt(0)})
	for name, body := range map[string]string{
		"if_arm":   "\tv := c.Pinned\n\tif x > 0 {\n\t\tv = x\n\t}\n\trunar.Assert(runar.Groth16PublicInput(0) == v)",
		"loop_arm": "\tv := c.Pinned\n\tfor i := 0; i < 2; i++ {\n\t\tv = x\n\t}\n\trunar.Assert(runar.Groth16PublicInput(0) == v)",
	} {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			// The frontend refuses a local; lower under a pinned vk.json to
			// get the IR an --ir file would carry.
			prog, err := CompileSourceToIR(r2MSMWriteContract(t, "IRRebind", body), CompileOptions{Groth16WAVKey: pinnedVK})
			if err != nil {
				t.Fatalf("CompileSourceToIR (pinned vk): %v", err)
			}
			_, err = CompileFromProgram(prog, CompileOptions{Groth16WAVKey: vkPath})
			r2MSMRequireUnbound(t, err, "--ir "+name)
		})
	}

	// Top-level shadowing: the comparison reads N while N is a parameter;
	// N is re-bound to the readonly property afterwards, before the assert.
	t.Run("shadowed_after_compare", func(t *testing.T) {
		prog, err := CompileSourceToIR(r2MSMWriteContract(t, "IRShadow", r2MSMBoundBodies["property"]))
		if err != nil {
			t.Fatalf("CompileSourceToIR: %v", err)
		}
		done := false
		for mi := range prog.Methods {
			body := prog.Methods[mi].Body
			propIdx, assertIdx := -1, -1
			for bi, b := range body {
				if b.Value.Kind == "load_prop" && b.Value.Name == "pinned" && propIdx < 0 {
					propIdx = bi
				}
				if b.Value.Kind == "assert" && propIdx >= 0 && assertIdx < 0 {
					assertIdx = bi
				}
			}
			if propIdx < 0 || assertIdx < 0 {
				continue
			}
			n := body[propIdx].Name
			shadow := ir.ANFBinding{Name: n, Value: ir.ANFValue{Kind: "load_prop", Name: "pinned"}}
			body[propIdx].Value = ir.ANFValue{Kind: "load_param", Name: "x"}
			body = append(body[:assertIdx], append([]ir.ANFBinding{shadow}, body[assertIdx:]...)...)
			prog.Methods[mi].Body = body
			done = true
		}
		if !done {
			t.Fatal("premise: no load_prop pinned / assert pair in the lowered program")
		}
		_, err = CompileFromProgram(prog, CompileOptions{Groth16WAVKey: vkPath})
		r2MSMRequireUnbound(t, err, "--ir comparison against a parameter shadowed by a later binding")
	})
}
