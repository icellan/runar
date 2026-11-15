package compiler

// GK-BUG-006: assertGroth16WitnessAssisted (the raw witness-assisted Groth16
// marker) compiled to EmitGroth16VerifierWitnessAssisted, whose only check on
// the prover-supplied prepared_inputs point is an on-curve test. The public
// inputs never reach the script, so the verifier attests that SOME statement
// was proven, not which one: a spender picks a statement they can satisfy,
// mints an honest proof for it and spends. A method holding both markers
// silently got the raw variant, because the marker scan returned the first
// marker it met.
//
// User decision: the raw marker is a compile error in --source and --ir
// contracts (the raw emitter stays an internal/test primitive), and a method
// holding both markers is a compile error.
//
// Proves: CompileFromSource and CompileFromProgram (the --source and --ir
// back ends) refuse the raw marker with an unpinned, real SP1 vk.json, refuse
// a method that mixes the two markers in either order (top level and inside
// if / loop arms), and still compile the MSM marker.
// Does not prove: anything about the runtime verifier (see the GK-BUG-005 /
// GK-GAP-009 execution tests in compilers/go/codegen).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

func gk006WriteContract(t *testing.T, name, body string) string {
	t.Helper()
	source := `
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type ` + name + ` struct {
	runar.SmartContract
}

func (c *` + name + `) Verify() {
` + body + `
}
`
	p := filepath.Join(t.TempDir(), name+".runar.go")
	if err := os.WriteFile(p, []byte(source), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	return p
}

func gk006RequireRefusal(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("GK-BUG-006: %s compiled; the raw witness-assisted Groth16 verifier binds no public input", what)
	}
	msg := err.Error()
	// "assertGroth16WitnessAssisted()" with the parens: the bare prefix would
	// also match the WithMSM name the message must point at.
	if !strings.Contains(msg, "assertGroth16WitnessAssisted()") || !strings.Contains(msg, "assertGroth16WitnessAssistedWithMSM") {
		t.Fatalf("%s: refusal must name the raw marker and point at assertGroth16WitnessAssistedWithMSM; got: %v", what, err)
	}
}

func TestGKBUG006_RawMarkerRefused_Source(t *testing.T) {
	vkPath := sp1VKPath(t) // real SP1 v6 key, no pinnedPublicInputs
	src := gk006WriteContract(t, "RawUnpinned", "\trunar.AssertGroth16WitnessAssisted()\n\trunar.Assert(true)")
	_, err := CompileFromSource(src, CompileOptions{Groth16WAVKey: vkPath})
	gk006RequireRefusal(t, err, "a --source contract calling AssertGroth16WitnessAssisted")
}

func TestGKBUG006_MixedMarkersRefused_Source(t *testing.T) {
	vkPath := sp1VKPath(t)
	for name, body := range map[string]string{
		"RawThenMSM": "\trunar.AssertGroth16WitnessAssisted()\n\trunar.AssertGroth16WitnessAssistedWithMSM()\n\trunar.Assert(true)",
		"MSMThenRaw": "\trunar.AssertGroth16WitnessAssistedWithMSM()\n\trunar.AssertGroth16WitnessAssisted()\n\trunar.Assert(true)",
	} {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			_, err := CompileFromSource(gk006WriteContract(t, name, body), CompileOptions{Groth16WAVKey: vkPath})
			gk006RequireRefusal(t, err, "a --source method mixing both Groth16 markers ("+name+")")
		})
	}
}

// gk006MSMProgram lowers a contract whose only statement is the MSM marker
// to ANF, the shape an --ir file carries.
func gk006MSMProgram(t *testing.T) *ir.ANFProgram {
	t.Helper()
	src := gk006WriteContract(t, "MSMOnly", "\trunar.AssertGroth16WitnessAssistedWithMSM()\n\trunar.Assert(true)")
	prog, err := CompileSourceToIR(src)
	if err != nil {
		t.Fatalf("CompileSourceToIR: %v", err)
	}
	return prog
}

// gk006FindMarker returns the index of the MSM marker binding in the Verify
// method body.
func gk006FindMarker(t *testing.T, prog *ir.ANFProgram) (int, int) {
	t.Helper()
	for mi := range prog.Methods {
		for bi, b := range prog.Methods[mi].Body {
			if b.Value.Kind == "call" && b.Value.Func == "assertGroth16WitnessAssistedWithMSM" {
				return mi, bi
			}
		}
	}
	t.Fatal("MSM marker binding not found in the lowered program")
	return 0, 0
}

func gk006RawMarker(name string) ir.ANFBinding {
	return ir.ANFBinding{Name: name, Value: ir.ANFValue{Kind: "call", Func: "assertGroth16WitnessAssisted", Args: []string{}}}
}

func TestGKBUG006_RawMarkerRefused_IR(t *testing.T) {
	vkPath := sp1VKPath(t)

	t.Run("control_msm_marker_compiles", func(t *testing.T) {
		if _, err := CompileFromProgram(gk006MSMProgram(t), CompileOptions{Groth16WAVKey: vkPath}); err != nil {
			t.Fatalf("the MSM marker must still compile from IR: %v", err)
		}
	})

	t.Run("raw_marker", func(t *testing.T) {
		prog := gk006MSMProgram(t)
		mi, bi := gk006FindMarker(t, prog)
		prog.Methods[mi].Body[bi].Value.Func = "assertGroth16WitnessAssisted"
		_, err := CompileFromProgram(prog, CompileOptions{Groth16WAVKey: vkPath})
		gk006RequireRefusal(t, err, "an --ir method calling assertGroth16WitnessAssisted")
	})

	mixed := map[string]func(body []ir.ANFBinding, bi int) []ir.ANFBinding{
		"raw_before_msm": func(body []ir.ANFBinding, bi int) []ir.ANFBinding {
			out := append([]ir.ANFBinding{}, body[:bi]...)
			out = append(out, gk006RawMarker("_gk006_raw"))
			return append(out, body[bi:]...)
		},
		"raw_after_msm": func(body []ir.ANFBinding, bi int) []ir.ANFBinding {
			out := append([]ir.ANFBinding{}, body[:bi+1]...)
			out = append(out, gk006RawMarker("_gk006_raw"))
			return append(out, body[bi+1:]...)
		},
		"raw_inside_loop_arm": func(body []ir.ANFBinding, bi int) []ir.ANFBinding {
			loop := ir.ANFBinding{Name: "_gk006_loop", Value: ir.ANFValue{
				Kind: "loop", Count: 1, IterVar: "_gk006_i",
				Body: []ir.ANFBinding{gk006RawMarker("_gk006_raw")},
			}}
			out := append([]ir.ANFBinding{}, body[:bi+1]...)
			out = append(out, loop)
			return append(out, body[bi+1:]...)
		},
	}
	for name, edit := range mixed {
		name, edit := name, edit
		t.Run("mixed/"+name, func(t *testing.T) {
			prog := gk006MSMProgram(t)
			mi, bi := gk006FindMarker(t, prog)
			prog.Methods[mi].Body = edit(prog.Methods[mi].Body, bi)
			_, err := CompileFromProgram(prog, CompileOptions{Groth16WAVKey: vkPath})
			gk006RequireRefusal(t, err, "an --ir method mixing both Groth16 markers ("+name+")")
		})
	}
}

// gk006PrivateHelperSource is a contract whose public method reaches the
// marker only through a private helper, which the preamble scan does not
// walk. Inlining the helper is where the refusal has to fire.
func gk006PrivateHelperSource(t *testing.T, name, marker string) string {
	t.Helper()
	source := `
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type ` + name + ` struct {
	runar.SmartContract
}

func (c *` + name + `) helper() {
	runar.` + marker + `()
}

func (c *` + name + `) Verify() {
	c.helper()
	runar.Assert(true)
}
`
	p := filepath.Join(t.TempDir(), name+".runar.go")
	if err := os.WriteFile(p, []byte(source), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	return p
}

// TestGKBUG006_RawMarkerInPrivateMethodRefused covers the private-method path
// on both entry points: --source (typecheck) and --ir (stack lowering, where
// the helper is inlined into the public method).
func TestGKBUG006_RawMarkerInPrivateMethodRefused(t *testing.T) {
	vkPath := sp1VKPath(t)

	t.Run("source", func(t *testing.T) {
		src := gk006PrivateHelperSource(t, "RawInHelper", "AssertGroth16WitnessAssisted")
		_, err := CompileFromSource(src, CompileOptions{Groth16WAVKey: vkPath})
		gk006RequireRefusal(t, err, "a --source private helper calling AssertGroth16WitnessAssisted")
	})

	t.Run("ir", func(t *testing.T) {
		// Lower a helper that calls the MSM marker (the frontend accepts it),
		// then rename that call to the raw marker in the private method only.
		prog, err := CompileSourceToIR(gk006PrivateHelperSource(t, "IRHelper", "AssertGroth16WitnessAssistedWithMSM"))
		if err != nil {
			t.Fatalf("CompileSourceToIR: %v", err)
		}
		renamed := false
		for mi := range prog.Methods {
			if prog.Methods[mi].IsPublic {
				continue
			}
			for bi, b := range prog.Methods[mi].Body {
				if b.Value.Kind == "call" && b.Value.Func == "assertGroth16WitnessAssistedWithMSM" {
					prog.Methods[mi].Body[bi].Value.Func = "assertGroth16WitnessAssisted"
					renamed = true
				}
			}
		}
		if !renamed {
			t.Fatal("premise: no marker call found in a private method of the lowered program")
		}
		_, err = CompileFromProgram(prog, CompileOptions{Groth16WAVKey: vkPath})
		gk006RequireRefusal(t, err, "an --ir private helper calling assertGroth16WitnessAssisted")
	})
}

// TestGKBUG006_RawMarkerRefusedByFrontend pins the typecheck refusal on its
// own. Every other --source test also reaches stack lowering, which refuses
// the marker too, so they stay green with the typecheck refusal removed. The
// frontend-only path (CompileSourceToIR here; runar.CompileCheck uses the
// same parse/validate/typecheck) never lowers, so only typecheck can catch it.
func TestGKBUG006_RawMarkerRefusedByFrontend(t *testing.T) {
	for name, path := range map[string]string{
		"public_method":  gk006WriteContract(t, "RawFrontend", "\trunar.AssertGroth16WitnessAssisted()\n\trunar.Assert(true)"),
		"private_helper": gk006PrivateHelperSource(t, "RawFrontendHelper", "AssertGroth16WitnessAssisted"),
	} {
		name, path := name, path
		t.Run(name, func(t *testing.T) {
			_, err := CompileSourceToIR(path)
			gk006RequireRefusal(t, err, "the frontend (parse/validate/typecheck) on a "+name+" calling AssertGroth16WitnessAssisted")
		})
	}
}
