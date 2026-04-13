package compiler

import "github.com/icellan/runar/compilers/go/ir"

// CompileOptions controls optional compiler behavior.
type CompileOptions struct {
	// DisableConstantFolding skips the ANF constant folding pass.
	// Default (false) enables constant folding.
	DisableConstantFolding bool

	// ParseOnly stops compilation after the parse pass (pass 1).
	ParseOnly bool

	// ValidateOnly stops compilation after the validate pass (pass 2).
	ValidateOnly bool

	// TypecheckOnly stops compilation after the type-check pass (pass 3).
	TypecheckOnly bool

	// ConstructorArgs bakes property values into the locking script,
	// replacing OP_0 placeholders with real push data.
	// Keys are property names; values are string (hex bytes), int64, or bool.
	ConstructorArgs map[string]interface{}

	// IncludeSourceMap includes source-level debug mappings in the artifact.
	IncludeSourceMap bool

	// IncludeIR includes ANF and Stack IR snapshots in the artifact for debugging.
	IncludeIR bool

	// Groth16WAVKey is the path to a SP1-format Groth16 vk.json file. When
	// non-empty, any method that calls runar.AssertGroth16WitnessAssisted is
	// lowered with a witness-assisted BN254 Groth16 verifier preamble whose
	// verifying key is loaded from this file. The VK becomes baked-in
	// pushdata in the resulting locking script.
	//
	// When empty, calls to runar.AssertGroth16WitnessAssisted are rejected
	// at stack-lowering time with an error pointing back at this option.
	//
	// See compilers/go/codegen/bn254_groth16.go for the underlying emitter
	// (EmitGroth16VerifierWitnessAssisted) and packages/runar-go/bn254witness
	// for the matching prover-side witness generator.
	Groth16WAVKey string
}

func mergeOptions(opts []CompileOptions) CompileOptions {
	if len(opts) == 0 {
		return CompileOptions{}
	}
	return opts[0]
}

// applyConstructorArgs bakes constructor arg values into ANF property initialValues.
// This replaces OP_0 placeholders with real push data in the emitted script.
func applyConstructorArgs(program *ir.ANFProgram, args map[string]interface{}) {
	if len(args) == 0 || program == nil {
		return
	}
	for i := range program.Properties {
		if v, ok := args[program.Properties[i].Name]; ok {
			program.Properties[i].InitialValue = v
		}
	}
}
