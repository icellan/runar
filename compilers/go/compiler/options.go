package compiler

import (
	"fmt"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/compilers/go/ir"
)

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

	// SP1FriParams is an optional override for the SP1 FRI verifier
	// parameter tuple. When nil, every `runar.VerifySP1FRI(...)` call in
	// the compiled program lowers at the default PoC tuple
	// (`codegen.DefaultSP1FriParams()`). When non-nil, every call lowers
	// at this tuple — the natural production-deploy path for the SP1 FRI
	// verifier:
	//
	//	artifact, err := compiler.CompileFromSource(
	//	    "MyContract.runar.go",
	//	    compiler.CompileOptions{
	//	        SP1FriParams: compiler.SP1FriPresetMust("evm-guest"),
	//	    },
	//	)
	//
	// Use `compiler.SP1FriPreset(name)` for the canonical presets:
	// "minimal-guest" / "evm-guest" / "production-100" / "production-64" /
	// "production-16". Custom tuples are also accepted; see
	// `codegen.SP1FriVerifierParams` for the field semantics.
	SP1FriParams *codegen.SP1FriVerifierParams
}

// SP1FriPreset returns the canonical SP1 FRI verifier parameter tuple for
// a named preset. The presets cover:
//
//   - "minimal-guest"   — PoC tuple, matches
//                         tests/vectors/sp1/fri/minimal-guest/proof.postcard
//                         (degreeBits=3, num_queries=2, log_blowup=2,
//                         log_final_poly_len=2, commit/query_pow_bits=1).
//   - "evm-guest"       — production-scale tuple, matches
//                         tests/vectors/sp1/fri/evm-guest/proof.postcard
//                         (degreeBits=10, num_queries=100, log_blowup=1,
//                         log_final_poly_len=0, commit/query_pow_bits=16).
//   - "production-100"  — alias for "evm-guest".
//   - "production-64"   — production-scale w/ num_queries=64 fallback
//                         (per docs/sp1-fri-verifier.md §5).
//   - "production-16"   — production-scale w/ num_queries=16 fallback
//                         (per docs/sp1-fri-verifier.md §5).
//
// Returns an error when the preset name is unrecognised.
func SP1FriPreset(name string) (codegen.SP1FriVerifierParams, error) {
	switch name {
	case "minimal-guest":
		// Validated PoC tuple. Matches the minimal-guest fixture and the
		// Go reference verifier's `minimalGuestConfig`
		// (packages/runar-go/sp1fri/verify.go).
		return codegen.DefaultSP1FriParams(), nil
	case "evm-guest", "production-100":
		// Production-scale tuple. Mirrors `evmGuestConfig` in
		// packages/runar-go/sp1fri/verify.go: num_queries=100,
		// log_blowup=1, log_final_poly_len=0, degreeBits=10,
		// commit/query_pow_bits=16. The natural production tuple from
		// the BSVM handoff §2.1 — log_final_poly_len=0 is now valid
		// because EmitFullSP1FriVerifierBody derives numRounds from
		// params (B1 fix in compilers/go/codegen/sp1_fri.go).
		p := codegen.DefaultSP1FriParams()
		p.LogBlowup = 1
		p.NumQueries = 100
		p.LogFinalPolyLen = 0
		p.CommitPoWBits = 16
		p.QueryPoWBits = 16
		p.DegreeBits = 10
		p.BaseDegreeBits = 10
		// PublicValuesByteSize and SP1VKeyHashByteSize are kept at the
		// PoC defaults (12 + 0). Override via the returned struct if the
		// guest program uses a different layout.
		return p, nil
	case "production-64":
		// Fallback per docs/sp1-fri-verifier.md §5: num_queries 100 → 64.
		p, _ := SP1FriPreset("evm-guest")
		p.NumQueries = 64
		return p, nil
	case "production-16":
		// Fallback per docs/sp1-fri-verifier.md §5: num_queries 100 → 16.
		// Lowest security parameter; reserve for the strictest mainnet
		// policy regimes.
		p, _ := SP1FriPreset("evm-guest")
		p.NumQueries = 16
		return p, nil
	default:
		return codegen.SP1FriVerifierParams{}, fmt.Errorf(
			"compiler.SP1FriPreset: unknown preset %q (known: "+
				"minimal-guest, evm-guest, production-100, production-64, production-16)",
			name)
	}
}

// SP1FriPresetMust is a convenience wrapper for callers that know the
// preset name is valid (e.g. test code, callsites with a static literal).
// Panics on an unknown preset name.
func SP1FriPresetMust(name string) *codegen.SP1FriVerifierParams {
	p, err := SP1FriPreset(name)
	if err != nil {
		panic(err)
	}
	return &p
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
