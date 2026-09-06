package compiler

import (
	"fmt"
	"sort"
	"strings"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/compilers/go/frontend"
	"github.com/icellan/runar/compilers/go/ir"
)

// CompileOptions controls optional compiler behavior.
type CompileOptions struct {
	// DisableConstantFolding skips the ANF constant folding pass.
	// Default (false) enables constant folding.
	DisableConstantFolding bool

	// EcConstantPool, EcReductionSinking and EcFixedBaseComb are the
	// EXPERIMENTAL EC script-size optimizations. All three default off, and
	// with all three off every EC emitter is byte-identical to the shipping
	// output — no golden, size baseline, or cross-tier hex comparison moves.
	//
	// Cross-tier byte parity for the flags THEMSELVES is gated by
	// conformance/ec-flag-parity/expected.json, replayed here in
	// codegen/ec_flag_parity_test.go. See
	// docs/experiments/script-size-optimizer-results.md.
	EcConstantPool bool

	// EcReductionSinking needs EcConstantPool: the cheap subtraction shape
	// references the field prime twice, so without a pooled slot it is a
	// regression. The emitters compare the two costs and never take the cheap
	// shape when it does not pay, so enabling it alone is safe — just useless.
	EcReductionSinking bool

	// EcFixedBaseComb applies only where the base point is a compile-time
	// constant (ecMulGen, p256MulGen, p384MulGen, and the u1*G half of ECDSA
	// verification). Runtime-base multiplies keep the binary ladder: the comb's
	// interval soundness argument does not cover an attacker-chosen base.
	EcFixedBaseComb bool

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
//     tests/vectors/sp1/fri/minimal-guest/proof.postcard
//     (degreeBits=3, num_queries=2, log_blowup=2,
//     log_final_poly_len=2, commit/query_pow_bits=1).
//   - "evm-guest"       — production-scale tuple, matches
//     tests/vectors/sp1/fri/evm-guest/proof.postcard
//     (degreeBits=10, num_queries=100, log_blowup=1,
//     log_final_poly_len=0, commit/query_pow_bits=16).
//   - "production-100"  — alias for "evm-guest".
//   - "production-64"   — production-scale w/ num_queries=64 fallback
//     (per docs/sp1-fri-verifier.md §5).
//   - "production-16"   — production-scale w/ num_queries=16 fallback
//     (per docs/sp1-fri-verifier.md §5).
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

// applyConstructorArgs validates and bakes constructor arg values into ANF
// property initialValues, replacing OP_0 placeholders with real push data in
// the emitted script. It returns a list of diagnostic error messages (empty
// when valid); a non-empty result means nothing was baked and the caller must
// surface the errors.
//
// The no-args placeholder path (len(args) == 0) is unchecked and byte-identical
// to before — that is the normal deploy-artifact path where the SDK substitutes
// values via constructorSlots.
//
// Mirrors the TypeScript reference (validateConstructorArgsShape +
// findUnbakedReferencedReadonly in packages/runar-compiler/src/index.ts):
//
//	(a) positional-array reject — N/A for the Go tier. ConstructorArgs is a
//	    typed map[string]interface{}, so a positional array cannot reach this
//	    API. The dynamically-typed tiers (Python isinstance(list), Ruby
//	    is_a?(Array)) must guard this explicitly; Go's type system does.
//	(b) unknown-key reject — every key must match a contract property name.
//	(c) unbaked-referenced-readonly reject — after baking, a readonly property
//	    referenced by a method body but still without a value would emit an OP_0
//	    placeholder that fails opaquely at runtime.
func applyConstructorArgs(program *ir.ANFProgram, args map[string]interface{}) []string {
	if len(args) == 0 || program == nil {
		return nil
	}

	// (b) Unknown-key reject.
	propNameSet := make(map[string]bool, len(program.Properties))
	for i := range program.Properties {
		propNameSet[program.Properties[i].Name] = true
	}
	var errs []string
	keys := make([]string, 0, len(args))
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys) // deterministic diagnostics across map-iteration order
	for _, key := range keys {
		if !propNameSet[key] {
			errs = append(errs, fmt.Sprintf(
				"constructorArgs key '%s' does not match any property of contract "+
					"'%s' (properties: [%s]). Nothing would be baked for this key.",
				key, program.ContractName, propertyNameList(program)))
		}
	}
	if len(errs) > 0 {
		return errs
	}

	// Bake constructor args into ANF property initialValues.
	for i := range program.Properties {
		if v, ok := args[program.Properties[i].Name]; ok {
			program.Properties[i].InitialValue = v
		}
	}

	// (c) Unbaked-referenced-readonly reject.
	return findUnbakedReferencedReadonly(program)
}

// propertyNameList renders the contract's property names as "a, b, c" for
// diagnostics.
func propertyNameList(program *ir.ANFProgram) string {
	names := make([]string, len(program.Properties))
	for i := range program.Properties {
		names[i] = program.Properties[i].Name
	}
	return strings.Join(names, ", ")
}

// findUnbakedReferencedReadonly finds readonly properties that are referenced
// by at least one method body but still have no baked InitialValue after
// applying constructorArgs. Such properties would be emitted as OP_0
// placeholders, making the compiled script fail opaquely at runtime.
func findUnbakedReferencedReadonly(program *ir.ANFProgram) []string {
	referenced := collectReferencedProps(program)
	var errs []string
	for i := range program.Properties {
		p := &program.Properties[i]
		if p.Readonly && p.InitialValue == nil && referenced[p.Name] {
			errs = append(errs, fmt.Sprintf(
				"readonly property '%s' is referenced by a method but has no value "+
					"after baking constructorArgs — the emitted script would carry an OP_0 "+
					"placeholder that fails at runtime. Provide '%s' in constructorArgs "+
					"(or give the property an initializer).",
				p.Name, p.Name))
		}
	}
	return errs
}

// collectReferencedProps collects the property names actually referenced by
// method bodies. The raw ANF from pass 4 loads every property at method entry;
// only after dead-binding elimination do the surviving load_prop nodes reflect
// real references. DCE is a pure function, so running it on a throwaway probe
// copy does not perturb the main pipeline.
func collectReferencedProps(program *ir.ANFProgram) map[string]bool {
	// Throwaway probe: EliminateDeadCode reassigns each method's Body slice
	// header (never mutating property or binding contents), so shallow-copying
	// the method structs into a fresh slice fully isolates the real program.
	probe := &ir.ANFProgram{
		ContractName: program.ContractName,
		Properties:   program.Properties,
		Methods:      make([]ir.ANFMethod, len(program.Methods)),
	}
	copy(probe.Methods, program.Methods)
	frontend.EliminateDeadCode(probe)

	referenced := make(map[string]bool)
	for i := range probe.Methods {
		m := &probe.Methods[i]
		// The constructor's super(...) call references every property but is
		// never emitted as script code — only real method bodies count.
		if m.Name == "constructor" {
			continue
		}
		collectLoadPropRefs(m.Body, referenced)
	}
	return referenced
}

// collectLoadPropRefs recursively collects load_prop property names from ANF
// bindings, recursing through if(then/else) and loop(body).
func collectLoadPropRefs(bindings []ir.ANFBinding, out map[string]bool) {
	for i := range bindings {
		v := &bindings[i].Value
		switch v.Kind {
		case "load_prop":
			out[v.Name] = true
		case "if":
			collectLoadPropRefs(v.Then, out)
			collectLoadPropRefs(v.Else, out)
		case "loop":
			collectLoadPropRefs(v.Body, out)
		}
	}
}

// ecCodegenOptions builds the options handed to the EC / NIST codegen modules.
//
// Returns nil — not an all-false struct — when nothing is enabled, so those
// emitters take their untouched default path and the emitted bytes are provably
// identical to the shipping ones.
func (o *CompileOptions) ecCodegenOptions() *codegen.EcCodegenOptions {
	if !o.EcConstantPool && !o.EcReductionSinking && !o.EcFixedBaseComb {
		return nil
	}
	return &codegen.EcCodegenOptions{
		ConstantPool:     o.EcConstantPool,
		ReductionSinking: o.EcReductionSinking,
		FixedBaseComb:    o.EcFixedBaseComb,
	}
}
