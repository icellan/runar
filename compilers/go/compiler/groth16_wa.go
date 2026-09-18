package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// ---------------------------------------------------------------------------
// runarc groth16-wa backend
// ---------------------------------------------------------------------------
//
// Phase 6 of the Rúnar Groth16 roadmap: this file wraps the witness-assisted
// BN254 Groth16 verifier codegen (codegen.EmitGroth16VerifierWitnessAssisted)
// and the bn254witness helpers (for MillerLoop(α, -β) precomputation) behind a
// single `CompileGroth16WA` entry point. The resulting Artifact has a Bitcoin
// Script locking script with a SPECIFIC verifying key baked in — changing the
// VK requires recompiling.
//
// This is a dedicated compiler backend: it does NOT touch the Rúnar DSL
// parser / ANF / type-checker pipeline. It consumes a .groth16.vk.json file
// that matches `spec/groth16_wa_vk.schema.json` and produces a standard
// RunarArtifact that can be deployed via the Rúnar SDK.

const (
	// defaultGroth16WAContractName is the contract name used when
	// Groth16WAOpts.ContractName is empty.
	defaultGroth16WAContractName = "Groth16Verifier"
)

// Groth16WAOpts configures a `runarc groth16-wa` compile run.
type Groth16WAOpts struct {
	// ContractName sets the artifact's contract name. When empty this
	// defaults to "Groth16Verifier".
	ContractName string

	// ModuloThreshold controls deferred mod reduction inside the BN254
	// field arithmetic. It is forwarded verbatim to codegen.Groth16Config.
	//
	// Default: 0 (strict — every intermediate is reduced mod p). This
	// produces a LARGER script (~718 KB for SP1) but is dramatically
	// faster on the go-sdk interpreter because Bitcoin Script bignum
	// multiplication is O(n²) in the schoolbook sense. The 2048-byte
	// threshold from the nChain paper is NOT recommended for real
	// deployment on today's interpreters — defer only if you know what
	// you're doing.
	ModuloThreshold int

	// PublicInputs pins the circuit's public-input scalars into the
	// emitted locking script. REQUIRED: a Groth16 verifier that does not
	// fix its public inputs attests that *some* statement was proven, not
	// that *this* statement was proven — an attacker picks a vector they
	// can satisfy, mints an honest proof for it, and spends. The scalars
	// are baked in as pushdata, so changing them requires recompiling
	// (exactly like changing the VK does).
	//
	// Must contain exactly numPubInputs entries (numPubInputs = len(vk.IC)
	// - 1), each in [0, r) where r is the BN254 scalar field order.
	PublicInputs []*big.Int
}

// groth16MSMArity is the number of public-input scalars
// codegen.EmitGroth16VerifierWitnessAssistedWithMSM binds. The MSM preamble
// reserves fixed stack slots _pub_0 .. _pub_4, matching SP1's Groth16
// wrapper arity; generalising it is a codegen change, not a backend one.
const groth16MSMArity = 5

// bn254ScalarR is the order of the BN254 scalar field (Fr) — the domain of
// Groth16 public inputs.
var bn254ScalarR, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// validateGroth16PublicInputs checks that the caller pinned exactly the
// public inputs this verifying key expects, and that each one is a valid
// scalar-field element.
func validateGroth16PublicInputs(pubs []*big.Int, numPubInputs int) error {
	if len(pubs) == 0 {
		return fmt.Errorf(
			"no public inputs pinned: a Groth16 verifier that does not fix its %d public inputs "+
				"proves only that SOME statement was satisfied — an attacker supplies their own "+
				"public-input vector with a matching proof and the script accepts. Pass "+
				"Groth16WAOpts.PublicInputs (CLI: --pub <scalar> once per input) with the %d "+
				"scalars this output is meant to attest to",
			numPubInputs, numPubInputs)
	}
	if numPubInputs != groth16MSMArity {
		return fmt.Errorf(
			"verifying key declares %d public inputs, but the on-chain MSM binding supports "+
				"exactly %d (the SP1 Groth16 arity). Binding a different arity requires extending "+
				"codegen.EmitGroth16VerifierWitnessAssistedWithMSM",
			numPubInputs, groth16MSMArity)
	}
	if len(pubs) != numPubInputs {
		return fmt.Errorf("pinned %d public inputs but the verifying key declares %d", len(pubs), numPubInputs)
	}
	for i, p := range pubs {
		if p == nil {
			return fmt.Errorf("public input %d is nil", i)
		}
		if p.Sign() < 0 || p.Cmp(bn254ScalarR) >= 0 {
			return fmt.Errorf("public input %d is outside the BN254 scalar field [0, r)", i)
		}
	}
	return nil
}

// emitGroth16PublicInputPins appends the ops that assert the five witness-
// supplied public-input scalars equal the values pinned at compile time.
//
// EmitGroth16VerifierWitnessAssistedWithMSM leaves the main stack as
//
//	[_pub_0, _pub_1, _pub_2, _pub_3, _pub_4, _ok]   (_ok on top)
//
// so we drop the truthy marker, compare the scalars top-down (_pub_4 first),
// and re-push the marker. Together with the MSM binding this closes the loop:
// the MSM check forces prepared_inputs == IC[0] + Σ pub_j·IC[j+1], and these
// checks force each pub_j to the deployer's chosen value.
func emitGroth16PublicInputPins(ops []codegen.StackOp, pubs []*big.Int) []codegen.StackOp {
	ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_DROP"})
	for i := len(pubs) - 1; i >= 0; i-- {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(pubs[i])},
		})
		ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	}
	return append(ops, codegen.StackOp{
		Op:    "push",
		Value: codegen.PushValue{Kind: "bigint", BigInt: big.NewInt(1)},
	})
}

// LoadGroth16WAConfigForTests is the exported alias for the internal
// loadGroth16WAConfig helper. It exists so integration tests in
// integration/go/helpers can build a codegen.Groth16Config from a vk.json
// path without depending on bn254witness directly. The "ForTests" suffix
// signals that production callers should set CompileOptions.Groth16WAVKey
// and let CompileFromProgram do the loading internally.
func LoadGroth16WAConfigForTests(vkPath string) (codegen.Groth16Config, error) {
	return loadGroth16WAConfig(vkPath)
}

// loadGroth16WAConfig reads an SP1-format Groth16 vk.json file, computes
// MillerLoop(α, -β) off-chain via gnark-crypto, and returns a populated
// codegen.Groth16Config ready to feed into LowerToStackOptions or
// EmitGroth16VerifierWitnessAssisted.
//
// This is the shared loader behind both CompileGroth16WA (the standalone
// stateless backend) and the Mode 3 stateful preamble path through
// CompileFromProgram.
func loadGroth16WAConfig(vkPath string) (codegen.Groth16Config, error) {
	vk, err := bn254witness.LoadSP1VKFromFile(vkPath)
	if err != nil {
		return codegen.Groth16Config{}, fmt.Errorf("parse %s: %w", vkPath, err)
	}

	alphaNegBetaFp12, err := bn254witness.PrecomputeAlphaNegBeta(vk.AlphaG1, vk.BetaNegG2)
	if err != nil {
		return codegen.Groth16Config{}, fmt.Errorf("PrecomputeAlphaNegBeta: %w", err)
	}

	cfg := codegen.Groth16Config{
		// ModuloThreshold=0 matches the load-bearing
		// TestGroth16WA_EndToEnd_SP1Proof_Script test (groth16_script_test.go)
		// — strict residue reduction at every step. The 2048-byte deferred
		// path is dramatically slower on the go-sdk interpreter, and the
		// preamble path needs to share the same configuration as the
		// standalone stateless verifier so witness compatibility is
		// guaranteed.
		ModuloThreshold:  0,
		AlphaNegBetaFp12: alphaNegBetaFp12,
		GammaNegG2:       vk.GammaNegG2,
		DeltaNegG2:       vk.DeltaNegG2,
	}

	// Populate IC for the MSM-binding verifier variant. The raw variant
	// ignores IC; the MSM variant requires exactly 6 points (IC[0] plus
	// IC[1..5] for the 5 SP1 public inputs). When the VK carries fewer
	// entries (non-SP1 circuits) or more, the unused slots default to
	// (0, 0) — the MSM variant is only sound for 5-public-input circuits.
	for i := 0; i < 6; i++ {
		if i < len(vk.IC) && vk.IC[i] != nil {
			cfg.IC[i] = [2]*big.Int{
				new(big.Int).Set(vk.IC[i][0]),
				new(big.Int).Set(vk.IC[i][1]),
			}
		} else {
			cfg.IC[i] = [2]*big.Int{big.NewInt(0), big.NewInt(0)}
		}
	}

	return cfg, nil
}

// CompileGroth16WA reads a .groth16.vk.json file, builds the witness-assisted
// BN254 Groth16 verifier locking script for its verifying key, and returns a
// RunarArtifact (defined in this package as `Artifact`) with the script baked
// in. The artifact can be deployed as a standard stateless Rúnar contract via
// the `runar-go` SDK or any other SDK that consumes RunarArtifact JSON.
//
// The VK is FIXED at compile time: the resulting script contains the VK
// values (AlphaNegBetaFp12, GammaNegG2, DeltaNegG2) as pushdata. Changing the
// VK requires regenerating the artifact.
//
// The PUBLIC INPUTS are fixed at compile time too, via opts.PublicInputs,
// and compilation FAILS without them. The emitted script uses the MSM-binding
// verifier variant, which recomputes IC[0] + Σ pub_j·IC[j+1] on-chain and
// requires it to equal the prover-supplied prepared_inputs, and then asserts
// each pub_j equals its pinned value. Without both halves the artifact would
// accept a proof of any statement the spender chose for themselves: the raw
// variant's only check on prepared_inputs is an on-curve test, and the
// pairing equation ties the proof to whatever prepared_inputs was supplied
// rather than to the statement this output is about.
//
// The artifact's ABI intentionally exposes a single public method `verify`
// with no parameters. The Groth16 unlock is a raw witness bundle (gradients
// + final-exp witnesses + public-input scalars + proof + prepared inputs)
// pushed directly by the caller via `bn254witness.Witness.ToStackOps()` —
// build it with `bn254witness.BuildFromProofWithInputs`, which emits the
// MSM layout. It does not fit the standard Rúnar ABI-param model, which is
// why Params is empty.
func CompileGroth16WA(vkPath string, opts Groth16WAOpts) (*Artifact, error) {
	// 1. Load the raw VK JSON bytes — we need them for the digest AND
	//    for the typed parse. Reading twice would risk a TOCTOU mismatch.
	vkBytes, err := os.ReadFile(vkPath)
	if err != nil {
		return nil, fmt.Errorf("CompileGroth16WA: read %s: %w", vkPath, err)
	}

	// 2. Re-parse into a bn254witness.VerifyingKey just to extract the
	//    public-input count for the artifact metadata. The shared
	//    loadGroth16WAConfig helper does the same parse but does not
	//    expose the IC slice through the codegen.Groth16Config it
	//    returns (codegen does not consume IC).
	vk, err := bn254witness.LoadSP1VKFromFile(vkPath)
	if err != nil {
		return nil, fmt.Errorf("CompileGroth16WA: parse %s: %w", vkPath, err)
	}
	numPubInputs := len(vk.IC) - 1

	// 2a. Refuse to emit an unbound verifier. This is the whole soundness
	//     story of the standalone backend — see the doc comment above.
	if err := validateGroth16PublicInputs(opts.PublicInputs, numPubInputs); err != nil {
		return nil, fmt.Errorf("CompileGroth16WA: %w", err)
	}

	// 3. Build the codegen config via the shared loader. The standalone
	//    backend lets the caller override ModuloThreshold (the original
	//    knob from the nChain paper); the Mode 3 preamble path uses the
	//    loadGroth16WAConfig default of 0 (strict reduction).
	config, err := loadGroth16WAConfig(vkPath)
	if err != nil {
		return nil, fmt.Errorf("CompileGroth16WA: %w", err)
	}
	config.ModuloThreshold = opts.ModuloThreshold

	// 4. Emit the MSM-binding verifier. loadGroth16WAConfig already
	//    populated config.IC from the VK, which is what the MSM preamble
	//    recomputes the prepared-inputs accumulator from.
	var ops []codegen.StackOp
	codegen.EmitGroth16VerifierWitnessAssistedWithMSM(func(op codegen.StackOp) {
		ops = append(ops, op)
	}, config)
	if len(ops) == 0 {
		return nil, fmt.Errorf("CompileGroth16WA: codegen produced zero ops (bug)")
	}

	// 5. Pin the public-input scalars the MSM preamble left on the stack.
	ops = emitGroth16PublicInputPins(ops, opts.PublicInputs)

	// 6. Run peephole optimizers: the general stack-op peepholes and the
	//    BN254-specific ones. Both are applied in the same order as the
	//    existing TestGroth16WA_EndToEnd_SP1Proof_Script pipeline, which
	//    is our load-bearing correctness oracle.
	ops = codegen.OptimizeStackOps(ops)
	ops = codegen.OptimizeBN254Ops(ops)

	// 7. Emit to hex. We pass a single StackMethod named "verify" — it
	//    corresponds to the single public entry point on the ABI.
	method := codegen.StackMethod{Name: "verify", Ops: ops}
	emitResult, err := codegen.Emit([]codegen.StackMethod{method})
	if err != nil {
		return nil, fmt.Errorf("CompileGroth16WA: emit: %w", err)
	}

	// 8. Assemble the artifact. This path is independent from
	//    assembleArtifact() above because we don't have an ANF program
	//    (no Rúnar source was compiled). All the derived metadata —
	//    ConstructorSlots, StateFields, ANF, IR, SourceMap — is
	//    deliberately absent.
	contractName := opts.ContractName
	if contractName == "" {
		contractName = defaultGroth16WAContractName
	}

	digest := sha256.Sum256(vkBytes)
	vkDigest := hex.EncodeToString(digest[:])

	pinnedPubs := make([]string, len(opts.PublicInputs))
	for i, p := range opts.PublicInputs {
		pinnedPubs[i] = p.String()
	}

	artifact := &Artifact{
		Version:         schemaVersion,
		CompilerVersion: compilerVersion,
		ContractName:    contractName,
		ABI: ABI{
			Constructor: ABIConstructor{Params: []ABIParam{}},
			Methods: []ABIMethod{
				{
					Name:     "verify",
					Params:   []ABIParam{},
					IsPublic: true,
				},
			},
		},
		Script: emitResult.ScriptHex,
		ASM:    emitResult.ScriptAsm,
		// buildTimestamp(), not time.Now(): this path used to stamp the clock
		// directly, so SOURCE_DATE_EPOCH was honoured by every artifact except
		// the one whose entire purpose is to be reproduced from the same
		// vk.json by someone deciding whether to trust it (R-176).
		BuildTimestamp: buildTimestamp(),
		Groth16WA: &Groth16WAMeta{
			NumPubInputs: numPubInputs,
			VKDigest:     vkDigest,
			PublicInputs: pinnedPubs,
		},
	}

	return artifact, nil
}
