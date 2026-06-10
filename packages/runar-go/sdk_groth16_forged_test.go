package runar

// End-to-end forged-Groth16-proof rejection tests for the public SDK call
// path Groth16WAContract.CallWithWitness. These complement the codegen-
// level adversarial tests in
// compilers/go/codegen/bn254_groth16_subgroup_test.go (which exercise the
// emitted on-curve / subgroup-check helpers in isolation) by exercising
// the FULL SDK pipeline:
//
//   1. Compile a real witness-assisted BN254 Groth16 verifier locking
//      script via codegen.EmitGroth16VerifierWitnessAssisted +
//      codegen.Emit (the same path runarc groth16-wa uses).
//   2. Wrap that script in a RunarArtifact + Groth16WAContract.
//   3. Construct a structurally valid Groth16 proof + witness for a
//      synthetic-but-mathematically-valid Groth16 instance.
//   4. Tamper one witness field in a way that defeats the on-chain
//      verifier while keeping the witness format valid (so
//      serializeWitnessToUnlock succeeds and the SDK happily produces
//      and broadcasts a spend tx).
//   5. Confirm Groth16WAContract.CallWithWitness completes without an
//      SDK-level error (i.e. the SDK does NOT pre-validate semantics).
//   6. Replay the resulting (unlocking, locking) pair through the
//      go-sdk script interpreter (packages/runar-go/script_vm.go) and
//      assert it fails — i.e. the forged spend would be rejected on-
//      chain.
//
// MockProvider.Broadcast records the raw tx hex without running the
// script — so a positive Broadcast result is NOT evidence the spend is
// valid. The script-VM replay step is what makes this an honest end-to-
// end rejection test.
//
// The three forgery axes mirror the codegen-level test classification:
//
//   - Off-curve proof.A      (defeats the G1 on-curve check)
//   - Bad Miller-loop slope  (defeats the witness-assisted gradient check)
//   - Inconsistent subgroup  (defeats the G2 prime-order subgroup check)
//
// Together they cover every layer of the witness-assisted verifier's
// soundness preamble.

import (
	"math/big"
	"strings"
	"sync"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// -----------------------------------------------------------------------
// Shared fixtures
// -----------------------------------------------------------------------

// forgedTestFixture caches the synthetic Groth16 instance + compiled
// verifier locking script across the forgery sub-tests. Building the
// verifier script is fast (~100 ms) but running it through the script
// interpreter takes ~1 s; sharing the locking script means the three
// negative tests only pay the interpreter cost, not the codegen cost.
type forgedTestFixture struct {
	vk            bn254witness.VerifyingKey
	proof         bn254witness.Proof
	publicInputs  []*big.Int
	lockingScript string // hex
	artifact      *RunarArtifact
}

var (
	forgedFixtureOnce sync.Once
	forgedFixture     *forgedTestFixture
	forgedFixtureErr  error
)

// buildForgedTestFixture builds a synthetic but mathematically valid
// Groth16 verification instance and compiles the corresponding witness-
// assisted verifier locking script. Returns a cached fixture on
// subsequent calls.
//
// The synthetic instance is identical to the one used in
// bn254witness/groth16_script_test.go's trivialGroth16Instance — small
// scalar multiples of (G1, G2) chosen so the SP1-rearranged Groth16
// equation holds with exponent sum 0. We do not re-derive the math here;
// see that file for the algebraic justification.
func buildForgedTestFixture(t *testing.T) *forgedTestFixture {
	t.Helper()
	forgedFixtureOnce.Do(func() {
		forgedFixture, forgedFixtureErr = buildForgedTestFixtureUncached()
	})
	if forgedFixtureErr != nil {
		t.Fatalf("buildForgedTestFixture: %v", forgedFixtureErr)
	}
	return forgedFixture
}

func buildForgedTestFixtureUncached() (*forgedTestFixture, error) {
	_, _, g1Aff, g2Aff := bn254.Generators()
	scaleG1 := func(k int64) bn254.G1Affine {
		var p bn254.G1Affine
		p.ScalarMultiplication(&g1Aff, big.NewInt(k))
		return p
	}
	scaleG2 := func(k int64) bn254.G2Affine {
		var p bn254.G2Affine
		p.ScalarMultiplication(&g2Aff, big.NewInt(k))
		return p
	}

	// Synthetic instance (see trivialGroth16Instance for the algebra).
	alpha := scaleG1(1)
	beta := scaleG2(1)
	gamma := scaleG2(2)
	delta := scaleG2(3)
	ic0 := scaleG1(1)
	ic1 := scaleG1(2)
	publicInput := big.NewInt(1)
	a := scaleG1(13)
	b := scaleG2(1)
	c := scaleG1(2)

	vk := bn254witness.NewVerifyingKeyFromPositive(
		alpha, beta, gamma, delta,
		[]bn254.G1Affine{ic0, ic1},
	)
	proof := bn254witness.Proof{
		A: bn254witness.G1AffineToBig(a),
		B: bn254witness.G2AffineToBig(b),
		C: bn254witness.G1AffineToBig(c),
	}

	// Compile the verifier locking script.
	alphaNegBetaFp12, err := bn254witness.PrecomputeAlphaNegBeta(vk.AlphaG1, vk.BetaNegG2)
	if err != nil {
		return nil, err
	}
	// ModuloThreshold=0 matches the existing D0 end-to-end test in
	// bn254witness/groth16_script_test.go; values stay small so the
	// go-sdk interpreter runs in ~1 s instead of stalling on the
	// deferred-mod path's O(n²) big-int multiplication.
	config := codegen.Groth16Config{
		ModuloThreshold:  0,
		AlphaNegBetaFp12: alphaNegBetaFp12,
		GammaNegG2:       vk.GammaNegG2,
		DeltaNegG2:       vk.DeltaNegG2,
	}
	var verifierOps []codegen.StackOp
	codegen.EmitGroth16VerifierWitnessAssisted(func(op codegen.StackOp) {
		verifierOps = append(verifierOps, op)
	}, config)

	result, err := codegen.Emit([]codegen.StackMethod{
		{Name: "verify", Ops: verifierOps},
	})
	if err != nil {
		return nil, err
	}

	artifact := &RunarArtifact{
		Version:         "1",
		CompilerVersion: "test",
		ContractName:    "Groth16VerifierForgedTest",
		Script:          result.ScriptHex,
		ABI: ABI{
			Constructor: ABIConstructor{Params: []ABIParam{}},
			Methods: []ABIMethod{
				{Name: "verify", Params: []ABIParam{}, IsPublic: true},
			},
		},
		Groth16WA: &Groth16WAMeta{
			NumPubInputs: 1,
			VKDigest:     "forged-test-synthetic-vk",
		},
	}

	return &forgedTestFixture{
		vk:            vk,
		proof:         proof,
		publicInputs:  []*big.Int{publicInput},
		lockingScript: result.ScriptHex,
		artifact:      artifact,
	}, nil
}

// assertForgedSpendRejectedOnChain drives the supplied (already-tampered)
// witness through the full SDK call path and then through the go-sdk
// script interpreter to confirm the resulting spend would be rejected
// on-chain.
//
// Expectations:
//   - The SDK's CallWithWitness call MUST succeed (return nil error). The
//     SDK does not validate proof semantics — it just serializes the
//     witness as push data and broadcasts. Anything else would be the
//     SDK doing the verifier's job.
//   - MockProvider records the broadcast tx, but it does NOT execute
//     the script, so we have to do the script-execution check ourselves.
//   - ScriptVM.Execute on (unlocking, locking) MUST report Success=false.
//     A truthy result here would mean the forged proof is accepted by
//     the verifier — that would be the BUG-006 semantic-soundness hole.
func assertForgedSpendRejectedOnChain(
	t *testing.T,
	fix *forgedTestFixture,
	w *bn254witness.Witness,
	tamperName string,
) {
	t.Helper()

	g := NewGroth16WAContract(fix.artifact)
	g.SetCurrentUTXO(&UTXO{
		Txid:        strings.Repeat("cc", 32),
		OutputIndex: 0,
		Satoshis:    1_000_000,
		Script:      fix.lockingScript,
	})

	provider := NewMockProvider("mocknet")
	// Set a low fee rate so the contract UTXO comfortably covers fee +
	// dust output, regardless of the (large) verifier-tx size.
	provider.SetFeeRate(1)
	signer := NewMockSigner("", "")

	destScript := "76a914" + strings.Repeat("00", 20) + "88ac"
	_, txData, err := g.CallWithWitness(provider, signer, w, "", destScript)
	if err != nil {
		t.Fatalf("[%s] SDK CallWithWitness errored: %v (the SDK should accept a structurally-valid witness — semantic rejection must happen on-chain, not in the SDK)", tamperName, err)
	}
	if txData == nil || len(txData.Inputs) != 1 {
		t.Fatalf("[%s] missing input in synthesized TransactionData", tamperName)
	}
	unlockingHex := txData.Inputs[0].Script
	if unlockingHex == "" {
		t.Fatalf("[%s] empty unlocking script in broadcast tx", tamperName)
	}

	// Replay the spend through the go-sdk script interpreter directly,
	// matching the post-Genesis / post-Chronicle / ForkID flag set used by
	// codegen.BuildAndExecuteOps. We deliberately bypass the recording
	// wrapper packages/runar-go/script_vm.go: it snapshots the full main
	// + alt stack after EVERY opcode, which for the ~462K-op verifier
	// would allocate many gigabytes of trace and crater the test runtime.
	// We only care about the binary accept/reject decision here.
	unlockScript, err := bsvscript.NewFromHex(unlockingHex)
	if err != nil {
		t.Fatalf("[%s] parse unlocking hex: %v", tamperName, err)
	}
	lockScript, err := bsvscript.NewFromHex(fix.lockingScript)
	if err != nil {
		t.Fatalf("[%s] parse locking hex: %v", tamperName, err)
	}
	execErr := interpreter.NewEngine().Execute(
		interpreter.WithScripts(lockScript, unlockScript),
		interpreter.WithAfterGenesis(),
		interpreter.WithAfterChronicle(),
		interpreter.WithForkID(),
	)
	if execErr == nil {
		t.Fatalf(
			"[%s] FORGED PROOF ACCEPTED ON-CHAIN: go-sdk interpreter returned nil error. "+
				"This is BUG-006: the SDK call path produced a spend the verifier would "+
				"accept for a tampered witness.",
			tamperName,
		)
	}
	t.Logf("[%s] forged spend correctly rejected on-chain: %v", tamperName, execErr)
}

// -----------------------------------------------------------------------
// Forgery #1: off-curve proof.A
// -----------------------------------------------------------------------

// TestGroth16WASDK_ForgedProof_OffCurveA verifies the full SDK call path
// rejects a proof whose A point is not on the BN254 G1 curve. The
// witness is otherwise structurally valid (gradients land in the right
// slots, prepared inputs are sane) so the SDK will happily build and
// broadcast the spend. The on-chain G1 on-curve check inside
// emitWAG1OnCurveCheck must abort the verifier script.
func TestGroth16WASDK_ForgedProof_OffCurveA(t *testing.T) {
	fix := buildForgedTestFixture(t)

	// Build the honest witness for the (untampered) instance, then mutate
	// ProofA after the fact. This is the realistic adversary model: the
	// prover would generate witnesses against the honest scalar-mul chain
	// and only swap in the off-curve point at the last moment.
	w, err := bn254witness.GenerateWitness(fix.vk, fix.proof, fix.publicInputs)
	if err != nil {
		t.Fatalf("GenerateWitness: %v", err)
	}

	// Tamper: add 1 to proof.A.x. The new point is almost certainly off
	// the curve y² = x³ + 3 (mod p). We do NOT regenerate the witness —
	// the unlocking script still claims the honest gradients, which is
	// what makes this a "forged" proof rather than an honest proof against
	// a different statement.
	w.ProofA[0] = new(big.Int).Add(w.ProofA[0], big.NewInt(1))

	assertForgedSpendRejectedOnChain(t, fix, w, "off-curve proof.A")
}

// -----------------------------------------------------------------------
// Forgery #2: bad Miller-loop gradient
// -----------------------------------------------------------------------

// TestGroth16WASDK_ForgedProof_BadGradient verifies the SDK call path
// rejects a proof whose Miller-loop slope witness is inconsistent with
// the proof points. This forgery axis exercises the witness-assisted
// gradient verification (emitWitnessGradientVerifyFp2) — the heart of
// the WA verifier's per-step soundness check. Without it, a prover could
// supply arbitrary final-pairing accumulators.
func TestGroth16WASDK_ForgedProof_BadGradient(t *testing.T) {
	fix := buildForgedTestFixture(t)

	w, err := bn254witness.GenerateWitness(fix.vk, fix.proof, fix.publicInputs)
	if err != nil {
		t.Fatalf("GenerateWitness: %v", err)
	}
	if len(w.MillerGradients) == 0 {
		t.Fatal("no Miller gradients generated — synthetic instance produced an empty chain")
	}

	// Tamper: bump the first gradient by 1 mod p. Still a valid Fp value
	// (push encoding succeeds, SDK accepts) but no longer the honest
	// slope, so λ·(2·Ty) == 3·Tx² fails inside the gradient verifier.
	q := codegen.Bn254FieldPrime()
	w.MillerGradients[0] = new(big.Int).Mod(
		new(big.Int).Add(w.MillerGradients[0], big.NewInt(1)),
		q,
	)

	assertForgedSpendRejectedOnChain(t, fix, w, "bad Miller gradient")
}

// -----------------------------------------------------------------------
// Forgery #3: bad subgroup-check gradient on proof.B
// -----------------------------------------------------------------------

// TestGroth16WASDK_ForgedProof_BadSubgroupGradient verifies the SDK call
// path rejects a proof whose ProofBSubgroupGradients chain is
// inconsistent — i.e. an attempt to defeat the G2 prime-order subgroup
// check on proof.B without providing an honest [6·x²]·B chain. The
// emitted preamble runs emitWAG2SubgroupCheck which consumes these
// gradients and asserts the final accumulator equals ψ(B).
//
// We deliberately tamper a subgroup gradient (not a Miller gradient or
// a proof coordinate) so this test fails on a different on-chain
// soundness boundary than the other two — exercising a third independent
// rejection axis.
func TestGroth16WASDK_ForgedProof_BadSubgroupGradient(t *testing.T) {
	fix := buildForgedTestFixture(t)

	w, err := bn254witness.GenerateWitness(fix.vk, fix.proof, fix.publicInputs)
	if err != nil {
		t.Fatalf("GenerateWitness: %v", err)
	}
	if len(w.ProofBSubgroupGradients) == 0 {
		t.Fatal("no subgroup-check gradients generated — synthetic instance produced an empty chain")
	}

	// Tamper the first subgroup-doubling gradient.
	q := codegen.Bn254FieldPrime()
	w.ProofBSubgroupGradients[0] = new(big.Int).Mod(
		new(big.Int).Add(w.ProofBSubgroupGradients[0], big.NewInt(1)),
		q,
	)

	assertForgedSpendRejectedOnChain(t, fix, w, "bad subgroup gradient")
}
