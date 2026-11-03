package compiler

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// ---------------------------------------------------------------------------
// R-011 — public-input binding of the deployable Groth16 verifier.
//
// `CompileGroth16WA` is the only standalone path that produces a deployable
// Groth16 verifier artifact. If the locking script it bakes does not tie
// prepared_inputs to a FIXED public-input vector, the artifact proves
// "somebody proved something", not "somebody proved the statement this
// output is about": an attacker picks a public-input vector of their own
// choosing, mints an honest proof for it, computes the matching
// prepared_inputs, and spends.
//
// The tests below construct exactly that attack against the compiled
// artifact and run it through the go-sdk script interpreter.
// ---------------------------------------------------------------------------

// synthGroth16 is a Groth16 verifying key whose discrete logs (relative to
// the BN254 generators) we know, which lets the test mint a mathematically
// VALID proof for ANY public-input vector. That capability is what makes the
// attack constructible; a real SP1 VK would require the proving key.
//
// Layout (all points are scalar multiples of the generators):
//
//	α = a·G1   β = b·G2   γ = c·G2   δ = d·G2   IC[j] = m_j·G1
//
// For a public-input vector P the prepared-inputs accumulator is
//
//	L = IC[0] + Σ_j P_j·IC[j+1] = ℓ·G1,  ℓ = m_0 + Σ_j P_j·m_{j+1}
//
// and the SP1-convention verification equation
//
//	e(A, B) · e(L, -γ) · e(C, -δ) · e(α, -β) = 1
//
// reduces, in e(G1,G2) exponent space, to
//
//	A_e·B_e − ℓ·c − C_e·d − a·b = 0.
//
// Fixing B = G2 (B_e = 1) and C = G1 (C_e = 1) leaves A_e = a·b + ℓ·c + d,
// so a valid proof exists for every P.
type synthGroth16 struct {
	vk     bn254witness.VerifyingKey
	vkPath string
	icScal [6]*big.Int
	aExp   *big.Int
	bExp   *big.Int
	cExp   *big.Int
	dExp   *big.Int
}

func synthScalarMulG1(k *big.Int) bn254.G1Affine {
	_, _, g1, _ := bn254.Generators()
	var p bn254.G1Affine
	p.ScalarMultiplication(&g1, new(big.Int).Mod(k, fr.Modulus()))
	return p
}

func synthScalarMulG2(k *big.Int) bn254.G2Affine {
	_, _, _, g2 := bn254.Generators()
	var p bn254.G2Affine
	p.ScalarMultiplication(&g2, new(big.Int).Mod(k, fr.Modulus()))
	return p
}

// newSynthGroth16 builds the synthetic 5-public-input VK and writes it to a
// temp-dir vk.json in the SP1 fixture schema, so it can be fed to
// CompileGroth16WA exactly like a real verifying key.
func newSynthGroth16(t *testing.T) *synthGroth16 {
	t.Helper()

	s := &synthGroth16{
		icScal: [6]*big.Int{
			big.NewInt(2), big.NewInt(3), big.NewInt(5),
			big.NewInt(7), big.NewInt(11), big.NewInt(13),
		},
		aExp: big.NewInt(7),
		bExp: big.NewInt(11),
		cExp: big.NewInt(13),
		dExp: big.NewInt(17),
	}

	ic := make([]bn254.G1Affine, 6)
	for i := range ic {
		ic[i] = synthScalarMulG1(s.icScal[i])
	}

	s.vk = bn254witness.NewVerifyingKeyFromPositive(
		synthScalarMulG1(s.aExp),
		synthScalarMulG2(s.bExp),
		synthScalarMulG2(s.cExp),
		synthScalarMulG2(s.dExp),
		ic,
	)

	s.vkPath = filepath.Join(t.TempDir(), "synth.groth16.vk.json")
	writeSP1VKJSON(t, s.vk, s.vkPath)
	return s
}

// proofFor mints a valid Groth16 proof for the supplied public-input vector.
func (s *synthGroth16) proofFor(pubs []*big.Int) bn254witness.Proof {
	r := fr.Modulus()

	ell := new(big.Int).Set(s.icScal[0])
	for j, p := range pubs {
		term := new(big.Int).Mul(new(big.Int).Mod(p, r), s.icScal[j+1])
		ell.Add(ell, term)
	}
	ell.Mod(ell, r)

	// A_e = a·b + ℓ·c + d   (with B_e = 1, C_e = 1)
	aPoint := new(big.Int).Mul(s.aExp, s.bExp)
	aPoint.Add(aPoint, new(big.Int).Mul(ell, s.cExp))
	aPoint.Add(aPoint, s.dExp)
	aPoint.Mod(aPoint, r)

	return bn254witness.GnarkProofToWitnessInputs(
		synthScalarMulG1(aPoint),
		synthScalarMulG2(big.NewInt(1)),
		synthScalarMulG1(big.NewInt(1)),
	)
}

// sanityCheck verifies, off-chain via gnark's pairing, that the minted proof
// really does satisfy the Groth16 equation for `pubs`. If this fails the test
// harness itself is broken and no conclusion about the script is warranted.
func (s *synthGroth16) sanityCheck(t *testing.T, proof bn254witness.Proof, pubs []*big.Int) {
	t.Helper()
	r := fr.Modulus()

	ell := new(big.Int).Set(s.icScal[0])
	for j, p := range pubs {
		ell.Add(ell, new(big.Int).Mul(new(big.Int).Mod(p, r), s.icScal[j+1]))
	}
	prepared := synthScalarMulG1(ell)

	toG1 := func(v [2]*big.Int) bn254.G1Affine {
		var p bn254.G1Affine
		p.X.SetBigInt(v[0])
		p.Y.SetBigInt(v[1])
		return p
	}
	toG2 := func(v [4]*big.Int) bn254.G2Affine {
		var p bn254.G2Affine
		p.X.A0.SetBigInt(v[0])
		p.X.A1.SetBigInt(v[1])
		p.Y.A0.SetBigInt(v[2])
		p.Y.A1.SetBigInt(v[3])
		return p
	}

	gt, err := bn254.Pair(
		[]bn254.G1Affine{toG1(proof.A), prepared, toG1(proof.C), synthScalarMulG1(s.aExp)},
		[]bn254.G2Affine{toG2(proof.B), toG2(s.vk.GammaNegG2), toG2(s.vk.DeltaNegG2), toG2(s.vk.BetaNegG2)},
	)
	if err != nil {
		t.Fatalf("gnark Pair: %v", err)
	}
	var one bn254.E12
	one.SetOne()
	if !gt.Equal(&one) {
		t.Fatalf("synthetic Groth16 instance is not valid off-chain: pairing = %s", gt.String())
	}
}

// writeSP1VKJSON serializes a VerifyingKey into the SP1 fixture vk.json
// schema consumed by bn254witness.LoadSP1VKFromFile.
func writeSP1VKJSON(t *testing.T, vk bn254witness.VerifyingKey, path string) {
	t.Helper()

	type g1JSON struct {
		X string `json:"x"`
		Y string `json:"y"`
	}
	type g2JSON struct {
		X0 string `json:"x0"`
		X1 string `json:"x1"`
		Y0 string `json:"y0"`
		Y1 string `json:"y1"`
	}
	type vkJSON struct {
		Version      string   `json:"version"`
		Curve        string   `json:"curve"`
		NumPubInputs int      `json:"numPubInputs"`
		Convention   string   `json:"convention"`
		AlphaG1      g1JSON   `json:"alphaG1"`
		BetaNegG2    g2JSON   `json:"betaNegG2"`
		GammaNegG2   g2JSON   `json:"gammaNegG2"`
		DeltaNegG2   g2JSON   `json:"deltaNegG2"`
		IC           []g1JSON `json:"ic"`
	}

	mkG1 := func(p [2]*big.Int) g1JSON {
		return g1JSON{X: p[0].String(), Y: p[1].String()}
	}
	mkG2 := func(p [4]*big.Int) g2JSON {
		return g2JSON{X0: p[0].String(), X1: p[1].String(), Y0: p[2].String(), Y1: p[3].String()}
	}

	out := vkJSON{
		Version:      "synthetic",
		Curve:        "bn254",
		NumPubInputs: len(vk.IC) - 1,
		Convention:   "sp1-negated",
		AlphaG1:      mkG1(vk.AlphaG1),
		BetaNegG2:    mkG2(vk.BetaNegG2),
		GammaNegG2:   mkG2(vk.GammaNegG2),
		DeltaNegG2:   mkG2(vk.DeltaNegG2),
	}
	for _, p := range vk.IC {
		out.IC = append(out.IC, mkG1(*p))
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatalf("marshal synthetic vk.json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write synthetic vk.json: %v", err)
	}
}

// executeArtifactWithWitness deploys the artifact to a fixed owner key and
// spends it with [witness pushes ‖ owner signature] through the go-sdk
// Bitcoin Script interpreter with full transaction context (F-233: the
// standalone verifier opens with `<ownerPubKey> OP_CHECKSIGVERIFY`). The
// signature is always the owner's own, valid one, so a rejection here comes
// from the proof-verification half of the script. Returns nil when the
// script succeeds.
func executeArtifactWithWitness(t *testing.T, art *Artifact, w *bn254witness.Witness) error {
	t.Helper()

	owner := groth16TestKey(0x11)
	lockHex := groth16DeployedLockHex(t, art, owner.PubKey().Compressed())
	tx, prevOut := groth16SpendTx(t, lockHex, groth16PayTo(0x11))
	groth16SetUnlock(t, tx, groth16HonestUnlockHex(t, art, tx, groth16WitnessHex(t, w), owner))
	return groth16ExecuteSpend(tx, prevOut)
}

// witnessLayout is the shape of the unlocking-script stack a compiled
// artifact expects. The raw verifier variant reads no public-input scalars;
// the MSM-binding variant reads five of them between the final-exp witnesses
// and prepared_inputs. Which one a given artifact wants is a property of the
// backend, so the tests below DISCOVER it from the honest spend rather than
// assuming it — otherwise a layout mismatch would fail the attack spend for
// a reason that has nothing to do with public-input binding, and the test
// would "pass" while proving nothing.
type witnessLayout int

const (
	layoutRaw witnessLayout = iota
	layoutMSM
)

func (l witnessLayout) String() string {
	if l == layoutMSM {
		return "msm (5 public-input scalars on the witness stack)"
	}
	return "raw (no public-input scalars on the witness stack)"
}

func buildWitness(t *testing.T, layout witnessLayout, vk bn254witness.VerifyingKey, proof bn254witness.Proof, pubs []*big.Int) *bn254witness.Witness {
	t.Helper()
	var (
		w   *bn254witness.Witness
		err error
	)
	if layout == layoutMSM {
		w, err = bn254witness.BuildFromProofWithInputs(vk, proof, pubs)
	} else {
		w, err = bn254witness.GenerateWitness(vk, proof, pubs)
	}
	if err != nil {
		t.Fatalf("build witness (%s): %v", layout, err)
	}
	return w
}

// detectLayout runs the honest spend in each layout and returns the one the
// artifact accepts. Failing to find one means the verifier rejects even a
// valid proof of the pinned statement, which invalidates every conclusion
// the attack tests would otherwise draw.
func detectLayout(t *testing.T, art *Artifact, vk bn254witness.VerifyingKey, proof bn254witness.Proof, pubs []*big.Int) witnessLayout {
	t.Helper()
	for _, layout := range []witnessLayout{layoutMSM, layoutRaw} {
		w := buildWitness(t, layout, vk, proof, pubs)
		if err := executeArtifactWithWitness(t, art, w); err == nil {
			return layout
		}
	}
	t.Fatal("the honest spend was rejected in BOTH witness layouts — the compiled verifier does not accept a valid proof of its own statement; no conclusion about forgery resistance is possible")
	return layoutRaw
}

// honestPublicInputs mirrors the real SP1 v6.0.0 fixture's public-input
// shape (three nonzero scalars, two exactly zero) so the test exercises the
// zero-scalar path of the on-chain MSM.
func honestPublicInputs(t *testing.T) []*big.Int {
	t.Helper()
	dec := func(s string) *big.Int {
		v, ok := new(big.Int).SetString(s, 10)
		if !ok {
			t.Fatalf("bad decimal literal %q", s)
		}
		return v
	}
	return []*big.Int{
		dec("66357586313644860799771794752501372267945898538662503063451090361394363786"),
		dec("847835036251654310728024989634801415315612733526607753937102182742950003855"),
		big.NewInt(0),
		dec("248831628400185611740479071450564250193912070693925013182243127282342200944"),
		big.NewInt(0),
	}
}

// attackerPublicInputs is a DIFFERENT statement the attacker chooses for
// themselves: honest vector with the first scalar bumped by one.
func attackerPublicInputs(t *testing.T) []*big.Int {
	t.Helper()
	pubs := honestPublicInputs(t)
	pubs[0] = new(big.Int).Add(pubs[0], big.NewInt(1))
	return pubs
}

// TestCompileGroth16WA_RejectsProofOfAnUnpinnedStatement is the R-011 gate.
//
// The attacker never touches the proof, the gradients, or the field prime:
// every one of those stays internally consistent. They simply pick a public
// input vector of their own choosing, mint an honest proof for it, and push
// the matching prepared_inputs — a perfectly valid on-curve BN254 G1 point
// that is NOT IC[0] + Σ pub_j·IC[j+1] for the vector this artifact is
// supposed to be about.
//
// A deployable verifier that binds its public inputs MUST reject that spend.
// A verifier whose only check on prepared_inputs is an on-curve test accepts
// it, and therefore attests to a statement the deployer never chose.
func TestCompileGroth16WA_RejectsProofOfAnUnpinnedStatement(t *testing.T) {
	s := newSynthGroth16(t)

	honest := honestPublicInputs(t)
	attacker := attackerPublicInputs(t)

	honestProof := s.proofFor(honest)
	attackerProof := s.proofFor(attacker)
	s.sanityCheck(t, honestProof, honest)
	s.sanityCheck(t, attackerProof, attacker)

	art, err := CompileGroth16WA(s.vkPath, Groth16WAOpts{PublicInputs: honest})
	if err != nil {
		t.Fatalf("CompileGroth16WA: %v", err)
	}

	// Control: establish that the artifact accepts a valid proof of its own
	// pinned statement, and learn which witness layout it wants.
	layout := detectLayout(t, art, s.vk, honestProof, honest)
	t.Logf("artifact accepts the honest spend in layout: %s", layout)

	// The attack: a self-consistent proof of the attacker's OWN statement.
	// Every component is internally valid — only the STATEMENT differs.
	attackWitness := buildWitness(t, layout, s.vk, attackerProof, attacker)
	if err := executeArtifactWithWitness(t, art, attackWitness); err == nil {
		t.Fatal("FORGERY ACCEPTED: the compiled Groth16 artifact validated a proof of a public-input vector the deployer never pinned; the verifier attests that *some* statement was proven, not *this* one")
	}
}

// TestCompileGroth16WA_RejectsForgedPreparedInputsForPinnedInputs is the
// narrower form of the same attack, and the one R-011 names literally: the
// attacker pushes the CORRECT public-input scalars (so any per-scalar pin
// check passes) but a prepared_inputs point that is a valid on-curve BN254
// G1 point which is NOT IC[0] + Σ pub_j·IC[j+1] for them. Only an on-chain
// recomputation of the accumulator catches this.
func TestCompileGroth16WA_RejectsForgedPreparedInputsForPinnedInputs(t *testing.T) {
	s := newSynthGroth16(t)

	honest := honestPublicInputs(t)
	attacker := attackerPublicInputs(t)
	honestProof := s.proofFor(honest)
	attackerProof := s.proofFor(attacker)
	s.sanityCheck(t, honestProof, honest)
	s.sanityCheck(t, attackerProof, attacker)

	art, err := CompileGroth16WA(s.vkPath, Groth16WAOpts{PublicInputs: honest})
	if err != nil {
		t.Fatalf("CompileGroth16WA: %v", err)
	}

	layout := detectLayout(t, art, s.vk, honestProof, honest)

	// Witness for the attacker's statement...
	w := buildWitness(t, layout, s.vk, attackerProof, attacker)
	// ...but with the declared public-input scalars swapped back to the
	// pinned ones. prepared_inputs still encodes the attacker's vector.
	if layout == layoutMSM {
		for i := 0; i < 5; i++ {
			w.PublicInputs[i] = new(big.Int).Set(honest[i])
		}
	}

	// The forged accumulator must still be a genuine curve point, or this
	// test would only be re-proving the pre-existing on-curve check.
	assertOnCurveG1(t, w.PreparedInputs)

	if err := executeArtifactWithWitness(t, art, w); err == nil {
		t.Fatal("FORGERY ACCEPTED: prepared_inputs was on-curve but not the MSM of the pinned public inputs, and the script still validated")
	}
}

// TestCompileGroth16WA_RefusesWithoutPinnedPublicInputs asserts that the
// backend cannot be used to mint an unbound verifier by omission. An
// artifact with no pinned public inputs is not deployable, so compilation
// must fail loudly rather than emit one.
func TestCompileGroth16WA_RefusesWithoutPinnedPublicInputs(t *testing.T) {
	s := newSynthGroth16(t)

	if _, err := CompileGroth16WA(s.vkPath, Groth16WAOpts{}); err == nil {
		t.Fatal("CompileGroth16WA produced an artifact with no pinned public inputs; such a verifier binds nothing")
	}

	wrongArity := honestPublicInputs(t)[:4]
	if _, err := CompileGroth16WA(s.vkPath, Groth16WAOpts{PublicInputs: wrongArity}); err == nil {
		t.Fatal("CompileGroth16WA accepted 4 pinned public inputs for a 5-input verifying key")
	}
}

// assertOnCurveG1 fails the test unless (x, y) satisfies y² = x³ + 3 over
// the BN254 base field — i.e. unless the forged point is a real G1 point.
func assertOnCurveG1(t *testing.T, p [2]*big.Int) {
	t.Helper()
	var g bn254.G1Affine
	if _, err := g.X.SetString(p[0].String()); err != nil {
		t.Fatalf("forged prepared_inputs.x is not an Fp element: %v", err)
	}
	if _, err := g.Y.SetString(p[1].String()); err != nil {
		t.Fatalf("forged prepared_inputs.y is not an Fp element: %v", err)
	}
	if !g.IsOnCurve() {
		t.Fatal(fmt.Sprintf("forged prepared_inputs (%s, %s) is not on the BN254 curve; the test would only be re-proving the existing on-curve check", p[0], p[1]))
	}
}

// TestGroth16WAMSM_PublicInputAtOrderRRejected — F-036, policy per N-035
// (user decision R86a: reject non-canonical public inputs).
//
// The attack witness: pub_0 = r (the BN254 Fr order), with a proof and a
// prepared_inputs honestly derived — by the SDK itself,
// bn254witness.BuildFromProofWithInputs — as if pub_0 were 0. The SDK
// reduces pub_i mod r, so it considers pub_0 = r and pub_0 = 0 the same
// statement and hands back the SAME prepared_inputs for both (asserted
// below). The MSM binding alone would bind it as 0 (F-036), but the full
// verifier must REJECT it: pub_0 = r is not a canonical Fr element, and
// accepting it would let a spender show groth16PublicInput(0), the
// CompileGroth16WA pins and the txid a value other than the one the proof
// is about (gnark: PublicInputNotInField).
//
// The verifier is emitted WITHOUT CompileGroth16WA's compile-time pins
// (those would refuse pub_0 = r on their own and mask the preamble's range
// check); this is the shape the Mode-3 groth16PublicInput(i) path embeds.
//
// Proves: the full MSM-binding verifier, executed on the go-sdk
// interpreter, accepts the honest spend (pub_0 = 0) and rejects the
// non-canonical pub_0 = r even though its prepared_inputs are exactly the
// honest ones. Does NOT prove: that the SDK refuses to build such a witness
// (it does not; tracked as N-232).
func TestGroth16WAMSM_PublicInputAtOrderRRejected(t *testing.T) {
	s := newSynthGroth16(t)

	honest := honestPublicInputs(t)
	honest[0] = big.NewInt(0)
	adversarial := honestPublicInputs(t)
	adversarial[0] = new(big.Int).Set(fr.Modulus())

	proof := s.proofFor(honest)
	s.sanityCheck(t, proof, honest)
	// proofFor reduces mod r too (B and C are fixed), so the two statements
	// share a proof; if they did not, the premise below would be false.
	adv := s.proofFor(adversarial)
	for i := range adv.A {
		if adv.A[i].Cmp(proof.A[i]) != 0 {
			t.Fatal("proofFor(pub_0 = r) differs from proofFor(pub_0 = 0); harness premise broken")
		}
	}

	config, err := loadGroth16WAConfig(s.vkPath)
	if err != nil {
		t.Fatalf("loadGroth16WAConfig: %v", err)
	}
	var ops []codegen.StackOp
	codegen.EmitGroth16VerifierWitnessAssistedWithMSM(func(op codegen.StackOp) {
		ops = append(ops, op)
	}, config)
	ops = codegen.OptimizeStackOps(ops)
	ops = codegen.OptimizeBN254Ops(ops)
	emitted, err := codegen.Emit([]codegen.StackMethod{{Name: "verify", Ops: ops}})
	if err != nil {
		t.Fatalf("emit MSM verifier: %v", err)
	}
	art := &Artifact{Script: emitted.ScriptHex}

	honestW, err := bn254witness.BuildFromProofWithInputs(s.vk, proof, honest)
	if err != nil {
		t.Fatalf("BuildFromProofWithInputs(honest): %v", err)
	}
	// pub_0 = r is non-canonical; since N-232, BuildFromProofWithInputs
	// refuses it. This test's whole point is to prove the SCRIPT rejects
	// that witness even though its prepared_inputs matches the honest
	// one — so it must use the test-only unchecked builder to construct
	// the adversarial witness BuildFromProofWithInputs itself now refuses.
	advW, err := bn254witness.BuildFromProofWithInputsUnchecked(s.vk, proof, adversarial)
	if err != nil {
		t.Fatalf("BuildFromProofWithInputsUnchecked(pub_0 = r): %v", err)
	}
	// The SDK's view: pub_0 = r and pub_0 = 0 give the same accumulator.
	for i := 0; i < 2; i++ {
		if advW.PreparedInputs[i].Cmp(honestW.PreparedInputs[i]) != 0 {
			t.Fatalf("SDK premise broken: prepared_inputs(pub_0 = r) != prepared_inputs(pub_0 = 0) at coord %d", i)
		}
	}
	if advW.PublicInputs[0].Cmp(fr.Modulus()) != 0 {
		t.Fatalf("witness must carry the raw pub_0 = r, got %s", advW.PublicInputs[0])
	}

	// Control: the honest witness verifies.
	if err := executeArtifactWithWitness(t, art, honestW); err != nil {
		t.Fatalf("honest MSM spend rejected: %v", err)
	}
	// pub_0 = r binds the same accumulator but is not canonical: reject.
	if err := executeArtifactWithWitness(t, art, advW); err == nil {
		t.Fatal("non-canonical pub_0 = r accepted")
	}
}

// TestGroth16WAMSM_RejectsNonCanonicalPublicInput — N-035 (GK-BUG-008),
// user decision R86a "switch to reject".
//
// The MSM binding reduces each witness-supplied pub_i mod r (F-036), so
// pub_i, pub_i + k·r and pub_i − r all bind the same prepared_inputs. If the
// script accepted them, the contract body (groth16PublicInput(i)), the
// CompileGroth16WA pins and the txid would see a number other than the one
// the proof is about, and any observer could re-encode an honest spend's
// public input. The verifier must therefore REJECT any pub_i outside
// [0, r), as gnark (PublicInputNotInField) and SP1's Solidity verifier do.
//
// The contract is compiled through the real pipeline (CompileFromSource with
// the synthetic VK). Its body is assert(groth16PublicInput(0) != 8): it
// accepts every canonical value except 8, so a rejection of 7 + 3r or 7 − r
// cannot come from the body — only from the binding preamble. Spends run on
// the go-sdk interpreter:
//
//  1. canonical pub_0 = 7 (proof for 7) — accepted (control);
//  2. pub_0 = 7 + 3r, same proof, SDK-derived prepared_inputs (≡ 7) —
//     rejected;
//  3. pub_0 = 7 − r (negative, ≡ 7), same proof — rejected;
//  4. canonical pub_0 = 8 with a VALID proof for 8 — rejected by the body,
//     which shows the body still reads and checks the value.
//
// Proves: the MSM-binding verifier refuses non-canonical representatives of
// a public input that its MSM would otherwise bind, so the value the body
// sees is the canonical witness value. Does NOT prove: slots 1–4 beyond
// sharing the same per-slot loop, rejection by a real node, or that the SDK
// witness builders refuse such inputs (they do not; they reduce).
func TestGroth16WAMSM_RejectsNonCanonicalPublicInput(t *testing.T) {
	s := newSynthGroth16(t)

	withPub0 := func(v *big.Int) []*big.Int {
		pubs := honestPublicInputs(t)
		pubs[0] = v
		return pubs
	}
	canonical := withPub0(big.NewInt(7))
	proof := s.proofFor(canonical)
	s.sanityCheck(t, proof, canonical)

	src := `
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type MSMCanonicalBody struct {
	runar.SmartContract
}

func (c *MSMCanonicalBody) Verify() {
	runar.AssertGroth16WitnessAssistedWithMSM()
	runar.Assert(runar.Groth16PublicInput(0) != 8)
}
`
	srcPath := filepath.Join(t.TempDir(), "MSMCanonicalBody.runar.go")
	if err := os.WriteFile(srcPath, []byte(src), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	art, err := CompileFromSource(srcPath, CompileOptions{Groth16WAVKey: s.vkPath})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(art.ConstructorSlots) != 0 {
		t.Fatalf("expected no constructor slots, got %+v", art.ConstructorSlots)
	}

	// build uses the TEST-ONLY unchecked constructor: since N-232,
	// BuildFromProofWithInputs itself refuses non-canonical pub_i values
	// (7+3r, 7-r below), so this helper — whose job is to hand the
	// adversarial witness to the SCRIPT and prove IT rejects it — must
	// bypass that refusal to even construct the witness.
	build := func(p bn254witness.Proof, pubs []*big.Int) *bn254witness.Witness {
		w, err := bn254witness.BuildFromProofWithInputsUnchecked(s.vk, p, pubs)
		if err != nil {
			t.Fatalf("BuildFromProofWithInputsUnchecked: %v", err)
		}
		return w
	}

	// (1) Control.
	canonW := build(proof, canonical)
	if err := executeArtifactWithWitness(t, art, canonW); err != nil {
		t.Fatalf("canonical spend (pub_0 = 7) rejected; harness broken: %v", err)
	}

	r := fr.Modulus()
	nonCanonical := []struct {
		name string
		v    *big.Int
	}{
		{"7+3r", new(big.Int).Add(big.NewInt(7), new(big.Int).Mul(big.NewInt(3), r))},
		{"7-r", new(big.Int).Sub(big.NewInt(7), r)},
	}
	for _, nc := range nonCanonical {
		// (2), (3): the witness carries the raw value, and the SDK binds it
		// exactly as it binds 7 — so only a canonicity check can refuse it.
		w := build(proof, withPub0(nc.v))
		if w.PublicInputs[0].Cmp(nc.v) != 0 {
			t.Fatalf("%s: witness must carry the raw pub_0, got %s", nc.name, w.PublicInputs[0])
		}
		for i := 0; i < 2; i++ {
			if w.PreparedInputs[i].Cmp(canonW.PreparedInputs[i]) != 0 {
				t.Fatalf("%s: SDK premise broken: prepared_inputs differ from pub_0 = 7 at coord %d", nc.name, i)
			}
		}
		if err := executeArtifactWithWitness(t, art, w); err == nil {
			t.Fatalf("non-canonical public input accepted by the binding: pub_0 = %s (≡ 7 mod r) was spent; the verifier must reject pub_i outside [0, r)", nc.name)
		}
	}

	// (4) pub_0 = 8 with a valid proof for 8: the binding accepts it, the
	// body must not.
	eight := withPub0(big.NewInt(8))
	proof8 := s.proofFor(eight)
	s.sanityCheck(t, proof8, eight)
	if err := executeArtifactWithWitness(t, art, build(proof8, eight)); err == nil {
		t.Fatal("pub_0 = 8 was accepted by a body asserting groth16PublicInput(0) != 8")
	}
}
