package codegen_test

// GK-BUG-005 — forged final-exponentiation witnesses against the
// witness-assisted Groth16 verifiers, executed on the go-sdk interpreter.
//
// The original finding: emitWAFinalExp took a = f2^x, b = f2^x², c = f2^x³
// from the unlocking script and never checked them, so scaling ONE of them
// by d = R^(-(E^-1 mod r)) (R the honest result of a false statement, E that
// slot's exponent) forced the script's result to 1. On the vulnerable code
// this file's predecessor accepted all six such forgeries (a, b, c × raw and
// WithMSM) while both controls passed.
//
// The fix replaces the final exponentiation by a residue witness (Novakovic
// & Eagen, eprint 2024/640): the prover supplies c, c⁻¹ and s ∈ {0, 1, 2},
// and the script accepts iff c·c⁻¹ == 1 and f·ω^s == c^λ, λ = 6x+2+p−p²+p³
// (derivation in bn254_groth16.go). The witness layout changed, so the
// forgeries below are the ones that make sense against the new scheme; the
// INTENT is unchanged: for a FALSE statement no witness may pass, the honest
// valid proof passes, and the honest generator's output for a false
// statement is rejected.
//
// Setup: the real SP1 v6.0.0 VK + proof (tests/vectors/sp1/v6.0.0) and an
// attacker-chosen public-input vector (pub_0 + 1). Every Miller gradient,
// prepared_inputs and the MSM scalars are honest for that false statement;
// only the residue witness is forged.
//
// gk005ScriptResult mirrors the script's arithmetic exactly (the folded
// exponents E₊/E₋ of the NAF, then c⁻¹^p · c^p² · c⁻¹^p³ written as integer
// exponents), recomputed here from p, x and the NAF — not from the code under
// test. Each negative first states, off-chain, why it must fail (or, for the
// inverse-check case, that ONLY the inverse check can make it fail), then
// requires the interpreter to abort.

import (
	"crypto/sha256"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

func gk005LoadSP1(t *testing.T) (bn254witness.VerifyingKey, bn254witness.Proof, []*big.Int) {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "tests", "vectors", "sp1", "v6.0.0")
	vk, err := bn254witness.LoadSP1VKFromFile(filepath.Join(dir, "vk.json"))
	if err != nil {
		t.Fatalf("LoadSP1VKFromFile: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "groth16_raw_proof.hex"))
	if err != nil {
		t.Fatalf("read raw proof: %v", err)
	}
	proof, err := bn254witness.ParseSP1RawProof(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("ParseSP1RawProof: %v", err)
	}
	pubs, err := bn254witness.LoadSP1PublicInputs(filepath.Join(dir, "groth16_public_inputs.txt"))
	if err != nil {
		t.Fatalf("LoadSP1PublicInputs: %v", err)
	}
	if len(pubs) != 5 {
		t.Fatalf("expected 5 public inputs, got %d", len(pubs))
	}
	return vk, proof, pubs
}

func gk005AttackerPubs(honest []*big.Int) []*big.Int {
	out := make([]*big.Int, len(honest))
	for i, v := range honest {
		out[i] = new(big.Int).Set(v)
	}
	out[0].Add(out[0], big.NewInt(1))
	return out
}

func gk005FlatToE12(flat [12]*big.Int) bn254.E12 {
	var z bn254.E12
	z.C0.B0.A0.SetBigInt(flat[0])
	z.C0.B0.A1.SetBigInt(flat[1])
	z.C0.B1.A0.SetBigInt(flat[2])
	z.C0.B1.A1.SetBigInt(flat[3])
	z.C0.B2.A0.SetBigInt(flat[4])
	z.C0.B2.A1.SetBigInt(flat[5])
	z.C1.B0.A0.SetBigInt(flat[6])
	z.C1.B0.A1.SetBigInt(flat[7])
	z.C1.B1.A0.SetBigInt(flat[8])
	z.C1.B1.A1.SetBigInt(flat[9])
	z.C1.B2.A0.SetBigInt(flat[10])
	z.C1.B2.A1.SetBigInt(flat[11])
	return z
}

func gk005E12ToFlat(z *bn254.E12) [12]*big.Int {
	var out [12]*big.Int
	coords := []*fp.Element{
		&z.C0.B0.A0, &z.C0.B0.A1, &z.C0.B1.A0, &z.C0.B1.A1, &z.C0.B2.A0, &z.C0.B2.A1,
		&z.C1.B0.A0, &z.C1.B0.A1, &z.C1.B1.A0, &z.C1.B1.A1, &z.C1.B2.A0, &z.C1.B2.A1,
	}
	for i, c := range coords {
		out[i] = new(big.Int)
		c.BigInt(out[i])
	}
	return out
}

// gk005Params are the residue-check constants, derived in the test.
type gk005Params struct {
	n, p, lambda *big.Int
	ePlus, eMin  *big.Int // NAF folds: c⁻¹^E₊ · c^E₋ = c^-(6x+2)
	eCInv, eC    *big.Int // whole script: c⁻¹^eCInv · c^eC = c^-λ
	omega        bn254.E12
}

func gk005Derive(t *testing.T) gk005Params {
	t.Helper()
	var P gk005Params
	P.p = fp.Modulus()
	x, _ := new(big.Int).SetString("4965661367192848881", 10)
	p2 := new(big.Int).Mul(P.p, P.p)
	p3 := new(big.Int).Mul(p2, P.p)
	P.n = new(big.Int).Exp(P.p, big.NewInt(12), nil)
	P.n.Sub(P.n, big.NewInt(1))

	s0 := new(big.Int).Add(new(big.Int).Mul(big.NewInt(6), x), big.NewInt(2))
	P.lambda = new(big.Int).Add(s0, P.p)
	P.lambda.Sub(P.lambda, p2)
	P.lambda.Add(P.lambda, p3)
	if new(big.Int).Mod(P.lambda, fr.Modulus()).Sign() != 0 {
		t.Fatal("premise: lambda is not a multiple of r")
	}

	naf := codegen.Bn254SixXPlus2NAF()
	P.ePlus, P.eMin = new(big.Int), new(big.Int)
	for i, d := range naf {
		bit := new(big.Int).Lsh(big.NewInt(1), uint(i))
		switch d {
		case 1:
			P.ePlus.Add(P.ePlus, bit)
		case -1:
			P.eMin.Add(P.eMin, bit)
		}
	}
	if new(big.Int).Sub(P.ePlus, P.eMin).Cmp(s0) != 0 {
		t.Fatal("premise: the NAF does not encode 6x+2")
	}
	P.eCInv = new(big.Int).Add(P.ePlus, P.p)
	P.eCInv.Add(P.eCInv, p3)
	P.eC = new(big.Int).Add(P.eMin, p2)
	if new(big.Int).Sub(P.eCInv, P.eC).Cmp(P.lambda) != 0 {
		t.Fatal("premise: folded exponents do not add up to lambda")
	}

	P.omega = gk005FlatToE12(codegen.Bn254ResidueOmega27())
	var w, def bn254.E12
	w.C1.B0.A0.SetOne()
	def.Exp(w, new(big.Int).Div(P.n, big.NewInt(27)))
	if !def.Equal(&P.omega) {
		t.Fatal("premise: codegen omega != w^((p^12-1)/27)")
	}
	return P
}

func gk005Pow(x bn254.E12, e, n *big.Int) bn254.E12 {
	var z bn254.E12
	z.Exp(x, new(big.Int).Mod(e, n))
	return z
}

// gk005ScriptResult is the value the script finally compares with 1:
// f · ω^s · c⁻¹^eCInv · c^eC (s taken as the script would map it if it had
// no range check: s != 0 → (s-1 != 0 → ω² : ω) : 1).
func gk005ScriptResult(P gk005Params, f, c, cInv bn254.E12, s int64) bn254.E12 {
	k := int64(0)
	if s != 0 {
		k = 1
		if s-1 != 0 {
			k = 2
		}
	}
	om := gk005Pow(P.omega, big.NewInt(k), P.n)
	a := gk005Pow(cInv, P.eCInv, P.n)
	b := gk005Pow(c, P.eC, P.n)
	var r bn254.E12
	r.Mul(&f, &om).Mul(&r, &a).Mul(&r, &b)
	return r
}

// gk005CubeRoot returns a cube root of z (which must be a cube), by the
// 27-Sylow split n = 27·t: the order-t part has the cube root z^(3⁻¹ mod t),
// the order-27 part lies in <ω³>.
func gk005CubeRoot(t *testing.T, P gk005Params, z bn254.E12) bn254.E12 {
	t.Helper()
	t27 := new(big.Int).Div(P.n, big.NewInt(27))
	toT := new(big.Int).Mul(big.NewInt(27), new(big.Int).ModInverse(big.NewInt(27), t27))
	to27 := new(big.Int).Mul(t27, new(big.Int).ModInverse(new(big.Int).Mod(t27, big.NewInt(27)), big.NewInt(27)))
	zt := gk005Pow(z, toT, P.n)
	z27 := gk005Pow(z, to27, P.n)
	ct := gk005Pow(zt, new(big.Int).ModInverse(big.NewInt(3), t27), P.n)
	for k := int64(0); k < 9; k++ {
		w3k := gk005Pow(P.omega, big.NewInt(3*k), P.n)
		if w3k.Equal(&z27) {
			wk := gk005Pow(P.omega, big.NewInt(k), P.n)
			var c bn254.E12
			c.Mul(&ct, &wk)
			var chk bn254.E12
			chk.Exp(c, big.NewInt(3))
			if !chk.Equal(&z) {
				t.Fatal("cube root arithmetic wrong")
			}
			return c
		}
	}
	t.Fatal("z is not a cube")
	return bn254.E12{}
}

// gk005CubeIndex returns the unique s in {0,1,2} making f·ω^s a cube.
func gk005CubeIndex(t *testing.T, P gk005Params, f bn254.E12) int64 {
	t.Helper()
	third := new(big.Int).Div(P.n, big.NewInt(3))
	for s := int64(0); s < 3; s++ {
		y := gk005ScaledProduct(P, f, s)
		probe := gk005Pow(y, third, P.n)
		if probe.IsOne() {
			return s
		}
	}
	t.Fatal("no s makes f*omega^s a cube")
	return -1
}

func gk005ScaledProduct(P gk005Params, f bn254.E12, s int64) bn254.E12 {
	om := gk005Pow(P.omega, big.NewInt(s), P.n)
	var y bn254.E12
	y.Mul(&f, &om)
	return y
}

func gk005SetResidue(w *bn254witness.Witness, c bn254.E12, s int64) {
	var ci bn254.E12
	ci.Inverse(&c)
	w.ResidueC = gk005E12ToFlat(&c)
	w.ResidueCInv = gk005E12ToFlat(&ci)
	w.ResidueScaling = int(s)
}

func gk005MSMConfig(t *testing.T, vk bn254witness.VerifyingKey) codegen.Groth16Config {
	t.Helper()
	ab, err := bn254witness.PrecomputeAlphaNegBeta(vk.AlphaG1, vk.BetaNegG2)
	if err != nil {
		t.Fatalf("PrecomputeAlphaNegBeta: %v", err)
	}
	cfg := codegen.Groth16Config{
		ModuloThreshold:  0,
		AlphaNegBetaFp12: ab,
		GammaNegG2:       vk.GammaNegG2,
		DeltaNegG2:       vk.DeltaNegG2,
	}
	if len(vk.IC) != 6 {
		t.Fatalf("SP1 VK has %d IC points, want 6", len(vk.IC))
	}
	for i := 0; i < 6; i++ {
		cfg.IC[i] = [2]*big.Int{new(big.Int).Set(vk.IC[i][0]), new(big.Int).Set(vk.IC[i][1])}
	}
	return cfg
}

func gk005Run(verifier []codegen.StackOp, w *bn254witness.Witness) error {
	ops := append([]codegen.StackOp{}, w.ToStackOps()...)
	ops = append(ops, verifier...)
	return codegen.BuildAndExecuteOps(ops)
}

func gk005Verifier(msm bool, cfg codegen.Groth16Config) []codegen.StackOp {
	var ops []codegen.StackOp
	emit := func(op codegen.StackOp) { ops = append(ops, op) }
	if msm {
		codegen.EmitGroth16VerifierWitnessAssistedWithMSM(emit, cfg)
	} else {
		codegen.EmitGroth16VerifierWitnessAssisted(emit, cfg)
	}
	return ops
}

// gk005OptimizedVerifier is the WithMSM verifier after the same peephole
// passes CompileGroth16WA runs (OptimizeStackOps then OptimizeBN254Ops): the
// bytes that are actually deployed.
func gk005OptimizedVerifier(cfg codegen.Groth16Config) []codegen.StackOp {
	return codegen.OptimizeBN254Ops(codegen.OptimizeStackOps(gk005Verifier(true, cfg)))
}

func gk005Witness(t *testing.T, msm bool, vk bn254witness.VerifyingKey, proof bn254witness.Proof, pubs []*big.Int) *bn254witness.Witness {
	t.Helper()
	var (
		w   *bn254witness.Witness
		err error
	)
	if msm {
		w, err = bn254witness.BuildFromProofWithInputs(vk, proof, pubs)
	} else {
		w, err = bn254witness.GenerateWitness(vk, proof, pubs)
	}
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	return w
}

// gk005RandomE12 is a fixed pseudo-random Fp12 element (no zero coefficient).
func gk005RandomE12(seed string) bn254.E12 {
	var flat [12]*big.Int
	for i := range flat {
		h := sha256.Sum256([]byte(seed + string(rune('a'+i))))
		flat[i] = new(big.Int).Mod(new(big.Int).SetBytes(h[:]), fp.Modulus())
	}
	return gk005FlatToE12(flat)
}

func gk005Case(t *testing.T, msm, optimized bool) {
	if testing.Short() {
		t.Skip("minutes-long interpreter runs")
	}
	P := gk005Derive(t)
	vk, proof, honestPubs := gk005LoadSP1(t)
	verifier := gk005Verifier(msm, gk005MSMConfig(t, vk))
	if optimized {
		verifier = gk005OptimizedVerifier(gk005MSMConfig(t, vk))
	}
	attacker := gk005AttackerPubs(honestPubs)

	fTrueFlat, err := bn254witness.MillerLoopProduct(vk, proof, honestPubs)
	if err != nil {
		t.Fatalf("MillerLoopProduct(true): %v", err)
	}
	fFalseFlat, err := bn254witness.MillerLoopProduct(vk, proof, attacker)
	if err != nil {
		t.Fatalf("MillerLoopProduct(false): %v", err)
	}
	fTrue, fFalse := gk005FlatToE12(fTrueFlat), gk005FlatToE12(fFalseFlat)
	{
		fin := bn254.FinalExponentiation(&fTrue)
		if !fin.IsOne() {
			t.Fatal("premise: the honest SP1 statement does not verify off-chain")
		}
		fin = bn254.FinalExponentiation(&fFalse)
		if fin.IsOne() {
			t.Fatal("premise: the attacker statement (pub_0+1) verifies off-chain")
		}
	}

	mustReject := func(t *testing.T, w *bn254witness.Witness, why string) {
		t.Helper()
		if err := gk005Run(verifier, w); err == nil {
			t.Fatalf("GK-BUG-005: verifier ACCEPTED %s", why)
		} else {
			t.Logf("rejected: %v", err)
		}
	}
	mirror := func(f bn254.E12, w *bn254witness.Witness) bn254.E12 {
		return gk005ScriptResult(P, f, gk005FlatToE12(w.ResidueC), gk005FlatToE12(w.ResidueCInv), int64(w.ResidueScaling))
	}

	t.Run("Control_HonestValidProofAccepted", func(t *testing.T) {
		w := gk005Witness(t, msm, vk, proof, honestPubs)
		if r := mirror(fTrue, w); !r.IsOne() {
			t.Fatal("premise: the honest witness does not satisfy the residue check off-chain")
		}
		if err := gk005Run(verifier, w); err != nil {
			t.Fatalf("honest valid SP1 proof rejected: %v", err)
		}
	})
	t.Run("Control_HonestWitnessForFalseStatementRejected", func(t *testing.T) {
		w := gk005Witness(t, msm, vk, proof, attacker)
		if r := mirror(fFalse, w); r.IsOne() {
			t.Fatal("premise broken: the generator's witness for a false statement passes off-chain")
		}
		mustReject(t, w, "the generator's witness for a false statement (pub_0+1)")
	})

	// c for a product whose pairing != 1, under every allowed scaling factor.
	// For the one s that makes f·ω^s a cube, c is the λ-th-root formula's
	// output (the best a prover can do — no λ-th root exists); for the other
	// two, f·ω^s is not even a cube, so take that c anyway.
	sFalse := gk005CubeIndex(t, P, fFalse)
	var mp, l big.Int
	{
		m := new(big.Int).Div(P.lambda, fr.Modulus())
		mp.Div(m, big.NewInt(3))
		l.Div(P.n, new(big.Int).Mul(big.NewInt(3), fr.Modulus()))
	}
	yFalse := gk005ScaledProduct(P, fFalse, sFalse)
	if probe := gk005Pow(yFalse, &l, P.n); probe.IsOne() {
		t.Fatal("premise broken: f*omega^s of the false statement is a lambda-th power")
	}
	eRoot := new(big.Int).ModInverse(new(big.Int).Mul(&mp, fr.Modulus()), &l)
	cFalse := gk005CubeRoot(t, P, gk005Pow(yFalse, eRoot, P.n))
	for s := int64(0); s < 3; s++ {
		s := s
		t.Run("ForgedC_RootFormulaForFalseProduct_s"+string(rune('0'+s)), func(t *testing.T) {
			w := gk005Witness(t, msm, vk, proof, attacker)
			gk005SetResidue(w, cFalse, s)
			if r := mirror(fFalse, w); r.IsOne() {
				t.Fatal("SOUNDNESS premise broken: forged residue passes off-chain")
			}
			mustReject(t, w, "a residue witness for a product whose pairing is not 1")
		})
	}

	t.Run("ForgedC_Random", func(t *testing.T) {
		w := gk005Witness(t, msm, vk, proof, attacker)
		gk005SetResidue(w, gk005RandomE12("gk005-random-c"), sFalse)
		mustReject(t, w, "a random residue witness for a false statement")
	})

	// c and c⁻¹ chosen as INDEPENDENT elements that satisfy the folded
	// arithmetic exactly: c^eC · c⁻¹^eCInv = (f·ω^s)⁻¹. gcd(eC, eCInv) = 3 and
	// f·ω^s is a cube, so Bezout gives the pair. Only c·c⁻¹ == 1 stops it.
	t.Run("ForgedCInv_IndependentPairPassesArithmetic", func(t *testing.T) {
		g, a, b := new(big.Int), new(big.Int), new(big.Int)
		g.GCD(a, b, P.eC, P.eCInv)
		if g.Cmp(big.NewInt(3)) != 0 {
			t.Fatalf("premise: gcd(eC, eCInv) = %s, want 3", g)
		}
		var yInv bn254.E12
		yInv.Inverse(&yFalse)
		root := gk005CubeRoot(t, P, yInv)
		c := gk005Pow(root, a, P.n)
		ci := gk005Pow(root, b, P.n)
		var prod bn254.E12
		prod.Mul(&c, &ci)
		if prod.IsOne() {
			t.Fatal("premise: the pair is accidentally inverse")
		}
		if r := gk005ScriptResult(P, fFalse, c, ci, sFalse); !r.IsOne() {
			t.Fatal("premise: the independent pair does not satisfy the folded arithmetic")
		}
		w := gk005Witness(t, msm, vk, proof, attacker)
		w.ResidueC = gk005E12ToFlat(&c)
		w.ResidueCInv = gk005E12ToFlat(&ci)
		w.ResidueScaling = int(sFalse)
		mustReject(t, w, "an independent (c, c⁻¹) pair for a false statement (the inverse check is missing)")
	})

	// Scaling factor outside the allowed set {1, ω, ω²}. Without the range
	// check, every s ∉ {0, 1} would select ω² — so for an honest s = 2 these
	// would pass; with it they must abort whatever the honest s is.
	wTrue := gk005Witness(t, msm, vk, proof, honestPubs)
	sTrue := int64(wTrue.ResidueScaling)
	t.Logf("honest scaling index s = %d (false statement: %d)", sTrue, sFalse)
	for _, bad := range []int64{3, 5, 27, -1} {
		bad := bad
		t.Run("ForgedW_OutsideAllowedSet_s="+big.NewInt(bad).String(), func(t *testing.T) {
			w := gk005Witness(t, msm, vk, proof, honestPubs)
			w.ResidueScaling = int(bad)
			mustReject(t, w, "a scaling index outside {0, 1, 2}")
		})
	}
	// Scaling factor inside the allowed set but not the honest one: f·ω^s'
	// is not a cube, so no c works; the honest c certainly does not.
	for s := int64(0); s < 3; s++ {
		if s == sTrue {
			continue
		}
		s := s
		t.Run("ForgedW_InsideAllowedSet_WrongIndex_s"+string(rune('0'+s)), func(t *testing.T) {
			w := gk005Witness(t, msm, vk, proof, honestPubs)
			w.ResidueScaling = int(s)
			if r := mirror(fTrue, w); r.IsOne() {
				t.Fatal("premise broken: two scaling indices verify")
			}
			mustReject(t, w, "the honest c with a wrong in-range scaling index")
		})
	}
}

func TestGKBUG005_WithMSM(t *testing.T) { gk005Case(t, true, false) }
func TestGKBUG005_Raw(t *testing.T)     { gk005Case(t, false, false) }

// TestGKBUG005_WithMSMOptimized runs every forgery against the peephole-
// optimised WithMSM verifier, so no optimiser rewrite can have weakened a
// check the unoptimised ops perform.
func TestGKBUG005_WithMSMOptimized(t *testing.T) { gk005Case(t, true, true) }

// TestGKBUG005_ScriptSize logs the WithMSM verifier size at the production
// threshold (0, as in compiler.loadGroth16WAConfig) on the real SP1 VK, before
// and after the compiler's peephole passes.
func TestGKBUG005_ScriptSize(t *testing.T) {
	vk, _, _ := gk005LoadSP1(t)
	v := gk005Verifier(true, gk005MSMConfig(t, vk))
	vres, err := codegen.Emit([]codegen.StackMethod{{Name: "v", Ops: v}})
	if err != nil {
		t.Fatalf("emit msm: %v", err)
	}
	t.Logf("WithMSM verifier, ModuloThreshold=0, unoptimized: %d bytes", len(vres.ScriptHex)/2)
	vo := codegen.OptimizeBN254Ops(codegen.OptimizeStackOps(v))
	vores, err := codegen.Emit([]codegen.StackMethod{{Name: "v", Ops: vo}})
	if err != nil {
		t.Fatalf("emit msm opt: %v", err)
	}
	t.Logf("WithMSM verifier, ModuloThreshold=0, optimized (compiler path): %d bytes", len(vores.ScriptHex)/2)
}

// TestGKBUG005_HonestNonZeroScalingAccepted: the SP1 v6 proof has scaling
// index s = 0, so on the full verifiers the AB·ω and AB·ω² branches of the
// scaling selector had only ever REJECTED. About two thirds of honest proofs
// take them, and a wrong constant there would lock funds. This builds
// synthetic Groth16 instances (α = G1, β = G2, γ = 2·G2, δ = 3·G2,
// IC = [G1 .. 6·G1], public inputs [1, 0, 0, 0, 0], B = G2, C = c·G1,
// A = (7 + 3c)·G1, so a·b = 1 + γ·l + δ·c with l = 3), searches c for
// honest s = 1 and s = 2, and requires each to be ACCEPTED by the raw,
// WithMSM and peephole-optimised WithMSM verifiers.
func TestGKBUG005_HonestNonZeroScalingAccepted(t *testing.T) {
	if testing.Short() {
		t.Skip("minutes-long interpreter runs")
	}
	_, _, g1, g2 := bn254.Generators()
	mul1 := func(k int64) bn254.G1Affine {
		var p bn254.G1Affine
		p.ScalarMultiplication(&g1, big.NewInt(k))
		return p
	}
	mul2 := func(k int64) bn254.G2Affine {
		var p bn254.G2Affine
		p.ScalarMultiplication(&g2, big.NewInt(k))
		return p
	}
	var ic []bn254.G1Affine
	for k := int64(1); k <= 6; k++ {
		ic = append(ic, mul1(k))
	}
	vk := bn254witness.NewVerifyingKeyFromPositive(mul1(1), mul2(1), mul2(2), mul2(3), ic)
	zero := big.NewInt(0)
	pubs := []*big.Int{big.NewInt(1), zero, zero, zero, zero}
	cfg := gk005MSMConfig(t, vk)
	raw := gk005Verifier(false, cfg)
	msm := gk005Verifier(true, cfg)
	opt := gk005OptimizedVerifier(cfg)

	found := map[int]bool{}
	for c := int64(1); c <= 40 && len(found) < 2; c++ {
		proof := bn254witness.Proof{
			A: bn254witness.G1AffineToBig(mul1(7 + 3*c)),
			B: bn254witness.G2AffineToBig(mul2(1)),
			C: bn254witness.G1AffineToBig(mul1(c)),
		}
		wm, err := bn254witness.BuildFromProofWithInputs(vk, proof, pubs)
		if err != nil {
			t.Fatalf("BuildFromProofWithInputs: %v", err)
		}
		s := wm.ResidueScaling
		if s == 0 || found[s] {
			continue
		}
		f, err := bn254witness.MillerLoopProduct(vk, proof, pubs)
		if err != nil {
			t.Fatalf("MillerLoopProduct: %v", err)
		}
		fe := gk005FlatToE12(f)
		if fin := bn254.FinalExponentiation(&fe); !fin.IsOne() {
			t.Fatalf("premise broken: synthetic instance c=%d does not verify off-chain", c)
		}
		found[s] = true
		wr, err := bn254witness.GenerateWitness(vk, proof, pubs)
		if err != nil {
			t.Fatalf("GenerateWitness: %v", err)
		}
		t.Run("s="+string(rune('0'+s)), func(t *testing.T) {
			t.Logf("c = %d gives honest scaling index %d", c, s)
			for _, v := range []struct {
				name string
				ops  []codegen.StackOp
				w    *bn254witness.Witness
			}{{"raw", raw, wr}, {"WithMSM", msm, wm}, {"WithMSMOptimized", opt, wm}} {
				if err := gk005Run(v.ops, v.w); err != nil {
					t.Fatalf("%s verifier REJECTED an honest proof with scaling index %d: %v", v.name, s, err)
				}
			}
		})
	}
	if !found[1] || !found[2] {
		t.Fatalf("no synthetic instance with scaling index 1 and 2 found (got %v)", found)
	}
}
