package bn254witness

import (
	"fmt"
	"math/big"
	"sync"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/icellan/runar/compilers/go/codegen"
)

// bn254X is the BN254 curve parameter (positive convention used in Rúnar's
// codegen — see compilers/go/codegen/bn254_pairing.go:42-43).
var bn254X *big.Int

func init() {
	var ok bool
	bn254X, ok = new(big.Int).SetString("4965661367192848881", 10)
	if !ok {
		panic("bn254witness: failed to parse curve parameter x")
	}
}

// residueParams are the BN254 constants of the residue-witness pairing
// check (GK-BUG-005; Novakovic & Eagen, "On Proving Pairings", eprint
// 2024/640 §4). The derivation, and why the check is sound, is the doc
// comment "Final-exponentiation elimination by residue witness" in
// compilers/go/codegen/bn254_groth16.go; every fact used here is re-checked
// when the parameters are built, so a wrong constant fails loudly instead of
// producing witnesses the verifier rejects.
//
// With n = p¹² − 1 and λ = 6x + 2 + p − p² + p³ = 3·m'·r:
//
//	l     = n / (3r)            y is a λ-th power iff y^l == 1
//	eRoot = (m'·r)⁻¹ mod l      y' = y^eRoot satisfies y'^(m'r) = y
//	t     = n / 27              prime to 3 (27 ∥ n)
//	toT   = 27·(27⁻¹ mod t)     y^toT is y's component of order dividing t
//	to27  = t·(t⁻¹ mod 27)      y^to27 is y's component of order dividing 27
//	cbrtT = 3⁻¹ mod t           cube root on the order-t component
type residueParams struct {
	nOver3 *big.Int
	l      *big.Int
	eRoot  *big.Int
	toT    *big.Int
	to27   *big.Int
	cbrtT  *big.Int
	lambda *big.Int
	omega  bn254.E12
}

var (
	residueOnce sync.Once
	residueP    residueParams
	residueErr  error
)

func residue() (*residueParams, error) {
	residueOnce.Do(func() { residueErr = buildResidueParams(&residueP) })
	if residueErr != nil {
		return nil, residueErr
	}
	return &residueP, nil
}

func buildResidueParams(rp *residueParams) error {
	p := fp.Modulus()
	r := fr.Modulus()
	one := big.NewInt(1)

	p2 := new(big.Int).Mul(p, p)
	p3 := new(big.Int).Mul(p2, p)
	lambda := new(big.Int).Mul(big.NewInt(6), bn254X)
	lambda.Add(lambda, big.NewInt(2))
	lambda.Add(lambda, p)
	lambda.Sub(lambda, p2)
	lambda.Add(lambda, p3)

	n := new(big.Int).Exp(p, big.NewInt(12), nil)
	n.Sub(n, one)

	m, rem := new(big.Int).QuoRem(lambda, r, new(big.Int))
	if rem.Sign() != 0 {
		return fmt.Errorf("residue: lambda is not a multiple of r")
	}
	mp, rem := new(big.Int).QuoRem(m, big.NewInt(3), new(big.Int))
	if rem.Sign() != 0 || new(big.Int).GCD(nil, nil, mp, n).Cmp(one) != 0 {
		return fmt.Errorf("residue: lambda/r is not 3·m' with gcd(m', p^12-1) = 1")
	}
	threeR := new(big.Int).Mul(big.NewInt(3), r)
	if new(big.Int).GCD(nil, nil, lambda, n).Cmp(threeR) != 0 {
		return fmt.Errorf("residue: gcd(lambda, p^12-1) != 3r")
	}
	l, rem := new(big.Int).QuoRem(n, threeR, new(big.Int))
	if rem.Sign() != 0 {
		return fmt.Errorf("residue: 3r does not divide p^12-1")
	}
	eRoot := new(big.Int).ModInverse(new(big.Int).Mul(mp, r), l)
	if eRoot == nil {
		return fmt.Errorf("residue: m'·r is not invertible mod (p^12-1)/3r")
	}
	t, rem := new(big.Int).QuoRem(n, big.NewInt(27), new(big.Int))
	if rem.Sign() != 0 || new(big.Int).Mod(t, big.NewInt(3)).Sign() == 0 {
		return fmt.Errorf("residue: 27 does not exactly divide p^12-1")
	}
	toT := new(big.Int).Mul(big.NewInt(27), new(big.Int).ModInverse(big.NewInt(27), t))
	to27 := new(big.Int).Mul(t, new(big.Int).ModInverse(new(big.Int).Mod(t, big.NewInt(27)), big.NewInt(27)))
	cbrtT := new(big.Int).ModInverse(big.NewInt(3), t)

	if err := flatFp12ToE12(codegen.Bn254ResidueOmega27(), &rp.omega); err != nil {
		return fmt.Errorf("residue: omega: %w", err)
	}
	var o9, o27 bn254.E12
	o9.Exp(rp.omega, big.NewInt(9))
	o27.Exp(rp.omega, big.NewInt(27))
	if !o27.IsOne() || o9.IsOne() {
		return fmt.Errorf("residue: codegen.Bn254ResidueOmega27 is not a primitive 27th root of unity")
	}

	rp.nOver3 = new(big.Int).Div(n, big.NewInt(3))
	rp.l = l
	rp.eRoot = eRoot
	rp.toT = toT
	rp.to27 = to27
	rp.cbrtT = cbrtT
	rp.lambda = lambda
	return nil
}

// computeResidueWitness returns the residue witness the verifier checks
// instead of a final exponentiation: s ∈ {0, 1, 2} and c with
//
//	f · ω^s == c^λ,   λ = 6x + 2 + p − p² + p³,   ω = codegen.Bn254ResidueOmega27(),
//
// for f the exact product the verifier's Miller loop computes (see
// MillerLoopProduct), together with c⁻¹.
//
// s is the unique index that makes y = f·ω^s a cube. Such a c exists iff
// the pairing check holds (y is then also an r-th power, hence a λ-th
// power); ok reports exactly that. For a FALSE statement ok is false and the
// returned c is the same formula applied anyway: c^λ != f·ω^s, so the
// verifier rejects it. Callers that build witnesses for statements they
// expect to verify should check ok.
func computeResidueWitness(f [12]*big.Int) (c, cInv [12]*big.Int, s int, ok bool, err error) {
	rp, err := residue()
	if err != nil {
		return c, cInv, 0, false, err
	}
	var fE bn254.E12
	if err := flatFp12ToE12(f, &fE); err != nil {
		return c, cInv, 0, false, fmt.Errorf("decode f: %w", err)
	}
	if fE.IsZero() {
		return c, cInv, 0, false, fmt.Errorf("Miller loop product is zero")
	}

	// 1. s: the unique index with (f·ω^s)^(n/3) == 1, i.e. f·ω^s a cube.
	s = -1
	var y bn254.E12
	cur := fE
	for k := 0; k < 3; k++ {
		var probe bn254.E12
		probe.Exp(cur, rp.nOver3)
		if probe.IsOne() {
			s, y = k, cur
			break
		}
		cur.Mul(&cur, &rp.omega)
	}
	if s < 0 {
		return c, cInv, 0, false, fmt.Errorf("residue: no scaling index makes f a cube (impossible for omega of order 27)")
	}

	// 2. y is a λ-th power iff y^l == 1: exactly when the pairing holds.
	var probe bn254.E12
	probe.Exp(y, rp.l)
	ok = probe.IsOne()

	// 3. c = ∛(y^eRoot). y is a cube, so y' is too; its order-27 component
	//    lies in <ω³> and has a cube root among ω^0 … ω^8.
	var y1, yt, y27, ct, cE bn254.E12
	y1.Exp(y, rp.eRoot)
	yt.Exp(y1, rp.toT)
	y27.Exp(y1, rp.to27)
	ct.Exp(yt, rp.cbrtT)
	var omega3, w3k, wk bn254.E12
	omega3.Exp(rp.omega, big.NewInt(3))
	w3k.SetOne()
	wk.SetOne()
	found := false
	for k := 0; k < 9; k++ {
		if w3k.Equal(&y27) {
			found = true
			break
		}
		w3k.Mul(&w3k, &omega3)
		wk.Mul(&wk, &rp.omega)
	}
	if !found {
		return c, cInv, 0, false, fmt.Errorf("residue: order-27 component is not a cube (impossible after step 1)")
	}
	cE.Mul(&ct, &wk)

	var cInvE bn254.E12
	cInvE.Inverse(&cE)
	return e12ToFlatFp12(&cE), e12ToFlatFp12(&cInvE), s, ok, nil
}

// ResidueLambda returns λ = 6x + 2 + p − p² + p³, the exponent of the
// residue check f·ω^s == c^λ.
func ResidueLambda() *big.Int {
	rp, err := residue()
	if err != nil {
		panic(err)
	}
	return new(big.Int).Set(rp.lambda)
}

// PrecomputeAlphaNegBeta computes the pre-final-exp Miller loop value
// MillerLoop(α, -β) which the verifier multiplies into its triple Miller
// loop accumulator before the residue check that stands in for the single
// shared final exponentiation.
//
// The input betaNegG2 is ALREADY NEGATED (-β), matching the SP1 Solidity
// verifier convention where β is stored pre-negated in the VK. The helper
// reads it into a gnark G2Affine and calls bn254.MillerLoop directly —
// there is no further negation.
//
// The SP1 rearrangement of Groth's 2016 equation is:
//
//	e(A, B) · e(L, -γ) · e(C, -δ) · e(α, -β) = 1
//
// The verifier multiplies the triple Miller loop accumulator by this
// precomputed constant BEFORE applying the final exponentiation, i.e.:
//
//	f = MillerLoop(A, B) · MillerLoop(prep, -γ) · MillerLoop(C, -δ) · MillerLoop(α, -β)
//	verify FinalExp(f) == 1   (on chain: f·ω^s == c^λ, see computeResidueWitness)
//
// Consequently this function returns the PRE-final-exp Miller loop
// value, NOT the post-final-exp GT element e(α, -β). Feeding the GT
// element into the verifier would require the unrealistic identity
// FinalExp(pre · post) == 1 (which generally fails because FinalExp is
// not the identity on GT: see `(p^12-1)/r` mod r ≠ 1 for BN254).
//
// alphaG1 is in Rúnar (x, y) order. betaNegG2 is in Rúnar (x0, x1, y0, y1)
// order (real, imag for each coordinate), holding -β.
func PrecomputeAlphaNegBeta(alphaG1 [2]*big.Int, betaNegG2 [4]*big.Int) ([12]*big.Int, error) {
	var alpha bn254.G1Affine
	alpha.X.SetBigInt(alphaG1[0])
	alpha.Y.SetBigInt(alphaG1[1])
	if !alpha.IsOnCurve() {
		return [12]*big.Int{}, fmt.Errorf("PrecomputeAlphaNegBeta: alpha is not on G1")
	}

	var negBeta bn254.G2Affine
	negBeta.X.A0.SetBigInt(betaNegG2[0])
	negBeta.X.A1.SetBigInt(betaNegG2[1])
	negBeta.Y.A0.SetBigInt(betaNegG2[2])
	negBeta.Y.A1.SetBigInt(betaNegG2[3])
	if !negBeta.IsOnCurve() {
		return [12]*big.Int{}, fmt.Errorf("PrecomputeAlphaNegBeta: -beta is not on G2")
	}

	// Use MillerLoop (pre-final-exp) so the result lives in the same space
	// as the triple Miller loop accumulator in the verifier script.
	ml, err := bn254.MillerLoop(
		[]bn254.G1Affine{alpha},
		[]bn254.G2Affine{negBeta},
	)
	if err != nil {
		return [12]*big.Int{}, fmt.Errorf("PrecomputeAlphaNegBeta: gnark MillerLoop failed: %w", err)
	}

	return e12ToFlatFp12(&ml), nil
}
