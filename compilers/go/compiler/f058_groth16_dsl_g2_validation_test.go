package compiler

// F-058 / CL-BUG-082: the shipped DSL contract
// integration/go/contracts/Groth16Verifier.runar.go takes the proof's G2
// point B as four spender-supplied bigints and feeds them straight into
// runar.Bn254MultiPairing4 with no on-curve or subgroup assertion of its own.
//
// These tests COMPILE THAT EXACT CONTRACT FILE with a baked verification key
// and EXECUTE the resulting locking script under the go-sdk interpreter (the
// same engine codegen.BuildAndExecuteOps uses). No TestContract, no ANF
// interpreter, no runar-go mock: Bn254MultiPairing4's int64 entry point
// (F-358) now delegates to a real pairing, but it still cannot carry a
// genuine, non-degenerate Groth16 proof — BN254 G2 coordinates are 254 bits
// and cannot fit in its int64 parameters — so it would prove nothing here.
//
// The Groth16 instance is simulator-built: random VK scalars and a random B
// scalar s, with A chosen so that
//
//	e(A, B) · e(L, -γ) · e(C, -δ) · e(α, -β) == 1
//
// holds exactly (checked off-chain with gnark-crypto's PairingCheck). That
// is precisely the relation the on-chain verifier checks, so it is an honest
// accepting input for this contract.
//
// Non-vacuity: any wrong B would already make the GT product ≠ 1, so "the
// script failed" alone does not show the G2 point was VALIDATED. Every
// negative therefore also asserts the FAILURE CLASS: a rejected input
// assertion aborts with OP_EQUALVERIFY mid-script, whereas a pairing-product
// mismatch runs to completion and leaves a false top-of-stack. The
// TamperedC control pins the second class for this very contract, so the
// two cannot be confused.

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

var (
	f058P, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
	f058R    = fr.Modulus()
)

type f058G2 struct{ x0, x1, y0, y1 *big.Int }

func f058FromG2(q bn254.G2Affine) f058G2 {
	var g f058G2
	g.x0, g.x1, g.y0, g.y1 = new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	q.X.A0.BigInt(g.x0)
	q.X.A1.BigInt(g.x1)
	q.Y.A0.BigInt(g.y0)
	q.Y.A1.BigInt(g.y1)
	return g
}

func f058PointHex(p bn254.G1Affine) string {
	x, y := new(big.Int), new(big.Int)
	p.X.BigInt(x)
	p.Y.BigInt(y)
	buf := make([]byte, 64)
	x.FillBytes(buf[:32])
	y.FillBytes(buf[32:])
	return hex.EncodeToString(buf)
}

func f058RandScalar(t *testing.T) *big.Int {
	t.Helper()
	for {
		k, err := rand.Int(rand.Reader, f058R)
		if err != nil {
			t.Fatal(err)
		}
		if k.Sign() != 0 {
			return k
		}
	}
}

func f058G1Mul(k *big.Int) bn254.G1Affine {
	_, _, g1, _ := bn254.Generators()
	var p bn254.G1Affine
	p.ScalarMultiplication(&g1, k)
	return p
}

func f058G2Mul(k *big.Int) bn254.G2Affine {
	_, _, _, g2 := bn254.Generators()
	var q bn254.G2Affine
	q.ScalarMultiplication(&g2, k)
	return q
}

type f058Instance struct {
	vk       map[string]interface{}
	a, c     bn254.G1Affine
	b        f058G2
	pub      *big.Int
	lockHex  string
	compiled bool
}

var (
	f058Once sync.Once
	f058Inst f058Instance
	f058Err  string
)

// f058Setup builds the simulated VK + honest proof and compiles the shipped
// contract once (the MultiPairing4 script is multi-megabyte).
func f058Setup(t *testing.T) *f058Instance {
	t.Helper()
	f058Once.Do(func() {
		mod := func(v *big.Int) *big.Int { return v.Mod(v, f058R) }
		a, b, g, d := f058RandScalar(t), f058RandScalar(t), f058RandScalar(t), f058RandScalar(t)
		i0, i1, pub := f058RandScalar(t), f058RandScalar(t), f058RandScalar(t)
		s, c := f058RandScalar(t), f058RandScalar(t)

		// l = i0 + pub·i1 ; want A·s = a·b + l·g + c·d  (mod r)
		l := mod(new(big.Int).Add(i0, new(big.Int).Mul(pub, i1)))
		rhs := new(big.Int).Mul(a, b)
		rhs.Add(rhs, new(big.Int).Mul(l, g))
		rhs.Add(rhs, new(big.Int).Mul(c, d))
		mod(rhs)
		aScalar := mod(new(big.Int).Mul(rhs, new(big.Int).ModInverse(s, f058R)))

		neg := func(k *big.Int) *big.Int { return mod(new(big.Int).Neg(k)) }
		betaNeg := f058FromG2(f058G2Mul(neg(b)))
		gammaNeg := f058FromG2(f058G2Mul(neg(g)))
		deltaNeg := f058FromG2(f058G2Mul(neg(d)))

		inst := f058Instance{
			a:   f058G1Mul(aScalar),
			c:   f058G1Mul(c),
			b:   f058FromG2(f058G2Mul(s)),
			pub: pub,
		}

		// Off-chain sanity: the relation the contract checks really holds.
		alpha := f058G1Mul(a)
		L := f058G1Mul(l)
		bQ := f058G2Mul(s)
		ok, err := bn254.PairingCheck(
			[]bn254.G1Affine{inst.a, L, inst.c, alpha},
			[]bn254.G2Affine{bQ, f058G2Mul(neg(g)), f058G2Mul(neg(d)), f058G2Mul(neg(b))},
		)
		if err != nil || !ok {
			f058Err = "simulated Groth16 instance fails gnark PairingCheck"
			return
		}

		inst.vk = map[string]interface{}{
			"alphaG1":     f058PointHex(alpha),
			"betaNegG2X0": betaNeg.x0, "betaNegG2X1": betaNeg.x1,
			"betaNegG2Y0": betaNeg.y0, "betaNegG2Y1": betaNeg.y1,
			"gammaNegG2X0": gammaNeg.x0, "gammaNegG2X1": gammaNeg.x1,
			"gammaNegG2Y0": gammaNeg.y0, "gammaNegG2Y1": gammaNeg.y1,
			"deltaNegG2X0": deltaNeg.x0, "deltaNegG2X1": deltaNeg.x1,
			"deltaNegG2Y0": deltaNeg.y0, "deltaNegG2Y1": deltaNeg.y1,
			"iC0": f058PointHex(f058G1Mul(i0)),
			"iC1": f058PointHex(f058G1Mul(i1)),
		}

		_, thisFile, _, _ := runtime.Caller(0)
		src := filepath.Join(filepath.Dir(thisFile), "..", "..", "..",
			"integration", "go", "contracts", "Groth16Verifier.runar.go")
		art, err := CompileFromSource(src, CompileOptions{ConstructorArgs: inst.vk})
		if err != nil {
			f058Err = "compile Groth16Verifier.runar.go: " + err.Error()
			return
		}
		inst.lockHex = art.Script
		inst.compiled = true
		f058Inst = inst
	})
	if f058Err != "" {
		t.Fatal(f058Err)
	}
	return &f058Inst
}

// f058Spend pushes verify(proofA, proofBX0, proofBX1, proofBY0, proofBY1,
// proofC, publicInput) in declaration order and executes against the
// compiled locking script.
func f058Spend(t *testing.T, inst *f058Instance, a bn254.G1Affine, b f058G2, c bn254.G1Affine) error {
	t.Helper()
	lock, err := script.NewFromHex(inst.lockHex)
	if err != nil {
		t.Fatalf("locking hex: %v", err)
	}
	unlock := &script.Script{}
	pushBytes := func(bs []byte) {
		if err := unlock.AppendPushData(bs); err != nil {
			t.Fatalf("append push: %v", err)
		}
	}
	pushPt := func(p bn254.G1Affine) {
		x, y := new(big.Int), new(big.Int)
		p.X.BigInt(x)
		p.Y.BigInt(y)
		buf := make([]byte, 64)
		x.FillBytes(buf[:32])
		y.FillBytes(buf[32:])
		pushBytes(buf)
	}
	pushPt(a)
	for _, v := range []*big.Int{b.x0, b.x1, b.y0, b.y1} {
		pushBytes(scriptNumBytes(v))
	}
	pushPt(c)
	pushBytes(scriptNumBytes(inst.pub))

	return interpreter.NewEngine().Execute(
		interpreter.WithScripts(lock, unlock),
		interpreter.WithAfterGenesis(),
		interpreter.WithAfterChronicle(),
		interpreter.WithForkID(),
	)
}

func f058IsInputAssertionFailure(err error) bool {
	return err != nil && strings.Contains(err.Error(), "OP_EQUALVERIFY")
}

// f058OffTwistB: honest B with y.imag incremented — canonical (< p) but not
// on E'(Fp²): y² != x³ + b'.
func f058OffTwistB(t *testing.T, honest f058G2) f058G2 {
	t.Helper()
	bad := honest
	bad.y1 = new(big.Int).Add(honest.y1, big.NewInt(1))
	bad.y1.Mod(bad.y1, f058P)
	var probe bn254.G2Affine
	probe.X.A0.SetBigInt(bad.x0)
	probe.X.A1.SetBigInt(bad.x1)
	probe.Y.A0.SetBigInt(bad.y0)
	probe.Y.A1.SetBigInt(bad.y1)
	if probe.IsOnCurve() {
		t.Fatal("off-twist vector is on the twist")
	}
	return bad
}

// f058SmallOrderB returns a point of order exactly 10069 on the twist.
// The twist order is h·r with h = 2p − r = 10069 · h', so
// [h·r / 10069]·P lands in the order-10069 subgroup for a generic twist
// point P. That point is on the curve but outside G2 — the canonical
// small-subgroup-confinement vector. Scalar multiplication is plain
// double-and-add on Jacobian coordinates (gnark's GLV path assumes r-torsion
// and is not valid off G2).
func f058SmallOrderB(t *testing.T) f058G2 {
	t.Helper()
	const q = 10069
	h := new(big.Int).Sub(new(big.Int).Lsh(f058P, 1), f058R)
	if new(big.Int).Mod(h, big.NewInt(q)).Sign() != 0 {
		t.Fatalf("%d does not divide the twist cofactor", q)
	}
	mul := func(base bn254.G2Affine, k *big.Int) bn254.G2Jac {
		var acc, bj bn254.G2Jac
		bj.FromAffine(&base)
		acc.Set(&bj)
		for i := k.BitLen() - 2; i >= 0; i-- {
			acc.Double(&acc)
			if k.Bit(i) == 1 {
				acc.AddAssign(&bj)
			}
		}
		return acc
	}
	cof := new(big.Int).Div(new(big.Int).Mul(h, f058R), big.NewInt(q))
	for seed := uint64(1); seed < 64; seed++ {
		var e bn254.E2
		e.A0.SetUint64(seed)
		e.A1.SetUint64(7)
		p := bn254.MapToCurve2(&e)
		if !p.IsOnCurve() {
			continue
		}
		qj := mul(p, cof)
		if qj.Z.IsZero() {
			continue
		}
		var qa bn254.G2Affine
		qa.FromJacobian(&qj)
		chk := mul(qa, big.NewInt(q))
		if !chk.Z.IsZero() {
			t.Fatal("constructed point does not have order dividing 10069")
		}
		if !qa.IsOnCurve() || qa.IsInSubGroup() {
			t.Fatal("small-order vector must be on the twist and outside G2")
		}
		return f058FromG2(qa)
	}
	t.Fatal("no order-10069 point found")
	return f058G2{}
}

// TestF058_Groth16VerifierDSL_AcceptsHonestProof is the positive control:
// the same harness and the same baked VK accept a valid proof.
func TestF058_Groth16VerifierDSL_AcceptsHonestProof(t *testing.T) {
	inst := f058Setup(t)
	if err := f058Spend(t, inst, inst.a, inst.b, inst.c); err != nil {
		t.Fatalf("honest proof REJECTED by the compiled Groth16Verifier: %v", err)
	}
}

// TestF058_Groth16VerifierDSL_TamperedCFailsAtPairing pins the failure class
// of a pairing-product mismatch: an on-curve but wrong C runs every input
// assertion successfully and fails only at the final GT == 1 check.
func TestF058_Groth16VerifierDSL_TamperedCFailsAtPairing(t *testing.T) {
	inst := f058Setup(t)
	var c2 bn254.G1Affine
	c2.Add(&inst.c, &inst.c)
	err := f058Spend(t, inst, inst.a, inst.b, c2)
	if err == nil {
		t.Fatal("tampered C ACCEPTED")
	}
	if f058IsInputAssertionFailure(err) {
		t.Fatalf("tampered (on-curve) C should fail at the pairing result, not an input assertion: %v", err)
	}
	t.Logf("pairing-mismatch failure class: %v", err)
}

// TestF058_Groth16VerifierDSL_RejectsOffTwistB: proofB off the BN254 twist,
// rest of the proof honest. Must be rejected by an input assertion.
func TestF058_Groth16VerifierDSL_RejectsOffTwistB(t *testing.T) {
	inst := f058Setup(t)
	err := f058Spend(t, inst, inst.a, f058OffTwistB(t, inst.b), inst.c)
	if err == nil {
		t.Fatal("off-twist proofB ACCEPTED by the compiled Groth16Verifier")
	}
	if !f058IsInputAssertionFailure(err) {
		t.Fatalf("off-twist proofB was not rejected by a G2 input assertion (reached the pairing): %v", err)
	}
	t.Logf("off-twist rejection: %v", err)
}

// TestF058_Groth16VerifierDSL_RejectsSmallOrderB: proofB is an on-twist
// point of order 10069 (outside G2), rest of the proof honest. Must be
// rejected by the subgroup assertion.
func TestF058_Groth16VerifierDSL_RejectsSmallOrderB(t *testing.T) {
	inst := f058Setup(t)
	err := f058Spend(t, inst, inst.a, f058SmallOrderB(t), inst.c)
	if err == nil {
		t.Fatal("small-order proofB ACCEPTED by the compiled Groth16Verifier")
	}
	if !f058IsInputAssertionFailure(err) {
		t.Fatalf("small-order proofB was not rejected by a G2 input assertion (reached the pairing): %v", err)
	}
	t.Logf("small-order rejection: %v", err)
}
