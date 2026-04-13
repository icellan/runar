package bn254witness

import (
	"fmt"
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
)

// flatFp12ToE12 decodes a 12-element flat representation into a gnark
// bn254.E12. The flat order matches gnark's internal field layout:
//
//	[0]  C0.B0.A0   [1]  C0.B0.A1
//	[2]  C0.B1.A0   [3]  C0.B1.A1
//	[4]  C0.B2.A0   [5]  C0.B2.A1
//	[6]  C1.B0.A0   [7]  C1.B0.A1
//	[8]  C1.B1.A0   [9]  C1.B1.A1
//	[10] C1.B2.A0   [11] C1.B2.A1
//
// This is the same order EmitGroth16VerifierWitnessAssisted pushes the
// precomputed e(alpha, beta) value (see bn254_groth16.go:1041-1051).
func flatFp12ToE12(flat [12]*big.Int, out *bn254.E12) error {
	for i := 0; i < 12; i++ {
		if flat[i] == nil {
			return fmt.Errorf("flatFp12ToE12: nil entry at index %d", i)
		}
	}
	out.C0.B0.A0.SetBigInt(flat[0])
	out.C0.B0.A1.SetBigInt(flat[1])
	out.C0.B1.A0.SetBigInt(flat[2])
	out.C0.B1.A1.SetBigInt(flat[3])
	out.C0.B2.A0.SetBigInt(flat[4])
	out.C0.B2.A1.SetBigInt(flat[5])
	out.C1.B0.A0.SetBigInt(flat[6])
	out.C1.B0.A1.SetBigInt(flat[7])
	out.C1.B1.A0.SetBigInt(flat[8])
	out.C1.B1.A1.SetBigInt(flat[9])
	out.C1.B2.A0.SetBigInt(flat[10])
	out.C1.B2.A1.SetBigInt(flat[11])
	return nil
}

// e12ToFlatFp12 encodes a gnark bn254.E12 into the flat 12-element form
// the verifier consumes.
func e12ToFlatFp12(e *bn254.E12) [12]*big.Int {
	var out [12]*big.Int
	out[0] = new(big.Int)
	e.C0.B0.A0.BigInt(out[0])
	out[1] = new(big.Int)
	e.C0.B0.A1.BigInt(out[1])
	out[2] = new(big.Int)
	e.C0.B1.A0.BigInt(out[2])
	out[3] = new(big.Int)
	e.C0.B1.A1.BigInt(out[3])
	out[4] = new(big.Int)
	e.C0.B2.A0.BigInt(out[4])
	out[5] = new(big.Int)
	e.C0.B2.A1.BigInt(out[5])
	out[6] = new(big.Int)
	e.C1.B0.A0.BigInt(out[6])
	out[7] = new(big.Int)
	e.C1.B0.A1.BigInt(out[7])
	out[8] = new(big.Int)
	e.C1.B1.A0.BigInt(out[8])
	out[9] = new(big.Int)
	e.C1.B1.A1.BigInt(out[9])
	out[10] = new(big.Int)
	e.C1.B2.A0.BigInt(out[10])
	out[11] = new(big.Int)
	e.C1.B2.A1.BigInt(out[11])
	return out
}
