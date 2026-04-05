package contract

import runar "github.com/icellan/runar/packages/runar-go"

// BabyBearDemo demonstrates Baby Bear prime field arithmetic.
//
// Baby Bear is the prime field used by SP1 STARK proofs (FRI verification).
// Field prime: p = 2^31 - 2^27 + 1 = 2013265921
//
// Four operations:
//   - BbFieldAdd(a, b) — (a + b) mod p
//   - BbFieldSub(a, b) — (a - b + p) mod p
//   - BbFieldMul(a, b) — (a * b) mod p
//   - BbFieldInv(a) — a^(p-2) mod p (multiplicative inverse via Fermat)
type BabyBearDemo struct {
	runar.SmartContract
}

// CheckAdd verifies field addition.
func (c *BabyBearDemo) CheckAdd(a, b, expected runar.Bigint) {
	runar.Assert(runar.BbFieldAdd(a, b) == expected)
}

// CheckSub verifies field subtraction.
func (c *BabyBearDemo) CheckSub(a, b, expected runar.Bigint) {
	runar.Assert(runar.BbFieldSub(a, b) == expected)
}

// CheckMul verifies field multiplication.
func (c *BabyBearDemo) CheckMul(a, b, expected runar.Bigint) {
	runar.Assert(runar.BbFieldMul(a, b) == expected)
}

// CheckInv verifies field inversion: a * inv(a) === 1.
func (c *BabyBearDemo) CheckInv(a runar.Bigint) {
	inv := runar.BbFieldInv(a)
	runar.Assert(runar.BbFieldMul(a, inv) == 1)
}

// CheckAddSubRoundtrip verifies that (a + b) - b === a.
func (c *BabyBearDemo) CheckAddSubRoundtrip(a, b runar.Bigint) {
	sum := runar.BbFieldAdd(a, b)
	result := runar.BbFieldSub(sum, b)
	runar.Assert(result == a)
}

// CheckDistributive verifies the distributive law: a * (b + c) === a*b + a*c.
func (c *BabyBearDemo) CheckDistributive(a, b, cc runar.Bigint) {
	lhs := runar.BbFieldMul(a, runar.BbFieldAdd(b, cc))
	rhs := runar.BbFieldAdd(runar.BbFieldMul(a, b), runar.BbFieldMul(a, cc))
	runar.Assert(lhs == rhs)
}
