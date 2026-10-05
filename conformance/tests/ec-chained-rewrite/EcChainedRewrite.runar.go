//go:build ignore

// EXCLUDED FROM THE GO BUILD -- n - 7 (the secp256k1 group order minus 7) does
// not fit an int64, and Go has no spelling for a 256-bit constant. The Rúnar
// frontend reads this file as text, where bigint is arbitrary precision.

package contract

import runar "github.com/icellan/runar/packages/runar-go"

// EcChainedRewrite -- two EC optimizer rules firing on one binding (F-115):
// ecAdd(ecMulGen(n - 7), ecMulGen(7)) -> ecMulGen(0) -> the point at infinity.
type EcChainedRewrite struct {
	runar.SmartContract
}

// Unlock accepts exactly the point the chained rewrite folds to.
func (c *EcChainedRewrite) Unlock(p runar.Point) {
	r := runar.EcAdd(runar.EcMulGen(115792089237316195423570985008687907852837564279074904382605163141518161494330), runar.EcMulGen(7))
	runar.Assert(r == p)
}
