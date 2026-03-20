package contract

import runar "github.com/icellan/runar/packages/runar-go"

// Sha256FinalizeTest is a stateless contract that verifies SHA-256 finalization
// with FIPS 180-4 padding.
//
// The spender provides an intermediate state, the remaining unprocessed bytes,
// and the total message bit length. The contract computes
// Sha256Finalize(state, remaining, msgBitLen) and asserts the result matches
// the Expected digest baked into the locking script at deployment time.
type Sha256FinalizeTest struct {
	runar.SmartContract
	// Expected is the expected 32-byte SHA-256 digest after finalization.
	Expected runar.ByteString `runar:"readonly"`
}

// Verify applies FIPS 180-4 padding and the final compression round(s),
// then asserts the result matches the stored Expected value.
func (c *Sha256FinalizeTest) Verify(state runar.ByteString, remaining runar.ByteString, msgBitLen runar.Bigint) {
	result := runar.Sha256Finalize(state, remaining, msgBitLen)
	runar.Assert(result == c.Expected)
}
