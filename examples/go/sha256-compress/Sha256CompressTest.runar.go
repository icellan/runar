package contract

import runar "github.com/icellan/runar/packages/runar-go"

// Sha256CompressTest is a stateless contract that verifies a single SHA-256
// compression function invocation (FIPS 180-4 Section 6.2.2).
//
// The spender provides a 32-byte state and a 64-byte block. The contract
// computes Sha256Compress(state, block) and asserts the result matches
// the Expected digest baked into the locking script at deployment time.
type Sha256CompressTest struct {
	runar.SmartContract
	// Expected is the expected 32-byte SHA-256 compression output.
	Expected runar.ByteString `runar:"readonly"`
}

// Verify computes a single SHA-256 compression round and asserts the result
// matches the stored Expected value.
func (c *Sha256CompressTest) Verify(state runar.ByteString, block runar.ByteString) {
	result := runar.Sha256Compress(state, block)
	runar.Assert(result == c.Expected)
}
