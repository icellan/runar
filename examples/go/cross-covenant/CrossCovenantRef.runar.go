package contract

import runar "github.com/icellan/runar/packages/runar-go"

// CrossCovenantRef demonstrates reading another covenant's output.
//
// This pattern allows one covenant to verify data from a DIFFERENT
// transaction's output, enabling cross-covenant communication on BSV.
//
// How it works:
//  1. The unlocking script passes the referenced output data as a parameter
//  2. The covenant hashes it and compares against a known script hash
//  3. If the hash matches, the data is authentic — extract fields from it
//
// Use cases:
//   - Bridge covenant reading state covenant's state root
//   - Side-chain anchor verifying main-chain commitments
//   - Oracle covenant referencing price feed covenant's data
type CrossCovenantRef struct {
	runar.SmartContract
	SourceScriptHash runar.Sha256Digest `runar:"readonly"`
}

// VerifyAndExtract verifies a referenced output and extracts a 32-byte state root.
func (c *CrossCovenantRef) VerifyAndExtract(referencedOutput, expectedStateRoot runar.ByteString, stateRootOffset runar.Bigint) {
	// Step 1: Hash the referenced output and verify it matches the known script hash.
	outputHash := runar.Hash256(referencedOutput)
	runar.Assert(outputHash == c.SourceScriptHash)

	// Step 2: Extract the state root from the referenced output.
	stateRoot := runar.Substr(referencedOutput, stateRootOffset, 32)

	// Step 3: Verify the extracted state root matches the expected value.
	runar.Assert(stateRoot == expectedStateRoot)
}

// VerifyAndExtractNumeric verifies a referenced output and extracts a numeric value.
func (c *CrossCovenantRef) VerifyAndExtractNumeric(referencedOutput runar.ByteString, expectedValue, valueOffset, valueLen runar.Bigint) {
	outputHash := runar.Hash256(referencedOutput)
	runar.Assert(outputHash == c.SourceScriptHash)

	valueBytes := runar.Substr(referencedOutput, valueOffset, valueLen)
	value := runar.Bin2Num(valueBytes)
	runar.Assert(value == expectedValue)
}
