use runar::prelude::*;

/// CrossCovenantRef -- Demonstrates reading another covenant's output.
///
/// This pattern allows one covenant to verify data from a DIFFERENT
/// transaction's output, enabling cross-covenant communication on BSV.
///
/// How it works:
/// 1. The unlocking script passes the referenced output data as a parameter
/// 2. The covenant hashes it and compares against a known script hash
/// 3. If the hash matches, the data is authentic -- extract fields from it
///
/// Use cases:
/// - Bridge covenant reading state covenant's state root
/// - Side-chain anchor verifying main-chain commitments
/// - Oracle covenant referencing price feed covenant's data
#[runar::contract]
pub struct CrossCovenantRef {
    /// Hash of the expected source covenant's locking script.
    #[readonly]
    pub source_script_hash: Sha256,
}

#[runar::methods(CrossCovenantRef)]
impl CrossCovenantRef {
    /// Verify a referenced output and extract a 32-byte state root from it.
    #[public]
    pub fn verify_and_extract(
        &self,
        referenced_output: ByteString,
        expected_state_root: ByteString,
        state_root_offset: Bigint,
    ) {
        // Step 1: Hash the referenced output and verify it matches the known script hash.
        let output_hash = hash256(&referenced_output);
        assert!(output_hash == self.source_script_hash);

        // Step 2: Extract the state root from the referenced output.
        let state_root = substr(&referenced_output, state_root_offset, 32);

        // Step 3: Verify the extracted state root matches the expected value.
        assert!(state_root == expected_state_root);
    }

    /// Verify a referenced output and extract a numeric value from it.
    #[public]
    pub fn verify_and_extract_numeric(
        &self,
        referenced_output: ByteString,
        expected_value: Bigint,
        value_offset: Bigint,
        value_len: Bigint,
    ) {
        let output_hash = hash256(&referenced_output);
        assert!(output_hash == self.source_script_hash);

        let value_bytes = substr(&referenced_output, value_offset, value_len);
        let value = bin2num(&value_bytes);
        assert!(value == expected_value);
    }
}
