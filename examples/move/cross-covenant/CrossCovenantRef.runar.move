// CrossCovenantRef — Demonstrates reading another covenant's output.
//
// This pattern allows one covenant to verify data from a DIFFERENT
// transaction's output, enabling cross-covenant communication on BSV.
//
// How it works:
// 1. The unlocking script passes the referenced output data as a parameter
// 2. The covenant hashes it and compares against a known script hash
// 3. If the hash matches, the data is authentic — extract fields from it
//
// Use cases:
// - Bridge covenant reading state covenant's state root
// - Side-chain anchor verifying main-chain commitments
// - Oracle covenant referencing price feed covenant's data
module CrossCovenantRef {
    use runar::types::{ByteString, Sha256};
    use runar::crypto::{hash256};
    use runar::bytes::{substr, bin2num};

    struct CrossCovenantRef {
        // Hash of the expected source covenant's locking script.
        source_script_hash: Sha256,
    }

    // Verify a referenced output and extract a 32-byte state root from it.
    //
    // referencedOutput: The full serialized output from the source covenant
    // expectedStateRoot: The state root we expect to find in the referenced output
    // stateRootOffset: Byte offset within the script where the state root starts
    public fun verify_and_extract(
        contract: &CrossCovenantRef,
        referenced_output: ByteString,
        expected_state_root: ByteString,
        state_root_offset: bigint
    ) {
        // Step 1: Hash the referenced output and verify it matches the known script hash.
        let output_hash: Sha256 = hash256(referenced_output);
        assert!(output_hash == contract.source_script_hash, 0);

        // Step 2: Extract the state root from the referenced output.
        let state_root: ByteString = substr(referenced_output, state_root_offset, 32);

        // Step 3: Verify the extracted state root matches the expected value.
        assert!(state_root == expected_state_root, 0);
    }

    // Verify a referenced output and extract a numeric value from it.
    //
    // referencedOutput: The full serialized output from the source covenant
    // expectedValue: The numeric value we expect to find
    // valueOffset: Byte offset within the script
    // valueLen: Length in bytes of the numeric value
    public fun verify_and_extract_numeric(
        contract: &CrossCovenantRef,
        referenced_output: ByteString,
        expected_value: bigint,
        value_offset: bigint,
        value_len: bigint
    ) {
        let output_hash: Sha256 = hash256(referenced_output);
        assert!(output_hash == contract.source_script_hash, 0);

        let value_bytes: ByteString = substr(referenced_output, value_offset, value_len);
        let value: bigint = bin2num(value_bytes);
        assert!(value == expected_value, 0);
    }
}
