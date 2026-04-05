pragma runar ^0.1.0;

/// @title CrossCovenantRef
/// @notice Demonstrates reading another covenant's output.
/// @dev This pattern allows one covenant to verify data from a DIFFERENT
/// transaction's output, enabling cross-covenant communication on BSV.
///
/// How it works:
/// 1. The unlocking script passes the referenced output data as a parameter
/// 2. The covenant hashes it and compares against a known script hash
/// 3. If the hash matches, the data is authentic — extract fields from it
///
/// Use cases:
/// - Bridge covenant reading state covenant's state root
/// - Side-chain anchor verifying main-chain commitments
/// - Oracle covenant referencing price feed covenant's data
contract CrossCovenantRef is SmartContract {
    /// @notice Hash of the expected source covenant's locking script.
    Sha256 immutable sourceScriptHash;

    constructor(Sha256 _sourceScriptHash) {
        sourceScriptHash = _sourceScriptHash;
    }

    /// @notice Verify a referenced output and extract a 32-byte state root from it.
    /// @param referencedOutput The full serialized output from the source covenant
    /// @param expectedStateRoot The state root we expect to find in the referenced output
    /// @param stateRootOffset Byte offset within the script where the state root starts
    function verifyAndExtract(
        ByteString referencedOutput,
        ByteString expectedStateRoot,
        bigint stateRootOffset
    ) public {
        // Step 1: Hash the referenced output and verify it matches the known script hash.
        Sha256 outputHash = hash256(referencedOutput);
        require(outputHash == this.sourceScriptHash);

        // Step 2: Extract the state root from the referenced output.
        ByteString stateRoot = substr(referencedOutput, stateRootOffset, 32);

        // Step 3: Verify the extracted state root matches the expected value.
        require(stateRoot == expectedStateRoot);
    }

    /// @notice Verify a referenced output and extract a numeric value from it.
    /// @param referencedOutput The full serialized output from the source covenant
    /// @param expectedValue The numeric value we expect to find
    /// @param valueOffset Byte offset within the script
    /// @param valueLen Length in bytes of the numeric value
    function verifyAndExtractNumeric(
        ByteString referencedOutput,
        bigint expectedValue,
        bigint valueOffset,
        bigint valueLen
    ) public {
        Sha256 outputHash = hash256(referencedOutput);
        require(outputHash == this.sourceScriptHash);

        ByteString valueBytes = substr(referencedOutput, valueOffset, valueLen);
        bigint value = bin2num(valueBytes);
        require(value == expectedValue);
    }
}
