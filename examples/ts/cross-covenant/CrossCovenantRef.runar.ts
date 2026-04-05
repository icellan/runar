import {
  SmartContract, assert, hash256, substr, bin2num,
} from 'runar-lang';
import type { ByteString, Sha256 } from 'runar-lang';

/**
 * CrossCovenantRef — Demonstrates reading another covenant's output.
 *
 * This pattern allows one covenant to verify data from a DIFFERENT
 * transaction's output, enabling cross-covenant communication on BSV.
 *
 * How it works:
 * 1. The unlocking script passes the referenced output data as a parameter
 * 2. The covenant hashes it and compares against a known script hash
 * 3. If the hash matches, the data is authentic — extract fields from it
 *
 * This is NOT introspection of the current transaction (which OP_PUSH_TX
 * handles). It's verification of external data passed into the contract.
 *
 * Use cases:
 * - Bridge covenant reading state covenant's state root
 * - Side-chain anchor verifying main-chain commitments
 * - Oracle covenant referencing price feed covenant's data
 */
class CrossCovenantRef extends SmartContract {
  /** Hash of the expected source covenant's locking script. */
  readonly sourceScriptHash: Sha256;

  constructor(sourceScriptHash: Sha256) {
    super(sourceScriptHash);
    this.sourceScriptHash = sourceScriptHash;
  }

  /**
   * Verify a referenced output and extract a 32-byte state root from it.
   *
   * @param referencedOutput - The full serialized output from the source covenant
   *                           (8-byte LE amount + varint + script bytes)
   * @param expectedStateRoot - The state root we expect to find in the referenced output
   * @param stateRootOffset - Byte offset within the script where the state root starts
   */
  public verifyAndExtract(
    referencedOutput: ByteString,
    expectedStateRoot: ByteString,
    stateRootOffset: bigint,
  ) {
    // Step 1: Hash the referenced output and verify it matches the known script hash.
    // This proves the output data is authentic (came from the expected covenant).
    const outputHash = hash256(referencedOutput);
    assert(outputHash === this.sourceScriptHash);

    // Step 2: Extract the state root from the referenced output.
    // The caller provides the offset where the state root lives within the output.
    const stateRoot = substr(referencedOutput, stateRootOffset, 32n);

    // Step 3: Verify the extracted state root matches the expected value.
    assert(stateRoot === expectedStateRoot);
  }

  /**
   * Verify a referenced output and extract a numeric value from it.
   *
   * @param referencedOutput - The full serialized output from the source covenant
   * @param expectedValue - The numeric value we expect to find
   * @param valueOffset - Byte offset within the script
   * @param valueLen - Length in bytes of the numeric value
   */
  public verifyAndExtractNumeric(
    referencedOutput: ByteString,
    expectedValue: bigint,
    valueOffset: bigint,
    valueLen: bigint,
  ) {
    const outputHash = hash256(referencedOutput);
    assert(outputHash === this.sourceScriptHash);

    const valueBytes = substr(referencedOutput, valueOffset, valueLen);
    const value = bin2num(valueBytes);
    assert(value === expectedValue);
  }
}
