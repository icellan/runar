require 'runar'

# CrossCovenantRef -- Demonstrates reading another covenant's output.
#
# This pattern allows one covenant to verify data from a DIFFERENT
# transaction's output, enabling cross-covenant communication on BSV.
#
# How it works:
# 1. The unlocking script passes the referenced output data as a parameter
# 2. The covenant hashes it and compares against a known script hash
# 3. If the hash matches, the data is authentic -- extract fields from it
#
# Use cases:
# - Bridge covenant reading state covenant's state root
# - Side-chain anchor verifying main-chain commitments
# - Oracle covenant referencing price feed covenant's data

class CrossCovenantRef < Runar::SmartContract
  # Hash of the expected source covenant's locking script.
  prop :source_script_hash, Sha256

  def initialize(source_script_hash)
    super(source_script_hash)
    @source_script_hash = source_script_hash
  end

  # Verify a referenced output and extract a 32-byte state root from it.
  #
  # referenced_output: The full serialized output from the source covenant
  # expected_state_root: The state root we expect to find in the referenced output
  # state_root_offset: Byte offset within the script where the state root starts
  runar_public referenced_output: ByteString, expected_state_root: ByteString, state_root_offset: Bigint
  def verify_and_extract(referenced_output, expected_state_root, state_root_offset)
    # Step 1: Hash the referenced output and verify it matches the known script hash.
    output_hash = hash256(referenced_output)
    assert output_hash == @source_script_hash

    # Step 2: Extract the state root from the referenced output.
    state_root = substr(referenced_output, state_root_offset, 32)

    # Step 3: Verify the extracted state root matches the expected value.
    assert state_root == expected_state_root
  end

  # Verify a referenced output and extract a numeric value from it.
  #
  # referenced_output: The full serialized output from the source covenant
  # expected_value: The numeric value we expect to find
  # value_offset: Byte offset within the script
  # value_len: Length in bytes of the numeric value
  runar_public referenced_output: ByteString, expected_value: Bigint, value_offset: Bigint, value_len: Bigint
  def verify_and_extract_numeric(referenced_output, expected_value, value_offset, value_len)
    output_hash = hash256(referenced_output)
    assert output_hash == @source_script_hash

    value_bytes = substr(referenced_output, value_offset, value_len)
    value = bin2num(value_bytes)
    assert value == expected_value
  end
end
