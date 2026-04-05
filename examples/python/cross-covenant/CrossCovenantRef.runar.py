"""CrossCovenantRef -- Demonstrates reading another covenant's output.

This pattern allows one covenant to verify data from a DIFFERENT
transaction's output, enabling cross-covenant communication on BSV.

How it works:
  1. The unlocking script passes the referenced output data as a parameter
  2. The covenant hashes it and compares against a known script hash
  3. If the hash matches, the data is authentic -- extract fields from it

Use cases:
  - Bridge covenant reading state covenant's state root
  - Side-chain anchor verifying main-chain commitments
  - Oracle covenant referencing price feed covenant's data
"""

from runar import (
    SmartContract, ByteString, Sha256, Bigint, public, assert_,
    hash256, substr, bin2num,
)


class CrossCovenantRef(SmartContract):
    """Demonstrates cross-covenant output verification and data extraction."""

    source_script_hash: Sha256

    def __init__(self, source_script_hash: Sha256):
        super().__init__(source_script_hash)
        self.source_script_hash = source_script_hash

    @public
    def verify_and_extract(
        self,
        referenced_output: ByteString,
        expected_state_root: ByteString,
        state_root_offset: Bigint,
    ):
        """Verify a referenced output and extract a 32-byte state root."""
        # Step 1: Hash the referenced output and verify it matches the known script hash.
        output_hash = hash256(referenced_output)
        assert_(output_hash == self.source_script_hash)

        # Step 2: Extract the state root from the referenced output.
        state_root = substr(referenced_output, state_root_offset, 32)

        # Step 3: Verify the extracted state root matches the expected value.
        assert_(state_root == expected_state_root)

    @public
    def verify_and_extract_numeric(
        self,
        referenced_output: ByteString,
        expected_value: Bigint,
        value_offset: Bigint,
        value_len: Bigint,
    ):
        """Verify a referenced output and extract a numeric value."""
        output_hash = hash256(referenced_output)
        assert_(output_hash == self.source_script_hash)

        value_bytes = substr(referenced_output, value_offset, value_len)
        value = bin2num(value_bytes)
        assert_(value == expected_value)
