"""
BLAKE3 integration tests -- compile + deploy smoke tests for the
``examples/ts/blake3/Blake3Test.runar.ts`` reference contract.

The full reference-vector matrix is exercised by the TS suite
(``integration/ts/blake3.test.ts``); this module focuses on the per-case
gap by ensuring the BLAKE3 codegen produces a script that compiles and
deploys end-to-end against a real regtest node.
"""

import hashlib

import pytest

from conftest import compile_contract, create_provider, create_funded_wallet
from runar.sdk import RunarContract, DeployOptions


CONTRACT_PATH = "examples/ts/blake3/Blake3Test.runar.ts"


class TestBlake3:

    def test_compile(self):
        artifact = compile_contract(CONTRACT_PATH)
        assert artifact
        assert artifact.contract_name == "Blake3Test"
        assert len(artifact.script) > 0

    def test_script_size_is_in_blake3_range(self):
        """Blake3Compress + Blake3Hash inlined yields ~20-30 KB."""
        artifact = compile_contract(CONTRACT_PATH)
        script_bytes = len(artifact.script) // 2
        assert 10_000 < script_bytes < 100_000, (
            f"expected 10-100 KB, got {script_bytes} bytes"
        )

    def test_deploy_with_zero_digest(self):
        """Deploy locking the contract to a 32-byte zero ``expected`` value.

        We don't spend in this test because that requires a known on-chain
        BLAKE3 digest; spending is covered end-to-end by the TS suite.
        """
        artifact = compile_contract(CONTRACT_PATH)
        provider = create_provider()
        wallet = create_funded_wallet(provider)

        zero_digest = "00" * 32
        contract = RunarContract(artifact, [zero_digest])
        txid, _ = contract.deploy(
            provider, wallet["signer"], DeployOptions(satoshis=10_000),
        )
        assert txid
        assert len(txid) == 64
