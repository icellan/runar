"""
SHA-256 ``sha256Compress`` integration tests -- compile + deploy smoke tests
for ``examples/ts/sha256-compress/Sha256CompressTest.runar.ts``.

The full reference-vector matrix is exercised by ``integration/ts/sha256-compress.test.ts``;
this module satisfies the per-case gap (the audit lists ``sha256-compress`` as
a regtest case that must have a dedicated Python test file) and gives a
quick deploy smoke test against the real regtest node.
"""

import pytest

from conftest import compile_contract, create_provider, create_funded_wallet
from runar.sdk import RunarContract, DeployOptions


CONTRACT_PATH = "examples/ts/sha256-compress/Sha256CompressTest.runar.ts"


class TestSha256Compress:

    def test_compile(self):
        artifact = compile_contract(CONTRACT_PATH)
        assert artifact
        assert artifact.contract_name == "Sha256CompressTest"
        assert len(artifact.script) > 0

    def test_script_is_inlined_compression(self):
        """sha256Compress inlined should yield ~20-30 KB of script."""
        artifact = compile_contract(CONTRACT_PATH)
        script_bytes = len(artifact.script) // 2
        # Generous bounds — exact size drifts with peephole optimisation.
        assert 10_000 < script_bytes < 100_000, (
            f"expected 10-100 KB, got {script_bytes} bytes"
        )

    def test_deploy_with_zero_expected_digest(self):
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
