"""
SHA-256 ``sha256Finalize`` integration tests -- compile + deploy smoke tests
for ``examples/ts/sha256-finalize/Sha256FinalizeTest.runar.ts``.

``sha256Finalize`` adds FIPS 180-4 padding and compresses one or two blocks.
The cross-verification matrix against OP_SHA256 is in the TS suite
(``integration/ts/sha256-finalize.test.ts``); this module satisfies the
per-case Python gap and gives a quick deploy smoke test.
"""

import pytest

from conftest import compile_contract, create_provider, create_funded_wallet
from runar.sdk import RunarContract, DeployOptions


CONTRACT_PATH = "examples/ts/sha256-finalize/Sha256FinalizeTest.runar.ts"


class TestSha256Finalize:

    def test_compile(self):
        artifact = compile_contract(CONTRACT_PATH)
        assert artifact
        assert artifact.contract_name == "Sha256FinalizeTest"
        assert len(artifact.script) > 0

    def test_script_size_includes_finalize_padding(self):
        """sha256Finalize is larger than compress alone (padding + 1-2 blocks)."""
        artifact = compile_contract(CONTRACT_PATH)
        script_bytes = len(artifact.script) // 2
        # sha256Finalize emits 63941 ops in the Python ref; scripts ~70 KB.
        assert script_bytes > 30_000, f"expected >30 KB, got {script_bytes}"

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
