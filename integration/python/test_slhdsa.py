"""
SLH-DSA integration tests -- compile + deploy smoke tests for the
SLH-DSA-SHA2 hybrid wallet contract.

Ported from integration/go/slhdsa_test.go. The deeper end-to-end spend
flow with full two-pass signing is exercised by ``test_sphincs_wallet.py``;
this module exists to satisfy the per-case test gap (the audit lists
``slhdsa`` as a regtest case that must have a dedicated Python test file)
and to give a quick deploy smoke test against the real regtest node.
"""

import pytest

from conftest import compile_contract, create_provider, create_funded_wallet, _hash160
from runar.sdk import RunarContract, DeployOptions


# Deterministic SLH-DSA-SHA2-128s test public key (32 bytes hex):
# PK.seed[16] || PK.root[16].
SLHDSA_TEST_PK = "00000000000000000000000000000000b618cb38f7f785488c9768f3a2972baf"
SLHDSA_TEST_PK_HASH = _hash160(bytes.fromhex(SLHDSA_TEST_PK))


CONTRACT_PATH = "examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts"


class TestSLHDSA:

    def test_compile(self):
        """Compile the SPHINCSWallet contract — uses the SLH-DSA codegen."""
        artifact = compile_contract(CONTRACT_PATH)
        assert artifact
        assert artifact.contract_name == "SPHINCSWallet"
        assert len(artifact.script) > 0

    def test_script_size_in_range(self):
        """Hybrid ECDSA+SLH-DSA-SHA2-128s scripts are ~150-300 KB."""
        artifact = compile_contract(CONTRACT_PATH)
        script_bytes = len(artifact.script) // 2
        assert 100_000 < script_bytes < 500_000, (
            f"expected 100-500 KB, got {script_bytes} bytes"
        )

    def test_deploy(self):
        """Deploy with ECDSA pubKeyHash + SLH-DSA pubKeyHash."""
        artifact = compile_contract(CONTRACT_PATH)
        provider = create_provider()
        wallet = create_funded_wallet(provider, btc_amount=2.0)

        contract = RunarContract(
            artifact, [wallet["pubKeyHash"], SLHDSA_TEST_PK_HASH],
        )

        # SLH-DSA scripts are huge, so request more dust to cover the deploy.
        txid, _ = contract.deploy(
            provider, wallet["signer"], DeployOptions(satoshis=50_000),
        )
        assert txid
        assert len(txid) == 64
