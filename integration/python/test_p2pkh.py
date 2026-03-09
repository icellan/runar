"""
P2PKH integration test -- stateless contract with checkSig.

P2PKH locks funds to a public key hash. Spending requires a valid signature
and the matching public key. The SDK auto-computes Sig params when None is passed.
"""

import pytest

from conftest import (
    compile_contract, create_provider, create_funded_wallet, create_wallet,
)
from runar.sdk import RunarContract, DeployOptions


class TestP2PKH:

    def test_compile_and_deploy(self):
        """Compile and deploy with a valid pubKeyHash."""
        artifact = compile_contract("examples/ts/p2pkh/P2PKH.runar.ts")
        assert artifact
        assert artifact.contract_name == "P2PKH"

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [wallet["pubKeyHash"]])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid
        assert isinstance(txid, str)
        assert len(txid) == 64

    def test_deploy_and_spend(self):
        """Deploy and spend with unlock(sig, pubKey) -- Sig auto-computed."""
        artifact = compile_contract("examples/ts/p2pkh/P2PKH.runar.ts")

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [wallet["pubKeyHash"]])
        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        # None Sig and PubKey args are auto-computed by the SDK
        call_txid, _ = contract.call(
            "unlock", [None, None], provider, wallet["signer"],
        )
        assert call_txid
        assert len(call_txid) == 64

    def test_deploy_different_pubkey_hash(self):
        """Deploy with a different wallet's pubKeyHash as the lock target."""
        artifact = compile_contract("examples/ts/p2pkh/P2PKH.runar.ts")

        provider = create_provider()
        wallet = create_funded_wallet(provider)
        other = create_wallet()

        contract = RunarContract(artifact, [other["pubKeyHash"]])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

    def test_wrong_signer_rejected(self):
        """Unlock with wrong signer should be rejected."""
        artifact = compile_contract("examples/ts/p2pkh/P2PKH.runar.ts")

        provider = create_provider()
        wallet_a = create_funded_wallet(provider)
        wallet_b = create_funded_wallet(provider)

        # Lock to wallet_a's pubKeyHash
        contract = RunarContract(artifact, [wallet_a["pubKeyHash"]])
        contract.deploy(provider, wallet_a["signer"], DeployOptions(satoshis=5000))

        # Try to unlock with wallet_b's signer
        with pytest.raises(Exception):
            contract.call(
                "unlock", [None, None], provider, wallet_b["signer"],
            )
