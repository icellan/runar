"""
Escrow integration test -- stateless contract with dual-signature checkSig.

Escrow locks funds and allows release or refund via two methods, each
requiring signatures from two parties (dual-sig):
  - release(sellerSig, arbiterSig) -- seller + arbiter must both sign
  - refund(buyerSig, arbiterSig) -- buyer + arbiter must both sign

This ensures no party can act alone. The arbiter serves as the trust anchor.

The SDK auto-computes Sig params when None is passed. We use the same key
for both required roles so both auto-computed signatures match.
"""

import pytest

from conftest import (
    compile_contract, create_provider, create_funded_wallet, create_wallet,
)
from runar.sdk import RunarContract, DeployOptions


class TestEscrow:

    def test_compile(self):
        """Compile the Escrow contract."""
        artifact = compile_contract("examples/ts/escrow/Escrow.runar.ts")
        assert artifact
        assert artifact.contract_name == "Escrow"

    def test_deploy_three_pubkeys(self):
        """Deploy with three distinct pubkeys (buyer, seller, arbiter)."""
        artifact = compile_contract("examples/ts/escrow/Escrow.runar.ts")

        provider = create_provider()
        buyer = create_wallet()
        seller = create_wallet()
        arbiter = create_wallet()
        wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            buyer["pubKeyHex"],
            seller["pubKeyHex"],
            arbiter["pubKeyHex"],
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid
        assert isinstance(txid, str)
        assert len(txid) == 64

    def test_deploy_same_key_multiple_roles(self):
        """Deploy with the same key as both buyer and arbiter."""
        artifact = compile_contract("examples/ts/escrow/Escrow.runar.ts")

        provider = create_provider()
        buyer_and_arbiter = create_wallet()
        seller = create_wallet()
        wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            buyer_and_arbiter["pubKeyHex"],
            seller["pubKeyHex"],
            buyer_and_arbiter["pubKeyHex"],
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

    def test_release(self):
        """Deploy and spend via release(sellerSig, arbiterSig) with auto-computed Sigs.

        Uses the same key for both seller and arbiter roles so both
        auto-computed signatures match.
        """
        artifact = compile_contract("examples/ts/escrow/Escrow.runar.ts")

        provider = create_provider()
        buyer = create_wallet()
        # Signer is both seller and arbiter
        signer_wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            buyer["pubKeyHex"],
            signer_wallet["pubKeyHex"],
            signer_wallet["pubKeyHex"],
        ])

        contract.deploy(provider, signer_wallet["signer"], DeployOptions(satoshis=5000))

        # release(sellerSig=None, arbiterSig=None) — both auto-computed from signer
        call_txid, _ = contract.call(
            "release", [None, None], provider, signer_wallet["signer"],
        )
        assert call_txid
        assert len(call_txid) == 64

    def test_refund(self):
        """Deploy and spend via refund(buyerSig, arbiterSig) with auto-computed Sigs.

        Uses the same key for both buyer and arbiter roles.
        """
        artifact = compile_contract("examples/ts/escrow/Escrow.runar.ts")

        provider = create_provider()
        seller = create_wallet()
        # Signer is both buyer and arbiter
        signer_wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            signer_wallet["pubKeyHex"],
            seller["pubKeyHex"],
            signer_wallet["pubKeyHex"],
        ])

        contract.deploy(provider, signer_wallet["signer"], DeployOptions(satoshis=5000))

        # refund(buyerSig=None, arbiterSig=None)
        call_txid, _ = contract.call(
            "refund", [None, None], provider, signer_wallet["signer"],
        )
        assert call_txid
        assert len(call_txid) == 64

    def test_release_wrong_signer_rejected(self):
        """release with wrong signer should be rejected (checkSig fails)."""
        artifact = compile_contract("examples/ts/escrow/Escrow.runar.ts")

        provider = create_provider()
        buyer = create_wallet()
        # Deploy with seller=arbiter=walletA
        wallet_a = create_funded_wallet(provider)
        wallet_b = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            buyer["pubKeyHex"],
            wallet_a["pubKeyHex"],
            wallet_a["pubKeyHex"],
        ])

        contract.deploy(provider, wallet_a["signer"], DeployOptions(satoshis=5000))

        with pytest.raises(Exception):
            contract.call(
                "release", [None, None], provider, wallet_b["signer"],
            )

    def test_refund_wrong_signer_rejected(self):
        """refund with wrong signer should be rejected (checkSig fails)."""
        artifact = compile_contract("examples/ts/escrow/Escrow.runar.ts")

        provider = create_provider()
        seller = create_wallet()
        # Deploy with buyer=arbiter=walletA
        wallet_a = create_funded_wallet(provider)
        wallet_b = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            wallet_a["pubKeyHex"],
            seller["pubKeyHex"],
            wallet_a["pubKeyHex"],
        ])

        contract.deploy(provider, wallet_a["signer"], DeployOptions(satoshis=5000))

        with pytest.raises(Exception):
            contract.call(
                "refund", [None, None], provider, wallet_b["signer"],
            )
