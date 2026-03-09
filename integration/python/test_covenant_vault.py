"""
CovenantVault integration test -- stateless contract with checkSig + checkPreimage.

How It Works
============

CovenantVault demonstrates a covenant pattern: it constrains HOW funds can be spent,
not just WHO can spend them. The contract checks:
    1. The owner's ECDSA signature (authentication via checkSig)
    2. The transaction preimage (via checkPreimage / OP_PUSH_TX)
    3. That the transaction outputs match the expected P2PKH script to the recipient
       with amount >= minAmount (enforced by comparing hash256(expectedOutput) against
       extractOutputHash(txPreimage))

Constructor
    - owner: PubKey -- the ECDSA public key that must sign to spend
    - recipient: Addr -- the hash160 of the authorized recipient's public key
    - minAmount: bigint -- minimum satoshis that must be sent to the recipient

Method: spend(sig: Sig, txPreimage: SigHashPreimage)
    The compiler inserts an implicit _opPushTxSig parameter before the declared params.
    The full unlocking script order is: <opPushTxSig> <sig> <txPreimage>

Spending Limitation
    Covenant spending requires constructing a transaction whose outputs exactly match
    what the contract expects (a P2PKH output to the recipient for minAmount satoshis).
    The SDK's generic call() creates default outputs that don't match. For real
    applications, developers use the SDK's raw transaction builder.
"""

import pytest

from conftest import (
    compile_contract, create_provider, create_funded_wallet, create_wallet,
)
from runar.sdk import RunarContract, DeployOptions


class TestCovenantVault:

    def test_compile(self):
        """Compile the CovenantVault contract."""
        artifact = compile_contract("examples/ts/covenant-vault/CovenantVault.runar.ts")
        assert artifact
        assert artifact.contract_name == "CovenantVault"

    def test_deploy(self):
        """Deploy with owner, recipient, and minAmount."""
        artifact = compile_contract("examples/ts/covenant-vault/CovenantVault.runar.ts")

        provider = create_provider()
        owner = create_wallet()
        recipient = create_wallet()
        wallet = create_funded_wallet(provider)

        # Constructor: (owner: PubKey, recipient: Addr, minAmount: bigint)
        # Addr is a pubKeyHash (20-byte hash160)
        contract = RunarContract(artifact, [
            owner["pubKeyHex"],
            recipient["pubKeyHash"],
            1000,
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid
        assert isinstance(txid, str)
        assert len(txid) == 64

    def test_deploy_zero_min_amount(self):
        """Deploy with zero minAmount."""
        artifact = compile_contract("examples/ts/covenant-vault/CovenantVault.runar.ts")

        provider = create_provider()
        owner = create_wallet()
        recipient = create_wallet()
        wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            owner["pubKeyHex"],
            recipient["pubKeyHash"],
            0,
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

    def test_deploy_large_min_amount(self):
        """Deploy with large minAmount (1 BTC in satoshis)."""
        artifact = compile_contract("examples/ts/covenant-vault/CovenantVault.runar.ts")

        provider = create_provider()
        owner = create_wallet()
        recipient = create_wallet()
        wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            owner["pubKeyHex"],
            recipient["pubKeyHash"],
            100_000_000,
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

    def test_deploy_same_key_owner_recipient(self):
        """Deploy with the same key as owner and recipient."""
        artifact = compile_contract("examples/ts/covenant-vault/CovenantVault.runar.ts")

        provider = create_provider()
        both = create_wallet()
        wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            both["pubKeyHex"],
            both["pubKeyHash"],
            500,
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

    def test_wrong_signer_rejected(self):
        """Spend with wrong signer should be rejected (checkSig fails before covenant check)."""
        artifact = compile_contract("examples/ts/covenant-vault/CovenantVault.runar.ts")

        provider = create_provider()
        recipient = create_wallet()

        # Deploy with owner=walletA
        owner_wallet = create_funded_wallet(provider)
        wrong_wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"],
            recipient["pubKeyHash"],
            1000,
        ])

        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        # Call spend with walletB -- checkSig will fail on-chain
        with pytest.raises(Exception):
            contract.call(
                "spend", [None, None], provider, wrong_wallet["signer"],
            )
