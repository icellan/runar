"""
FunctionPatterns integration test -- stateful contract demonstrating private
methods, built-in functions, and method composition.

FunctionPatterns is a StatefulSmartContract with properties:
    - owner: PubKey (readonly)
    - balance: bigint (mutable)

The SDK auto-computes Sig params when None is passed.
"""

import pytest

from conftest import (
    compile_contract, create_provider, create_funded_wallet, create_wallet,
)
from runar.sdk import RunarContract, DeployOptions


class TestFunctionPatterns:

    def test_compile(self):
        """Compile the FunctionPatterns contract."""
        artifact = compile_contract("examples/ts/function-patterns/FunctionPatterns.runar.ts")
        assert artifact
        assert artifact.contract_name == "FunctionPatterns"

    def test_deploy_with_owner_and_balance(self):
        """Deploy with owner and initial balance of 1000."""
        artifact = compile_contract("examples/ts/function-patterns/FunctionPatterns.runar.ts")

        provider = create_provider()
        owner = create_wallet()
        wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            owner["pubKeyHex"],
            1000,
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=10000))
        assert txid
        assert isinstance(txid, str)
        assert len(txid) == 64

    def test_deploy_zero_balance(self):
        """Deploy with zero initial balance."""
        artifact = compile_contract("examples/ts/function-patterns/FunctionPatterns.runar.ts")

        provider = create_provider()
        owner = create_wallet()
        wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            owner["pubKeyHex"],
            0,
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=10000))
        assert txid

    def test_deploy_large_balance(self):
        """Deploy with a large initial balance."""
        artifact = compile_contract("examples/ts/function-patterns/FunctionPatterns.runar.ts")

        provider = create_provider()
        owner = create_wallet()
        wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            owner["pubKeyHex"],
            999_999_999,
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=10000))
        assert txid

    def test_distinct_deploy_txids(self):
        """Two instances with different owners should produce distinct txids."""
        artifact = compile_contract("examples/ts/function-patterns/FunctionPatterns.runar.ts")

        provider = create_provider()
        owner1 = create_wallet()
        owner2 = create_wallet()
        wallet = create_funded_wallet(provider)

        contract1 = RunarContract(artifact, [owner1["pubKeyHex"], 100])
        txid1, _ = contract1.deploy(provider, wallet["signer"], DeployOptions(satoshis=10000))

        contract2 = RunarContract(artifact, [owner2["pubKeyHex"], 200])
        txid2, _ = contract2.deploy(provider, wallet["signer"], DeployOptions(satoshis=10000))

        assert txid1
        assert txid2
        assert txid1 != txid2

    def test_deposit(self):
        """Deploy and deposit funds with auto-computed Sig."""
        artifact = compile_contract("examples/ts/function-patterns/FunctionPatterns.runar.ts")

        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)

        # Owner is the funded signer
        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"],
            100,
        ])

        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=10000))

        # deposit: sig=None (auto), amount=50
        call_txid, _ = contract.call(
            "deposit",
            [None, 50],
            provider, owner_wallet["signer"],
        )
        assert call_txid
        assert len(call_txid) == 64

    def test_deposit_then_withdraw(self):
        """Chain: deposit then withdraw."""
        artifact = compile_contract("examples/ts/function-patterns/FunctionPatterns.runar.ts")

        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"],
            1000,
        ])

        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=10000))

        # deposit(sig=None, amount=500) -> balance = 1500
        contract.call(
            "deposit",
            [None, 500],
            provider, owner_wallet["signer"],
        )

        # withdraw(sig=None, amount=200, feeBps=100) -> fee=2, balance=1298
        contract.call(
            "withdraw",
            [None, 200, 100],
            provider, owner_wallet["signer"],
        )

    def test_wrong_owner_rejected(self):
        """Deposit with wrong signer (not the owner) should be rejected."""
        artifact = compile_contract("examples/ts/function-patterns/FunctionPatterns.runar.ts")

        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        wrong_wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"],
            100,
        ])

        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=10000))

        with pytest.raises(Exception):
            contract.call(
                "deposit",
                [None, 50],
                provider, wrong_wallet["signer"],
            )
