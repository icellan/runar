"""
FungibleToken integration test -- stateful contract with addOutput.

FungibleToken is a StatefulSmartContract with properties:
    - owner: PubKey (mutable)
    - balance: bigint (mutable)
    - tokenId: ByteString (readonly)

The SDK auto-computes Sig params when None is passed.
"""

import pytest

from conftest import (
    compile_contract, create_provider, create_funded_wallet, create_wallet,
)
from runar.sdk import RunarContract, DeployOptions, CallOptions


class TestFungibleToken:

    def test_compile(self):
        """Compile the FungibleToken contract."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")
        assert artifact
        assert artifact.contract_name == "FungibleToken"

    def test_deploy_with_owner_and_balance(self):
        """Deploy with owner and initial balance of 1000."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")

        provider = create_provider()
        owner = create_wallet()
        wallet = create_funded_wallet(provider)

        token_id_hex = b"TEST-TOKEN-001".hex()

        contract = RunarContract(artifact, [
            owner["pubKeyHex"],
            1000,
            0,
            token_id_hex,
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid
        assert isinstance(txid, str)
        assert len(txid) == 64

    def test_deploy_zero_balance(self):
        """Deploy with zero initial balance."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")

        provider = create_provider()
        owner = create_wallet()
        wallet = create_funded_wallet(provider)

        token_id_hex = b"ZERO-BAL-TOKEN".hex()

        contract = RunarContract(artifact, [
            owner["pubKeyHex"],
            0,
            0,
            token_id_hex,
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

    def test_deploy_large_balance(self):
        """Deploy with a very large balance (21M BTC in satoshis)."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")

        provider = create_provider()
        owner = create_wallet()
        wallet = create_funded_wallet(provider)

        token_id_hex = b"BIG-TOKEN".hex()

        contract = RunarContract(artifact, [
            owner["pubKeyHex"],
            21000000_00000000,
            0,
            token_id_hex,
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

    def test_send(self):
        """Deploy and send entire balance to a recipient."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")

        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        recipient = create_wallet()

        token_id_hex = b"SEND-TOKEN".hex()

        # Owner is the funded signer
        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"],
            1000,
            0,
            token_id_hex,
        ])

        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        # send: sig=None (auto), to=recipient, outputSatoshis=5000
        # State auto-computed from ANF IR (owner changes to recipient)
        call_txid, _ = contract.call(
            "send",
            [None, recipient["pubKeyHex"], 5000],
            provider, owner_wallet["signer"],
        )
        assert call_txid
        assert len(call_txid) == 64

    def test_wrong_owner_rejected(self):
        """Send with wrong signer (not the owner) should be rejected."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")

        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        wrong_wallet = create_funded_wallet(provider)
        recipient = create_wallet()

        token_id_hex = b"REJECT-TOKEN".hex()

        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"],
            1000,
            0,
            token_id_hex,
        ])

        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        with pytest.raises(Exception):
            contract.call(
                "send",
                [None, recipient["pubKeyHex"], 5000],
                provider, wrong_wallet["signer"],
                options=CallOptions(outputs=[
                    {"satoshis": 5000, "state": {"owner": recipient["pubKeyHex"], "balance": 1000, "mergeBalance": 0}},
                ]),
            )

    def test_transfer(self):
        """Transfer using SDK multi-output support: split 1 UTXO into 2 outputs."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")
        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        recipient = create_wallet()
        token_id_hex = b"TRANSFER-TOKEN".hex()

        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"], 1000, 0, token_id_hex,
        ])
        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        # transfer(sig, to, amount, outputSatoshis) — 2 outputs
        call_txid, _ = contract.call(
            "transfer",
            [None, recipient["pubKeyHex"], 300, 2000],
            provider, owner_wallet["signer"],
            options=CallOptions(outputs=[
                {"satoshis": 2000, "state": {"owner": recipient["pubKeyHex"], "balance": 300, "mergeBalance": 0}},
                {"satoshis": 2000, "state": {"owner": owner_wallet["pubKeyHex"], "balance": 700, "mergeBalance": 0}},
            ]),
        )
        assert call_txid
        assert len(call_txid) == 64

    def test_merge(self):
        """Merge using SDK additional-contract-input support: consolidate 2 UTXOs into 1."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")
        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        token_id_hex = b"MERGE-SDK-TOKEN".hex()

        contract1 = RunarContract(artifact, [owner_wallet["pubKeyHex"], 400, 0, token_id_hex])
        contract1.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        contract2 = RunarContract(artifact, [owner_wallet["pubKeyHex"], 600, 0, token_id_hex])
        contract2.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        utxo2 = contract2.get_utxo()
        call_txid, _ = contract1.call(
            "merge",
            [None, 600, None, 4000],
            provider, owner_wallet["signer"],
            options=CallOptions(
                additional_contract_inputs=[utxo2],
                additional_contract_input_args=[[None, 400, None, 4000]],
                outputs=[{"satoshis": 4000, "state": {"owner": owner_wallet["pubKeyHex"], "balance": 400, "mergeBalance": 600}}],
            ),
        )
        assert call_txid
        assert len(call_txid) == 64

    def test_merge_inflated_total(self):
        """Attacker claims inflated otherBalance. hashOutputs mismatch should reject."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")
        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        token_id_hex = b"MERGE-INFLATE".hex()

        contract1 = RunarContract(artifact, [owner_wallet["pubKeyHex"], 400, 0, token_id_hex])
        contract1.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        contract2 = RunarContract(artifact, [owner_wallet["pubKeyHex"], 600, 0, token_id_hex])
        contract2.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        utxo2 = contract2.get_utxo()

        with pytest.raises(Exception):
            contract1.call(
                "merge",
                [None, 1600, None, 4000],
                provider, owner_wallet["signer"],
                options=CallOptions(
                    additional_contract_inputs=[utxo2],
                    additional_contract_input_args=[[None, 1400, None, 4000]],
                    outputs=[{"satoshis": 4000, "state": {"owner": owner_wallet["pubKeyHex"], "balance": 400, "mergeBalance": 1600}}],
                ),
            )

    def test_merge_deflated(self):
        """Negative otherBalance fails assert(otherBalance >= 0)."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")
        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        token_id_hex = b"MERGE-DEFLATE".hex()

        contract1 = RunarContract(artifact, [owner_wallet["pubKeyHex"], 400, 0, token_id_hex])
        contract1.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        contract2 = RunarContract(artifact, [owner_wallet["pubKeyHex"], 600, 0, token_id_hex])
        contract2.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        utxo2 = contract2.get_utxo()

        with pytest.raises(Exception):
            contract1.call(
                "merge",
                [None, 100, None, 4000],
                provider, owner_wallet["signer"],
                options=CallOptions(
                    additional_contract_inputs=[utxo2],
                    additional_contract_input_args=[[None, -100, None, 4000]],
                    outputs=[{"satoshis": 4000, "state": {"owner": owner_wallet["pubKeyHex"], "balance": 400, "mergeBalance": 100}}],
                ),
            )

    def test_merge_zero_balance(self):
        """Edge case: one zero-balance UTXO merged with a non-zero one. Should succeed."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")
        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        token_id_hex = b"MERGE-ZERO".hex()

        contract1 = RunarContract(artifact, [owner_wallet["pubKeyHex"], 0, 0, token_id_hex])
        contract1.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        contract2 = RunarContract(artifact, [owner_wallet["pubKeyHex"], 500, 0, token_id_hex])
        contract2.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        utxo2 = contract2.get_utxo()

        call_txid, _ = contract1.call(
            "merge",
            [None, 500, None, 4000],
            provider, owner_wallet["signer"],
            options=CallOptions(
                additional_contract_inputs=[utxo2],
                additional_contract_input_args=[[None, 0, None, 4000]],
                outputs=[{"satoshis": 4000, "state": {"owner": owner_wallet["pubKeyHex"], "balance": 0, "mergeBalance": 500}}],
            ),
        )
        assert call_txid
        assert len(call_txid) == 64

    def test_merge_wrong_signer(self):
        """Wrong signer tries to merge. Should fail checkSig."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")
        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        wrong_wallet = create_funded_wallet(provider)
        token_id_hex = b"MERGE-WRONG".hex()

        contract1 = RunarContract(artifact, [owner_wallet["pubKeyHex"], 400, 0, token_id_hex])
        contract1.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        contract2 = RunarContract(artifact, [owner_wallet["pubKeyHex"], 600, 0, token_id_hex])
        contract2.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        utxo2 = contract2.get_utxo()

        with pytest.raises(Exception):
            contract1.call(
                "merge",
                [None, 600, None, 4000],
                provider, wrong_wallet["signer"],
                options=CallOptions(
                    additional_contract_inputs=[utxo2],
                    additional_contract_input_args=[[None, 400, None, 4000]],
                    outputs=[{"satoshis": 4000, "state": {"owner": owner_wallet["pubKeyHex"], "balance": 400, "mergeBalance": 600}}],
                ),
            )

    def test_transfer_exact_balance(self):
        """Transfer entire balance to recipient. Should produce 1 output (no change)."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")
        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        recipient = create_wallet()
        token_id_hex = b"XFER-EXACT".hex()

        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"], 1000, 0, token_id_hex,
        ])
        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        call_txid, _ = contract.call(
            "transfer",
            [None, recipient["pubKeyHex"], 1000, 2000],
            provider, owner_wallet["signer"],
            options=CallOptions(outputs=[
                {"satoshis": 2000, "state": {"owner": recipient["pubKeyHex"], "balance": 1000, "mergeBalance": 0}},
            ]),
        )
        assert call_txid
        assert len(call_txid) == 64

    def test_transfer_inflated_balance(self):
        """Attacker inflates output balances beyond input. Should be rejected."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")
        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        recipient = create_wallet()
        token_id_hex = b"XFER-INFLATE".hex()

        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"], 1000, 0, token_id_hex,
        ])
        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        # Claim recipient gets 800, sender keeps 500 = 1300 total (inflated from 1000)
        with pytest.raises(Exception):
            contract.call(
                "transfer",
                [None, recipient["pubKeyHex"], 800, 2000],
                provider, owner_wallet["signer"],
                options=CallOptions(outputs=[
                    {"satoshis": 2000, "state": {"owner": recipient["pubKeyHex"], "balance": 800, "mergeBalance": 0}},
                    {"satoshis": 2000, "state": {"owner": owner_wallet["pubKeyHex"], "balance": 500, "mergeBalance": 0}},
                ]),
            )

    def test_transfer_deflated_balance(self):
        """Attacker deflates output balances to steal tokens. Should be rejected."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")
        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        recipient = create_wallet()
        token_id_hex = b"XFER-DEFLATE".hex()

        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"], 1000, 0, token_id_hex,
        ])
        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        # Claim recipient gets 300, sender keeps 200 = 500 total (deflated from 1000)
        with pytest.raises(Exception):
            contract.call(
                "transfer",
                [None, recipient["pubKeyHex"], 300, 2000],
                provider, owner_wallet["signer"],
                options=CallOptions(outputs=[
                    {"satoshis": 2000, "state": {"owner": recipient["pubKeyHex"], "balance": 300, "mergeBalance": 0}},
                    {"satoshis": 2000, "state": {"owner": owner_wallet["pubKeyHex"], "balance": 200, "mergeBalance": 0}},
                ]),
            )

    def test_transfer_zero_amount_rejected(self):
        """Transfer of zero amount should fail assert(amount > 0)."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")
        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        recipient = create_wallet()
        token_id_hex = b"XFER-ZERO".hex()

        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"], 1000, 0, token_id_hex,
        ])
        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        with pytest.raises(Exception):
            contract.call(
                "transfer",
                [None, recipient["pubKeyHex"], 0, 2000],
                provider, owner_wallet["signer"],
                options=CallOptions(outputs=[
                    {"satoshis": 2000, "state": {"owner": recipient["pubKeyHex"], "balance": 0, "mergeBalance": 0}},
                    {"satoshis": 2000, "state": {"owner": owner_wallet["pubKeyHex"], "balance": 1000, "mergeBalance": 0}},
                ]),
            )

    def test_transfer_exceeds_balance_rejected(self):
        """Transfer exceeding balance should fail assert(amount <= totalBalance)."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")
        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        recipient = create_wallet()
        token_id_hex = b"XFER-EXCEED".hex()

        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"], 1000, 0, token_id_hex,
        ])
        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        with pytest.raises(Exception):
            contract.call(
                "transfer",
                [None, recipient["pubKeyHex"], 2000, 2000],
                provider, owner_wallet["signer"],
                options=CallOptions(outputs=[
                    {"satoshis": 2000, "state": {"owner": recipient["pubKeyHex"], "balance": 2000, "mergeBalance": 0}},
                ]),
            )

    def test_transfer_wrong_signer(self):
        """Wrong signer tries to transfer. Should fail checkSig."""
        artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts")
        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        wrong_wallet = create_funded_wallet(provider)
        recipient = create_wallet()
        token_id_hex = b"XFER-WRONG".hex()

        contract = RunarContract(artifact, [owner_wallet["pubKeyHex"], 1000, 0, token_id_hex])
        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        with pytest.raises(Exception):
            contract.call(
                "transfer",
                [None, recipient["pubKeyHex"], 300, 2000],
                provider, wrong_wallet["signer"],
                options=CallOptions(outputs=[
                    {"satoshis": 2000, "state": {"owner": recipient["pubKeyHex"], "balance": 300, "mergeBalance": 0}},
                    {"satoshis": 2000, "state": {"owner": owner_wallet["pubKeyHex"], "balance": 700, "mergeBalance": 0}},
                ]),
            )
