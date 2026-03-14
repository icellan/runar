"""
InductiveToken integration test -- inductive contract with chain verification.

InductiveToken is an InductiveSmartContract with properties:
    - owner: PubKey (mutable)
    - balance: bigint (mutable)
    - tokenId: ByteString (readonly)

Constructor ABI: (owner, balance, tokenId, _genesisOutpoint, _proof)
The last two are internal fields initialized with zero sentinels at deploy time.

The SDK auto-computes Sig params when None is passed.
"""

import pytest

from conftest import (
    compile_contract, create_provider, create_funded_wallet, create_wallet,
)
from runar.sdk import RunarContract, DeployOptions, CallOptions


# ---------------------------------------------------------------------------
# Zero sentinels for internal inductive fields
# ---------------------------------------------------------------------------
ZERO_SENTINEL = "00" * 36    # 36 zero bytes (_genesisOutpoint)
ZERO_PROOF = "00" * 256      # 256 zero bytes (_proof)

# Inductive scripts are ~75 KB.  500K sats covers script + fees comfortably.
DEPLOY_SATS = 500_000


class TestInductiveToken:

    def test_compile(self):
        """Compile the InductiveToken contract."""
        artifact = compile_contract("examples/ts/inductive-token/InductiveToken.runar.ts")
        assert artifact
        assert artifact.contract_name == "InductiveToken"

    def test_deploy(self):
        """Deploy with owner and initial balance of 1000."""
        artifact = compile_contract("examples/ts/inductive-token/InductiveToken.runar.ts")

        provider = create_provider()
        owner = create_wallet()
        wallet = create_funded_wallet(provider)

        token_id_hex = b"INDUCTIVE-DEPLOY".hex()

        contract = RunarContract(artifact, [
            owner["pubKeyHex"],
            1000,
            token_id_hex,
            ZERO_SENTINEL,
            ZERO_PROOF,
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=DEPLOY_SATS))
        assert txid
        assert isinstance(txid, str)
        assert len(txid) == 64

    def test_send_chain(self):
        """Deploy and chain 3 sends: genesis + 2 non-genesis spends."""
        artifact = compile_contract("examples/ts/inductive-token/InductiveToken.runar.ts")

        provider = create_provider()
        owner_wallet = create_funded_wallet(provider, 2.0)

        token_id_hex = b"SEND-CHAIN".hex()

        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"],
            1000,
            token_id_hex,
            ZERO_SENTINEL,
            ZERO_PROOF,
        ])

        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=DEPLOY_SATS))

        # Tx1: first spend (genesis detection branch)
        tx1_id, _ = contract.call(
            "send",
            [None, owner_wallet["pubKeyHex"], 1],
            provider, owner_wallet["signer"],
            options=CallOptions(
                new_state={"owner": owner_wallet["pubKeyHex"]},
                satoshis=1,
            ),
        )
        assert tx1_id
        assert len(tx1_id) == 64

        # Tx2: second spend (non-genesis -- full parent verification)
        tx2_id, _ = contract.call(
            "send",
            [None, owner_wallet["pubKeyHex"], 1],
            provider, owner_wallet["signer"],
            options=CallOptions(
                new_state={"owner": owner_wallet["pubKeyHex"]},
                satoshis=1,
            ),
        )
        assert tx2_id
        assert len(tx2_id) == 64

        # Tx3: third spend (depth 3)
        tx3_id, _ = contract.call(
            "send",
            [None, owner_wallet["pubKeyHex"], 1],
            provider, owner_wallet["signer"],
            options=CallOptions(
                new_state={"owner": owner_wallet["pubKeyHex"]},
                satoshis=1,
            ),
        )
        assert tx3_id
        assert len(tx3_id) == 64

    def test_transfer_split(self):
        """Deploy, genesis send, then transfer (multi-output split)."""
        artifact = compile_contract("examples/ts/inductive-token/InductiveToken.runar.ts")

        provider = create_provider()
        owner_wallet = create_funded_wallet(provider, 2.0)
        recipient = create_wallet()

        token_id_hex = b"SPLIT-TOKEN".hex()

        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"],
            1000,
            token_id_hex,
            ZERO_SENTINEL,
            ZERO_PROOF,
        ])

        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=DEPLOY_SATS))

        # Tx1: genesis -- send to self
        contract.call(
            "send",
            [None, owner_wallet["pubKeyHex"], 1],
            provider, owner_wallet["signer"],
            options=CallOptions(
                new_state={"owner": owner_wallet["pubKeyHex"]},
                satoshis=1,
            ),
        )

        # Tx2: transfer (multi-output split) -- 300 to recipient, 700 to self
        call_txid, _ = contract.call(
            "transfer",
            [None, recipient["pubKeyHex"], 300, 1],
            provider, owner_wallet["signer"],
            options=CallOptions(outputs=[
                {"satoshis": 1, "state": {"owner": recipient["pubKeyHex"], "balance": 300}},
                {"satoshis": 1, "state": {"owner": owner_wallet["pubKeyHex"], "balance": 700}},
            ]),
        )
        assert call_txid
        assert len(call_txid) == 64

    def test_wrong_signer_rejected(self):
        """Wrong signer (not the owner) should be rejected by checkSig."""
        artifact = compile_contract("examples/ts/inductive-token/InductiveToken.runar.ts")

        provider = create_provider()
        owner_wallet = create_funded_wallet(provider, 2.0)
        wrong_wallet = create_funded_wallet(provider)

        token_id_hex = b"WRONG-SIGNER".hex()

        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"],
            1000,
            token_id_hex,
            ZERO_SENTINEL,
            ZERO_PROOF,
        ])

        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=DEPLOY_SATS))

        # Tx1: genesis (legitimate owner signs)
        contract.call(
            "send",
            [None, owner_wallet["pubKeyHex"], 1],
            provider, owner_wallet["signer"],
            options=CallOptions(
                new_state={"owner": owner_wallet["pubKeyHex"]},
                satoshis=1,
            ),
        )

        # Tx2: attacker tries to spend with wrong key
        with pytest.raises(Exception):
            contract.call(
                "send",
                [None, owner_wallet["pubKeyHex"], 1],
                provider, wrong_wallet["signer"],
                options=CallOptions(
                    new_state={"owner": owner_wallet["pubKeyHex"]},
                    satoshis=1,
                ),
            )

    def test_overspend_rejected(self):
        """Transfer amount > balance should fail assert(amount <= this.balance)."""
        artifact = compile_contract("examples/ts/inductive-token/InductiveToken.runar.ts")

        provider = create_provider()
        owner_wallet = create_funded_wallet(provider, 2.0)
        recipient = create_wallet()

        token_id_hex = b"OVERSPEND".hex()

        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"],
            100,
            token_id_hex,
            ZERO_SENTINEL,
            ZERO_PROOF,
        ])

        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=DEPLOY_SATS))

        # Tx1: genesis
        contract.call(
            "send",
            [None, owner_wallet["pubKeyHex"], 1],
            provider, owner_wallet["signer"],
            options=CallOptions(
                new_state={"owner": owner_wallet["pubKeyHex"]},
                satoshis=1,
            ),
        )

        # Tx2: try to transfer 200 when balance is only 100
        with pytest.raises(Exception):
            contract.call(
                "transfer",
                [None, recipient["pubKeyHex"], 200, 1],
                provider, owner_wallet["signer"],
                options=CallOptions(outputs=[
                    {"satoshis": 1, "state": {"owner": recipient["pubKeyHex"], "balance": 200}},
                    {"satoshis": 1, "state": {"owner": owner_wallet["pubKeyHex"], "balance": -100}},
                ]),
            )
