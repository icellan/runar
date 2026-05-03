"""
MessageBoard integration tests -- a stateful contract with a ``ByteString``
mutable state field. Mirrors ``integration/ts/message-board.test.ts`` and
satisfies the per-case audit gap for Python.
"""

import pytest

from conftest import compile_contract, create_provider, create_funded_wallet
from runar.sdk import RunarContract, DeployOptions


CONTRACT_PATH = "examples/ts/message-board/MessageBoard.runar.ts"


class TestMessageBoard:

    def test_compile(self):
        artifact = compile_contract(CONTRACT_PATH)
        assert artifact
        assert artifact.contract_name == "MessageBoard"
        assert len(artifact.script) > 0

    def test_deploy_with_initial_message(self):
        """Deploy with an initial 'hello' message and the owner's pubkey."""
        artifact = compile_contract(CONTRACT_PATH)
        provider = create_provider()
        wallet = create_funded_wallet(provider)

        initial_message = "68656c6c6f"  # 'hello'
        contract = RunarContract(
            artifact, [initial_message, wallet["pubKeyHex"]],
        )
        txid, _ = contract.deploy(
            provider, wallet["signer"], DeployOptions(satoshis=10_000),
        )
        assert txid
        assert len(txid) == 64

    def test_post_updates_state_message(self):
        """post(newMessage) is a no-signature mutation that replaces state."""
        artifact = compile_contract(CONTRACT_PATH)
        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract = RunarContract(
            artifact, ["68656c6c6f", wallet["pubKeyHex"]],
        )
        contract.deploy(
            provider, wallet["signer"], DeployOptions(satoshis=10_000),
        )

        new_message = "776f726c64"  # 'world'
        call_txid, _ = contract.call(
            "post", [new_message], provider, wallet["signer"],
        )
        assert call_txid
        assert len(call_txid) == 64
