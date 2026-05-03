"""PrivateHelperOutputs integration test — 2026-04-30 audit regression
(F1 + F3).

The contract delegates state mutation, addDataOutput, and addOutput to
private helpers. Before the F1 fix the auto-injection was a shallow
scan of the public method body, so these methods were silently
classified as terminal and the deploy + call cycle would fail.

Mirrors the TS / Go integration tests for the same contract.
"""

from conftest import (
    compile_contract, create_provider, create_funded_wallet,
)
from runar.sdk import RunarContract, DeployOptions


class TestPrivateHelperOutputs:

    def test_commit_chain(self):
        """Three sequential commits — each spends the previous
        continuation UTXO. Failure here means the runtime
        hashOutputs hash didn't match the compiled continuation,
        which is exactly what F1's shallow-scan miss would produce
        for state-mutation routed through a private helper."""
        artifact = compile_contract(
            "examples/ts/private-helper-outputs/PrivateHelperOutputs.runar.ts"
        )
        contract = RunarContract(artifact, [0])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(
            provider, wallet["signer"], DeployOptions(satoshis=5000)
        )

        for i in range(3):
            txid, _ = contract.call(
                "commit", [], provider, wallet["signer"],
            )
            assert txid, f"commit #{i + 1}: empty txid"

    def test_log_emits_data_output(self):
        """log routes a data output through a private helper —
        verifies the F1 fix's recursive scan picks up
        addDataOutput inside a private method."""
        artifact = compile_contract(
            "examples/ts/private-helper-outputs/PrivateHelperOutputs.runar.ts"
        )
        contract = RunarContract(artifact, [0])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(
            provider, wallet["signer"], DeployOptions(satoshis=5000)
        )

        # OP_RETURN-style payload (0x6a + 7-byte ASCII "hello!").
        payload = "6a0768656c6c6f21"
        txid, _ = contract.call(
            "log", [payload], provider, wallet["signer"],
        )
        assert txid
