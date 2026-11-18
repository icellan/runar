"""Deep-review finding G1 (P1) — Python SDK.

A method that calls ``self.add_raw_output(...)`` produces a state-class output
which the compiler folds into the covenant continuation ``hashOutputs`` IN
SOURCE ORDER, interleaved with the ``self.add_output(...)`` state continuation.
The SDK call path must emit the outputs in that same source order, or the built
transaction's outputs mismatch ``hashOutputs`` → input 0's auto-injected
state-check ``OP_VERIFY`` rejects and the funds are stranded.

The shipped example ``RawOutputTest.send_to_script`` emits, in SOURCE order::

    self.add_raw_output(1000, script_bytes)  # raw output FIRST
    self.count = self.count + 1
    self.add_output(0, self.count)           # state continuation SECOND (0 sats)

so the on-chain output layout the covenant reconstructs is
``[raw(1000, script_bytes)] [stateContinuation(0)] [change]``. Emitting only the
state continuation (the pre-fix behaviour, which dropped raw outputs on the call
path) mismatches ``hashOutputs``.

This test deploys + calls ``send_to_script`` via ``MockProvider`` and asserts:

* the built call tx's outputs are exactly, in order,
  ``[0] raw = (1000, script_bytes)``,
  ``[1] state continuation = (0, codePart + OP_RETURN + serialized count)``,
  ``[2] change`` — the strongest deterministic proof available without a running
  Script VM (``bsv-sdk`` is an optional dependency of runar-py);
* the continuation UTXO is tracked at its REAL index (1, not 0) and its real
  0-sats value, so contract chaining stays correct behind raw outputs;
* (when ``bsv-sdk`` is importable) input 0 of the built call tx VALIDATES through
  the ``bsv`` ``Spend`` interpreter — the covenant ``OP_PUSH_TX`` + ``hashOutputs``
  ``OP_VERIFY`` actually passes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.provider import MockProvider
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.local_signer import LocalSigner
from runar.sdk.types import RunarArtifact, DeployOptions, Utxo
from runar.sdk.oppushtx import _parse_raw_tx

compiler = pytest.importorskip("runar_compiler.compiler")

DEPLOYER_KEY = "00" * 31 + "03"
CALLER_KEY = "00" * 31 + "04"

# The caller-supplied raw locking script: a plain P2PKH (76a914 <20 bytes> 88ac).
RAW_SCRIPT = "76a914" + "ab" * 20 + "88ac"

_EXAMPLE = (
    Path(__file__).resolve().parents[3]
    / "examples" / "python" / "add-raw-output" / "RawOutputTest.runar.py"
)


def _artifact() -> RunarArtifact:
    src = _EXAMPLE.read_text()
    result = compiler.compile_from_source_str_with_result(src, "RawOutputTest.runar.py")
    errs = [d.message for d in result.diagnostics if d.severity == "error"]
    assert result.artifact is not None, errs
    d = json.loads(compiler.artifact_to_json(result.artifact))
    return RunarArtifact.from_dict(d)


def _funded_signer(provider: MockProvider, key_hex: str, satoshis: int) -> LocalSigner:
    signer = LocalSigner(key_hex)
    # A REAL P2PKH script for this signer. The old fixture
    # ("76a914" + "00"*20 + "88ac") is not spendable by ANY key, so the funding
    # input it produced would be rejected by a node — visible only once
    # MockProvider stopped always-acking (testing-gap remediation Phase A5).
    provider.add_utxo(signer.get_address(), Utxo(
        txid=key_hex[:64],
        output_index=0,
        satoshis=satoshis,
        script=build_p2pkh_script(signer.get_public_key()),
    ))
    return signer


def _deploy_and_call():
    """Deploy RawOutputTest, call send_to_script(RAW_SCRIPT), return the
    contract + provider + the list of broadcast raw-tx hexes."""
    artifact = _artifact()
    provider = MockProvider("testnet")
    deployer = _funded_signer(provider, DEPLOYER_KEY, 500_000)
    caller = _funded_signer(provider, CALLER_KEY, 500_000)

    contract = RunarContract(artifact, [0])
    contract.deploy(provider, deployer, DeployOptions(satoshis=50_000))
    contract.call("sendToScript", [RAW_SCRIPT], provider, caller)
    return contract, provider, provider.get_broadcasted_txs()


def test_send_to_script_outputs_are_raw_state_change_in_order():
    """The built call tx must lay out [raw(1000)][state(0)][change]."""
    contract, _provider, txs = _deploy_and_call()

    # State advanced 0 -> 1 (self.count = self.count + 1).
    assert contract.get_state()["count"] == 1

    call_tx = _parse_raw_tx(bytes.fromhex(txs[1]))
    outs = call_tx["outputs"]

    # Three outputs in source order: raw, state continuation, change.
    assert len(outs) == 3

    # [0] raw output: 1000 sats, script === the caller-supplied bytes.
    assert outs[0]["satoshis"] == 1000
    assert outs[0]["script"].hex() == RAW_SCRIPT

    # [1] state continuation: 0 sats, codePart + OP_RETURN (6a) + serialized count.
    assert outs[1]["satoshis"] == 0
    state_script = outs[1]["script"].hex()
    assert state_script != RAW_SCRIPT
    assert "6a" in state_script

    # The SDK tracks the continuation at its REAL index (1) and 0-sats value.
    assert contract._current_utxo is not None
    assert contract._current_utxo.output_index == 1
    assert contract._current_utxo.script == state_script
    assert contract._current_utxo.satoshis == 0

    # [2] change: a P2PKH output (76a9…88ac) carrying the remainder.
    change_script = outs[2]["script"].hex()
    assert change_script.startswith("76a914")
    assert change_script.endswith("88ac")
    assert outs[2]["satoshis"] > 0


def test_send_to_script_covenant_input0_validates_through_spend():
    """Strongest attempted proof: replay input 0 through bsv-sdk's Spend
    interpreter and assert the covenant OP_PUSH_TX + hashOutputs OP_VERIFY
    passes. Skipped when bsv-sdk (the optional ScriptVM dependency) is absent.
    Needs bsv-sdk >= 2.5.0: older releases sighash the wrong scriptCode after
    OP_RETURN (bsv-blockchain/py-sdk#247)."""
    pytest.importorskip("bsv")
    from bsv.script.spend import Spend
    from bsv.transaction import Transaction

    contract, _provider, txs = _deploy_and_call()
    deploy_tx = Transaction.from_hex(txs[0])
    call_tx = Transaction.from_hex(txs[1])

    inp0 = call_tx.inputs[0]
    src_out = deploy_tx.outputs[0]  # the contract UTXO the call spends

    spend = Spend({
        "sourceTXID": inp0.source_txid,
        "sourceOutputIndex": inp0.source_output_index,
        "sourceSatoshis": src_out.satoshis,
        "lockingScript": src_out.locking_script,
        "transactionVersion": call_tx.version,
        "otherInputs": [
            inp for i, inp in enumerate(call_tx.inputs) if i != 0
        ],
        "outputs": call_tx.outputs,
        "inputIndex": 0,
        "unlockingScript": inp0.unlocking_script,
        "inputSequence": inp0.sequence,
        "lockTime": call_tx.locktime,
    })

    try:
        ok = spend.validate()
    except Exception as exc:  # noqa: BLE001 - upstream raises on covenant failure
        pytest.fail(f"covenant input 0 failed to validate: {exc}")
    assert ok is True

    # And the outputs the covenant validated against are in source order.
    assert call_tx.outputs[0].satoshis == 1000
    assert call_tx.outputs[0].locking_script.hex() == RAW_SCRIPT
    assert call_tx.outputs[1].satoshis == 0
