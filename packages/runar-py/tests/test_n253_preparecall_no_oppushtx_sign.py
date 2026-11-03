"""N-253: since F-369/N-213 the k=1 OP_PUSH_TX ECDSA signature is unused on the
stateful prepare_call path (the on-chain script derives it from the preimage),
yet the path still computed and discarded one per pass. The fix adds
``compute_op_push_tx_preimage`` and uses it there; ``compute_op_push_tx`` stays
public and unchanged.

Proves: a stateful merge prepare_call (the shared N-286 vector: primary + extra
contract input) performs zero OP_PUSH_TX signs, counted by wrapping
``_ecdsa_sign_k1``; the control shows the wrapper does see
``compute_op_push_tx`` sign and that the preimage-only variant returns the same
preimage without signing. Byte-identity of prepare_call output is proven by
test_n286_stateful_merge_prepared. Says nothing about the stateless / terminal
paths.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar.sdk import oppushtx
from runar.sdk.contract import RunarContract
from runar.sdk.local_signer import LocalSigner
from runar.sdk.provider import MockProvider
from runar.sdk.types import CallOptions, RunarArtifact, Utxo

VECTOR_PATH = (
    Path(__file__).resolve().parents[3]
    / "conformance" / "sdk-call" / "stateful-merge-prepared.json"
)


def _utxo(d: dict) -> Utxo:
    return Utxo(txid=d["txid"], output_index=d["outputIndex"], satoshis=d["satoshis"], script=d["script"])


@pytest.fixture
def k1_sign_count(monkeypatch):
    calls = {"n": 0}
    orig = oppushtx._ecdsa_sign_k1

    def counting(msg_hash):
        calls["n"] += 1
        return orig(msg_hash)

    monkeypatch.setattr(oppushtx, "_ecdsa_sign_k1", counting)
    return calls


def test_n253_stateful_prepare_call_computes_no_op_push_tx_signature(k1_sign_count):
    v = json.loads(VECTOR_PATH.read_text())
    e = v["expected"]
    art = RunarArtifact.from_dict(v["artifact"])

    signer = LocalSigner(v["privKeyHex"])
    provider = MockProvider("testnet")
    provider.add_utxo(signer.get_address(), _utxo(v["fundingUtxo"]))
    cu = _utxo(v["contractUtxo"])
    eu = _utxo(v["extraContractUtxo"])
    provider.add_contract_utxo(cu.script, cu)
    provider.add_contract_utxo(eu.script + ":extra", eu)

    contract = RunarContract.from_utxo(art, cu)
    prepared = contract.prepare_call(
        v["method"], [None], provider, signer,
        CallOptions(additional_contract_inputs=[eu]),
    )
    assert prepared.sighash == e["sighash"]
    assert k1_sign_count["n"] == 0, (
        f"stateful prepare_call computed {k1_sign_count['n']} OP_PUSH_TX signature(s); want 0"
    )


def test_n253_preimage_only_variant_matches_full_helper_without_signing(k1_sign_count):
    v = json.loads(VECTOR_PATH.read_text())
    tx_hex = v["expected"]["referenceTxHex"]
    cu = v["contractUtxo"]
    for flag in (0x41, 0x43):
        before = k1_sign_count["n"]
        _sig, full = oppushtx.compute_op_push_tx(tx_hex, 0, cu["script"], cu["satoshis"], -1, flag)
        assert k1_sign_count["n"] == before + 1
        only = oppushtx.compute_op_push_tx_preimage(tx_hex, 0, cu["script"], cu["satoshis"], -1, flag)
        assert k1_sign_count["n"] == before + 1
        assert only == full
    with pytest.raises(ValueError):
        oppushtx.compute_op_push_tx_preimage(tx_hex, 0, "", 1)
