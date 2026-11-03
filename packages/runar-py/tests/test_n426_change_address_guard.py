"""N-426: the stateful change-address guard. Replays the shared cross-SDK
vector conformance/sdk-call/n426-change-address-guard.json (TS reference,
Spend-validated in conformance/sdk-call/n426-change-address-guard.test.ts).

Proves: on a stateful method that takes _changePKH, prepare_call refuses a
change_address for another key (no change_pub_key) with the shared message and
broadcasts nothing; change_address + the matching change_pub_key and a
change_address equal to the signer's own address are accepted.

Does NOT prove: the terminal path, finalize_call, or a live node.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.local_signer import LocalSigner
from runar.sdk.provider import MockProvider
from runar.sdk.types import CallOptions, RunarArtifact, Utxo

DIR = Path(__file__).resolve().parents[3] / "conformance" / "sdk-call"
G = json.loads((DIR / "n426-change-address-guard.json").read_text())
V = json.loads((DIR / "stateful-merge-prepared.json").read_text())


def _utxo(d: dict) -> Utxo:
    return Utxo(txid=d["txid"], output_index=d["outputIndex"], satoshis=d["satoshis"], script=d["script"])


def _prepare(opts: CallOptions):
    signer = LocalSigner(V["privKeyHex"])
    assert signer.get_address() == G["ownAddress"]
    provider = MockProvider("testnet")
    provider.add_utxo(signer.get_address(), _utxo(V["fundingUtxo"]))
    cu = _utxo(V["contractUtxo"])
    provider.add_contract_utxo(cu.script, cu)
    contract = RunarContract.from_utxo(RunarArtifact.from_dict(V["artifact"]), cu)
    return contract.prepare_call(V["method"], [None], provider, signer, opts), provider


def test_n426_refuses_change_address_for_another_key_without_change_pub_key():
    want = G["message"].replace("{changeAddress}", G["otherAddress"])
    signer = LocalSigner(V["privKeyHex"])
    provider = MockProvider("testnet")
    provider.add_utxo(signer.get_address(), _utxo(V["fundingUtxo"]))
    cu = _utxo(V["contractUtxo"])
    provider.add_contract_utxo(cu.script, cu)
    contract = RunarContract.from_utxo(RunarArtifact.from_dict(V["artifact"]), cu)
    with pytest.raises(Exception) as ei:
        contract.prepare_call(V["method"], [None], provider, signer,
                              CallOptions(change_address=G["otherAddress"]))
    assert want in str(ei.value)
    assert provider.get_broadcasted_txs() == []


def test_n426_accepts_change_address_with_matching_change_pub_key():
    prepared, _ = _prepare(CallOptions(change_address=G["otherAddress"], change_pub_key=G["otherPubKeyHex"]))
    assert prepared.sig_indices == [0]


def test_n426_accepts_change_address_equal_to_signers_own_address():
    prepared, _ = _prepare(CallOptions(change_address=G["ownAddress"]))
    assert prepared.sig_indices == [0]
