"""N-412: a STATELESS contract method that takes the auto-injected intent
witness ``_prevOutScript_0``. Replays the shared cross-SDK vector
conformance/sdk-call/stateless-witness.json (produced by the TS SDK, whose
MockProvider Spend-validated every input; re-checked with @bsv/sdk Spend --
including a tampered/omitted witness push -- in
conformance/sdk-call/stateless-witness.test.ts).

Proves: the Python SDK's call (no-Sig ``peek``, Sig ``spend``) and
prepare_call + finalize_call (``spend``) push
``<declared args> <witness> <selector>`` on input 0 and broadcast a tx
byte-equal to the TS reference.

Does NOT prove: a live node, or ``_serialisedOutputs`` on a stateless method
(the compiler refuses requireOutputP2PKH outside StatefulSmartContract).
"""

from __future__ import annotations

import json
from pathlib import Path

from runar.sdk.contract import RunarContract
from runar.sdk.local_signer import LocalSigner
from runar.sdk.provider import MockProvider
from runar.sdk.types import RunarArtifact, Utxo

VECTOR_PATH = (
    Path(__file__).resolve().parents[3]
    / "conformance" / "sdk-call" / "stateless-witness.json"
)


def _utxo(d: dict) -> Utxo:
    return Utxo(txid=d["txid"], output_index=d["outputIndex"], satoshis=d["satoshis"], script=d["script"])


def _fresh(v: dict):
    art = RunarArtifact.from_dict(v["artifact"])
    signer = LocalSigner(v["privKeyHex"])
    provider = MockProvider("testnet")
    provider.add_utxo(signer.get_address(), _utxo(v["fundingUtxo"]))
    cu = _utxo(v["contractUtxo"])
    provider.add_contract_utxo(cu.script, cu)
    contract = RunarContract.from_utxo(art, cu)
    contract.set_prev_out_script(0, v["prevOutScriptHex"])
    return contract, provider, signer


def _assert_broadcast(provider: MockProvider, want: dict) -> None:
    txs = provider.get_broadcasted_txs()
    assert len(txs) == 1
    assert want["input0UnlockingHex"] in txs[0]
    assert txs[0] == want["referenceTxHex"], "broadcast tx differs from the shared TS vector"


def test_n412_stateless_intent_witness_call_peek():
    v = json.loads(VECTOR_PATH.read_text())
    contract, provider, signer = _fresh(v)
    contract.call("peek", [5], provider, signer)
    _assert_broadcast(provider, v["expected"]["peek"])


def test_n412_stateless_intent_witness_call_spend():
    v = json.loads(VECTOR_PATH.read_text())
    contract, provider, signer = _fresh(v)
    contract.call("spend", [None, v["pubKeyHex"]], provider, signer)
    _assert_broadcast(provider, v["expected"]["spend"])


def test_n412_stateless_intent_witness_prepare_finalize_spend():
    v = json.loads(VECTOR_PATH.read_text())
    contract, provider, signer = _fresh(v)
    prepared = contract.prepare_call("spend", [None, v["pubKeyHex"]], provider, signer)
    assert prepared.sig_indices == [0]
    contract.finalize_call(prepared, {0: v["expected"]["spend"]["signatureHex"]}, provider)
    _assert_broadcast(provider, v["expected"]["spend"])
