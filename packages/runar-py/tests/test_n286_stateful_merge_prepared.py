"""N-286: a stateful merge through the two-phase API (prepare_call /
finalize_call). Replays the shared cross-SDK vector
conformance/sdk-call/stateful-merge-prepared.json (produced by the TS SDK,
whose MockProvider Spend-validated all three inputs; re-checked with Spend in
conformance/sdk-call/stateful-merge.test.ts).

Proves: given the vector's artifact, two contract UTXOs, funding UTXO and key,
the Python SDK's prepare_call yields the same primary sighash and sig indices,
and finalize_call with the vector's primary signature broadcasts a tx
byte-equal to the TS reference (extra contract input's unlock, fee and change
included).

Does NOT prove: a live node.
"""

from __future__ import annotations

import json
from pathlib import Path

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


def test_n286_stateful_merge_prepare_finalize_matches_shared_vector():
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
    assert prepared.sig_indices == e["sigIndices"]
    assert prepared.sighash == e["sighash"]

    contract.finalize_call(prepared, {0: e["primarySignatureHex"]}, provider)
    txs = provider.get_broadcasted_txs()
    assert len(txs) == 1
    assert txs[0] == e["referenceTxHex"], "broadcast tx differs from the shared TS vector"
