"""N-038 — the Python SDK reproduces the cross-SDK SIGHASH_SINGLE stateful call
vector (``conformance/sdk-call/sighash-single-stateful.json``).

Under BIP-143 SINGLE the contract input commits hashOutputs to
hash256(output[0]) only, so the input-0 unlocking bytes depend on the inputs and
the continuation output, not on the change amount or fee policy. The SINGLE
method's ABI declares no ``_changePKH`` / ``_changeAmount``; the SDK must push
none, still add a change output, and still track the new state.

Proves: the Python SDK's call for the vector's inputs pushes byte-identical
input-0 unlocking bytes to the TS reference (which conformance/sdk-call/
sdk-call.test.ts replays through @bsv/sdk Spend: accept, and tampered output[0]
reject), builds the same continuation output, keeps a change output, and
advances the state to count == 1.
Does not prove: script execution in this tier — runar-py's MockProvider records
every covenant input as unvalidatable (see provider.py ``_COVENANT_PUSHTX_MARKER``),
so on-chain acceptance rests on the TS Spend replay of the identical bytes.
"""
from __future__ import annotations

import json
from pathlib import Path

from runar.sdk.contract import RunarContract
from runar.sdk.local_signer import LocalSigner
from runar.sdk.provider import MockProvider
from runar.sdk.types import RunarArtifact, Utxo

VECTOR = (
    Path(__file__).resolve().parents[3]
    / "conformance" / "sdk-call" / "sighash-single-stateful.json"
)


def _utxo(d: dict) -> Utxo:
    return Utxo(txid=d["txid"], output_index=d["outputIndex"], satoshis=d["satoshis"], script=d["script"])


def _parse_tx(raw_hex: str) -> tuple[list[str], list[tuple[int, str]]]:
    """(input unlocking scripts hex, [(satoshis, script hex)]) of a raw tx."""
    b = bytes.fromhex(raw_hex)
    pos = 4

    def varint() -> int:
        nonlocal pos
        n = b[pos]
        pos += 1
        if n < 0xFD:
            return n
        size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[n]
        v = int.from_bytes(b[pos:pos + size], "little")
        pos += size
        return v

    unlocks: list[str] = []
    for _ in range(varint()):
        pos += 36
        n = varint()
        unlocks.append(b[pos:pos + n].hex())
        pos += n + 4
    outs: list[tuple[int, str]] = []
    for _ in range(varint()):
        sats = int.from_bytes(b[pos:pos + 8], "little")
        pos += 8
        n = varint()
        outs.append((sats, b[pos:pos + n].hex()))
        pos += n
    return unlocks, outs


def test_single_call_matches_the_cross_sdk_vector():
    v = json.loads(VECTOR.read_text(encoding="utf-8"))
    exp = v["expected"]
    artifact = RunarArtifact.from_dict(v["artifact"])
    bump = next(m for m in artifact.abi.methods if m.name == "bump")
    assert [p.name for p in bump.params] == exp["methodParams"] == ["txPreimage"]

    signer = LocalSigner(v["privKeyHex"])
    assert signer.get_public_key() == v["pubKeyHex"]
    provider = MockProvider("testnet")
    funding = _utxo(v["fundingUtxo"])
    provider.add_utxo(signer.get_address(), funding)
    contract_utxo = _utxo(v["contractUtxo"])
    provider.add_contract_utxo(contract_utxo.script, contract_utxo)

    contract = RunarContract.from_utxo(artifact, contract_utxo)
    contract.call(v["method"], v["args"], provider, signer)
    raw = provider.get_broadcasted_txs()[-1]
    unlocks, outs = _parse_tx(raw)

    assert unlocks[0] == exp["input0UnlockingHex"]
    assert len(outs) == exp["outputCount"]
    assert outs[0] == (exp["output0"]["satoshis"], exp["output0"]["scriptHex"])
    assert outs[1][0] > 0  # the change output is present
    assert contract.get_state()["count"] == int(exp["newCount"])


def test_typed_codegen_treats_the_single_method_as_non_terminal():
    """The compiler omits ``isTerminal`` for a continuing method; codegen's
    fallback must not read the missing ``_changePKH`` as "terminal"."""
    from runar.sdk.codegen import _is_terminal_method

    v = json.loads(VECTOR.read_text(encoding="utf-8"))
    artifact = RunarArtifact.from_dict(v["artifact"])
    methods = {m.name: m for m in artifact.abi.methods}
    assert methods["bump"].is_terminal is None
    assert _is_terminal_method(methods["bump"], True) is False
    assert _is_terminal_method(methods["reset"], True) is False
