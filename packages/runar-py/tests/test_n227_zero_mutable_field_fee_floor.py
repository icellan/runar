"""N-227 (port of sdk:ts N-085): a zero-mutable-field ``StatefulSmartContract``
call underpays MockProvider's 100 sat/KB fee floor.

``AllReadonlyCleanstack`` has ZERO mutable fields, so its ``state_fields`` is
empty and ``prepare_call``'s ``is_stateful`` is ``False`` — even though the
contract IS ``parent_stateful`` (``parent_class == "StatefulSmartContract"``)
and still auto-injects ``checkPreimage`` / OP_CODESEPARATOR at method entry
(its ``claim`` method carries a visible ``txPreimage`` ABI param, so
``needs_op_push_tx`` is true via ``preimage_index is not None``). That routes
the call through ``prepare_call``'s "stateless" branch (``elif
needs_op_push_tx or sig_indices``), which — before this fix — never
recomputed fee/change from the REAL (final) unlocking script the way the
``is_stateful`` branch's rebuild does.

The injected OP_CODESEPARATOR sits right at method entry, so the BIP-143
scriptCode (everything after it) is almost the WHOLE locking script — far
bigger than the generic placeholder preimage the earlier sizing pass
assumed. The real unlocking script ends up hundreds of bytes bigger than
what fee/change were computed against, so the broadcast tx pays less than
the fee its own (larger) byte size requires.

Proves: the Python SDK's ``claim()`` call on a zero-mutable-field
StatefulSmartContract broadcasts a tx whose actual fee (computed from the
REAL broadcast bytes this test parses itself: sum of known input satoshis
minus sum of output satoshis) meets the 100 sat/KB floor
``MockProvider``'s fee rate reports. It also relies on
``MockProvider.broadcast``'s default-on ``spend.validate()`` check (see
``provider.py``, active here since ``bsv-sdk`` is installed) to prove the
rebuilt unlock is still a VALID spend of the locking script — not just
correctly sized.

Does NOT prove: the same fix in TypeScript (already fixed, N-085), Go, Rust,
Zig, Ruby or Java — each tier is a separate item slot. It also does not
prove anything about continuation-bearing (non-empty ``state_fields``)
stateful calls, which already take the ``is_stateful`` branch and were
unaffected by this bug, nor about a zero-mutable-field call that also merges
``additional_contract_inputs`` (N-227 Part 2 — a separate fail-closed guard,
covered by the sibling test below).
"""

from __future__ import annotations

import json

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.local_signer import LocalSigner
from runar.sdk.provider import MockProvider
from runar.sdk.types import CallOptions, DeployOptions, RunarArtifact, Utxo

compiler = pytest.importorskip("runar_compiler.compiler")

KEY = "0000000000000000000000000000000000000000000000000000000000000003"

SRC = """import { StatefulSmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';

class AllReadonlyCleanstack extends StatefulSmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public claim(sig: Sig): void {
    const ownerCopy = this.owner;
    assert(checkSig(sig, this.owner));
  }
}
"""


def _artifact() -> RunarArtifact:
    result = compiler.compile_from_source_str_with_result(SRC, "AllReadonlyCleanstack.runar.ts")
    errs = [d.message for d in result.diagnostics if d.severity == "error"]
    assert result.artifact is not None, errs
    return RunarArtifact.from_dict(json.loads(compiler.artifact_to_json(result.artifact)))


def _parse_tx(hex_str: str) -> tuple[int, int]:
    """Minimal raw-tx hex parser: returns (input_count, total_output_satoshis).

    Deliberately independent of any crate/library's internal tx types — reads
    the standard non-segwit Bitcoin tx wire format directly off the bytes the
    SDK broadcast.
    """
    data = bytes.fromhex(hex_str)
    pos = 0

    def read_varint() -> int:
        nonlocal pos
        first = data[pos]
        pos += 1
        if first == 0xFD:
            v = int.from_bytes(data[pos:pos + 2], "little")
            pos += 2
            return v
        if first == 0xFE:
            v = int.from_bytes(data[pos:pos + 4], "little")
            pos += 4
            return v
        if first == 0xFF:
            v = int.from_bytes(data[pos:pos + 8], "little")
            pos += 8
            return v
        return first

    pos += 4  # version
    input_count = read_varint()
    for _ in range(input_count):
        pos += 32 + 4  # prev txid + prev index
        script_len = read_varint()
        pos += script_len
        pos += 4  # sequence
    output_count = read_varint()
    total_output_satoshis = 0
    for _ in range(output_count):
        total_output_satoshis += int.from_bytes(data[pos:pos + 8], "little")
        pos += 8
        script_len = read_varint()
        pos += script_len

    return input_count, total_output_satoshis


def test_claim_on_all_readonly_cleanstack_pays_fee_floor():
    art = _artifact()

    # Sanity on the premise: zero mutable state fields, but still a real
    # StatefulSmartContract (auto-injects checkPreimage).
    assert art.parent_class == "StatefulSmartContract"
    assert not art.state_fields

    signer = LocalSigner(KEY)
    address = signer.get_address()
    pub_key = signer.get_public_key()

    provider = MockProvider("testnet")  # broadcast validation default-on
    provider.add_utxo(address, Utxo(
        txid="aa" * 32, output_index=0, satoshis=100_000, script=build_p2pkh_script(pub_key),
    ))

    contract = RunarContract(art, [pub_key])
    contract.deploy(provider, signer, DeployOptions(satoshis=5_000, change_address=address))

    # claim(sig, txPreimage): both auto-resolved. is_stateful is False here,
    # so neither param is hidden from the caller — mirrors the TS N-085
    # repro's [null, null].
    contract.call("claim", [None, None], provider, signer)

    call_hex = provider.get_broadcasted_txs()[-1]
    input_count, total_out = _parse_tx(call_hex)

    # Total input value: the contract's own deployed UTXO (5000 sats) plus,
    # if more than one input is present, the ONE funding UTXO this test
    # registered (100000 sats) — this test controls the entire UTXO
    # universe, so the input count alone determines which UTXOs were spent.
    total_in = 5_000
    if input_count > 1:
        total_in += 100_000

    actual_fee = total_in - total_out
    fee_rate = provider.get_fee_rate()
    tx_size_bytes = len(call_hex) // 2
    import math
    required_fee = math.ceil(tx_size_bytes * fee_rate / 1000.0)

    assert actual_fee >= required_fee, (
        f"fee too low: paid {actual_fee} sats, required >= {required_fee} sats "
        f"(tx size {tx_size_bytes} bytes, fee rate {fee_rate} sat/KB)"
    )


def test_claim_with_additional_contract_inputs_is_refused():
    """N-227 Part 2: a zero-mutable-field StatefulSmartContract call that
    also merges ``additional_contract_inputs`` must fail closed rather than
    broadcast an invalid tx. The ``is_stateful`` branch builds a REAL
    per-input unlock for every extra contract input; the non-stateful
    ("stateless") branch this contract's ``claim()`` takes has no
    equivalent — it would ship the SIZING placeholder unlock as the FINAL
    unlocking script for the extra input, which does not validate on-chain.
    """
    art = _artifact()
    assert not art.state_fields

    signer = LocalSigner(KEY)
    address = signer.get_address()
    pub_key = signer.get_public_key()

    provider = MockProvider("testnet")
    provider.add_utxo(address, Utxo(
        txid="aa" * 32, output_index=0, satoshis=100_000, script=build_p2pkh_script(pub_key),
    ))

    contract = RunarContract(art, [pub_key])
    contract.deploy(provider, signer, DeployOptions(satoshis=5_000, change_address=address))

    # The "extra" merge input's content is irrelevant — the guard must fire
    # before any unlock is built for it. Reuse the deployed contract's own
    # locking script so it is at least well-formed hex.
    extra = Utxo(
        txid="cc" * 32, output_index=0, satoshis=5_000,
        script=contract._current_utxo.script,
    )

    with pytest.raises(Exception):
        contract.call(
            "claim", [None, None], provider, signer,
            CallOptions(additional_contract_inputs=[extra]),
        )
