"""D25 (D12 PRE-F1) -- twin-input theft, Python SDK.

Two UTXOs of one stateful contract spent in ONE transaction that reach the
same post-state used to be satisfied by ONE continuation output (the covenant
hashes the whole output list; the preimage carries no input position), so the
second input's value left as the spender's change. The fix binds every
continuation to its input, per contract:

* class 1 (every continuation method mutate-only, e.g. Counter): SIGHASH_SINGLE
  by default; the SDK refuses to spend extra contract inputs into one SINGLE
  continuation.
* class 2 (MixedPot: an auto-continuation method next to an addOutput one):
  a hidden last state field ``_spentOutpointHash = sha256(outpoint)``.

Every transaction below is broadcast through ``MockProvider``, whose default
validation replays EVERY known input through the upstream bsv-sdk ``Spend``
interpreter. Mirrors packages/runar-sdk/src/__tests__/d25-twin-input.test.ts.

Proves: honest Counter and MixedPot call chains (both MixedPot methods, the
binding field tracked from the REAL spent outpoint) verify on every input; a
MixedPot twin built by the SDK's own merge path (``additional_contract_inputs``)
is refused on the SECOND input for both methods, while the identical twin of a
class-3 contract without the binding verifies on both (control: the SDK
assembles the shape, so the refusal is the binding); a Counter twin is refused
up front; PreparedCall.sighash under a SINGLE covenant is the ALL|FORKID digest.
Does not prove: regtest acceptance.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.errors import BroadcastRejected
from runar.sdk.local_signer import LocalSigner
from runar.sdk.oppushtx import compute_op_push_tx_preimage
from runar.sdk.provider import MockProvider, _bsv_sdk_available
from runar.sdk.types import CallOptions, DeployOptions, RunarArtifact, Utxo

compiler = pytest.importorskip("runar_compiler.compiler")

pytestmark = pytest.mark.skipif(
    not _bsv_sdk_available(),
    reason="bsv-sdk not installed: the Spend replay these tests rest on cannot run",
)

ROOT = Path(__file__).resolve().parents[3]
COUNTER_PATH = ROOT / "examples" / "ts" / "stateful-counter" / "Counter.runar.ts"
BINDING_FIELD = "_spentOutpointHash"
KEY = "00" * 31 + "03"

MIXED_SRC = """
import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';

class MixedPot extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment() {
    this.count++;
  }

  public bump() {
    this.addOutput(extractAmount(this.txPreimage), this.count + 1n);
  }
}
"""

# Class 3 (explicit outputs only): MixedPot minus its auto-continuation method.
# No binding; the twin aliasing is documented and warned about.
EXPLICIT_SRC = """
import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';

class ExplicitPot extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public bump() {
    this.addOutput(extractAmount(this.txPreimage), this.count + 1n);
  }
}
"""


def _artifact(src: str, file_name: str) -> RunarArtifact:
    r = compiler.compile_from_source_str_with_result(src, file_name)
    errs = [d.message for d in r.diagnostics if d.severity == "error"]
    assert r.artifact is not None, errs
    return RunarArtifact.from_dict(json.loads(compiler.artifact_to_json(r.artifact)))


def _counter() -> RunarArtifact:
    return _artifact(COUNTER_PATH.read_text(encoding="utf-8"), "Counter.runar.ts")


def _mixed() -> RunarArtifact:
    return _artifact(MIXED_SRC, "MixedPot.runar.ts")


def _outpoint_hash(txid: str, vout: int) -> str:
    return hashlib.sha256(bytes.fromhex(txid)[::-1] + vout.to_bytes(4, "little")).hexdigest()


def _provider(signer: LocalSigner) -> MockProvider:
    p = MockProvider("testnet")  # broadcast validation default-on
    p.add_utxo(signer.get_address(), Utxo(
        txid="bb" * 32, output_index=0, satoshis=500_000,
        script=build_p2pkh_script(signer.get_public_key()),
    ))
    return p


def _assert_every_input_validated(p: MockProvider) -> None:
    report = p.last_validation_report
    assert report["script_vm_available"] is True, report
    assert report["unknown"] == 0, report
    assert report["validated"] == report["total"], report


def _method(art: RunarArtifact, name: str):
    return next(m for m in art.abi.methods if m.name == name)


# ---------------------------------------------------------------------------
# class 1 -- Counter
# ---------------------------------------------------------------------------

def test_counter_methods_are_single_and_take_no_change_params():
    art = _counter()
    for name in ("increment", "decrement"):
        m = _method(art, name)
        assert m.sig_hash_type == 0x43
        assert [p.name for p in m.params] == ["_newAmount", "txPreimage"]
    assert [f.name for f in art.state_fields] == ["count"]


def test_counter_honest_call_chain_validates_on_spend():
    art = _counter()
    signer = LocalSigner(KEY)
    p = _provider(signer)
    c = RunarContract(art, [0])
    c.deploy(p, signer, DeployOptions(satoshis=5_000))
    _assert_every_input_validated(p)

    for method in ("increment", "increment", "decrement"):
        c.call(method, [], p, signer)
        _assert_every_input_validated(p)
    assert c.get_state()["count"] == 1
    # The continuation is output 0 (== the contract's input index) and keeps
    # its value (F-024 floor).
    assert c.get_utxo().output_index == 0
    assert c.get_utxo().satoshis == 5_000


def test_counter_twin_is_refused_before_building():
    art = _counter()
    signer = LocalSigner(KEY)
    script = RunarContract(art, [0]).get_locking_script()
    primary = Utxo(txid="c0" * 32, output_index=0, satoshis=5_000, script=script)
    extra = Utxo(txid="c1" * 32, output_index=1, satoshis=5_000, script=script)
    p = _provider(signer)
    p.add_contract_utxo(script, primary)
    p.add_contract_utxo(script + ":extra", extra)
    c = RunarContract.from_utxo(art, primary)
    with pytest.raises(ValueError, match="additionalContractInputs cannot be spent into one continuation"):
        c.call("increment", [], p, signer, CallOptions(additional_contract_inputs=[extra]))
    assert p.get_broadcasted_txs() == []


def test_prepared_call_sighash_is_the_all_forkid_digest_under_a_single_covenant():
    art = _counter()
    signer = LocalSigner(KEY)
    p = _provider(signer)
    c = RunarContract(art, [0])
    c.deploy(p, signer, DeployOptions(satoshis=5_000))
    utxo = c.get_utxo()
    prepared = c.prepare_call("increment", [], p, signer)
    tx = prepared.tx_hex
    code_sep = c._get_code_sep_index(c._find_method_index("increment"))
    pre_all = compute_op_push_tx_preimage(tx, 0, utxo.script, utxo.satoshis, code_sep, 0x41)
    pre_single = compute_op_push_tx_preimage(tx, 0, utxo.script, utxo.satoshis, code_sep, 0x43)
    sha256d = lambda h: hashlib.sha256(hashlib.sha256(bytes.fromhex(h)).digest()).hexdigest()  # noqa: E731
    assert prepared.preimage == pre_single
    assert prepared.sighash == sha256d(pre_all)
    assert prepared.sighash != sha256d(pre_single)


# ---------------------------------------------------------------------------
# class 2 -- MixedPot
# ---------------------------------------------------------------------------

def test_mixed_pot_carries_the_hidden_binding_field():
    art = _mixed()
    assert [f.name for f in art.state_fields] == ["count", BINDING_FIELD]
    assert [p.name for p in art.abi.constructor_params] == ["count"]
    assert _method(art, "increment").sig_hash_type in (None, 0x41)
    assert _method(art, "bump").sig_hash_type in (None, 0x41)


def test_mixed_pot_honest_call_chain_validates_on_spend():
    art = _mixed()
    signer = LocalSigner(KEY)
    p = _provider(signer)
    c = RunarContract(art, [0])
    c.deploy(p, signer, DeployOptions(satoshis=5_000))
    _assert_every_input_validated(p)
    assert c.get_state()[BINDING_FIELD] == "00" * 32

    expected = 0
    for method in ("increment", "bump", "increment", "bump"):
        spent = c.get_utxo()
        c.call(method, [], p, signer)
        _assert_every_input_validated(p)
        expected += 1
        state = c.get_state()
        assert state["count"] == expected
        # The binding is the REAL outpoint of the UTXO this call spent.
        assert state[BINDING_FIELD] == _outpoint_hash(spent.txid, spent.output_index)


def _twin(art: RunarArtifact, method: str) -> MockProvider:
    signer = LocalSigner(KEY)
    script = RunarContract(art, [0]).get_locking_script()
    primary = Utxo(txid="c0" * 32, output_index=0, satoshis=5_000, script=script)
    extra = Utxo(txid="c1" * 32, output_index=1, satoshis=5_000, script=script)
    p = _provider(signer)
    p.add_contract_utxo(script, primary)
    p.add_contract_utxo(script + ":extra", extra)
    c = RunarContract.from_utxo(art, primary)
    c.call(method, [], p, signer, CallOptions(additional_contract_inputs=[extra]))
    return p


@pytest.mark.parametrize("method", ["increment", "bump"])
def test_mixed_pot_twin_is_refused_on_the_second_input(method):
    art = _mixed()
    with pytest.raises(BroadcastRejected, match=r"input 1"):
        _twin(art, method)


def test_control_explicit_contract_twin_verifies_on_both_inputs():
    """Class 3 has no binding (documented, warned): the SAME SDK-built twin
    verifies on every input, so the class-2 refusal above is the binding,
    not an SDK assembly failure."""
    art = _artifact(EXPLICIT_SRC, "ExplicitPot.runar.ts")
    assert [f.name for f in art.state_fields] == ["count"]
    p = _twin(art, "bump")
    _assert_every_input_validated(p)
    assert p.last_validation_report["total"] == 3
