"""F-245 — the typed wrapper ``generate_python`` emits must not declare or
forward the intent-intrinsic witness params (``_prevOutScript_<i>``,
``_serialisedOutputs``). ``RunarContract.prepare_call`` supplies them from
``set_prev_out_script`` / ``set_serialised_outputs`` and excludes them from
its arity check, so a wrapper that forwards them is rejected by arity.

Proves: for the real compiled ``IntentPrevOutputScript`` example (its ``bind``
method carries the auto-injected ``_prevOutScript_0``), the generated wrapper,
exec'd as-is, deploys and calls ``bind()`` with no witness argument through the
default VALIDATING MockProvider and a real LocalSigner: the call passes the
arity check, the SDK's ANF auto-state step receives the witness it holds (it
used to fail closed with "requires witness bytes for '_prevOutScript_0'"),
and the broadcast tx carries the witness push. The funding input is
script-validated by bsv-sdk ``Spend``.
Does not prove: the covenant input's script validity. The Python MockProvider
counts OP_PUSH_TX covenant inputs as ``unvalidatable`` (bsv-sdk ``Spend``
rejects the push-tx OP_CHECKSIGVERIFY; see ``_COVENANT_PUSHTX_MARKER`` in
runar/sdk/provider.py), so a wrong witness would not be caught here. The TS
tier's end-to-end test covers script validity. The ``_serialisedOutputs`` path
is not exercised here either.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runar.sdk.codegen import generate_python
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.local_signer import LocalSigner
from runar.sdk.provider import MockProvider
from runar.sdk.types import DeployOptions, RunarArtifact, Utxo

compiler = pytest.importorskip("runar_compiler.compiler")

KEY = "00" * 31 + "09"
EXAMPLE = (
    Path(__file__).resolve().parents[3]
    / "examples/python/intent-prev-output-script/IntentPrevOutputScript.runar.py"
)


def _artifact() -> RunarArtifact:
    result = compiler.compile_from_source_str_with_result(EXAMPLE.read_text(), EXAMPLE.name)
    errs = [d.message for d in result.diagnostics if d.severity == "error"]
    assert result.artifact is not None, errs
    return RunarArtifact.from_dict(json.loads(compiler.artifact_to_json(result.artifact)))


def _hash256_hex(hex_str: str) -> str:
    b = bytes.fromhex(hex_str)
    return hashlib.sha256(hashlib.sha256(b).digest()).hexdigest()


def test_generated_wrapper_call_excludes_intent_witness_params():
    artifact = _artifact()
    bind = next(m for m in artifact.abi.methods if m.name == "bind")
    assert "_prevOutScript_0" in [p.name for p in bind.params]

    source = generate_python(artifact)
    assert "prev_out_script" not in source

    ns: dict = {}
    exec(compile(source, "<generated wrapper>", "exec"), ns)
    wrapper_cls = ns["IntentPrevOutputScriptContract"]

    witness = build_p2pkh_script("11" * 20)
    wrapper = wrapper_cls(artifact, expected_hash=_hash256_hex(witness), count=0)

    provider = MockProvider("testnet")  # validating (default)
    signer = LocalSigner(KEY)
    provider.add_utxo(signer.get_address(), Utxo(
        txid=KEY[:64], output_index=0, satoshis=500_000,
        script=build_p2pkh_script(signer.get_public_key()),
    ))
    wrapper.connect(provider, signer)
    wrapper.deploy(options=DeployOptions(satoshis=10_000))

    wrapper.contract.set_prev_out_script(0, witness)
    wrapper.bind()
    assert wrapper.contract.get_state()["count"] == 1
    call_tx = provider.get_broadcasted_txs()[-1]
    assert "19" + witness in call_tx, "witness push missing from the call tx"
    assert provider.last_validation_report["validated"] >= 1 or not provider.last_validation_report["script_vm_available"]
