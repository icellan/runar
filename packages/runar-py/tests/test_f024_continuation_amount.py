"""F-024 (R14): the SDK's ANF interpreter derives the post-call state before
the tx exists; the covenant re-derives it on-chain. For a contract whose state
depends on ``continuationAmount()`` (the injected ``_newAmount``) and
``extractAmount(txPreimage)`` (the spent UTXO's satoshis), the SDK must feed the
interpreter those real values.

Proves: the Python SDK call path derives ``last_deposit = continuation - input``
from the call's real amounts (MockProvider's broadcast validation replays the
spend when bsv-sdk is installed), and the interpreter reads a caller-bound
``_newAmount`` / integer ``txPreimage``. Does NOT prove the other SDKs.
"""

from __future__ import annotations

import json

import pytest

from runar.sdk.anf_interpreter import compute_new_state
from runar.sdk.contract import RunarContract
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.local_signer import LocalSigner
from runar.sdk.provider import MockProvider
from runar.sdk.types import CallOptions, DeployOptions, RunarArtifact, Utxo

compiler = pytest.importorskip("runar_compiler.compiler")

KEY = "00" * 31 + "05"

SRC = '''from runar import StatefulSmartContract, Bigint, public, continuation_amount, extract_amount


class Tip(StatefulSmartContract):
    last_deposit: Bigint

    def __init__(self, last_deposit: Bigint):
        super().__init__(last_deposit)
        self.last_deposit = last_deposit

    @public
    def deposit(self):
        self.last_deposit = continuation_amount() - extract_amount(self.tx_preimage)
'''


def _artifact() -> RunarArtifact:
    result = compiler.compile_from_source_str_with_result(SRC, "Tip.runar.py")
    errs = [d.message for d in result.diagnostics if d.severity == "error"]
    assert result.artifact is not None, errs
    return RunarArtifact.from_dict(json.loads(compiler.artifact_to_json(result.artifact)))


def test_interpreter_reads_caller_bound_amounts():
    art = _artifact()
    out = compute_new_state(art.anf, "deposit", {"lastDeposit": 0}, {"_newAmount": 7000, "txPreimage": 5000}, [])
    assert out["lastDeposit"] == 2000


def test_call_path_derives_state_from_the_real_amounts():
    provider = MockProvider("testnet")
    signer = LocalSigner(KEY)
    provider.add_utxo(signer.get_address(), Utxo(
        txid=KEY[:64], output_index=0, satoshis=500_000, script=build_p2pkh_script(signer.get_public_key()),
    ))
    contract = RunarContract(_artifact(), [0])
    contract.deploy(provider, signer, DeployOptions(satoshis=10_000))
    contract.call("deposit", [], provider, signer, CallOptions(satoshis=12_500))
    assert contract.get_state()["lastDeposit"] == 2500
    assert contract._current_utxo.satoshis == 12_500
