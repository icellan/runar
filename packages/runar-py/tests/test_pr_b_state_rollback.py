"""``prepare_call`` advances the contract's local state to the post-call state
BEFORE ``finalize_call`` broadcasts. When the broadcast was refused nothing put
it back, so the next call was built from a state the chain never reached (same
bug as the TS SDK, packages/runar-sdk/src/__tests__/pr-b-state-rollback.test.ts).

Proves: after a refused broadcast, ``get_state()`` and ``get_utxo()`` equal
their pre-call values, and an honest follow-up call commits n = 1.
"""

from __future__ import annotations

import copy
import json

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.provider import MockProvider
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.local_signer import LocalSigner
from runar.sdk.types import RunarArtifact, DeployOptions, Utxo

compiler = pytest.importorskip("runar_compiler.compiler")

SRC = '''import { StatefulSmartContract, assert } from 'runar-lang';

class Gate extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(k: bigint) {
    assert(k === 7n);
    this.n = this.n + 1n;
  }
}
'''


class _RefusingProvider(MockProvider):
    """A MockProvider whose broadcast fails while ``refuse`` is set, like a node
    rejecting the transaction. Needed because a plain MockProvider ACCEPTS
    bump(8) in an environment without the optional bsv-sdk script engine."""

    refuse = False

    def broadcast(self, tx):
        if self.refuse:
            raise RuntimeError("node refused the transaction (mandatory-script-verify-flag-failed)")
        return super().broadcast(tx)


def _artifact() -> RunarArtifact:
    result = compiler.compile_from_source_str_with_result(SRC, "Gate.runar.ts")
    errs = [d.message for d in result.diagnostics if d.severity == "error"]
    assert result.artifact is not None, errs
    return RunarArtifact.from_dict(json.loads(compiler.artifact_to_json(result.artifact)))


def _deploy_gate():
    provider = _RefusingProvider("testnet")
    signer = LocalSigner("11" * 32)
    provider.add_utxo(signer.get_address(), Utxo(
        txid="aa" * 32, output_index=0, satoshis=5_000_000,
        script=build_p2pkh_script(signer.get_public_key()),
    ))
    contract = RunarContract(_artifact(), [0])
    contract.deploy(provider, signer, DeployOptions(satoshis=50_000))
    return contract, provider, signer


def test_pr_b_state_rollback_refused_broadcast_leaves_state_untouched():
    contract, provider, signer = _deploy_gate()
    state_before = copy.deepcopy(contract.get_state())
    utxo_before = copy.deepcopy(contract.get_utxo())

    provider.refuse = True
    with pytest.raises(Exception, match="refused"):
        contract.call("bump", [8], provider, signer)
    assert contract.get_state() == state_before
    assert contract.get_utxo() == utxo_before

    provider.refuse = False
    contract.call("bump", [7], provider, signer)
    assert contract.get_state() == {"n": 1}


def test_pr_b_state_rollback_retried_and_repeated_finalize():
    """A PreparedCall whose broadcast was refused can be finalized again: the
    retry commits the post-call state. A further finalize of the now-committed
    PreparedCall that fails must not rewind the state the chain reached."""
    contract, provider, signer = _deploy_gate()
    utxo_before = copy.deepcopy(contract.get_utxo())

    prepared = contract.prepare_call("bump", [7], provider, signer)
    provider.refuse = True
    with pytest.raises(Exception, match="refused"):
        contract.finalize_call(prepared, {}, provider)
    assert contract.get_state() == {"n": 0}
    assert contract.get_utxo() == utxo_before

    provider.refuse = False
    contract.finalize_call(prepared, {}, provider)
    assert contract.get_state() == {"n": 1}
    utxo_after = copy.deepcopy(contract.get_utxo())

    provider.refuse = True
    with pytest.raises(Exception, match="refused"):
        contract.finalize_call(prepared, {}, provider)
    assert contract.get_state() == {"n": 1}
    assert contract.get_utxo() == utxo_after
