"""D12 SDK-F1/F2: ``prepare_call`` must never leave the tracked state or
``current_utxo`` changed. It used to advance ``_state`` to the post-call state
and then do more fallible work (``get_utxos``, ``get_fee_rate``, funding
signing); a throw there left the state at n+1 while the chain was at n. An
abandoned or superseded PreparedCall did the same. Semantics now:
``prepare_call`` carries the post-state in the PreparedCall and
``finalize_call`` commits it only after a successful broadcast.

Proves: a ``get_utxos`` / ``get_fee_rate`` failure inside ``prepare_call`` and
an abandoned PreparedCall leave state + UTXO untouched; prepare A, prepare B,
finalize A ok, finalize B fails -> state is A's post-state.
Does not prove: interpreter verdicts (needs the optional bsv-sdk Spend).
"""

from __future__ import annotations

import copy

import pytest

from tests.test_pr_b_state_rollback import _deploy_gate, _RefusingProvider  # noqa: F401


def _fail_once(provider, attr):
    orig = getattr(provider, attr)
    state = {"armed": True}

    def wrapped(*a, **kw):
        if state["armed"]:
            state["armed"] = False
            raise RuntimeError(f"{attr}: ECONNRESET")
        return orig(*a, **kw)

    setattr(provider, attr, wrapped)


@pytest.mark.parametrize("attr", ["get_utxos", "get_fee_rate"])
def test_prepare_call_throw_leaves_state_untouched(attr):
    contract, provider, signer = _deploy_gate()
    state_before = copy.deepcopy(contract.get_state())
    utxo_before = copy.deepcopy(contract.get_utxo())
    _fail_once(provider, attr)
    with pytest.raises(Exception, match="ECONNRESET"):
        contract.call("bump", [7], provider, signer)
    assert contract.get_state() == state_before
    assert contract.get_utxo() == utxo_before
    contract.call("bump", [7], provider, signer)
    assert contract.get_state() == {"n": 1}


def test_abandoned_prepared_call_leaves_state_untouched():
    contract, provider, signer = _deploy_gate()
    contract.prepare_call("bump", [7], provider, signer)
    assert contract.get_state() == {"n": 0}
    contract.call("bump", [7], provider, signer)
    assert contract.get_state() == {"n": 1}


def test_superseded_prepare_failed_finalize_keeps_committed_state():
    contract, provider, signer = _deploy_gate()
    a = contract.prepare_call("bump", [7], provider, signer)
    b = contract.prepare_call("bump", [7], provider, signer)
    assert contract.get_state() == {"n": 0}
    contract.finalize_call(a, {}, provider)
    assert contract.get_state() == {"n": 1}
    utxo_after = copy.deepcopy(contract.get_utxo())
    provider.refuse = True
    with pytest.raises(Exception):
        contract.finalize_call(b, {}, provider)
    assert contract.get_state() == {"n": 1}
    assert contract.get_utxo() == utxo_after
