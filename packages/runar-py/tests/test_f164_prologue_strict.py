"""F-164 (round 2): execute_strict must mock the WHOLE auto-injected
stateful prologue (checkPreimage's assert AND the sighash-type assert),
not just developer asserts.

See packages/runar-sdk/src/anf-interpreter.ts for the TS reference this
ports (detectAutoInjectedPrologueAsserts there,
_detect_auto_injected_prologue_asserts here).

Round 1 of F-164 fixed the ``check_preimage`` ANF-node kind to mock-return
True in strict mode. That alone is NOT enough: the compiler's prologue also
emits a SECOND, un-marked assert right after -- the sighash-type check
(``assert(extractSigHashType(txPreimage) === <mode>)``) -- and
``extractSigHashType`` has no real/mock value off-chain. Before round 2, a
strict-mode call against a REAL compiled stateful method would get past
checkPreimage only to throw at the sighash-type assert instead -- never
reaching the method's actual body.
"""

from __future__ import annotations

from typing import List

import pytest

from runar.sdk.anf_interpreter import AssertionFailureError, execute_strict


def _load_tx_preimage(name: str) -> dict:
    return {"name": name, "value": {"kind": "load_param", "name": "txPreimage"}}


def _check_preimage(name: str, preimage_ref: str) -> dict:
    return {"name": name, "value": {"kind": "check_preimage", "preimage": preimage_ref}}


def _assert(name: str, pred_ref: str) -> dict:
    return {"name": name, "value": {"kind": "assert", "value": pred_ref}}


def _extract_sighash_call(name: str, preimage_ref: str) -> dict:
    return {
        "name": name,
        "value": {"kind": "call", "func": "extractSigHashType", "args": [preimage_ref]},
    }


def _bin_op_eq(name: str, left: str, right: str) -> dict:
    return {"name": name, "value": {"kind": "bin_op", "op": "===", "left": left, "right": right}}


def _const(name: str, value) -> dict:
    return {"name": name, "value": {"kind": "load_const", "value": value}}


def _full_prologue_anf(user_body: List[dict]) -> dict:
    """The exact 8-binding prologue
    ``compilers/python/runar_compiler/frontend/anf_lower.py``'s
    stateful-prologue emitter injects at the START of every public stateful
    method (mirrors compiled conformance/tests/stateful-counter
    expected-ir.json: t0-t7), followed by whatever ``user_body`` bindings
    the caller supplies.
    """
    body = [
        _load_tx_preimage("t0"),
        _check_preimage("t1", "t0"),
        _assert("t2", "t1"),
        _load_tx_preimage("t3"),
        _extract_sighash_call("t4", "t3"),
        _const("t5", 65),
        _bin_op_eq("t6", "t4", "t5"),
        _assert("t7", "t6"),
    ]
    body.extend(user_body)
    return {
        "contractName": "Counter",
        "properties": [{"name": "count", "type": "bigint", "readonly": False}],
        "methods": [
            {
                "name": "increment",
                "params": [{"name": "txPreimage", "type": "SigHashPreimage"}],
                "body": body,
                "isPublic": True,
            },
        ],
    }


def test_execute_strict_mocks_whole_auto_injected_prologue():
    """Proves the full prologue (checkPreimage assert + sighash-type
    assert) no longer aborts strict mode -- the method's real body result
    comes through."""
    anf = _full_prologue_anf([
        {"name": "t8", "value": {"kind": "load_prop", "name": "count"}},
        _const("t9", 1),
        {"name": "t10", "value": {"kind": "bin_op", "op": "+", "left": "t8", "right": "t9"}},
        {"name": "t11", "value": {"kind": "update_prop", "name": "count", "value": "t10"}},
    ])

    state, data_outputs, raw_outputs = execute_strict(
        anf, "increment", {"count": 0}, {}, [],
    )
    assert state["count"] == 1


def test_user_written_assert_after_prologue_still_enforced():
    """Structural detection is anchored to bindings [0..7] at the START of
    the method body -- the compiler's own prologue. A developer's own
    ``assert(extractSigHashType(txPreimage) === someMode)``, written in
    their method body, is lowered AFTER the prologue and must remain fully
    enforced in strict mode."""
    anf = _full_prologue_anf([
        _load_tx_preimage("u0"),
        _extract_sighash_call("u1", "u0"),
        _const("u2", 1),  # wrong expected mode (real mode is 65)
        _bin_op_eq("u3", "u1", "u2"),
        _assert("userAssert", "u3"),
        {"name": "t8", "value": {"kind": "load_prop", "name": "count"}},
        _const("t9", 1),
        {"name": "t10", "value": {"kind": "bin_op", "op": "+", "left": "t8", "right": "t9"}},
        {"name": "t11", "value": {"kind": "update_prop", "name": "count", "value": "t10"}},
    ])

    with pytest.raises(AssertionFailureError) as exc_info:
        execute_strict(anf, "increment", {"count": 0}, {}, [])
    assert exc_info.value.binding_name == "userAssert"
