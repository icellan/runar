"""N-208: ``--ir`` refuses a wrong-typed optional field instead of silently
treating it as absent.

Before this fix, three optional ANF-value fields were read with a bare
``d.get(key)`` (or a ``== True`` comparison) and NO type check:

  - ``bin_op.result_type``: any value other than the string ``"bytes"``
    (including a non-string) makes stack lowering's ``result_type ==
    "bytes"`` comparison False, so a mistyped hint silently lowers a
    byte-equality comparison as a numeric one -- a different script with no
    diagnostic.
  - ``assert.isAutoInjectedStateCheck``: ``d.get(k) == True`` is False for
    every non-``True`` value, including the STRING ``"true"``, so a
    wrong-typed marker silently becomes ``False`` with no diagnostic. Off-
    chain SDK interpreters key off this exact marker to skip the
    compiler-injected stateful-continuation assert.
  - ``add_output.preimage``: a wrong-typed value was still handed to
    ref-collection; a non-string ref can never match a real binding name,
    silently breaking the liveness bookkeeping the ref list exists for.

Go, Rust, Zig and TS already refuse all three (their typed decoders reject a
JSON value of the wrong shape); this closes the same gap in this tier's
``--ir`` loader.

Proves: each field, given a value of the wrong JSON type, is refused by
``load_ir`` / ``assert_required_ir_fields`` with the same
``IR validation: <path> must be <type>, got <type>`` diagnostic the N-069 /
F-038 checks in this same module already use -- and that a correctly-typed
or absent value is still accepted.
Does not prove: Ruby or Java (their own suites prove the same fields), or
that these are the only three fields this gap applied to (N-069 / F-038 /
N-059 already closed it for ``parentClass``, ``sigHashType`` and
``sighashFlag`` elsewhere in this file).
"""

from __future__ import annotations

import json

import pytest

from runar_compiler.ir.loader import load_ir
from runar_compiler.ir.required_fields import assert_required_ir_fields


def _program(body: list[dict]) -> dict:
    return {
        "contractName": "X",
        "properties": [],
        "methods": [{
            "name": "run",
            "isPublic": True,
            "params": [],
            "body": body,
        }],
    }


# -- bin_op.result_type ------------------------------------------------------

def test_bin_op_result_type_valid_string_loads():
    body = [
        {"name": "t0", "value": {"kind": "load_const", "value": 1}},
        {"name": "t1", "value": {"kind": "load_const", "value": 1}},
        {"name": "t2", "value": {
            "kind": "bin_op", "op": "===", "left": "t0", "right": "t1",
            "result_type": "bytes",
        }},
        {"name": "t3", "value": {"kind": "assert", "value": "t2"}},
    ]
    program = load_ir(json.dumps(_program(body)))
    assert program.methods[0].body[2].value.result_type == "bytes"


def test_bin_op_result_type_absent_loads():
    body = [
        {"name": "t0", "value": {"kind": "load_const", "value": 1}},
        {"name": "t1", "value": {"kind": "load_const", "value": 1}},
        {"name": "t2", "value": {"kind": "bin_op", "op": "===", "left": "t0", "right": "t1"}},
        {"name": "t3", "value": {"kind": "assert", "value": "t2"}},
    ]
    program = load_ir(json.dumps(_program(body)))
    assert program.methods[0].body[2].value.result_type is None


def test_bin_op_result_type_wrong_type_refused():
    body = [
        {"name": "t0", "value": {"kind": "load_const", "value": 1}},
        {"name": "t1", "value": {"kind": "load_const", "value": 1}},
        {"name": "t2", "value": {
            "kind": "bin_op", "op": "===", "left": "t0", "right": "t1",
            "result_type": 1,
        }},
        {"name": "t3", "value": {"kind": "assert", "value": "t2"}},
    ]
    with pytest.raises(ValueError) as exc:
        load_ir(json.dumps(_program(body)))
    assert str(exc.value) == (
        "IR validation: methods[0].body[2].value.result_type must be a string, got number"
    )


# -- assert.isAutoInjectedStateCheck -----------------------------------------

def test_assert_is_auto_injected_state_check_valid_bool_loads():
    body = [
        {"name": "t0", "value": {"kind": "load_const", "value": True}},
        {"name": "t1", "value": {
            "kind": "assert", "value": "t0", "isAutoInjectedStateCheck": True,
        }},
    ]
    program = load_ir(json.dumps(_program(body)))
    assert program.methods[0].body[1].value.is_auto_injected_state_check is True


def test_assert_is_auto_injected_state_check_absent_defaults_false():
    body = [
        {"name": "t0", "value": {"kind": "load_const", "value": True}},
        {"name": "t1", "value": {"kind": "assert", "value": "t0"}},
    ]
    program = load_ir(json.dumps(_program(body)))
    assert program.methods[0].body[1].value.is_auto_injected_state_check is False


def test_assert_is_auto_injected_state_check_wrong_type_refused():
    body = [
        {"name": "t0", "value": {"kind": "load_const", "value": True}},
        {"name": "t1", "value": {
            "kind": "assert", "value": "t0", "isAutoInjectedStateCheck": "true",
        }},
    ]
    with pytest.raises(ValueError) as exc:
        load_ir(json.dumps(_program(body)))
    assert str(exc.value) == (
        "IR validation: methods[0].body[1].value.isAutoInjectedStateCheck "
        "must be a boolean, got string"
    )


# -- add_output.preimage ------------------------------------------------------
#
# add_output is a STATEFUL-only node (_STATEFUL_ONLY_KINDS): a full load_ir()
# through a minimal body would also have to satisfy N-101's re-derived
# StatefulSmartContract scaffolding, which is unrelated to this fix. The type
# check lives in assert_required_ir_fields, which runs BEFORE validate_ir /
# the scaffold check, so it is exercised directly here instead -- the same
# function load_ir calls first.

def test_add_output_preimage_valid_string_accepted():
    ir = _program([
        {"name": "t0", "value": {"kind": "load_const", "value": 1}},
        {"name": "t1", "value": {
            "kind": "add_output", "satoshis": "t0", "stateValues": [], "preimage": "",
        }},
    ])
    assert_required_ir_fields(ir)  # does not raise


def test_add_output_preimage_absent_accepted():
    ir = _program([
        {"name": "t0", "value": {"kind": "load_const", "value": 1}},
        {"name": "t1", "value": {
            "kind": "add_output", "satoshis": "t0", "stateValues": [],
        }},
    ])
    assert_required_ir_fields(ir)  # does not raise -- defaulted for older payloads


def test_add_output_preimage_wrong_type_refused():
    ir = _program([
        {"name": "t0", "value": {"kind": "load_const", "value": 1}},
        {"name": "t1", "value": {
            "kind": "add_output", "satoshis": "t0", "stateValues": [], "preimage": 123,
        }},
    ])
    with pytest.raises(ValueError) as exc:
        assert_required_ir_fields(ir)
    assert str(exc.value) == (
        "IR validation: methods[0].body[1].value.preimage must be a string, got number"
    )
