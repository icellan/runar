"""F-014 / CL-BUG-266: ``--ir`` input must obey the two source-path rules whose
absence mints a spendable-by-anyone or guarantee-breaking script.

The ``--ir`` entry points (``compile_from_ir`` / ``compile_from_ir_bytes``) go
straight from ``load_ir`` to codegen; the frontend validator and type checker
never run. Two of the rules they enforce were not re-checked in ``validate_ir``:

* a public method must end with ``assert()`` -- without one, a body of
  ``load_const true`` compiled to ``51`` (OP_TRUE): anyone-can-spend;
* a readonly property may only be assigned in the constructor -- an
  ``update_prop`` on one compiled clean.

What this proves: ``load_ir`` (and therefore both ``--ir`` compile entry points
and the CLI) rejects both shapes with a diagnostic naming the method (and, for
the readonly write, the property and binding), while the IR shapes that the
source frontend itself emits -- terminal assert, an ``if`` whose arms both end
in assert, and an UnsafeSmartContract terminal ``raw_script`` with out_arity 1
-- are still accepted.

What this does NOT prove: IR carries no ``parentClass``, so a ``raw_script``
cannot be gated on UnsafeSmartContract here, and calls to unknown function
names (``call func:"totallyNotABuiltin"``) are still not rejected, because the
IR also carries compiler-internal call names (``super``,
``computeStateOutput``, ...) that are not in the builtin table. Neither of those
is covered by this test. It also says nothing about the other six tiers.
"""

from __future__ import annotations

import json

import pytest

from runar_compiler.compiler import compile_from_ir_bytes
from runar_compiler.ir.loader import load_ir


def _program(body: list[dict], *, properties=None) -> str:
    return json.dumps({
        "contractName": "C",
        "properties": properties or [],
        "methods": [
            {"name": "unlock", "params": [], "isPublic": True, "body": body},
        ],
    })


_TRUE = {"name": "t0", "value": {"kind": "load_const", "value": True}}
_ASSERT = {"name": "t9", "value": {"kind": "assert", "value": "t0"}}


# ---------------------------------------------------------------------------
# (a) public method must end with an assert
# ---------------------------------------------------------------------------

def test_rejects_public_method_without_terminal_assert() -> None:
    # Reproduced at HEAD: compiled to script '51' (OP_TRUE), exit 0.
    with pytest.raises(ValueError) as exc:
        compile_from_ir_bytes(_program([_TRUE]).encode())
    msg = str(exc.value)
    assert "public method 'unlock' must end with an assert() call" in msg, msg


def test_rejects_assert_that_is_not_the_last_binding() -> None:
    body = [_TRUE, _ASSERT, {"name": "t10", "value": {"kind": "load_const", "value": True}}]
    with pytest.raises(ValueError) as exc:
        load_ir(_program(body))
    assert "must end with an assert() call" in str(exc.value)


def test_rejects_if_with_one_arm_missing_the_assert() -> None:
    body = [
        _TRUE,
        {"name": "t1", "value": {
            "kind": "if", "cond": "t0",
            "then": [{"name": "t2", "value": {"kind": "assert", "value": "t0"}}],
            "else": [{"name": "t3", "value": {"kind": "load_const", "value": True}}],
        }},
    ]
    with pytest.raises(ValueError) as exc:
        load_ir(_program(body))
    assert "must end with an assert() call" in str(exc.value)


def test_accepts_if_whose_arms_both_end_in_assert() -> None:
    body = [
        _TRUE,
        {"name": "t1", "value": {
            "kind": "if", "cond": "t0",
            "then": [{"name": "t2", "value": {"kind": "assert", "value": "t0"}}],
            "else": [{"name": "t3", "value": {"kind": "assert", "value": "t0"}}],
        }},
    ]
    load_ir(_program(body))


def test_accepts_terminal_raw_script_with_out_arity_one() -> None:
    # The conformance fixture asm-raw-script (an UnsafeSmartContract) has
    # exactly this shape; the source path accepts it.
    body = [{"name": "t0", "value": {
        "kind": "raw_script", "bytes": "51", "in_arity": 0, "out_arity": 1,
    }}]
    load_ir(_program(body))


def test_rejects_terminal_raw_script_with_out_arity_zero() -> None:
    body = [{"name": "t0", "value": {
        "kind": "raw_script", "bytes": "61", "in_arity": 0, "out_arity": 0,
    }}]
    with pytest.raises(ValueError) as exc:
        load_ir(_program(body))
    assert "must end with an assert() call" in str(exc.value)


# ---------------------------------------------------------------------------
# (b) readonly property may only be written in the constructor
# ---------------------------------------------------------------------------

_OWNER = [{"name": "owner", "type": "ByteString", "readonly": True}]


def _readonly_write_body() -> list[dict]:
    return [
        {"name": "t0", "value": {"kind": "load_const", "value": "deadbeef"}},
        {"name": "t1", "value": {"kind": "update_prop", "name": "owner", "value": "t0"}},
        {"name": "t2", "value": {"kind": "load_const", "value": True}},
        {"name": "t3", "value": {"kind": "assert", "value": "t2"}},
    ]


def test_rejects_update_prop_on_readonly_property() -> None:
    # Reproduced at HEAD: compiled clean to '04deadbeef5177', exit 0.
    with pytest.raises(ValueError) as exc:
        compile_from_ir_bytes(
            _program(_readonly_write_body(), properties=_OWNER).encode()
        )
    msg = str(exc.value)
    assert "cannot assign to readonly property 'owner' in method 'unlock'" in msg, msg
    assert "t1" in msg, msg


def test_rejects_update_prop_on_readonly_property_inside_a_branch() -> None:
    body = [
        {"name": "t0", "value": {"kind": "load_const", "value": "deadbeef"}},
        {"name": "t1", "value": {"kind": "load_const", "value": True}},
        {"name": "t2", "value": {
            "kind": "if", "cond": "t1",
            "then": [{"name": "t3", "value": {"kind": "update_prop", "name": "owner", "value": "t0"}}],
            "else": [],
        }},
        {"name": "t4", "value": {"kind": "assert", "value": "t1"}},
    ]
    with pytest.raises(ValueError) as exc:
        load_ir(_program(body, properties=_OWNER))
    assert "cannot assign to readonly property 'owner'" in str(exc.value)


def test_constructor_may_write_readonly_property() -> None:
    payload = json.loads(_program([_TRUE, _ASSERT], properties=_OWNER))
    payload["methods"].insert(0, {
        "name": "constructor",
        "params": [{"name": "owner", "type": "ByteString"}],
        "isPublic": False,
        "body": [
            {"name": "t0", "value": {"kind": "load_param", "name": "owner"}},
            {"name": "t1", "value": {"kind": "update_prop", "name": "owner", "value": "t0"}},
        ],
    })
    load_ir(json.dumps(payload))


def test_update_prop_on_mutable_property_still_accepted() -> None:
    props = [{"name": "owner", "type": "ByteString", "readonly": False}]
    payload = json.loads(_program(_readonly_write_body(), properties=props))
    # add_output arity etc. is irrelevant here; only the readonly rule is probed.
    load_ir(json.dumps(payload))
