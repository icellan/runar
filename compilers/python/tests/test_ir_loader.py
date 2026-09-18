"""IR loader and validator tests for the Python compiler.

Mirrors compilers/go/ir/loader_test.go — verifies that the IR loader
correctly parses JSON, decodes typed constants, validates structure, and
rejects malformed input.
"""

from __future__ import annotations

import json
import pytest

from runar_compiler.ir.loader import load_ir, validate_ir, MAX_LOOP_COUNT
from runar_compiler.ir.types import (
    ANFBinding,
    ANFMethod,
    ANFParam,
    ANFProgram,
    ANFProperty,
    ANFValue,
)


# ---------------------------------------------------------------------------
# Test: load_ir with a minimal valid ANF IR
# ---------------------------------------------------------------------------

class TestLoadIR_MinimalValid:
    def test_load_ir_minimal_valid(self):
        ir_json = json.dumps({
            "contractName": "P2PKH",
            "properties": [
                {"name": "pubKeyHash", "type": "Addr", "readonly": True}
            ],
            "methods": [
                {
                    "name": "constructor",
                    "params": [{"name": "pubKeyHash", "type": "Addr"}],
                    "body": [],
                    "isPublic": False,
                },
                {
                    "name": "unlock",
                    "params": [
                        {"name": "sig", "type": "Sig"},
                        {"name": "pubKey", "type": "PubKey"},
                    ],
                    "body": [
                        {"name": "t0", "value": {"kind": "load_param", "name": "pubKey"}},
                        {"name": "t1", "value": {"kind": "call", "func": "hash160", "args": ["t0"]}},
                        {"name": "t2", "value": {"kind": "load_prop", "name": "pubKeyHash"}},
                        {"name": "t3", "value": {"kind": "bin_op", "op": "===", "left": "t1", "right": "t2"}},
                        {"name": "t4", "value": {"kind": "assert", "value": "t3"}},
                    ],
                    "isPublic": True,
                },
            ],
        })

        program = load_ir(ir_json)

        assert program.contract_name == "P2PKH"
        assert len(program.properties) == 1
        assert program.properties[0].name == "pubKeyHash"
        assert len(program.methods) == 2
        assert program.methods[1].name == "unlock"
        assert len(program.methods[1].body) == 5


# ---------------------------------------------------------------------------
# Test: load_ir decodes constants correctly
# ---------------------------------------------------------------------------

class TestLoadIR_DecodesConstants:
    def test_decode_integer_constant(self):
        ir_json = json.dumps({
            "contractName": "ConstTest",
            "properties": [],
            "methods": [
                {
                    "name": "constructor",
                    "params": [],
                    "body": [],
                    "isPublic": False,
                },
                {
                    "name": "check",
                    "params": [{"name": "x", "type": "bigint"}],
                    "body": [
                        {"name": "t0", "value": {"kind": "load_const", "value": 42}},
                        {"name": "t1", "value": {"kind": "load_const", "value": True}},
                        {"name": "t2", "value": {"kind": "load_const", "value": "deadbeef"}},
                        {"name": "t3", "value": {"kind": "load_param", "name": "x"}},
                    ],
                    "isPublic": True,
                },
            ],
        })

        program = load_ir(ir_json)
        body = program.methods[1].body

        # t0: load_const 42
        v0 = body[0].value
        assert v0.kind == "load_const"
        assert v0.const_big_int == 42

        # t1: load_const true
        v1 = body[1].value
        assert v1.const_bool is True

        # t2: load_const "deadbeef"
        v2 = body[2].value
        assert v2.const_string == "deadbeef"


# ---------------------------------------------------------------------------
# Test: load_ir rejects unknown kinds
# ---------------------------------------------------------------------------

class TestLoadIR_UnknownKind:
    def test_unknown_kind_raises_error(self):
        ir_json = json.dumps({
            "contractName": "Bad",
            "properties": [],
            "methods": [
                {
                    "name": "constructor",
                    "params": [],
                    "body": [],
                    "isPublic": False,
                },
                {
                    "name": "check",
                    "params": [],
                    "body": [
                        {"name": "t0", "value": {"kind": "bogus_kind"}},
                    ],
                    "isPublic": True,
                },
            ],
        })

        with pytest.raises(ValueError) as exc_info:
            load_ir(ir_json)

        assert "unknown" in str(exc_info.value).lower() or "kind" in str(exc_info.value).lower(), \
            f"expected error about unknown kind, got: {exc_info.value}"


# ---------------------------------------------------------------------------
# Test: validate_ir rejects empty contract name
# ---------------------------------------------------------------------------

class TestValidateIR_EmptyContractName:
    def test_empty_contract_name(self):
        program = ANFProgram(
            contract_name="",
            properties=[],
            methods=[],
        )
        errors = validate_ir(program)
        assert any("contractName" in e for e in errors), (
            f"expected error about contractName, got: {errors}"
        )


# ---------------------------------------------------------------------------
# Test: validate_ir rejects empty method name
# ---------------------------------------------------------------------------

class TestValidateIR_EmptyMethodName:
    def test_empty_method_name(self):
        program = ANFProgram(
            contract_name="Test",
            properties=[],
            methods=[
                ANFMethod(name="", params=[], body=[], is_public=False),
            ],
        )
        errors = validate_ir(program)
        assert len(errors) > 0, "expected error for empty method name"


# ---------------------------------------------------------------------------
# Test: validate_ir rejects empty param name
# ---------------------------------------------------------------------------

class TestValidateIR_EmptyParamName:
    def test_empty_param_name(self):
        program = ANFProgram(
            contract_name="Test",
            properties=[],
            methods=[
                ANFMethod(
                    name="check",
                    params=[ANFParam(name="", type="bigint")],
                    body=[],
                    is_public=True,
                ),
            ],
        )
        errors = validate_ir(program)
        assert len(errors) > 0, "expected error for empty param name"


# ---------------------------------------------------------------------------
# Test: validate_ir rejects empty property name
# ---------------------------------------------------------------------------

class TestValidateIR_EmptyPropertyName:
    def test_empty_property_name(self):
        program = ANFProgram(
            contract_name="Test",
            properties=[
                ANFProperty(name="", type="bigint"),
            ],
            methods=[],
        )
        errors = validate_ir(program)
        assert len(errors) > 0, "expected error for empty property name"


# ---------------------------------------------------------------------------
# Test: validate_ir rejects loop count exceeding maximum
# ---------------------------------------------------------------------------

class TestValidateIR_LoopCountExceedsMax:
    def test_loop_count_exceeds_max(self):
        program = ANFProgram(
            contract_name="Test",
            properties=[],
            methods=[
                ANFMethod(
                    name="run",
                    params=[],
                    body=[
                        ANFBinding(
                            name="t0",
                            value=ANFValue(
                                kind="loop",
                                count=MAX_LOOP_COUNT + 1,
                                iter_var="i",
                                body=[],
                            ),
                        ),
                    ],
                    is_public=True,
                ),
            ],
        )
        errors = validate_ir(program)
        assert any("exceeding maximum" in e for e in errors), (
            f"expected error about exceeding maximum, got: {errors}"
        )


# ---------------------------------------------------------------------------
# Test: validate_ir rejects negative loop count
# ---------------------------------------------------------------------------

class TestValidateIR_NegativeLoopCount:
    def test_negative_loop_count(self):
        program = ANFProgram(
            contract_name="Test",
            properties=[],
            methods=[
                ANFMethod(
                    name="run",
                    params=[],
                    body=[
                        ANFBinding(
                            name="t0",
                            value=ANFValue(
                                kind="loop",
                                count=-1,
                                iter_var="i",
                                body=[],
                            ),
                        ),
                    ],
                    is_public=True,
                ),
            ],
        )
        errors = validate_ir(program)
        assert any("negative loop count" in e for e in errors), (
            f"expected error about negative loop count, got: {errors}"
        )


# ---------------------------------------------------------------------------
# Test: Round-trip — construct ANFProgram, serialize, deserialize
# ---------------------------------------------------------------------------

class TestLoadIR_RoundTrip:
    def test_round_trip(self):
        # Build original program as JSON
        original_json = json.dumps({
            "contractName": "RoundTrip",
            "properties": [
                {"name": "target", "type": "bigint", "readonly": True},
            ],
            "methods": [
                {
                    "name": "constructor",
                    "params": [{"name": "target", "type": "bigint"}],
                    "body": [],
                    "isPublic": False,
                },
                {
                    "name": "check",
                    "params": [{"name": "x", "type": "bigint"}],
                    "body": [
                        {"name": "t0", "value": {"kind": "load_param", "name": "x"}},
                        {"name": "t1", "value": {"kind": "load_const", "value": 42}},
                        {"name": "t2", "value": {"kind": "bin_op", "op": "===", "left": "t0", "right": "t1"}},
                        {"name": "t3", "value": {"kind": "assert", "value": "t2"}},
                    ],
                    "isPublic": True,
                },
            ],
        })

        loaded = load_ir(original_json)

        assert loaded.contract_name == "RoundTrip"
        assert len(loaded.properties) == 1
        assert len(loaded.methods) == 2

        # Verify constant was decoded
        check_method = loaded.methods[1]
        assert len(check_method.body) == 4
        const_binding = check_method.body[1]
        assert const_binding.value.const_big_int == 42, (
            f"constant not decoded correctly: expected 42, got {const_binding.value.const_big_int}"
        )

        # Verify assert value ref was decoded
        assert_binding = check_method.body[3]
        assert assert_binding.value.value_ref == "t2", (
            f"assert valueRef: expected t2, got {assert_binding.value.value_ref}"
        )


# ---------------------------------------------------------------------------
# Test: load_ir rejects invalid JSON
# ---------------------------------------------------------------------------

class TestLoadIR_InvalidJSON:
    def test_invalid_json(self):
        with pytest.raises(ValueError):
            load_ir("{not valid json")


# ---------------------------------------------------------------------------
# Test: IR with methods but no body bindings is valid
# ---------------------------------------------------------------------------

class TestLoadIR_EmptyMethodsValid:
    def test_empty_methods_valid(self):
        """IR with methods array but no body bindings is valid.
        Mirrors Rust test_load_ir_empty_methods_valid."""
        ir_json = json.dumps({
            "contractName": "Empty",
            "properties": [],
            "methods": [
                {
                    "name": "noop",
                    "params": [],
                    "body": [
                        {"name": "t0", "value": {"kind": "load_const", "value": True}},
                        {"name": "t1", "value": {"kind": "assert", "value": "t0"}},
                    ],
                    "isPublic": True,
                },
            ],
        })

        program = load_ir(ir_json)
        assert program.contract_name == "Empty"
        assert len(program.properties) == 0


# ---------------------------------------------------------------------------
# Test: validate_ir rejects empty property type
# ---------------------------------------------------------------------------

class TestValidateIR_EmptyPropertyType:
    def test_empty_property_type(self):
        """IR with empty property type raises error.
        Mirrors Rust test_load_ir_empty_property_type_error."""
        program = ANFProgram(
            contract_name="Bad",
            properties=[
                ANFProperty(name="x", type=""),
            ],
            methods=[],
        )
        errors = validate_ir(program)
        assert len(errors) > 0, "expected error for empty property type"
        assert any("empty type" in e for e in errors), (
            f"expected error mentioning 'empty type', got: {errors}"
        )


# ---------------------------------------------------------------------------
# Test: Round-trip with initial_value and if/loop nodes
# ---------------------------------------------------------------------------

class TestLoadIR_RoundTripExtended:
    def test_round_trip_with_initial_value(self):
        """Property with initializer round-trips correctly.
        Mirrors Rust test_round_trip_with_initial_value."""
        ir_json = json.dumps({
            "contractName": "InitTest",
            "properties": [
                {"name": "value", "type": "bigint", "readonly": True, "initialValue": 100},
            ],
            "methods": [
                {
                    "name": "check",
                    "params": [],
                    "body": [
                        {"name": "t0", "value": {"kind": "load_const", "value": True}},
                        {"name": "t1", "value": {"kind": "assert", "value": "t0"}},
                    ],
                    "isPublic": True,
                },
            ],
        })

        loaded = load_ir(ir_json)
        assert loaded.contract_name == "InitTest"
        assert len(loaded.properties) == 1
        assert loaded.properties[0].initial_value == 100, (
            f"initial_value should be 100, got {loaded.properties[0].initial_value}"
        )

    def test_round_trip_if_and_loop(self):
        """If/else and loop nodes survive a JSON round-trip.
        Mirrors Rust test_round_trip_if_and_loop."""
        ir_json = json.dumps({
            "contractName": "Nested",
            "properties": [],
            "methods": [
                {
                    "name": "test",
                    "params": [],
                    "body": [
                        {"name": "cond", "value": {"kind": "load_const", "value": True}},
                        {
                            "name": "ifExpr",
                            "value": {
                                "kind": "if",
                                "cond": "cond",
                                "then": [
                                    {"name": "t", "value": {"kind": "load_const", "value": 1}},
                                ],
                                "else": [
                                    {"name": "e", "value": {"kind": "load_const", "value": 2}},
                                ],
                            },
                        },
                        {
                            "name": "loopExpr",
                            "value": {
                                "kind": "loop",
                                "count": 5,
                                "iterVar": "i",
                                "body": [
                                    {"name": "lb", "value": {"kind": "load_const", "value": 0}},
                                ],
                            },
                        },
                    ],
                    "isPublic": True,
                },
            ],
        })

        loaded = load_ir(ir_json)
        assert loaded.contract_name == "Nested"
        assert len(loaded.methods) == 1

        body = loaded.methods[0].body
        assert len(body) == 3

        # Verify if survived
        if_binding = body[1]
        assert if_binding.value.kind == "if", f"expected 'if' kind, got '{if_binding.value.kind}'"
        assert if_binding.value.cond == "cond", (
            f"expected cond='cond', got '{if_binding.value.cond}'"
        )
        assert len(if_binding.value.then) == 1, (
            f"expected 1 then-binding, got {len(if_binding.value.then)}"
        )
        assert len(if_binding.value.else_) == 1, (
            f"expected 1 else-binding, got {len(if_binding.value.else_)}"
        )

        # Verify loop survived
        loop_binding = body[2]
        assert loop_binding.value.kind == "loop", f"expected 'loop' kind, got '{loop_binding.value.kind}'"
        assert loop_binding.value.count == 5, (
            f"expected count=5, got {loop_binding.value.count}"
        )
        assert len(loop_binding.value.body) == 1, (
            f"expected 1 loop body binding, got {len(loop_binding.value.body)}"
        )
        assert loop_binding.value.iter_var == "i", (
            f"expected iter_var='i', got '{loop_binding.value.iter_var}'"
        )


# ---------------------------------------------------------------------------
# Gap tests: I9, I19
# ---------------------------------------------------------------------------

class TestValidateIR_Gaps:
    # I9: empty param type rejected
    def test_i9_empty_param_type_rejected(self):
        """Method param with type='' → exception raised (via validate_ir errors)."""
        program = ANFProgram(
            contract_name="Test",
            properties=[],
            methods=[
                ANFMethod(
                    name="check",
                    params=[ANFParam(name="x", type="")],
                    body=[
                        ANFBinding(
                            name="t0",
                            value=ANFValue(kind="load_const", raw_value=True, const_bool=True),
                        ),
                        ANFBinding(
                            name="t1",
                            value=ANFValue(kind="assert", raw_value="t0", value_ref="t0"),
                        ),
                    ],
                    is_public=True,
                ),
            ],
        )
        errors = validate_ir(program)
        assert len(errors) > 0, (
            "expected validation error for param with empty type"
        )
        assert any("empty type" in e or "type" in e.lower() for e in errors), (
            f"expected error mentioning empty type, got: {errors}"
        )

    # I19: empty binding name rejected
    def test_i19_empty_binding_name_rejected(self):
        """Binding with name='' → exception raised (via validate_ir errors)."""
        program = ANFProgram(
            contract_name="Test",
            properties=[],
            methods=[
                ANFMethod(
                    name="check",
                    params=[],
                    body=[
                        ANFBinding(
                            name="",
                            value=ANFValue(kind="load_const", raw_value=True, const_bool=True),
                        ),
                    ],
                    is_public=True,
                ),
            ],
        )
        errors = validate_ir(program)
        assert len(errors) > 0, (
            "expected validation error for binding with empty name"
        )
        assert any("empty" in e.lower() or "name" in e.lower() for e in errors), (
            f"expected error mentioning empty name, got: {errors}"
        )


# ---------------------------------------------------------------------------
# N-113 — the two shapes the Go tier rejected alone (R-079 / R-081)
#
# Both are `--ir`-only: the source path refuses each shape in
# frontend/validator.py, and validate_ir is reachable only from the IR loader.
# Go grew these guards first (compilers/go/ir/loader.go) and was deliberately,
# transiently stricter than its six peers until N-113;
# conformance/negatives/ir-rejection-parity.test.ts is the gate that now
# compares the six.
# ---------------------------------------------------------------------------


def _ir_json(is_public: bool = True, raw_bytes: str = "51") -> str:
    """A one-method contract parameterised on the two fields under test, so
    every case below differs from the VALID control in exactly one way."""
    return json.dumps(
        {
            "contractName": "Anyone",
            "properties": [],
            "methods": [
                {
                    "name": "unlock",
                    "params": [],
                    "isPublic": is_public,
                    "body": [
                        {
                            "name": "t0",
                            "value": {
                                "kind": "raw_script",
                                "bytes": raw_bytes,
                                "in_arity": 0,
                                "out_arity": 1,
                            },
                        }
                    ],
                }
            ],
        }
    )


def test_control_valid_ir_is_accepted() -> None:
    # The control every case below is derived from. A probe whose control also
    # fails proves nothing.
    program = load_ir(_ir_json())
    assert program.contract_name == "Anyone"


def test_rejects_empty_raw_script_body() -> None:
    # R-079: lowering pops in_arity and pushes out_arity on the stack model
    # while emission writes nothing for a zero-length span. The span degrades
    # to the identity function and a DIFFERENT WITNESS spends the output.
    # Measured on @bsv/sdk's Spend: `8f01859c` accepts x=5 and rejects x=-5;
    # with the body erased, `01859c` does the opposite.
    with pytest.raises(ValueError) as exc:
        load_ir(_ir_json(raw_bytes=""))
    assert "empty bytes body" in str(exc.value), str(exc.value)


def test_rejects_empty_raw_script_body_even_at_zero_arity() -> None:
    # The degenerate in=0/out=0 case is harmless on its own and is rejected
    # anyway: mirroring the source validator exactly beats a narrower
    # arity-conditional rule that would differ from the rule one pass earlier.
    payload = json.loads(_ir_json(raw_bytes=""))
    payload["methods"][0]["body"][0]["value"]["out_arity"] = 0
    with pytest.raises(ValueError):
        load_ir(json.dumps(payload))


def test_rejects_no_public_methods() -> None:
    # R-081: emission succeeds with an EMPTY locking script, which is
    # anyone-can-spend. On @bsv/sdk's Spend under full consensus wrappers,
    # lock="" with unlock=OP_1 (0x51) validates.
    with pytest.raises(ValueError) as exc:
        load_ir(_ir_json(is_public=False))
    assert "no public methods" in str(exc.value), str(exc.value)


def test_rejects_empty_method_list() -> None:
    with pytest.raises(ValueError) as exc:
        load_ir('{"contractName": "Empty", "properties": [], "methods": []}')
    assert "no public methods" in str(exc.value), str(exc.value)


def test_structural_errors_keep_priority_over_the_entry_point_error() -> None:
    # Ordering matters and is asserted, not assumed: when a binding is ALSO
    # malformed, the malformed binding is the more actionable diagnostic. The
    # loader raises errors[0], so the entry-point error is APPENDED last.
    # Same ordering as compilers/go/ir/loader.go.
    payload = json.loads(_ir_json(is_public=False))
    payload["methods"][0]["body"][0]["value"]["bytes"] = "515"
    with pytest.raises(ValueError) as exc:
        load_ir(json.dumps(payload))
    assert "odd hex length" in str(exc.value), str(exc.value)
