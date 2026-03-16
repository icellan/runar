"""ANF IR type definitions for the Runar compiler.

This module defines the A-Normal Form intermediate representation types.
Direct port of ``compilers/go/ir/types.go``.

Python ``int`` replaces Go ``*big.Int`` since Python integers have arbitrary
precision natively.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Program structure
# ---------------------------------------------------------------------------

@dataclass
class ANFProgram:
    """Top-level IR container."""

    contract_name: str = ""
    properties: list[ANFProperty] = field(default_factory=list)
    methods: list[ANFMethod] = field(default_factory=list)


@dataclass
class ANFProperty:
    """A contract-level property (constructor parameter)."""

    name: str = ""
    type: str = ""
    readonly: bool = False
    initial_value: str | int | bool | None = None  # string | number | bool


@dataclass
class ANFMethod:
    """A single contract method."""

    name: str = ""
    params: list[ANFParam] = field(default_factory=list)
    body: list[ANFBinding] = field(default_factory=list)
    is_public: bool = False


@dataclass
class ANFParam:
    """A method parameter."""

    name: str = ""
    type: str = ""


# ---------------------------------------------------------------------------
# Bindings -- the core of the ANF representation
# ---------------------------------------------------------------------------

@dataclass
class ANFBinding:
    """A single let-binding: ``let <name> = <value>``.

    Names follow the pattern t0, t1, ... and are scoped per method.
    """

    name: str = ""
    value: ANFValue = field(default_factory=lambda: ANFValue())


# ---------------------------------------------------------------------------
# ANF value types (discriminated on kind)
# ---------------------------------------------------------------------------

@dataclass
class ANFValue:
    """Flat struct with a ``kind`` discriminator.

    Only the fields relevant to the specific kind are populated.  This mirrors
    the Go approach: a single struct rather than an interface hierarchy, which
    keeps JSON round-tripping straightforward.
    """

    kind: str = ""

    # -- load_param, load_prop, update_prop --------------------------------
    name: str | None = None

    # -- load_const: raw JSON value (kept for lossless round-trip) ---------
    raw_value: Any = None  # the raw JSON value before decoding

    # -- Decoded constant value (populated by decode_constants) ------------
    const_string: str | None = None
    const_big_int: int | None = None  # Python int is arbitrary-precision
    const_bool: bool | None = None
    const_int: int | None = None  # small integers from JSON numbers

    # -- bin_op ------------------------------------------------------------
    op: str | None = None
    left: str | None = None
    right: str | None = None
    result_type: str | None = None  # operand type hint: "bytes" for byte-typed equality

    # -- unary_op ----------------------------------------------------------
    operand: str | None = None

    # -- call --------------------------------------------------------------
    func: str | None = None
    args: list[str] | None = None

    # -- method_call -------------------------------------------------------
    object: str | None = None
    method: str | None = None

    # -- if ----------------------------------------------------------------
    cond: str | None = None
    then: list[ANFBinding] | None = None
    else_: list[ANFBinding] | None = None

    # -- loop --------------------------------------------------------------
    count: int | None = None
    iter_var: str | None = None
    body: list[ANFBinding] | None = None

    # -- assert, update_prop (value ref), check_preimage -------------------
    value_ref: str | None = None

    # -- check_preimage, deserialize_state ---------------------------------
    preimage: str | None = None

    # -- add_output --------------------------------------------------------
    satoshis: str | None = None
    state_values: list[str] | None = None

    # -- add_raw_output ----------------------------------------------------
    script_bytes: str | None = None

    # -- array_literal -----------------------------------------------------
    elements: list[str] | None = None


# ---------------------------------------------------------------------------
# Constant decoding
# ---------------------------------------------------------------------------

def decode_constants(program: ANFProgram) -> None:
    """Walk *program* and decode ``raw_value`` fields in ``load_const``
    bindings into their typed Python representations, and extract the value
    reference string for ``assert`` / ``update_prop`` kinds.

    Raises ``ValueError`` on decode failures.
    """
    for method in program.methods:
        _decode_bindings(method.body, method.name)


def _decode_bindings(bindings: list[ANFBinding], method_name: str) -> None:
    for binding in bindings:
        _decode_value(binding.value, method_name, binding.name)


def _decode_value(v: ANFValue, method_name: str, binding_name: str) -> None:
    match v.kind:
        case "load_const":
            _decode_const_value(v, method_name, binding_name)

        case "assert" | "update_prop":
            # The "value" field is a string reference
            if v.raw_value is not None:
                if not isinstance(v.raw_value, str):
                    raise ValueError(
                        f"method {method_name}: binding {binding_name}: "
                        f"{v.kind} value must be a string, got {type(v.raw_value).__name__}"
                    )
                v.value_ref = v.raw_value

        case "if":
            if v.then:
                _decode_bindings(v.then, method_name)
            if v.else_:
                _decode_bindings(v.else_, method_name)

        case "loop":
            if v.body:
                _decode_bindings(v.body, method_name)

        case "add_output":
            # satoshis and state_values decoded directly; nothing extra needed.
            pass


def _decode_const_value(
    v: ANFValue, method_name: str, binding_name: str
) -> None:
    if v.raw_value is None:
        raise ValueError(
            f"method {method_name}: binding {binding_name}: load_const missing value"
        )

    raw = v.raw_value

    # Boolean -- must check before int because isinstance(True, int) is True
    if isinstance(raw, bool):
        v.const_bool = raw
        return

    # String (hex-encoded bytes)
    if isinstance(raw, str):
        v.const_string = raw
        return

    # Number (int or float from JSON)
    if isinstance(raw, (int, float)):
        int_val = int(raw)
        v.const_int = int_val
        v.const_big_int = int_val
        return

    raise ValueError(
        f"method {method_name}: binding {binding_name}: "
        f"unable to decode constant value: {raw!r}"
    )


# ---------------------------------------------------------------------------
# JSON deserialization helpers
# ---------------------------------------------------------------------------

def _anf_value_from_dict(d: dict[str, Any]) -> ANFValue:
    """Build an ``ANFValue`` from a raw JSON dict."""
    v = ANFValue(kind=d.get("kind", ""))

    v.name = d.get("name")
    v.raw_value = d.get("value")
    v.op = d.get("op")
    v.left = d.get("left")
    v.right = d.get("right")
    v.result_type = d.get("result_type")
    v.operand = d.get("operand")
    v.func = d.get("func")
    v.args = d.get("args")
    v.object = d.get("object")
    v.method = d.get("method")
    v.cond = d.get("cond")
    v.count = d.get("count")
    v.iter_var = d.get("iterVar")
    v.preimage = d.get("preimage")
    v.satoshis = d.get("satoshis")
    v.state_values = d.get("stateValues")
    v.script_bytes = d.get("scriptBytes")
    v.elements = d.get("elements")

    # Nested bindings
    if "then" in d and d["then"] is not None:
        v.then = [_anf_binding_from_dict(b) for b in d["then"]]
    if "else" in d and d["else"] is not None:
        v.else_ = [_anf_binding_from_dict(b) for b in d["else"]]
    if "body" in d and d["body"] is not None:
        v.body = [_anf_binding_from_dict(b) for b in d["body"]]

    return v


def _anf_binding_from_dict(d: dict[str, Any]) -> ANFBinding:
    """Build an ``ANFBinding`` from a raw JSON dict."""
    return ANFBinding(
        name=d.get("name", ""),
        value=_anf_value_from_dict(d.get("value", {})),
    )


def _anf_param_from_dict(d: dict[str, Any]) -> ANFParam:
    """Build an ``ANFParam`` from a raw JSON dict."""
    return ANFParam(name=d.get("name", ""), type=d.get("type", ""))


def _anf_property_from_dict(d: dict[str, Any]) -> ANFProperty:
    """Build an ``ANFProperty`` from a raw JSON dict."""
    return ANFProperty(
        name=d.get("name", ""),
        type=d.get("type", ""),
        readonly=d.get("readonly", False),
        initial_value=d.get("initialValue"),
    )


def _anf_method_from_dict(d: dict[str, Any]) -> ANFMethod:
    """Build an ``ANFMethod`` from a raw JSON dict."""
    return ANFMethod(
        name=d.get("name", ""),
        params=[_anf_param_from_dict(p) for p in d.get("params", [])],
        body=[_anf_binding_from_dict(b) for b in d.get("body", [])],
        is_public=d.get("isPublic", False),
    )


def anf_program_from_dict(d: dict[str, Any]) -> ANFProgram:
    """Build an ``ANFProgram`` from a parsed JSON dict."""
    return ANFProgram(
        contract_name=d.get("contractName", ""),
        properties=[_anf_property_from_dict(p) for p in d.get("properties", [])],
        methods=[_anf_method_from_dict(m) for m in d.get("methods", [])],
    )


def anf_program_from_json(json_str: str) -> ANFProgram:
    """Deserialize an ``ANFProgram`` from a JSON string.

    This does **not** decode constants or validate -- call
    :func:`decode_constants` and the loader's :func:`validate_ir` separately.
    """
    d = json.loads(json_str)
    return anf_program_from_dict(d)
