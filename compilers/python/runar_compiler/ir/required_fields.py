"""N-069 -- presence and JSON type of the ANF IR's required fields.

Checked on the raw ``json.loads`` document BEFORE ``anf_program_from_dict``
reads it. That reader defaulted a missing list to empty and indexed into
whatever it was given, so a public method with no ``body`` loaded with zero
bindings, ``params: {}`` iterated as an empty list, and ``body: "x"`` died as
``'str' object has no attribute 'get'``.

The required set is ``anf-ir.schema.json``'s ``required`` keys, minus the ones
every loader defaults for older payloads (``loop.start`` / ``loop.step``,
``add_output.preimage``). The diagnostics are shared verbatim with the other
six tiers (Java's F-084 loader is the origin), pinned by
``conformance/negatives/ir-required-fields.test.ts``::

    IR validation: required field <path> is missing
    IR validation: <path> must be <a type>, got <json type>
"""

from __future__ import annotations

from typing import Any


def _json_type(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, str):
        return "string"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return "number"


def _path(path: str, key: str) -> str:
    return key if path == "" else f"{path}.{key}"


def _malformed(path: str, expected: str, got: Any) -> ValueError:
    return ValueError(f"IR validation: {path} must be {expected}, got {_json_type(got)}")


def _req(obj: dict, key: str, path: str) -> Any:
    """Absence and a JSON null are both "missing"."""
    v = obj.get(key)
    if v is None:
        raise ValueError(f"IR validation: required field {_path(path, key)} is missing")
    return v


def _req_str(obj: dict, key: str, path: str) -> None:
    v = _req(obj, key, path)
    if not isinstance(v, str):
        raise _malformed(_path(path, key), "a string", v)


def _req_strs(obj: dict, path: str, *keys: str) -> None:
    for k in keys:
        _req_str(obj, k, path)


def _req_bool(obj: dict, key: str, path: str) -> None:
    v = _req(obj, key, path)
    if not isinstance(v, bool):
        raise _malformed(_path(path, key), "a boolean", v)


def _req_list(obj: dict, key: str, path: str) -> list:
    v = _req(obj, key, path)
    if not isinstance(v, list):
        raise _malformed(_path(path, key), "an array", v)
    return v


def _as_obj(v: Any, path: str) -> dict:
    if not isinstance(v, dict):
        raise _malformed(path, "an object", v)
    return v


def _req_str_list(obj: dict, key: str, path: str) -> None:
    lp = _path(path, key)
    for i, e in enumerate(_req_list(obj, key, path)):
        if not isinstance(e, str):
            raise _malformed(f"{lp}[{i}]", "a string", e)


def _check_bindings(obj: dict, key: str, path: str) -> None:
    lp = _path(path, key)
    for i, b in enumerate(_req_list(obj, key, path)):
        bp = f"{lp}[{i}]"
        binding = _as_obj(b, bp)
        _req_str(binding, "name", bp)
        _check_value(_as_obj(binding.get("value"), f"{bp}.value"), f"{bp}.value")


def _check_value(v: dict, path: str) -> None:
    _req_str(v, "kind", path)
    kind = v["kind"]
    if kind in ("load_param", "load_prop"):
        _req_strs(v, path, "name")
    elif kind == "bin_op":
        _req_strs(v, path, "op", "left", "right")
    elif kind == "unary_op":
        _req_strs(v, path, "op", "operand")
    elif kind == "call":
        _req_str(v, "func", path)
        _req_str_list(v, "args", path)
    elif kind == "method_call":
        _req_strs(v, path, "object", "method")
        _req_str_list(v, "args", path)
    elif kind == "if":
        _req_str(v, "cond", path)
        _check_bindings(v, "then", path)
        _check_bindings(v, "else", path)
        if "results" in v:
            _req_str_list(v, "results", path)
    elif kind == "loop":
        _check_bindings(v, "body", path)
        _req_str(v, "iterVar", path)
    elif kind == "assert":
        _req_strs(v, path, "value")
    elif kind == "update_prop":
        _req_strs(v, path, "name", "value")
    elif kind in ("check_preimage", "deserialize_state"):
        _req_strs(v, path, "preimage")
    elif kind == "add_output":
        _req_str(v, "satoshis", path)
        _req_str_list(v, "stateValues", path)
    elif kind in ("add_raw_output", "add_data_output"):
        _req_strs(v, path, "satoshis", "scriptBytes")
    elif kind == "array_literal":
        _req_str_list(v, "elements", path)
    # load_const, get_state_script, raw_script: value-level rules check their
    # fields. Unknown kinds are refused by validate_ir.


# F-038 / F-065: two OPTIONAL keys the artifact copies into the fields the SDK
# signs by. Absent (or null) is legal -- IR written before they existed -- but
# a present value must be one the source path can produce. Shared verbatim
# with the other six tiers.
_PARENT_CLASSES = ("SmartContract", "StatefulSmartContract", "UnsafeSmartContract")
_SIGHASH_TYPES = (0x41, 0x42, 0x43, 0xC1, 0xC2, 0xC3)


def _opt_parent_class(obj: dict) -> None:
    v = obj.get("parentClass")
    if v is None:
        return
    if not isinstance(v, str):
        raise _malformed("parentClass", "a string", v)
    if v not in _PARENT_CLASSES:
        raise ValueError(
            f"IR validation: parentClass must be one of {', '.join(_PARENT_CLASSES)}, got {v}"
        )


def _opt_sighash_type(obj: dict, path: str) -> None:
    v = obj.get("sigHashType")
    if v is None:
        return
    lp = _path(path, "sigHashType")
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise _malformed(lp, "an integer", v)
    if v not in _SIGHASH_TYPES:
        raise ValueError(
            f"IR validation: {lp} must be one of "
            f"{', '.join(str(t) for t in _SIGHASH_TYPES)}, got {v}"
        )


# N-059 / F-102 (F-068 in Go): a ``check_preimage`` binding's optional
# ``sighashFlag``, at every nesting depth. Codegen appends ``sighashFlag & 0xff``
# to the OP_PUSH_TX binding, so an out-of-set value was truncated to a byte no
# BSV spend can satisfy (999999 -> 0x3F, FORKID clear) and an explicit 0
# emitted a 0x00 byte. Absent (or null) means the default ALL|FORKID. In a
# public method the flag must also equal the method's ``sigHashType`` (default
# 0x41): the artifact tells the SDK to sign under ``sigHashType``, the script
# derives its sighash under the flag, and a divergence is unspendable. Both
# diagnostics are shared verbatim with the other six tiers.
_SIGHASH_DEFAULT = 0x41


def _check_sighash_flags(
    obj: dict, key: str, path: str, method: str, is_public: bool, declared: int
) -> None:
    lp = _path(path, key)
    for i, binding in enumerate(obj[key]):
        vp = f"{lp}[{i}].value"
        v = binding["value"]
        kind = v["kind"]
        if kind == "if":
            _check_sighash_flags(v, "then", vp, method, is_public, declared)
            _check_sighash_flags(v, "else", vp, method, is_public, declared)
        elif kind == "loop":
            _check_sighash_flags(v, "body", vp, method, is_public, declared)
        elif kind == "check_preimage":
            flag = v.get("sighashFlag")
            if flag is None:
                flag = _SIGHASH_DEFAULT
            elif isinstance(flag, bool) or not isinstance(flag, (int, float)):
                raise _malformed(_path(vp, "sighashFlag"), "an integer", flag)
            elif flag not in _SIGHASH_TYPES:
                raise ValueError(
                    f"IR validation: method {method} binding {binding['name']} check_preimage "
                    f"has sighashFlag {flag}; sighashFlag must be one of "
                    "{0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3} (ALL/NONE/SINGLE with FORKID, "
                    "optionally ANYONECANPAY). Any other value is truncated to a sighash "
                    "byte no BSV spend can satisfy."
                )
            if is_public and flag != declared:
                raise ValueError(
                    f"IR validation: method {method} binding {binding['name']} check_preimage "
                    f"has sighashFlag {int(flag)} but the method declares sigHashType {declared}; "
                    "a public method's check_preimage must bind the sighash type its ABI "
                    "declares, or the SDK signs a preimage the script rejects."
                )


def assert_required_ir_fields(root: Any) -> None:
    """Raise ``ValueError`` on the first required field that is missing or mistyped."""
    program = _as_obj(root, "the IR document")
    _req_str(program, "contractName", "")
    _opt_parent_class(program)
    for i, p in enumerate(_req_list(program, "properties", "")):
        pp = f"properties[{i}]"
        prop = _as_obj(p, pp)
        _req_strs(prop, pp, "name", "type")
        _req_bool(prop, "readonly", pp)
    for i, m in enumerate(_req_list(program, "methods", "")):
        mp = f"methods[{i}]"
        method = _as_obj(m, mp)
        _req_str(method, "name", mp)
        _req_bool(method, "isPublic", mp)
        _opt_sighash_type(method, mp)
        for j, p in enumerate(_req_list(method, "params", mp)):
            pp = f"{mp}.params[{j}]"
            param = _as_obj(p, pp)
            _req_strs(param, pp, "name", "type")
        _check_bindings(method, "body", mp)
        declared = method.get("sigHashType")
        _check_sighash_flags(
            method, "body", mp, method["name"], method["isPublic"],
            _SIGHASH_DEFAULT if declared is None else int(declared),
        )
