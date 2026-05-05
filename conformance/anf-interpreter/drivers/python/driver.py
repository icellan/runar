#!/usr/bin/env python3
"""ANF interpreter parity driver — Python SDK.

Spec: ../PROTOCOL.md

Reads a single JSON input file, invokes the Python SDK's
``compute_new_state_and_data_outputs`` (lenient),
``execute_strict`` (strict), or ``execute_on_chain_authoritative`` (on-chain)
ANF interpreter entry point, and prints a single JSON output object on stdout.

Invocation::

    driver.py <input.json>                # lenient (default)
    driver.py --mode=strict <input.json>  # strict
    driver.py --mode=on-chain <input.json>  # strict + real-crypto

Strict and on-chain modes emit
``{error: "AssertionFailureError", methodName, bindingName}`` on the first
falsy ``assert(...)`` predicate (including failed crypto verifications in
on-chain mode); otherwise the same ``{state, dataOutputs, rawOutputs}``
envelope as lenient.

On-chain mode reads ``sighash`` from the input JSON (32-byte hex string)
and passes it through :class:`OnChainCryptoContext` so ``checkSig`` /
``checkMultiSig`` / ``checkPreimage`` perform real ECDSA + double-SHA-256
verification rather than mock-returning ``True``.

Bigints are encoded as ``"42n"`` strings on the wire and decoded to / from
Python ``int`` at the boundary.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Tuple


_BIGINT_RE = re.compile(r"^-?\d+n$")


# Mode constants
_MODE_LENIENT = "lenient"
_MODE_STRICT = "strict"
_MODE_ON_CHAIN = "on-chain"


def _decode_bigints(v: Any) -> Any:
    """Recursively decode ``"42n"`` strings into Python ``int``."""
    if isinstance(v, str) and _BIGINT_RE.match(v):
        return int(v[:-1])
    if isinstance(v, list):
        return [_decode_bigints(x) for x in v]
    if isinstance(v, dict):
        return {k: _decode_bigints(val) for k, val in v.items()}
    return v


def _encode_bigints(v: Any) -> Any:
    """Recursively encode Python ``int`` (non-bool) back to ``"Xn"`` strings."""
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return f"{v}n"
    if isinstance(v, list):
        return [_encode_bigints(x) for x in v]
    if isinstance(v, dict):
        return {k: _encode_bigints(val) for k, val in v.items()}
    return v


def _resolve_anf_path(input_obj: dict, input_file: str) -> str:
    """Resolve the ANF IR path. Prefer ``anfPath``; fall back to ``case``."""
    anf_path = input_obj.get("anfPath")
    if isinstance(anf_path, str) and anf_path:
        return anf_path
    case = input_obj.get("case")
    if isinstance(case, str) and case:
        # conformance/anf-interpreter/inputs/<file>.json
        # → conformance/tests/<case>/expected-ir.json
        anf_dir = os.path.dirname(os.path.abspath(input_file))
        # anf_dir = .../conformance/anf-interpreter/inputs
        anf_root = os.path.dirname(anf_dir)
        # anf_root = .../conformance/anf-interpreter
        conformance_root = os.path.dirname(anf_root)
        # conformance_root = .../conformance
        return os.path.join(conformance_root, "tests", case, "expected-ir.json")
    raise ValueError("input JSON missing both 'anfPath' and 'case' fields")


def _parse_args(argv: list) -> Tuple[str, str]:
    """Parse argv into (mode, input_file). Order is irrelevant."""
    mode = _MODE_LENIENT
    input_file = ""
    for a in argv[1:]:
        if a == "--mode=strict":
            mode = _MODE_STRICT
        elif a == "--mode=lenient":
            mode = _MODE_LENIENT
        elif a == "--mode=on-chain":
            mode = _MODE_ON_CHAIN
        elif a.startswith("--"):
            raise ValueError(f"unknown flag: {a}")
        else:
            if input_file:
                raise ValueError(
                    "usage: driver.py [--mode=strict|--mode=on-chain] <input-json-file>"
                )
            input_file = a
    if not input_file:
        raise ValueError(
            "usage: driver.py [--mode=strict|--mode=on-chain] <input-json-file>"
        )
    return mode, input_file


def main(argv: list) -> int:
    mode, input_file = _parse_args(argv)

    # Wire up the runar-py package: drivers/python/driver.py → packages/runar-py
    here = os.path.dirname(os.path.abspath(__file__))
    runar_py_pkg = os.path.normpath(os.path.join(here, "..", "..", "..", "..", "packages", "runar-py"))
    if runar_py_pkg not in sys.path:
        sys.path.insert(0, runar_py_pkg)

    # Import after sys.path is set up.
    from runar.sdk.anf_interpreter import (
        AssertionFailureError,
        OnChainCryptoContext,
        compute_new_state_and_data_outputs,
        execute_on_chain_authoritative,
        execute_strict,
    )

    with open(input_file, "r", encoding="utf-8") as fh:
        raw = json.load(fh)

    anf_path = _resolve_anf_path(raw, input_file)
    method_name = raw.get("methodName")
    current_state = _decode_bigints(raw.get("currentState", {}) or {})
    args = _decode_bigints(raw.get("args", {}) or {})
    constructor_args = _decode_bigints(raw.get("constructorArgs", []) or [])

    with open(anf_path, "r", encoding="utf-8") as fh:
        anf = json.load(fh)

    try:
        if mode == _MODE_ON_CHAIN:
            sighash_hex = raw.get("sighash")
            if not isinstance(sighash_hex, str) or not sighash_hex:
                raise ValueError(
                    "on-chain mode requires 'sighash' field in input JSON"
                )
            ctx = OnChainCryptoContext(sighash_hex)
            state, data_outputs, raw_outputs = execute_on_chain_authoritative(
                anf, method_name, current_state, args, constructor_args, ctx,
            )
        elif mode == _MODE_STRICT:
            state, data_outputs, raw_outputs = execute_strict(
                anf, method_name, current_state, args, constructor_args,
            )
        else:
            state, data_outputs, raw_outputs = compute_new_state_and_data_outputs(
                anf, method_name, current_state, args, constructor_args,
            )
    except AssertionFailureError as af:
        # Strict / on-chain assert failure: emit the standard envelope so
        # the cross-tier parity test can byte-compare. Real driver errors
        # (missing IR, malformed input, …) still surface via the
        # non-zero exit + stderr message in __main__.
        out = {
            "error": "AssertionFailureError",
            "methodName": af.method_name,
            "bindingName": af.binding_name,
        }
        sys.stdout.write(json.dumps(out, sort_keys=True))
        sys.stdout.write("\n")
        return 0

    encoded_state = _encode_bigints(state)

    def _encode_outputs(entries: list) -> list:
        out_list = []
        for d in entries:
            sat = d.get("satoshis", 0)
            if isinstance(sat, str) and _BIGINT_RE.match(sat):
                sat_str = sat
            else:
                sat_str = f"{int(sat)}n"
            script_val = d.get("script", "")
            out_list.append({
                "satoshis": sat_str,
                "script": script_val if isinstance(script_val, str) else "",
            })
        return out_list

    encoded_outputs = _encode_outputs(data_outputs)
    encoded_raw_outputs = _encode_outputs(raw_outputs)

    out = {
        "state": encoded_state,
        "dataOutputs": encoded_outputs,
        "rawOutputs": encoded_raw_outputs,
    }
    sys.stdout.write(json.dumps(out, sort_keys=True))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:  # noqa: BLE001 — driver must surface any error to stderr
        print(f"driver error: {exc}", file=sys.stderr)
        sys.exit(1)
