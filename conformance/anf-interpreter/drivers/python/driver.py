#!/usr/bin/env python3
"""ANF interpreter parity driver — Python SDK.

Spec: ../PROTOCOL.md

Reads a single JSON input file (path in argv[1]), invokes the Python SDK's
``compute_new_state_and_data_outputs`` ANF interpreter entry point, and prints
a single JSON output object on stdout.

Bigints are encoded as ``"42n"`` strings on the wire and decoded to / from
Python ``int`` at the boundary.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any


_BIGINT_RE = re.compile(r"^-?\d+n$")


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


def main(argv: list) -> int:
    if len(argv) < 2:
        print("usage: driver.py <input-json-file>", file=sys.stderr)
        return 2

    input_file = argv[1]

    # Wire up the runar-py package: drivers/python/driver.py → packages/runar-py
    here = os.path.dirname(os.path.abspath(__file__))
    runar_py_pkg = os.path.normpath(os.path.join(here, "..", "..", "..", "..", "packages", "runar-py"))
    if runar_py_pkg not in sys.path:
        sys.path.insert(0, runar_py_pkg)

    # Import after sys.path is set up.
    from runar.sdk.anf_interpreter import compute_new_state_and_data_outputs

    with open(input_file, "r", encoding="utf-8") as fh:
        raw = json.load(fh)

    anf_path = _resolve_anf_path(raw, input_file)
    method_name = raw.get("methodName")
    current_state = _decode_bigints(raw.get("currentState", {}) or {})
    args = _decode_bigints(raw.get("args", {}) or {})
    constructor_args = _decode_bigints(raw.get("constructorArgs", []) or [])

    with open(anf_path, "r", encoding="utf-8") as fh:
        anf = json.load(fh)

    state, data_outputs = compute_new_state_and_data_outputs(
        anf, method_name, current_state, args, constructor_args,
    )

    encoded_state = _encode_bigints(state)
    encoded_outputs = []
    for d in data_outputs:
        sat = d.get("satoshis", 0)
        if isinstance(sat, str) and _BIGINT_RE.match(sat):
            sat_str = sat
        else:
            sat_str = f"{int(sat)}n"
        script_val = d.get("script", "")
        encoded_outputs.append({
            "satoshis": sat_str,
            "script": script_val if isinstance(script_val, str) else "",
        })

    out = {"state": encoded_state, "dataOutputs": encoded_outputs}
    sys.stdout.write(json.dumps(out))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:  # noqa: BLE001 — driver must surface any error to stderr
        print(f"driver error: {exc}", file=sys.stderr)
        sys.exit(1)
