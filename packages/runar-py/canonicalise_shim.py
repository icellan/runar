#!/usr/bin/env python3
"""Python-tier CLI shim for the cross-tier canonicalJson (RFC 8785 / JCS)
differential fuzzer (conformance/fuzzer/canonical-json-differential.ts).

Protocol (single-shot, stdin -> stdout), mirrors the Go / Rust shims:

  {"mode":"json","value":<any JSON>}
      Parse `value` with the stdlib json module (int and float are distinct
      Python types, preserving the int-vs-float distinction the same way the
      test_envelope_interop fixture loader does), run runar.sdk.canonical_json,
      print canonical bytes, exit 0.
  {"mode":"utf16","key":"<string>","units":[<int>,...]}
      Build {key: <string from UTF-16 code units>} via "".join(chr(u) ...) —
      Python `str` can hold a lone surrogate, so the lone-surrogate REJECTION
      happens inside canonical_json (mirrors test_envelope_interop's
      test_canonical_json_rejection_vectors).
  {"mode":"deep","depth":<int>,"shape":"array"|"object"}
      Build `depth` nested containers around the integer leaf 1, NATIVELY.
  {"mode":"bigstring","bytes":<int>,"where":"value"|"key"}
      Build a one-entry object whose value (or key) is `bytes` ASCII 'a',
      NATIVELY, and respond with the SHA-256 of the canonical bytes rather
      than the bytes themselves.

  Why `deep` / `bigstring` describe the value instead of carrying it: a deep or
  huge value sent as JSON would have to survive THIS shim's json.loads before
  ever reaching canonical_json, so the transport would be imposing a limit on
  the very thing under test. Building natively keeps the request ~50 bytes and
  takes the request parser out of the measurement. Hashing the bigstring
  response keeps a ~4 MiB canonical output from crossing the pipe while still
  detecting a single divergent byte.

  On a typed rejection the shim prints "RUNAR_CANON_ERR:<message>" to stdout
  and exits 3; any other failure exits 1.

Run via:  PYTHONPATH=packages/runar-py python3 packages/runar-py/canonicalise_shim.py
"""

import hashlib
import json
import sys

from runar.sdk import canonical_json

DIGEST_PREFIX = "RUNAR_CANON_SHA256:"


def build_deep(depth, shape):
    """Build `depth` nested containers around the integer leaf 1, iteratively
    (a recursive builder would hit Python's own recursion limit long before
    canonical_json's depth guard, which is the thing under test)."""
    v = 1
    for _ in range(depth):
        v = [v] if shape == "array" else {"k": v}
    return v


def build_big_string(nbytes, where):
    s = "a" * nbytes
    return {"s": s} if where == "value" else {s: 1}


def utf16_units_to_string(units):
    """Build a Python str from UTF-16 code units, decoding surrogate pairs and
    leaving lone surrogates intact (Python str permits them)."""
    out = []
    i = 0
    n = len(units)
    while i < n:
        u = units[i]
        if 0xD800 <= u <= 0xDBFF and i + 1 < n and 0xDC00 <= units[i + 1] <= 0xDFFF:
            cp = 0x10000 + ((u - 0xD800) << 10) + (units[i + 1] - 0xDC00)
            out.append(chr(cp))
            i += 2
            continue
        out.append(chr(u))
        i += 1
    return "".join(out)


def main():
    raw = sys.stdin.read()
    try:
        req = json.loads(raw)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"parse request: {e}\n")
        sys.exit(1)

    mode = req.get("mode")
    if mode == "json":
        value = req.get("value")
    elif mode == "utf16":
        value = {req.get("key", ""): utf16_units_to_string(req.get("units", []))}
    elif mode == "deep":
        value = build_deep(int(req["depth"]), req.get("shape", "array"))
    elif mode == "bigstring":
        value = build_big_string(int(req["bytes"]), req.get("where", "value"))
    else:
        sys.stderr.write(f"unknown mode {mode!r}\n")
        sys.exit(1)

    try:
        out = canonical_json(value)
    except (ValueError, TypeError) as e:
        sys.stdout.write(f"RUNAR_CANON_ERR:{e}")
        sys.exit(3)
    except RecursionError:
        # A native stack exhaustion is NOT the typed rejection the guard is
        # supposed to produce. Report it distinctly so it cannot be mistaken
        # for agreement with a tier that rejected properly.
        sys.stdout.write("RUNAR_CANON_ERR:RecursionError (native stack, not a guard)")
        sys.exit(3)
    if mode == "bigstring":
        digest = hashlib.sha256(out.encode("utf-8")).hexdigest()
        sys.stdout.write(f"{DIGEST_PREFIX}{digest}")
        return
    sys.stdout.write(out)


if __name__ == "__main__":
    main()
