"""`--ir <file> --output <artifact>` crashed with a raw JSONDecodeError.

Found while verifying R-289, not filed by any reviewer.

`ANFValue.raw_value` carries TWO representations depending on how the program
was built:

    frontend/anf_lower.py   raw = json.dumps(...)   -> JSON-ENCODED TEXT
    ir/types.py             v.raw_value = d["value"] -> the DECODED value

`compiler.py::_serialize_anf_program._ser_value` assumes the first and calls
`json.loads(v.raw_value)` unconditionally. On the IR path any `load_const`
holding a plain string — every `@ref:...` alias, every hex ByteString literal —
is not valid JSON, so the compiler dies:

    json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)

and prints a Python traceback instead of a diagnostic.

WHY NOTHING CAUGHT IT: the artifact's embedded `anf` field is the only consumer
of `_ser_value`, and it is only written when an artifact is produced. The
conformance runner drives this tier as `--source ... --hex --emit-ir-to` and as
`--ir ... --hex`; neither writes an artifact, so the one combination that
crashes — `--ir` WITH `--output` — is never exercised. `--hex` round-trips fine,
which is why the tier reports green.

The fix normalises `raw_value` to ONE meaning: the decoded value, which is what
`ir/types.py`'s type comment says and what every decoder in that module already
assumes (`isinstance(raw, bool)`, `isinstance(raw, (int, float))`,
`isinstance(raw, str)`). `_ser_value` and `__main__`'s IR emitter then hand the
value straight out instead of re-parsing it.

The second case below is the guard that keeps that normalisation honest. Both
emitters used to re-parse, and a bare `json.loads` on an ALREADY-decoded hex
ByteString is worse than the crash: `json.loads("3030")` is the integer 3030, so
a ByteString literal would silently become a number. The case pins that an
all-digit hex literal survives `--emit-ir` as a string.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parents[1]

# A stateful contract with a FixedArray: its ANF is full of `@ref:` alias
# constants, which are exactly the strings `json.loads` chokes on.
ARRAY_WRITE = """import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

export class ArrayWrite extends StatefulSmartContract {
  table: FixedArray<bigint, 4> = [0n, 0n, 0n, 0n];

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.table[i]++;
    assert(true);
  }
}
"""

# An all-digit hex ByteString literal: valid JSON as a bare number, which is
# what makes a tolerant `json.loads` fallback unsafe rather than merely untidy.
BYTES_PROBE = """import { SmartContract, assert } from 'runar-lang';
import type { ByteString } from 'runar-lang';

export class Bytes extends SmartContract {
  readonly tag: ByteString;

  constructor(tag: ByteString) {
    super(tag);
    this.tag = tag;
  }

  public unlock(x: ByteString) {
    const probe: ByteString = "3030" as ByteString;
    assert(x === probe);
  }
}
"""


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "runar_compiler", *args],
        cwd=str(PKG_ROOT),
        capture_output=True,
        text=True,
    )


def _load_consts(ir: dict) -> list[tuple[str, object]]:
    """Every `load_const` in the program, innermost blocks included."""
    found: list[tuple[str, object]] = []

    def walk(bindings: list) -> None:
        for b in bindings:
            v = b.get("value", {})
            if v.get("kind") == "load_const":
                found.append((b["name"], v.get("value")))
            for key in ("then", "else", "body"):
                inner = v.get(key)
                if isinstance(inner, list):
                    walk(inner)

    for m in ir.get("methods", []):
        walk(m.get("body", []))
    return found


def test_ir_input_produces_the_same_artifact_as_source_input(tmp_path):
    src = tmp_path / "ArrayWrite.runar.ts"
    src.write_text(ARRAY_WRITE)

    ir = tmp_path / "program.ir.json"
    from_source = tmp_path / "from-source.json"
    res = _run("--source", str(src), "--emit-ir-to", str(ir), "--output", str(from_source))
    assert res.returncode == 0, res.stderr

    # The contract must actually contain the string constants that trigger it,
    # or this test would pass for the wrong reason.
    strings = [(n, v) for n, v in _load_consts(json.loads(ir.read_text())) if isinstance(v, str)]
    assert strings, "no string load_const in the IR; this contract cannot reproduce the defect"

    from_ir = tmp_path / "from-ir.json"
    res = _run("--ir", str(ir), "--output", str(from_ir))
    assert res.returncode == 0, (
        "--ir with --output failed:\n" + res.stderr[-2000:]
    )
    assert "Traceback" not in res.stderr, (
        "the CLI printed a Python traceback instead of a diagnostic:\n" + res.stderr[-2000:]
    )

    a = json.loads(from_source.read_text())
    b = json.loads(from_ir.read_text())
    assert b["script"] == a["script"]
    assert b["stateFields"] == a["stateFields"]


def test_an_all_digit_hex_bytestring_survives_emit_ir_as_a_string(tmp_path):
    src = tmp_path / "Bytes.runar.ts"
    src.write_text(BYTES_PROBE)

    res = _run("--source", str(src), "--emit-ir")
    assert res.returncode == 0, res.stderr
    consts = _load_consts(json.loads(res.stdout))
    probes = [v for _, v in consts if v == "3030" or v == 3030]
    assert probes, f"the 3030 literal is missing from the IR: {consts}"
    assert probes[0] == "3030", (
        "an all-digit hex ByteString was emitted as a NUMBER; a bare json.loads "
        f"on an already-decoded value did this: {probes[0]!r}"
    )
