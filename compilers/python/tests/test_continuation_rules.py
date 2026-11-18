"""#199 (release-trap warning) and D18 (dropped-continuation error), Python tier.

Corpora: conformance/negatives/release-trap-cases.json and
dropped-continuation-cases.json, shared with the other six tiers and the
conformance gates (gk-frontend-parity.test.ts, ir-release-trap.test.ts).
Mirrors packages/runar-compiler/src/passes/continuation-rules.ts.

Proves: every warn case compiles and carries the shared non-fatal warning, no
nowarn case does; every refuse case fails the source compile with the shared
D18 text, every accept case compiles; on the --ir path the loader refuses each
refuse case's unchecked ANF with the same text, and still accepts each accept
case's own ANF.
Does not prove: the other six tiers (conformance/negatives covers them).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar_compiler.__main__ import _anf_to_camel_dict
from runar_compiler.compiler import (
    CompilationError,
    compile_from_ir_bytes,
    compile_from_source,
    compile_from_source_collecting_warnings,
    compile_source_to_ir,
)
from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.expand_fixed_arrays import expand_fixed_arrays
from runar_compiler.frontend.parser_dispatch import parse_source

_REPO = Path(__file__).resolve().parents[3]
_TRAP = json.loads((_REPO / "conformance/negatives/release-trap-cases.json").read_text())
_D18 = json.loads((_REPO / "conformance/negatives/dropped-continuation-cases.json").read_text())


def _write(tmp_path: Path, case: dict) -> str:
    path = tmp_path / case["file"]
    path.write_text(case["src"])
    return str(path)


def _ir_bytes(program) -> bytes:
    return json.dumps(_anf_to_camel_dict(program), default=str).encode()


@pytest.mark.parametrize("case", _TRAP["warn"], ids=[c["name"] for c in _TRAP["warn"]])
def test_199_warns(case, tmp_path):
    artifact, warnings = compile_from_source_collecting_warnings(
        _write(tmp_path, case), disable_constant_folding=True)
    assert artifact.script
    assert any(case["warning"] in w for w in warnings), warnings


@pytest.mark.parametrize("case", _TRAP["nowarn"], ids=[c["name"] for c in _TRAP["nowarn"]])
def test_199_does_not_warn(case, tmp_path):
    artifact, warnings = compile_from_source_collecting_warnings(
        _write(tmp_path, case), disable_constant_folding=True)
    assert artifact.script
    assert not any(case["warning_absent"] in w for w in warnings), warnings


@pytest.mark.parametrize("case", _D18["refuse"], ids=[c["name"] for c in _D18["refuse"]])
def test_d18_source_refuses(case, tmp_path):
    with pytest.raises(CompilationError) as exc:
        compile_from_source(_write(tmp_path, case))
    assert case["error"] in str(exc.value)


@pytest.mark.parametrize("case", _D18["accept"], ids=[c["name"] for c in _D18["accept"]])
def test_d18_source_accepts(case, tmp_path):
    assert compile_from_source(_write(tmp_path, case)).script


@pytest.mark.parametrize("case", _D18["refuse"], ids=[c["name"] for c in _D18["refuse"]])
def test_d18_ir_refuses(case):
    parsed = parse_source(case["src"], case["file"])
    assert parsed.contract is not None, parsed.errors
    # Pass 3b, as the real pipeline runs it before ANF lowering.
    expanded = expand_fixed_arrays(parsed.contract)
    assert not expanded.errors, expanded.errors
    try:
        program = lower_to_anf(expanded.contract)
    except Exception as e:  # noqa: BLE001
        # The lowerer itself refuses a write inside an output-declaring
        # branch: that refusal is this case's expected outcome here; the IR
        # shape is hand-built in test_d18_ir_refuses_write_on_raw_branch.
        if "both declares outputs and assigns contract properties" in str(e):
            return
        raise
    data = _ir_bytes(program)
    text = data.decode()
    assert '"update_prop"' in text
    assert '"add_raw_output"' in text or '"add_output"' in text
    with pytest.raises(Exception) as exc:
        compile_from_ir_bytes(data)
    assert case["error"] in str(exc.value)


def test_d18_ir_refuses_write_on_raw_branch(tmp_path):
    """The per-path shape only a hand-written IR can carry: the accepted
    terminal-branch-writes-nothing program with an update_prop added to its
    raw-output branch (mirrors writeOnRawBranchIr in ir-release-trap.test.ts)."""
    base = next(c for c in _D18["accept"] if c["name"] == "terminal-branch-writes-nothing")
    want = next(c for c in _D18["refuse"] if c["name"] == "write-on-raw-branch-sibling-add-output")
    program = compile_source_to_ir(_write(tmp_path, base), disable_constant_folding=True)
    ir = json.loads(_ir_bytes(program))
    pay = next(m for m in ir["methods"] if m["name"] == "pay")
    ifb = next(
        b for b in pay["body"]
        if b["value"]["kind"] == "if"
        and any(x["value"]["kind"] == "add_raw_output" for x in b["value"].get("then") or [])
    )
    ifb["value"]["then"][:0] = [
        {"name": "d18w0", "value": {"kind": "load_const", "value": 7}},
        {"name": "d18w1", "value": {"kind": "update_prop", "name": "count", "value": "d18w0"}},
    ]
    with pytest.raises(Exception) as exc:
        compile_from_ir_bytes(json.dumps(ir).encode())
    assert want["error"] in str(exc.value)


@pytest.mark.parametrize("case", _D18["accept"], ids=[c["name"] for c in _D18["accept"]])
def test_d18_ir_accepts(case, tmp_path):
    program = compile_source_to_ir(_write(tmp_path, case), disable_constant_folding=True)
    assert compile_from_ir_bytes(_ir_bytes(program)).script
