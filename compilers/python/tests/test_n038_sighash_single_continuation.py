"""N-038 — a stateful ``@sighash SINGLE|FORKID`` method's continuation hashes
only the method's own output (BIP-143 SINGLE commits hashOutputs to
hash256(output[inputIndex]) alone), and the method takes no
``_changePKH`` / ``_changeAmount`` params.

Proves: the Python compiler emits the TS reference's IR and script for the
N-038 sdk-call pins (``conformance/sdk-call/expected-{ir.json,script.hex}``) byte for byte (fold OFF), the
SINGLE method's ABI is exactly ``[txPreimage]`` and stays non-terminal, the
ALL method in the same contract keeps its change params, and the ``--ir``
scaffolding check accepts the SINGLE shape (no change params required).
Does not prove: on-chain acceptance (the sdk-call vector Spend replay and the TS SDK
Spend tests do that).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tests.test_conformance_goldens import (
    CONFORMANCE_DIR,
    PYTHON_COMPILER_DIR,
    _canonicalize_json,
    _run_compiler,
)

FIXTURE = CONFORMANCE_DIR.parent / "sdk-call"
SOURCE = (
    PYTHON_COMPILER_DIR.parent.parent
    / "conformance" / "sdk-call" / "SingleCounter.runar.ts"
)


def test_ir_matches_golden():
    proc = _run_compiler(SOURCE, ["--emit-ir", "--disable-constant-folding"])
    assert proc.returncode == 0, proc.stderr
    expected = _canonicalize_json((FIXTURE / "expected-ir.json").read_text(encoding="utf-8"))
    assert _canonicalize_json(proc.stdout) == expected


def test_script_matches_golden():
    proc = _run_compiler(SOURCE, ["--hex", "--disable-constant-folding"])
    assert proc.returncode == 0, proc.stderr
    expected = "".join((FIXTURE / "expected-script.hex").read_text(encoding="utf-8").split()).lower()
    assert "".join(proc.stdout.split()).lower() == expected


def _abi() -> dict:
    proc = _run_compiler(SOURCE, ["--disable-constant-folding"])
    assert proc.returncode == 0, proc.stderr
    return {m["name"]: m for m in json.loads(proc.stdout)["abi"]["methods"]}


def test_single_method_abi_has_no_change_params_and_is_not_terminal():
    methods = _abi()
    bump = methods["bump"]
    assert [p["name"] for p in bump["params"]] == ["txPreimage"]
    assert bump.get("sigHashType") == 0x43
    assert not bump.get("isTerminal")
    reset = methods["reset"]
    assert [p["name"] for p in reset["params"]] == [
        "_changePKH", "_changeAmount", "_newAmount", "txPreimage",
    ]


def _compile_ir(ir: dict, tmp_path: Path) -> subprocess.CompletedProcess:
    path = tmp_path / "prog.json"
    path.write_text(json.dumps(ir), encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-m", "runar_compiler", "--ir", str(path), "--hex"],
        cwd=str(PYTHON_COMPILER_DIR), capture_output=True, text=True, timeout=60,
    )


def test_ir_scaffold_check_follows_the_single_shape(tmp_path):
    ir = json.loads((FIXTURE / "expected-ir.json").read_text(encoding="utf-8"))
    ok = _compile_ir(ir, tmp_path)
    assert ok.returncode == 0, ok.stderr
