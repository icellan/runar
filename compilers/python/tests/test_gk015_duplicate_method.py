"""GK-BUG-015 -- a contract may not declare two methods with the same name.

Every name-keyed pass (side-effect summary, private-method lookup, stack
lowering's private map, the affine ``consumed_param_summary`` fixpoint)
assumed method names were unique, and nothing enforced it: two public
``withdraw`` bodies both became spend entries, and two same-named privates
with different Sig consumption made the consumption fixpoint oscillate
forever (the compile hung).

The validator now refuses a repeated method name with the diagnostic every
tier shares. The corpus is the cross-tier one in
``conformance/negatives/duplicate-method-cases.json``.

Proves: validate() reports the shared diagnostic for every corpus case, the
full compile pipeline raises it (in a child process with a hard timeout, so
the pre-fix hang fails the test instead of wedging the suite), and each
renamed twin compiles.
Does not prove: anything about the other six tiers (the conformance
negatives test drives those).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.validator import validate

_REPO = Path(__file__).resolve().parents[3]
_CORPUS = json.loads(
    (_REPO / "conformance" / "negatives" / "duplicate-method-cases.json").read_text()
)["cases"]
_PKG = Path(__file__).resolve().parents[1]


def _compile_in_child(path: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "runar_compiler", "--source", path, "--hex"],
        cwd=_PKG,
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.mark.parametrize("case", _CORPUS, ids=[c["name"] for c in _CORPUS])
def test_validate_refuses_duplicate_method(case):
    parsed = parse_source(case["src"], case["file"])
    assert parsed.contract is not None, parsed.errors
    result = validate(parsed.contract)
    assert case["error"] in [e.message for e in result.errors]


@pytest.mark.parametrize("case", _CORPUS, ids=[c["name"] for c in _CORPUS])
def test_compile_refuses_duplicate_method_without_hanging(case):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, case["file"])
        Path(path).write_text(case["src"])
        res = _compile_in_child(path)
    assert res.returncode != 0, f"accepted: {res.stdout[:200]}"
    assert case["error"] in res.stderr + res.stdout


@pytest.mark.parametrize("case", _CORPUS, ids=[c["name"] for c in _CORPUS])
def test_renamed_twin_compiles(case):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, case["file"])
        Path(path).write_text(case["twin"])
        res = _compile_in_child(path)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip()
