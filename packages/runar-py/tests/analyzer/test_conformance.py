"""Byte-identity tests against the 8 canonical conformance goldens.

Spec §13 fixtures (multisig deferred).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from runar.analyzer import analyze_script
from runar.analyzer.emit import report_to_json


_FIXTURES = [
    "basic-p2pkh",
    "escrow",
    "stateful-counter",
    "auction",
    "covenant-vault",
    "ec-demo",
    "schnorr-zkp",
    "if-else",
]


def _repo_root() -> Path:
    # tests/analyzer/test_conformance.py → packages/runar-py/tests/analyzer/
    # parents: [0]=analyzer [1]=tests [2]=runar-py [3]=packages [4]=repo
    return Path(__file__).resolve().parents[4]


@pytest.mark.parametrize("fixture", _FIXTURES)
def test_fixture_byte_identical(fixture: str):
    root = _repo_root()
    hex_path = root / "conformance" / "tests" / fixture / "expected-script.hex"
    golden_path = (
        root / "conformance" / "analyzer" / fixture / "expected-analyzer-report.json"
    )
    if not hex_path.exists():
        pytest.skip(f"no hex at {hex_path}")
    if not golden_path.exists():
        pytest.skip(f"no golden at {golden_path}")

    hex_text = hex_path.read_text(encoding="utf-8").strip()
    golden = golden_path.read_text(encoding="utf-8")

    report = analyze_script(hex_text)
    actual = report_to_json(report)

    assert actual == golden, (
        f"{fixture}: byte mismatch (actual={len(actual)} bytes, "
        f"golden={len(golden)} bytes)"
    )
