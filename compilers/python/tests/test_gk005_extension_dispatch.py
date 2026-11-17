"""GK-GAP-005 / GK-GAP-006 -- one file-extension dispatch rule in every tier.

The rule (user decision): the nine ``.runar.*`` suffixes match ignoring ASCII
case, any other suffix is refused with the shared unsupported-extension
diagnostic, and NO file name (``None`` or ``""``) means the TypeScript
surface.

Proves: upper-case and lower-case spellings of a suffix compile to the same
hex through both the library API and the CLI; a valid TypeScript contract
saved as ``.runar.xyz`` is refused with the shared diagnostic; parse_source
with no file name parses TypeScript.
Does not prove: the other six tiers (conformance/negatives covers them).
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source

_REPO = Path(__file__).resolve().parents[3]
_PKG = Path(__file__).resolve().parents[1]
_TS = (_REPO / "examples/ts/p2pkh/P2PKH.runar.ts").read_text()
_PY = (_REPO / "examples/python/p2pkh/P2PKH.runar.py").read_text()

UNSUPPORTED = (
    "unsupported file extension: {} (expected .runar.ts, .runar.sol, .runar.move, "
    ".runar.go, .runar.rs, .runar.py, .runar.rb, .runar.zig, or .runar.java)"
)


def _cli_hex(file_name: str, src: str) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / file_name
        path.write_text(src)
        return subprocess.run(
            [sys.executable, "-m", "runar_compiler", "--source", str(path), "--hex"],
            cwd=_PKG, capture_output=True, text=True, timeout=120,
        )


@pytest.mark.parametrize("lower,upper,src", [
    ("P2PKH.runar.ts", "P2PKH.RUNAR.TS", _TS),
    ("P2PKH.runar.py", "P2PKH.RUNAR.PY", _PY),
    ("P2PKH.runar.py", "P2PKH.Runar.Py", _PY),
])
def test_suffix_case_does_not_change_the_compile(lower, upper, src):
    a = _cli_hex(lower, src)
    b = _cli_hex(upper, src)
    assert a.returncode == 0, a.stderr
    assert b.returncode == 0, b.stderr
    assert a.stdout.strip() and a.stdout == b.stdout


def test_library_upper_case_suffix_selects_the_same_parser():
    a = parse_source(_PY, "P2PKH.runar.py")
    b = parse_source(_PY, "P2PKH.RUNAR.PY")
    assert not a.errors and not b.errors
    assert a.contract.name == b.contract.name == "P2PKH"


def test_unknown_suffix_is_refused_even_for_valid_typescript():
    res = parse_source(_TS, "P2PKH.runar.xyz")
    assert res.contract is None
    assert [e.message for e in res.errors] == [UNSUPPORTED.format("P2PKH.runar.xyz")]


def test_cli_refuses_unknown_suffix_with_the_shared_diagnostic():
    res = _cli_hex("P2PKH.runar.xyz", _TS)
    assert res.returncode != 0
    assert "unsupported file extension: " in res.stderr + res.stdout
    assert "(expected .runar.ts, .runar.sol" in res.stderr + res.stdout


@pytest.mark.parametrize("name", [None, ""])
def test_no_file_name_means_typescript(name):
    res = parse_source(_TS, name)
    assert not res.errors, res.errors
    assert res.contract is not None and res.contract.name == "P2PKH"
