"""Byte-equality acceptance test for the Python TicTacToe FixedArray port.

The v2 contract uses a single ``FixedArray[Bigint, 9]`` property instead of
9 hand-rolled ``c0..c8`` cells. The Rúnar compiler's ``expand_fixed_arrays``
pass must desugar v2 to the same scalar sibling layout as v1, and the
resulting Bitcoin Script must be byte-identical.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "compilers" / "python"))

from runar_compiler.compiler import compile_from_source  # noqa: E402


V1_PATH = str(Path(__file__).parent / "TicTacToe.runar.py")
V2_PATH = str(Path(__file__).parent / "TicTacToe.v2.runar.py")


def test_tictactoe_v1_and_v2_compile_identically():
    v1 = compile_from_source(V1_PATH)
    v2 = compile_from_source(V2_PATH)

    assert v1.contract_name == v2.contract_name == "TicTacToe"
    assert len(v1.script) == len(v2.script), (
        f"v1 length {len(v1.script)//2} != v2 length {len(v2.script)//2}"
    )
    assert v1.script == v2.script, (
        "TicTacToe v1 and v2 compiled to different hex scripts"
    )


def test_tictactoe_v2_script_length_matches_v1_baseline():
    v2 = compile_from_source(V2_PATH)
    v1 = compile_from_source(V1_PATH)
    v1_bytes = len(v1.script) // 2
    v2_bytes = len(v2.script) // 2
    assert v2_bytes == v1_bytes


def test_tictactoe_v2_state_fields_report_fixed_array():
    v2 = compile_from_source(V2_PATH)
    # The compile_from_source returns an Artifact with dataclass state_fields
    board_field = next(
        (f for f in v2.state_fields if f.name == "board"), None
    )
    assert board_field is not None, "expected regrouped 'board' state field"
    assert board_field.type == "FixedArray<bigint, 9>"
    assert board_field.fixed_array is not None
    assert board_field.fixed_array["length"] == 9
    assert board_field.fixed_array["syntheticNames"] == [
        f"board__{i}" for i in range(9)
    ]
