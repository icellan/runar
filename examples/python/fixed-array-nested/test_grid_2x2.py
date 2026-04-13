"""Nested FixedArray acceptance test for the Python compiler."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "compilers" / "python"))

from runar_compiler.compiler import compile_from_source, artifact_to_json  # noqa: E402
from runar.sdk.types import RunarArtifact  # noqa: E402
from runar.sdk.state import serialize_state, deserialize_state  # noqa: E402


SOURCE = str(Path(__file__).parent / "Grid2x2.v2.runar.py")


def test_grid_2x2_compiles():
    art = compile_from_source(SOURCE)
    assert art.contract_name == "Grid2x2"
    grid_field = next(
        (f for f in art.state_fields if f.name == "grid"), None
    )
    assert grid_field is not None
    assert grid_field.type == "FixedArray<FixedArray<bigint, 2>, 2>"
    assert grid_field.fixed_array is not None
    assert grid_field.fixed_array["length"] == 2
    assert grid_field.fixed_array["elementType"] == "FixedArray<bigint, 2>"
    assert grid_field.fixed_array["syntheticNames"] == [
        "grid__0__0", "grid__0__1", "grid__1__0", "grid__1__1",
    ]
    assert grid_field.initial_value == [[0, 0], [0, 0]]


def test_grid_2x2_sdk_state_roundtrip():
    art = compile_from_source(SOURCE)
    sdk = RunarArtifact.from_dict(json.loads(artifact_to_json(art)))

    values = {"grid": [[1, 2], [3, 4]]}
    hex_out = serialize_state(sdk.state_fields, values)
    result = deserialize_state(sdk.state_fields, hex_out)
    assert result == {"grid": [[1, 2], [3, 4]]}
