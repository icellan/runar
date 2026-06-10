"""BUG-008 follow-up: IR-loader size-guard regression tests."""

import pytest

from runar_compiler.ir.input_limits import (
    MAX_IR_BYTES,
    MAX_IR_NESTING,
    IRNestingExceededError,
    IRSizeExceededError,
    assert_ir_bytes_under_limit,
    assert_ir_nesting_under_limit,
)
from runar_compiler.ir.loader import load_ir


def test_load_ir_rejects_oversized_input() -> None:
    oversized = " " * (MAX_IR_BYTES + 1)
    with pytest.raises(IRSizeExceededError) as exc:
        load_ir(oversized)
    assert exc.value.limit == MAX_IR_BYTES
    assert exc.value.actual == MAX_IR_BYTES + 1


def test_load_ir_rejects_deeply_nested_input() -> None:
    depth = MAX_IR_NESTING + 50
    body = "1"
    for _ in range(depth):
        body = '{"n":' + body + "}"
    with pytest.raises(IRNestingExceededError) as exc:
        load_ir(body)
    assert exc.value.limit == MAX_IR_NESTING


def test_depth_walk_ignores_braces_inside_strings() -> None:
    # 1000 `{` inside a JSON string MUST NOT count toward depth.
    inner = "{" * 1000
    bad = (
        '{"contractName":"X","properties":[],"methods":[],'
        f'"_note":"{inner}"}}'
    )
    # Neither DoS-bound guard should fire. The downstream loader might
    # raise ValueError on missing fields or otherwise succeed — neither
    # IRSizeExceededError nor IRNestingExceededError should appear.
    try:
        load_ir(bad)
    except (IRSizeExceededError, IRNestingExceededError) as e:
        pytest.fail(f"DoS-bound guard incorrectly tripped: {e}")
    except ValueError:
        pass  # downstream schema/decoding may fail; that's fine.


def test_load_ir_accepts_minimal_program() -> None:
    minimal = '{"contractName":"X","properties":[],"methods":[]}'
    program = load_ir(minimal)
    assert program is not None


def test_assert_ir_bytes_under_limit_typed_error() -> None:
    with pytest.raises(IRSizeExceededError):
        assert_ir_bytes_under_limit("x" * (MAX_IR_BYTES + 1))


def test_assert_ir_nesting_under_limit_typed_error() -> None:
    depth = MAX_IR_NESTING + 1
    body = "1"
    for _ in range(depth):
        body = "[" + body + "]"
    with pytest.raises(IRNestingExceededError):
        assert_ir_nesting_under_limit(body)
