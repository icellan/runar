"""BUG-008 follow-up: source-parser size-guard regression tests."""

import pytest

from runar_compiler.frontend.input_limits import (
    MAX_SOURCE_BYTES,
    SourceSizeExceededError,
    assert_source_bytes_under_limit,
)
from runar_compiler.frontend.parser_dispatch import parse_source


def test_parse_source_rejects_oversized_input() -> None:
    oversized = " " * (MAX_SOURCE_BYTES + 1)
    with pytest.raises(SourceSizeExceededError) as exc:
        parse_source(oversized, "Counter.runar.ts")
    assert exc.value.limit == MAX_SOURCE_BYTES
    assert exc.value.actual == MAX_SOURCE_BYTES + 1


@pytest.mark.parametrize(
    "ext",
    [
        ".runar.ts",
        ".runar.sol",
        ".runar.move",
        ".runar.go",
        ".runar.py",
        ".runar.rs",
        ".runar.rb",
        ".runar.zig",
        ".runar.java",
    ],
)
def test_parse_source_rejects_oversized_input_regardless_of_extension(ext: str) -> None:
    oversized = " " * (MAX_SOURCE_BYTES + 1)
    with pytest.raises(SourceSizeExceededError):
        parse_source(oversized, "Counter" + ext)


def test_parse_source_accepts_normal_sized_input() -> None:
    # A minimal Python contract source. parse_source returns a ParseResult;
    # we only assert the size guard does not raise.
    src = (
        "from runar import SmartContract\n"
        "class Counter(SmartContract):\n"
        "    def __init__(self, x: int) -> None:\n"
        "        super().__init__()\n"
        "        self.x = x\n"
        "    @public\n"
        "    def unlock(self) -> None:\n"
        "        pass\n"
    )
    result = parse_source(src, "Counter.runar.py")
    # The Python parser may produce diagnostics; the only assertion is the
    # size guard did NOT raise.
    assert result is not None


def test_assert_source_bytes_under_limit_typed_error() -> None:
    with pytest.raises(SourceSizeExceededError) as exc:
        assert_source_bytes_under_limit(" " * (MAX_SOURCE_BYTES + 1))
    assert "MAX_SOURCE_BYTES" in str(exc.value)
    assert exc.value.limit == MAX_SOURCE_BYTES
