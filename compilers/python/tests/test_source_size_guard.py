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


# N-136: the nine per-format parse_* functions are exported from
# runar_compiler.frontend and importable directly (parser_dispatch.parse_source
# dispatches to them, but a caller can reach around the dispatcher exactly the
# way R-146 found in TS and F-177 found in Go). Only parse_source called
# assert_source_bytes_under_limit; each per-format entry went straight to its
# own tokenizer, so a caller invoking e.g. parse_java or parse_sol directly
# got no DoS-bound rejection at all. This proves each of the 9 exported
# entries raises SourceSizeExceededError for a MAX_SOURCE_BYTES+1 input; it
# does not prove the guard runs before tokenization (code inspection only).
def _per_format_parsers():
    from runar_compiler.frontend.parser_python import parse_python
    from runar_compiler.frontend.parser_ts import parse_ts
    from runar_compiler.frontend.parser_sol import parse_sol
    from runar_compiler.frontend.parser_move import parse_move
    from runar_compiler.frontend.parser_go import parse_go
    from runar_compiler.frontend.parser_rust import parse_rust
    from runar_compiler.frontend.parser_ruby import parse_ruby
    from runar_compiler.frontend.parser_zig import parse_zig
    from runar_compiler.frontend.parser_java import parse_java

    return [
        ("parse_python", parse_python),
        ("parse_ts", parse_ts),
        ("parse_sol", parse_sol),
        ("parse_move", parse_move),
        ("parse_go", parse_go),
        ("parse_rust", parse_rust),
        ("parse_ruby", parse_ruby),
        ("parse_zig", parse_zig),
        ("parse_java", parse_java),
    ]


@pytest.mark.parametrize(
    "name,fn", _per_format_parsers(), ids=[n for n, _ in _per_format_parsers()]
)
def test_every_exported_per_format_parser_rejects_oversized_input(name, fn) -> None:
    oversized = " " * (MAX_SOURCE_BYTES + 1)
    with pytest.raises(SourceSizeExceededError) as exc:
        fn(oversized, "Counter.runar.ts")
    assert exc.value.limit == MAX_SOURCE_BYTES, name
    assert exc.value.actual == MAX_SOURCE_BYTES + 1, name


@pytest.mark.parametrize(
    "name,fn", _per_format_parsers(), ids=[n for n, _ in _per_format_parsers()]
)
def test_every_exported_per_format_parser_accepts_small_input_at_the_guard(
    name, fn
) -> None:
    # Not a syntax test -- the control that the guard itself does not trip on
    # ordinary small input. The parser is free to fail afterwards for its own
    # reasons; this only asserts the size guard did not raise.
    result = fn("", "Counter.runar.ts")
    assert result is not None, name
