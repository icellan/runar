"""Regression: Rúnar does not support break/continue; Python parser must reject.

Before the fix at compilers/python/runar_compiler/frontend/parser_python.py
:parse_statement, a `break` / `continue` keyword was silently parsed as an
`Identifier(name='break')` and dropped in downstream passes. That masked
bugs where a developer wrote early-exit logic that never actually executed.

The TS parser already rejects `BreakStatement` / `ContinueStatement` with
'Unsupported statement kind'; this test asserts Python behaves the same.
"""

from runar_compiler.frontend.parser_dispatch import parse_source


_BREAK_SOURCE = """\
from runar import SmartContract, assert_

class BreakTest(SmartContract):
    hash: int

    def __init__(self, hash: int):
        super().__init__(hash)
        self.hash = hash

    def unlock(self, n: int) -> None:
        total = 0
        for i in range(10):
            if i == n:
                break
            total = total + i
        assert_(total >= 0)
"""


_CONTINUE_SOURCE = _BREAK_SOURCE.replace("break", "continue").replace(
    "BreakTest", "ContTest"
)


def _parse_errors(src: str) -> list[str]:
    result = parse_source(src, "test.runar.py")
    return [e.format_message() for e in result.errors]


def test_break_is_rejected_by_parser():
    errors = _parse_errors(_BREAK_SOURCE)
    assert errors, "expected parser to reject `break`, but got no errors"
    assert any("break" in msg.lower() for msg in errors), errors


def test_continue_is_rejected_by_parser():
    errors = _parse_errors(_CONTINUE_SOURCE)
    assert errors, "expected parser to reject `continue`, but got no errors"
    assert any("continue" in msg.lower() for msg in errors), errors
