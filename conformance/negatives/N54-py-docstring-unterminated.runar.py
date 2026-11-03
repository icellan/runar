# F-011: an unterminated triple-quoted Python string (docstring).
#
# A triple-quoted string may span lines, so only end of file makes it
# unterminated. The docstring below never closes. The reference tokenizer
# skipped every remaining line as docstring text, so the guard y < 5 was
# dropped and the method compiled with only y >= 0. CPython rejects the file.
# Every tier must refuse with:
#   unterminated string literal
from runar import SmartContract, Bigint, public, assert_


class Guarded(SmartContract):
    def __init__(self):
        super().__init__()

    @public
    def unlock(self, y: Bigint):
        assert_(y >= 0)
        """Upper bound check follows.
        assert_(y < 5)
