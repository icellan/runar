# F-011 (CL-BUG-196): an unterminated Python byte-string literal.
#
# The b-string on the tag line has no closing quote. Tokenizers that scanned
# to the next matching quote ran across the newline and closed the literal on
# the comment line below, so the guard y < 5 became literal DATA (b-strings
# hex-encode arbitrary bytes, so no hex validator fires). Pre-fix the Go,
# Python, Zig and Java tiers emitted a script without the guard, and
# @bsv/sdk Spend.validate accepted the Go artifact with y = 100.
#
# A single-line Python string that reaches a line break is unterminated.
# Every tier must refuse with:
#   unterminated string literal
from runar import SmartContract, Bigint, ByteString, public, assert_


class Guarded(SmartContract):
    def __init__(self):
        super().__init__()

    @public
    def unlock(self, y: Bigint):
        tag: ByteString = b"cafe
        assert_(y < 5)
        # "
        assert_(y >= 0)
