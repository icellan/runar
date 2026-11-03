# F-011: an unterminated single-quoted Python string literal whose next
# matching quote sits on a later comment line. Every tier must refuse with:
#   unterminated string literal
from runar import SmartContract, Bigint, ByteString, public, assert_


class Guarded(SmartContract):
    def __init__(self):
        super().__init__()

    @public
    def unlock(self, y: Bigint):
        tag: ByteString = 'cafe
        assert_(y < 5)
        # '
        assert_(y >= 0)
