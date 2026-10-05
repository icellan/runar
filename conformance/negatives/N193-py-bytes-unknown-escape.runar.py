# F-203: a .runar.py bytes literal with an escape CPython does not define.
#
# CPython keeps `\q` in b'..' as the two bytes 5c 71 and warns
# (SyntaxWarning, an error in a future Python). The tiers used to disagree on
# escapes in byte literals, so the same source compiled to different bytes
# than pytest ran. Every tier decodes the escapes CPython defines and refuses
# any other with:
#   invalid escape sequence '\q'
from runar import SmartContract, ByteString, public, assert_


class N193(SmartContract):
    def __init__(self):
        super().__init__()

    @public
    def unlock(self, x: ByteString):
        assert_(x == b'\q')
