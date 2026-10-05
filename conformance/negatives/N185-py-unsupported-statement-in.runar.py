# N-053: a .runar.py statement that starts with the keyword `in`. The TS
# reference and the Rust tier skipped the unknown token and the bare name
# after it, and compiled the method as if the line were absent; the other
# tiers refused it with unrelated diagnostics. Every tier must refuse it:
#   Unsupported statement starting with 'in'
from runar import SmartContract, Bigint, public, assert_


class N185(SmartContract):
    t: Bigint

    def __init__(self, t: Bigint):
        super().__init__(t)
        self.t = t

    @public
    def unlock(self, x: Bigint):
        in x
        assert_(x == self.t)
