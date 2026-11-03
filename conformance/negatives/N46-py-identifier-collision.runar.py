# F-017 — two Python locals whose names convert to ONE Rúnar name.
#
# The .runar.py surface converts snake_case to camelCase and strips a trailing
# underscore, so `tmp` and `tmp_` both become `tmp`. Under Python semantics the
# guard below is always false (n + 1 != n + 2), so the output is unspendable.
# Before the collision rule every tier bound both spellings to one variable and
# emitted `OP_DUP OP_1ADD OP_SWAP OP_2 OP_ADD OP_DUP OP_DUP OP_NUMEQUAL ...`:
# the second binding compared with a copy of itself, an always-TRUE guard that
# the real @bsv/sdk engine accepts for any n.
#
# Every tier must refuse with:
#   identifier collision: 'tmp' and 'tmp_' both convert to 'tmp'; rename one of them
from runar import SmartContract, Bigint, public, assert_


class IdentCollisionPy(SmartContract):
    k: Bigint

    def __init__(self, k: Bigint):
        super().__init__(k)
        self.k = k

    @public
    def unlock(self, n: Bigint):
        tmp = n + 1
        tmp_ = n + 2
        assert_(tmp == tmp_)
