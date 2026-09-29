# F-026: a class-level .runar.py field whose line carries a stray token after
# its initializer. The field parser used to skip the rest of the line, so
# `limit: Bigint = 0b1010` initialised `limit` to 0 (the tokenizer split the
# literal into `0` and `b1010`) and the guard compiled to `amount > 0`; the
# pre-fix TS reference emitted 00a0 for it. The same shape is written out here
# with a space, so the refusal rests on the line-break rule alone. Every tier
# must refuse with:
#   expected a line break between statements
from runar import SmartContract, Bigint, public, assert_


class T(SmartContract):
    target: Bigint
    limit: Bigint = 0 b1010

    def __init__(self, target: Bigint):
        super().__init__(target)
        self.target = target

    @public
    def verify(self, amount: Bigint):
        assert_(amount > self.limit)
