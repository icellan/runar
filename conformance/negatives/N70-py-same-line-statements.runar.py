# F-026: two .runar.py statements on one line with no separator. The tokenizer
# used to split `0b1010` into `0` and `b1010`, and this loop then parsed
# `b1010` as a second, discarded expression statement, so `lim` became 0 and
# the guard compiled to `amount > 0`. The same shape is written out here with a
# space, so the refusal rests on the line-break rule alone. Every tier must
# refuse with:
#   expected a line break between statements
from runar import SmartContract, Bigint, public, assert_


class T(SmartContract):
    target: Bigint

    def __init__(self, target: Bigint):
        super().__init__(target)
        self.target = target

    @public
    def verify(self, amount: Bigint, b1010: Bigint):
        lim = 0 b1010
        assert_(amount > lim)
