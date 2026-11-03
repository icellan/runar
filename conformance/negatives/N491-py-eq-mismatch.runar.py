# N-491: TS surface-parser operand anchor parity. A bigint and a boolean compared with `==`.
# TS must anchor the refusal on this surface exactly where it does on .runar.ts
# (see n491-operand-anchor-surface-matrix.test.ts).
from runar import SmartContract, Bigint, public, assert_

class Anchor(SmartContract):
    t: Bigint

    def __init__(self, t: Bigint):
        super().__init__(t)
        self.t = t

    @public
    def go(self, x: Bigint, flag: bool):
        assert_(x == flag)
