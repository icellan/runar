from runar import SmartContract, Bigint, public, assert_

class BooleanLogic(SmartContract):
    threshold: Bigint

    def __init__(self, threshold: Bigint):
        super().__init__(threshold)
        self.threshold = threshold

    @public
    def verify(self, a: Bigint, b: Bigint, flag: bool):
        a_above_threshold: bool = a > self.threshold
        b_above_threshold: bool = b > self.threshold
        both_above: bool = a_above_threshold and b_above_threshold
        either_above: bool = a_above_threshold or b_above_threshold
        not_flag: bool = not flag
        assert_(both_above or (either_above and not_flag))
