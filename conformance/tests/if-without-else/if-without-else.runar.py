from runar import SmartContract, Bigint, public, assert_

class IfWithoutElse(SmartContract):
    threshold: Bigint

    def __init__(self, threshold: Bigint):
        super().__init__(threshold)
        self.threshold = threshold

    @public
    def check(self, a: Bigint, b: Bigint):
        count: Bigint = 0
        if a > self.threshold:
            count = count + 1
        if b > self.threshold:
            count = count + 1
        assert_(count > 0)
