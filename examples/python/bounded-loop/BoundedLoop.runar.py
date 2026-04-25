from runar import SmartContract, Bigint, public, assert_

class BoundedLoop(SmartContract):
    expected_sum: Bigint

    def __init__(self, expected_sum: Bigint):
        super().__init__(expected_sum)
        self.expected_sum = expected_sum

    @public
    def verify(self, start: Bigint):
        sum_: Bigint = 0
        for i in range(5):
            sum_ = sum_ + start + i
        assert_(sum_ == self.expected_sum)
