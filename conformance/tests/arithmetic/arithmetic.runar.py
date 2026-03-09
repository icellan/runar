from runar import SmartContract, Bigint, public, assert_

class Arithmetic(SmartContract):
    target: Bigint

    def __init__(self, target: Bigint):
        super().__init__(target)
        self.target = target

    @public
    def verify(self, a: Bigint, b: Bigint):
        sum_: Bigint = a + b
        diff: Bigint = a - b
        prod: Bigint = a * b
        quot: Bigint = a // b
        result: Bigint = sum_ + diff + prod + quot
        assert_(result == self.target)
