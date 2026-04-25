from runar import SmartContract, Bigint, public, assert_

class IfElse(SmartContract):
    limit: Bigint

    def __init__(self, limit: Bigint):
        super().__init__(limit)
        self.limit = limit

    @public
    def check(self, value: Bigint, mode: bool):
        result: Bigint = 0
        if mode:
            result = value + self.limit
        else:
            result = value - self.limit
        assert_(result > 0)
