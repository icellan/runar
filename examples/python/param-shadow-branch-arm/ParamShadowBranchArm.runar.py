# ParamShadowBranchArm — N-007 conformance fixture. The parameter ``count``
# shares the property's name; inside the ``if`` arm it is still the parameter.
from runar import StatefulSmartContract, Bigint, public, assert_

class ParamShadowBranchArm(StatefulSmartContract):
    count: Bigint

    def __init__(self, count: Bigint):
        super().__init__(count)
        self.count = count

    @public
    def set(self, count: Bigint, flag: bool):
        if flag:
            assert_(count == 5)
        self.count = count
