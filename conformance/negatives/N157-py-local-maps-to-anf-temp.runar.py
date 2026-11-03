# N-065: the Python surface maps `t_2` to the Runar name `t2`, an ANF temp name. The
# rule applies after name mapping, so every tier must refuse with:
#   't2' is reserved for compiler-generated names and cannot be used as an identifier
from runar import SmartContract, Bigint, public, assert_

class RPyLocalT2MapsToT2(SmartContract):
    target: Bigint

    def __init__(self, target: Bigint):
        super().__init__(target)
        self.target = target

    @public
    def verify(self, a: Bigint, b: Bigint):
        t_2: Bigint = a + b
        assert_(t_2 == self.target)
