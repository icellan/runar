from runar import StatefulSmartContract, Ripemd160, public, assert_

class HashRegistry(StatefulSmartContract):
    current_hash: Ripemd160

    def __init__(self, current_hash: Ripemd160):
        super().__init__(current_hash)
        self.current_hash = current_hash

    @public
    def update(self, new_hash: Ripemd160):
        self.current_hash = new_hash
        assert_(True)
