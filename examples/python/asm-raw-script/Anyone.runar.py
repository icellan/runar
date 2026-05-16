# Anyone — minimal `asm` raw-script contract (Python surface).
from runar import UnsafeSmartContract, public, asm


class Anyone(UnsafeSmartContract):
    def __init__(self):
        super().__init__()

    @public
    def unlock(self):
        asm("51", 0, 1)
