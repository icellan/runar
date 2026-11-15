# R2-GK010-ASSERT (GK-GAP-010) -- the Python surface: check_preimage(tx_preimage) as a bare statement.
# Every tier refuses:
#   public method 'spend' must pass its SigHashPreimage parameter 'txPreimage'
#   to checkPreimage() on every path
from runar import SmartContract, SigHashPreimage, public, assert_, check_preimage, extract_amount

class N529(SmartContract):
    min_amount: int

    def __init__(self, min_amount: int):
        super().__init__(min_amount)
        self.min_amount = min_amount

    @public
    def spend(self, tx_preimage: SigHashPreimage, flag: bool):
        check_preimage(tx_preimage)
        assert_(extract_amount(tx_preimage) >= self.min_amount)
