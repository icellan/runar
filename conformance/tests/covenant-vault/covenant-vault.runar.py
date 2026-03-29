from runar import (
    SmartContract, PubKey, Sig, Addr, ByteString, SigHashPreimage, Bigint,
    public, assert_, check_sig, check_preimage, extract_output_hash, hash256, num2bin, cat,
)

class CovenantVault(SmartContract):
    owner: PubKey
    recipient: Addr
    min_amount: Bigint

    def __init__(self, owner: PubKey, recipient: Addr, min_amount: Bigint):
        super().__init__(owner, recipient, min_amount)
        self.owner = owner
        self.recipient = recipient
        self.min_amount = min_amount

    @public
    def spend(self, sig: Sig, tx_preimage: SigHashPreimage):
        assert_(check_sig(sig, self.owner))
        assert_(check_preimage(tx_preimage))
        p2pkh_script = cat(cat('1976a914', self.recipient), '88ac')
        expected_output = cat(num2bin(self.min_amount, 8), p2pkh_script)
        assert_(hash256(expected_output) == extract_output_hash(tx_preimage))
