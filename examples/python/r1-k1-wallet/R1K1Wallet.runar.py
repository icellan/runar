"""Hardware-backed P-256 primary spending with independent K1 recovery."""

from runar import (
    Addr, ByteString, PubKey, Sig, SigHashPreimage, SmartContract,
    assert_, cat, check_preimage, check_sig, hash160, len_, public,
    sha256, substr, verify_ecdsa_p256,
)


class R1K1Wallet(SmartContract):
    r1_salted_pub_key_hash: Addr
    k1_pub_key_hash: Addr

    def __init__(self, r1_salted_pub_key_hash: Addr, k1_pub_key_hash: Addr):
        super().__init__(r1_salted_pub_key_hash, k1_pub_key_hash)
        self.r1_salted_pub_key_hash = r1_salted_pub_key_hash
        self.k1_pub_key_hash = k1_pub_key_hash

    @public
    def spend_r1(
        self,
        r1_sig: ByteString,
        r1_pub_key: ByteString,
        r1_salt: ByteString,
        tx_preimage: SigHashPreimage,
    ):
        assert_(len_(r1_salt) == 32)
        assert_(hash160(cat(r1_pub_key, r1_salt)) == self.r1_salted_pub_key_hash)
        assert_(substr(tx_preimage, len_(tx_preimage) - 4, 4) == '41000000')
        assert_(check_preimage(tx_preimage))
        assert_(verify_ecdsa_p256(sha256(tx_preimage), r1_sig, r1_pub_key))

    @public
    def recover_k1(self, k1_sig: Sig, k1_pub_key: PubKey):
        assert_(hash160(k1_pub_key) == self.k1_pub_key_hash)
        assert_(check_sig(k1_sig, k1_pub_key))
