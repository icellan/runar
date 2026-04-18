from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig


class OrdinalNFT(SmartContract):
    """OrdinalNFT -- Pay-to-Public-Key-Hash lock for a 1sat ordinal inscription.

    This is a stateless P2PKH contract used to lock an ordinal NFT. The owner
    (holder of the private key whose public key hashes to ``pub_key_hash``) can
    unlock and transfer the ordinal by providing a valid signature and public key.

    Ordinal Inscriptions:

    A 1sat ordinal NFT is a UTXO carrying exactly 1 satoshi with an inscription
    envelope embedded in the locking script. The inscription is a no-op
    (``OP_FALSE OP_IF ... OP_ENDIF``) that doesn't affect script execution but
    permanently records content (image, text, JSON, etc.) on-chain.

    The inscription envelope is injected by the SDK's ``with_inscription()``
    method at deployment time -- the contract logic itself is just standard P2PKH.

    Script Layout:
      Unlocking: ``<sig> <pub_key>``
      Locking:   ``OP_DUP OP_HASH160 <pub_key_hash> OP_EQUALVERIFY OP_CHECKSIG [inscription envelope]``
    """
    pub_key_hash: Addr

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        """Unlock by proving ownership of the private key corresponding to pub_key_hash."""
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
