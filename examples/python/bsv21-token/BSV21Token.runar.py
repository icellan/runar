from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig


class BSV21Token(SmartContract):
    """BSV21Token -- Pay-to-Public-Key-Hash lock for a BSV-21 fungible token.

    BSV-21 (v2) is an improvement over BSV-20 that uses ID-based tokens instead
    of tick-based. The token ID is derived from the deploy transaction
    (``<txid>_<vout>``), eliminating ticker squatting and enabling
    admin-controlled distribution.

    BSV-21 Token Lifecycle:

      1. Deploy+Mint -- A single inscription deploys the token and mints the
         initial supply in one atomic operation. The token ID is the outpoint of
         the output containing this inscription.
      2. Transfer   -- Inscribe a transfer JSON referencing the token ID and amount.

    The SDK helpers ``bsv21_deploy_mint()`` and ``bsv21_transfer()`` build the
    correct inscription payloads for each operation.
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
