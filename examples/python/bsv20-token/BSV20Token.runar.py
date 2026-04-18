from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig


class BSV20Token(SmartContract):
    """BSV20Token -- Pay-to-Public-Key-Hash lock for a BSV-20 fungible token.

    BSV-20 is a 1sat ordinals token standard where fungible tokens are represented
    as inscriptions on P2PKH UTXOs. The contract logic is standard P2PKH -- the
    token semantics (deploy, mint, transfer) are encoded in the inscription
    envelope and interpreted by indexers, not by the script itself.

    BSV-20 Token Lifecycle:

      1. Deploy   -- Inscribe a deploy JSON
         (``{"p":"bsv-20","op":"deploy","tick":"RUNAR","max":"21000000"}``)
         onto a UTXO to register a new ticker. First deployer wins.
      2. Mint     -- Inscribe a mint JSON
         (``{"p":"bsv-20","op":"mint","tick":"RUNAR","amt":"1000"}``)
         to claim tokens up to the per-mint limit.
      3. Transfer -- Inscribe a transfer JSON
         (``{"p":"bsv-20","op":"transfer","tick":"RUNAR","amt":"50"}``)
         to move tokens between addresses.

    The SDK helpers ``bsv20_deploy()``, ``bsv20_mint()``, and ``bsv20_transfer()``
    build the correct inscription payloads for each operation.
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
