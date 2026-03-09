from runar import (
    StatefulSmartContract, PubKey, Sig, ByteString, Bigint, Readonly,
    public, assert_, check_sig,
)


class SimpleNFT(StatefulSmartContract):
    """A non-fungible token (NFT) represented as a single UTXO.

    Unlike fungible tokens, an NFT is indivisible -- the token IS the UTXO. This contract
    demonstrates ownership transfer and burn (permanent destruction) of a unique digital asset,
    enforced entirely by Bitcoin Script.

    UTXO as NFT:
        Each NFT is a single UTXO carrying:
        - owner (mutable): current owner's public key, updated on transfer
        - token_id (readonly): unique identifier baked into the locking script
        - metadata (readonly): content hash or URI, also baked in and immutable

    Operations:
        transfer -- Changes ownership. Creates one continuation UTXO via add_output.
        burn     -- Destroys the token permanently. No add_output = no successor = token ceases to exist.

    Authorization:
        Both operations require the current owner's ECDSA signature via check_sig.
    """

    owner: PubKey                    # Current owner's public key. Mutable -- updated when the NFT is transferred.
    token_id: Readonly[ByteString]   # Unique token identifier. Readonly -- baked into the locking script at deploy time.
    metadata: Readonly[ByteString]   # Token metadata (content hash or URI). Readonly -- immutable for the token's lifetime.

    def __init__(self, owner: PubKey, token_id: ByteString, metadata: ByteString):
        super().__init__(owner, token_id, metadata)
        self.owner = owner
        self.token_id = token_id
        self.metadata = metadata

    @public
    def transfer(self, sig: Sig, new_owner: PubKey, output_satoshis: Bigint):
        """Transfer ownership of the NFT to a new owner.

        Creates one continuation UTXO via add_output with the new owner. token_id and
        metadata remain unchanged (readonly properties are baked into the locking script).
        add_output(satoshis, owner) takes the single mutable property positionally.

        Args:
            sig: Current owner's signature (authorization).
            new_owner: New owner's public key.
            output_satoshis: Satoshis to fund the continuation UTXO.
        """
        assert_(check_sig(sig, self.owner))
        assert_(output_satoshis >= 1)
        self.add_output(output_satoshis, new_owner)

    @public
    def burn(self, sig: Sig):
        """Burn (permanently destroy) the NFT.

        The owner signs to authorize destruction. Because this method does not call add_output
        and does not mutate state, the compiler generates no state continuation. The UTXO is
        simply spent with no successor -- the token ceases to exist on-chain.

        Args:
            sig: Current owner's signature (authorization).
        """
        assert_(check_sig(sig, self.owner))
