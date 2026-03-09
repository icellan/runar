pragma runar ^0.1.0;

/// @title SimpleNFT
/// @notice A non-fungible token (NFT) represented as a single UTXO.
/// Unlike fungible tokens, an NFT is indivisible -- the token IS the UTXO. This contract
/// demonstrates ownership transfer and burn (permanent destruction) of a unique digital asset,
/// enforced entirely by Bitcoin Script.
/// @dev UTXO as NFT:
/// Each NFT is a single UTXO carrying:
///   - owner (mutable): current owner's public key, updated on transfer
///   - tokenId (readonly): unique identifier baked into the locking script
///   - metadata (readonly): content hash or URI, also baked in and immutable
///
/// Operations:
///   transfer -- Changes ownership. Creates one continuation UTXO via addOutput.
///   burn     -- Destroys the token permanently. No addOutput = no successor = token ceases to exist.
///
/// Authorization: Both operations require the current owner's ECDSA signature via checkSig.
contract SimpleNFT is StatefulSmartContract {
    PubKey owner;                    /// @notice Current owner's public key. Mutable -- updated when the NFT is transferred.
    ByteString immutable tokenId;    /// @notice Unique token identifier. Readonly -- baked into the locking script at deploy time.
    ByteString immutable metadata;   /// @notice Token metadata (content hash or URI). Readonly -- immutable for the token's lifetime.

    constructor(PubKey _owner, ByteString _tokenId, ByteString _metadata) {
        owner = _owner;
        tokenId = _tokenId;
        metadata = _metadata;
    }

    /// @notice Transfer ownership of the NFT to a new owner.
    /// @dev Creates one continuation UTXO via addOutput with the new owner. tokenId and
    /// metadata remain unchanged (readonly properties are baked into the locking script).
    /// addOutput(satoshis, owner) takes the single mutable property positionally.
    /// @param sig Current owner's signature (authorization)
    /// @param newOwner New owner's public key
    /// @param outputSatoshis Satoshis to fund the continuation UTXO
    function transfer(Sig sig, PubKey newOwner, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));
        require(outputSatoshis >= 1);
        this.addOutput(outputSatoshis, newOwner);
    }

    /// @notice Burn (permanently destroy) the NFT.
    /// @dev The owner signs to authorize destruction. Because this method does not call addOutput
    /// and does not mutate state, the compiler generates no state continuation. The UTXO is
    /// simply spent with no successor -- the token ceases to exist on-chain.
    /// @param sig Current owner's signature (authorization)
    function burn(Sig sig) public {
        require(checkSig(sig, this.owner));
        // No addOutput and no state mutation = token destroyed
    }
}
