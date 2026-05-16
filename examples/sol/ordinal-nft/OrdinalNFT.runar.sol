pragma runar ^0.1.0;

/// @title OrdinalNFT -- Pay-to-Public-Key-Hash lock for a 1sat ordinal inscription.
/// @notice A stateless P2PKH contract used to lock an ordinal NFT. The owner
/// (holder of the private key whose public key hashes to `pubKeyHash`) can
/// unlock and transfer the ordinal by providing a valid signature and public key.
///
/// Ordinal Inscriptions:
///   A 1sat ordinal NFT is a UTXO carrying exactly 1 satoshi with an inscription
///   envelope embedded in the locking script. The inscription is a no-op
///   (OP_FALSE OP_IF ... OP_ENDIF) that doesn't affect script execution but
///   permanently records content (image, text, JSON, etc.) on-chain.
///
///   The inscription envelope is injected by the SDK's `withInscription()` method
///   at deployment time -- the contract logic itself is just standard P2PKH.
///
/// Script Layout:
///   Unlocking: <sig> <pubKey>
///   Locking:   OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG [inscription envelope]
contract OrdinalNFT is SmartContract {
    Addr immutable pubKeyHash;

    constructor(Addr _pubKeyHash) {
        pubKeyHash = _pubKeyHash;
    }

    /// @notice Unlock by proving ownership of the private key corresponding to pubKeyHash.
    function unlock(Sig sig, PubKey pubKey) public {
        require(hash160(pubKey) == pubKeyHash);
        require(checkSig(sig, pubKey));
    }
}
