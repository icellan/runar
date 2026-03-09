pragma runar ^0.1.0;

/// @title P2PKH — Pay-to-Public-Key-Hash
/// @notice The most fundamental Bitcoin spending pattern. Funds are locked to
/// the HASH160 (SHA-256 then RIPEMD-160) of a public key. To spend, the
/// recipient must provide their full public key (which must hash to the stored
/// hash) and a valid ECDSA signature over the transaction.
///
/// How It Works: Two-Step Verification
///
///  1. Hash check — hash160(pubKey) == pubKeyHash proves the provided public
///     key matches the one committed to when the output was created.
///  2. Signature check — checkSig(sig, pubKey) proves the spender holds the
///     private key corresponding to that public key.
///
/// This is the same pattern as standard Bitcoin P2PKH transactions, but
/// expressed in the Runar smart contract language.
///
/// Script Layout:
///   Unlocking: <sig> <pubKey>
///   Locking:   OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
///
/// Parameter Sizes:
///   - pubKeyHash: 20 bytes (HASH160 of compressed public key)
///   - sig: ~72 bytes (DER-encoded ECDSA signature + sighash flag)
///   - pubKey: 33 bytes (compressed secp256k1 public key)
contract P2PKH is SmartContract {
    Addr immutable pubKeyHash;

    constructor(Addr _pubKeyHash) {
        pubKeyHash = _pubKeyHash;
    }

    /// @notice Verify the pubKey hashes to the committed hash, then check the signature.
    function unlock(Sig sig, PubKey pubKey) public {
        // Step 1: Verify pubKey matches the committed hash
        require(hash160(pubKey) == pubKeyHash);
        // Step 2: Verify ECDSA signature proves ownership of the private key
        require(checkSig(sig, pubKey));
    }
}
