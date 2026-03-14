pragma runar ^0.1.0;

/// @title P2Blake3PKH — Pay-to-Blake3-Public-Key-Hash
/// @notice A variant of P2PKH that uses BLAKE3 instead of HASH160 (SHA-256 then
/// RIPEMD-160) for public key hashing. BLAKE3 produces a 32-byte digest (vs
/// HASH160's 20 bytes), offering a larger pre-image space and resistance to
/// length-extension attacks.
///
/// How It Works: Two-Step Verification
///
///  1. Hash check — blake3Hash(pubKey) == pubKeyHash proves the provided public
///     key matches the one committed to when the output was created.
///  2. Signature check — checkSig(sig, pubKey) proves the spender holds the
///     private key corresponding to that public key.
///
/// Script Layout:
///   The compiled Bitcoin Script inlines the BLAKE3 compression function
///   directly into the locking script (~7K-10K ops), unlike P2PKH which
///   uses the single OP_HASH160 opcode.
///
///   Locking script:
///     OP_DUP
///     <blake3 compression inlined — ~7K-10K ops>
///     <pubKeyHash (32 bytes)>
///     OP_EQUALVERIFY
///     OP_CHECKSIG
///
///   Unlocking script:
///     <sig> <pubKey>
///
/// Parameter Sizes:
///   - pubKeyHash: 32 bytes (BLAKE3 hash of compressed public key)
///   - sig: ~72 bytes (DER-encoded ECDSA signature + sighash flag)
///   - pubKey: 33 bytes (compressed secp256k1 public key)
contract P2Blake3PKH is SmartContract {
    bytes immutable pubKeyHash;

    constructor(bytes _pubKeyHash) {
        pubKeyHash = _pubKeyHash;
    }

    /// @notice Verify the pubKey hashes to the committed BLAKE3 hash, then check the signature.
    function unlock(Sig sig, PubKey pubKey) public {
        // Step 1: Verify pubKey matches the committed BLAKE3 hash
        require(blake3Hash(pubKey) == pubKeyHash);
        // Step 2: Verify ECDSA signature proves ownership of the private key
        require(checkSig(sig, pubKey));
    }
}
