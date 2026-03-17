require 'runar'

# P2Blake3PKH -- Pay-to-Blake3-Public-Key-Hash.
#
# A variant of P2PKH that uses BLAKE3 instead of HASH160 (SHA-256 then
# RIPEMD-160) for public key hashing. BLAKE3 produces a 32-byte digest
# (vs HASH160's 20 bytes), offering a larger pre-image space and resistance
# to length-extension attacks.
#
# How It Works: Two-Step Verification
#
#   1. Hash check -- blake3_hash(pub_key) == pub_key_hash proves the provided
#      public key matches the one committed to when the output was created.
#   2. Signature check -- check_sig(sig, pub_key) proves the spender holds
#      the private key corresponding to that public key.
#
# Script Layout:
#   The compiled Bitcoin Script inlines the BLAKE3 compression function
#   directly into the locking script (~7K-10K ops), unlike P2PKH which
#   uses the single OP_HASH160 opcode.
#
#   Locking script:
#     OP_DUP
#     <blake3 compression inlined -- ~7K-10K ops>
#     <pubKeyHash (32 bytes)>
#     OP_EQUALVERIFY
#     OP_CHECKSIG
#
#   Unlocking script:
#     <sig> <pubKey>
#
# Parameter Sizes:
#   - pub_key_hash: 32 bytes (BLAKE3 hash of compressed public key)
#   - sig: ~72 bytes (DER-encoded ECDSA signature + sighash flag)
#   - pub_key: 33 bytes (compressed secp256k1 public key)

class P2Blake3PKH < Runar::SmartContract
  prop :pub_key_hash, ByteString

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  # Verify the pub_key hashes to the committed BLAKE3 hash, then check the
  # signature.
  #
  # Step 1: blake3_hash(pub_key) == pub_key_hash proves the public key matches
  #         the one committed to at deployment.
  # Step 2: check_sig(sig, pub_key) proves the spender holds the private key.
  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    # Step 1: Verify pub_key matches the committed BLAKE3 hash
    assert blake3_hash(pub_key) == @pub_key_hash
    # Step 2: Verify ECDSA signature proves ownership of the private key
    assert check_sig(sig, pub_key)
  end
end
