# P256Wallet -- Hybrid secp256k1 + P-256 wallet.
#
# == Security Model: Two-Layer Authentication
#
# This contract binds a spend to two independent keys:
#
#  1. secp256k1 OP_CHECKSIG proves the signature commits to this specific
#     transaction (via the Bitcoin sighash preimage).
#  2. P-256 ECDSA verifies the secp256k1 sig bytes -- proving the transaction
#     was also authorized by the P-256 (NIST / Web PKI) key holder.
#
# The secp256k1 sig bytes ARE the message that P-256 signs. This means a
# hardware security module or browser WebAuthn key (which speaks P-256) can
# gate Bitcoin spending without any new opcode.
#
# == Locking Script Layout
#
#   Unlocking: <p256_sig(64B)> <p256_pub_key(33B)> <ecdsa_sig(~72B)> <ecdsa_pub_key(33B)>
#
#   Locking:
#     # --- secp256k1 verification (P2PKH) ---
#     OP_OVER OP_TOALTSTACK           # copy ecdsa_sig to alt stack for P-256 later
#     OP_DUP OP_HASH160 <ecdsa_pub_key_hash(20B)> OP_EQUALVERIFY OP_CHECKSIG OP_VERIFY
#     # --- P-256 pubkey commitment ---
#     OP_DUP OP_HASH160 <p256_pub_key_hash(20B)> OP_EQUALVERIFY
#     # --- P-256 verification ---
#     OP_FROMALTSTACK OP_ROT OP_ROT   # bring ecdsa_sig back as P-256 message
#     <verify_ecdsa_p256 inline>      # verify P256(ecdsa_sig, p256_sig, p256_pub_key)
#
# == Parameter Sizes
#
#  - ecdsa_pub_key_hash: 20 bytes (HASH160 of compressed secp256k1 public key)
#  - p256_pub_key_hash:  20 bytes (HASH160 of 33-byte compressed P-256 public key)
#  - ecdsa_sig:          ~72 bytes (DER-encoded secp256k1 signature + sighash flag)
#  - ecdsa_pub_key:      33 bytes (compressed secp256k1 public key)
#  - p256_sig:           64 bytes (raw r[32] || s[32] P-256 signature)
#  - p256_pub_key:       33 bytes (compressed P-256 public key)
require 'runar'

class P256Wallet < Runar::SmartContract
  prop :ecdsa_pub_key_hash, Addr
  prop :p256_pub_key_hash, ByteString

  def initialize(ecdsa_pub_key_hash, p256_pub_key_hash)
    super(ecdsa_pub_key_hash, p256_pub_key_hash)
    @ecdsa_pub_key_hash = ecdsa_pub_key_hash
    @p256_pub_key_hash = p256_pub_key_hash
  end

  # Verify both secp256k1 and P-256 signatures to allow spending.
  runar_public p256_sig: ByteString, p256_pub_key: ByteString, sig: Sig, pub_key: PubKey
  def spend(p256_sig, p256_pub_key, sig, pub_key)
    # Step 1: Verify secp256k1 -- proves sig commits to this transaction
    assert hash160(pub_key) == @ecdsa_pub_key_hash
    assert check_sig(sig, pub_key)

    # Step 2: Verify P-256 -- proves secp256k1 sig was authorized by P-256 key
    assert hash160(p256_pub_key) == @p256_pub_key_hash
    assert verify_ecdsa_p256(sig, p256_sig, p256_pub_key)
  end
end
