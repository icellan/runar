# =============================================================================
# INSECURE -- DO NOT USE IN PRODUCTION
# =============================================================================
# This contract is intentionally broken. It exists ONLY for educational
# purposes, to demonstrate why a "raw" post-quantum signature check is NOT a
# safe spending condition on its own.
#
# THE FLAW
# --------
# `verify_slh_dsa_sha2_128s` (and any post-quantum signature primitive:
# WOTS+, SLH-DSA, etc.) verifies that `sig` is a valid signature of `msg`
# under `pubkey`. Here `msg` is a free unlocking-script argument supplied by
# the spender. The contract has no relationship between `msg` and the
# Bitcoin transaction being authorised. Anyone observing a single valid
# spend can reuse the same (msg, sig) pair -- or pick any other (msg, sig)
# they have a signature for -- and the script still verifies. The coins can
# be stolen or replayed.
#
# WHY POST-QUANTUM SIG SCHEMES DO NOT BIND TRANSACTIONS BY THEMSELVES
# ------------------------------------------------------------------
# OP_CHECKSIG is special: it commits to the transaction's sighash via the
# secp256k1 ECDSA signature. WOTS+ / SLH-DSA verify a message you hand them;
# they have no view of the transaction. To get post-quantum security AND
# transaction binding, you need a hybrid construction that feeds the ECDSA
# signature bytes (which DO commit to the sighash) as the "message" to the
# post-quantum verifier.
#
# THE CORRECT PATTERN
# -------------------
#   examples/ruby/post-quantum-wallet/   -- WOTS+ hybrid (ECDSA sig as msg)
#   examples/ruby/sphincs-wallet/        -- SLH-DSA hybrid (ECDSA sig as msg)
#
# Use those for any real PQ-secured wallet. This file is a teaching artifact.
# =============================================================================

require 'runar'

class PostQuantumSLHDSANaiveInsecure < Runar::SmartContract
  prop :pubkey, ByteString

  def initialize(pubkey)
    super(pubkey)
    @pubkey = pubkey
  end

  runar_public msg: ByteString, sig: ByteString
  def spend(msg, sig)
    assert verify_slh_dsa_sha2_128s(msg, sig, @pubkey)
  end
end
