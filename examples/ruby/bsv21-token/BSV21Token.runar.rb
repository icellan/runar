# BSV21Token -- Pay-to-Public-Key-Hash lock for a BSV-21 fungible token.
#
# BSV-21 (v2) is an improvement over BSV-20 that uses ID-based tokens instead
# of tick-based. The token ID is derived from the deploy transaction
# (<txid>_<vout>), eliminating ticker squatting and enabling admin-controlled
# distribution.
#
# BSV-21 Token Lifecycle:
#   1. Deploy+Mint -- A single inscription deploys the token and mints the
#                     initial supply in one atomic operation. The token ID is
#                     the outpoint of the output containing this inscription.
#   2. Transfer    -- Inscribe a transfer JSON referencing the token ID and
#                     amount.
#
# The Ruby SDK helpers Runar::SDK::Ordinals.bsv21_deploy_mint /
# .bsv21_transfer build the correct inscription payloads for each operation.

require 'runar'

class BSV21Token < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  # Unlock by proving ownership of the private key corresponding to pub_key_hash.
  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end
