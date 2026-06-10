# BSV20Token -- Pay-to-Public-Key-Hash lock for a BSV-20 fungible token.
#
# BSV-20 is a 1sat ordinals token standard where fungible tokens are
# represented as inscriptions on P2PKH UTXOs. The contract logic is standard
# P2PKH -- the token semantics (deploy, mint, transfer) are encoded in the
# inscription envelope and interpreted by indexers, not by the script itself.
#
# BSV-20 Token Lifecycle:
#   1. Deploy   -- Inscribe {"p":"bsv-20","op":"deploy","tick":"RUNAR","max":"21000000"}
#                  onto a UTXO to register a new ticker. First deployer wins.
#   2. Mint     -- Inscribe {"p":"bsv-20","op":"mint","tick":"RUNAR","amt":"1000"}
#                  to claim tokens up to the per-mint limit.
#   3. Transfer -- Inscribe {"p":"bsv-20","op":"transfer","tick":"RUNAR","amt":"50"}
#                  to move tokens between addresses.
#
# The Ruby SDK helpers Runar::SDK::Ordinals.bsv20_deploy / .bsv20_mint /
# .bsv20_transfer build the correct inscription payloads for each operation.

require 'runar'

class BSV20Token < Runar::SmartContract
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
