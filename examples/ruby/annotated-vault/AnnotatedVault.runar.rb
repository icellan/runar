require 'runar'

# AnnotatedVault -- N-044 conformance fixture: a mutable variable-length
# ByteString state field (memo) BEFORE a mutable PubKey (owner). Anyone may
# replace the memo; only the owner may withdraw.
class AnnotatedVault < Runar::StatefulSmartContract
  prop :memo, ByteString
  prop :owner, PubKey
  prop :balance, Bigint

  def initialize(memo, owner, balance)
    super(memo, owner, balance)
    @memo = memo
    @owner = owner
    @balance = balance
  end

  # Replace the memo. Anyone can call this method.
  runar_public next_memo: ByteString
  def annotate(next_memo)
    @memo = next_memo
  end

  # Only the owner may spend.
  runar_public sig: Sig
  def withdraw(sig)
    assert check_sig(sig, @owner)
  end
end
