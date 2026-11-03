require 'runar'

# Ledger -- F-352 second witness for the mutable-state shape
# {PubKey, bigint, bigint}.
class Ledger < Runar::StatefulSmartContract
  prop :holder, PubKey
  prop :balance, Bigint
  prop :nonce, Bigint

  def initialize(holder, balance, nonce)
    super(holder, balance, nonce)
    @holder = holder
    @balance = balance
    @nonce = nonce
  end

  runar_public sig: Sig, amount: Bigint
  def spend(sig, amount)
    assert check_sig(sig, @holder)
    assert amount > 0
    assert amount <= @balance
    @balance = @balance - amount
    @nonce = @nonce + 1
  end
end
