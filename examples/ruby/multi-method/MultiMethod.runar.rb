require 'runar'

class MultiMethod < Runar::SmartContract
  prop :owner, PubKey
  prop :backup, PubKey

  def initialize(owner, backup)
    super(owner, backup)
    @owner = owner
    @backup = backup
  end

  params a: Bigint, b: Bigint
  def compute_threshold(a, b)
    return a * b + 1
  end

  runar_public sig: Sig, amount: Bigint
  def spend_with_owner(sig, amount)
    threshold = compute_threshold(amount, 2)
    assert threshold > 10
    assert check_sig(sig, @owner)
  end

  runar_public sig: Sig
  def spend_with_backup(sig)
    assert check_sig(sig, @backup)
  end
end
