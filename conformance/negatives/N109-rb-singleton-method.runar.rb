# N-050 (StaticSiphon): a static / class-level method is not a contract method.
# Pre-fix, `requirePositive` became a PUBLIC spending entry point in several
# tiers — a path anyone satisfies with `<1>` and no signature (@bsv/sdk
# Spend.validate accepted it against the TS artifact). Every tier must refuse:
#   static methods are not allowed in Rúnar contracts; method 'require_positive' is declared static
# Shape: `def self.require_positive` on the Ruby surface.
require 'runar'

class Vault < Runar::SmartContract
  prop :owner, PubKey

  def initialize(owner)
    super(owner)
    @owner = owner
  end

  runar_public amount: Bigint
  def self.require_positive(amount)
    assert amount > 0
  end

  runar_public sig: Sig
  def withdraw(sig)
    assert check_sig(sig, @owner)
  end
end
