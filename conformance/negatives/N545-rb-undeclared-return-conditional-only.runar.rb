# N-511 (review follow-up): the .runar.rb spelling of N544 (Ruby spells no
# return type). Compiled in all seven tiers, the missing path evaluating to
# OP_0. Every tier refuses:
#   Method 'helper' returns a value on some paths but not on every path
require 'runar'

class Probe < Runar::SmartContract
  prop :target, Bigint

  def initialize(target)
    super(target)
    @target = target
  end

  params x: Bigint
  def helper(x)
    if x > 0
      return x
    end
  end

  runar_public a: Bigint
  def verify(a)
    assert helper(a) == @target
  end
end
