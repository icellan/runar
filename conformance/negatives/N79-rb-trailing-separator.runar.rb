# F-026: Ruby refuses `10_` ("trailing '_' in number"). Pre-fix every tier
# read it as 10. Every tier must refuse with:
#   invalid Ruby integer literal '10_'
require 'runar'

class T < Runar::SmartContract
  prop :target, Bigint

  def initialize(target)
    super(target)
    @target = target
  end

  runar_public a: Bigint
  def verify(a)
    assert a > 10_
  end
end
