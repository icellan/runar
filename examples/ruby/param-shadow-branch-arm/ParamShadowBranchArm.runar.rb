# ParamShadowBranchArm — N-007 conformance fixture. The parameter `count`
# shares the property's name; inside the `if` arm it is still the parameter,
# and `@count` is the property.
require 'runar'

class ParamShadowBranchArm < Runar::StatefulSmartContract
  prop :count, Bigint

  def initialize(count)
    super(count)
    @count = count
  end

  runar_public count: Bigint, flag: Boolean
  def set(count, flag)
    if flag
      assert count == 5
    end
    @count = count
  end
end
