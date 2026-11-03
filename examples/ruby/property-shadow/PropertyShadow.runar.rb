# PropertyShadow — N-016 conformance fixture. A local that shares a
# property's name never captures `@property`.
require 'runar'

class PropertyShadow < Runar::StatefulSmartContract
  prop :target, Bigint, readonly: true
  prop :count, Bigint

  def initialize(target, count)
    super(target, count)
    @target = target
    @count = count
  end

  runar_public n: Bigint
  def bump(n)
    target = n + 1
    assert target == @target
    count = n
    @count = @count + count
    assert @count > count
  end
end
