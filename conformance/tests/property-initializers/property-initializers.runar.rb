require 'runar'

class PropertyInitializers < Runar::StatefulSmartContract
  prop :count,     Bigint,  default: 0
  prop :max_count, Bigint,  readonly: true
  prop :active,    Boolean, readonly: true, default: true

  def initialize(max_count)
    super(max_count)
    @max_count = max_count
  end

  runar_public amount: Bigint
  def increment(amount)
    assert @active
    @count = @count + amount
    assert @count <= @max_count
  end

  runar_public
  def reset
    @count = 0
  end
end
