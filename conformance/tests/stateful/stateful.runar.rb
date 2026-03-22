require 'runar'

class Stateful < Runar::StatefulSmartContract
  prop :count, Bigint
  prop :max_count, Bigint, readonly: true

  def initialize(count, max_count)
    super(count, max_count)
    @count = count
    @max_count = max_count
  end

  runar_public amount: Bigint
  def increment(amount)
    @count = @count + amount
    assert @count <= @max_count
  end

  runar_public
  def reset
    @count = 0
  end
end
