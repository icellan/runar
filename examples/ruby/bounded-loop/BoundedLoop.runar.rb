require 'runar'

class BoundedLoop < Runar::SmartContract
  prop :expected_sum, Bigint

  def initialize(expected_sum)
    super(expected_sum)
    @expected_sum = expected_sum
  end

  runar_public start: Bigint
  def verify(start)
    sum = 0
    for i in 0...5
      sum = sum + start + i
    end
    assert sum == @expected_sum
  end
end
