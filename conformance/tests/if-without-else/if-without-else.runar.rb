require 'runar'

class IfWithoutElse < Runar::SmartContract
  prop :threshold, Bigint

  def initialize(threshold)
    super(threshold)
    @threshold = threshold
  end

  runar_public a: Bigint, b: Bigint
  def check(a, b)
    count = 0
    if a > @threshold
      count = count + 1
    end
    if b > @threshold
      count = count + 1
    end
    assert count > 0
  end
end
