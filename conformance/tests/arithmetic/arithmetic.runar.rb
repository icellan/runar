require 'runar'

class Arithmetic < Runar::SmartContract
  prop :target, Bigint

  def initialize(target)
    super(target)
    @target = target
  end

  runar_public a: Bigint, b: Bigint
  def verify(a, b)
    sum = a + b
    diff = a - b
    prod = a * b
    quot = a / b
    result = sum + diff + prod + quot
    assert result == @target
  end
end
