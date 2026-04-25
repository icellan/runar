require 'runar'

class BooleanLogic < Runar::SmartContract
  prop :threshold, Bigint

  def initialize(threshold)
    super(threshold)
    @threshold = threshold
  end

  runar_public a: Bigint, b: Bigint, flag: Boolean
  def verify(a, b, flag)
    a_above_threshold = a > @threshold
    b_above_threshold = b > @threshold
    both_above = a_above_threshold && b_above_threshold
    either_above = a_above_threshold || b_above_threshold
    not_flag = !flag
    assert both_above || (either_above && not_flag)
  end
end
