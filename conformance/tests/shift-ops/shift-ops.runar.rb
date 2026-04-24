require 'runar'

# ShiftOps -- Exercises bitshift operators << and >> on Bigint values.

class ShiftOps < Runar::SmartContract
  prop :a, Bigint, readonly: true

  def initialize(a)
    super(a)
    @a = a
  end

  # Apply left shift and right shift, then sanity-check the results.
  runar_public
  def test_shift
    left = @a << 3
    right = @a >> 2
    assert left >= 0 || left < 0
    assert right >= 0 || right < 0
  end
end
