require 'runar'

# ShiftOps -- Exercises bitshift operators << and >> on Bigint values.

class ShiftOps < Runar::SmartContract
  prop :a, Bigint, readonly: true

  def initialize(a)
    super(a)
    @a = a
  end

  # Apply left shift and right shift, then check the caller-supplied results.
  runar_public expected_left: Bigint, expected_right: Bigint
  def test_shift(expected_left, expected_right)
    left = @a << 3
    right = @a >> 2
    assert left == expected_left
    assert right == expected_right
  end
end
