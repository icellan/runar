require 'runar'

# BitwiseOps -- Demonstrates bitwise and shift operators on Bigint values.

class BitwiseOps < Runar::SmartContract
  prop :a, Bigint, readonly: true
  prop :b, Bigint, readonly: true

  def initialize(a, b)
    super(a, b)
    @a = a
    @b = b
  end

  # Check the caller-supplied shift results.
  runar_public expected_left: Bigint, expected_right: Bigint
  def test_shift(expected_left, expected_right)
    left = @a << 2
    right = @a >> 1
    assert left == expected_left
    assert right == expected_right
  end

  # Check the caller-supplied AND/OR/XOR results; ~ is checked by double
  # inversion and De Morgan's law (see the TS source for why).
  runar_public expected_and: Bigint, expected_or: Bigint, expected_xor: Bigint
  def test_bitwise(expected_and, expected_or, expected_xor)
    and_result = @a & @b
    or_result = @a | @b
    xor_result = @a ^ @b
    not_result = ~@a
    assert and_result == expected_and
    assert or_result == expected_or
    assert xor_result == expected_xor
    assert ~not_result == @a
    assert ~(@a | @b) == (not_result & ~@b)
  end
end
