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

  # Verify shift operators compile and run.
  runar_public
  def test_shift
    left = @a << 2
    right = @a >> 1
    assert left >= 0 || left < 0
    assert right >= 0 || right < 0
    assert true
  end

  # Verify bitwise operators compile and run.
  runar_public
  def test_bitwise
    and_result = @a & @b
    or_result = @a | @b
    xor_result = @a ^ @b
    not_result = ~@a
    assert and_result >= 0 || and_result < 0
    assert or_result >= 0 || or_result < 0
    assert xor_result >= 0 || xor_result < 0
    assert not_result >= 0 || not_result < 0
    assert true
  end
end
