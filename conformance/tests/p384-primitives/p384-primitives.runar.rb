require 'runar'

class P384Primitives < Runar::SmartContract
  prop :expected_point, P384Point

  def initialize(expected_point)
    super(expected_point)
    @expected_point = expected_point
  end

  runar_public k: Bigint, base_point: P384Point
  def verify(k, base_point)
    result = p384_mul(base_point, k)
    assert p384_on_curve(result)
    assert result == @expected_point
  end

  runar_public a: P384Point, b: P384Point
  def verify_add(a, b)
    result = p384_add(a, b)
    assert p384_on_curve(result)
    assert result == @expected_point
  end

  runar_public k: Bigint
  def verify_mul_gen(k)
    result = p384_mul_gen(k)
    assert p384_on_curve(result)
    assert result == @expected_point
  end
end
