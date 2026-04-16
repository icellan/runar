require 'runar'

class P256Primitives < Runar::SmartContract
  prop :expected_point, P256Point

  def initialize(expected_point)
    super(expected_point)
    @expected_point = expected_point
  end

  runar_public k: Bigint, base_point: P256Point
  def verify(k, base_point)
    result = p256_mul(base_point, k)
    assert p256_on_curve(result)
    assert result == @expected_point
  end

  runar_public a: P256Point, b: P256Point
  def verify_add(a, b)
    result = p256_add(a, b)
    assert p256_on_curve(result)
    assert result == @expected_point
  end

  runar_public k: Bigint
  def verify_mul_gen(k)
    result = p256_mul_gen(k)
    assert p256_on_curve(result)
    assert result == @expected_point
  end
end
