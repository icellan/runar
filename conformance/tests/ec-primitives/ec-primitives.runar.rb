require 'runar'

class ECPrimitives < Runar::SmartContract
  prop :pt, Point

  def initialize(pt)
    super(pt)
    @pt = pt
  end

  runar_public expected_x: Bigint
  def check_x(expected_x)
    assert ec_point_x(@pt) == expected_x
  end

  runar_public expected_y: Bigint
  def check_y(expected_y)
    assert ec_point_y(@pt) == expected_y
  end

  runar_public
  def check_on_curve
    assert ec_on_curve(@pt)
  end

  runar_public expected_neg_y: Bigint
  def check_negate_y(expected_neg_y)
    negated = ec_negate(@pt)
    assert ec_point_y(negated) == expected_neg_y
  end

  runar_public value: Bigint, modulus: Bigint, expected: Bigint
  def check_mod_reduce(value, modulus, expected)
    assert ec_mod_reduce(value, modulus) == expected
  end

  runar_public other: Point, expected_x: Bigint, expected_y: Bigint
  def check_add(other, expected_x, expected_y)
    result = ec_add(@pt, other)
    assert ec_point_x(result) == expected_x
    assert ec_point_y(result) == expected_y
  end

  runar_public scalar: Bigint, expected_x: Bigint, expected_y: Bigint
  def check_mul(scalar, expected_x, expected_y)
    result = ec_mul(@pt, scalar)
    assert ec_point_x(result) == expected_x
    assert ec_point_y(result) == expected_y
  end

  runar_public scalar: Bigint, expected_x: Bigint, expected_y: Bigint
  def check_mul_gen(scalar, expected_x, expected_y)
    result = ec_mul_gen(scalar)
    assert ec_point_x(result) == expected_x
    assert ec_point_y(result) == expected_y
  end

  runar_public x: Bigint, y: Bigint, expected_x: Bigint, expected_y: Bigint
  def check_make_point(x, y, expected_x, expected_y)
    pt = ec_make_point(x, y)
    assert ec_point_x(pt) == expected_x
    assert ec_point_y(pt) == expected_y
  end

  runar_public expected: ByteString
  def check_encode_compressed(expected)
    compressed = ec_encode_compressed(@pt)
    assert compressed == expected
  end

  runar_public
  def check_mul_identity
    result = ec_mul(@pt, 1)
    assert ec_point_x(result) == ec_point_x(@pt)
    assert ec_point_y(result) == ec_point_y(@pt)
  end

  runar_public
  def check_negate_roundtrip
    neg1 = ec_negate(@pt)
    neg2 = ec_negate(neg1)
    assert ec_point_x(neg2) == ec_point_x(@pt)
    assert ec_point_y(neg2) == ec_point_y(@pt)
  end

  runar_public other: Point
  def check_add_on_curve(other)
    result = ec_add(@pt, other)
    assert ec_on_curve(result)
  end

  runar_public scalar: Bigint
  def check_mul_gen_on_curve(scalar)
    result = ec_mul_gen(scalar)
    assert ec_on_curve(result)
  end
end
