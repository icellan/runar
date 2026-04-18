require 'runar'

# ECUnit -- Unit-style exercises for the secp256k1 EC built-ins.

class ECUnit < Runar::SmartContract
  prop :pub_key, ByteString

  def initialize(pub_key)
    super(pub_key)
    @pub_key = pub_key
  end

  # Exercise ecMulGen, ecOnCurve, ecNegate, ecMul, ecAdd, ecPointX,
  # ecPointY, ecMakePoint, and ecEncodeCompressed.
  runar_public
  def test_ops
    g = ec_mul_gen(1)
    assert ec_on_curve(g)
    neg = ec_negate(g)
    assert ec_on_curve(neg)
    doubled = ec_mul(g, 2)
    assert ec_on_curve(doubled)
    sum = ec_add(g, g)
    assert ec_on_curve(sum)
    x = ec_point_x(g)
    y = ec_point_y(g)
    rebuilt = ec_make_point(x, y)
    assert ec_on_curve(rebuilt)
    compressed = ec_encode_compressed(g)
    assert len(compressed) == 33
    assert true
  end
end
