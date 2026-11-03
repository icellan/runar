require 'runar'

# EcChainedRewrite -- two EC optimizer rules firing on one binding (F-115):
# ecAdd(ecMulGen(n - 7), ecMulGen(7)) -> ecMulGen(0) -> the point at infinity.
class EcChainedRewrite < Runar::SmartContract
  def initialize
    super()
  end

  runar_public p: Point
  def unlock(p)
    r = ec_add(ec_mul_gen(115792089237316195423570985008687907852837564279074904382605163141518161494330), ec_mul_gen(7))
    assert r == p
  end
end
