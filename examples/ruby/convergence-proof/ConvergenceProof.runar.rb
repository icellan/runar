require 'runar'

class ConvergenceProof < Runar::SmartContract
  prop :r_a, Point
  prop :r_b, Point

  def initialize(r_a, r_b)
    super(r_a, r_b)
    @r_a = r_a
    @r_b = r_b
  end

  runar_public delta_o: Bigint
  def prove_convergence(delta_o)
    assert ec_on_curve(@r_a)
    assert ec_on_curve(@r_b)
    diff = ec_add(@r_a, ec_negate(@r_b))
    expected = ec_mul_gen(delta_o)
    assert ec_point_x(diff) == ec_point_x(expected)
    assert ec_point_y(diff) == ec_point_y(expected)
  end
end
