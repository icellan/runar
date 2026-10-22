require 'runar'

# Bn254Pairing -- N-314: four-pair BN254 pairing-product check (Go-only codegen).
class Bn254Pairing < Runar::SmartContract
  def initialize
    super()
  end

  runar_public p1: Point, q1x0: Bigint, q1x1: Bigint, q1y0: Bigint, q1y1: Bigint, p2: Point, q2x0: Bigint, q2x1: Bigint, q2y0: Bigint, q2y1: Bigint, p3: Point, q3x0: Bigint, q3x1: Bigint, q3y0: Bigint, q3y1: Bigint, p4: Point, q4x0: Bigint, q4x1: Bigint, q4y0: Bigint, q4y1: Bigint
  def verify(p1, q1x0, q1x1, q1y0, q1y1, p2, q2x0, q2x1, q2y0, q2y1, p3, q3x0, q3x1, q3y0, q3y1, p4, q4x0, q4x1, q4y0, q4y1)
    assert bn254_multi_pairing4(p1, q1x0, q1x1, q1y0, q1y1, p2, q2x0, q2x1, q2y0, q2y1, p3, q3x0, q3x1, q3y0, q3y1, p4, q4x0, q4x1, q4y0, q4y1)
  end
end
