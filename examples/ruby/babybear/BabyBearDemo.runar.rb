require 'runar'

# BabyBearDemo -- Demonstrates Baby Bear prime field arithmetic.
#
# Baby Bear is the prime field used by SP1 STARK proofs (FRI verification).
# Field prime: p = 2^31 - 2^27 + 1 = 2013265921
#
# Four operations:
# - bb_field_add(a, b) -- (a + b) mod p
# - bb_field_sub(a, b) -- (a - b + p) mod p
# - bb_field_mul(a, b) -- (a * b) mod p
# - bb_field_inv(a) -- a^(p-2) mod p (multiplicative inverse via Fermat)

class BabyBearDemo < Runar::SmartContract
  def initialize
    super()
  end

  # Verify field addition.
  runar_public a: Bigint, b: Bigint, expected: Bigint
  def check_add(a, b, expected)
    assert bb_field_add(a, b) == expected
  end

  # Verify field subtraction.
  runar_public a: Bigint, b: Bigint, expected: Bigint
  def check_sub(a, b, expected)
    assert bb_field_sub(a, b) == expected
  end

  # Verify field multiplication.
  runar_public a: Bigint, b: Bigint, expected: Bigint
  def check_mul(a, b, expected)
    assert bb_field_mul(a, b) == expected
  end

  # Verify field inversion: a * inv(a) === 1.
  runar_public a: Bigint
  def check_inv(a)
    inv = bb_field_inv(a)
    assert bb_field_mul(a, inv) == 1
  end

  # Verify subtraction is the inverse of addition: (a + b) - b === a.
  runar_public a: Bigint, b: Bigint
  def check_add_sub_roundtrip(a, b)
    sum = bb_field_add(a, b)
    result = bb_field_sub(sum, b)
    assert result == a
  end

  # Verify distributive law: a * (b + c) === a*b + a*c.
  runar_public a: Bigint, b: Bigint, c: Bigint
  def check_distributive(a, b, c)
    lhs = bb_field_mul(a, bb_field_add(b, c))
    rhs = bb_field_add(bb_field_mul(a, b), bb_field_mul(a, c))
    assert lhs == rhs
  end
end
