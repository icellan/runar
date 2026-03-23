require 'runar'

class MathDemo < Runar::StatefulSmartContract
  prop :value, Bigint

  def initialize(value)
    super(value)
    @value = value
  end

  runar_public divisor: Bigint
  def divide_by(divisor)
    @value = safediv(@value, divisor)
  end

  runar_public amount: Bigint, fee_bps: Bigint
  def withdraw_with_fee(amount, fee_bps)
    fee = percent_of(amount, fee_bps)
    total = amount + fee
    assert total <= @value
    @value = @value - total
  end

  runar_public lo: Bigint, hi: Bigint
  def clamp_value(lo, hi)
    @value = clamp(@value, lo, hi)
  end

  runar_public
  def normalize
    @value = sign(@value)
  end

  runar_public exp: Bigint
  def exponentiate(exp)
    @value = pow(@value, exp)
  end

  runar_public
  def square_root
    @value = sqrt(@value)
  end

  runar_public other: Bigint
  def reduce_gcd(other)
    @value = gcd(@value, other)
  end

  runar_public numerator: Bigint, denominator: Bigint
  def scale_by_ratio(numerator, denominator)
    @value = mul_div(@value, numerator, denominator)
  end

  runar_public
  def compute_log2
    @value = log2(@value)
  end
end
