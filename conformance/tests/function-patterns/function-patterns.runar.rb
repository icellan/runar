require 'runar'

class FunctionPatterns < Runar::StatefulSmartContract
  prop :owner, PubKey, readonly: true
  prop :balance, Bigint

  def initialize(owner, balance)
    super(owner, balance)
    @owner = owner
    @balance = balance
  end

  runar_public sig: Sig, amount: Bigint
  def deposit(sig, amount)
    _require_owner(sig)
    assert amount > 0
    @balance = @balance + amount
  end

  runar_public sig: Sig, amount: Bigint, fee_bps: Bigint
  def withdraw(sig, amount, fee_bps)
    _require_owner(sig)
    assert amount > 0
    fee = _compute_fee(amount, fee_bps)
    total = amount + fee
    assert total <= @balance
    @balance = @balance - total
  end

  runar_public sig: Sig, numerator: Bigint, denominator: Bigint
  def scale(sig, numerator, denominator)
    _require_owner(sig)
    @balance = _scale_value(@balance, numerator, denominator)
  end

  runar_public sig: Sig, lo: Bigint, hi: Bigint, step: Bigint
  def normalize(sig, lo, hi, step)
    _require_owner(sig)
    clamped = _clamp_value(@balance, lo, hi)
    @balance = _round_down(clamped, step)
  end

  private

  params sig: Sig
  def _require_owner(sig)
    assert check_sig(sig, @owner)
  end

  params amount: Bigint, fee_bps: Bigint
  def _compute_fee(amount, fee_bps)
    percent_of(amount, fee_bps)
  end

  params value: Bigint, numerator: Bigint, denominator: Bigint
  def _scale_value(value, numerator, denominator)
    mul_div(value, numerator, denominator)
  end

  params value: Bigint, lo: Bigint, hi: Bigint
  def _clamp_value(value, lo, hi)
    clamp(value, lo, hi)
  end

  params value: Bigint, step: Bigint
  def _round_down(value, step)
    remainder = safemod(value, step)
    value - remainder
  end
end
