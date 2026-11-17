require 'runar'

# TernaryExpression -- see TernaryExpression.runar.ts.
class TernaryExpression < Runar::SmartContract
  prop :threshold, Bigint
  prop :high_tag, ByteString
  prop :low_tag, ByteString

  def initialize(threshold, high_tag, low_tag)
    super(threshold, high_tag, low_tag)
    @threshold = threshold
    @high_tag = high_tag
    @low_tag = low_tag
  end

  runar_public x: Bigint, distance: Bigint, tag: ByteString, band: Bigint
  def check(x, distance, tag, band)
    d = x > @threshold ? x - @threshold : @threshold - x
    assert d == distance

    t = x > @threshold ? @high_tag : @low_tag
    assert t == tag

    b = x > @threshold ? 2 : (x == @threshold ? 1 : 0)
    assert b == band
  end
end
