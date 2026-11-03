# N-491: TS surface-parser operand anchor parity. A boolean identifier as the right operand of `<`.
# TS must anchor the refusal on this surface exactly where it does on .runar.ts
# (see n491-operand-anchor-surface-matrix.test.ts).
require 'runar'

class Anchor < Runar::SmartContract
  prop :t, Bigint

  def initialize(t)
    super(t)
    @t = t
  end

  runar_public flag: Boolean, x: Bigint
  def go(flag, x)
    assert(x < flag)
  end
end
