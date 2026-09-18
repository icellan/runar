require 'runar'

# LoopShapes -- Ruby port. A NON-ZERO loop start, ascending (R-102).
class LoopShapes < Runar::SmartContract
  prop :target, Bigint

  def initialize(target)
    super(target)
    @target = target
  end

  runar_public seed: Bigint
  def verify(seed)
    acc = seed
    for i in 3...7
      acc = acc + i
    end
    assert acc == @target
  end
end
