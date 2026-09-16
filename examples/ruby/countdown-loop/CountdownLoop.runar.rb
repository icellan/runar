require 'runar'

# CountdownLoop -- Ruby port. `step = -1` (R-102).
#
# Ruby's range operators only ever ascend -- `(5..2)` is empty -- so the
# countdown is spelled `5.downto(2)`, the language's own countdown verb. It
# returns an Enumerator and `for x in enum` is valid Ruby over one, so the
# header means in Ruby exactly what it compiles to here: 5, 4, 3, 2. Before
# this fixture the surface had no descending spelling at all (N-130).
# See CountdownLoop.runar.ts.
class CountdownLoop < Runar::SmartContract
  prop :target, Bigint

  def initialize(target)
    super(target)
    @target = target
  end

  runar_public seed: Bigint
  def verify(seed)
    acc = seed
    for i in 5.downto(2)
      acc = acc + i
    end
    assert acc == @target
  end
end
