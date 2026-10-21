# ArraySet -- Ruby port of ArraySet.runar.ts.

require 'runar'

class ArraySet < Runar::StatefulSmartContract
  prop :slots, FixedArray[Bigint, 4], default: [0, 0, 0, 0]

  def initialize
    super()
  end

  runar_public i: Bigint, v: Bigint
  def put(i, v)
    @slots[i] = v
    assert true
  end
end
