# ArrayWrite -- Ruby port of
# examples/ts/fixed-array-write/ArrayWrite.runar.ts.

require 'runar'

class ArrayWrite < Runar::StatefulSmartContract
  prop :table, FixedArray[Bigint, 4], default: [0, 0, 0, 0]

  def initialize
    super()
  end

  runar_public i: Bigint
  def bump(i)
    @table[i] = @table[i] + 1
    assert true
  end
end
