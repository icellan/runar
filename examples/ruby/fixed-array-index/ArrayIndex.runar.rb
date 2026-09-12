# ArrayIndex -- Ruby port of
# examples/ts/fixed-array-index/ArrayIndex.runar.ts.
#
# Exercises FixedArray[Bigint, 4] together with a RUNTIME index read
# @table[i].

require 'runar'

class ArrayIndex < Runar::SmartContract
  prop :table, FixedArray[Bigint, 4], readonly: true, default: [10, 20, 30, 40]

  def initialize
    super()
  end

  runar_public i: Bigint, expected: Bigint
  def lookup(i, expected)
    assert @table[i] == expected
  end
end
