# Grid2x2 -- minimal nested FixedArray[FixedArray[Bigint, 2], 2] acceptance
# contract for the Ruby port of the FixedArray feature.
#
# The expand-fixed-arrays pass desugars +grid+ into four scalar siblings
# +grid__0__0+, +grid__0__1+, +grid__1__0+, +grid__1__1+.  Pass 3b attaches a
# two-element +synthetic_array_chain+ to each leaf, and the iterative
# regrouper in the artifact assembler rebuilds a single nested FixedArray
# state field so the SDK exposes +state.grid+ as a real nested array matching
# the declared shape.
#
# Runtime indexing into a nested FixedArray is still a compile error for the
# v1 spike, so each write is split into its own literal-index method.

require 'runar'

class Grid2x2 < Runar::StatefulSmartContract
  prop :grid, FixedArray[FixedArray[Bigint, 2], 2], default: [[0, 0], [0, 0]]

  def initialize
    super()
  end

  runar_public v: Bigint
  def set00(v)
    @grid[0][0] = v
    assert true
  end

  runar_public v: Bigint
  def set01(v)
    @grid[0][1] = v
    assert true
  end

  runar_public v: Bigint
  def set10(v)
    @grid[1][0] = v
    assert true
  end

  runar_public v: Bigint
  def set11(v)
    @grid[1][1] = v
    assert true
  end

  runar_public
  def read00
    assert @grid[0][0] == @grid[0][0]
  end
end
