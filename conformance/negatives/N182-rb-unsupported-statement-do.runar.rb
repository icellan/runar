# N-053: a .runar.rb statement that starts with a keyword no statement or
# expression starts with. Every tier's statement dispatcher used to skip the
# unknown token (`do`) and parse the rest of the line as a statement of its
# own, so the program compiled as if `do` were not there. Every tier must
# refuse it:
#   Unsupported statement starting with 'do'
require 'runar'

class N182 < Runar::SmartContract
  prop :t, Bigint

  def initialize(t)
    super(t)
    @t = t
  end

  runar_public x: Bigint
  def unlock(x)
    do assert x == @t
    assert true
  end
end
