# N-053: a .runar.rb statement that is a bare symbol. Every tier's statement
# dispatcher used to skip the unknown token and compile the method as if the
# line were absent. Every tier must refuse it (the TS reference reports
# "Unsupported statement starting with 'foo'").
require 'runar'

class N183 < Runar::SmartContract
  prop :t, Bigint

  def initialize(t)
    super(t)
    @t = t
  end

  runar_public x: Bigint
  def unlock(x)
    :foo
    assert x == @t
  end
end
