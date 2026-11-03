# N-244: the sighash marker glued to its flag list on the Ruby surface.
# Only .runar.ts honours the directive; every other surface must refuse ANY
# occurrence of the marker (N-039's rule), not just a word-bounded one, with
# the one shared "not supported by the Ruby surface parser" message.
# Before N-244 every tier read the glued form as prose and compiled ALL|FORKID.
require 'runar'

class Counter < Runar::StatefulSmartContract
  prop :count, Bigint

  def initialize(count)
    super(count)
    @count = count
  end

  # @sighashSINGLE|FORKID
  runar_public
  def increment
    @count += 1
  end
end
