require 'runar'

# StatefulTerminalLoop -- a TERMINAL stateful method (no state write, so no
# injected continuation assert) whose bounded loop of asserts is followed by a
# final assert, which is the script result. Without it the method is refused
# in every tier (conformance/negatives N547).
class StatefulTerminalLoop < Runar::StatefulSmartContract
  prop :floor, Bigint
  prop :count, Bigint

  def initialize(floor, count)
    super(floor, count)
    @floor = floor
    @count = count
  end

  runar_public x: Bigint
  def close(x)
    for i in 0...2
      assert x >= @floor + i
    end
    assert x > @count
  end
end
