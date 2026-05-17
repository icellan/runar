require 'runar'

class IntentCurrentBlockHeight < Runar::StatefulSmartContract
  prop :deadline, Bigint, readonly: true
  prop :count, Bigint

  def initialize(deadline, count)
    super(deadline, count)
    @deadline = deadline
    @count = count
  end

  runar_public
  def spend
    h = current_block_height()
    assert h <= @deadline
    @count = @count + 1
  end
end
