require 'runar'

# CurrentBlockHeightHelperTernary -- see CurrentBlockHeightHelperTernary.runar.ts.
class CurrentBlockHeightHelperTernary < Runar::StatefulSmartContract
  prop :start, Bigint, readonly: true
  prop :count, Bigint

  def initialize(start, count)
    super(start, count)
    @start = start
    @count = count
  end

  def height
    return current_block_height()
  end

  runar_public
  def spend
    assert height() >= @start
    h = @count > 5 ? current_block_height() : @start
    assert h >= @start
    @count = @count + 1
  end
end
