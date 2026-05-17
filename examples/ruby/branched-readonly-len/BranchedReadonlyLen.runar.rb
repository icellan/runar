require 'runar'

class BranchedReadonlyLen < Runar::StatefulSmartContract
  prop :count, Bigint
  prop :tag, ByteString

  def initialize(count, tag)
    super(count, tag)
    @count = count
    @tag = tag
  end

  runar_public scratch: ByteString
  def spend(scratch)
    if len(scratch) > 0
      @count = @count + 1
      @tag = scratch
    else
      @count = @count - 1
      @tag = '3030'
    end
    add_output(1000, @count, @tag)
  end
end
