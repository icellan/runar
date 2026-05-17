require 'runar'

class IntentPrevOutputScript < Runar::StatefulSmartContract
  prop :expected_hash, ByteString, readonly: true
  prop :count, Bigint

  def initialize(expected_hash, count)
    super(expected_hash, count)
    @expected_hash = expected_hash
    @count = count
  end

  runar_public
  def bind
    s = extract_prev_output_script(0, @expected_hash)
    assert len(s) > 0
    @count = @count + 1
  end
end
