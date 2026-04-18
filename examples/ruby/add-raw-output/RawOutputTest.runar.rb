require 'runar'

# RawOutputTest -- Exercises add_raw_output alongside add_output for stateful
# contracts.

class RawOutputTest < Runar::StatefulSmartContract
  prop :count, Bigint

  def initialize(count)
    super(count)
    @count = count
  end

  # Emit a raw output with arbitrary script bytes, then increment the counter
  # and emit the state continuation.
  runar_public script_bytes: ByteString
  def send_to_script(script_bytes)
    add_raw_output(1000, script_bytes)
    @count = @count + 1
    add_output(0, @count)
  end
end
