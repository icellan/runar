require 'runar'

# DataOutputTest -- Exercises add_data_output alongside state continuation.

class DataOutputTest < Runar::StatefulSmartContract
  prop :count, Bigint

  def initialize(count)
    super(count)
    @count = count
  end

  # Increment the counter and attach an arbitrary data output whose bytes
  # are committed to by the state continuation hash.
  runar_public payload: ByteString
  def publish(payload)
    @count = @count + 1
    add_data_output(0, payload)
  end
end
