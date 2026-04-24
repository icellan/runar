require 'runar'

# Sha256CompressTest -- Verifies SHA-256 compression correctness on-chain.
#
# Local conformance copy of the runar-lang example. Uses a `result` local to
# match the ANF produced by the other formats.

class Sha256CompressTest < Runar::SmartContract
  prop :expected, ByteString, readonly: true

  def initialize(expected)
    super(expected)
    @expected = expected
  end

  runar_public state: ByteString, block: ByteString
  def verify(state, block)
    result = sha256_compress(state, block)
    assert result == @expected
  end
end
