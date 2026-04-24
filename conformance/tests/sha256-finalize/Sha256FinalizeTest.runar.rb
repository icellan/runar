require 'runar'

# Sha256FinalizeTest -- Verifies SHA-256 finalize correctness on-chain.
#
# Local conformance copy of the runar-lang example. Uses a `result` local to
# match the ANF produced by the other formats.

class Sha256FinalizeTest < Runar::SmartContract
  prop :expected, ByteString, readonly: true

  def initialize(expected)
    super(expected)
    @expected = expected
  end

  runar_public state: ByteString, remaining: ByteString, msgBitLen: Bigint
  def verify(state, remaining, msgBitLen)
    result = sha256_finalize(state, remaining, msgBitLen)
    assert result == @expected
  end
end
