require 'runar'

# P384EncodeNegate -- Ruby port. Executed coverage for p384_negate and
# p384_encode_compressed, neither of which appeared in any fixture.
# See the `.runar.ts` port for the full rationale.
class P384EncodeNegate < Runar::SmartContract
  prop :expected_compressed, ByteString, readonly: true

  def initialize(expected_compressed)
    super(expected_compressed)
    @expected_compressed = expected_compressed
  end

  # (x, y) -> (x, p - y). Guards coordinate canonicity AND the 96-byte width.
  runar_public p: P384Point, expected: P384Point
  def check_negate(p, expected)
    n = p384_negate(p)
    assert n == expected
  end

  # Point -> 49-byte 02/03||x. Guards the width; parity read at a fixed offset.
  runar_public p: P384Point, expected: ByteString
  def check_encode(p, expected)
    e = p384_encode_compressed(p)
    assert e == expected
  end

  # Composed: compressing the negation must flip the prefix and nothing else.
  runar_public p: P384Point
  def check_negate_then_encode(p)
    n = p384_negate(p)
    e = p384_encode_compressed(n)
    assert e == @expected_compressed
  end
end
