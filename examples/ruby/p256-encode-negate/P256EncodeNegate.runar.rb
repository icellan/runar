require 'runar'

# P256EncodeNegate -- Ruby port. Executed coverage for p256_negate and
# p256_encode_compressed, neither of which appeared in any fixture.
# See the `.runar.ts` port for the full rationale.
class P256EncodeNegate < Runar::SmartContract
  prop :expected_compressed, ByteString, readonly: true

  def initialize(expected_compressed)
    super(expected_compressed)
    @expected_compressed = expected_compressed
  end

  # (x, y) -> (x, p - y). Guards coordinate canonicity AND the 64-byte width.
  runar_public p: P256Point, expected: P256Point
  def check_negate(p, expected)
    n = p256_negate(p)
    assert n == expected
  end

  # Point -> 33-byte 02/03||x. Guards the width; parity read at a fixed offset.
  runar_public p: P256Point, expected: ByteString
  def check_encode(p, expected)
    e = p256_encode_compressed(p)
    assert e == expected
  end

  # Composed: compressing the negation must flip the prefix and nothing else.
  runar_public p: P256Point
  def check_negate_then_encode(p)
    n = p256_negate(p)
    e = p256_encode_compressed(n)
    assert e == @expected_compressed
  end
end
