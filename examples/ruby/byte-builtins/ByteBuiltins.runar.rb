require 'runar'

# ByteBuiltins -- Ruby port. Executed coverage for four byte-level builtins
# that no conformance fixture called: split, int2str, reverse_bytes and
# sha256. See the `.runar.ts` port for the full rationale, and for why
# ripemd160 is absent.
class ByteBuiltins < Runar::SmartContract
  prop :expected_digest, Sha256, readonly: true

  def initialize(expected_digest)
    super(expected_digest)
    @expected_digest = expected_digest
  end

  # OP_SPLIT. Binds the right half of `data` at `idx`.
  runar_public data: ByteString, idx: Bigint, expected_tail: ByteString
  def check_split(data, idx, expected_tail)
    tail = split(data, idx)
    assert tail == expected_tail
  end

  # OP_NUM2BIN. Fixed-width little-endian sign-magnitude encoding.
  runar_public value: Bigint, width: Bigint, expected: ByteString
  def check_int2_str(value, width, expected)
    s = int2str(value, width)
    assert s == expected
  end

  # 520 unrolled OP_SPLIT / OP_CAT iterations -- one per possible byte.
  runar_public data: ByteString, expected: ByteString
  def check_reverse(data, expected)
    r = reverse_bytes(data)
    assert r == expected
  end

  # OP_SHA256, against the digest baked into the locking script.
  runar_public preimage: ByteString
  def check_sha256(preimage)
    h = sha256(preimage)
    assert h == @expected_digest
  end
end
