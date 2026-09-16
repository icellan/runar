"""ByteBuiltins -- Python port. Executed coverage for four byte-level builtins
that no conformance fixture called: split, int_to_str, reverse_bytes and
sha256. See the `.runar.ts` port for the full rationale, and for why ripemd160
is absent.
"""

from runar import (
    SmartContract,
    ByteString,
    Bigint,
    Sha256,
    public,
    assert_,
    sha256,
    split,
    int_to_str,
    reverse_bytes,
)


class ByteBuiltins(SmartContract):
    expected_digest: Sha256

    def __init__(self, expected_digest: Sha256):
        super().__init__(expected_digest)
        self.expected_digest = expected_digest

    @public
    def check_split(self, data: ByteString, idx: Bigint, expected_tail: ByteString):
        """OP_SPLIT. Binds the right half of `data` at `idx`."""
        tail: ByteString = split(data, idx)
        assert_(tail == expected_tail)

    @public
    def check_int2_str(self, value: Bigint, width: Bigint, expected: ByteString):
        """OP_NUM2BIN. Fixed-width little-endian sign-magnitude encoding."""
        s: ByteString = int_to_str(value, width)
        assert_(s == expected)

    @public
    def check_reverse(self, data: ByteString, expected: ByteString):
        """520 unrolled OP_SPLIT / OP_CAT iterations -- one per possible byte."""
        r: ByteString = reverse_bytes(data)
        assert_(r == expected)

    @public
    def check_sha256(self, preimage: ByteString):
        """OP_SHA256, against the digest baked into the locking script."""
        h: Sha256 = sha256(preimage)
        assert_(h == self.expected_digest)
