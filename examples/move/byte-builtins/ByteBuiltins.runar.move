// ByteBuiltins -- Move-style port. Executed coverage for five byte-level
// builtins that no conformance fixture called: split, int2str, reverseBytes,
// sha256 and ripemd160. See the `.runar.ts` port for the full rationale.
module ByteBuiltins {
    use runar::types::{ByteString, Int, Sha256, Ripemd160};
    use runar::crypto::{sha256, ripemd160};
    use runar::bytes::{split, int2str, reverseBytes};

    struct ByteBuiltins {
        expectedDigest: Sha256,
        expectedRipemd: Ripemd160,
    }

    /// OP_SPLIT. Binds the right half of `data` at `idx`.
    public fun checkSplit(contract: &ByteBuiltins, data: ByteString, idx: Int, expectedTail: ByteString) {
        let tail: ByteString = split(data, idx);
        assert!(tail == expectedTail, 0);
    }

    /// OP_NUM2BIN. Fixed-width little-endian sign-magnitude encoding.
    public fun checkInt2Str(contract: &ByteBuiltins, value: Int, width: Int, expected: ByteString) {
        let s: ByteString = int2str(value, width);
        assert!(s == expected, 0);
    }

    /// 520 unrolled OP_SPLIT / OP_CAT iterations -- one per possible byte.
    public fun checkReverse(contract: &ByteBuiltins, data: ByteString, expected: ByteString) {
        let r: ByteString = reverseBytes(data);
        assert!(r == expected, 0);
    }

    /// OP_SHA256, against the digest baked into the locking script.
    public fun checkSha256(contract: &ByteBuiltins, preimage: ByteString) {
        let h: Sha256 = sha256(preimage);
        assert!(h == contract.expectedDigest, 0);
    }

    /// OP_RIPEMD160, against the digest baked into the locking script.
    public fun checkRipemd(contract: &ByteBuiltins, preimage: ByteString) {
        let h: Ripemd160 = ripemd160(preimage);
        assert!(h == contract.expectedRipemd, 0);
    }
}
