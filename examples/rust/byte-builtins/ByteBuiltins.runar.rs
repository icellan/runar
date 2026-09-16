use runar::prelude::*;

/// ByteBuiltins -- Rust DSL port. Executed coverage for five byte-level
/// builtins that no conformance fixture called: split, int2str, reverse_bytes,
/// sha256 and ripemd160. See the `.runar.ts` port for the full rationale.
#[runar::contract]
pub struct ByteBuiltins {
    #[readonly]
    pub expectedDigest: Sha256,
    #[readonly]
    pub expectedRipemd: Ripemd160,
}

impl ByteBuiltins {
    /// OP_SPLIT. Binds the right half of `data` at `idx`.
    pub fn checkSplit(&self, data: &ByteString, idx: Int, expectedTail: &ByteString) {
        let tail: ByteString = split(data, idx);
        assert!(tail == expectedTail);
    }

    /// OP_NUM2BIN. Fixed-width little-endian sign-magnitude encoding.
    pub fn checkInt2Str(&self, value: Int, width: Int, expected: &ByteString) {
        let s: ByteString = int2str(value, width);
        assert!(s == expected);
    }

    /// 520 unrolled OP_SPLIT / OP_CAT iterations -- one per possible byte.
    pub fn checkReverse(&self, data: &ByteString, expected: &ByteString) {
        let r: ByteString = reverseBytes(data);
        assert!(r == expected);
    }

    /// OP_SHA256, against the digest baked into the locking script.
    pub fn checkSha256(&self, preimage: &ByteString) {
        let h: Sha256 = sha256(preimage);
        assert!(h == self.expectedDigest);
    }

    /// OP_RIPEMD160, against the digest baked into the locking script.
    pub fn checkRipemd(&self, preimage: &ByteString) {
        let h: Ripemd160 = ripemd160(preimage);
        assert!(h == self.expectedRipemd);
    }
}
