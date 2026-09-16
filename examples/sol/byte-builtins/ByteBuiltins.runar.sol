pragma runar ^0.1.0;

/// ByteBuiltins — Solidity-like port. Executed coverage for five byte-level
/// builtins that no conformance fixture called: split, int2str, reverseBytes,
/// sha256 and ripemd160. See the `.runar.ts` port for the full rationale.
contract ByteBuiltins is SmartContract {
    Sha256 immutable expectedDigest;
    Ripemd160 immutable expectedRipemd;

    constructor(Sha256 _expectedDigest, Ripemd160 _expectedRipemd) {
        expectedDigest = _expectedDigest;
        expectedRipemd = _expectedRipemd;
    }

    /// OP_SPLIT. Binds the right half of `data` at `idx`.
    function checkSplit(ByteString data, int idx, ByteString expectedTail) public {
        ByteString tail = split(data, idx);
        require(tail == expectedTail);
    }

    /// OP_NUM2BIN. Fixed-width little-endian sign-magnitude encoding.
    function checkInt2Str(int value, int width, ByteString expected) public {
        ByteString s = int2str(value, width);
        require(s == expected);
    }

    /// 520 unrolled OP_SPLIT / OP_CAT iterations — one per possible byte.
    function checkReverse(ByteString data, ByteString expected) public {
        ByteString r = reverseBytes(data);
        require(r == expected);
    }

    /// OP_SHA256, against the digest baked into the locking script.
    function checkSha256(ByteString preimage) public {
        Sha256 h = sha256(preimage);
        require(h == this.expectedDigest);
    }

    /// OP_RIPEMD160, against the digest baked into the locking script.
    function checkRipemd(ByteString preimage) public {
        Ripemd160 h = ripemd160(preimage);
        require(h == this.expectedRipemd);
    }
}
