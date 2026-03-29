module Blake3Test {
    use runar::types::{ByteString};
    use runar::crypto::{blake3Compress, blake3Hash};

    struct Blake3Test {
        expected: ByteString,
    }

    public fun verify_compress(contract: &Blake3Test, chaining_value: ByteString, block: ByteString) {
        let result: ByteString = blake3Compress(chaining_value, block);
        assert!(result == contract.expected, 0);
    }

    public fun verify_hash(contract: &Blake3Test, message: ByteString) {
        let result: ByteString = blake3Hash(message);
        assert!(result == contract.expected, 0);
    }
}
