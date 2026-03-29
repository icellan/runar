pragma runar ^0.1.0;

contract Blake3Test is SmartContract {
    ByteString immutable expected;

    constructor(ByteString _expected) {
        expected = _expected;
    }

    function verifyCompress(ByteString chainingValue, ByteString block) public {
        ByteString result = blake3Compress(chainingValue, block);
        require(result == this.expected);
    }

    function verifyHash(ByteString message) public {
        ByteString result = blake3Hash(message);
        require(result == this.expected);
    }
}
