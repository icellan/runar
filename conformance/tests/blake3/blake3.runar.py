from runar import SmartContract, ByteString, public, assert_, blake3_compress, blake3_hash

class Blake3Test(SmartContract):
    expected: ByteString

    def __init__(self, expected: ByteString):
        super().__init__(expected)
        self.expected = expected

    @public
    def verify_compress(self, chaining_value: ByteString, block: ByteString):
        result = blake3_compress(chaining_value, block)
        assert_(result == self.expected)

    @public
    def verify_hash(self, message: ByteString):
        result = blake3_hash(message)
        assert_(result == self.expected)
