use runar::prelude::*;

#[runar::contract]
struct Blake3Test {
    #[readonly]
    expected: ByteString,
}

#[runar::methods(Blake3Test)]
impl Blake3Test {
    #[public]
    fn verify_compress(&self, chaining_value: &ByteString, block: &ByteString) {
        let result = blake3_compress(chaining_value, block);
        assert!(result == self.expected);
    }

    #[public]
    fn verify_hash(&self, message: &ByteString) {
        let result = blake3_hash(message);
        assert!(result == self.expected);
    }
}
