// F-011: an unterminated .runar.move string literal that swallowed the
// assert on the next line in run-to-next-quote tokenizers.
// Every tier must refuse with:
//   unterminated string literal
module Guarded {
    use runar::types::{Int, ByteString};

    struct Guarded {
    }

    public fun unlock(contract: &Guarded, y: Int) {
        let tag: ByteString = "cafe
        assert!(y < 5, 0);
        // ";
        assert!(y >= 0, 0);
    }
}
