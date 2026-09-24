// F-011: an unterminated .runar.rs string literal. Rust strings may span
// lines, so on this surface only end of file terminates the scan: the
// literal below never closes. Every tier must refuse with:
//   unterminated string literal
use runar::prelude::*;

#[runar::contract]
pub struct Guarded {
}

impl Guarded {
    pub fn unlock(&self, y: Bigint) {
        let tag: ByteString = "cafe;
        assert!(y < 5);
        assert!(y >= 0);
    }
}
