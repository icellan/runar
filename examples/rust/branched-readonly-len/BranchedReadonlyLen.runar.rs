// EXCLUDED FROM NATIVE RUST COMPILATION
//
// `cargo test` cannot compile this file as Rust, and it is not a missing mock:
// `len` ships in `packages/runar-rs` now, and `len(&scratch)` compiles. Two
// other things do not.
//
//   `self.tag = 0x3030;`  — `tag` is a ByteString, which this tier represents
//   as `Vec<u8>`, and `0x3030` is a Rúnar ByteString LITERAL. rustc:
//   `expected `Vec<u8>`, found integer`. `to_byte_string("3030")` is valid Rust
//   and emits byte-identical script hex, but it is NOT ANF-neutral: the
//   `.runar.rs` parsers lower it to a `toByteString` call node while the other
//   eight surfaces carry a plain ByteString literal, and canonical ANF is
//   compared across all seven tiers. Folding it is a seven-parser change.
//
//   `self.add_output(1000, self.count, self.tag);` — rustc: `no method named
//   `add_output``. The `#[runar::contract]` proc macro in
//   `packages/runar-rs-macros` does not generate the output intrinsics
//   (`add_output`, `add_data_output`, `add_raw_output`) at all. That blocks
//   nine `.runar.rs` contracts, is orthogonal to the byte builtins, and needs
//   an output-recording surface on the mock contract rather than a mock
//   function.
//
// Pinned by `examples/rust/native-exclusions/exclusions_test.rs`. Remove this
// header and the entry there in the same commit that wires the contract up.

use runar::prelude::*;

/// BranchedReadonlyLen -- exercises a state-mutating if/else branched
/// on a read-only intrinsic value (`len`).
#[runar::contract]
pub struct BranchedReadonlyLen {
    pub count: Bigint,
    pub tag: ByteString,
}

impl BranchedReadonlyLen {
    pub fn spend(&mut self, scratch: ByteString) {
        if len(&scratch) > 0 {
            self.count = self.count + 1;
            self.tag = scratch;
        } else {
            self.count = self.count - 1;
            self.tag = 0x3030;
        }
        self.add_output(1000, self.count, self.tag);
    }
}
