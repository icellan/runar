// EXCLUDED FROM NATIVE RUST COMPILATION
//
// `cargo test` cannot compile this file as Rust, and it is not a missing mock:
// `len` ships in `packages/runar-rs` now, and `len(&scratch)` compiles. Wiring
// this contract into a `[[test]]` target with a `#[path]` module include
// produces EXACTLY ONE rustc error — measured, not assumed:
//
//   error[E0599]: no method named `add_output` found for mutable reference
//   `&mut BranchedReadonlyLen` in the current scope
//     --> branched-readonly-len/BranchedReadonlyLen.runar.rs:47:14
//
// The `#[runar::contract]` proc macro in `packages/runar-rs-macros` does not
// generate the output intrinsics (`add_output`, `add_data_output`,
// `add_raw_output`) at all. That blocks nine `.runar.rs` contracts, is
// orthogonal to the byte builtins, and needs an output-recording surface on the
// mock contract rather than a mock function.
//
// The second blocker this header used to name is gone. `self.tag = 0x3030;`
// did not compile — `tag` is a ByteString, `Vec<u8>` in this tier, and rustc
// said `expected `Vec<u8>`, found integer`. It is now spelled
// `to_byte_string("3030")`, which `spec/grammar.md` section 11 defines as the
// ByteStringLiteral production and which all seven tiers now fold to a literal
// in ANF lowering, so it matches the one `expected-ir.json` the runner compares
// every format against.
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
            self.tag = to_byte_string("3030");
        }
        self.add_output(1000, self.count, self.tag);
    }
}
