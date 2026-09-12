use runar::prelude::*;

/// ArrayIndex -- Rust DSL port of
/// `examples/ts/fixed-array-index/ArrayIndex.runar.ts`.
///
/// Exercises `[Bigint; 4]` together with a RUNTIME index read `self.table[i]`.
/// The array literal lives in the private `init()` method, which is how the Go
/// and Rust DSL surfaces spell a property initializer.
#[runar::contract]
pub struct ArrayIndex {
    #[readonly]
    pub table: [Bigint; 4],
}

impl ArrayIndex {
    pub fn init(&mut self) {
        self.table = [10, 20, 30, 40];
    }

    pub fn lookup(&self, i: Bigint, expected: Bigint) {
        assert!(self.table[i] == expected);
    }
}
