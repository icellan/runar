//! Integration tests for the Rúnar proc-macro crate.
//!
//! Verifies that `#[contract]` behaves as documented — specifically, that it
//! strips `#[readonly]` field annotations so the struct compiles under rustc.
//! Methods live in a plain `impl` block with no attribute; `pub fn` marks a
//! public spending entry point.

use runar_lang_macros::contract;

#[contract]
pub struct StripsReadonly {
    #[readonly]
    pub a: i64,
    pub b: Vec<u8>,
}

impl StripsReadonly {
    pub fn plain(&self) -> i64 {
        self.a
    }

    pub fn with_args(&self, x: i64) -> i64 {
        self.a + x
    }
}

#[test]
fn strips_readonly_and_preserves_fields() {
    let c = StripsReadonly { a: 7, b: vec![1, 2, 3] };
    assert_eq!(c.a, 7);
    assert_eq!(c.b, vec![1_u8, 2, 3]);
}

#[test]
fn plain_impl_methods_work() {
    let c = StripsReadonly { a: 11, b: vec![] };
    assert_eq!(c.plain(), 11);
    assert_eq!(c.with_args(4), 15);
}

// --- `#[readonly]` with surrounding whitespace is also stripped --------------

#[contract]
pub struct StripsSpacedReadonly {
    # [readonly]
    pub a: i64,
}

#[test]
fn strips_spaced_readonly_form() {
    let c = StripsSpacedReadonly { a: 99 };
    assert_eq!(c.a, 99);
}
