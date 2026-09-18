//! Integration tests for the Rúnar proc-macro crate.
//!
//! Verifies that `#[contract]` behaves as documented — specifically, that it
//! strips `#[readonly]` field annotations so the struct compiles under rustc.
//! Methods live in a plain `impl` block with no attribute; `pub fn` marks a
//! public spending entry point.

use runar_lang_macros::{contract, stateful_contract};

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

// Native `#[path = "...runar.rs"]` tests compile the contract as Rust. The
// Rúnar compiler materialises `self.add_output` / `add_raw_output` /
// `add_data_output` into Bitcoin Script, but rustc needs those methods on
// the struct. The attribute is the output-recording surface — not a free
// function the contract author has to stub in every test file.
#[contract]
pub struct RecordsOutputs {
    #[readonly]
    pub owner: Vec<u8>,
    pub count: i64,
}

impl RecordsOutputs {
    pub fn bump(&mut self) {
        self.count += 1;
        self.add_output(0, self.count);
        self.add_raw_output(1000, vec![0x51_u8]);
        self.add_data_output(0, vec![1_u8, 2, 3]);
    }
}

#[test]
fn add_output_intrinsics_exist_on_the_generated_struct() {
    let mut c = RecordsOutputs {
        owner: vec![1, 2, 3],
        count: 0,
    };
    c.bump();
    assert_eq!(c.count, 1);
}

// The compiler injects `tx_preimage` for checkPreimage. Native Rust still
// declares it on the struct, but it is not a mutable state slot — parsers
// omit it, and `add_output` must too, or token-ft's
// `add_output(sats, owner, balance, merge_balance)` fails to typecheck.
#[stateful_contract]
pub struct ImplicitPreimage {
    pub owner: Vec<u8>,
    pub balance: i64,
    pub tx_preimage: Vec<u8>,
    pub tx_preimage_backup: Vec<u8>,
}

impl ImplicitPreimage {
    pub fn bump(&mut self) {
        self.add_output(0, self.owner.clone(), self.balance, self.tx_preimage_backup.clone());
    }
}

#[test]
fn add_output_omits_implicit_preimage() {
    let mut c = ImplicitPreimage {
        owner: vec![1],
        balance: 7,
        tx_preimage: vec![],
        tx_preimage_backup: vec![0xbb],
    };
    c.bump();
    assert_eq!(c.balance, 7);
    assert_eq!(c.tx_preimage_backup, vec![0xbb]);
}
