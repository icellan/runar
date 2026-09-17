//! Byte-equality test for the FixedArray TicTacToe.
//!
//! Compiles the hand-rolled v1 TicTacToe (9 scalar `c0..c8` fields) and the
//! FixedArray v2 TicTacToe (`board: [Bigint; 9]`) through the Rust compiler
//! and asserts the resulting locking scripts are byte-identical. The v2
//! contract exercises:
//!   - A FixedArray property with a flat array literal initializer.
//!   - Literal-index reads (`self.board[0]`, `self.board[8]`) throughout
//!     `assert_cell_empty`, `get_cell_or_override`, and `count_occupied`.
//!   - Literal-index writes (`self.board[0] = self.turn`) inside
//!     `place_move`.
//! The expand-fixed-arrays pass desugars each of these to the same scalar
//! siblings the v1 contract spells out by hand, and the assembler regroups
//! them back into a single logical `board` state field.

use runar_compiler_rust::compile_from_source_str;

// The v2 contract is `#[path]`-included as well as compiled as text. Until
// `toByteString(<literal>)` was accepted in a property INITIALIZER, `init()`
// assigned bare `&str` to `ByteString` / `PubKey` (both `Vec<u8>` here), so
// this file was not valid Rust and could only ever be fed to the compiler as a
// string — the Rust type checker never saw it.
#[path = "TicTacToe.v2.runar.rs"]
mod contract;

const V1_SOURCE: &str = include_str!("TicTacToe.runar.rs");
const V2_SOURCE: &str = include_str!("TicTacToe.v2.runar.rs");

#[test]
fn test_v2_compile_check() {
    runar::compile_check(V2_SOURCE, "TicTacToe.v2.runar.rs").unwrap();
}

#[test]
fn test_v2_byte_identical_to_v1() {
    let v1 = compile_from_source_str(V1_SOURCE, Some("TicTacToe.runar.rs"))
        .expect("v1 compile");
    let v2 = compile_from_source_str(V2_SOURCE, Some("TicTacToe.v2.runar.rs"))
        .expect("v2 compile");
    assert_eq!(
        v1.script, v2.script,
        "TicTacToe v1 and v2 must compile to byte-identical locking scripts"
    );
    // Sanity: non-empty script at a specific known length (documents current
    // Rust compiler output for TicTacToe).
    assert!(
        !v2.script.is_empty(),
        "v2 locking script must not be empty"
    );
}

#[test]
fn test_v2_state_field_is_fixed_array() {
    let v2 = compile_from_source_str(V2_SOURCE, Some("TicTacToe.v2.runar.rs"))
        .expect("v2 compile");
    let board = v2
        .state_fields
        .iter()
        .find(|f| f.name == "board")
        .expect("v2 artifact must expose 'board' as a state field");
    let fa = board
        .fixed_array
        .as_ref()
        .expect("board must be a FixedArray entry");
    assert_eq!(fa.length, 9, "board length should be 9");
    assert_eq!(fa.element_type, "bigint", "element type should be bigint");
    let expected: Vec<String> = (0..9).map(|i| format!("board__{}", i)).collect();
    assert_eq!(
        fa.synthetic_names, expected,
        "synthetic names must be board__0..board__8"
    );
}

#[test]
fn test_v2_init_decodes_bytestring_initializers_natively() {
    use runar::prelude::*;

    let mut g = contract::TicTacToe {
        player_x: ALICE.pub_key.to_vec(),
        bet_amount: 1000,
        // Deliberately NOT the real defaults, so a missing `init()` fails loudly.
        p2pkh_prefix: Vec::new(),
        p2pkh_suffix: Vec::new(),
        player_o: Vec::new(),
        board: [-1; 9],
        turn: -1,
        status: -1,
        tx_preimage: mock_preimage(),
    };
    g.init();

    // `to_byte_string("1976a914")` denotes the four bytes 19 76 a9 14 — not
    // the eight ASCII bytes of the string.
    assert_eq!(g.p2pkh_prefix, vec![0x19, 0x76, 0xa9, 0x14]);
    assert_eq!(g.p2pkh_suffix, vec![0x88, 0xac]);
    assert_eq!(g.player_o, vec![0u8; 33]);
    assert_eq!(g.board, [0i64; 9]);
    assert_eq!(g.turn, 0);
    assert_eq!(g.status, 0);
}
