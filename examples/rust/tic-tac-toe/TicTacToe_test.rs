//! Native-Rust tests for `TicTacToe.runar.rs`.
//!
//! This file used to define an inline MIRROR of the contract — a hand-copied
//! struct and impl — because the contract itself was not valid Rust: its
//! `init()` assigned bare `&str` literals to `ByteString` / `PubKey` fields,
//! both of which are `Vec<u8>` in this tier. `to_byte_string(...)` is the only
//! spelling that is both valid Rust and valid Rúnar, and until the validator
//! accepted it in a property INITIALIZER (it already folded in every
//! expression position) it was refused with "initializer must be a literal
//! value".
//!
//! The mirror was not merely redundant, it was WRONG: it initialized
//! `p2pkh_prefix` to `b"1976a914".to_vec()` — the eight ASCII bytes of the
//! string — where the contract's `to_byte_string("1976a914")` denotes the four
//! bytes `19 76 a9 14`. Every payout assertion below now runs against the
//! contract's real bytes.
//!
//! The contract is `#[path]`-included, so these tests execute the SHIPPED
//! code. An edit to `TicTacToe.runar.rs` now fails this file.

#[path = "TicTacToe.runar.rs"]
mod contract;

use contract::TicTacToe;
use runar::prelude::*;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn player_x() -> PubKey { ALICE.pub_key.to_vec() }
fn player_o() -> PubKey { BOB.pub_key.to_vec() }
fn player_x_sig() -> Sig { ALICE.sign_test_message() }
fn player_o_sig() -> Sig { BOB.sign_test_message() }
fn zero_pk() -> PubKey { vec![0u8; 33] }

/// Build a game the way the contract does: the constructor supplies only the
/// readonly `player_x` / `bet_amount`, and `init()` — the contract's OWN
/// property initializers — supplies everything else. Nothing here restates a
/// default the contract already declares, so a changed initializer changes
/// these tests.
fn new_game() -> TicTacToe {
    let mut g = TicTacToe {
        player_x: player_x(),
        bet_amount: 1000,
        // Every field below is overwritten by `init()`; these are placeholders
        // that the struct literal requires, deliberately NOT the real defaults
        // so that a missing `init()` call fails loudly rather than passing.
        p2pkh_prefix: Vec::new(),
        p2pkh_suffix: Vec::new(),
        player_o: Vec::new(),
        c0: -1, c1: -1, c2: -1,
        c3: -1, c4: -1, c5: -1,
        c6: -1, c7: -1, c8: -1,
        turn: -1,
        status: -1,
        tx_preimage: mock_preimage(),
    };
    g.init();
    g
}

/// The contract's initializers are the bytes the payout assertions hash, so
/// pin them here rather than only exercising them indirectly. The old inline
/// mirror had `b"1976a914".to_vec()` — the ASCII of the string, eight bytes —
/// which is NOT what `to_byte_string("1976a914")` denotes.
#[test]
fn test_init_decodes_bytestring_initializers() {
    let g = new_game();
    assert_eq!(g.p2pkh_prefix, vec![0x19, 0x76, 0xa9, 0x14]);
    assert_eq!(g.p2pkh_suffix, vec![0x88, 0xac]);
    assert_eq!(g.player_o, zero_pk());
    assert_eq!(g.turn, 0);
    assert_eq!(g.status, 0);
}

fn playing_game() -> TicTacToe {
    let mut g = new_game();
    g.player_o = player_o();
    g.status = 1;
    g.turn = 1;
    g
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_join() {
    let mut game = new_game();
    game.join(player_o(), &player_o_sig());
    assert_eq!(game.player_o, player_o());
    assert_eq!(game.status, 1);
    assert_eq!(game.turn, 1);
}

#[test]
#[should_panic]
fn test_join_rejects_when_already_playing() {
    let mut game = playing_game();
    game.join(player_o(), &player_o_sig());
}

#[test]
fn test_move_player_x() {
    let mut game = playing_game();
    game.move_piece(0, player_x(), &player_x_sig());
    assert_eq!(game.c0, 1);
    assert_eq!(game.turn, 2);
}

#[test]
fn test_move_player_o() {
    let mut game = playing_game();
    game.turn = 2;
    game.move_piece(4, player_o(), &player_o_sig());
    assert_eq!(game.c4, 2);
    assert_eq!(game.turn, 1);
}

#[test]
#[should_panic]
fn test_move_rejects_occupied_cell() {
    let mut game = playing_game();
    game.c0 = 1;
    game.move_piece(0, player_x(), &player_x_sig());
}

#[test]
#[should_panic]
fn test_move_rejects_when_not_playing() {
    let mut game = new_game();
    game.move_piece(0, player_x(), &player_x_sig());
}

#[test]
#[should_panic]
fn test_move_rejects_wrong_player() {
    let mut game = playing_game(); // turn=1 (player X's turn)
    game.move_piece(0, player_o(), &player_o_sig());
}

#[test]
fn test_multiple_moves() {
    let mut game = playing_game();

    game.move_piece(0, player_x(), &player_x_sig());
    assert_eq!(game.c0, 1);
    assert_eq!(game.turn, 2);

    game.move_piece(4, player_o(), &player_o_sig());
    assert_eq!(game.c4, 2);
    assert_eq!(game.turn, 1);

    game.move_piece(8, player_x(), &player_x_sig());
    assert_eq!(game.c8, 1);
    assert_eq!(game.turn, 2);
}

#[test]
fn test_full_game_join_and_moves() {
    let mut game = new_game();

    // Join
    game.join(player_o(), &player_o_sig());
    assert_eq!(game.status, 1);

    // X@0, O@3, X@1, O@4 — set up X to win with position 2 (top row)
    game.move_piece(0, player_x(), &player_x_sig());
    assert_eq!(game.c0, 1);

    game.move_piece(3, player_o(), &player_o_sig());
    assert_eq!(game.c3, 2);

    game.move_piece(1, player_x(), &player_x_sig());
    assert_eq!(game.c1, 1);

    game.move_piece(4, player_o(), &player_o_sig());
    assert_eq!(game.c4, 2);
    assert_eq!(game.turn, 1); // X's turn

    // X plays position 2 to win top row (0,1,2).
    // Pre-compute the payout hash so extract_output_hash returns the right value.
    let total_payout = game.bet_amount * 2;
    let payout = cat(&cat(&cat(&num2bin(&total_payout, 8), &game.p2pkh_prefix), &hash160(&player_x())), &game.p2pkh_suffix);
    game.tx_preimage = hash256(&payout);
    game.move_and_win(2, player_x(), &player_x_sig(), b"00".to_vec(), 0);
}

// ---------------------------------------------------------------------------
// Win / tie detection.
//
// These used to call the PRIVATE helpers `check_win_after_move` and
// `count_occupied` directly — possible only because this file defined its own
// mirror of the contract. Rust's real visibility rules reject that on the
// shipped code, and rightly: those helpers are `fn`, not `pub fn`, so in Rúnar
// they are inlined into the spending script and are not entry points. Each
// test now drives the PUBLIC method that consumes the helper, so what is
// exercised is the path a spender actually takes.
// ---------------------------------------------------------------------------

/// Set `tx_preimage` so `extract_output_hash` returns the hash of the winning
/// payout for `winner`, satisfying the covenant check in `move_and_win`.
fn arm_win_payout(game: &mut TicTacToe, winner: &PubKey) {
    let total_payout = game.bet_amount * 2;
    let payout = cat(
        &cat(&num2bin(&total_payout, 8), &game.p2pkh_prefix),
        &cat(&hash160(winner), &game.p2pkh_suffix),
    );
    game.tx_preimage = hash256(&payout);
}

/// Set `tx_preimage` so `extract_output_hash` returns the hash of the equal
/// split both players receive on a tie, satisfying `move_and_tie`.
fn arm_tie_payout(game: &mut TicTacToe) {
    let out1 = cat(
        &cat(&num2bin(&game.bet_amount, 8), &game.p2pkh_prefix),
        &cat(&hash160(&game.player_x), &game.p2pkh_suffix),
    );
    let out2 = cat(
        &cat(&num2bin(&game.bet_amount, 8), &game.p2pkh_prefix),
        &cat(&hash160(&game.player_o), &game.p2pkh_suffix),
    );
    game.tx_preimage = hash256(&cat(&out1, &out2));
}

#[test]
fn test_check_win_row() {
    let mut game = playing_game();
    game.c0 = 1;
    game.c1 = 1;
    // Position 2 with player X (turn 1) completes the top row.
    arm_win_payout(&mut game, &player_x());
    game.move_and_win(2, player_x(), &player_x_sig(), b"00".to_vec(), 0);
}

#[test]
fn test_check_win_column() {
    let mut game = playing_game();
    game.c0 = 1;
    game.c3 = 1;
    // Position 6 with player X completes the left column.
    arm_win_payout(&mut game, &player_x());
    game.move_and_win(6, player_x(), &player_x_sig(), b"00".to_vec(), 0);
}

#[test]
fn test_check_win_diagonal() {
    let mut game = playing_game();
    game.c0 = 1;
    game.c4 = 1;
    // Position 8 with player X completes the main diagonal.
    arm_win_payout(&mut game, &player_x());
    game.move_and_win(8, player_x(), &player_x_sig(), b"00".to_vec(), 0);
}

#[test]
fn test_check_win_anti_diagonal() {
    let mut game = playing_game();
    game.turn = 2;
    game.c2 = 2;
    game.c4 = 2;
    // Position 6 with player O (turn 2) completes the anti-diagonal.
    arm_win_payout(&mut game, &player_o());
    game.move_and_win(6, player_o(), &player_o_sig(), b"00".to_vec(), 0);
}

#[test]
#[should_panic]
fn test_check_no_win() {
    let mut game = playing_game();
    game.c0 = 1;
    game.c1 = 2;
    // Position 2 with player X completes no line, so `move_and_win`'s
    // `check_win_after_move` assert must reject the spend. The payout is armed
    // so that a PASS here could only mean the win check itself failed to fire.
    arm_win_payout(&mut game, &player_x());
    game.move_and_win(2, player_x(), &player_x_sig(), b"00".to_vec(), 0);
}

#[test]
fn test_tie_requires_eight_occupied_cells() {
    // `move_and_tie` asserts `count_occupied() == 8` — the move about to be
    // played is the ninth and last. Board below has 8 filled and no line.
    let mut game = playing_game();
    game.c0 = 1; game.c1 = 2; game.c2 = 1;
    game.c3 = 1; game.c4 = 2; game.c5 = 2;
    game.c6 = 2; game.c7 = 1;
    arm_tie_payout(&mut game);
    game.move_and_tie(8, player_x(), &player_x_sig(), b"00".to_vec(), 0);
}

#[test]
#[should_panic]
fn test_tie_rejects_board_with_a_free_cell() {
    // Only 7 occupied — `count_occupied() == 8` must reject. Payout armed, so
    // the rejection can only come from the cell count.
    let mut game = playing_game();
    game.c0 = 1; game.c1 = 2; game.c2 = 1;
    game.c3 = 1; game.c4 = 2; game.c5 = 2;
    game.c6 = 2;
    arm_tie_payout(&mut game);
    game.move_and_tie(7, player_x(), &player_x_sig(), b"00".to_vec(), 0);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("TicTacToe.runar.rs"), "TicTacToe.runar.rs").unwrap();
}
