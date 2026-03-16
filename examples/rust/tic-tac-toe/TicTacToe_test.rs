// Contract logic tests for TicTacToe.
//
// Uses inline struct definition because the contract has property initializers
// via init() that must be called explicitly in native Rust tests.

use runar::prelude::*;

// ---------------------------------------------------------------------------
// Inline struct and methods (mirrors the contract but usable in tests)
// ---------------------------------------------------------------------------

struct TicTacToe {
    player_x: PubKey,
    #[allow(dead_code)]
    bet_amount: Bigint,
    #[allow(dead_code)]
    p2pkh_prefix: ByteString,
    #[allow(dead_code)]
    p2pkh_suffix: ByteString,
    player_o: PubKey,
    c0: Bigint,
    c1: Bigint,
    c2: Bigint,
    c3: Bigint,
    c4: Bigint,
    c5: Bigint,
    c6: Bigint,
    c7: Bigint,
    c8: Bigint,
    turn: Bigint,
    status: Bigint,
    #[allow(dead_code)]
    tx_preimage: SigHashPreimage,
}

impl TicTacToe {
    fn join(&mut self, opponent_pk: PubKey, sig: &Sig) {
        assert!(self.status == 0);
        assert!(check_sig(sig, &opponent_pk));
        self.player_o = opponent_pk;
        self.status = 1;
        self.turn = 1;
    }

    fn move_piece(&mut self, position: Bigint, player: PubKey, sig: &Sig) {
        assert!(self.status == 1);
        assert!(check_sig(sig, &player));
        self.assert_correct_player(player);
        self.place_move(position);
        if self.turn == 1 {
            self.turn = 2;
        } else {
            self.turn = 1;
        }
    }

    fn assert_correct_player(&self, player: PubKey) {
        if self.turn == 1 {
            assert!(player == self.player_x);
        } else {
            assert!(player == self.player_o);
        }
    }

    fn assert_cell_empty(&self, position: Bigint) {
        if position == 0 { assert!(self.c0 == 0); }
        else if position == 1 { assert!(self.c1 == 0); }
        else if position == 2 { assert!(self.c2 == 0); }
        else if position == 3 { assert!(self.c3 == 0); }
        else if position == 4 { assert!(self.c4 == 0); }
        else if position == 5 { assert!(self.c5 == 0); }
        else if position == 6 { assert!(self.c6 == 0); }
        else if position == 7 { assert!(self.c7 == 0); }
        else if position == 8 { assert!(self.c8 == 0); }
        else { assert!(false); }
    }

    fn place_move(&mut self, position: Bigint) {
        self.assert_cell_empty(position);
        if position == 0 { self.c0 = self.turn; }
        else if position == 1 { self.c1 = self.turn; }
        else if position == 2 { self.c2 = self.turn; }
        else if position == 3 { self.c3 = self.turn; }
        else if position == 4 { self.c4 = self.turn; }
        else if position == 5 { self.c5 = self.turn; }
        else if position == 6 { self.c6 = self.turn; }
        else if position == 7 { self.c7 = self.turn; }
        else if position == 8 { self.c8 = self.turn; }
        else { assert!(false); }
    }

    fn get_cell_or_override(&self, cell_index: Bigint, override_pos: Bigint, override_val: Bigint) -> Bigint {
        if cell_index == override_pos { return override_val; }
        if cell_index == 0 { return self.c0; }
        else if cell_index == 1 { return self.c1; }
        else if cell_index == 2 { return self.c2; }
        else if cell_index == 3 { return self.c3; }
        else if cell_index == 4 { return self.c4; }
        else if cell_index == 5 { return self.c5; }
        else if cell_index == 6 { return self.c6; }
        else if cell_index == 7 { return self.c7; }
        else { return self.c8; }
    }

    fn check_win_after_move(&self, position: Bigint, player: Bigint) -> bool {
        let v0 = self.get_cell_or_override(0, position, player);
        let v1 = self.get_cell_or_override(1, position, player);
        let v2 = self.get_cell_or_override(2, position, player);
        let v3 = self.get_cell_or_override(3, position, player);
        let v4 = self.get_cell_or_override(4, position, player);
        let v5 = self.get_cell_or_override(5, position, player);
        let v6 = self.get_cell_or_override(6, position, player);
        let v7 = self.get_cell_or_override(7, position, player);
        let v8 = self.get_cell_or_override(8, position, player);

        if v0 == player && v1 == player && v2 == player { return true; }
        if v3 == player && v4 == player && v5 == player { return true; }
        if v6 == player && v7 == player && v8 == player { return true; }
        if v0 == player && v3 == player && v6 == player { return true; }
        if v1 == player && v4 == player && v7 == player { return true; }
        if v2 == player && v5 == player && v8 == player { return true; }
        if v0 == player && v4 == player && v8 == player { return true; }
        if v2 == player && v4 == player && v6 == player { return true; }
        return false;
    }

    fn count_occupied(&self) -> Bigint {
        let mut count: Bigint = 0;
        if self.c0 != 0 { count += 1; }
        if self.c1 != 0 { count += 1; }
        if self.c2 != 0 { count += 1; }
        if self.c3 != 0 { count += 1; }
        if self.c4 != 0 { count += 1; }
        if self.c5 != 0 { count += 1; }
        if self.c6 != 0 { count += 1; }
        if self.c7 != 0 { count += 1; }
        if self.c8 != 0 { count += 1; }
        count
    }

    fn move_and_win(&mut self, position: Bigint, player: PubKey, sig: &Sig, change_pkh: ByteString, change_amount: Bigint) {
        assert!(self.status == 1);
        assert!(check_sig(sig, &player));
        self.assert_correct_player(player.clone());
        self.assert_cell_empty(position);
        assert!(self.check_win_after_move(position, self.turn));

        let total_payout = self.bet_amount * 2;
        let payout = cat(&cat(&cat(&num2bin(&total_payout, 8), &self.p2pkh_prefix), &hash160(&player)), &self.p2pkh_suffix);
        if change_amount > 0 {
            let change = cat(&cat(&cat(&num2bin(&change_amount, 8), &self.p2pkh_prefix), &change_pkh), &self.p2pkh_suffix);
            assert!(hash256(&cat(&payout, &change)) == extract_output_hash(&self.tx_preimage));
        } else {
            assert!(hash256(&payout) == extract_output_hash(&self.tx_preimage));
        }
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn player_x() -> PubKey { ALICE.pub_key.to_vec() }
fn player_o() -> PubKey { BOB.pub_key.to_vec() }
fn player_x_sig() -> Sig { ALICE.sign_test_message() }
fn player_o_sig() -> Sig { BOB.sign_test_message() }
fn zero_pk() -> PubKey { vec![0u8; 33] }

fn new_game() -> TicTacToe {
    TicTacToe {
        player_x: player_x(),
        bet_amount: 1000,
        p2pkh_prefix: b"1976a914".to_vec(),
        p2pkh_suffix: b"88ac".to_vec(),
        player_o: zero_pk(),
        c0: 0, c1: 0, c2: 0,
        c3: 0, c4: 0, c5: 0,
        c6: 0, c7: 0, c8: 0,
        turn: 0,
        status: 0,
        tx_preimage: mock_preimage(),
    }
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

#[test]
fn test_check_win_row() {
    let mut game = playing_game();
    game.c0 = 1;
    game.c1 = 1;
    // Position 2 with player=1 completes top row
    assert!(game.check_win_after_move(2, 1));
}

#[test]
fn test_check_win_column() {
    let mut game = playing_game();
    game.c0 = 1;
    game.c3 = 1;
    // Position 6 with player=1 completes left column
    assert!(game.check_win_after_move(6, 1));
}

#[test]
fn test_check_win_diagonal() {
    let mut game = playing_game();
    game.c0 = 1;
    game.c4 = 1;
    // Position 8 with player=1 completes main diagonal
    assert!(game.check_win_after_move(8, 1));
}

#[test]
fn test_check_win_anti_diagonal() {
    let mut game = playing_game();
    game.c2 = 2;
    game.c4 = 2;
    // Position 6 with player=2 completes anti-diagonal
    assert!(game.check_win_after_move(6, 2));
}

#[test]
fn test_check_no_win() {
    let mut game = playing_game();
    game.c0 = 1;
    game.c1 = 2;
    // Position 2 with player=1 does not complete any line
    assert!(!game.check_win_after_move(2, 1));
}

#[test]
fn test_count_occupied() {
    let mut game = playing_game();
    assert_eq!(game.count_occupied(), 0);
    game.c0 = 1;
    game.c4 = 2;
    game.c8 = 1;
    assert_eq!(game.count_occupied(), 3);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("TicTacToe.runar.rs"), "TicTacToe.runar.rs").unwrap();
}
