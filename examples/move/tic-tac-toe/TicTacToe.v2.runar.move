// TicTacToe v2 — Move-style port of
// `examples/ts/tic-tac-toe/TicTacToe.v2.runar.ts`.
//
// Semantically identical to `TicTacToe.runar.move`, with the 9 board cells
// expressed as a single `FixedArray<bigint, 9>` field instead of nine scalar
// fields. The `expand-fixed-arrays` pass desugars that back into the same nine
// scalar siblings v1 declares by hand, so this file compiles to byte-identical
// Bitcoin Script.
//
// R-208: v2 shipped in six surfaces and not in this one. The dynamic
// FixedArray WRITE (`self.board[position] = self.turn`) is what the missing
// coverage was about.
module TicTacToe {
    use runar::StatefulSmartContract;
    use runar::types::{PubKey, Sig, ByteString};
    use runar::crypto::{check_sig, hash256, hash160, extract_output_hash, num2bin, cat};

    resource struct TicTacToe {
        player_x: PubKey,
        bet_amount: bigint,
        p2pkh_prefix: ByteString = 0x1976a914,
        p2pkh_suffix: ByteString = 0x88ac,
        player_o: &mut PubKey = 0x000000000000000000000000000000000000000000000000000000000000000000,
        board: &mut FixedArray<bigint, 9> = [0, 0, 0, 0, 0, 0, 0, 0, 0],
        turn: &mut bigint = 0,
        status: &mut bigint = 0,
    }

    // Player O joins the game.
    public fun join(opponent_pk: PubKey, sig: Sig) {
        assert!(self.status == 0, 0);
        assert!(check_sig(sig, opponent_pk), 0);
        self.player_o = opponent_pk;
        self.status = 1;
        self.turn = 1;
    }

    // Make a non-terminal move. Updates board and flips turn.
    public fun move(position: bigint, player: PubKey, sig: Sig) {
        assert!(self.status == 1, 0);
        assert!(check_sig(sig, player), 0);
        self.assert_correct_player(player);
        self.place_move(position);
        if (self.turn == 1) {
            self.turn = 2;
        } else {
            self.turn = 1;
        }
    }

    // Make a winning move. Terminal method.
    public fun move_and_win(position: bigint, player: PubKey, sig: Sig, change_pkh: ByteString, change_amount: bigint) {
        assert!(self.status == 1, 0);
        assert!(check_sig(sig, player), 0);
        self.assert_correct_player(player);
        self.assert_cell_empty(position);
        assert!(self.check_win_after_move(position, self.turn), 0);

        let total_payout: bigint = self.bet_amount * 2;
        let payout: ByteString = cat(cat(num2bin(total_payout, 8), self.p2pkh_prefix), cat(hash160(player), self.p2pkh_suffix));
        if (change_amount > 0) {
            let change: ByteString = cat(cat(num2bin(change_amount, 8), self.p2pkh_prefix), cat(change_pkh, self.p2pkh_suffix));
            assert!(hash256(cat(payout, change)) == extract_output_hash(self.tx_preimage), 0);
        } else {
            assert!(hash256(payout) == extract_output_hash(self.tx_preimage), 0);
        }
    }

    // Make a move that fills the board (tie). Terminal method.
    public fun move_and_tie(position: bigint, player: PubKey, sig: Sig, change_pkh: ByteString, change_amount: bigint) {
        assert!(self.status == 1, 0);
        assert!(check_sig(sig, player), 0);
        self.assert_correct_player(player);
        self.assert_cell_empty(position);
        assert!(self.count_occupied() == 8, 0);
        assert!(!self.check_win_after_move(position, self.turn), 0);

        let out1: ByteString = cat(cat(num2bin(self.bet_amount, 8), self.p2pkh_prefix), cat(hash160(self.player_x), self.p2pkh_suffix));
        let out2: ByteString = cat(cat(num2bin(self.bet_amount, 8), self.p2pkh_prefix), cat(hash160(self.player_o), self.p2pkh_suffix));
        if (change_amount > 0) {
            let change: ByteString = cat(cat(num2bin(change_amount, 8), self.p2pkh_prefix), cat(change_pkh, self.p2pkh_suffix));
            assert!(hash256(cat(cat(out1, out2), change)) == extract_output_hash(self.tx_preimage), 0);
        } else {
            assert!(hash256(cat(out1, out2)) == extract_output_hash(self.tx_preimage), 0);
        }
    }

    // Player X cancels before anyone joins. Terminal method.
    public fun cancel_before_join(sig: Sig, change_pkh: ByteString, change_amount: bigint) {
        assert!(self.status == 0, 0);
        assert!(check_sig(sig, self.player_x), 0);
        let payout: ByteString = cat(cat(num2bin(self.bet_amount, 8), self.p2pkh_prefix), cat(hash160(self.player_x), self.p2pkh_suffix));
        if (change_amount > 0) {
            let change: ByteString = cat(cat(num2bin(change_amount, 8), self.p2pkh_prefix), cat(change_pkh, self.p2pkh_suffix));
            assert!(hash256(cat(payout, change)) == extract_output_hash(self.tx_preimage), 0);
        } else {
            assert!(hash256(payout) == extract_output_hash(self.tx_preimage), 0);
        }
    }

    // Both players agree to cancel. Terminal method.
    public fun cancel(sig_x: Sig, sig_o: Sig, change_pkh: ByteString, change_amount: bigint) {
        let out1: ByteString = cat(cat(num2bin(self.bet_amount, 8), self.p2pkh_prefix), cat(hash160(self.player_x), self.p2pkh_suffix));
        let out2: ByteString = cat(cat(num2bin(self.bet_amount, 8), self.p2pkh_prefix), cat(hash160(self.player_o), self.p2pkh_suffix));
        if (change_amount > 0) {
            let change: ByteString = cat(cat(num2bin(change_amount, 8), self.p2pkh_prefix), cat(change_pkh, self.p2pkh_suffix));
            assert!(hash256(cat(cat(out1, out2), change)) == extract_output_hash(self.tx_preimage), 0);
        } else {
            assert!(hash256(cat(out1, out2)) == extract_output_hash(self.tx_preimage), 0);
        }
        assert!(check_sig(sig_x, self.player_x), 0);
        assert!(check_sig(sig_o, self.player_o), 0);
    }

    // --- Private helpers ---

    fun assert_correct_player(player: PubKey) {
        if (self.turn == 1) {
            assert!(player == self.player_x, 0);
        } else {
            assert!(player == self.player_o, 0);
        }
    }

    fun assert_cell_empty(position: bigint) {
        if (position == 0) {
            assert!(self.board[0] == 0, 0);
        } else {
            if (position == 1) {
                assert!(self.board[1] == 0, 0);
            } else {
                if (position == 2) {
                    assert!(self.board[2] == 0, 0);
                } else {
                    if (position == 3) {
                        assert!(self.board[3] == 0, 0);
                    } else {
                        if (position == 4) {
                            assert!(self.board[4] == 0, 0);
                        } else {
                            if (position == 5) {
                                assert!(self.board[5] == 0, 0);
                            } else {
                                if (position == 6) {
                                    assert!(self.board[6] == 0, 0);
                                } else {
                                    if (position == 7) {
                                        assert!(self.board[7] == 0, 0);
                                    } else {
                                        if (position == 8) {
                                            assert!(self.board[8] == 0, 0);
                                        } else {
                                            assert!(false, 0);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fun place_move(position: bigint) {
        self.assert_cell_empty(position);
        self.board[position] = self.turn;
    }

    fun get_cell_or_override(cell_index: bigint, override_pos: bigint, override_val: bigint): bigint {
        if (cell_index == override_pos) {
            return override_val;
        }
        if (cell_index == 0) {
            return self.board[0];
        } else {
            if (cell_index == 1) {
                return self.board[1];
            } else {
                if (cell_index == 2) {
                    return self.board[2];
                } else {
                    if (cell_index == 3) {
                        return self.board[3];
                    } else {
                        if (cell_index == 4) {
                            return self.board[4];
                        } else {
                            if (cell_index == 5) {
                                return self.board[5];
                            } else {
                                if (cell_index == 6) {
                                    return self.board[6];
                                } else {
                                    if (cell_index == 7) {
                                        return self.board[7];
                                    } else {
                                        return self.board[8];
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fun check_win_after_move(position: bigint, player: bigint): bool {
        let v0: bigint = self.get_cell_or_override(0, position, player);
        let v1: bigint = self.get_cell_or_override(1, position, player);
        let v2: bigint = self.get_cell_or_override(2, position, player);
        let v3: bigint = self.get_cell_or_override(3, position, player);
        let v4: bigint = self.get_cell_or_override(4, position, player);
        let v5: bigint = self.get_cell_or_override(5, position, player);
        let v6: bigint = self.get_cell_or_override(6, position, player);
        let v7: bigint = self.get_cell_or_override(7, position, player);
        let v8: bigint = self.get_cell_or_override(8, position, player);

        if (v0 == player && v1 == player && v2 == player) { return true; }
        if (v3 == player && v4 == player && v5 == player) { return true; }
        if (v6 == player && v7 == player && v8 == player) { return true; }
        if (v0 == player && v3 == player && v6 == player) { return true; }
        if (v1 == player && v4 == player && v7 == player) { return true; }
        if (v2 == player && v5 == player && v8 == player) { return true; }
        if (v0 == player && v4 == player && v8 == player) { return true; }
        if (v2 == player && v4 == player && v6 == player) { return true; }
        return false;
    }

    fun count_occupied(): bigint {
        let count: bigint = 0;
        if (self.board[0] != 0) { count = count + 1; }
        if (self.board[1] != 0) { count = count + 1; }
        if (self.board[2] != 0) { count = count + 1; }
        if (self.board[3] != 0) { count = count + 1; }
        if (self.board[4] != 0) { count = count + 1; }
        if (self.board[5] != 0) { count = count + 1; }
        if (self.board[6] != 0) { count = count + 1; }
        if (self.board[7] != 0) { count = count + 1; }
        if (self.board[8] != 0) { count = count + 1; }
        return count;
    }
}
