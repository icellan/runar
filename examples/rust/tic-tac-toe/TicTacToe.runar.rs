use runar::prelude::*;

/// On-chain Tic-Tac-Toe contract.
///
/// Two players compete on a 3x3 board. Each move is an on-chain transaction.
/// The contract holds both players' bets and enforces correct game rules
/// entirely in Bitcoin Script.
///
/// Board encoding:
/// Since Runar has no arrays, the 3x3 board uses 9 individual bigint fields
/// (c0-c8). Values: 0=empty, 1=X, 2=O.
///
/// Lifecycle:
///  1. Player X deploys the contract with their bet amount.
///  2. Player O calls `join` to enter the game, adding their bet.
///  3. Players alternate calling `move_piece` (non-terminal) or
///     `move_and_win` / `move_and_tie` (terminal).
///  4. Either player can propose `cancel` (requires both signatures).
///
/// Method types:
///   - State-mutating: `join`, `move_piece` -- produce a continuation UTXO.
///   - Non-mutating terminal: `move_and_win`, `move_and_tie`, `cancel` -- spend
///     the UTXO and enforce payout outputs via extract_output_hash.
#[runar::contract]
pub struct TicTacToe {
    #[readonly]
    pub player_x: PubKey,
    #[readonly]
    pub bet_amount: Bigint,
    #[readonly]
    pub p2pkh_prefix: ByteString,
    #[readonly]
    pub p2pkh_suffix: ByteString,
    pub player_o: PubKey,
    pub c0: Bigint,
    pub c1: Bigint,
    pub c2: Bigint,
    pub c3: Bigint,
    pub c4: Bigint,
    pub c5: Bigint,
    pub c6: Bigint,
    pub c7: Bigint,
    pub c8: Bigint,
    pub turn: Bigint,
    pub status: Bigint,
    pub tx_preimage: SigHashPreimage,
}

#[runar::methods(TicTacToe)]
impl TicTacToe {
    pub fn init(&mut self) {
        self.p2pkh_prefix = "1976a914";
        self.p2pkh_suffix = "88ac";
        self.player_o = "000000000000000000000000000000000000000000000000000000000000000000";
        self.c0 = 0;
        self.c1 = 0;
        self.c2 = 0;
        self.c3 = 0;
        self.c4 = 0;
        self.c5 = 0;
        self.c6 = 0;
        self.c7 = 0;
        self.c8 = 0;
        self.turn = 0;
        self.status = 0;
    }

    /// Player O joins the game.
    /// State-mutating: produces continuation UTXO with doubled bet.
    #[public]
    pub fn join(&mut self, opponent_pk: PubKey, sig: &Sig) {
        assert!(self.status == 0);
        assert!(check_sig(sig, &opponent_pk));
        self.player_o = opponent_pk;
        self.status = 1;
        self.turn = 1;
    }

    /// Make a non-terminal move. Updates board and flips turn.
    /// State-mutating: produces continuation UTXO.
    /// Caller provides their pubkey; contract verifies it matches the expected turn.
    #[public]
    pub fn move_piece(&mut self, position: Bigint, player: PubKey, sig: &Sig) {
        assert!(self.status == 1);
        assert!(check_sig(sig, &player));
        self.assert_correct_player(player.clone());
        self.place_move(position);
        if self.turn == 1 {
            self.turn = 2;
        } else {
            self.turn = 1;
        }
    }

    /// Make a winning move. Non-mutating terminal method.
    /// Enforces winner-gets-all payout via extract_output_hash.
    /// Supports optional change output for fee funding.
    #[public]
    pub fn move_and_win(&mut self, position: Bigint, player: PubKey, sig: &Sig, change_pkh: ByteString, change_amount: Bigint) {
        assert!(self.status == 1);
        assert!(check_sig(sig, &player));
        self.assert_correct_player(player.clone());
        self.assert_cell_empty(position);
        assert!(self.check_win_after_move(position, self.turn));

        let total_payout = self.bet_amount * 2;
        let payout = cat(&cat(&num2bin(&total_payout, 8), &self.p2pkh_prefix), &cat(&hash160(&player), &self.p2pkh_suffix));
        if change_amount > 0 {
            let change = cat(&cat(&num2bin(&change_amount, 8), &self.p2pkh_prefix), &cat(&change_pkh, &self.p2pkh_suffix));
            assert!(hash256(&cat(&payout, &change)) == extract_output_hash(&self.tx_preimage));
        } else {
            assert!(hash256(&payout) == extract_output_hash(&self.tx_preimage));
        }
    }

    /// Make a move that fills the board (tie). Non-mutating terminal method.
    /// Enforces equal split payout via extract_output_hash.
    /// Supports optional change output for fee funding.
    #[public]
    pub fn move_and_tie(&mut self, position: Bigint, player: PubKey, sig: &Sig, change_pkh: ByteString, change_amount: Bigint) {
        assert!(self.status == 1);
        assert!(check_sig(sig, &player));
        self.assert_correct_player(player.clone());
        self.assert_cell_empty(position);
        assert!(self.count_occupied() == 8);
        assert!(!self.check_win_after_move(position, self.turn));

        let out1 = cat(&cat(&num2bin(&self.bet_amount, 8), &self.p2pkh_prefix), &cat(&hash160(&self.player_x), &self.p2pkh_suffix));
        let out2 = cat(&cat(&num2bin(&self.bet_amount, 8), &self.p2pkh_prefix), &cat(&hash160(&self.player_o), &self.p2pkh_suffix));
        if change_amount > 0 {
            let change = cat(&cat(&num2bin(&change_amount, 8), &self.p2pkh_prefix), &cat(&change_pkh, &self.p2pkh_suffix));
            assert!(hash256(&cat(&cat(&out1, &out2), &change)) == extract_output_hash(&self.tx_preimage));
        } else {
            assert!(hash256(&cat(&out1, &out2)) == extract_output_hash(&self.tx_preimage));
        }
    }

    /// Player X cancels before anyone joins. Non-mutating terminal method.
    /// Refunds the full bet to player X.
    /// Supports optional change output for fee funding.
    #[public]
    pub fn cancel_before_join(&mut self, sig: &Sig, change_pkh: ByteString, change_amount: Bigint) {
        assert!(self.status == 0);
        assert!(check_sig(sig, &self.player_x));
        let payout = cat(&cat(&num2bin(&self.bet_amount, 8), &self.p2pkh_prefix), &cat(&hash160(&self.player_x), &self.p2pkh_suffix));
        if change_amount > 0 {
            let change = cat(&cat(&num2bin(&change_amount, 8), &self.p2pkh_prefix), &cat(&change_pkh, &self.p2pkh_suffix));
            assert!(hash256(&cat(&payout, &change)) == extract_output_hash(&self.tx_preimage));
        } else {
            assert!(hash256(&payout) == extract_output_hash(&self.tx_preimage));
        }
    }

    /// Both players agree to cancel. Non-mutating terminal method.
    /// Enforces equal refund via extract_output_hash.
    /// Supports optional change output for fee funding.
    #[public]
    pub fn cancel(&mut self, sig_x: &Sig, sig_o: &Sig, change_pkh: ByteString, change_amount: Bigint) {
        let out1 = cat(&cat(&num2bin(&self.bet_amount, 8), &self.p2pkh_prefix), &cat(&hash160(&self.player_x), &self.p2pkh_suffix));
        let out2 = cat(&cat(&num2bin(&self.bet_amount, 8), &self.p2pkh_prefix), &cat(&hash160(&self.player_o), &self.p2pkh_suffix));
        if change_amount > 0 {
            let change = cat(&cat(&num2bin(&change_amount, 8), &self.p2pkh_prefix), &cat(&change_pkh, &self.p2pkh_suffix));
            assert!(hash256(&cat(&cat(&out1, &out2), &change)) == extract_output_hash(&self.tx_preimage));
        } else {
            assert!(hash256(&cat(&out1, &out2)) == extract_output_hash(&self.tx_preimage));
        }
        assert!(check_sig(sig_x, &self.player_x));
        assert!(check_sig(sig_o, &self.player_o));
    }

    // --- Private helpers ---

    /// Assert the provided player pubkey matches whoever's turn it is.
    fn assert_correct_player(&self, player: PubKey) {
        if self.turn == 1 {
            assert!(player == self.player_x);
        } else {
            assert!(player == self.player_o);
        }
    }

    fn assert_cell_empty(&self, position: Bigint) {
        if position == 0 {
            assert!(self.c0 == 0);
        } else {
            if position == 1 {
                assert!(self.c1 == 0);
            } else {
                if position == 2 {
                    assert!(self.c2 == 0);
                } else {
                    if position == 3 {
                        assert!(self.c3 == 0);
                    } else {
                        if position == 4 {
                            assert!(self.c4 == 0);
                        } else {
                            if position == 5 {
                                assert!(self.c5 == 0);
                            } else {
                                if position == 6 {
                                    assert!(self.c6 == 0);
                                } else {
                                    if position == 7 {
                                        assert!(self.c7 == 0);
                                    } else {
                                        if position == 8 {
                                            assert!(self.c8 == 0);
                                        } else {
                                            assert!(1 == 0);
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

    fn place_move(&mut self, position: Bigint) {
        self.assert_cell_empty(position);
        if position == 0 {
            self.c0 = self.turn;
        } else {
            if position == 1 {
                self.c1 = self.turn;
            } else {
                if position == 2 {
                    self.c2 = self.turn;
                } else {
                    if position == 3 {
                        self.c3 = self.turn;
                    } else {
                        if position == 4 {
                            self.c4 = self.turn;
                        } else {
                            if position == 5 {
                                self.c5 = self.turn;
                            } else {
                                if position == 6 {
                                    self.c6 = self.turn;
                                } else {
                                    if position == 7 {
                                        self.c7 = self.turn;
                                    } else {
                                        if position == 8 {
                                            self.c8 = self.turn;
                                        } else {
                                            assert!(1 == 0);
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

    fn get_cell_or_override(&self, cell_index: Bigint, override_pos: Bigint, override_val: Bigint) -> Bigint {
        if cell_index == override_pos {
            return override_val;
        }
        if cell_index == 0 {
            return self.c0;
        } else {
            if cell_index == 1 {
                return self.c1;
            } else {
                if cell_index == 2 {
                    return self.c2;
                } else {
                    if cell_index == 3 {
                        return self.c3;
                    } else {
                        if cell_index == 4 {
                            return self.c4;
                        } else {
                            if cell_index == 5 {
                                return self.c5;
                            } else {
                                if cell_index == 6 {
                                    return self.c6;
                                } else {
                                    if cell_index == 7 {
                                        return self.c7;
                                    } else {
                                        return self.c8;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
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
        if self.c0 != 0 { count = count + 1; }
        if self.c1 != 0 { count = count + 1; }
        if self.c2 != 0 { count = count + 1; }
        if self.c3 != 0 { count = count + 1; }
        if self.c4 != 0 { count = count + 1; }
        if self.c5 != 0 { count = count + 1; }
        if self.c6 != 0 { count = count + 1; }
        if self.c7 != 0 { count = count + 1; }
        if self.c8 != 0 { count = count + 1; }
        return count;
    }
}
