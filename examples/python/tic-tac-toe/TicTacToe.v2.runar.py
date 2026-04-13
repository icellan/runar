from runar import (
    StatefulSmartContract, PubKey, Sig, ByteString, Bigint, Readonly,
    FixedArray,
    public, assert_, check_sig, extract_output_hash, hash256, hash160,
    num2bin, cat,
)


class TicTacToe(StatefulSmartContract):
    # TicTacToe v2 — FixedArray rewrite of the hand-rolled v1 contract.
    #
    # Semantically identical to ``TicTacToe.runar.py``, with the 9 board cells
    # expressed as a single ``FixedArray[Bigint, 9]`` property. The Rúnar
    # compiler's ``expand_fixed_arrays`` pass desugars this to the same 9
    # scalar siblings that v1 declares manually, so this file must compile
    # to byte-identical Bitcoin Script.

    player_x: Readonly[PubKey]
    bet_amount: Readonly[Bigint]
    p2pkh_prefix: Readonly[ByteString] = "1976a914"
    p2pkh_suffix: Readonly[ByteString] = "88ac"

    player_o: PubKey = "000000000000000000000000000000000000000000000000000000000000000000"
    board: FixedArray[Bigint, 9] = [0, 0, 0, 0, 0, 0, 0, 0, 0]
    turn: Bigint = 0
    status: Bigint = 0

    def __init__(self, player_x: PubKey, bet_amount: Bigint):
        super().__init__(player_x, bet_amount)
        self.player_x = player_x
        self.bet_amount = bet_amount

    @public
    def join(self, opponent_pk: PubKey, sig: Sig):
        assert_(self.status == 0)
        assert_(check_sig(sig, opponent_pk))
        self.player_o = opponent_pk
        self.status = 1
        self.turn = 1

    @public
    def move(self, position: Bigint, player: PubKey, sig: Sig):
        assert_(self.status == 1)
        assert_(check_sig(sig, player))
        self.assert_correct_player(player)
        self.place_move(position)
        if self.turn == 1:
            self.turn = 2
        else:
            self.turn = 1

    @public
    def move_and_win(self, position: Bigint, player: PubKey, sig: Sig, change_pkh: ByteString, change_amount: Bigint):
        assert_(self.status == 1)
        assert_(check_sig(sig, player))
        self.assert_correct_player(player)
        self.assert_cell_empty(position)
        assert_(self.check_win_after_move(position, self.turn))

        total_payout = self.bet_amount * 2
        payout = cat(cat(num2bin(total_payout, 8), self.p2pkh_prefix), cat(hash160(player), self.p2pkh_suffix))
        if change_amount > 0:
            change = cat(cat(num2bin(change_amount, 8), self.p2pkh_prefix), cat(change_pkh, self.p2pkh_suffix))
            assert_(hash256(cat(payout, change)) == extract_output_hash(self.tx_preimage))
        else:
            assert_(hash256(payout) == extract_output_hash(self.tx_preimage))

    @public
    def move_and_tie(self, position: Bigint, player: PubKey, sig: Sig, change_pkh: ByteString, change_amount: Bigint):
        assert_(self.status == 1)
        assert_(check_sig(sig, player))
        self.assert_correct_player(player)
        self.assert_cell_empty(position)
        assert_(self.count_occupied() == 8)
        assert_(not self.check_win_after_move(position, self.turn))

        out1 = cat(cat(num2bin(self.bet_amount, 8), self.p2pkh_prefix), cat(hash160(self.player_x), self.p2pkh_suffix))
        out2 = cat(cat(num2bin(self.bet_amount, 8), self.p2pkh_prefix), cat(hash160(self.player_o), self.p2pkh_suffix))
        if change_amount > 0:
            change = cat(cat(num2bin(change_amount, 8), self.p2pkh_prefix), cat(change_pkh, self.p2pkh_suffix))
            assert_(hash256(cat(cat(out1, out2), change)) == extract_output_hash(self.tx_preimage))
        else:
            assert_(hash256(cat(out1, out2)) == extract_output_hash(self.tx_preimage))

    @public
    def cancel_before_join(self, sig: Sig, change_pkh: ByteString, change_amount: Bigint):
        assert_(self.status == 0)
        assert_(check_sig(sig, self.player_x))
        payout = cat(cat(num2bin(self.bet_amount, 8), self.p2pkh_prefix), cat(hash160(self.player_x), self.p2pkh_suffix))
        if change_amount > 0:
            change = cat(cat(num2bin(change_amount, 8), self.p2pkh_prefix), cat(change_pkh, self.p2pkh_suffix))
            assert_(hash256(cat(payout, change)) == extract_output_hash(self.tx_preimage))
        else:
            assert_(hash256(payout) == extract_output_hash(self.tx_preimage))

    @public
    def cancel(self, sig_x: Sig, sig_o: Sig, change_pkh: ByteString, change_amount: Bigint):
        out1 = cat(cat(num2bin(self.bet_amount, 8), self.p2pkh_prefix), cat(hash160(self.player_x), self.p2pkh_suffix))
        out2 = cat(cat(num2bin(self.bet_amount, 8), self.p2pkh_prefix), cat(hash160(self.player_o), self.p2pkh_suffix))
        if change_amount > 0:
            change = cat(cat(num2bin(change_amount, 8), self.p2pkh_prefix), cat(change_pkh, self.p2pkh_suffix))
            assert_(hash256(cat(cat(out1, out2), change)) == extract_output_hash(self.tx_preimage))
        else:
            assert_(hash256(cat(out1, out2)) == extract_output_hash(self.tx_preimage))
        assert_(check_sig(sig_x, self.player_x))
        assert_(check_sig(sig_o, self.player_o))

    # --- Private helpers ---

    def assert_correct_player(self, player: PubKey):
        if self.turn == 1:
            assert_(player == self.player_x)
        else:
            assert_(player == self.player_o)

    def assert_cell_empty(self, position: Bigint):
        if position == 0:
            assert_(self.board[0] == 0)
        elif position == 1:
            assert_(self.board[1] == 0)
        elif position == 2:
            assert_(self.board[2] == 0)
        elif position == 3:
            assert_(self.board[3] == 0)
        elif position == 4:
            assert_(self.board[4] == 0)
        elif position == 5:
            assert_(self.board[5] == 0)
        elif position == 6:
            assert_(self.board[6] == 0)
        elif position == 7:
            assert_(self.board[7] == 0)
        elif position == 8:
            assert_(self.board[8] == 0)
        else:
            assert_(False)

    def place_move(self, position: Bigint):
        self.assert_cell_empty(position)
        if position == 0:
            self.board[0] = self.turn
        elif position == 1:
            self.board[1] = self.turn
        elif position == 2:
            self.board[2] = self.turn
        elif position == 3:
            self.board[3] = self.turn
        elif position == 4:
            self.board[4] = self.turn
        elif position == 5:
            self.board[5] = self.turn
        elif position == 6:
            self.board[6] = self.turn
        elif position == 7:
            self.board[7] = self.turn
        elif position == 8:
            self.board[8] = self.turn
        else:
            assert_(False)

    def get_cell_or_override(self, cell_index: Bigint, override_pos: Bigint, override_val: Bigint) -> Bigint:
        if cell_index == override_pos:
            return override_val
        if cell_index == 0:
            return self.board[0]
        elif cell_index == 1:
            return self.board[1]
        elif cell_index == 2:
            return self.board[2]
        elif cell_index == 3:
            return self.board[3]
        elif cell_index == 4:
            return self.board[4]
        elif cell_index == 5:
            return self.board[5]
        elif cell_index == 6:
            return self.board[6]
        elif cell_index == 7:
            return self.board[7]
        else:
            return self.board[8]

    def check_win_after_move(self, position: Bigint, player: Bigint) -> bool:
        v0 = self.get_cell_or_override(0, position, player)
        v1 = self.get_cell_or_override(1, position, player)
        v2 = self.get_cell_or_override(2, position, player)
        v3 = self.get_cell_or_override(3, position, player)
        v4 = self.get_cell_or_override(4, position, player)
        v5 = self.get_cell_or_override(5, position, player)
        v6 = self.get_cell_or_override(6, position, player)
        v7 = self.get_cell_or_override(7, position, player)
        v8 = self.get_cell_or_override(8, position, player)

        if v0 == player and v1 == player and v2 == player:
            return True
        if v3 == player and v4 == player and v5 == player:
            return True
        if v6 == player and v7 == player and v8 == player:
            return True
        if v0 == player and v3 == player and v6 == player:
            return True
        if v1 == player and v4 == player and v7 == player:
            return True
        if v2 == player and v5 == player and v8 == player:
            return True
        if v0 == player and v4 == player and v8 == player:
            return True
        if v2 == player and v4 == player and v6 == player:
            return True
        return False

    def count_occupied(self) -> Bigint:
        count = 0
        if self.board[0] != 0:
            count = count + 1
        if self.board[1] != 0:
            count = count + 1
        if self.board[2] != 0:
            count = count + 1
        if self.board[3] != 0:
            count = count + 1
        if self.board[4] != 0:
            count = count + 1
        if self.board[5] != 0:
            count = count + 1
        if self.board[6] != 0:
            count = count + 1
        if self.board[7] != 0:
            count = count + 1
        if self.board[8] != 0:
            count = count + 1
        return count
