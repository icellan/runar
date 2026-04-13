const runar = @import("runar");

// TicTacToe v2 -- FixedArray rewrite of the hand-rolled v1 contract.
//
// Semantically identical to TicTacToe.runar.zig, with the 9 board cells
// expressed as a single [9]i64 property. The Runar compiler's
// expand-fixed-arrays pass desugars this to the same 9 scalar siblings
// that v1 declares manually, so this file must compile to byte-identical
// Bitcoin Script.
//
// This file is the Zig DSL mirror of `examples/ts/tic-tac-toe/TicTacToe.v2.runar.ts`
// — every payout uses the same inline `cat(cat(num2bin(amt, 8), pfx), cat(h, sfx))`
// form as the canonical TS source, so the compiled script must be a byte-for-byte
// match for the canonical 4951-byte output.
pub const TicTacToe = struct {
    pub const Contract = runar.StatefulSmartContract;

    playerX: runar.PubKey,
    betAmount: i64,
    p2pkhPrefix: runar.Readonly(runar.ByteString) = "1976a914",
    p2pkhSuffix: runar.Readonly(runar.ByteString) = "88ac",
    playerO: runar.PubKey = "000000000000000000000000000000000000000000000000000000000000000000",
    board: [9]i64 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    turn: i64 = 0,
    status: i64 = 0,

    pub fn init(playerX: runar.PubKey, betAmount: i64) TicTacToe {
        return .{
            .playerX = playerX,
            .betAmount = betAmount,
        };
    }

    pub fn join(self: *TicTacToe, opponentPK: runar.PubKey, sig: runar.Sig) void {
        runar.assert(self.status == 0);
        runar.assert(runar.checkSig(sig, opponentPK));
        self.playerO = opponentPK;
        self.status = 1;
        self.turn = 1;
    }

    pub fn move(self: *TicTacToe, position: i64, player: runar.PubKey, sig: runar.Sig) void {
        runar.assert(self.status == 1);
        runar.assert(runar.checkSig(sig, player));
        self.assertCorrectPlayer(player);
        self.placeMove(position);

        if (self.turn == 1) {
            self.turn = 2;
        } else {
            self.turn = 1;
        }
    }

    pub fn moveAndWin(
        self: *const TicTacToe,
        ctx: runar.StatefulContext,
        position: i64,
        player: runar.PubKey,
        sig: runar.Sig,
        changePKH: runar.ByteString,
        changeAmount: i64,
    ) void {
        runar.assert(self.status == 1);
        runar.assert(runar.checkSig(sig, player));
        self.assertCorrectPlayer(player);
        self.assertCellEmpty(position);
        runar.assert(self.checkWinAfterMove(position, self.turn));

        const totalPayout = self.betAmount * 2;
        const payout = runar.cat(runar.cat(runar.num2bin(totalPayout, 8), self.p2pkhPrefix), runar.cat(runar.hash160(player), self.p2pkhSuffix));
        if (changeAmount > 0) {
            const change = runar.cat(runar.cat(runar.num2bin(changeAmount, 8), self.p2pkhPrefix), runar.cat(changePKH, self.p2pkhSuffix));
            runar.assert(runar.bytesEq(runar.hash256(runar.cat(payout, change)), runar.extractOutputHash(ctx.txPreimage)));
        } else {
            runar.assert(runar.bytesEq(runar.hash256(payout), runar.extractOutputHash(ctx.txPreimage)));
        }
    }

    pub fn moveAndTie(
        self: *const TicTacToe,
        ctx: runar.StatefulContext,
        position: i64,
        player: runar.PubKey,
        sig: runar.Sig,
        changePKH: runar.ByteString,
        changeAmount: i64,
    ) void {
        runar.assert(self.status == 1);
        runar.assert(runar.checkSig(sig, player));
        self.assertCorrectPlayer(player);
        self.assertCellEmpty(position);
        runar.assert(self.countOccupied() == 8);
        runar.assert(!self.checkWinAfterMove(position, self.turn));

        const out1 = runar.cat(runar.cat(runar.num2bin(self.betAmount, 8), self.p2pkhPrefix), runar.cat(runar.hash160(self.playerX), self.p2pkhSuffix));
        const out2 = runar.cat(runar.cat(runar.num2bin(self.betAmount, 8), self.p2pkhPrefix), runar.cat(runar.hash160(self.playerO), self.p2pkhSuffix));
        if (changeAmount > 0) {
            const change = runar.cat(runar.cat(runar.num2bin(changeAmount, 8), self.p2pkhPrefix), runar.cat(changePKH, self.p2pkhSuffix));
            runar.assert(runar.bytesEq(runar.hash256(runar.cat(runar.cat(out1, out2), change)), runar.extractOutputHash(ctx.txPreimage)));
        } else {
            runar.assert(runar.bytesEq(runar.hash256(runar.cat(out1, out2)), runar.extractOutputHash(ctx.txPreimage)));
        }
    }

    pub fn cancelBeforeJoin(
        self: *const TicTacToe,
        ctx: runar.StatefulContext,
        sig: runar.Sig,
        changePKH: runar.ByteString,
        changeAmount: i64,
    ) void {
        runar.assert(self.status == 0);
        runar.assert(runar.checkSig(sig, self.playerX));

        const payout = runar.cat(runar.cat(runar.num2bin(self.betAmount, 8), self.p2pkhPrefix), runar.cat(runar.hash160(self.playerX), self.p2pkhSuffix));
        if (changeAmount > 0) {
            const change = runar.cat(runar.cat(runar.num2bin(changeAmount, 8), self.p2pkhPrefix), runar.cat(changePKH, self.p2pkhSuffix));
            runar.assert(runar.bytesEq(runar.hash256(runar.cat(payout, change)), runar.extractOutputHash(ctx.txPreimage)));
        } else {
            runar.assert(runar.bytesEq(runar.hash256(payout), runar.extractOutputHash(ctx.txPreimage)));
        }
    }

    pub fn cancel(
        self: *const TicTacToe,
        ctx: runar.StatefulContext,
        sigX: runar.Sig,
        sigO: runar.Sig,
        changePKH: runar.ByteString,
        changeAmount: i64,
    ) void {
        const out1 = runar.cat(runar.cat(runar.num2bin(self.betAmount, 8), self.p2pkhPrefix), runar.cat(runar.hash160(self.playerX), self.p2pkhSuffix));
        const out2 = runar.cat(runar.cat(runar.num2bin(self.betAmount, 8), self.p2pkhPrefix), runar.cat(runar.hash160(self.playerO), self.p2pkhSuffix));
        if (changeAmount > 0) {
            const change = runar.cat(runar.cat(runar.num2bin(changeAmount, 8), self.p2pkhPrefix), runar.cat(changePKH, self.p2pkhSuffix));
            runar.assert(runar.bytesEq(runar.hash256(runar.cat(runar.cat(out1, out2), change)), runar.extractOutputHash(ctx.txPreimage)));
        } else {
            runar.assert(runar.bytesEq(runar.hash256(runar.cat(out1, out2)), runar.extractOutputHash(ctx.txPreimage)));
        }

        runar.assert(runar.checkSig(sigX, self.playerX));
        runar.assert(runar.checkSig(sigO, self.playerO));
    }

    fn assertCorrectPlayer(self: *const TicTacToe, player: runar.PubKey) void {
        if (self.turn == 1) {
            runar.assert(runar.bytesEq(player, self.playerX));
        } else {
            runar.assert(runar.bytesEq(player, self.playerO));
        }
    }

    fn assertCellEmpty(self: *const TicTacToe, position: i64) void {
        if (position == 0) {
            runar.assert(self.board[0] == 0);
        } else if (position == 1) {
            runar.assert(self.board[1] == 0);
        } else if (position == 2) {
            runar.assert(self.board[2] == 0);
        } else if (position == 3) {
            runar.assert(self.board[3] == 0);
        } else if (position == 4) {
            runar.assert(self.board[4] == 0);
        } else if (position == 5) {
            runar.assert(self.board[5] == 0);
        } else if (position == 6) {
            runar.assert(self.board[6] == 0);
        } else if (position == 7) {
            runar.assert(self.board[7] == 0);
        } else if (position == 8) {
            runar.assert(self.board[8] == 0);
        } else {
            runar.assert(false);
        }
    }

    fn placeMove(self: *TicTacToe, position: i64) void {
        self.assertCellEmpty(position);
        self.board[position] = self.turn;
    }

    fn getCellOrOverride(self: *const TicTacToe, cellIndex: i64, overridePos: i64, overrideVal: i64) i64 {
        if (cellIndex == overridePos) {
            return overrideVal;
        }
        if (cellIndex == 0) {
            return self.board[0];
        }
        if (cellIndex == 1) {
            return self.board[1];
        }
        if (cellIndex == 2) {
            return self.board[2];
        }
        if (cellIndex == 3) {
            return self.board[3];
        }
        if (cellIndex == 4) {
            return self.board[4];
        }
        if (cellIndex == 5) {
            return self.board[5];
        }
        if (cellIndex == 6) {
            return self.board[6];
        }
        if (cellIndex == 7) {
            return self.board[7];
        }
        return self.board[8];
    }

    fn checkWinAfterMove(self: *const TicTacToe, position: i64, player: i64) bool {
        const c0 = self.getCellOrOverride(0, position, player);
        const c1 = self.getCellOrOverride(1, position, player);
        const c2 = self.getCellOrOverride(2, position, player);
        const c3 = self.getCellOrOverride(3, position, player);
        const c4 = self.getCellOrOverride(4, position, player);
        const c5 = self.getCellOrOverride(5, position, player);
        const c6 = self.getCellOrOverride(6, position, player);
        const c7 = self.getCellOrOverride(7, position, player);
        const c8 = self.getCellOrOverride(8, position, player);

        if (c0 == player and c1 == player and c2 == player) {
            return true;
        }
        if (c3 == player and c4 == player and c5 == player) {
            return true;
        }
        if (c6 == player and c7 == player and c8 == player) {
            return true;
        }
        if (c0 == player and c3 == player and c6 == player) {
            return true;
        }
        if (c1 == player and c4 == player and c7 == player) {
            return true;
        }
        if (c2 == player and c5 == player and c8 == player) {
            return true;
        }
        if (c0 == player and c4 == player and c8 == player) {
            return true;
        }
        if (c2 == player and c4 == player and c6 == player) {
            return true;
        }
        return false;
    }

    fn countOccupied(self: *const TicTacToe) i64 {
        var count: i64 = 0;
        if (self.board[0] != 0) {
            count += 1;
        }
        if (self.board[1] != 0) {
            count += 1;
        }
        if (self.board[2] != 0) {
            count += 1;
        }
        if (self.board[3] != 0) {
            count += 1;
        }
        if (self.board[4] != 0) {
            count += 1;
        }
        if (self.board[5] != 0) {
            count += 1;
        }
        if (self.board[6] != 0) {
            count += 1;
        }
        if (self.board[7] != 0) {
            count += 1;
        }
        if (self.board[8] != 0) {
            count += 1;
        }
        return count;
    }
};
