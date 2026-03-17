const runar = @import("runar");

pub const TicTacToe = struct {
    pub const Contract = runar.StatefulSmartContract;

    playerX: runar.PubKey,
    betAmount: i64,
    playerO: runar.PubKey = "000000000000000000000000000000000000000000000000000000000000000000",
    c0: i64 = 0,
    c1: i64 = 0,
    c2: i64 = 0,
    c3: i64 = 0,
    c4: i64 = 0,
    c5: i64 = 0,
    c6: i64 = 0,
    c7: i64 = 0,
    c8: i64 = 0,
    turn: i64 = 0,
    status: i64 = 0,

    pub fn init(playerX: runar.PubKey, betAmount: i64) TicTacToe {
        return .{
            .playerX = playerX,
            .betAmount = betAmount,
        };
    }

    pub fn join(self: *TicTacToe, opponentPk: runar.PubKey, sig: runar.Sig) void {
        runar.assert(self.status == 0);
        runar.assert(runar.checkSig(sig, opponentPk));
        self.playerO = opponentPk;
        self.status = 1;
        self.turn = 1;
    }

    pub fn movePiece(self: *TicTacToe, position: i64, player: runar.PubKey, sig: runar.Sig) void {
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
        position: i64,
        player: runar.PubKey,
        sig: runar.Sig,
        changePkh: runar.ByteString,
        changeAmount: i64,
    ) void {
        const playerMark = self.playerMark(player);

        runar.assert(self.status == 1);
        runar.assert(runar.checkSig(sig, player));
        self.assertCorrectPlayer(player);
        self.assertCellEmpty(position);
        runar.assert(self.checkWinAfterMove(position, playerMark));

        const winnerOutput = self.buildP2PKHOutput(self.betAmount * 2, runar.hash160(player));
        if (changeAmount > 0) {
            const changeOutput = self.buildP2PKHOutput(changeAmount, changePkh);
            runar.assert(runar.hash256(runar.cat(winnerOutput, changeOutput)) == runar.extractOutputHash(self.txPreimage));
        } else {
            runar.assert(runar.hash256(winnerOutput) == runar.extractOutputHash(self.txPreimage));
        }
    }

    pub fn moveAndTie(
        self: *const TicTacToe,
        position: i64,
        player: runar.PubKey,
        sig: runar.Sig,
        changePkh: runar.ByteString,
        changeAmount: i64,
    ) void {
        const playerMark = self.playerMark(player);

        runar.assert(self.status == 1);
        runar.assert(runar.checkSig(sig, player));
        self.assertCorrectPlayer(player);
        self.assertCellEmpty(position);
        runar.assert(!self.checkWinAfterMove(position, playerMark));
        runar.assert(self.countOccupied() == 8);

        const outputX = self.buildP2PKHOutput(self.betAmount, runar.hash160(self.playerX));
        const outputO = self.buildP2PKHOutput(self.betAmount, runar.hash160(self.playerO));
        const outputs = runar.cat(outputX, outputO);
        if (changeAmount > 0) {
            const changeOutput = self.buildP2PKHOutput(changeAmount, changePkh);
            runar.assert(runar.hash256(runar.cat(outputs, changeOutput)) == runar.extractOutputHash(self.txPreimage));
        } else {
            runar.assert(runar.hash256(outputs) == runar.extractOutputHash(self.txPreimage));
        }
    }

    pub fn cancelBeforeJoin(
        self: *const TicTacToe,
        sig: runar.Sig,
        changePkh: runar.ByteString,
        changeAmount: i64,
    ) void {
        runar.assert(self.status == 0);
        runar.assert(runar.checkSig(sig, self.playerX));

        const payout = self.buildP2PKHOutput(self.betAmount, runar.hash160(self.playerX));
        if (changeAmount > 0) {
            const changeOutput = self.buildP2PKHOutput(changeAmount, changePkh);
            runar.assert(runar.hash256(runar.cat(payout, changeOutput)) == runar.extractOutputHash(self.txPreimage));
        } else {
            runar.assert(runar.hash256(payout) == runar.extractOutputHash(self.txPreimage));
        }
    }

    pub fn cancel(
        self: *const TicTacToe,
        sigX: runar.Sig,
        sigO: runar.Sig,
        changePkh: runar.ByteString,
        changeAmount: i64,
    ) void {
        const outputX = self.buildP2PKHOutput(self.betAmount, runar.hash160(self.playerX));
        const outputO = self.buildP2PKHOutput(self.betAmount, runar.hash160(self.playerO));
        const outputs = runar.cat(outputX, outputO);

        if (changeAmount > 0) {
            const changeOutput = self.buildP2PKHOutput(changeAmount, changePkh);
            runar.assert(runar.hash256(runar.cat(outputs, changeOutput)) == runar.extractOutputHash(self.txPreimage));
        } else {
            runar.assert(runar.hash256(outputs) == runar.extractOutputHash(self.txPreimage));
        }

        runar.assert(runar.checkSig(sigX, self.playerX));
        runar.assert(runar.checkSig(sigO, self.playerO));
    }

    fn playerMark(self: *const TicTacToe, player: runar.PubKey) i64 {
        self.assertCorrectPlayer(player);
        if (player == self.playerX) {
            return 1;
        }
        return 2;
    }

    fn assertCorrectPlayer(self: *const TicTacToe, player: runar.PubKey) void {
        if (self.turn == 1) {
            runar.assert(player == self.playerX);
        } else {
            runar.assert(player == self.playerO);
        }
    }

    fn assertCellEmpty(self: *const TicTacToe, position: i64) void {
        if (position == 0) {
            runar.assert(self.c0 == 0);
        } else if (position == 1) {
            runar.assert(self.c1 == 0);
        } else if (position == 2) {
            runar.assert(self.c2 == 0);
        } else if (position == 3) {
            runar.assert(self.c3 == 0);
        } else if (position == 4) {
            runar.assert(self.c4 == 0);
        } else if (position == 5) {
            runar.assert(self.c5 == 0);
        } else if (position == 6) {
            runar.assert(self.c6 == 0);
        } else if (position == 7) {
            runar.assert(self.c7 == 0);
        } else if (position == 8) {
            runar.assert(self.c8 == 0);
        } else {
            runar.assert(false);
        }
    }

    fn placeMove(self: *TicTacToe, position: i64) void {
        self.assertCellEmpty(position);
        if (position == 0) {
            self.c0 = self.turn;
        } else if (position == 1) {
            self.c1 = self.turn;
        } else if (position == 2) {
            self.c2 = self.turn;
        } else if (position == 3) {
            self.c3 = self.turn;
        } else if (position == 4) {
            self.c4 = self.turn;
        } else if (position == 5) {
            self.c5 = self.turn;
        } else if (position == 6) {
            self.c6 = self.turn;
        } else if (position == 7) {
            self.c7 = self.turn;
        } else if (position == 8) {
            self.c8 = self.turn;
        } else {
            runar.assert(false);
        }
    }

    fn getCellOrOverride(self: *const TicTacToe, index: i64, overridePos: i64, overrideVal: i64) i64 {
        if (index == overridePos) {
            return overrideVal;
        }
        if (index == 0) {
            return self.c0;
        }
        if (index == 1) {
            return self.c1;
        }
        if (index == 2) {
            return self.c2;
        }
        if (index == 3) {
            return self.c3;
        }
        if (index == 4) {
            return self.c4;
        }
        if (index == 5) {
            return self.c5;
        }
        if (index == 6) {
            return self.c6;
        }
        if (index == 7) {
            return self.c7;
        }
        if (index == 8) {
            return self.c8;
        }
        return 0;
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

        return
            (c0 == player and c1 == player and c2 == player) or
            (c3 == player and c4 == player and c5 == player) or
            (c6 == player and c7 == player and c8 == player) or
            (c0 == player and c3 == player and c6 == player) or
            (c1 == player and c4 == player and c7 == player) or
            (c2 == player and c5 == player and c8 == player) or
            (c0 == player and c4 == player and c8 == player) or
            (c2 == player and c4 == player and c6 == player);
    }

    fn countOccupied(self: *const TicTacToe) i64 {
        var count: i64 = 0;
        if (self.c0 != 0) {
            count += 1;
        }
        if (self.c1 != 0) {
            count += 1;
        }
        if (self.c2 != 0) {
            count += 1;
        }
        if (self.c3 != 0) {
            count += 1;
        }
        if (self.c4 != 0) {
            count += 1;
        }
        if (self.c5 != 0) {
            count += 1;
        }
        if (self.c6 != 0) {
            count += 1;
        }
        if (self.c7 != 0) {
            count += 1;
        }
        if (self.c8 != 0) {
            count += 1;
        }
        return count;
    }

    fn buildP2PKHOutput(self: *const TicTacToe, amount: i64, pkh: runar.ByteString) runar.ByteString {
        _ = self;
        const scriptPrefix = runar.cat("1976a914", pkh);
        const script = runar.cat(scriptPrefix, "88ac");
        return runar.cat(runar.num2bin(amount, 8), script);
    }
};
