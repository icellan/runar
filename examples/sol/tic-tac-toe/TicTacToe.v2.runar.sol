pragma runar ^0.1.0;

/// @title TicTacToe (v2)
/// @notice Solidity-like port of `examples/ts/tic-tac-toe/TicTacToe.v2.runar.ts`.
///
/// Semantically identical to `TicTacToe.runar.sol`, with the 9 board cells
/// expressed as a single fixed-size array instead of nine scalar fields.
/// Solidity's native `T[N]` suffix declares it; the Rúnar frontend lowers
/// `bigint[9]` to `FixedArray<bigint, 9>`, and the `expand-fixed-arrays` pass
/// desugars that back into the same nine scalar siblings v1 declares by hand —
/// so this file compiles to byte-identical Bitcoin Script.
///
/// R-208: v2 shipped in six surfaces and not in this one. The dynamic
/// FixedArray WRITE (`this.board[position] = this.turn`) is what the missing
/// coverage was about.
contract TicTacToe is StatefulSmartContract {
    PubKey immutable playerX;
    bigint immutable betAmount;
    ByteString immutable p2pkhPrefix = 0x1976a914;
    ByteString immutable p2pkhSuffix = 0x88ac;

    PubKey playerO = 0x000000000000000000000000000000000000000000000000000000000000000000;
    bigint[9] board = [0, 0, 0, 0, 0, 0, 0, 0, 0];
    bigint turn = 0;
    bigint status = 0;

    constructor(PubKey _playerX, bigint _betAmount) {
        playerX = _playerX;
        betAmount = _betAmount;
    }

    /// @notice Player O joins the game.
    function join(PubKey opponentPK, Sig sig) public {
        require(this.status == 0);
        require(checkSig(sig, opponentPK));
        this.playerO = opponentPK;
        this.status = 1;
        this.turn = 1;
    }

    /// @notice Make a non-terminal move. Updates board and flips turn.
    function move(bigint position, PubKey player, Sig sig) public {
        require(this.status == 1);
        require(checkSig(sig, player));
        this.assertCorrectPlayer(player);
        this.placeMove(position);
        if (this.turn == 1) {
            this.turn = 2;
        } else {
            this.turn = 1;
        }
    }

    /// @notice Make a winning move. Terminal method.
    function moveAndWin(bigint position, PubKey player, Sig sig, ByteString changePKH, bigint changeAmount) public {
        require(this.status == 1);
        require(checkSig(sig, player));
        this.assertCorrectPlayer(player);
        this.assertCellEmpty(position);
        require(this.checkWinAfterMove(position, this.turn));

        bigint totalPayout = this.betAmount * 2;
        ByteString payout = cat(cat(num2bin(totalPayout, 8), this.p2pkhPrefix), cat(hash160(player), this.p2pkhSuffix));
        if (changeAmount > 0) {
            ByteString change = cat(cat(num2bin(changeAmount, 8), this.p2pkhPrefix), cat(changePKH, this.p2pkhSuffix));
            require(hash256(cat(payout, change)) == extractOutputHash(this.txPreimage));
        } else {
            require(hash256(payout) == extractOutputHash(this.txPreimage));
        }
    }

    /// @notice Make a move that fills the board (tie). Terminal method.
    function moveAndTie(bigint position, PubKey player, Sig sig, ByteString changePKH, bigint changeAmount) public {
        require(this.status == 1);
        require(checkSig(sig, player));
        this.assertCorrectPlayer(player);
        this.assertCellEmpty(position);
        require(this.countOccupied() == 8);
        require(!this.checkWinAfterMove(position, this.turn));

        ByteString out1 = cat(cat(num2bin(this.betAmount, 8), this.p2pkhPrefix), cat(hash160(this.playerX), this.p2pkhSuffix));
        ByteString out2 = cat(cat(num2bin(this.betAmount, 8), this.p2pkhPrefix), cat(hash160(this.playerO), this.p2pkhSuffix));
        if (changeAmount > 0) {
            ByteString change = cat(cat(num2bin(changeAmount, 8), this.p2pkhPrefix), cat(changePKH, this.p2pkhSuffix));
            require(hash256(cat(cat(out1, out2), change)) == extractOutputHash(this.txPreimage));
        } else {
            require(hash256(cat(out1, out2)) == extractOutputHash(this.txPreimage));
        }
    }

    /// @notice Player X cancels before anyone joins. Terminal method.
    function cancelBeforeJoin(Sig sig, ByteString changePKH, bigint changeAmount) public {
        require(this.status == 0);
        require(checkSig(sig, this.playerX));
        ByteString payout = cat(cat(num2bin(this.betAmount, 8), this.p2pkhPrefix), cat(hash160(this.playerX), this.p2pkhSuffix));
        if (changeAmount > 0) {
            ByteString change = cat(cat(num2bin(changeAmount, 8), this.p2pkhPrefix), cat(changePKH, this.p2pkhSuffix));
            require(hash256(cat(payout, change)) == extractOutputHash(this.txPreimage));
        } else {
            require(hash256(payout) == extractOutputHash(this.txPreimage));
        }
    }

    /// @notice Both players agree to cancel. Terminal method.
    function cancel(Sig sigX, Sig sigO, ByteString changePKH, bigint changeAmount) public {
        ByteString out1 = cat(cat(num2bin(this.betAmount, 8), this.p2pkhPrefix), cat(hash160(this.playerX), this.p2pkhSuffix));
        ByteString out2 = cat(cat(num2bin(this.betAmount, 8), this.p2pkhPrefix), cat(hash160(this.playerO), this.p2pkhSuffix));
        if (changeAmount > 0) {
            ByteString change = cat(cat(num2bin(changeAmount, 8), this.p2pkhPrefix), cat(changePKH, this.p2pkhSuffix));
            require(hash256(cat(cat(out1, out2), change)) == extractOutputHash(this.txPreimage));
        } else {
            require(hash256(cat(out1, out2)) == extractOutputHash(this.txPreimage));
        }
        require(checkSig(sigX, this.playerX));
        require(checkSig(sigO, this.playerO));
    }

    // --- Private helpers ---

    function assertCorrectPlayer(PubKey player) private {
        if (this.turn == 1) {
            require(player == this.playerX);
        } else {
            require(player == this.playerO);
        }
    }

    function assertCellEmpty(bigint position) private {
        if (position == 0) {
            require(this.board[0] == 0);
        } else {
            if (position == 1) {
                require(this.board[1] == 0);
            } else {
                if (position == 2) {
                    require(this.board[2] == 0);
                } else {
                    if (position == 3) {
                        require(this.board[3] == 0);
                    } else {
                        if (position == 4) {
                            require(this.board[4] == 0);
                        } else {
                            if (position == 5) {
                                require(this.board[5] == 0);
                            } else {
                                if (position == 6) {
                                    require(this.board[6] == 0);
                                } else {
                                    if (position == 7) {
                                        require(this.board[7] == 0);
                                    } else {
                                        if (position == 8) {
                                            require(this.board[8] == 0);
                                        } else {
                                            require(false);
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

    function placeMove(bigint position) private {
        this.assertCellEmpty(position);
        this.board[position] = this.turn;
    }

    function getCellOrOverride(bigint cellIndex, bigint overridePos, bigint overrideVal) private returns (bigint) {
        if (cellIndex == overridePos) {
            return overrideVal;
        }
        if (cellIndex == 0) {
            return this.board[0];
        } else {
            if (cellIndex == 1) {
                return this.board[1];
            } else {
                if (cellIndex == 2) {
                    return this.board[2];
                } else {
                    if (cellIndex == 3) {
                        return this.board[3];
                    } else {
                        if (cellIndex == 4) {
                            return this.board[4];
                        } else {
                            if (cellIndex == 5) {
                                return this.board[5];
                            } else {
                                if (cellIndex == 6) {
                                    return this.board[6];
                                } else {
                                    if (cellIndex == 7) {
                                        return this.board[7];
                                    } else {
                                        return this.board[8];
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    function checkWinAfterMove(bigint position, bigint player) private returns (bool) {
        bigint v0 = this.getCellOrOverride(0, position, player);
        bigint v1 = this.getCellOrOverride(1, position, player);
        bigint v2 = this.getCellOrOverride(2, position, player);
        bigint v3 = this.getCellOrOverride(3, position, player);
        bigint v4 = this.getCellOrOverride(4, position, player);
        bigint v5 = this.getCellOrOverride(5, position, player);
        bigint v6 = this.getCellOrOverride(6, position, player);
        bigint v7 = this.getCellOrOverride(7, position, player);
        bigint v8 = this.getCellOrOverride(8, position, player);

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

    function countOccupied() private returns (bigint) {
        bigint count = 0;
        if (this.board[0] != 0) { count = count + 1; }
        if (this.board[1] != 0) { count = count + 1; }
        if (this.board[2] != 0) { count = count + 1; }
        if (this.board[3] != 0) { count = count + 1; }
        if (this.board[4] != 0) { count = count + 1; }
        if (this.board[5] != 0) { count = count + 1; }
        if (this.board[6] != 0) { count = count + 1; }
        if (this.board[7] != 0) { count = count + 1; }
        if (this.board[8] != 0) { count = count + 1; }
        return count;
    }
}
