pragma runar ^0.1.0;

/// @title TicTacToe
/// @notice On-chain Tic-Tac-Toe contract.
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
/// 1. Player X deploys the contract with their bet amount.
/// 2. Player O calls join to enter the game, adding their bet.
/// 3. Players alternate calling move (non-terminal) or
///    moveAndWin / moveAndTie (terminal).
/// 4. Either player can propose cancel (requires both signatures).
contract TicTacToe is StatefulSmartContract {
    PubKey immutable playerX;
    bigint immutable betAmount;
    ByteString immutable p2pkhPrefix = 0x1976a914;
    ByteString immutable p2pkhSuffix = 0x88ac;

    PubKey playerO = 0x000000000000000000000000000000000000000000000000000000000000000000;
    bigint c0 = 0;
    bigint c1 = 0;
    bigint c2 = 0;
    bigint c3 = 0;
    bigint c4 = 0;
    bigint c5 = 0;
    bigint c6 = 0;
    bigint c7 = 0;
    bigint c8 = 0;
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
            require(this.c0 == 0);
        } else {
            if (position == 1) {
                require(this.c1 == 0);
            } else {
                if (position == 2) {
                    require(this.c2 == 0);
                } else {
                    if (position == 3) {
                        require(this.c3 == 0);
                    } else {
                        if (position == 4) {
                            require(this.c4 == 0);
                        } else {
                            if (position == 5) {
                                require(this.c5 == 0);
                            } else {
                                if (position == 6) {
                                    require(this.c6 == 0);
                                } else {
                                    if (position == 7) {
                                        require(this.c7 == 0);
                                    } else {
                                        if (position == 8) {
                                            require(this.c8 == 0);
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
        if (position == 0) {
            this.c0 = this.turn;
        } else {
            if (position == 1) {
                this.c1 = this.turn;
            } else {
                if (position == 2) {
                    this.c2 = this.turn;
                } else {
                    if (position == 3) {
                        this.c3 = this.turn;
                    } else {
                        if (position == 4) {
                            this.c4 = this.turn;
                        } else {
                            if (position == 5) {
                                this.c5 = this.turn;
                            } else {
                                if (position == 6) {
                                    this.c6 = this.turn;
                                } else {
                                    if (position == 7) {
                                        this.c7 = this.turn;
                                    } else {
                                        if (position == 8) {
                                            this.c8 = this.turn;
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

    function getCellOrOverride(bigint cellIndex, bigint overridePos, bigint overrideVal) private returns (bigint) {
        if (cellIndex == overridePos) {
            return overrideVal;
        }
        if (cellIndex == 0) {
            return this.c0;
        } else {
            if (cellIndex == 1) {
                return this.c1;
            } else {
                if (cellIndex == 2) {
                    return this.c2;
                } else {
                    if (cellIndex == 3) {
                        return this.c3;
                    } else {
                        if (cellIndex == 4) {
                            return this.c4;
                        } else {
                            if (cellIndex == 5) {
                                return this.c5;
                            } else {
                                if (cellIndex == 6) {
                                    return this.c6;
                                } else {
                                    if (cellIndex == 7) {
                                        return this.c7;
                                    } else {
                                        return this.c8;
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
        if (this.c0 != 0) { count = count + 1; }
        if (this.c1 != 0) { count = count + 1; }
        if (this.c2 != 0) { count = count + 1; }
        if (this.c3 != 0) { count = count + 1; }
        if (this.c4 != 0) { count = count + 1; }
        if (this.c5 != 0) { count = count + 1; }
        if (this.c6 != 0) { count = count + 1; }
        if (this.c7 != 0) { count = count + 1; }
        if (this.c8 != 0) { count = count + 1; }
        return count;
    }
}
