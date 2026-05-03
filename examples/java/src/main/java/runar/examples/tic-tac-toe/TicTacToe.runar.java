package runar.examples.tictactoe;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.cat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.extractOutputHash;
import static runar.lang.Builtins.hash160;
import static runar.lang.Builtins.hash256;
import static runar.lang.Builtins.num2bin;

/**
 * TicTacToe -- on-chain Tic-Tac-Toe contract.
 *
 * <p>Ports {@code examples/ts/tic-tac-toe/TicTacToe.runar.ts} to Java.
 * Byte-identical to the TS reference: same fields, same default
 * initialisers, same method bodies, same private helpers. The
 * {@code TicTacToe.v2.runar.java} sibling expresses the same contract
 * with a {@code FixedArray<Bigint>} board; this v1 spelling uses 9
 * individual {@code Bigint} cells just like the TS source.
 *
 * <p>Two players compete on a 3x3 board. Each move is an on-chain
 * transaction. Either player can propose cancellation
 * ({@code cancelBeforeJoin} pre-join, {@code cancel} post-join with
 * both signatures). Win / tie paths use {@code extractOutputHash} to
 * pin the payout shape.
 *
 * <p>Board encoding: 0 = empty, 1 = X, 2 = O.
 */
class TicTacToe extends StatefulSmartContract {

    @Readonly PubKey playerX;
    @Readonly Bigint betAmount;
    @Readonly ByteString p2pkhPrefix = ByteString.fromHex("1976a914");
    @Readonly ByteString p2pkhSuffix = ByteString.fromHex("88ac");

    PubKey playerO = PubKey.fromHex(
        "000000000000000000000000000000000000000000000000000000000000000000"
    );
    Bigint c0 = Bigint.ZERO;
    Bigint c1 = Bigint.ZERO;
    Bigint c2 = Bigint.ZERO;
    Bigint c3 = Bigint.ZERO;
    Bigint c4 = Bigint.ZERO;
    Bigint c5 = Bigint.ZERO;
    Bigint c6 = Bigint.ZERO;
    Bigint c7 = Bigint.ZERO;
    Bigint c8 = Bigint.ZERO;
    Bigint turn = Bigint.ZERO;
    Bigint status = Bigint.ZERO;

    TicTacToe(PubKey playerX, Bigint betAmount) {
        super(playerX, betAmount);
        this.playerX = playerX;
        this.betAmount = betAmount;
    }

    /** Player O joins an open game. */
    @Public
    void join(PubKey opponentPK, Sig sig) {
        assertThat(this.status.eq(Bigint.ZERO));
        assertThat(checkSig(sig, opponentPK));
        this.playerO = opponentPK;
        this.status = Bigint.ONE;
        this.turn = Bigint.ONE;
    }

    /** A non-terminal move updates the board and flips the turn. */
    @Public
    void move(Bigint position, PubKey player, Sig sig) {
        assertThat(this.status.eq(Bigint.ONE));
        assertThat(checkSig(sig, player));
        assertCorrectPlayer(player);
        placeMove(position);
        if (this.turn.eq(Bigint.ONE)) {
            this.turn = Bigint.TWO;
        } else {
            this.turn = Bigint.ONE;
        }
    }

    /** Make a winning move. Non-mutating terminal method. */
    @Public
    void moveAndWin(Bigint position, PubKey player, Sig sig, ByteString changePkh, Bigint changeAmount) {
        assertThat(this.status.eq(Bigint.ONE));
        assertThat(checkSig(sig, player));
        assertCorrectPlayer(player);
        assertCellEmpty(position);
        assertThat(checkWinAfterMove(position, this.turn));

        Bigint totalPayout = this.betAmount.times(Bigint.TWO);
        ByteString payout = cat(
            cat(num2bin(totalPayout.value(), Bigint.of(8).value()), this.p2pkhPrefix),
            cat(hash160(player), this.p2pkhSuffix)
        );
        if (changeAmount.gt(Bigint.ZERO)) {
            ByteString change = cat(
                cat(num2bin(changeAmount.value(), Bigint.of(8).value()), this.p2pkhPrefix),
                cat(changePkh, this.p2pkhSuffix)
            );
            assertThat(hash256(cat(payout, change)).equals(extractOutputHash(this.txPreimage)));
        } else {
            assertThat(hash256(payout).equals(extractOutputHash(this.txPreimage)));
        }
    }

    /** Make a move that fills the board (tie). Non-mutating terminal method. */
    @Public
    void moveAndTie(Bigint position, PubKey player, Sig sig, ByteString changePkh, Bigint changeAmount) {
        assertThat(this.status.eq(Bigint.ONE));
        assertThat(checkSig(sig, player));
        assertCorrectPlayer(player);
        assertCellEmpty(position);
        assertThat(countOccupied().eq(Bigint.of(8)));
        assertThat(!checkWinAfterMove(position, this.turn));

        ByteString out1 = cat(
            cat(num2bin(this.betAmount.value(), Bigint.of(8).value()), this.p2pkhPrefix),
            cat(hash160(this.playerX), this.p2pkhSuffix)
        );
        ByteString out2 = cat(
            cat(num2bin(this.betAmount.value(), Bigint.of(8).value()), this.p2pkhPrefix),
            cat(hash160(this.playerO), this.p2pkhSuffix)
        );
        if (changeAmount.gt(Bigint.ZERO)) {
            ByteString change = cat(
                cat(num2bin(changeAmount.value(), Bigint.of(8).value()), this.p2pkhPrefix),
                cat(changePkh, this.p2pkhSuffix)
            );
            assertThat(hash256(cat(cat(out1, out2), change)).equals(extractOutputHash(this.txPreimage)));
        } else {
            assertThat(hash256(cat(out1, out2)).equals(extractOutputHash(this.txPreimage)));
        }
    }

    /** Player X cancels before anyone joins. Non-mutating terminal method. */
    @Public
    void cancelBeforeJoin(Sig sig, ByteString changePkh, Bigint changeAmount) {
        assertThat(this.status.eq(Bigint.ZERO));
        assertThat(checkSig(sig, this.playerX));
        ByteString payout = cat(
            cat(num2bin(this.betAmount.value(), Bigint.of(8).value()), this.p2pkhPrefix),
            cat(hash160(this.playerX), this.p2pkhSuffix)
        );
        if (changeAmount.gt(Bigint.ZERO)) {
            ByteString change = cat(
                cat(num2bin(changeAmount.value(), Bigint.of(8).value()), this.p2pkhPrefix),
                cat(changePkh, this.p2pkhSuffix)
            );
            assertThat(hash256(cat(payout, change)).equals(extractOutputHash(this.txPreimage)));
        } else {
            assertThat(hash256(payout).equals(extractOutputHash(this.txPreimage)));
        }
    }

    /** Both players agree to cancel. Non-mutating terminal method. */
    @Public
    void cancel(Sig sigX, Sig sigO, ByteString changePkh, Bigint changeAmount) {
        ByteString out1 = cat(
            cat(num2bin(this.betAmount.value(), Bigint.of(8).value()), this.p2pkhPrefix),
            cat(hash160(this.playerX), this.p2pkhSuffix)
        );
        ByteString out2 = cat(
            cat(num2bin(this.betAmount.value(), Bigint.of(8).value()), this.p2pkhPrefix),
            cat(hash160(this.playerO), this.p2pkhSuffix)
        );
        if (changeAmount.gt(Bigint.ZERO)) {
            ByteString change = cat(
                cat(num2bin(changeAmount.value(), Bigint.of(8).value()), this.p2pkhPrefix),
                cat(changePkh, this.p2pkhSuffix)
            );
            assertThat(hash256(cat(cat(out1, out2), change)).equals(extractOutputHash(this.txPreimage)));
        } else {
            assertThat(hash256(cat(out1, out2)).equals(extractOutputHash(this.txPreimage)));
        }
        assertThat(checkSig(sigX, this.playerX));
        assertThat(checkSig(sigO, this.playerO));
    }

    // --- Private helpers -------------------------------------------------

    private void assertCorrectPlayer(PubKey player) {
        if (this.turn.eq(Bigint.ONE)) {
            assertThat(player.equals(this.playerX));
        } else {
            assertThat(player.equals(this.playerO));
        }
    }

    private void assertCellEmpty(Bigint position) {
        if      (position.eq(Bigint.ZERO))  { assertThat(this.c0.eq(Bigint.ZERO)); }
        else if (position.eq(Bigint.ONE))   { assertThat(this.c1.eq(Bigint.ZERO)); }
        else if (position.eq(Bigint.TWO))   { assertThat(this.c2.eq(Bigint.ZERO)); }
        else if (position.eq(Bigint.of(3))) { assertThat(this.c3.eq(Bigint.ZERO)); }
        else if (position.eq(Bigint.of(4))) { assertThat(this.c4.eq(Bigint.ZERO)); }
        else if (position.eq(Bigint.of(5))) { assertThat(this.c5.eq(Bigint.ZERO)); }
        else if (position.eq(Bigint.of(6))) { assertThat(this.c6.eq(Bigint.ZERO)); }
        else if (position.eq(Bigint.of(7))) { assertThat(this.c7.eq(Bigint.ZERO)); }
        else if (position.eq(Bigint.of(8))) { assertThat(this.c8.eq(Bigint.ZERO)); }
        else                                { assertThat(false); }
    }

    private void placeMove(Bigint position) {
        assertCellEmpty(position);
        if      (position.eq(Bigint.ZERO))  { this.c0 = this.turn; }
        else if (position.eq(Bigint.ONE))   { this.c1 = this.turn; }
        else if (position.eq(Bigint.TWO))   { this.c2 = this.turn; }
        else if (position.eq(Bigint.of(3))) { this.c3 = this.turn; }
        else if (position.eq(Bigint.of(4))) { this.c4 = this.turn; }
        else if (position.eq(Bigint.of(5))) { this.c5 = this.turn; }
        else if (position.eq(Bigint.of(6))) { this.c6 = this.turn; }
        else if (position.eq(Bigint.of(7))) { this.c7 = this.turn; }
        else if (position.eq(Bigint.of(8))) { this.c8 = this.turn; }
        else                                { assertThat(false); }
    }

    private Bigint getCellOrOverride(Bigint cellIndex, Bigint overridePos, Bigint overrideVal) {
        if (cellIndex.eq(overridePos)) return overrideVal;
        if      (cellIndex.eq(Bigint.ZERO))  return this.c0;
        else if (cellIndex.eq(Bigint.ONE))   return this.c1;
        else if (cellIndex.eq(Bigint.TWO))   return this.c2;
        else if (cellIndex.eq(Bigint.of(3))) return this.c3;
        else if (cellIndex.eq(Bigint.of(4))) return this.c4;
        else if (cellIndex.eq(Bigint.of(5))) return this.c5;
        else if (cellIndex.eq(Bigint.of(6))) return this.c6;
        else if (cellIndex.eq(Bigint.of(7))) return this.c7;
        else                                 return this.c8;
    }

    private boolean checkWinAfterMove(Bigint position, Bigint player) {
        Bigint v0 = getCellOrOverride(Bigint.ZERO,  position, player);
        Bigint v1 = getCellOrOverride(Bigint.ONE,   position, player);
        Bigint v2 = getCellOrOverride(Bigint.TWO,   position, player);
        Bigint v3 = getCellOrOverride(Bigint.of(3), position, player);
        Bigint v4 = getCellOrOverride(Bigint.of(4), position, player);
        Bigint v5 = getCellOrOverride(Bigint.of(5), position, player);
        Bigint v6 = getCellOrOverride(Bigint.of(6), position, player);
        Bigint v7 = getCellOrOverride(Bigint.of(7), position, player);
        Bigint v8 = getCellOrOverride(Bigint.of(8), position, player);

        if (v0.eq(player) && v1.eq(player) && v2.eq(player)) return true;
        if (v3.eq(player) && v4.eq(player) && v5.eq(player)) return true;
        if (v6.eq(player) && v7.eq(player) && v8.eq(player)) return true;
        if (v0.eq(player) && v3.eq(player) && v6.eq(player)) return true;
        if (v1.eq(player) && v4.eq(player) && v7.eq(player)) return true;
        if (v2.eq(player) && v5.eq(player) && v8.eq(player)) return true;
        if (v0.eq(player) && v4.eq(player) && v8.eq(player)) return true;
        if (v2.eq(player) && v4.eq(player) && v6.eq(player)) return true;
        return false;
    }

    private Bigint countOccupied() {
        Bigint count = Bigint.ZERO;
        if (this.c0.neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        if (this.c1.neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        if (this.c2.neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        if (this.c3.neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        if (this.c4.neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        if (this.c5.neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        if (this.c6.neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        if (this.c7.neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        if (this.c8.neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        return count;
    }
}
