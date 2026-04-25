package runar.examples.tictactoev2;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.FixedArray;
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
 * TicTacToe v2 -- {@link FixedArray} rewrite of the hand-rolled v1
 * contract.
 *
 * <p>Ports {@code examples/python/tic-tac-toe/TicTacToe.v2.runar.py} to
 * Java. Semantically identical to {@code TicTacToe.runar.java}, with the
 * 9 board cells expressed as a single
 * {@code FixedArray<Bigint>} property of length 9. The Rúnar compiler's
 * {@code expand_fixed_arrays} pass desugars this to the same 9 scalar
 * siblings that v1 declares manually, so this file must compile to
 * byte-identical Bitcoin Script.
 */
class TicTacToe extends StatefulSmartContract {

    private static final ByteString P2PKH_PREFIX_DEFAULT = ByteString.fromHex("1976a914");
    private static final ByteString P2PKH_SUFFIX_DEFAULT = ByteString.fromHex("88ac");
    private static final PubKey ZERO_PUBKEY = PubKey.fromHex(
        "000000000000000000000000000000000000000000000000000000000000000000"
    );
    private static final FixedArray<Bigint> ZERO_BOARD = FixedArray.of(
        9,
        Bigint.ZERO, Bigint.ZERO, Bigint.ZERO,
        Bigint.ZERO, Bigint.ZERO, Bigint.ZERO,
        Bigint.ZERO, Bigint.ZERO, Bigint.ZERO
    );

    @Readonly PubKey playerX;
    @Readonly Bigint betAmount;
    @Readonly ByteString p2pkhPrefix = P2PKH_PREFIX_DEFAULT;
    @Readonly ByteString p2pkhSuffix = P2PKH_SUFFIX_DEFAULT;

    PubKey playerO = ZERO_PUBKEY;
    FixedArray<Bigint> board = ZERO_BOARD;
    Bigint turn = Bigint.ZERO;
    Bigint status = Bigint.ZERO;

    TicTacToe(PubKey playerX, Bigint betAmount) {
        super(playerX, betAmount);
        this.playerX = playerX;
        this.betAmount = betAmount;
    }

    @Public
    void join(PubKey opponentPK, Sig sig) {
        assertThat(this.status.eq(Bigint.ZERO));
        assertThat(checkSig(sig, opponentPK));
        this.playerO = opponentPK;
        this.status = Bigint.ONE;
        this.turn = Bigint.ONE;
    }

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
        if      (position.eq(Bigint.ZERO))  { assertThat(this.board.get(0).eq(Bigint.ZERO)); }
        else if (position.eq(Bigint.ONE))   { assertThat(this.board.get(1).eq(Bigint.ZERO)); }
        else if (position.eq(Bigint.TWO))   { assertThat(this.board.get(2).eq(Bigint.ZERO)); }
        else if (position.eq(Bigint.of(3))) { assertThat(this.board.get(3).eq(Bigint.ZERO)); }
        else if (position.eq(Bigint.of(4))) { assertThat(this.board.get(4).eq(Bigint.ZERO)); }
        else if (position.eq(Bigint.of(5))) { assertThat(this.board.get(5).eq(Bigint.ZERO)); }
        else if (position.eq(Bigint.of(6))) { assertThat(this.board.get(6).eq(Bigint.ZERO)); }
        else if (position.eq(Bigint.of(7))) { assertThat(this.board.get(7).eq(Bigint.ZERO)); }
        else if (position.eq(Bigint.of(8))) { assertThat(this.board.get(8).eq(Bigint.ZERO)); }
        else                                { assertThat(false); }
    }

    private void placeMove(Bigint position) {
        assertCellEmpty(position);
        // FixedArray is immutable; rebuild it with the slot updated. The Rúnar
        // compiler's expand_fixed_arrays pass turns this into 9 scalar writes.
        java.util.List<Bigint> next = new java.util.ArrayList<>(this.board.items());
        if      (position.eq(Bigint.ZERO))  next.set(0, this.turn);
        else if (position.eq(Bigint.ONE))   next.set(1, this.turn);
        else if (position.eq(Bigint.TWO))   next.set(2, this.turn);
        else if (position.eq(Bigint.of(3))) next.set(3, this.turn);
        else if (position.eq(Bigint.of(4))) next.set(4, this.turn);
        else if (position.eq(Bigint.of(5))) next.set(5, this.turn);
        else if (position.eq(Bigint.of(6))) next.set(6, this.turn);
        else if (position.eq(Bigint.of(7))) next.set(7, this.turn);
        else if (position.eq(Bigint.of(8))) next.set(8, this.turn);
        else                                { assertThat(false); }
        this.board = new FixedArray<>(9, next);
    }

    private Bigint getCellOrOverride(Bigint cellIndex, Bigint overridePos, Bigint overrideVal) {
        if (cellIndex.eq(overridePos)) return overrideVal;
        if      (cellIndex.eq(Bigint.ZERO))  return this.board.get(0);
        else if (cellIndex.eq(Bigint.ONE))   return this.board.get(1);
        else if (cellIndex.eq(Bigint.TWO))   return this.board.get(2);
        else if (cellIndex.eq(Bigint.of(3))) return this.board.get(3);
        else if (cellIndex.eq(Bigint.of(4))) return this.board.get(4);
        else if (cellIndex.eq(Bigint.of(5))) return this.board.get(5);
        else if (cellIndex.eq(Bigint.of(6))) return this.board.get(6);
        else if (cellIndex.eq(Bigint.of(7))) return this.board.get(7);
        else                                 return this.board.get(8);
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
        if (this.board.get(0).neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        if (this.board.get(1).neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        if (this.board.get(2).neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        if (this.board.get(3).neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        if (this.board.get(4).neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        if (this.board.get(5).neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        if (this.board.get(6).neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        if (this.board.get(7).neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        if (this.board.get(8).neq(Bigint.ZERO)) count = count.plus(Bigint.ONE);
        return count;
    }
}
