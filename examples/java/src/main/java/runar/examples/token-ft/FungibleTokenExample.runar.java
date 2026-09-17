package runar.examples.tokenft;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.bin2num;
import static runar.lang.Builtins.cat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.extractHashPrevouts;
import static runar.lang.Builtins.extractOutpoint;
import static runar.lang.Builtins.extractScriptCode;
import static runar.lang.Builtins.hash256;
import static runar.lang.Builtins.len;
import static runar.lang.Builtins.num2bin;
import static runar.lang.Builtins.substr;

/**
 * FungibleToken -- a UTXO-based fungible token using Rúnar's multi-output
 * ({@code addOutput}) facility.
 *
 * <p>Ports {@code examples/python/token-ft/FungibleTokenExample.runar.py}
 * to Java. Demonstrates how to model divisible token balances that can be
 * split, transferred, and merged -- similar to colored coins or SLP-style
 * tokens but enforced entirely by Bitcoin Script.
 *
 * <h2>UTXO token model vs account model</h2>
 * <p>Unlike Ethereum ERC-20 where balances live in a global mapping, each
 * token "balance" here is a separate UTXO. The UTXO carries state: the
 * current owner (PubKey), balance (Bigint), and an immutable token id
 * (ByteString). Transferring tokens means spending one UTXO and creating
 * new ones with updated state.
 *
 * <h2>Operations</h2>
 * <ul>
 *   <li>{@code transfer} -- 1 UTXO -> 2 UTXOs (recipient + change back).</li>
 *   <li>{@code send}     -- 1 UTXO -> 1 UTXO (full balance to new owner).</li>
 *   <li>{@code merge}    -- 2 UTXOs -> 1 UTXO (consolidate two token UTXOs).</li>
 * </ul>
 *
 * <h2>Companion-parent merge (W8 / SoloMerge)</h2>
 * <p>{@code merge} authenticates the companion via {@code otherParentTx}.
 * Input count is not identity. Pin:
 * {@code packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts}.
 *
 * <p>Authorization: all operations require the current owner's ECDSA
 * signature via {@code checkSig}.
 */
class FungibleToken extends StatefulSmartContract {

    PubKey owner;                           // Current owner, mutable
    Bigint balance;                         // Primary token balance, mutable
    Bigint mergeBalance;                    // Secondary balance slot used during merge, mutable (normally 0)
    @Readonly ByteString tokenId;           // Unique identifier, immutable

    FungibleToken(PubKey owner, Bigint balance, Bigint mergeBalance, ByteString tokenId) {
        super(owner, balance, mergeBalance, tokenId);
        this.owner = owner;
        this.balance = balance;
        this.mergeBalance = mergeBalance;
        this.tokenId = tokenId;
    }

    /**
     * Transfer tokens to a recipient. If the full balance is sent, produces
     * one output; otherwise produces two outputs (recipient + change back
     * to sender).
     */
    @Public
    void transfer(Sig sig, PubKey to, Bigint amount, Bigint outputSatoshis) {
        assertThat(checkSig(sig, this.owner));
        assertThat(outputSatoshis.ge(Bigint.ONE));
        Bigint totalBalance = this.balance.plus(this.mergeBalance);
        assertThat(amount.gt(Bigint.ZERO));
        assertThat(amount.le(totalBalance));

        // First output: recipient receives `amount` tokens
        this.addOutput(outputSatoshis, to, amount, Bigint.ZERO);
        // Second output: sender keeps the remaining balance as change (skip if fully spent)
        if (amount.lt(totalBalance)) {
            this.addOutput(outputSatoshis, this.owner, totalBalance.minus(amount), Bigint.ZERO);
        }
    }

    /**
     * Simple send: 1 UTXO -> 1 UTXO. Transfers the entire balance to a
     * new owner.
     */
    @Public
    void send(Sig sig, PubKey to, Bigint outputSatoshis) {
        assertThat(checkSig(sig, this.owner));
        assertThat(outputSatoshis.ge(Bigint.ONE));
        this.addOutput(outputSatoshis, to, this.balance.plus(this.mergeBalance), Bigint.ZERO);
    }

    /**
     * Merge: 2 UTXOs -&gt; 1 UTXO. Companion-parent merge (W8).
     */
    @Public
    void merge(Sig sig, Bigint otherBalance, ByteString allPrevouts, ByteString otherParentTx, Bigint outputSatoshis) {
        assertThat(checkSig(sig, this.owner));
        assertThat(outputSatoshis.ge(Bigint.ONE));
        assertThat(otherBalance.ge(Bigint.ZERO));
        assertThat(len(this.tokenId).gt(Bigint.ZERO));

        ByteString pad00 = num2bin(Bigint.ZERO, Bigint.ONE);
        assertThat(hash256(allPrevouts).equals(extractHashPrevouts(this.txPreimage)));
        assertThat(len(allPrevouts).ge(Bigint.of(72)));

        ByteString myOutpoint = extractOutpoint(this.txPreimage);
        ByteString firstOutpoint = substr(allPrevouts, Bigint.ZERO.value(), Bigint.of(36).value());
        ByteString secondOutpoint = substr(allPrevouts, Bigint.of(36).value(), Bigint.of(36).value());
        ByteString companionOutpoint = firstOutpoint;
        if (myOutpoint.equals(firstOutpoint)) {
            companionOutpoint = secondOutpoint;
        } else {
            assertThat(myOutpoint.equals(secondOutpoint));
        }
        ByteString companionTxid = substr(companionOutpoint, Bigint.ZERO.value(), Bigint.of(32).value());
        Bigint companionVout = Bigint.of(bin2num(cat(substr(companionOutpoint, Bigint.of(32).value(), Bigint.of(4).value()), pad00)));
        assertThat(companionVout.eq(Bigint.ZERO));
        assertThat(hash256(otherParentTx).equals(companionTxid));

        Bigint inCount = Bigint.of(bin2num(cat(substr(otherParentTx, Bigint.of(4).value(), Bigint.ONE.value()), pad00)));
        assertThat(inCount.ge(Bigint.ONE));
        assertThat(inCount.le(Bigint.of(3)));
        Bigint off = Bigint.of(5);
        if (Bigint.ZERO.lt(inCount)) {
            Bigint sl = Bigint.of(bin2num(cat(substr(otherParentTx, off.plus(Bigint.of(36)).value(), Bigint.ONE.value()), pad00)));
            assertThat(sl.lt(Bigint.of(253)));
            off = off.plus(Bigint.of(36)).plus(Bigint.ONE).plus(sl).plus(Bigint.of(4));
        }
        if (Bigint.ONE.lt(inCount)) {
            Bigint sl = Bigint.of(bin2num(cat(substr(otherParentTx, off.plus(Bigint.of(36)).value(), Bigint.ONE.value()), pad00)));
            assertThat(sl.lt(Bigint.of(253)));
            off = off.plus(Bigint.of(36)).plus(Bigint.ONE).plus(sl).plus(Bigint.of(4));
        }
        if (Bigint.of(2).lt(inCount)) {
            Bigint sl = Bigint.of(bin2num(cat(substr(otherParentTx, off.plus(Bigint.of(36)).value(), Bigint.ONE.value()), pad00)));
            assertThat(sl.lt(Bigint.of(253)));
            off = off.plus(Bigint.of(36)).plus(Bigint.ONE).plus(sl).plus(Bigint.of(4));
        }
        Bigint outCount = Bigint.of(bin2num(cat(substr(otherParentTx, off.value(), Bigint.ONE.value()), pad00)));
        assertThat(outCount.ge(Bigint.ONE));
        Bigint marker = Bigint.of(bin2num(cat(substr(otherParentTx, off.plus(Bigint.of(9)).value(), Bigint.ONE.value()), pad00)));
        assertThat(marker.eq(Bigint.of(253)));
        Bigint scriptLen = Bigint.of(bin2num(cat(substr(otherParentTx, off.plus(Bigint.of(10)).value(), Bigint.of(2).value()), pad00)));
        Bigint scriptStart = off.plus(Bigint.of(12));
        assertThat(len(otherParentTx).ge(scriptStart.plus(scriptLen)));
        ByteString companionScript = substr(otherParentTx, scriptStart.value(), scriptLen.value());
        assertThat(scriptLen.gt(Bigint.of(49)));

        ByteString sc = extractScriptCode(this.txPreimage);
        Bigint scMarker = Bigint.of(bin2num(cat(substr(sc, Bigint.ZERO.value(), Bigint.ONE.value()), pad00)));
        assertThat(scMarker.eq(Bigint.of(253)));
        ByteString myBody = substr(sc, Bigint.of(3).value(), len(sc).minus(Bigint.of(3)).value());
        ByteString companionBody = substr(companionScript, Bigint.of(2).value(), scriptLen.minus(Bigint.of(2)).value());
        assertThat(len(myBody).eq(len(companionBody)));
        assertThat(len(myBody).gt(Bigint.of(49)));
        assertThat(substr(myBody, Bigint.ZERO.value(), len(myBody).minus(Bigint.of(49)).value()).equals(
            substr(companionBody, Bigint.ZERO.value(), len(companionBody).minus(Bigint.of(49)).value())));

        Bigint otherPrimary = Bigint.of(bin2num(cat(substr(companionScript, scriptLen.minus(Bigint.of(16)).value(), Bigint.of(8).value()), pad00)));
        Bigint otherMerge = Bigint.of(bin2num(cat(substr(companionScript, scriptLen.minus(Bigint.of(8)).value(), Bigint.of(8).value()), pad00)));
        assertThat(otherPrimary.plus(otherMerge).eq(otherBalance));

        Bigint myBalance = this.balance.plus(this.mergeBalance);
        if (myOutpoint.equals(firstOutpoint)) {
            this.addOutput(outputSatoshis, this.owner, myBalance, otherBalance);
        } else {
            this.addOutput(outputSatoshis, this.owner, otherBalance, myBalance);
        }
    }
}
