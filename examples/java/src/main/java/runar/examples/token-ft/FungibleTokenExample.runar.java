package runar.examples.tokenft;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.extractHashPrevouts;
import static runar.lang.Builtins.extractOutpoint;
import static runar.lang.Builtins.hash256;
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
 * <h2>Secure merge design</h2>
 * <p>The merge uses position-dependent output construction verified via
 * {@code hashPrevouts}. Each input reads its own balance from its locking
 * script (verified by OP_PUSH_TX) and writes it to a specific slot in the
 * output based on its position in the transaction. Since {@code hashOutputs}
 * forces both inputs to agree on the exact same output, each input's
 * claimed {@code otherBalance} must equal the other input's real verified
 * balance. This prevents the inflation attack where an attacker lies about
 * {@code otherBalance}.
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
     * Secure merge: 2 UTXOs -> 1 UTXO. Consolidates two token UTXOs.
     */
    @Public
    void merge(Sig sig, Bigint otherBalance, ByteString allPrevouts, Bigint outputSatoshis) {
        assertThat(checkSig(sig, this.owner));
        assertThat(outputSatoshis.ge(Bigint.ONE));
        assertThat(otherBalance.ge(Bigint.ZERO));

        // Verify allPrevouts is authentic (matches the actual transaction inputs)
        assertThat(hash256(allPrevouts).equals(extractHashPrevouts(this.txPreimage)));

        // Determine position: am I the first contract input?
        ByteString myOutpoint = extractOutpoint(this.txPreimage);
        ByteString firstOutpoint = substr(allPrevouts, Bigint.ZERO.value(), Bigint.of(36).value());
        Bigint myBalance = this.balance.plus(this.mergeBalance);

        if (myOutpoint.equals(firstOutpoint)) {
            // I'm input 0: my verified balance goes to slot 0
            this.addOutput(outputSatoshis, this.owner, myBalance, otherBalance);
        } else {
            // I'm input 1: my verified balance goes to slot 1
            this.addOutput(outputSatoshis, this.owner, otherBalance, myBalance);
        }
    }
}
