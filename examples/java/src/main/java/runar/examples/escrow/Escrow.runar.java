package runar.examples.escrow;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;

/**
 * Three-party escrow contract for marketplace payment protection.
 *
 * <p>Holds funds in a UTXO until two parties jointly authorize a spend.
 * The buyer deposits funds by sending to this contract's locking script.
 * Two spending paths allow funds to move depending on the transaction
 * outcome:
 *
 * <ul>
 *   <li>{@link #release} -- seller + arbiter both sign to release funds
 *       to the seller (e.g., goods delivered successfully).</li>
 *   <li>{@link #refund} -- buyer + arbiter both sign to refund funds to
 *       the buyer (e.g., dispute resolved in buyer's favor).</li>
 * </ul>
 *
 * <p>The arbiter serves as the trust anchor -- no single party can act
 * alone. Both paths require two signatures (dual-sig), ensuring the
 * arbiter must co-sign every spend. This prevents unilateral action by
 * either party.
 *
 * <p><strong>Script layout:</strong>
 * <pre>
 *   Unlocking: &lt;methodIndex&gt; &lt;sig1&gt; &lt;sig2&gt;
 *   Locking:   OP_IF &lt;seller checkSig&gt; &lt;arbiter checkSig&gt;
 *              OP_ELSE &lt;buyer checkSig&gt; &lt;arbiter checkSig&gt; OP_ENDIF
 * </pre>
 *
 * <p>This is a stateless contract ({@link SmartContract}). The three
 * public keys are {@code @Readonly} constructor parameters baked into
 * the locking script at deploy time.
 */
class Escrow extends SmartContract {

    @Readonly PubKey buyer;
    @Readonly PubKey seller;
    @Readonly PubKey arbiter;

    Escrow(PubKey buyer, PubKey seller, PubKey arbiter) {
        super(buyer, seller, arbiter);
        this.buyer = buyer;
        this.seller = seller;
        this.arbiter = arbiter;
    }

    /**
     * Release escrowed funds to the seller. Requires both the seller's
     * and arbiter's signatures.
     */
    @Public
    void release(Sig sellerSig, Sig arbiterSig) {
        assertThat(checkSig(sellerSig, this.seller));
        assertThat(checkSig(arbiterSig, this.arbiter));
    }

    /**
     * Refund escrowed funds to the buyer. Requires both the buyer's and
     * arbiter's signatures.
     */
    @Public
    void refund(Sig buyerSig, Sig arbiterSig) {
        assertThat(checkSig(buyerSig, this.buyer));
        assertThat(checkSig(arbiterSig, this.arbiter));
    }
}
