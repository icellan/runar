package runar.end2end;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.RabinPubKey;
import runar.lang.types.RabinSig;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.num2bin;
import static runar.lang.Builtins.verifyRabinSig;

/**
 * PriceBet -- a two-party price wager settled by a Rabin oracle.
 *
 * <p>Java port of {@code examples/end2end-example/ts/PriceBet.runar.ts}
 * and {@code examples/end2end-example/go/PriceBet.runar.go}. Demonstrates
 * the full Rúnar end-to-end flow with a Java SDK consumer.
 *
 * <p>Oracle replay note: The oracle signs only {@code num2bin(price, 8)}
 * — raw price bytes with no domain separation. Any valid oracle
 * signature for a given price can be reused across all PriceBet
 * contracts that share the same {@code oraclePubKey}. This is acceptable
 * when oracle attestations represent reusable global facts (e.g., "BTC
 * price at block N"). Production contracts requiring per-instance
 * isolation should include domain fields such as a contract ID, UTXO
 * outpoint, or expiry timestamp in the signed message.
 */
class PriceBet extends SmartContract {

    @Readonly PubKey alicePubKey;
    @Readonly PubKey bobPubKey;
    @Readonly RabinPubKey oraclePubKey;
    @Readonly Bigint strikePrice;

    PriceBet(PubKey alicePubKey, PubKey bobPubKey, RabinPubKey oraclePubKey, Bigint strikePrice) {
        super(alicePubKey, bobPubKey, oraclePubKey, strikePrice);
        this.alicePubKey = alicePubKey;
        this.bobPubKey = bobPubKey;
        this.oraclePubKey = oraclePubKey;
        this.strikePrice = strikePrice;
    }

    @Public
    void settle(Bigint price, RabinSig rabinSig, ByteString padding, Sig aliceSig, Sig bobSig) {
        ByteString msg = num2bin(price.value(), java.math.BigInteger.valueOf(8));
        assertThat(verifyRabinSig(msg, rabinSig, padding, this.oraclePubKey));

        assertThat(price.gt(Bigint.of(0)));

        if (price.gt(this.strikePrice)) {
            // bobSig is present in the unlocking script for stack alignment but
            // is intentionally not checked in this branch — alice is the winner.
            assertThat(checkSig(aliceSig, this.alicePubKey));
        } else {
            // aliceSig is present in the unlocking script for stack alignment
            // but is intentionally not checked in this branch — bob is the winner.
            assertThat(checkSig(bobSig, this.bobPubKey));
        }
    }

    @Public
    void cancel(Sig aliceSig, Sig bobSig) {
        assertThat(checkSig(aliceSig, this.alicePubKey));
        assertThat(checkSig(bobSig, this.bobPubKey));
    }
}
