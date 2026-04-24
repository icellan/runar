package runar.examples.pricebet;

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

// PriceBet -- a two-party price wager settled by a Rabin oracle.
//
// Oracle replay note: the oracle signs only num2bin(price, 8) -- raw price
// bytes with no domain separation. Any valid oracle signature for a given
// price can be reused across all PriceBet contracts that share the same
// oraclePubKey. This is acceptable when oracle attestations represent
// reusable global facts (e.g., "BTC price at block N"). For production
// contracts requiring per-instance isolation, include domain fields such
// as a contract ID, UTXO outpoint, or expiry timestamp in the signed
// message.
//
// Mirrors the reference variants in:
//   - examples/end2end-example/ts/PriceBet.runar.ts
//   - examples/end2end-example/go/PriceBet.runar.go
//   - examples/end2end-example/rust/src/price_bet.runar.rs
//   - examples/end2end-example/python/PriceBet.runar.py
//   - examples/end2end-example/ruby/PriceBet.runar.rb
//
// Contract classes in .runar.java files are package-private so that javac
// accepts the compound .runar.java suffix (which does not match a bare
// public class name). See examples/java/src/main/java/runar/examples/p2pkh
// for the reference shape.
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
        ByteString msg = num2bin(price, 8);
        assertThat(verifyRabinSig(msg, rabinSig, padding, oraclePubKey));

        assertThat(price > 0);

        if (price > strikePrice) {
            // bobSig is present in the unlocking script for stack alignment but is
            // intentionally not checked in this branch -- only alice (the winner) signs.
            assertThat(checkSig(aliceSig, alicePubKey));
        } else {
            // aliceSig is present in the unlocking script for stack alignment but is
            // intentionally not checked in this branch -- only bob (the winner) signs.
            assertThat(checkSig(bobSig, bobPubKey));
        }
    }

    @Public
    void cancel(Sig aliceSig, Sig bobSig) {
        assertThat(checkSig(aliceSig, alicePubKey));
        assertThat(checkSig(bobSig, bobPubKey));
    }
}
