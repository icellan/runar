package runar.examples.oracleprice;

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
 * OraclePriceFeed -- stateless oracle contract for price-triggered
 * payouts.
 *
 * <p>Ports {@code examples/go/oracle-price/OraclePriceFeed.runar.go}.
 * Demonstrates the "oracle pattern" where off-chain data (e.g., asset
 * prices) is cryptographically signed by a trusted oracle and verified
 * on-chain using Rabin signatures. Rabin is well-suited for Script
 * because verification is modular multiplication + comparison.
 */
class OraclePriceFeed extends SmartContract {

    @Readonly RabinPubKey oraclePubKey;
    @Readonly PubKey receiver;

    OraclePriceFeed(RabinPubKey oraclePubKey, PubKey receiver) {
        super(oraclePubKey, receiver);
        this.oraclePubKey = oraclePubKey;
        this.receiver = receiver;
    }

    /**
     * Verify the oracle-attested price exceeds the threshold and that
     * the receiver authorises the spend.
     */
    @Public
    void settle(Bigint price, RabinSig rabinSig, ByteString padding, Sig sig) {
        // Layer 1: Oracle verification — canonicalise the price and verify Rabin sig.
        ByteString msg = num2bin(price.value(), java.math.BigInteger.valueOf(8));
        assertThat(verifyRabinSig(msg, rabinSig, padding, this.oraclePubKey));
        // Layer 2: Application-specific threshold.
        assertThat(price.gt(Bigint.of(50000)));
        // Layer 3: Receiver authorisation.
        assertThat(checkSig(sig, this.receiver));
    }
}
