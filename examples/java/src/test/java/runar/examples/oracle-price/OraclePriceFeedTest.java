package runar.examples.oracleprice;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.RabinPubKey;
import runar.lang.types.RabinSig;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OraclePriceFeedTest {

    private static final RabinPubKey ORACLE_PK = new RabinPubKey(BigInteger.valueOf(12345));
    private static final RabinSig    ORACLE_SIG = new RabinSig(BigInteger.valueOf(67890));
    private static final PubKey      RECEIVER = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000001");
    private static final Sig         SIG = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

    @Test
    void contractInstantiates() {
        OraclePriceFeed c = new OraclePriceFeed(ORACLE_PK, RECEIVER);
        assertNotNull(c);
        assertEquals(ORACLE_PK, c.oraclePubKey);
        assertEquals(RECEIVER, c.receiver);
    }

    @Test
    void settleSucceedsWhenPriceExceedsThreshold() {
        OraclePriceFeed c = new OraclePriceFeed(ORACLE_PK, RECEIVER);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("settle", Bigint.of(100_000), ORACLE_SIG, ByteString.fromHex(""), SIG);
    }

    @Test
    void settleFailsWhenPriceBelowThreshold() {
        OraclePriceFeed c = new OraclePriceFeed(ORACLE_PK, RECEIVER);
        ContractSimulator sim = ContractSimulator.stateless(c);
        assertThrows(
            AssertionError.class,
            () -> sim.call("settle", Bigint.of(40_000), ORACLE_SIG, ByteString.fromHex(""), SIG)
        );
    }
}
