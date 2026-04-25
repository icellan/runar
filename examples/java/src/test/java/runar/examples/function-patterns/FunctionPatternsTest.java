package runar.examples.functionpatterns;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.Bigint;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Surface + simulator tests for FunctionPatterns. Exercises the three
 * function-call categories Rúnar supports: public methods, private
 * helpers, and built-in functions.
 */
class FunctionPatternsTest {

    private static final PubKey OWNER = PubKey.fromHex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
    private static final Sig SIG = Sig.fromHex(
        "30440220" + "00".repeat(32) + "0220" + "00".repeat(32)
    );

    private static FunctionPatterns make(long balance) {
        return new FunctionPatterns(OWNER, Bigint.of(balance));
    }

    @Test
    void contractInstantiates() {
        FunctionPatterns c = make(1000);
        assertNotNull(c);
        assertEquals(OWNER, c.owner);
        assertEquals(Bigint.of(1000), c.balance);
    }

    @Test
    void depositIncreasesBalance() {
        FunctionPatterns c = make(100);
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("deposit", SIG, Bigint.of(50));
        assertEquals(Bigint.of(150), c.balance);
    }

    @Test
    void depositRejectsZero() {
        FunctionPatterns c = make(100);
        ContractSimulator sim = ContractSimulator.stateful(c);
        assertThrows(AssertionError.class, () -> sim.call("deposit", SIG, Bigint.ZERO));
    }

    @Test
    void withdrawDeductsAmountPlusFee() {
        // 100 satoshis, 1% fee (100 bps) -> 1 satoshi fee, total 101.
        FunctionPatterns c = make(1000);
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("withdraw", SIG, Bigint.of(100), Bigint.of(100));
        assertEquals(Bigint.of(899), c.balance);
    }

    @Test
    void withdrawRejectsOverdraft() {
        FunctionPatterns c = make(50);
        ContractSimulator sim = ContractSimulator.stateful(c);
        assertThrows(
            AssertionError.class,
            () -> sim.call("withdraw", SIG, Bigint.of(100), Bigint.of(100))
        );
    }

    @Test
    void scaleAppliesRatio() {
        // 1000 * 3 / 4 = 750
        FunctionPatterns c = make(1000);
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("scale", SIG, Bigint.of(3), Bigint.of(4));
        assertEquals(Bigint.of(750), c.balance);
    }

    @Test
    void normalizeClampsAndRoundsDown() {
        // 1234 -> clamp(1234, 0, 100000) = 1234 -> round down to nearest 10 = 1230
        FunctionPatterns c = make(1234);
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("normalize", SIG, Bigint.ZERO, Bigint.of(100000), Bigint.of(10));
        assertEquals(Bigint.of(1230), c.balance);
    }
}
