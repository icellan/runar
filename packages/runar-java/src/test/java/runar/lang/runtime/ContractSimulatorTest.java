package runar.lang.runtime;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

import runar.lang.SmartContract;
import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.*;
import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;

class ContractSimulatorTest {

    /** Minimal P2PKH in the same shape as examples/java. */
    public static class P2PKH extends SmartContract {
        @Readonly public Addr pubKeyHash;

        public P2PKH(Addr pubKeyHash) {
            super(pubKeyHash);
            this.pubKeyHash = pubKeyHash;
        }

        @Public
        public void unlock(Sig sig, PubKey pubKey) {
            assertThat(hash160(pubKey).equals(pubKeyHash));
            assertThat(checkSig(sig, pubKey));
        }
    }

    private static final PubKey PK = PubKey.fromHex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );

    private static Addr expectedHash() {
        // hash160 of PK under real-deterministic hashing.
        return MockCrypto.hash160(PK);
    }

    @Test
    void unlockSucceedsWithMatchingHash() {
        Addr h = expectedHash();
        P2PKH contract = new P2PKH(h);
        Sig s = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));
        ContractSimulator sim = ContractSimulator.stateless(contract);
        assertDoesNotThrow(() -> sim.call("unlock", s, PK));
    }

    @Test
    void unlockFailsWithWrongHash() {
        Addr wrong = Addr.fromHex("00".repeat(20));
        P2PKH contract = new P2PKH(wrong);
        Sig s = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));
        ContractSimulator sim = ContractSimulator.stateless(contract);
        assertThrows(AssertionError.class, () -> sim.call("unlock", s, PK));
    }

    @Test
    void expectFailureHelperReturnsOnAssertionError() {
        Addr wrong = Addr.fromHex("ff".repeat(20));
        P2PKH contract = new P2PKH(wrong);
        Sig s = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));
        ContractSimulator sim = ContractSimulator.stateless(contract);
        AssertionError e = sim.expectFailure("unlock", s, PK);
        assertNotNull(e);
    }

    @Test
    void simulatorFlagResetsAfterCall() {
        // After any successful call, simulator mode must be off on the
        // caller thread so plain-Java consumers still see throwing stubs.
        Addr h = expectedHash();
        P2PKH contract = new P2PKH(h);
        Sig s = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));
        ContractSimulator.stateless(contract).call("unlock", s, PK);
        assertFalse(SimulatorContext.isActive());
        // And the builtin should throw outside the simulator.
        assertThrows(UnsupportedOperationException.class, () -> runar.lang.Builtins.hash160(PK));
    }

    // --- Stateful contract: Counter ---------------------------------

    /** Minimal stateful counter that increments `count` on each call. */
    public static class Counter extends StatefulSmartContract {
        public BigInteger count;

        public Counter(BigInteger count) {
            super(count);
            this.count = count;
        }

        @Public
        public void increment() {
            BigInteger next = this.count.add(BigInteger.ONE);
            addOutput(BigInteger.valueOf(1000), next);
            this.count = next;
        }
    }

    @Test
    void statefulCounterIncrementsTwice() {
        Counter c = new Counter(BigInteger.ZERO);
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("increment");
        sim.call("increment");
        assertEquals(BigInteger.TWO, c.count);
        assertEquals(2, sim.outputs().size(), "both calls emit outputs into the simulator's captured list");
        assertEquals(BigInteger.ONE, sim.outputs().get(0).values[0]);
        assertEquals(BigInteger.TWO, sim.outputs().get(1).values[0]);
    }

    @Test
    void statefulCounterCapturesOutput() {
        Counter c = new Counter(BigInteger.valueOf(41));
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("increment");
        assertEquals(1, sim.outputs().size());
        ContractSimulator.Output o = sim.outputs().get(0);
        assertEquals(BigInteger.valueOf(1000), o.satoshis);
        assertEquals(BigInteger.valueOf(42), o.values[0]);
        assertFalse(o.isRaw());
    }

    @Test
    void statefulCallWithPreimageStashesIt() {
        Counter c = new Counter(BigInteger.ZERO);
        ContractSimulator sim = ContractSimulator.stateful(c);
        Preimage p = Preimage.builder().amount(BigInteger.valueOf(50000)).build();
        sim.callStateful("increment", p);
        assertSame(p, sim.lastPreimage());
    }
}
