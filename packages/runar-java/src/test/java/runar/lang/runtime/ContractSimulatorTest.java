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
        ContractSimulator sim = ContractSimulator.stateful(c, counterArtifact());
        // F-129: callStateful now checks the preimage against the spending
        // transaction, so the preimage must be that transaction's.
        Preimage p = sim.preimageFor("increment", Preimage.builder().amount(BigInteger.valueOf(50000)).build());
        sim.callStateful("increment", p);
        assertSame(p, sim.lastPreimage());
    }

    // --- F-129: callStateful's preimage must be the spending tx's ---------
    //
    // Proves: callStateful rebuilds the spending transaction the call produces
    // (input 0 spends Counter's real locking script, output 0 is the
    // continuation the method emitted) and rejects a well-formed preimage that
    // commits to a different continuation (hashOutputs) or a different locking
    // script (scriptCode). Does NOT prove on-chain acceptance: the honest
    // preimage comes from the SDK's own sighash code (OpPushTx, the code real
    // calls use), not from an independent script VM, and change outputs /
    // extra inputs are not modelled.

    /**
     * Rúnar source for {@link Counter}. The Java class keeps its plain
     * BigInteger arithmetic; the source spells the same contract with the
     * Bigint wrapper the Java frontend reads. Same state field, same output.
     */
    private static final String COUNTER_SRC = """
        import runar.lang.StatefulSmartContract;
        import runar.lang.annotations.Public;
        import runar.lang.types.Bigint;

        class Counter extends StatefulSmartContract {
            Bigint count;

            Counter(Bigint count) {
                super(count);
                this.count = count;
            }

            @Public
            void increment() {
                Bigint next = this.count.plus(Bigint.ONE);
                this.addOutput(1000L, next);
                this.count = next;
            }
        }
        """;

    private static runar.lang.sdk.RunarArtifact counterArtifact;

    private static runar.lang.sdk.RunarArtifact counterArtifact() {
        if (counterArtifact == null) {
            try {
                counterArtifact = runar.lang.sdk.SimulatedSpend.compile(COUNTER_SRC, "Counter.runar.java");
            } catch (java.io.IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        }
        return counterArtifact;
    }

    private static Preimage withHashOutputs(Preimage p, byte[] hashOutputs) {
        return copy(p).hashOutputs(hashOutputs).build();
    }

    private static Preimage.Builder copy(Preimage p) {
        return Preimage.builder()
            .version(p.version()).hashPrevouts(p.hashPrevouts()).hashSequence(p.hashSequence())
            .outpoint(p.outpoint()).scriptCode(p.scriptCode()).amount(p.amount())
            .sequence(p.sequence()).hashOutputs(p.hashOutputs()).locktime(p.locktime())
            .sighashType(p.sighashType());
    }

    /** hash256 of one serialized output: 8-byte LE value, varint length, script. */
    private static byte[] hashOneOutput(long sats, String scriptHex) {
        byte[] script = runar.lang.types.ByteString.fromHex(scriptHex).toByteArray();
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < 8; i++) out.write((int) (sats >>> (8 * i)) & 0xff);
        assertTrue(script.length <= 0xffff);
        if (script.length < 0xfd) {
            out.write(script.length);
        } else {
            out.write(0xfd);
            out.write(script.length & 0xff);
            out.write(script.length >>> 8);
        }
        out.writeBytes(script);
        return MockCrypto.hash256(new runar.lang.types.ByteString(out.toByteArray())).toByteArray();
    }

    @Test
    void callStatefulAcceptsTheSpendingTransactionsPreimage() {
        Counter c = new Counter(BigInteger.ZERO);
        ContractSimulator sim = ContractSimulator.stateful(c, counterArtifact());
        Preimage honest = sim.preimageFor("increment", Preimage.builder().build());
        // The dry run left the contract and the captured outputs untouched.
        assertEquals(BigInteger.ZERO, c.count);
        assertEquals(0, sim.outputs().size());

        // hashOutputs commits to exactly one output: 1000 sats to Counter's
        // code part + OP_RETURN + count=1.
        String lock0 = runar.lang.sdk.SimulatedSpend.lockingScript(
            counterArtifact(), java.util.List.of(BigInteger.ZERO), java.util.Map.of("count", BigInteger.ZERO));
        String cont1 = runar.lang.sdk.SimulatedSpend.continuationScript(
            counterArtifact(), lock0, java.util.Map.of("count", BigInteger.ONE));
        assertArrayEquals(hashOneOutput(1000, cont1), honest.hashOutputs());
        // scriptCode is the locking script after Counter's OP_CODESEPARATOR.
        assertTrue(lock0.endsWith(honest.scriptCode().toHex()));
        assertTrue(honest.scriptCode().length() < lock0.length() / 2);

        assertDoesNotThrow(() -> sim.callStateful("increment", honest));
        assertEquals(BigInteger.ONE, c.count);
    }

    /**
     * The item's attack: a well-formed preimage whose hashOutputs commits to a
     * continuation the covenant would not produce (count jumps to 999). The
     * stub accepted it; the off-chain checkPreimage must not.
     */
    @Test
    void callStatefulRejectsForgedHashOutputs() {
        Counter c = new Counter(BigInteger.ZERO);
        ContractSimulator sim = ContractSimulator.stateful(c, counterArtifact());
        Preimage honest = sim.preimageFor("increment", Preimage.builder().build());
        String lock0 = runar.lang.sdk.SimulatedSpend.lockingScript(
            counterArtifact(), java.util.List.of(BigInteger.ZERO), java.util.Map.of("count", BigInteger.ZERO));
        String forgedCont = runar.lang.sdk.SimulatedSpend.continuationScript(
            counterArtifact(), lock0, java.util.Map.of("count", BigInteger.valueOf(999)));
        Preimage forged = withHashOutputs(honest, hashOneOutput(1000, forgedCont));

        AssertionError e = assertThrows(AssertionError.class, () -> sim.callStateful("increment", forged));
        assertTrue(e.getMessage().contains("hashOutputs"), e.getMessage());
    }

    /** A preimage signing a different locking script (Counter at count=5) is rejected before the body runs. */
    @Test
    void callStatefulRejectsForgedScriptCode() {
        Counter other = new Counter(BigInteger.valueOf(5));
        Preimage otherScript = ContractSimulator.stateful(other, counterArtifact())
            .preimageFor("increment", Preimage.builder().build());

        Counter c = new Counter(BigInteger.ZERO);
        ContractSimulator sim = ContractSimulator.stateful(c, counterArtifact());
        AssertionError e = assertThrows(AssertionError.class, () -> sim.callStateful("increment", otherScript));
        assertTrue(e.getMessage().contains("scriptCode"), e.getMessage());
        assertEquals(BigInteger.ZERO, c.count, "rejected before the method body ran");
        assertEquals(0, sim.outputs().size());
    }

    /** Without an artifact there is no transaction to check against: refuse, never pass. */
    @Test
    void callStatefulWithoutArtifactRefuses() {
        ContractSimulator sim = ContractSimulator.stateful(new Counter(BigInteger.ZERO));
        assertThrows(IllegalStateException.class,
            () -> sim.callStateful("increment", Preimage.builder().build()));
    }
}
