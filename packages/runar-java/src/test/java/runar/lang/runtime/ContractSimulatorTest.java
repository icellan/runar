package runar.lang.runtime;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

import runar.lang.SmartContract;
import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;
import runar.lang.types.SigHashPreimage;

import static org.junit.jupiter.api.Assertions.*;
import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.cat;
import static runar.lang.Builtins.checkPreimage;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.extractOutputHash;
import static runar.lang.Builtins.hash160;
import static runar.lang.Builtins.hash256;
import static runar.lang.Builtins.num2bin;

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

    // --- N-099: a stateless method's explicit checkPreimage -----------------
    //
    // Proves: a stateless call whose method calls checkPreimage(SigHashPreimage)
    // is checked against the BIP-143 preimage of the spending transaction the
    // caller describes (input 0 spends the contract's compiled locking script;
    // the outputs are the caller's). A 32-byte fake and a well-formed preimage
    // committing to other outputs are rejected; the honest preimage passes;
    // with no spend described, checkPreimage throws instead of passing. Does
    // NOT prove on-chain acceptance: the honest preimage comes from the SDK's
    // own sighash code (OpPushTx), not an independent script VM.

    /** Stateless covenant: the preimage must sign a tx paying 1000 sats to `pkh` (P2PKH), and nothing else. */
    public static class PayTo extends SmartContract {
        @Readonly public Addr pkh;

        public PayTo(Addr pkh) {
            super(pkh);
            this.pkh = pkh;
        }

        @Public
        public void spend(SigHashPreimage txPreimage) {
            assertThat(checkPreimage(txPreimage));
            ByteString out = cat(cat(cat(num2bin(Bigint.of(1000), Bigint.of(8)), ByteString.fromHex("1976a914")),
                this.pkh), ByteString.fromHex("88ac"));
            assertThat(hash256(out).equals(extractOutputHash(txPreimage)));
        }
    }

    private static final Addr PAYEE = Addr.fromHex("0102030405060708090a0b0c0d0e0f1011121314");

    /** The 34-byte output PayTo requires: 8-byte LE 1000, varint 25, P2PKH to PAYEE. */
    private static ByteString payeeOutput() {
        return ByteString.fromHex("e803000000000000" + "1976a914" + PAYEE.toHex() + "88ac");
    }

    /**
     * The 32-byte fake the old tests used: hash256(required output), which the
     * stub checkPreimage accepted and the old extractOutputHash echoed back.
     */
    private static SigHashPreimage fake32() {
        return new SigHashPreimage(MockCrypto.hash256(payeeOutput()).toByteArray());
    }

    /** The item's attack at its simplest: 32 bytes posing as a preimage, and no spend to check it against. */
    @Test
    void statelessCheckPreimageWithoutASpendThrows() {
        ContractSimulator sim = ContractSimulator.stateless(new PayTo(PAYEE));
        SigHashPreimage fake = fake32();
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> sim.call("spend", fake));
        assertTrue(e.getMessage().contains("checkPreimage"), e.getMessage());
    }

    /**
     * N-245: extractOutputHash(SigHashPreimage) with an empty preimage and no
     * active simulator preimage must refuse, like checkPreimage does — not
     * silently answer ZERO_32. An all-zero hashOutputs is a value an
     * assertion could accidentally be satisfied by; checkPreimage already
     * treats "no spending transaction to check against" as fail-closed
     * (N-099), and extractOutputHash must match.
     */
    @Test
    void extractOutputHashWithoutASpendThrows() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
            () -> extractOutputHash(new SigHashPreimage(new byte[0])));
        assertTrue(e.getMessage().contains("extractOutputHash"), e.getMessage());
    }

    /** Rúnar source for {@link PayTo}. */
    private static final String PAY_TO_SRC = """
        import runar.lang.SmartContract;
        import runar.lang.annotations.Public;
        import runar.lang.annotations.Readonly;
        import runar.lang.types.Addr;
        import runar.lang.types.Bigint;
        import runar.lang.types.ByteString;
        import runar.lang.types.SigHashPreimage;

        import static runar.lang.Builtins.assertThat;
        import static runar.lang.Builtins.cat;
        import static runar.lang.Builtins.checkPreimage;
        import static runar.lang.Builtins.extractOutputHash;
        import static runar.lang.Builtins.hash256;
        import static runar.lang.Builtins.num2bin;

        class PayTo extends SmartContract {
            @Readonly Addr pkh;

            PayTo(Addr pkh) {
                super(pkh);
                this.pkh = pkh;
            }

            @Public
            void spend(SigHashPreimage txPreimage) {
                assertThat(checkPreimage(txPreimage));
                ByteString out = cat(cat(cat(num2bin(Bigint.of(1000), Bigint.of(8)), ByteString.fromHex("1976a914")),
                    this.pkh), ByteString.fromHex("88ac"));
                assertThat(hash256(out).equals(extractOutputHash(txPreimage)));
            }
        }
        """;

    private static runar.lang.sdk.RunarArtifact payToArtifact;

    private static runar.lang.sdk.RunarArtifact payToArtifact() {
        if (payToArtifact == null) {
            try {
                payToArtifact = runar.lang.sdk.SimulatedSpend.compile(PAY_TO_SRC, "PayTo.runar.java");
            } catch (java.io.IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        }
        return payToArtifact;
    }

    private static java.util.List<runar.lang.sdk.SimulatedSpend.Out> payeeOutputs() {
        return java.util.List.of(new runar.lang.sdk.SimulatedSpend.Out(1000, "76a914" + PAYEE.toHex() + "88ac"));
    }

    @Test
    void callWithSpendAcceptsTheSpendingTransactionsPreimage() {
        ContractSimulator sim = ContractSimulator.stateless(new PayTo(PAYEE), payToArtifact());
        Preimage template = Preimage.builder().amount(BigInteger.valueOf(5000)).build();
        SigHashPreimage honest = sim.spendPreimage("spend", template, payeeOutputs());
        Preimage parsed = Preimage.parse(honest.toByteArray());
        // hashOutputs commits to the one output, serialized independently here.
        assertArrayEquals(MockCrypto.hash256(payeeOutput()).toByteArray(), parsed.hashOutputs());
        // scriptCode is PayTo's locking script with PAYEE spliced in.
        assertTrue(parsed.scriptCode().toHex().contains(PAYEE.toHex()));
        assertEquals(BigInteger.valueOf(5000), parsed.amount());
        assertDoesNotThrow(() -> sim.callWithSpend("spend", template, payeeOutputs(), honest));
        assertNull(SimulatorContext.currentPreimage(), "the spend does not leak past the call");
    }

    /** With the spend described, the 32-byte fake the old tests used is still rejected by checkPreimage. */
    @Test
    void callWithSpendRejectsA32ByteFake() {
        ContractSimulator sim = ContractSimulator.stateless(new PayTo(PAYEE), payToArtifact());
        AssertionError e = assertThrows(AssertionError.class,
            () -> sim.callWithSpend("spend", Preimage.builder().build(), payeeOutputs(), fake32()));
        assertTrue(e.getMessage().contains("not a BIP-143 preimage"), e.getMessage());
    }

    /**
     * A well-formed preimage of a transaction paying the 1000 sats elsewhere: it
     * satisfies the covenant's own output rule when built for that other tx, but
     * it is not the preimage of the transaction being spent.
     */
    @Test
    void callWithSpendRejectsThePreimageOfADifferentTransaction() {
        ContractSimulator sim = ContractSimulator.stateless(new PayTo(PAYEE), payToArtifact());
        Preimage template = Preimage.builder().build();
        java.util.List<runar.lang.sdk.SimulatedSpend.Out> theft = java.util.List.of(
            new runar.lang.sdk.SimulatedSpend.Out(1000, "76a914" + "cc".repeat(20) + "88ac"));
        SigHashPreimage forTheft = sim.spendPreimage("spend", template, theft);
        AssertionError e = assertThrows(AssertionError.class,
            () -> sim.callWithSpend("spend", template, payeeOutputs(), forTheft));
        assertTrue(e.getMessage().contains("hashOutputs"), e.getMessage());

        // And the theft tx's own honest preimage gets past checkPreimage but
        // fails the covenant's output rule.
        AssertionError rule = assertThrows(AssertionError.class,
            () -> sim.callWithSpend("spend", template, theft, forTheft));
        assertFalse(rule.getMessage() != null && rule.getMessage().contains("checkPreimage"), rule.getMessage());
    }

    /** The structured Preimage overload is no stub either: it needs a spend too. */
    @Test
    void structuredCheckPreimageHasNoStub() {
        SimulatorContext.enter();
        try {
            assertThrows(IllegalStateException.class, () -> runar.lang.Builtins.checkPreimage(Preimage.zero()));
        } finally {
            SimulatorContext.exit();
        }
    }
}
