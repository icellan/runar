package runar.lang.runtime;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static runar.lang.Builtins.extractAmount;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.SimulatedSpend;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

/**
 * D25 (D12 PRE-F1) on the Java tier's off-chain validating path,
 * {@link ContractSimulator#callStateful}: it rebuilds the spending transaction
 * from the compiled artifact and refuses any preimage that is not that
 * transaction's BIP-143 preimage (this tier has no Script VM).
 *
 * <p>Proves: a class-1 contract (Counter, every continuation method
 * mutate-only, compiled by the Java compiler) chains two honest calls under
 * its SIGHASH_SINGLE|FORKID covenant, and a preimage under the old ALL mode is
 * refused; a class-2 contract (MixedPot) chains increment then bump
 * with the hidden {@code _spentOutpointHash} field tracked from the REAL
 * spent outpoint, and a second input (another outpoint) that claims the same
 * output list is refused. Does NOT prove script execution: the honest
 * preimage comes from the SDK's own sighash code, not an independent VM.
 */
class D25SimulatorTest {

    private static final String FIELD = "_spentOutpointHash";

    /** examples/java stateful-counter, mutate-only (class 1). */
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
                this.count = this.count.plus(Bigint.ONE);
            }
        }
        """;

    /** The brief's MixedPot (class 2): an auto-continuation next to an addOutput method. */
    private static final String MIXED_SRC = """
        import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';
        class MixedPot extends StatefulSmartContract {
          count: bigint;
          constructor(count: bigint) { super(count); this.count = count; }
          public increment() { this.count++; }
          public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }
        }
        """;

    public static class Counter extends StatefulSmartContract {
        public Bigint count;

        public Counter(Bigint count) {
            super(count);
            this.count = count;
        }

        @Public
        public void increment() {
            this.count = this.count.plus(Bigint.ONE);
        }
    }

    public static class MixedPot extends StatefulSmartContract {
        public Bigint count;

        public MixedPot(Bigint count) {
            super(count);
            this.count = count;
        }

        @Public
        public void increment() {
            this.count = this.count.plus(Bigint.ONE);
        }

        @Public
        public void bump() {
            this.addOutput(extractAmount(this.txPreimage), this.count.plus(Bigint.ONE));
        }
    }

    private static RunarArtifact compile(String src, String file) {
        try {
            return SimulatedSpend.compile(src, file);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    private static byte[] outpoint(int k) {
        byte[] op = new byte[36];
        java.util.Arrays.fill(op, 0, 32, (byte) (0xa0 + k));
        op[32] = (byte) k;
        return op;
    }

    private static Preimage template(long sighashType, int k) {
        return Preimage.builder().sighashType(sighashType).outpoint(outpoint(k)).build();
    }

    private static String hex(byte[] b) {
        return java.util.HexFormat.of().formatHex(b);
    }

    /** hash256 of one serialized output (8-byte LE value, varint length, script). */
    private static byte[] hashOneOutput(long sats, String scriptHex) {
        byte[] script = ByteString.fromHex(scriptHex).toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < 8; i++) out.write((int) (sats >>> (8 * i)) & 0xff);
        if (script.length < 0xfd) {
            out.write(script.length);
        } else {
            out.write(0xfd);
            out.write(script.length & 0xff);
            out.write(script.length >>> 8);
        }
        out.writeBytes(script);
        return MockCrypto.hash256(new ByteString(out.toByteArray())).toByteArray();
    }

    // ---- class 1 -------------------------------------------------------------

    @Test
    void counterIsSingleAndChainsTwoHonestCalls() {
        RunarArtifact art = compile(COUNTER_SRC, "Counter.runar.java");
        RunarArtifact.ABIMethod inc = art.abi().methods().stream()
            .filter(m -> m.name().equals("increment")).findFirst().orElseThrow();
        assertEquals(0x43, inc.sigHashType());
        assertEquals(List.of("_newAmount", "txPreimage"),
            inc.params().stream().map(RunarArtifact.ABIParam::name).toList());

        Counter c = new Counter(Bigint.ZERO);
        ContractSimulator sim = ContractSimulator.stateful(c, art);
        for (int k = 0; k < 2; k++) {
            Preimage honest = sim.preimageFor("increment", template(0x43, k));
            assertDoesNotThrow(() -> sim.callStateful("increment", honest));
        }
        assertEquals(Bigint.TWO, c.count);
    }

    @Test
    void counterRefusesAnAllPreimage() {
        RunarArtifact art = compile(COUNTER_SRC, "Counter.runar.java");
        Counter c = new Counter(Bigint.ZERO);
        ContractSimulator sim = ContractSimulator.stateful(c, art);
        Preimage all = sim.preimageFor("increment", template(0x41, 0));
        AssertionError e = assertThrows(AssertionError.class, () -> sim.callStateful("increment", all));
        assertTrue(e.getMessage().contains("covenant mode 0x43"), e.getMessage());
        assertEquals(Bigint.ZERO, c.count);
    }

    // ---- class 2 -------------------------------------------------------------

    @Test
    void mixedPotChainsBothMethodsWithTheRealOutpointBound() {
        RunarArtifact art = compile(MIXED_SRC, "MixedPot.runar.ts");
        assertEquals(List.of("count", FIELD), SimulatedSpend.stateFieldNamesInOrder(art));
        MixedPot p = new MixedPot(Bigint.ZERO);
        ContractSimulator sim = ContractSimulator.stateful(p, art);

        // increment spends outpoint 0: the continuation carries count 1 and sha256(outpoint 0).
        String lock0 = SimulatedSpend.lockingScript(art, List.of(BigInteger.ZERO),
            Map.of("count", BigInteger.ZERO, FIELD, "00".repeat(32)));
        Preimage inc = sim.preimageFor("increment", template(0x41, 0));
        String cont1 = SimulatedSpend.continuationScript(art, lock0,
            Map.of("count", BigInteger.ONE, FIELD, hex(MockCrypto.sha256(outpoint(0)))));
        assertArrayEquals(hashOneOutput(10000, cont1), inc.hashOutputs());
        assertDoesNotThrow(() -> sim.callStateful("increment", inc));

        // bump spends outpoint 1 (the UTXO increment made): addOutput carries sha256(outpoint 1).
        Preimage bump = sim.preimageFor("bump", template(0x41, 1));
        String cont2 = SimulatedSpend.continuationScript(art, cont1,
            Map.of("count", BigInteger.TWO, FIELD, hex(MockCrypto.sha256(outpoint(1)))));
        assertArrayEquals(hashOneOutput(10000, cont2), bump.hashOutputs());
        assertDoesNotThrow(() -> sim.callStateful("bump", bump));
    }

    /**
     * The twin: a second UTXO of the same contract and state (another outpoint)
     * claims the output list the first input's call commits to. Before D25 its
     * covenant rebuilt the same list and accepted; now its own continuation
     * carries its own outpoint, so the shared list is refused.
     */
    @Test
    void mixedPotTwinOnTheSecondInputIsRefused() {
        RunarArtifact art = compile(MIXED_SRC, "MixedPot.runar.ts");
        for (String method : List.of("increment", "bump")) {
            Preimage first = ContractSimulator.stateful(new MixedPot(Bigint.ZERO), art)
                .preimageFor(method, template(0x41, 0));
            ContractSimulator second = ContractSimulator.stateful(new MixedPot(Bigint.ZERO), art);
            Preimage twin = Preimage.builder().sighashType(0x41).outpoint(outpoint(1))
                .hashOutputs(first.hashOutputs()).build();
            Preimage honestSecond = second.preimageFor(method, template(0x41, 1));
            assertFalse(java.util.Arrays.equals(first.hashOutputs(), honestSecond.hashOutputs()),
                method + ": two inputs must not share one continuation");
            // the twin's input side must be the second UTXO's, honestly
            Preimage twinFull = Preimage.builder()
                .version(honestSecond.version()).hashPrevouts(honestSecond.hashPrevouts())
                .hashSequence(honestSecond.hashSequence()).outpoint(honestSecond.outpoint())
                .scriptCode(honestSecond.scriptCode()).amount(honestSecond.amount())
                .sequence(honestSecond.sequence()).hashOutputs(twin.hashOutputs())
                .locktime(honestSecond.locktime()).sighashType(honestSecond.sighashType()).build();
            AssertionError e = assertThrows(AssertionError.class, () -> second.callStateful(method, twinFull));
            assertTrue(e.getMessage().contains("hashOutputs"), method + ": " + e.getMessage());
        }
    }

    /** Class 3 control (explicit outputs only, no binding field): the same twin still verifies. */
    public static class Pot extends StatefulSmartContract {
        public Bigint count;

        public Pot(Bigint count) {
            super(count);
            this.count = count;
        }

        @Public
        public void bump() {
            this.addOutput(extractAmount(this.txPreimage), this.count.plus(Bigint.ONE));
        }
    }

    private static final String POT_SRC = """
        import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';
        class Pot extends StatefulSmartContract {
          count: bigint;
          constructor(count: bigint) { super(count); this.count = count; }
          public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }
        }
        """;

    @Test
    void controlAnUnboundExplicitContractStillAliases() {
        RunarArtifact art = compile(POT_SRC, "Pot.runar.ts");
        assertEquals(List.of("count"), SimulatedSpend.stateFieldNamesInOrder(art));
        Preimage first = ContractSimulator.stateful(new Pot(Bigint.ZERO), art).preimageFor("bump", template(0x41, 0));
        ContractSimulator second = ContractSimulator.stateful(new Pot(Bigint.ZERO), art);
        Preimage honestSecond = second.preimageFor("bump", template(0x41, 1));
        // the documented class-3 aliasing: both inputs commit to the identical output
        assertArrayEquals(first.hashOutputs(), honestSecond.hashOutputs());
        assertDoesNotThrow(() -> second.callStateful("bump", honestSecond));
    }
}
