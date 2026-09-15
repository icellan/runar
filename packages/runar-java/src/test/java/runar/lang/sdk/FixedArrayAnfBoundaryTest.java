package runar.lang.sdk;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * FixedArray state across the ANF-interpreter boundary (call path).
 *
 * <p>Pass {@code 03b-expand-fixed-arrays} runs BEFORE ANF lowering, so the ANF
 * program has no property called {@code table} at all — it has
 * {@code table__0}..{@code table__3}, and every {@code load_prop} /
 * {@code update_prop} in the method body names one of those. The SDK's
 * user-facing {@code state} map, by contrast, is keyed by the GROUPED name.
 * Both directions of that boundary have to be bridged or the continuation
 * output commits a state the method did not compute.
 *
 * <p>The sharp probe is the RECONNECT path: {@link RunarContract#fromUtxo}
 * sets {@code state} to exactly what {@link StateSerializer#extractFromScript}
 * decodes, which for a FixedArray field is the grouped entry and nothing else —
 * no synthetic leaves to mask an unbridged inbound boundary. Because
 * {@code this.table[i]++} at a runtime index lowers to a per-leaf select, an
 * absent property makes the interpreter fall back to each leaf's ANF
 * {@code initialValue} and rewrite ALL FOUR leaves from it, so the continuation
 * commits the deploy-time array and the covenant's hashOutputs binding rejects
 * the spend.
 *
 * <p>Fixture: {@code examples/*}/fixed-array-write/ArrayWrite —
 * {@code table: FixedArray<bigint, 4> = [0,0,0,0]}, {@code bump(i)} doing
 * {@code this.table[i]++}. Checked in at
 * {@code src/test/resources/artifacts/arraywrite.runar.json}, compiled with
 * {@code --ir} so the artifact carries the ANF the call path needs.
 *
 * <p>Every case runs on the DEFAULT validating {@link MockProvider} with a real
 * {@link LocalSigner}. Java ships no ScriptVM, so the load-bearing assertion is
 * the continuation BYTES — the 32-byte state section the next spend is bound to.
 */
class FixedArrayAnfBoundaryTest {

    private static final String PRIV =
        "0000000000000000000000000000000000000000000000000000000000000007";

    private static RunarArtifact loadArtifact() throws Exception {
        try (var in = FixedArrayAnfBoundaryTest.class.getClassLoader()
                .getResourceAsStream("artifacts/arraywrite.runar.json")) {
            assertTrue(in != null, "ArrayWrite artifact resource must exist");
            RunarArtifact artifact = RunarArtifact.fromJson(new String(in.readAllBytes()));
            // Without ANF the call path never reaches the interpreter and this
            // whole test class would be vacuous.
            assertNotNull(artifact.anf(), "ArrayWrite artifact carries no ANF");
            assertTrue(artifact.isStateful(), "ArrayWrite is a StatefulSmartContract");
            return artifact;
        }
    }

    /** Little-endian 8-byte words, one per leaf — the contract's state bytes. */
    private static String leHex(long... vals) {
        StringBuilder sb = new StringBuilder();
        for (long v : vals) {
            for (int i = 0; i < 8; i++) {
                sb.append(String.format("%02x", (int) ((v >> (8 * i)) & 0xffL)));
            }
        }
        return sb.toString();
    }

    /** The 32-byte state section after the final OP_RETURN of a locking script. */
    private static String stateTailHex(String scriptHex) {
        final int nibbles = 4 * 8 * 2;
        assertTrue(scriptHex.length() > nibbles + 2,
            "locking script too short to carry a 32-byte state section");
        int start = scriptHex.length() - nibbles;
        assertEquals("6a", scriptHex.substring(start - 2, start),
            "expected OP_RETURN (6a) before the 32-byte state section");
        return scriptHex.substring(start);
    }

    /** The user-facing grouped state entry, as longs. */
    private static List<Long> groupedTable(Map<String, Object> state) {
        Object raw = state.get("table");
        assertTrue(raw instanceof List, "state has no grouped `table` list: " + raw);
        List<Long> out = new ArrayList<>();
        for (Object v : (List<?>) raw) {
            if (v instanceof BigInteger b) {
                out.add(b.longValueExact());
            } else if (v instanceof Number n) {
                out.add(n.longValue());
            } else if (v instanceof String s) {
                // A grouped entry still holding the artifact's `initialValue`
                // is the compiler's `"0n"` literal form.
                out.add(Long.parseLong(s.endsWith("n") ? s.substring(0, s.length() - 1) : s));
            } else {
                throw new AssertionError("grouped `table` leaf is " + v + ", want a numeric value");
            }
        }
        return out;
    }

    private record Deployed(RunarContract contract, MockProvider provider, LocalSigner signer) {}

    private static Deployed deployArrayWrite() throws Exception {
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();
        provider.addUtxo(signer.address(),
            new UTXO("aa".repeat(32), 0, 1_000_000L,
                ScriptUtils.buildP2PKHScript(signer.address())));

        RunarContract contract = new RunarContract(loadArtifact(), List.of());
        contract.deploy(provider, signer, 50_000L, signer.address());
        return new Deployed(contract, provider, signer);
    }

    /**
     * OUTBOUND: the post-call state the interpreter computed under the SYNTHETIC
     * leaf names has to reach BOTH the continuation output's state section and
     * the grouped user-facing {@code table} entry. A stale grouped entry is a
     * state lie to every caller of {@code state()}, and it leaves the
     * continuation bytes depending entirely on {@code StateSerializer}'s
     * synthetic-key preference.
     */
    @Test
    void outboundContinuationAndGroupedEntryCarryTheComputedState() throws Exception {
        Deployed d = deployArrayWrite();

        assertEquals(leHex(0, 0, 0, 0),
            stateTailHex(d.contract().currentUtxo().scriptHex()),
            "deployed state section");

        d.contract().call("bump", List.of(BigInteger.ZERO), null, d.provider(), d.signer());

        assertEquals(leHex(1, 0, 0, 0),
            stateTailHex(d.contract().currentUtxo().scriptHex()),
            "the continuation committed a state the method did not compute");
        assertEquals(List.of(1L, 0L, 0L, 0L), groupedTable(d.contract().state()));
    }

    /**
     * INBOUND: the interpreter must see the CURRENT value of each leaf. If the
     * grouped entry is never spread over the synthetic names, {@code this.table[i]++}
     * evaluates against an absent property and every bump computes from the
     * property's {@code initialValue}.
     */
    @Test
    void inboundRepeatedBumpsOfOneSlotAccumulate() throws Exception {
        Deployed d = deployArrayWrite();

        for (long n = 1; n <= 3; n++) {
            d.contract().call("bump", List.of(BigInteger.ZERO), null, d.provider(), d.signer());
            assertEquals(leHex(n, 0, 0, 0),
                stateTailHex(d.contract().currentUtxo().scriptHex()),
                "after " + n + " bump(0) call(s)");
            assertEquals(List.of(n, 0L, 0L, 0L), groupedTable(d.contract().state()));
        }
    }

    /**
     * INBOUND, the sharper probe and the one that costs money: a contract
     * reconnected with {@link RunarContract#fromUtxo} carries the grouped entry
     * ONLY. Without the inbound bridge the interpreter falls back to each leaf's
     * ANF {@code initialValue}, and because the runtime-index write lowers to a
     * per-leaf select it rewrites ALL FOUR leaves — the call silently rewinds
     * the array to its deploy-time contents and commits that to the continuation.
     */
    @Test
    void inboundReconnectedContractCommitsTheRestoredState() throws Exception {
        Deployed d = deployArrayWrite();

        // Real on-chain history: table -> [0,2,0,0].
        for (int n = 0; n < 2; n++) {
            d.contract().call("bump", List.of(BigInteger.ONE), null, d.provider(), d.signer());
        }
        UTXO onChain = d.contract().currentUtxo();
        assertEquals(leHex(0, 2, 0, 0), stateTailHex(onChain.scriptHex()),
            "state section before reconnect");

        // A fresh process that only ever sees the deployed script.
        RunarContract restored = RunarContract.fromUtxo(loadArtifact(), onChain);
        assertFalse(restored.state().containsKey("table__1"),
            "fromUtxo leaked a synthetic leaf; this test no longer probes the "
                + "grouped-only restore path");
        assertEquals(List.of(0L, 2L, 0L, 0L), groupedTable(restored.state()));

        restored.call("bump", List.of(BigInteger.ONE), null, d.provider(), d.signer());

        assertEquals(leHex(0, 3, 0, 0),
            stateTailHex(restored.currentUtxo().scriptHex()),
            "the interpreter did not see the restored leaves");
        assertEquals(List.of(0L, 3L, 0L, 0L), groupedTable(restored.state()));
    }
}
