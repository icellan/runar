package runar.lang.sdk;

import java.math.BigInteger;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tier-parity gap: the Java SDK had no way to spend more than one contract UTXO
 * in a single call. Every other tier exposes {@code additionalContractInputs} +
 * {@code additionalContractInputArgs} (TypeScript {@code CallOptions}, Go
 * {@code CallOptions}, Rust/Python/Zig/Ruby equivalents), which is what makes
 * merge / swap / any multi-input covenant pattern reachable from the SDK.
 * Java had zero references to it, so a Java-only deployment could mint token
 * UTXOs it could never recombine.
 *
 * <p>The canonical exercise is the fungible-token {@code merge} method:
 * two contract UTXOs holding balances 400 and 600 are spent by one transaction
 * that produces a single continuation. The covenant binds every input through
 * {@code allPrevouts}, so the SDK must also auto-resolve that parameter from
 * the transaction's own inputs — the second half of the gap, since Java's
 * null-arg guard rejected every null {@code ByteString} including this one.
 */
class AdditionalContractInputsTest {

    private static final String PRIV =
        "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";
    private static final String FUND_TXID = "ff".repeat(32);
    private static final long FUND_SATS = 5_000_000L;
    private static final String TOKEN_ID = "4d45524745"; // "MERGE"

    private static RunarArtifact tokenArtifact() throws Exception {
        try (var in = AdditionalContractInputsTest.class.getClassLoader()
                .getResourceAsStream("artifacts/token-ft.runar.json")) {
            assertTrue(in != null, "token-ft artifact resource must exist");
            return RunarArtifact.fromJson(new String(in.readAllBytes()));
        }
    }

    private record Setup(
        RunarContract first, RunarContract second, MockProvider provider, LocalSigner signer
    ) {}

    /** Deploy two token contracts under one owner: balances 400 and 600. */
    private static Setup deployPair() throws Exception {
        RunarArtifact artifact = tokenArtifact();
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();
        provider.addUtxo(signer.address(),
            new UTXO(FUND_TXID, 0, FUND_SATS, ScriptUtils.buildP2PKHScript(signer.address())));

        String ownerHex = ScriptUtils.bytesToHex(signer.pubKey());
        RunarContract first = new RunarContract(artifact, List.of(
            ownerHex, BigInteger.valueOf(400), BigInteger.ZERO, TOKEN_ID));
        first.deploy(provider, signer, 1L, signer.address());

        RunarContract second = new RunarContract(artifact, List.of(
            ownerHex, BigInteger.valueOf(600), BigInteger.ZERO, TOKEN_ID));
        second.deploy(provider, signer, 1L, signer.address());

        return new Setup(first, second, provider, signer);
    }

    @Test
    void mergeSpendsBothContractUtxosInOneTransaction() throws Exception {
        Setup s = deployPair();
        UTXO other = s.second().currentUtxo();
        UTXO primary = s.first().currentUtxo();

        CallOptions opts = new CallOptions(null, null, null)
            .withAdditionalContractInputs(List.of(other))
            .withAdditionalContractInputArgs(List.of(
                // merge(sig, otherBalance, allPrevouts, outputSatoshis) as seen
                // from the SECOND input: its counterpart holds 400.
                java.util.Arrays.asList(null, BigInteger.valueOf(400), null, BigInteger.ONE)
            ));

        s.first().callWithOptions(
            "merge",
            java.util.Arrays.asList(null, BigInteger.valueOf(600), null, BigInteger.ONE),
            opts, s.provider(), s.signer());

        List<String> txs = s.provider().getBroadcastedTxs();
        RawTx callTx = RawTxParser.parse(txs.get(txs.size() - 1));

        // Both contract UTXOs must be inputs, at indices 0 and 1, ahead of any
        // P2PKH funding input.
        assertTrue(callTx.inputs.size() >= 2,
            "merge tx must carry both contract inputs, got " + callTx.inputs.size());
        assertEquals(primary.txid(), callTx.inputs.get(0).prevTxid,
            "input 0 stays the primary contract UTXO");
        assertEquals(primary.outputIndex(), callTx.inputs.get(0).prevVout);
        assertEquals(other.txid(), callTx.inputs.get(1).prevTxid,
            "input 1 must be the additional contract UTXO");
        assertEquals(other.outputIndex(), callTx.inputs.get(1).prevVout);

        // Each contract input carries its OWN unlocking script — the second one
        // is not a copy of the first (different preimage, different args).
        String unlock0 = callTx.inputs.get(0).scriptSigHex;
        String unlock1 = callTx.inputs.get(1).scriptSigHex;
        assertTrue(unlock0 != null && !unlock0.isEmpty(), "input 0 must be unlocked");
        assertTrue(unlock1 != null && !unlock1.isEmpty(),
            "input 1 must carry its own unlocking script, not an empty placeholder");
        assertNotEquals(unlock0, unlock1,
            "the two contract inputs must not share an unlocking script — each binds "
                + "its own outpoint through its own BIP-143 preimage");

        // The failure this port could plausibly introduce is a second input
        // whose preimage still describes input 0's outpoint — the covenant
        // would then verify the wrong UTXO. BIP-143 puts the spent outpoint at
        // byte offset 68 (4 nVersion + 32 hashPrevouts + 32 hashSequence),
        // 36 bytes of txid(LE) || vout(LE32). Check each unlock's preimage
        // names its own input.
        int csi = tokenArtifact().codeSeparatorIndex();
        assertEquals(outpointLE(primary), outpointInPreimage(unlock0, primary, csi),
            "input 0's preimage must bind input 0's outpoint");
        assertEquals(outpointLE(other), outpointInPreimage(unlock1, other, csi),
            "input 1's preimage must bind ITS OWN outpoint, not input 0's");
    }

    @Test
    void terminalCallsRejectAdditionalContractInputsRatherThanDropThem() throws Exception {
        Setup s = deployPair();
        CallOptions opts = new CallOptions(
            null,
            List.of(new CallOptions.TerminalOutput(
                BigInteger.ONE, s.signer().address(), null)),
            null)
            .withAdditionalContractInputs(List.of(s.second().currentUtxo()));

        // The terminal builder lays out exactly one contract input. Accepting
        // the option there would spend less than the caller asked for while
        // reporting success.
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
            s.first().callWithOptions(
                "merge",
                java.util.Arrays.asList(null, BigInteger.valueOf(600), null, BigInteger.ONE),
                opts, s.provider(), s.signer()));
        assertTrue(e.getMessage().contains("additionalContractInputs"),
            "the error must name the option that was rejected, got: " + e.getMessage());
    }

    /** {@code txid} little-endian || {@code vout} LE32, as BIP-143 serialises it. */
    private static String outpointLE(UTXO u) {
        return ScriptUtils.reverseHex(u.txid()) + ScriptUtils.toLittleEndian32(u.outputIndex());
    }

    /**
     * Extract the 36-byte spent outpoint from the BIP-143 preimage pushed
     * inside an unlocking script. The preimage's length is fully determined by
     * the input's own scriptCode, so find the push of exactly that length —
     * unambiguous, unlike "the biggest push".
     */
    private static String outpointInPreimage(String unlockHex, UTXO spent, int codeSepIdx) {
        String scriptCode = codeSepIdx >= 0
            ? spent.scriptHex().substring((codeSepIdx + 1) * 2)
            : spent.scriptHex();
        int wantLen = RunarContract.bip143PreimageLen(scriptCode);

        int i = 0;
        while (i < unlockHex.length()) {
            int op = Integer.parseInt(unlockHex.substring(i, i + 2), 16);
            int dataStart, len;
            if (op >= 1 && op <= 75) {
                len = op; dataStart = i + 2;
            } else if (op == 0x4c) {
                len = Integer.parseInt(unlockHex.substring(i + 2, i + 4), 16);
                dataStart = i + 4;
            } else if (op == 0x4d) {
                String le = unlockHex.substring(i + 2, i + 6);
                len = Integer.parseInt(le.substring(2, 4) + le.substring(0, 2), 16);
                dataStart = i + 6;
            } else if (op == 0x4e) {
                String le = unlockHex.substring(i + 2, i + 10);
                len = Integer.parseInt(le.substring(6, 8) + le.substring(4, 6)
                    + le.substring(2, 4) + le.substring(0, 2), 16);
                dataStart = i + 10;
            } else {
                i += 2; continue;
            }
            if (len == wantLen) {
                return unlockHex.substring(dataStart + 68 * 2, dataStart + 104 * 2);
            }
            i = dataStart + len * 2;
        }
        throw new AssertionError(
            "no " + wantLen + "-byte preimage push found in the unlocking script");
    }

    @Test
    void mergeFeeCoversTheLargerMultiInputTransaction() throws Exception {
        Setup s = deployPair();
        UTXO other = s.second().currentUtxo();
        String deployTxid1 = s.first().currentUtxo().txid();

        CallOptions opts = new CallOptions(null, null, null)
            .withAdditionalContractInputs(List.of(other))
            .withAdditionalContractInputArgs(List.of(
                java.util.Arrays.asList(null, BigInteger.valueOf(400), null, BigInteger.ONE)));

        s.first().callWithOptions(
            "merge",
            java.util.Arrays.asList(null, BigInteger.valueOf(600), null, BigInteger.ONE),
            opts, s.provider(), s.signer());

        List<String> txs = s.provider().getBroadcastedTxs();
        String callTxHex = txs.get(txs.size() - 1);
        RawTx callTx = RawTxParser.parse(callTxHex);

        // Resolve every input's value. MockProvider mints its own txids on
        // broadcast, so map the two we can observe (each contract's tracked
        // UTXO names the deploy tx that produced it) plus the seeded wallet
        // UTXO; a funding input spent from a deploy's change output resolves
        // through the same map.
        RawTx deploy1 = RawTxParser.parse(txs.get(0));
        RawTx deploy2 = RawTxParser.parse(txs.get(1));
        long inSats = 0;
        for (RawTx.Input in : callTx.inputs) {
            if (in.prevTxid.equals(deployTxid1)) {
                inSats += deploy1.outputs.get(in.prevVout).satoshis;
            } else if (in.prevTxid.equals(other.txid())) {
                inSats += deploy2.outputs.get(in.prevVout).satoshis;
            } else if (in.prevTxid.equals(FUND_TXID)) {
                inSats += FUND_SATS;
            } else {
                throw new AssertionError("unresolved input source " + in.prevTxid);
            }
        }
        long outSats = 0;
        for (RawTx.Output o : callTx.outputs) outSats += o.satoshis;

        long paid = inSats - outSats;
        long bytes = callTxHex.length() / 2;
        long needed = Math.max(1L, (bytes * s.provider().getFeeRate() + 999) / 1000);

        assertTrue(paid >= needed,
            "merge tx must pay the relay fee for its own (two-contract-input) size: paid "
                + paid + " sat, needs " + needed + " sat for " + bytes + " bytes");
    }

    @Test
    void feeStillCoversTheTxWhenMoreThanOneFundingInputIsNeeded() throws Exception {
        // The `allPrevouts` stand-in is sized for an ASSUMED input count
        // (contract + extras + one funding input). Its real value is spliced in
        // after the layout passes have already fixed the change output, so if
        // coin selection pulls a different number of funding inputs the unlock
        // grows by 36 bytes per extra input and the fee is short by that much —
        // the same defect class as the 181-byte preimage stand-in.
        //
        // Force TWO funding inputs by seeding ONLY small UTXOs. The contracts
        // are placed with setCurrentUtxo rather than deploy() so no large coin
        // has to exist in the wallet — with one, largest-first selection would
        // cover everything in a single input and the test would pass vacuously.
        RunarArtifact artifact = tokenArtifact();
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();
        String p2pkh = ScriptUtils.buildP2PKHScript(signer.address());
        for (int i = 0; i < 8; i++) {
            provider.addUtxo(signer.address(),
                new UTXO("ab".repeat(31) + String.format("%02x", i), 0, 300L, p2pkh));
        }

        String ownerHex = ScriptUtils.bytesToHex(signer.pubKey());
        List<Object> args1 = List.of(ownerHex, BigInteger.valueOf(400), BigInteger.ZERO, TOKEN_ID);
        List<Object> args2 = List.of(ownerHex, BigInteger.valueOf(600), BigInteger.ZERO, TOKEN_ID);
        RunarContract first = new RunarContract(artifact, args1);
        RunarContract second = new RunarContract(artifact, args2);
        UTXO primary = new UTXO("cc".repeat(32), 0, 1L,
            ContractScript.renderLockingScript(artifact, args1, null));
        UTXO other = new UTXO("dd".repeat(32), 0, 1L,
            ContractScript.renderLockingScript(artifact, args2, null));
        first.setCurrentUtxo(primary);
        // Phase A5 non-vacuity: the fail-closed MockProvider must also know the
        // outpoint this call spends — injecting it straight into the contract
        // bypasses the provider, which would then have nothing to check.
        provider.addKnownOutpoint(primary);
        second.setCurrentUtxo(other);
        // Phase A5 non-vacuity: the fail-closed MockProvider must also know the
        // outpoint this call spends — injecting it straight into the contract
        // bypasses the provider, which would then have nothing to check.
        provider.addKnownOutpoint(other);
        CallOptions opts = new CallOptions(null, null, null)
            .withAdditionalContractInputs(List.of(other))
            .withAdditionalContractInputArgs(List.of(
                java.util.Arrays.asList(null, BigInteger.valueOf(400), null, BigInteger.ONE)));
        first.callWithOptions(
            "merge",
            java.util.Arrays.asList(null, BigInteger.valueOf(600), null, BigInteger.ONE),
            opts, provider, signer);

        List<String> txs = provider.getBroadcastedTxs();
        String callTxHex = txs.get(txs.size() - 1);
        RawTx callTx = RawTxParser.parse(callTxHex);

        long inSats = 0;
        int fundingInputs = 0;
        for (RawTx.Input in : callTx.inputs) {
            if (in.prevTxid.equals(primary.txid()) || in.prevTxid.equals(other.txid())) {
                inSats += 1L; // contract UTXO
            } else {
                inSats += 300L; // one of the eight small coins
                fundingInputs++;
            }
        }
        // Guard against a vacuous pass: if coin selection happened to pull
        // exactly one funding input, this test exercises the same shape as the
        // one above and proves nothing about the stand-in's sizing assumption.
        assertTrue(fundingInputs >= 2,
            "this test must exercise MORE than one funding input to be meaningful, got "
                + fundingInputs + " (total inputs " + callTx.inputs.size() + ")");
        long outSats = 0;
        for (RawTx.Output o : callTx.outputs) outSats += o.satoshis;
        long paid = inSats - outSats;
        long bytes = callTxHex.length() / 2;
        long needed = Math.max(1L, (bytes * provider.getFeeRate() + 999) / 1000);

        assertTrue(paid >= needed,
            "merge tx must pay the relay fee for its own size regardless of how many "
                + "funding inputs coin selection pulled: paid " + paid + " sat, needs "
                + needed + " sat for " + bytes + " bytes, "
                + callTx.inputs.size() + " inputs");
    }

    @Test
    void perInputArgsCountMustMatchTheInputCount() throws Exception {
        Setup s = deployPair();
        CallOptions opts = new CallOptions(null, null, null)
            .withAdditionalContractInputs(List.of(s.second().currentUtxo()))
            .withAdditionalContractInputArgs(List.of(
                java.util.Arrays.asList(null, BigInteger.valueOf(400), null, BigInteger.ONE),
                java.util.Arrays.asList(null, BigInteger.valueOf(999), null, BigInteger.ONE)));

        // Two arg lists for one extra input is a caller mistake that would
        // otherwise silently drop the second: fail loudly instead.
        assertThrows(IllegalArgumentException.class, () ->
            s.first().callWithOptions(
                "merge",
                java.util.Arrays.asList(null, BigInteger.valueOf(600), null, BigInteger.ONE),
                opts, s.provider(), s.signer()));
    }

    /**
     * N-294: {@code layoutPushTx}'s funding-candidate filter excluded only
     * {@code currentUtxo} (the primary contract input), not
     * {@code additionalContractInputs} — TS excludes BOTH under finding
     * F-045 (see {@code f045-token-wallet-signs-broadcast-tx.test.ts},
     * "a token UTXO larger than the funding coin is still spent as a
     * contract input, not as funding").
     *
     * <p>An indexer that lists a token UTXO under the signer's own address
     * (exactly what {@code provider.addUtxo(signer.address(), other)} below
     * simulates — the same scenario the TS fix targets) made that UTXO a
     * legitimate-looking P2PKH funding candidate too. Largest-first coin
     * selection in {@code TransactionBuilder.buildCallTransactionFull}
     * always spends at least one funding candidate when any exist (N-292
     * TS parity), so a large-enough "extra contract input" outranks a small
     * genuine funding coin and gets selected AGAIN as funding — spending
     * the same outpoint twice in one transaction.
     */
    @Test
    void mergeNeverSelectsTheAdditionalContractUtxoAsFunding() throws Exception {
        RunarArtifact artifact = tokenArtifact();
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();
        String p2pkh = ScriptUtils.buildP2PKHScript(signer.address());

        String ownerHex = ScriptUtils.bytesToHex(signer.pubKey());
        List<Object> args1 = List.of(ownerHex, BigInteger.valueOf(400), BigInteger.ZERO, TOKEN_ID);
        List<Object> args2 = List.of(ownerHex, BigInteger.valueOf(600), BigInteger.ZERO, TOKEN_ID);
        RunarContract first = new RunarContract(artifact, args1);
        RunarContract second = new RunarContract(artifact, args2);

        // `other` carries a LARGE satoshi value so largest-first selection
        // prefers it over the genuine small funding coin, if it is (wrongly)
        // treated as a funding candidate.
        UTXO primary = new UTXO("cc".repeat(32), 0, 1L,
            ContractScript.renderLockingScript(artifact, args1, null));
        UTXO other = new UTXO("dd".repeat(32), 0, 300_000L,
            ContractScript.renderLockingScript(artifact, args2, null));
        first.setCurrentUtxo(primary);
        provider.addKnownOutpoint(primary);
        second.setCurrentUtxo(other);

        // A small genuine P2PKH funding coin — alone, comfortably enough to
        // cover the tx fee.
        UTXO funding = new UTXO("ee".repeat(32), 0, 2_000L, p2pkh);
        provider.addUtxo(signer.address(), funding);
        // The indexer ALSO lists the second token UTXO under the signer's
        // own address (F-045's exact scenario). addUtxo registers it both
        // as a candidate from provider.listUtxos(signer.address()) and as a
        // known outpoint for broadcast validation.
        provider.addUtxo(signer.address(), other);

        CallOptions opts = new CallOptions(null, null, null)
            .withAdditionalContractInputs(List.of(other))
            .withAdditionalContractInputArgs(List.of(
                java.util.Arrays.asList(null, BigInteger.valueOf(400), null, BigInteger.ONE)));
        first.callWithOptions(
            "merge",
            java.util.Arrays.asList(null, BigInteger.valueOf(600), null, BigInteger.ONE),
            opts, provider, signer);

        List<String> txs = provider.getBroadcastedTxs();
        RawTx callTx = RawTxParser.parse(txs.get(txs.size() - 1));

        long otherOccurrences = callTx.inputs.stream()
            .filter(in -> in.prevTxid.equals(other.txid()) && in.prevVout == other.outputIndex())
            .count();
        assertEquals(1, otherOccurrences,
            "the additional contract UTXO must be spent exactly once (as the merge's extra "
                + "contract input), never a second time as a P2PKH funding input — got "
                + otherOccurrences + " occurrences among " + callTx.inputs.size() + " inputs");
    }
}
