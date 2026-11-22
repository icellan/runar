package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * D25 (D12 PRE-F1), Java SDK: two UTXOs of one stateful contract spent in ONE
 * transaction that reach the same post-state used to be satisfied by ONE
 * continuation output. Port of the SDK half of
 * {@code packages/runar-sdk/src/__tests__/d25-twin-input.test.ts}.
 *
 * <p>This tier ships no Script VM, so each SDK-built transaction is checked
 * against what the covenant commits to, re-derived here independently of the
 * SDK's state derivation: (1) input i pushes the BIP-143 preimage of the
 * transaction at i under the method's covenant mode (checkPreimage), and (2)
 * the continuation the covenant rebuilds (code part + OP_RETURN + the expected
 * post-state, the binding field from the REAL spent outpoint) is the output
 * that preimage's hashOutputs commits to: {@code output[i]} alone under
 * SINGLE, the whole list under ALL. Every broadcast also passes the default
 * validating {@link MockProvider}.
 *
 * <p>Proves: Counter (examples/java, compiled by this tier) calls with
 * sigHashType 0x43 and {@code _newAmount, txPreimage}, its continuation at
 * output 0 with uncommitted change after it, two chained calls; MixedPot
 * chains increment / bump with {@code _spentOutpointHash = sha256(outpoint)};
 * the SDK's own two-input MixedPot call (additionalContractInputs) is refused
 * on the SECOND input for both methods, only by the binding; a Counter twin is
 * refused up front; PreparedCall's user-Sig digest under a SINGLE covenant is
 * the ALL|FORKID digest. Does NOT prove script execution or regtest
 * acceptance.
 */
class D25TwinInputTest {

    private static final String PRIV = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";
    private static final String FIELD = "_spentOutpointHash";
    private static final long CONTRACT_SATS = 5_000L;

    private static final String MIXED_SRC = """
        import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';
        class MixedPot extends StatefulSmartContract {
          count: bigint;
          constructor(count: bigint) { super(count); this.count = count; }
          public increment() { this.count++; }
          public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }
        }
        """;

    /** Class 1 with a user Sig: owner-gated mutate-only counter. */
    private static final String OWNED_SRC = """
        import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
        import type { PubKey, Sig } from 'runar-lang';
        class Owned extends StatefulSmartContract {
          count: bigint;
          readonly owner: PubKey;
          constructor(count: bigint, owner: PubKey) { super(count, owner); this.count = count; this.owner = owner; }
          public increment(sig: Sig) { assert(checkSig(sig, this.owner)); this.count++; }
        }
        """;

    private static Path repo() {
        return Paths.get(System.getProperty("user.dir"), "..", "..").normalize();
    }

    private static RunarArtifact counterArtifact() throws Exception {
        return SimulatedSpend.compile(repo().resolve(
            "examples/java/src/main/java/runar/examples/stateful-counter/Counter.runar.java"));
    }

    private record Env(MockProvider provider, LocalSigner signer) {}

    private static Env env() {
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();
        for (int i = 0; i < 4; i++) {
            provider.addUtxo(signer.address(),
                new UTXO(String.format("%02x", 0xf0 + i).repeat(32), 0, 1_000_000L,
                    ScriptUtils.buildP2PKHScript(signer.address())));
        }
        return new Env(provider, signer);
    }

    private static RunarContract deploy(RunarArtifact art, List<Object> args, Env e) {
        RunarContract c = new RunarContract(art, args);
        c.deploy(e.provider(), e.signer(), CONTRACT_SATS);
        return c;
    }

    private static byte[] sha256(byte[] b) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(b);
    }

    private static String wireOutpoint(UTXO u) {
        StringBuilder le = new StringBuilder();
        for (int i = 0; i < 4; i++) le.append(String.format("%02x", (u.outputIndex() >>> (8 * i)) & 0xff));
        return ScriptUtils.reverseHex(u.txid()) + le;
    }

    private static String bindingOf(UTXO spent) throws Exception {
        return ScriptUtils.bytesToHex(sha256(ScriptUtils.hexToBytes(wireOutpoint(spent))));
    }

    private static RunarArtifact.ABIMethod method(RunarArtifact art, String name) {
        return art.abi().methods().stream().filter(m -> m.name().equals(name)).findFirst().orElseThrow();
    }

    /** The continuation the covenant of {@code spent} rebuilds for {@code postState}. */
    private static String expectedContinuation(RunarArtifact art, UTXO spent, Map<String, Object> postState) {
        return ContractScript.extractCodePart(spent.scriptHex()) + "6a"
            + StateSerializer.serialize(art.stateFields(), postState);
    }

    /**
     * Whether the covenant of input {@code i} (spending {@code spent} through
     * {@code methodName}) accepts {@code tx}, given the post-state it must
     * continue into: the input pushes its honest preimage, and the output its
     * preimage commits to at the continuation's place is the expected one.
     */
    private static boolean covenantAccepts(RunarArtifact art, String methodName, RawTx tx, int i, UTXO spent,
                                           Map<String, Object> postState) {
        RunarArtifact.ABIMethod m = method(art, methodName);
        int mode = m.sigHashType() == null ? 0x41 : m.sigHashType();
        RunarContract rc = RunarContract.fromUtxo(art, spent);
        int codeSep = rc.getCodeSepIndex(rc.findPublicMethodIndex(methodName));
        String subscript = codeSep >= 0 ? RunarContract.subscriptAfterCodeSep(spent.scriptHex(), codeSep)
            : spent.scriptHex();
        byte[] preimage = OpPushTx.preimage(tx, i, ScriptUtils.hexToBytes(subscript), spent.satoshis(), mode);
        if (!tx.inputs.get(i).scriptSigHex.contains(ScriptUtils.bytesToHex(preimage))) return false;
        boolean single = (mode & 0x1f) == 0x03;
        // SINGLE: the continuation is output[i]; ALL: it leads the list (output 0).
        int contIdx = single ? i : 0;
        if (contIdx >= tx.outputs.size()) return false;
        RawTx.Output cont = tx.outputs.get(contIdx);
        boolean valueOk = cont.satoshis >= spent.satoshis(); // F-024 floor / extractAmount
        return valueOk && cont.scriptPubKeyHex.equals(expectedContinuation(art, spent, postState));
    }

    private static RawTx lastTx(Env e) {
        List<String> txs = e.provider().getBroadcastedTxs();
        return RawTxParser.parse(txs.get(txs.size() - 1));
    }

    private static Map<String, Object> state(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    /** The one DER-signature push (0x30 ... + sighash byte) of an unlocking script. */
    private static String derPush(String script) {
        String found = null;
        int i = 0;
        while (i < script.length()) {
            int op = Integer.parseInt(script.substring(i, i + 2), 16);
            i += 2;
            int len;
            if (op >= 1 && op <= 0x4b) {
                len = op;
            } else if (op == 0x4c) {
                len = Integer.parseInt(script.substring(i, i + 2), 16);
                i += 2;
            } else if (op == 0x4d) {
                len = Integer.parseInt(script.substring(i + 2, i + 4) + script.substring(i, i + 2), 16);
                i += 4;
            } else if (op == 0x4e) {
                len = Integer.parseInt(ScriptUtils.reverseHex(script.substring(i, i + 8)), 16);
                i += 8;
            } else {
                continue;
            }
            String data = script.substring(i, i + 2 * len);
            i += 2 * len;
            if (data.startsWith("30") && len >= 9 && len <= 73) {
                assertEquals(null, found, "exactly one signature push");
                found = data;
            }
        }
        assertNotNull(found, "no signature push in " + script);
        return found;
    }

    // ---- class 1: Counter ----------------------------------------------------

    @Test
    void counterHonestChainUnderSingle() throws Exception {
        RunarArtifact art = counterArtifact();
        for (String name : List.of("increment", "decrement")) {
            RunarArtifact.ABIMethod m = method(art, name);
            assertEquals(0x43, m.sigHashType(), name);
            assertEquals(List.of("_newAmount", "txPreimage"),
                m.params().stream().map(RunarArtifact.ABIParam::name).toList(), name);
        }
        Env e = env();
        RunarContract c = deploy(art, List.of(BigInteger.ZERO), e);
        for (long n = 1; n <= 2; n++) {
            UTXO spent = c.currentUtxo();
            c.call("increment", List.of(), null, e.provider(), e.signer());
            RawTx tx = lastTx(e);
            assertTrue(covenantAccepts(art, "increment", tx, 0, spent, state("count", BigInteger.valueOf(n))),
                "call " + n + ": the SINGLE covenant must accept its own continuation at output 0");
            assertTrue(tx.outputs.size() >= 2, "uncommitted change follows the continuation");
            assertEquals(BigInteger.valueOf(n), c.state().get("count"));
            assertTrue(e.provider().lastValidationReport().valueConserved(), "the validating MockProvider checked every input");
        }
    }

    @Test
    void counterTwinIsRefusedUpFront() throws Exception {
        RunarArtifact art = counterArtifact();
        Env e = env();
        RunarContract a = deploy(art, List.of(BigInteger.ZERO), e);
        RunarContract b = deploy(art, List.of(BigInteger.ZERO), e);
        int before = e.provider().getBroadcastedTxs().size();
        CallOptions opts = new CallOptions(null, null, null).withAdditionalContractInputs(List.of(b.currentUtxo()));
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> a.callWithOptions("increment", List.of(), opts, e.provider(), e.signer()));
        assertTrue(ex.getMessage().contains("additionalContractInputs cannot be spent into one continuation by a "
            + "SIGHASH_SINGLE method"), ex.getMessage());
        assertEquals(before, e.provider().getBroadcastedTxs().size(), "nothing broadcast");
    }

    // ---- class 2: MixedPot ---------------------------------------------------

    @Test
    void mixedPotHonestChainBindsTheRealOutpoint() throws Exception {
        RunarArtifact art = SimulatedSpend.compile(MIXED_SRC, "MixedPot.runar.ts");
        assertEquals(List.of("count", FIELD), SimulatedSpend.stateFieldNamesInOrder(art));
        assertEquals(List.of("count"),
            art.abi().constructor().params().stream().map(RunarArtifact.ABIParam::name).toList());
        Env e = env();
        RunarContract c = deploy(art, List.of(BigInteger.ZERO), e);
        assertEquals("00".repeat(32), c.state().get(FIELD), "zero at deploy");

        UTXO s1 = c.currentUtxo();
        c.call("increment", List.of(), null, e.provider(), e.signer());
        assertTrue(covenantAccepts(art, "increment", lastTx(e), 0, s1,
            state("count", BigInteger.ONE, FIELD, bindingOf(s1))));
        assertEquals(bindingOf(s1), c.state().get(FIELD));

        UTXO s2 = c.currentUtxo();
        c.call("bump", List.of(), null, e.provider(), e.signer());
        assertTrue(covenantAccepts(art, "bump", lastTx(e), 0, s2,
            state("count", BigInteger.TWO, FIELD, bindingOf(s2))));
        assertEquals(bindingOf(s2), c.state().get(FIELD));

        UTXO s3 = c.currentUtxo();
        c.call("increment", List.of(), null, e.provider(), e.signer());
        assertTrue(covenantAccepts(art, "increment", lastTx(e), 0, s3,
            state("count", BigInteger.valueOf(3), FIELD, bindingOf(s3))));
    }

    /**
     * CallOptions.newState / outputs never name the hidden field. The SDK must
     * write sha256(the outpoint this call spends) itself: left out, serialize
     * has no value; copied from state(), it is the previous outpoint's hash and
     * the covenant rejects the spend. The expected continuation is built here
     * by hand (code part || OP_RETURN || count as 8-byte LE || binding), not by
     * StateSerializer, and every broadcast passes the validating MockProvider.
     */
    @Test
    void mixedPotCallerSuppliedStateGetsTheSpentOutpointHash() throws Exception {
        RunarArtifact art = SimulatedSpend.compile(MIXED_SRC, "MixedPot.runar.ts");
        Env e = env();
        RunarContract c = deploy(art, List.of(BigInteger.ONE), e);
        String codePart = ContractScript.extractCodePart(c.currentUtxo().scriptHex());
        assertEquals(codePart + "6a" + "0100000000000000" + "00".repeat(32), c.currentUtxo().scriptHex());

        // 1. outputs: state without the hidden field.
        UTXO s1 = c.currentUtxo();
        c.callWithOptions("bump", List.of(), new CallOptions(null, null, null).withOutputs(List.of(
            new CallOptions.OutputSpec(BigInteger.valueOf(CONTRACT_SATS), state("count", BigInteger.TWO)))),
            e.provider(), e.signer());
        assertTrue(e.provider().lastValidationReport().valueConserved());
        assertEquals(codePart + "6a" + le8(2) + bindingOf(s1), lastTx(e).outputs.get(0).scriptPubKeyHex);
        assertEquals(codePart + "6a" + le8(2) + bindingOf(s1), c.currentUtxo().scriptHex());

        // 2. newState copied from state(): its hash is not this spend's.
        UTXO s2 = c.currentUtxo();
        Map<String, Object> stale = new LinkedHashMap<>(c.state());
        stale.put("count", BigInteger.valueOf(3));
        assertFalse(bindingOf(s2).equals(stale.get(FIELD)), "the copied hash is stale");
        c.callWithOptions("increment", List.of(), new CallOptions(stale, null, null), e.provider(), e.signer());
        assertTrue(e.provider().lastValidationReport().valueConserved());
        assertEquals(codePart + "6a" + le8(3) + bindingOf(s2), lastTx(e).outputs.get(0).scriptPubKeyHex);
        assertEquals(bindingOf(s2), c.state().get(FIELD));

        // 3. newState without the field (the tracked one is the previous call's).
        UTXO s3 = c.currentUtxo();
        c.callWithOptions("increment", List.of(), new CallOptions(state("count", BigInteger.valueOf(4)), null, null),
            e.provider(), e.signer());
        assertEquals(codePart + "6a" + le8(4) + bindingOf(s3), lastTx(e).outputs.get(0).scriptPubKeyHex);
        assertEquals(bindingOf(s3), c.state().get(FIELD));
        assertTrue(covenantAccepts(art, "increment", lastTx(e), 0, s3,
            state("count", BigInteger.valueOf(4), FIELD, bindingOf(s3))));
    }

    private static String le8(long n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) sb.append(String.format("%02x", (n >>> (8 * i)) & 0xff));
        return sb.toString();
    }

    /**
     * The SDK's own merge path spends two MixedPot UTXOs at the same state into
     * one continuation. Input 0's covenant accepts; input 1's rebuilds a
     * continuation carrying ITS outpoint, which is not in the tx: refused. The
     * same tx with input 0's binding substituted would verify on input 1 (the
     * pre-D25 theft), so the refusal is the binding's.
     */
    @Test
    void mixedPotTwinIsRefusedOnTheSecondInput() throws Exception {
        RunarArtifact art = SimulatedSpend.compile(MIXED_SRC, "MixedPot.runar.ts");
        for (String methodName : List.of("increment", "bump")) {
            Env e = env();
            RunarContract a = deploy(art, List.of(BigInteger.ZERO), e);
            RunarContract b = deploy(art, List.of(BigInteger.ZERO), e);
            UTXO u0 = a.currentUtxo();
            UTXO u1 = b.currentUtxo();
            CallOptions opts = new CallOptions(null, null, null).withAdditionalContractInputs(List.of(u1));
            a.callWithOptions(methodName, List.of(), opts, e.provider(), e.signer());
            RawTx tx = lastTx(e);
            assertEquals(u1.txid(), tx.inputs.get(1).prevTxid);

            assertTrue(covenantAccepts(art, methodName, tx, 0, u0,
                state("count", BigInteger.ONE, FIELD, bindingOf(u0))), methodName + ": input 0 verifies");
            assertFalse(covenantAccepts(art, methodName, tx, 1, u1,
                state("count", BigInteger.ONE, FIELD, bindingOf(u1))), methodName + ": input 1 must be refused");
            assertTrue(covenantAccepts(art, methodName, tx, 1, u1,
                state("count", BigInteger.ONE, FIELD, bindingOf(u0))),
                methodName + ": control: without its own binding input 1 would alias input 0's output");
        }
    }

    // ---- PreparedCall user-Sig digest ----------------------------------------

    @Test
    void preparedUserSigDigestIsAllForkidUnderASingleCovenant() throws Exception {
        RunarArtifact art = SimulatedSpend.compile(OWNED_SRC, "Owned.runar.ts");
        assertEquals(0x43, method(art, "increment").sigHashType());
        Env e = env();
        String owner = ScriptUtils.bytesToHex(e.signer().pubKey());
        RunarContract c = deploy(art, List.of(BigInteger.ZERO, owner), e);
        UTXO spent = c.currentUtxo();

        List<Object> args = new ArrayList<>();
        args.add(null);
        PreparedCall prep = c.prepareCall("increment", args, null, e.provider(), e.signer());
        RawTx tx = RawTxParser.parse(prep.txHex());
        int codeSep = c.getCodeSepIndex(c.findPublicMethodIndex("increment"));
        String subscript = RunarContract.subscriptAfterCodeSep(spent.scriptHex(), codeSep);
        byte[] all = tx.sighashBIP143(0, subscript, spent.satoshis(), 0x41);
        byte[] single = tx.sighashBIP143(0, subscript, spent.satoshis(), 0x43);
        assertEquals(1, prep.sighashes().size());
        assertArrayEquals(all, prep.sighashes().get(0), "the user Sig digest is the ALL|FORKID one");
        assertFalse(java.util.Arrays.equals(all, single));

        byte[] der = e.signer().sign(prep.sighashes().get(0), null);
        RunarContract.CallOutcome out = c.finalizeCall(prep, List.of(der), e.provider());
        assertNotNull(out.txid());
        RawTx done = RawTxParser.parse(out.rawTxHex());
        assertTrue(done.inputs.get(0).scriptSigHex.contains(ScriptUtils.bytesToHex(der) + "41"),
            "the user Sig carries the ALL|FORKID byte");
        assertTrue(covenantAccepts(art, "increment", done, 0, spent, state("count", BigInteger.ONE)));

        // call() signs the same digest in-process.
        UTXO spent2 = c.currentUtxo();
        c.call("increment", args, null, e.provider(), e.signer());
        RawTx t2 = lastTx(e);
        byte[] all2 = t2.sighashBIP143(0, RunarContract.subscriptAfterCodeSep(spent2.scriptHex(), codeSep),
            spent2.satoshis(), 0x41);
        String sig = derPush(t2.inputs.get(0).scriptSigHex);
        assertTrue(sig.endsWith("41"), "call()'s user Sig carries the ALL|FORKID byte");
        assertTrue(AnfInterpreter.verifyEcdsaReal(sig, owner, all2),
            "call()'s user Sig verifies against the ALL|FORKID digest");
    }
}
