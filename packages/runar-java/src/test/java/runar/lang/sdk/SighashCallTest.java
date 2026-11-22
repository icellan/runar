package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Issue #123 — the deployment SDK threads a public method's declared @sighash
 * mode (carried on ABIMethod.sigHashType) into the OP_PUSH_TX covenant preimage
 * + derived signature. A non-default mode changes the preimage's trailing
 * sighashType field and the appended DER flag byte; the default stays 0x41.
 */
class SighashCallTest {

    private static final String PRIV =
        "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";

    private static RunarArtifact load(String name) throws Exception {
        try (var in = SighashCallTest.class.getClassLoader().getResourceAsStream("artifacts/" + name)) {
            return RunarArtifact.fromJson(new String(in.readAllBytes()));
        }
    }

    /** Decode data pushes of a scriptSig (OP_0 -> empty, OP_PUSHDATA1/2 supported). */
    private static List<String> parsePushes(String scriptHex) {
        List<String> pushes = new ArrayList<>();
        int p = 0;
        int n = scriptHex.length() / 2;
        while (p < n) {
            int op = Integer.parseInt(scriptHex.substring(p * 2, p * 2 + 2), 16);
            p += 1;
            if (op == 0x00) {
                pushes.add("");
            } else if (op >= 0x01 && op <= 0x4b) {
                pushes.add(scriptHex.substring(p * 2, (p + op) * 2));
                p += op;
            } else if (op == 0x4c) {
                int len = Integer.parseInt(scriptHex.substring(p * 2, p * 2 + 2), 16);
                p += 1;
                pushes.add(scriptHex.substring(p * 2, (p + len) * 2));
                p += len;
            } else if (op == 0x4d) {
                int len = Integer.parseInt(scriptHex.substring(p * 2, p * 2 + 2), 16)
                    | (Integer.parseInt(scriptHex.substring(p * 2 + 2, p * 2 + 4), 16) << 8);
                p += 2;
                pushes.add(scriptHex.substring(p * 2, (p + len) * 2));
                p += len;
            } else {
                pushes.add("");
            }
        }
        return pushes;
    }

    private static String largestPush(List<String> pushes) {
        String big = "";
        for (String s : pushes) {
            if (s.length() > big.length()) big = s;
        }
        return big;
    }

    private String callPledgeUnlock(RunarArtifact artifact) throws Exception {
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();
        provider.addUtxo(signer.address(),
            new UTXO("ff".repeat(32), 7, 200_000L, ScriptUtils.buildP2PKHScript(signer.address())));
        RunarContract contract = new RunarContract(artifact, List.of(BigInteger.ZERO));
        UTXO utxo = new UTXO("cc".repeat(32), 0, 5_000L, contract.lockingScript());
        contract.setCurrentUtxo(utxo);
        // Phase A5 non-vacuity: the fail-closed MockProvider must also know the
        // outpoint this call spends — injecting it straight into the contract
        // bypasses the provider, which would then have nothing to check.
        provider.addKnownOutpoint(utxo);
        Map<String, Object> updates = new HashMap<>();
        updates.put("raised", BigInteger.valueOf(7));
        RunarContract.CallOutcome out = contract.call(
            "pledge", List.of(BigInteger.valueOf(7)), updates, provider, signer);
        RawTx tx = RawTxParser.parse(out.rawTxHex());
        return tx.inputs.get(0).scriptSigHex;
    }

    @Test
    void anyonecanpayCallBuildsPreimageAndSigUnder0xc3() throws Exception {
        String unlock = callPledgeUnlock(load("fund-acp.runar.json"));
        List<String> pushes = parsePushes(unlock);
        String preimage = largestPush(pushes);
        // Optimal OP_PUSH_TX derives the covenant signature ON-CHAIN from the
        // preimage (no witness sig is pushed), so the SDK's contribution is the
        // preimage itself. D25: Fund's only continuation method is mutate-only,
        // so its ALL|ANYONECANPAY|FORKID directive compiles to
        // SINGLE|ANYONECANPAY|FORKID; the trailing sighashType (LE uint32) is
        // 0xc3 -> "c3000000", proving the SDK built it under the artifact's mode.
        assertTrue(preimage.endsWith("c3000000"),
            "ANYONECANPAY preimage must end with sighashType c3000000; tail="
                + preimage.substring(Math.max(0, preimage.length() - 8)));
    }

    @Test
    void defaultCallBuildsPreimageAndSigUnder0x43() throws Exception {
        String unlock = callPledgeUnlock(load("fund-default.runar.json"));
        List<String> pushes = parsePushes(unlock);
        String preimage = largestPush(pushes);
        // D25: a mutate-only contract's default is SINGLE|FORKID (0x43).
        assertTrue(preimage.endsWith("43000000"),
            "default preimage must end with sighashType 43000000; tail="
                + preimage.substring(Math.max(0, preimage.length() - 8)));
    }
}
