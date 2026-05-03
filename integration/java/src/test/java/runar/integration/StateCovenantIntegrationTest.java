package runar.integration;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import runar.integration.helpers.ContractCompiler;
import runar.integration.helpers.IntegrationBase;
import runar.integration.helpers.IntegrationWallet;
import runar.integration.helpers.RpcProvider;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarContract;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * StateCovenant integration test -- stateful covenant combining BabyBear
 * field arithmetic, Merkle proof verification, and hash256 batch data
 * binding.
 *
 * <p>Ported from {@code integration/python/test_state_covenant.py}.
 * Java compiles this contract through the TS reference compiler (the
 * Java compiler also accepts BabyBear builtins via its
 * {@code BuiltinRegistry}, so the Java-surface variant could also be
 * compiled — but the TS reference is what every other integration test
 * pins, so we follow that here).
 */
class StateCovenantIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/state-covenant/StateCovenant.runar.ts";
    private static final long BB_PRIME = 2_013_265_921L;

    private static String sha256Hex(String hex) {
        try {
            byte[] data = fromHex(hex);
            byte[] h = MessageDigest.getInstance("SHA-256").digest(data);
            return toHex(h);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String hash256Hex(String hex) {
        return sha256Hex(sha256Hex(hex));
    }

    private static String stateRoot(int n) {
        return sha256Hex(String.format("%02x", n));
    }

    private static String zeros32() {
        return "0".repeat(64);
    }

    private static byte[] fromHex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    private static class Tree {
        List<List<String>> layers;
    }

    private static Tree buildTree() {
        List<String> leaves = new ArrayList<>();
        for (int i = 0; i < 16; i++) leaves.add(sha256Hex(String.format("%02x", i)));
        Tree t = new Tree();
        t.layers = new ArrayList<>();
        t.layers.add(leaves);
        List<String> level = leaves;
        while (level.size() > 1) {
            List<String> next = new ArrayList<>();
            for (int i = 0; i < level.size(); i += 2) {
                next.add(sha256Hex(level.get(i) + level.get(i + 1)));
            }
            t.layers.add(next);
            level = next;
        }
        return t;
    }

    private static String[] proof(Tree t, int index) {
        StringBuilder siblings = new StringBuilder();
        int idx = index;
        for (int d = 0; d < t.layers.size() - 1; d++) {
            siblings.append(t.layers.get(d).get(idx ^ 1));
            idx >>= 1;
        }
        return new String[] { t.layers.get(0).get(index), siblings.toString() };
    }

    private static List<Object> buildCallArgs(Tree t, String preStateRoot, int newBlockNumber) {
        String newStateRoot = stateRoot(newBlockNumber);
        String batchHash = hash256Hex(preStateRoot + newStateRoot);
        long proofA = 1_000_000L;
        long proofB = 2_000_000L;
        long proofC = (proofA * proofB) % BB_PRIME;
        String[] p = proof(t, 3);
        ArrayList<Object> args = new ArrayList<>();
        args.add(newStateRoot);
        args.add(BigInteger.valueOf(newBlockNumber));
        args.add(batchHash);
        args.add(preStateRoot);
        args.add(BigInteger.valueOf(proofA));
        args.add(BigInteger.valueOf(proofB));
        args.add(BigInteger.valueOf(proofC));
        args.add(p[0]);
        args.add(p[1]);
        args.add(BigInteger.valueOf(3));
        return args;
    }

    @Test
    @DisplayName("deploy StateCovenant with initial state")
    void deploy() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        Tree t = buildTree();
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            zeros32(), BigInteger.ZERO, t.layers.get(t.layers.size() - 1).get(0)
        ));
        RunarContract.DeployOutcome out = contract.deploy(provider, wallet.signer(), 10_000L);
        assertNotNull(out.txid());
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("advanceState with valid inputs succeeds")
    void advanceState() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        Tree t = buildTree();
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            zeros32(), BigInteger.ZERO, t.layers.get(t.layers.size() - 1).get(0)
        ));
        contract.deploy(provider, wallet.signer(), 10_000L);

        List<Object> args = buildCallArgs(t, zeros32(), 1);
        RunarContract.CallOutcome out = contract.call(
            "advanceState", args, null, provider, wallet.signer()
        );
        assertNotNull(out.txid());
    }

    @Test
    @DisplayName("Java-surface StateCovenant matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/state-covenant/StateCovenant.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
