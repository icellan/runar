package runar.integration;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
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
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Merkle proof verification integration tests. Compiles a minimal
 * inline contract that calls {@code merkleRootSha256} on a depth-4
 * tree (16 leaves) and exercises both valid and invalid proofs.
 *
 * <p>Ported from {@code integration/python/test_merkle_proof.py}.
 */
class MerkleProofIntegrationTest extends IntegrationBase {

    private static final String SOURCE = """
        import { SmartContract, assert, merkleRootSha256 } from 'runar-lang';
        import type { ByteString } from 'runar-lang';

        class MerkleSha256Test extends SmartContract {
          readonly expectedRoot: ByteString;
          constructor(expectedRoot: ByteString) {
            super(expectedRoot);
            this.expectedRoot = expectedRoot;
          }
          public verify(leaf: ByteString, proof: ByteString, index: bigint) {
            const root = merkleRootSha256(leaf, proof, index, 4n);
            assert(root === this.expectedRoot);
          }
        }
        """;

    private static String sha256Hex(String hex) {
        try {
            byte[] data = fromHex(hex);
            byte[] h = MessageDigest.getInstance("SHA-256").digest(data);
            return toHex(h);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] fromHex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
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
        String root() { return layers.get(layers.size() - 1).get(0); }
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

    private static RunarArtifact compileSource() {
        Path tmp;
        try {
            tmp = Files.createTempFile("runar-merkle-", "MerkleSha256Test.runar.ts");
            Files.writeString(tmp, SOURCE);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return ContractCompiler.compileAbsolute(tmp);
    }

    @Test
    @DisplayName("merkleRootSha256: leaf at index 0 verifies on-chain")
    void leafIndex0() {
        Tree t = buildTree();
        String[] p = proof(t, 0);

        RunarArtifact a = compileSource();
        assertEquals("MerkleSha256Test", a.contractName());
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(t.root()));
        contract.deploy(provider, wallet.signer(), 5_000L);

        RunarContract.CallOutcome out = contract.call(
            "verify", List.of(p[0], p[1], BigInteger.ZERO), null, provider, wallet.signer()
        );
        assertNotNull(out.txid());
    }

    @Test
    @DisplayName("merkleRootSha256: leaf at index 7 verifies on-chain")
    void leafIndex7() {
        Tree t = buildTree();
        String[] p = proof(t, 7);

        RunarArtifact a = compileSource();
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(t.root()));
        contract.deploy(provider, wallet.signer(), 5_000L);

        contract.call(
            "verify", List.of(p[0], p[1], BigInteger.valueOf(7)), null, provider, wallet.signer()
        );
    }

    @Test
    @DisplayName("merkleRootSha256: wrong leaf rejected on-chain")
    void wrongLeafRejected() {
        Tree t = buildTree();
        String[] p = proof(t, 0);
        String wrongLeaf = sha256Hex("ff");

        RunarArtifact a = compileSource();
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(t.root()));
        contract.deploy(provider, wallet.signer(), 5_000L);

        assertThrows(RuntimeException.class, () ->
            contract.call(
                "verify", List.of(wrongLeaf, p[1], BigInteger.ZERO), null, provider, wallet.signer()
            )
        );
    }
}
