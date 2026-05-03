package runar.integration;

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
 * SimpleNFT integration test -- stateful contract with addOutput.
 *
 * <p>Ported from {@code integration/python/test_nft.py}. Constructor:
 * {@code (owner: PubKey, tokenId: ByteString, metadata: ByteString)}.
 */
class TokenNftIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/token-nft/NFTExample.runar.ts";

    private static String hexAscii(String s) {
        StringBuilder sb = new StringBuilder(s.length() * 2);
        for (char c : s.toCharArray()) sb.append(String.format("%02x", (int) c & 0xff));
        return sb.toString();
    }

    @Test
    @DisplayName("compile produces a SimpleNFT artifact")
    void compile() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        assertEquals("SimpleNFT", a.contractName());
    }

    @Test
    @DisplayName("deploy with owner + tokenId + metadata")
    void deploy() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.create();
        IntegrationWallet funder = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            owner.pubKeyHex(), hexAscii("NFT-001"), hexAscii("My First NFT")
        ));
        RunarContract.DeployOutcome out = contract.deploy(provider, funder.signer(), 5_000L);
        assertNotNull(out.txid());
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("two NFTs with different owners produce distinct txids")
    void deployDistinct() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner1 = IntegrationWallet.create();
        IntegrationWallet owner2 = IntegrationWallet.create();
        IntegrationWallet funder = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract c1 = new RunarContract(a, List.of(
            owner1.pubKeyHex(), hexAscii("NFT-MULTI"), hexAscii("Unique Art Piece")
        ));
        RunarContract c2 = new RunarContract(a, List.of(
            owner2.pubKeyHex(), hexAscii("NFT-MULTI"), hexAscii("Unique Art Piece")
        ));
        String t1 = c1.deploy(provider, funder.signer(), 5_000L).txid();
        String t2 = c2.deploy(provider, funder.signer(), 5_000L).txid();
        assert !t1.equals(t2) : "expected distinct txids";
    }

    @Test
    @DisplayName("Java-surface SimpleNFT matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/token-nft/NFTExample.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
