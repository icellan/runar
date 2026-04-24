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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * End-to-end regtest tests for the {@code P2PKH} contract ported from
 * {@code integration/python/test_p2pkh.py}.
 *
 * <p>P2PKH is a stateless contract that locks funds to a public key
 * hash. Spending requires a valid ECDSA signature and the matching
 * public key. The Java SDK's {@code RunarContract.call} auto-fills the
 * {@code Sig} slot from the provided {@link runar.lang.sdk.Signer}.
 *
 * <p>The same tests also run the {@code .runar.java} source (same
 * contract, Java surface syntax) to prove end-to-end parity of the
 * Java frontend with the TypeScript reference.
 */
class P2PKHIntegrationTest extends IntegrationBase {

    @Test
    @DisplayName("compile + deploy a P2PKH locking script")
    void deploysP2PKH() {
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/ts/p2pkh/P2PKH.runar.ts"
        );
        assertEquals("P2PKH", artifact.contractName());

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(
            artifact, List.of(wallet.pubKeyHash())
        );

        RunarContract.DeployOutcome outcome = contract.deploy(
            provider, wallet.signer(), 5_000L
        );
        assertNotNull(outcome.txid());
        assertEquals(64, outcome.txid().length());
    }

    @Test
    @DisplayName("deploy then spend via unlock(sig, pubKey)")
    void deployAndSpendP2PKH() {
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/ts/p2pkh/P2PKH.runar.ts"
        );

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(
            artifact, List.of(wallet.pubKeyHash())
        );
        contract.deploy(provider, wallet.signer(), 5_000L);

        // null Sig / PubKey args are auto-computed by the SDK.
        java.util.List<Object> args = new java.util.ArrayList<>();
        args.add(null);
        args.add(null);
        RunarContract.CallOutcome call = contract.call(
            "unlock", args, null, provider, wallet.signer()
        );
        assertNotNull(call.txid());
        assertEquals(64, call.txid().length());
    }

    @Test
    @DisplayName("deploy with a different wallet's pubKeyHash")
    void deployDifferentPubKeyHash() {
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/ts/p2pkh/P2PKH.runar.ts"
        );

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet funder = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet target = IntegrationWallet.create();

        RunarContract contract = new RunarContract(
            artifact, List.of(target.pubKeyHash())
        );
        RunarContract.DeployOutcome outcome = contract.deploy(
            provider, funder.signer(), 5_000L
        );
        assertNotNull(outcome.txid());
        assertNotEquals(
            funder.pubKeyHash(), target.pubKeyHash(),
            "sanity: the two wallets must have distinct hashes"
        );
    }

    @Test
    @DisplayName("unlock with the wrong key is rejected by the node")
    void wrongSignerRejected() {
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/ts/p2pkh/P2PKH.runar.ts"
        );

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet a = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet b = IntegrationWallet.createFunded(rpc, 1.0);

        // Lock to A's hash, try to unlock with B's key.
        RunarContract contract = new RunarContract(
            artifact, List.of(a.pubKeyHash())
        );
        contract.deploy(provider, a.signer(), 5_000L);

        java.util.List<Object> args = new java.util.ArrayList<>();
        args.add(null);
        args.add(null);
        assertThrows(RuntimeException.class, () ->
            contract.call("unlock", args, null, provider, b.signer())
        );
    }

    @Test
    @DisplayName("Java surface contract (.runar.java) produces equivalent artifact")
    void javaSurfaceMatches() {
        RunarArtifact tsArtifact = ContractCompiler.compileRelative(
            "examples/ts/p2pkh/P2PKH.runar.ts"
        );
        RunarArtifact javaArtifact = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/p2pkh/P2PKH.runar.java"
        );
        // The compiled locking-script templates must be byte-identical
        // across surface syntaxes — this is the central invariant of the
        // multi-format design.
        assertEquals(tsArtifact.scriptHex(), javaArtifact.scriptHex());
        assertEquals(tsArtifact.contractName(), javaArtifact.contractName());
    }
}
