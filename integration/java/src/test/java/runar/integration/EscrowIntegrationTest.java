package runar.integration;

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
 * End-to-end regtest tests for {@code Escrow} — a stateless 2-of-3
 * contract where the release and refund paths each require two
 * signatures from the buyer/seller/arbiter triad.
 *
 * <p>Ported from {@code integration/python/test_escrow.py}. The
 * {@code release} and {@code refund} methods each take two
 * {@code Sig}s; the Java SDK fills both slots via the provided Signer
 * (which signs a single sighash twice — both checks must match the
 * respective pubkey baked into the locking script).
 */
class EscrowIntegrationTest extends IntegrationBase {

    @Test
    @DisplayName("release: seller + arbiter both sign — spend accepted")
    void release() {
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/ts/escrow/Escrow.runar.ts"
        );

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet deployer = IntegrationWallet.createFunded(rpc, 1.0);

        // All three parties share the same key for this happy-path test
        // so either release or refund will succeed. More realistic
        // multi-party flows use `prepareCall` / `finalizeCall` from the
        // Java SDK (exercised in the Python/Go suites; same API here).
        RunarContract contract = new RunarContract(
            artifact,
            List.of(deployer.pubKeyHex(), deployer.pubKeyHex(), deployer.pubKeyHex())
        );
        contract.deploy(provider, deployer.signer(), 5_000L);

        List<Object> args = new ArrayList<>();
        args.add(null); // sellerSig — auto-computed
        args.add(null); // arbiterSig — auto-computed
        RunarContract.CallOutcome out = contract.call(
            "release", args, null, provider, deployer.signer()
        );
        assertNotNull(out.txid());
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("refund: buyer + arbiter both sign — spend accepted")
    void refund() {
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/ts/escrow/Escrow.runar.ts"
        );

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet deployer = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(
            artifact,
            List.of(deployer.pubKeyHex(), deployer.pubKeyHex(), deployer.pubKeyHex())
        );
        contract.deploy(provider, deployer.signer(), 5_000L);

        List<Object> args = new ArrayList<>();
        args.add(null);
        args.add(null);
        RunarContract.CallOutcome out = contract.call(
            "refund", args, null, provider, deployer.signer()
        );
        assertNotNull(out.txid());
    }

    @Test
    @DisplayName("wrong signer rejected by the node (unilateral release)")
    void wrongSignerRejected() {
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/ts/escrow/Escrow.runar.ts"
        );

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet buyer = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet seller = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet arbiter = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet attacker = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(
            artifact,
            List.of(buyer.pubKeyHex(), seller.pubKeyHex(), arbiter.pubKeyHex())
        );
        contract.deploy(provider, buyer.signer(), 5_000L);

        // Attacker has none of the registered pubkeys — release must fail.
        List<Object> args = new ArrayList<>();
        args.add(null);
        args.add(null);
        assertThrows(RuntimeException.class, () ->
            contract.call("release", args, null, provider, attacker.signer())
        );
    }

    @Test
    @DisplayName("Java-surface Escrow matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(
            "examples/ts/escrow/Escrow.runar.ts"
        );
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/escrow/Escrow.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
