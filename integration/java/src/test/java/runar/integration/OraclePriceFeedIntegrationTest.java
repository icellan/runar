package runar.integration;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import runar.integration.helpers.ContractCompiler;
import runar.integration.helpers.IntegrationBase;
import runar.integration.helpers.IntegrationWallet;
import runar.integration.helpers.RabinHelpers;
import runar.integration.helpers.RpcProvider;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarContract;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * OraclePriceFeed integration test -- stateless contract with Rabin
 * signature verification + price threshold + receiver ECDSA.
 *
 * <p>Ported from {@code integration/python/test_oracle_price_feed.py}.
 */
class OraclePriceFeedIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/oracle-price/OraclePriceFeed.runar.ts";

    @Test
    @DisplayName("deploy with Rabin oracle key + receiver pubkey")
    void deploy() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet receiver = IntegrationWallet.create();

        RunarContract contract = new RunarContract(a, List.of(
            RabinHelpers.N, receiver.pubKeyHex()
        ));
        RunarContract.DeployOutcome out = contract.deploy(provider, wallet.signer(), 5_000L);
        assertNotNull(out.txid());
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("settle with valid oracle price (> 50000) succeeds")
    void settleValidPrice() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet receiver = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            RabinHelpers.N, receiver.pubKeyHex()
        ));
        contract.deploy(provider, receiver.signer(), 5_000L);

        long price = 55001L;
        byte[] msg = RabinHelpers.num2binLE(price, 8);
        RabinHelpers.Signature sig = RabinHelpers.sign(msg);

        ArrayList<Object> args = new ArrayList<>();
        args.add(BigInteger.valueOf(price));
        args.add(sig.sig());
        // Padding must be pushed as a script-number (it feeds OP_ADD inside
        // verifyRabinSig). Mirrors the Go integration test's
        // EncodePushBigInt(rabinSig.Padding).
        args.add(sig.padding());
        args.add(null); // ECDSA Sig — auto-computed
        RunarContract.CallOutcome out = contract.call(
            "settle", args, null, provider, receiver.signer()
        );
        assertNotNull(out.txid());
    }

    @Test
    @DisplayName("settle with price below 50000 threshold rejected")
    void settleBelowThresholdRejected() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet receiver = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            RabinHelpers.N, receiver.pubKeyHex()
        ));
        contract.deploy(provider, receiver.signer(), 5_000L);

        long price = 49999L;
        byte[] msg = RabinHelpers.num2binLE(price, 8);
        RabinHelpers.Signature sig = RabinHelpers.sign(msg);

        ArrayList<Object> args = new ArrayList<>();
        args.add(BigInteger.valueOf(price));
        args.add(sig.sig());
        // Padding must be pushed as a script-number (it feeds OP_ADD inside
        // verifyRabinSig). Mirrors the Go integration test's
        // EncodePushBigInt(rabinSig.Padding).
        args.add(sig.padding());
        args.add(null);
        assertThrows(RuntimeException.class, () ->
            contract.call("settle", args, null, provider, receiver.signer())
        );
    }

    @Test
    @DisplayName("Java-surface OraclePriceFeed matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/oracle-price/OraclePriceFeed.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
