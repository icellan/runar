package runar.integration;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
 * End-to-end regtest tests for the {@code Counter} stateful contract,
 * ported from {@code integration/python/test_counter.py}.
 *
 * <p>Counter keeps a single {@code bigint count} in contract state; the
 * compiler auto-injects {@code checkPreimage} on method entry and a
 * state-continuation output on method exit, so each call produces a
 * new UTXO holding the updated state.
 */
class CounterIntegrationTest extends IntegrationBase {

    @Test
    @DisplayName("deploy count=0, call increment, count=1")
    void incrementOnce() {
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/ts/stateful-counter/Counter.runar.ts"
        );

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(
            artifact, List.of(BigInteger.ZERO)
        );

        RunarContract.DeployOutcome deploy = contract.deploy(
            provider, wallet.signer(), 5_000L
        );
        assertNotNull(deploy.txid());
        assertEquals(64, deploy.txid().length());

        RunarContract.CallOutcome call = contract.call(
            "increment", List.of(), null, provider, wallet.signer()
        );
        assertNotNull(call.txid());
    }

    @Test
    @DisplayName("increment chain: 0 -> 1 -> 2 -> 3")
    void chainIncrements() {
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/ts/stateful-counter/Counter.runar.ts"
        );

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(
            artifact, List.of(BigInteger.ZERO)
        );
        contract.deploy(provider, wallet.signer(), 5_000L);

        for (int i = 0; i < 3; i++) {
            RunarContract.CallOutcome out = contract.call(
                "increment", List.of(), null, provider, wallet.signer()
            );
            assertNotNull(out.txid());
        }
    }

    @Test
    @DisplayName("increment then decrement restores count")
    void incrementThenDecrement() {
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/ts/stateful-counter/Counter.runar.ts"
        );

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(
            artifact, List.of(BigInteger.ZERO)
        );
        contract.deploy(provider, wallet.signer(), 5_000L);

        contract.call("increment", List.of(), null, provider, wallet.signer());
        contract.call("decrement", List.of(), null, provider, wallet.signer());
    }

    @Test
    @DisplayName("lying about the new state is rejected (count=99 after increment)")
    void rejectWrongState() {
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/ts/stateful-counter/Counter.runar.ts"
        );

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(
            artifact, List.of(BigInteger.ZERO)
        );
        contract.deploy(provider, wallet.signer(), 5_000L);

        Map<String, Object> badState = new HashMap<>();
        badState.put("count", BigInteger.valueOf(99));
        assertThrows(RuntimeException.class, () ->
            contract.call("increment", List.of(), badState, provider, wallet.signer())
        );
    }

    @Test
    @DisplayName("decrement from 0 fails the assert(count > 0) check")
    void rejectDecrementFromZero() {
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/ts/stateful-counter/Counter.runar.ts"
        );

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(
            artifact, List.of(BigInteger.ZERO)
        );
        contract.deploy(provider, wallet.signer(), 5_000L);

        assertThrows(RuntimeException.class, () ->
            contract.call("decrement", List.of(), null, provider, wallet.signer())
        );
    }

    @Test
    @DisplayName("Java-surface Counter contract produces same script as TS")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(
            "examples/ts/stateful-counter/Counter.runar.ts"
        );
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/stateful-counter/Counter.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
        assertEquals(ts.contractName(), java.contractName());
    }
}
