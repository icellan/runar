package runar.integration;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import runar.integration.helpers.ContractCompiler;
import runar.integration.helpers.IntegrationBase;
import runar.integration.helpers.IntegrationWallet;
import runar.integration.helpers.RpcProvider;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarContract;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * DataOutputs integration test -- stateful contract emitting an
 * OP_RETURN data output via {@code this.addDataOutput(...)}.
 *
 * <p>Ported from {@code integration/ts/data-outputs.test.ts} (and the
 * Go equivalent). Pins the BSVM R9 acceptance: data outputs must
 * appear in declaration order between state outputs and change so the
 * compile-time continuation-hash check matches at spend time.
 */
class DataOutputsIntegrationTest extends IntegrationBase {

    private static final String SOURCE = """
        import { StatefulSmartContract, ByteString } from 'runar-lang';

        export class DataEmitter extends StatefulSmartContract {
            counter: bigint;

            constructor(counter: bigint) {
                super(counter);
                this.counter = counter;
            }

            public emit(payload: ByteString) {
                this.counter = this.counter + 1n;
                this.addDataOutput(0n, payload);
            }
        }
        """;

    @Test
    @DisplayName("emit a data output between state and change outputs")
    void emit() {
        Path tmp;
        try {
            tmp = Files.createTempFile("runar-data-outputs-", "DataEmitter.runar.ts");
            Files.writeString(tmp, SOURCE);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        RunarArtifact a = ContractCompiler.compileAbsolute(tmp);

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(BigInteger.ZERO));
        contract.deploy(provider, wallet.signer(), 10_000L);

        // OP_RETURN "bsvm-test" payload (matches Go test exactly).
        String payload = "6a09" + "6273766d2d74657374";
        RunarContract.CallOutcome out = contract.call(
            "emit", List.of(payload), null, provider, wallet.signer()
        );
        assertNotNull(out.txid());
    }
}
