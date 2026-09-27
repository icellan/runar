package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import runar.compiler.Cli;
import runar.compiler.canonical.Jcs;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.passes.AnfLower;
import runar.compiler.passes.ExpandFixedArrays;
import runar.compiler.passes.Typecheck;
import runar.compiler.passes.Validate;

/**
 * F-024 (R14): the SDK's ANF interpreter derives the post-call state before
 * the tx exists; the covenant re-derives it on-chain. For a contract whose
 * state depends on {@code continuationAmount()} (the injected
 * {@code _newAmount}) and {@code extractAmount(txPreimage)} (the spent UTXO's
 * satoshis), the interpreter must read the caller-supplied values.
 *
 * <p>Proves: the Java interpreter reads a caller-bound {@code _newAmount} and
 * an integer {@code txPreimage}. Does NOT prove on-chain acceptance (Java ships
 * no ScriptVM); the TS/Go SDK tests cover the spend.
 */
class F024ContinuationAmountTest {

    private static final String TIP = String.join("\n",
        "class Tip extends StatefulSmartContract {",
        "  lastDeposit: bigint;",
        "  constructor(lastDeposit: bigint) { super(lastDeposit); this.lastDeposit = lastDeposit; }",
        "  public deposit() {",
        "    this.lastDeposit = continuationAmount() - extractAmount(this.txPreimage);",
        "  }",
        "}", "");

    private static Map<String, Object> anf() throws Exception {
        ContractNode contract = ParserDispatch.parse(TIP, "Tip.runar.ts");
        Validate.run(contract);
        contract = ExpandFixedArrays.run(contract);
        Typecheck.run(contract);
        AnfProgram anf = Cli.optimizeAnf(AnfLower.run(contract), true);
        return AnfInterpreter.loadAnf("{\"anf\":" + Jcs.stringify(anf) + "}");
    }

    @Test
    void interpreterReadsCallerBoundAmounts() throws Exception {
        Map<String, Object> out = AnfInterpreter.computeNewState(
            anf(), "deposit", Map.of("lastDeposit", BigInteger.ZERO),
            Map.of("_newAmount", BigInteger.valueOf(7000), "txPreimage", BigInteger.valueOf(5000)),
            List.of());
        assertEquals(BigInteger.valueOf(2000), out.get("lastDeposit"));
    }
}
