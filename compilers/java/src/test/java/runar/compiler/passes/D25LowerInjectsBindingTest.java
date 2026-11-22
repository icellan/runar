package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfProperty;
import runar.compiler.ir.ast.ContractNode;

/**
 * D25: {@link AnfLower#run} is a public entry point. A caller that assembles
 * its own pipeline (parse, Validate, Typecheck, AnfLower) and never runs
 * {@link ContinuationBinding#inject} would otherwise lower a mixed ("bind")
 * contract with no {@code _spentOutpointHash}: its continuations would not be
 * bound to the spent outpoint, which is the twin-input theft D25 closes.
 */
class D25LowerInjectsBindingTest {

    private static final String FIELD = ContinuationBinding.TWIN_BINDING_FIELD;

    private static final String MIXED =
        "import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';\n"
        + "class MixedPot extends StatefulSmartContract {\n"
        + "  count: bigint;\n"
        + "  constructor(count: bigint) { super(count); this.count = count; }\n"
        + "  public increment() { this.count++; }\n"
        + "  public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }\n"
        + "}\n";

    private static ContractNode frontend() throws Exception {
        ContractNode c = ParserDispatch.parse(MIXED, "MixedPot.runar.ts");
        Validate.run(c);
        Typecheck.run(c);
        return c;
    }

    @Test
    void lowerInjectsBindingWithoutCallerInjection() throws Exception {
        List<AnfProperty> props = AnfLower.run(frontend()).properties();
        assertEquals(FIELD, props.get(props.size() - 1).name(), "binding not injected");
    }

    @Test
    void lowerDoesNotInjectTwice() throws Exception {
        List<AnfProperty> props = AnfLower.run(ContinuationBinding.inject(frontend())).properties();
        assertEquals(1, props.stream().filter(p -> FIELD.equals(p.name())).count());
    }
}
