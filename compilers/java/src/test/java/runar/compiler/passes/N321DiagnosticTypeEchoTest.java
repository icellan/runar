package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;

/**
 * N-321 -- typecheck diagnostics must not echo an unbounded type text.
 *
 * <p>Proves: a typecheck diagnostic echoing a 1 MB source name is capped at
 * 1024 characters of message plus the {@code ...(N more bytes elided)} marker,
 * and an ordinary diagnostic is unchanged. This tier normalises an unknown
 * type annotation, so it never echoes the annotation text; the unbounded
 * source text it can echo is an identifier ({@code Undefined variable '...'}). Does NOT prove: the other
 * tiers (conformance/negatives/n321-diagnostic-type-echo-parity.test.ts) nor
 * each echo site individually (the cap sits at the diagnostic sink).
 */
class N321DiagnosticTypeEchoTest {

    private static final String HEAD =
        "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n public verify(a: bigint) {\n let q: bigint = ";
    private static final String TAIL = ";\n assert(q == this.t);\n }\n}\n";

    private static List<String> errors(String type) throws Exception {
        ContractNode c = ParserDispatch.parse(HEAD + type + TAIL, "P.runar.ts");
        Validate.run(c);
        c = ExpandFixedArrays.run(c);
        return Typecheck.collect(c);
    }

    @Test
    void hugeIdentifierIsElided() throws Exception {
        List<String> errs = errors("T".repeat(1 << 20));
        List<String> echoing = errs.stream().filter(m -> m.contains("TTTT")).toList();
        assertFalse(echoing.isEmpty(), "no diagnostic echoed the type");
        for (String m : echoing) {
            assertTrue(m.length() < 1200, "diagnostic is " + m.length() + " chars");
            assertTrue(m.matches("(?s).*\\.\\.\\.\\(\\d+ more bytes elided\\)$"), "no marker");
        }
    }

    @Test
    void ordinaryDiagnosticIsUnchanged() throws Exception {
        assertTrue(String.join("\n", errors("nope")).contains("Undefined variable 'nope'"));
    }
}
