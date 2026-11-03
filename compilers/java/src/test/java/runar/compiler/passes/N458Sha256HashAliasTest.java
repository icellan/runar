package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.builtins.BuiltinRegistry;
import runar.compiler.frontend.JavaParser;
import runar.compiler.ir.ast.ContractNode;

/**
 * N-458: {@link BuiltinRegistry} carried a "Sha256Hash" row. Typecheck
 * accepted a call to it but StackLower has no case for it ("unknown
 * builtin"). The only spelling that maps Sha256Hash to sha256 is the Go
 * parser, which rewrites it before typecheck, so the row was reachable only
 * from the other surfaces, where it let a call through typecheck that
 * lowering then rejected. Peers (TS BUILTIN_FUNCTIONS) have no such name and
 * refuse it at typecheck with the unknown-function diagnostic.
 *
 * <p>Proves: a {@code .runar.java} call to {@code Sha256Hash(...)} is refused
 * by Typecheck with the unknown-function diagnostic and the registry no
 * longer lists the name. Does not prove: the Go surface mapping (covered by
 * the Go parser tests) or parity of every other registry row with TS.
 */
class N458Sha256HashAliasTest {

    private static final String SRC = """
        class H extends SmartContract {
            @Readonly ByteString expected;

            H(ByteString expected) {
                super(expected);
                this.expected = expected;
            }

            @Public
            void check(ByteString data) {
                assertThat(Sha256Hash(data).equals(expected));
            }
        }
        """;

    @Test
    void sha256HashCallIsRefusedAtTypecheck() {
        ContractNode c = JavaParser.parse(SRC, "H.runar.java");
        List<String> errs = Typecheck.collect(c);
        assertTrue(
            errs.stream().anyMatch(e -> e.contains("unknown function 'Sha256Hash'")),
            "expected unknown-function diagnostic, got " + errs);
    }

    @Test
    void registryHasNoSha256HashRow() {
        assertFalse(BuiltinRegistry.isBuiltin("Sha256Hash"));
    }
}
