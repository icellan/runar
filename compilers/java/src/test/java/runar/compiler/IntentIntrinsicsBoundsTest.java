package runar.compiler;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import runar.compiler.frontend.GoParser;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.passes.Typecheck;

/**
 * R-2 / R-4 typecheck bounds for the intent sub-covenant intrinsics, ported
 * from the Go tier ({@code compilers/go/frontend/intent_intrinsics_test.go}).
 *
 * R-2: {@code requireOutputP2PKH} outputIndex must be in [0, 1000].
 * R-4: {@code extractPrevOutputScript} 3-arg prefixLen must be in
 *      [32, 4 MiB].
 */
class IntentIntrinsicsBoundsTest {

    private static void expectTypeError(String source, String substr) {
        ContractNode contract;
        try {
            contract = GoParser.parse(source, "Test.runar.go");
        } catch (GoParser.ParseException e) {
            throw new AssertionError("parse failed: " + e.getMessage(), e);
        }
        Typecheck.TypeCheckException ex = assertThrows(
            Typecheck.TypeCheckException.class,
            () -> Typecheck.run(contract)
        );
        boolean matched = false;
        for (String e : ex.errors()) {
            if (e.contains(substr)) { matched = true; break; }
        }
        assertTrue(
            matched,
            "expected typecheck error containing '" + substr + "' but got: " + ex.errors()
        );
    }

    // R-2 ----------------------------------------------------------------

    @Test
    void requireOutputP2PKH_outputIndexAboveBound_rejects() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type Cov struct {
            \trunar.StatefulSmartContract
            \tPKH runar.ByteString `runar:"readonly"`
            \tA   runar.Bigint     `runar:"readonly"`
            }

            func (c *Cov) Pay() {
            \t// 2000 > 1000 bound — must be rejected at typecheck.
            \trunar.RequireOutputP2PKH(2000, c.PKH, c.A)
            }
            """;
        expectTypeError(src, "bound to <= 1000");
    }

    @Test
    void requireOutputP2PKH_negativeIndex_rejects() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type Cov struct {
            \trunar.StatefulSmartContract
            \tPKH runar.ByteString `runar:"readonly"`
            \tA   runar.Bigint     `runar:"readonly"`
            }

            func (c *Cov) Pay() {
            \trunar.RequireOutputP2PKH(-1, c.PKH, c.A)
            }
            """;
        expectTypeError(src, "must be >= 0");
    }

    // R-4 ----------------------------------------------------------------

    @Test
    void extractPrevOutputScript_prefixLenTooSmall_rejects() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type Cov struct {
            \trunar.StatefulSmartContract
            \tH runar.ByteString `runar:"readonly"`
            }

            func (c *Cov) Bind() {
            \t// prefixLen=16 < 32 (hash size) — must be rejected.
            \t_ = runar.ExtractPrevOutputScript(0, c.H, 16)
            }
            """;
        expectTypeError(src, "must be >= 32");
    }

    @Test
    void extractPrevOutputScript_prefixLenTooLarge_rejects() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type Cov struct {
            \trunar.StatefulSmartContract
            \tH runar.ByteString `runar:"readonly"`
            }

            func (c *Cov) Bind() {
            \t// prefixLen=10485760 > 4 MiB — must be rejected.
            \t_ = runar.ExtractPrevOutputScript(0, c.H, 10485760)
            }
            """;
        expectTypeError(src, "MAX_SCRIPT_BYTES");
    }
}
