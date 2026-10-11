package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;

/**
 * F-265: {@code substr()} literal negative start is a compile-time error.
 *
 * <p>{@code substr(witness, start, len)} lowers to a raw {@code OP_SPLIT}
 * argument. No pass enforced {@code start >= 0}: a literal negative start
 * ({@code substr(a, -5n, 3n)}) type-checked as plain {@code bigint} (the
 * standard subtype loop never inspects a literal's VALUE) and compiled to a
 * script that aborts at runtime -- {@code -5n} minimal-encodes to
 * {@code <85>}, which {@code OP_SPLIT} rejects as out of range.
 *
 * <p>Mirrors the existing {@code extractPrevOutputScript}/
 * {@code requireOutputP2PKH} "must be &gt;= 0" literal-bound pattern in
 * {@link Typecheck}.
 *
 * <p>Proves: a literal (bare or unary-negated {@code BigIntLiteral})
 * negative start is now a typecheck-time diagnostic. Does not prove:
 * anything about a NON-literal negative start (a variable or computed
 * expression) -- that remains a runtime abort, unchanged, because the stack
 * model has no static value range for a non-literal.
 */
class F265SubstrLiteralStartBoundTest {

    @Test
    void rejectsLiteralNegativeStart() throws Exception {
        String src = """
            class C extends SmartContract {
              readonly a: ByteString;
              constructor(a: ByteString) { super(a); this.a = a; }
              public unlock(): void {
                assert(substr(this.a, -5n, 3n) === this.a);
              }
            }
            """;
        ContractNode c = ParserDispatch.parse(src, "C.runar.ts");
        List<String> errs = Typecheck.collect(c);
        assertTrue(
            errs.stream().anyMatch(e -> e.contains("substr() argument 2 (start) must be >= 0; got -5")),
            "expected a substr() start-bound error, got " + errs
        );
    }

    @Test
    void acceptsLiteralNonNegativeStart() throws Exception {
        String src = """
            class C extends SmartContract {
              readonly a: ByteString;
              constructor(a: ByteString) { super(a); this.a = a; }
              public unlock(): void {
                assert(substr(this.a, 0n, 3n) === this.a);
              }
            }
            """;
        ContractNode c = ParserDispatch.parse(src, "C.runar.ts");
        List<String> errs = Typecheck.collect(c);
        assertTrue(errs.isEmpty(), "expected no errors, got " + errs);
    }

    @Test
    void acceptsNonLiteralStartUnchanged() throws Exception {
        String src = """
            class C extends SmartContract {
              readonly a: ByteString;
              constructor(a: ByteString) { super(a); this.a = a; }
              public unlock(n: bigint): void {
                assert(substr(this.a, n, 3n) === this.a);
              }
            }
            """;
        ContractNode c = ParserDispatch.parse(src, "C.runar.ts");
        List<String> errs = Typecheck.collect(c);
        assertTrue(errs.isEmpty(), "expected no errors, got " + errs);
    }
}
