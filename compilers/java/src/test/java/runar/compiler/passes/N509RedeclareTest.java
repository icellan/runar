package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;

/**
 * N-509: a local cannot be re-declared in the same scope (spec/grammar.md).
 * One scope = one statement list; a method's parameters belong to its body's
 * top-level list. Shadowing in a NESTED list is not a re-declaration.
 * Mirrors packages/runar-compiler/src/__tests__/02-validate.test.ts (N-509).
 */
class N509RedeclareTest {

    private static final String DEFAULT_CTOR = "super(k);\n    this.k = k;";

    private static String source(String body, String ctor) {
        return "\nclass R extends SmartContract {\n  readonly k: bigint;\n  constructor(k: bigint) {\n    "
            + ctor + "\n  }\n  public unlock(p: bigint, c: boolean) {\n    " + body + "\n  }\n}\n";
    }

    private static String msg(String name) {
        return "'" + name + "' is already declared in this scope and cannot be re-declared";
    }

    private static List<String> errors(String src) throws Exception {
        return Validate.runCollecting(ParserDispatch.parse(src, "R.runar.ts")).errors();
    }

    private static long count(List<String> errs, String m) {
        return errs.stream().filter(e -> e.equals(m) || e.endsWith(": " + m)).count();
    }

    @Test
    void refusesSameScopeRedeclaration() throws Exception {
        String[][] cases = {
            {"const a = 1n; const a = 2n; assert(a == p);", "a", DEFAULT_CTOR},
            {"let x = 1n; let x = 2n; assert(x == p);", "x", DEFAULT_CTOR},
            {"const a = 1n; let a = 2n; a = 3n; assert(a == p);", "a", DEFAULT_CTOR},
            {"if (c) { let y = 1n; let y = 2n; assert(y == p); } assert(c);", "y", DEFAULT_CTOR},
            {"if (c) { assert(c); } else { let y = 1n; let y = 2n; assert(y == p); }", "y", DEFAULT_CTOR},
            {"let s = 0n; for (let i = 0n; i < 2n; i++) { let t = i; let t = i; s = s + t; } assert(s == p);", "t", DEFAULT_CTOR},
            {"let p = 5n; assert(p == this.k && c);", "p", DEFAULT_CTOR},
            {"assert(p == this.k && c);", "k", "super(k);\n    this.k = k;\n    const k = 2n;\n    assert(k > 0n);"},
        };
        for (String[] c : cases) {
            List<String> errs = errors(source(c[0], c[2]));
            assertEquals(1, count(errs, msg(c[1])), "want exactly one " + msg(c[1]) + " for " + c[0] + "; got " + errs);
        }
    }

    @Test
    void reportsTheSecondDeclaration() throws Exception {
        List<String> errs = errors(source("const a = 1n;\n    const a = 2n;\n    assert(a == p);", DEFAULT_CTOR));
        assertTrue(errs.stream().anyMatch(e -> e.equals("R.runar.ts:10:4: " + msg("a"))), errs.toString());
    }

    @Test
    void acceptsShadowingAndSiblings() throws Exception {
        String[] cases = {
            "let x = 1n; if (c) { let x = 2n; assert(x == 2n); } assert(x == p);",
            "if (c) { let p = 5n; assert(p == 5n); } assert(p == this.k);",
            "const k = 5n; assert(k == p + this.k && c);",
            "let s = 0n; for (let i = 0n; i < 2n; i++) { let i = 7n; s = s + i; } assert(s == p && c);",
            "if (c) { let y = 1n; assert(y == p); } else { let y = 2n; assert(y == p); }",
            "if (c) { let y = 1n; assert(y == p); } let y = 2n; assert(y == p);",
            "let s = 0n; for (let i = 0n; i < 2n; i++) { s = s + i; } for (let i = 0n; i < 3n; i++) { s = s + i; } assert(s == p && c);",
        };
        for (String body : cases) {
            List<String> errs = errors(source(body, DEFAULT_CTOR));
            assertTrue(errs.stream().noneMatch(e -> e.contains("already declared")), body + " -> " + errs);
        }
    }
}
