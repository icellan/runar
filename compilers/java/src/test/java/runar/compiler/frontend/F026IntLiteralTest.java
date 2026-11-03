package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.RecordComponent;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.ast.BigIntLiteral;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.MethodNode;

/**
 * F-026 (CL-BUG-198) — an integer literal means what its host language says it means,
 * on every surface, or it is refused.
 *
 * <p>Pre-fix, this tier's hand-written tokenizers scanned decimal digits (and sometimes
 * {@code 0x}) only. {@code 0b1010} on .runar.py / .runar.zig lexed as {@code 0} plus the
 * identifier {@code b1010}, and with an identifier of that name in scope the stray token
 * was absorbed (.zig call arguments needed no commas, .py took two statements on one line),
 * so {@code amount > 0b1010} compiled to {@code amount > 0}.
 *
 * <p>The rule is the TS reference's ({@code packages/runar-compiler/src/passes/int-literal.ts},
 * user decision R15): the number token runs over every glued [0-9A-Za-z_] character and
 * must be an integer literal of the surface's host language, with that language's value
 * (table: {@code conformance/negatives/int-literal-cases.json}, generated from the host
 * toolchains); anything else is refused with {@code invalid <Language> integer literal
 * '<text>'}. Also: .zig call and array lists require commas; .py refuses a second statement
 * on one line.
 *
 * <p>What this proves: this tier's validator reproduces every table row; every hand-written
 * tokenizer accepts exactly the table's forms with its values and refuses the rest with the
 * shared text, and the javac .runar.java path accepts and refuses the same forms (javac's
 * literal errors are mapped to the shared text); the attempt-1 exploit shapes read 10; the
 * absorbing paths are closed.
 * What it does NOT prove: the other tiers, or the Solidity / Move rows themselves
 * (documentation-derived).
 */
class F026IntLiteralTest {

    private static final String ZIG_COMMA = "expected ',' between list elements";
    private static final String PY_LINE_BREAK = "expected a line break between statements";
    private static final String[] SURFACES = {"ts", "sol", "move", "go", "rs", "py", "zig", "rb", "java"};

    private static final Map<String, Function<String, String>> TEMPLATE = Map.of(
        "ts", l -> "import { SmartContract, assert } from 'runar-lang';\n\nclass T extends SmartContract {\n  readonly target: bigint;\n\n  constructor(target: bigint) {\n    super(target);\n    this.target = target;\n  }\n\n  public verify(a: bigint): void {\n    assert(a > " + l + ");\n  }\n}\n",
        "sol", l -> "pragma runar ^0.1.0;\n\ncontract T is SmartContract {\n    int immutable target;\n\n    constructor(int _target) {\n        target = _target;\n    }\n\n    function verify(int a) public {\n        require(a > " + l + ");\n    }\n}\n",
        "move", l -> "module T {\n    use runar::types::{Int};\n\n    struct T {\n        target: Int,\n    }\n\n    public fun verify(contract: &T, a: Int) {\n        assert!(a > " + l + ");\n    }\n}\n",
        "go", l -> "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\ntype T struct {\n\trunar.SmartContract\n\tTarget runar.Int `runar:\"readonly\"`\n}\n\nfunc (c *T) Verify(a runar.Int) {\n\trunar.Assert(a > " + l + ")\n}\n",
        "rs", l -> "use runar::prelude::*;\n\n#[runar::contract]\nstruct T {\n    #[readonly]\n    target: Int,\n}\n\nimpl T {\n    pub fn verify(&self, a: Int) {\n        assert!(a > " + l + ");\n    }\n}\n",
        "py", l -> "from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n        self.target = target\n\n    @public\n    def verify(self, a: Bigint):\n        assert_(a > " + l + ")\n",
        "zig", l -> "const runar = @import(\"runar\");\n\npub const T = struct {\n    pub const Contract = runar.SmartContract;\n\n    target: i64,\n\n    pub fn init(target: i64) T {\n        return .{ .target = target };\n    }\n\n    pub fn verify(self: *const T, a: i64) void {\n        _ = self;\n        runar.assert(a > " + l + ");\n    }\n};\n",
        "rb", l -> "require 'runar'\n\nclass T < Runar::SmartContract\n  prop :target, Bigint\n\n  def initialize(target)\n    super(target)\n    @target = target\n  end\n\n  runar_public a: Bigint\n  def verify(a)\n    assert a > " + l + "\n  end\nend\n",
        "java", l -> "package t;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\n\nimport static runar.lang.Builtins.assertThat;\n\nclass T extends SmartContract {\n\n    @Readonly Bigint target;\n\n    T(Bigint target) {\n        super(target);\n        this.target = target;\n    }\n\n    @Public\n    void verify(Bigint a) {\n        assertThat(a.gt(Bigint.of(" + l + ")));\n    }\n}\n");

    /** surface -> [literal, value-or-null] rows, from the host-derived table. */
    private static Map<String, List<String[]>> cases() throws IOException {
        List<String> lines = Files.readAllLines(Path.of("../../conformance/negatives/int-literal-cases.json"));
        Map<String, List<String[]>> out = new LinkedHashMap<>();
        Pattern head = Pattern.compile("^\\s*\"(\\w+)\": \\[$");
        Pattern row = Pattern.compile("^\\s*\\[\"([^\"]*)\", (null|\"([^\"]*)\")\\],?$");
        String cur = null;
        for (String line : lines) {
            Matcher h = head.matcher(line);
            if (h.matches()) {
                cur = h.group(1);
                out.put(cur, new ArrayList<>());
                continue;
            }
            Matcher r = row.matcher(line);
            if (r.matches() && cur != null) out.get(cur).add(new String[] {r.group(1), r.group(3)});
        }
        return out;
    }

    private record Parsed(ContractNode contract, String error) {}

    private static Parsed parse(String source, String file) {
        try {
            return new Parsed(ParserDispatch.parse(source, file), null);
        } catch (ParserDispatch.ParseException e) {
            return new Parsed(null, e.getMessage());
        } catch (RuntimeException e) {
            return new Parsed(null, String.valueOf(e.getMessage()));
        }
    }

    private static void collect(Object node, List<BigInteger> out) throws Exception {
        if (node instanceof BigIntLiteral b) {
            out.add(b.value());
        } else if (node instanceof List<?> l) {
            for (Object x : l) collect(x, out);
        } else if (node != null && node.getClass().isRecord()) {
            for (RecordComponent rc : node.getClass().getRecordComponents()) {
                if (!rc.getName().equals("sourceLocation")) collect(rc.getAccessor().invoke(node), out);
            }
        }
    }

    private static List<BigInteger> literals(ContractNode c) throws Exception {
        List<BigInteger> vals = new ArrayList<>();
        for (MethodNode m : c.methods()) if (m.name().equals("verify")) collect(m.body(), vals);
        return vals;
    }

    @Test
    void validatorReproducesHostTable() throws IOException {
        Map<String, List<String[]>> cases = cases();
        assertEquals(9, cases.size());
        List<String> bad = new ArrayList<>();
        for (var e : cases.entrySet()) {
            for (String[] r : e.getValue()) {
                IntLiteral.Lit lit = IntLiteral.parse(e.getKey(), r[0]);
                String got = lit != null && !lit.negOnly() ? lit.value().toString() : null;
                if (got == null ? r[1] != null : !got.equals(r[1])) bad.add(e.getKey() + " " + r[0] + ": want " + r[1] + ", got " + got);
            }
        }
        assertTrue(bad.isEmpty(), String.join("\n", bad));
    }

    @Test
    void everyTokenizerAppliesTheTable() throws Exception {
        Map<String, List<String[]>> cases = cases();
        List<String> bad = new ArrayList<>();
        for (String surf : SURFACES) {
            // .runar.java goes through javac; its literal errors are mapped to
            // the shared text too, except the floating-point forms javac accepts
            // (`1e3`), which convertLiteral refuses in its own words.
            for (String[] r : cases.get(surf)) {
                boolean handWritten = !(surf.equals("java") && r[0].equals("1e3"));
                Parsed p = parse(TEMPLATE.get(surf).apply(r[0]), "T.runar." + surf);
                if (r[1] == null) {
                    if (p.error == null) bad.add(surf + " " + r[0] + ": accepted");
                    else if (handWritten && !p.error.contains(IntLiteral.invalid(surf, r[0]))) bad.add(surf + " " + r[0] + ": refused without the shared text: " + p.error);
                } else if (p.error != null) {
                    bad.add(surf + " " + r[0] + ": refused: " + p.error);
                } else if (!literals(p.contract).equals(List.of(new BigInteger(r[1])))) {
                    bad.add(surf + " " + r[0] + ": want [" + r[1] + "], got " + literals(p.contract));
                }
            }
        }
        assertTrue(bad.isEmpty(), String.join("\n", bad));
    }

    @Test
    void unaryMinusOnlyLiterals() throws Exception {
        String[][] accept = {
            {"java", "-2147483648", "2147483648"}, {"java", "- 9223372036854775808L", "9223372036854775808"},
            {"rs", "-128i8", "128"}, {"rs", "-(128i8)", "128"}, {"rs", "-9223372036854775808i64", "9223372036854775808"},
        };
        for (String[] a : accept) {
            Parsed p = parse(TEMPLATE.get(a[0]).apply(a[1]), "T.runar." + a[0]);
            assertNull(p.error, a[1] + ": " + p.error);
            List<BigInteger> vals = literals(p.contract);
            // javac folds `-2147483648` into one negative literal.
            BigInteger want = new BigInteger(a[2]);
            assertTrue(vals.equals(List.of(want)) || vals.equals(List.of(want.negate())), a[1] + ": " + vals);
        }
        String[][] refuse = {
            {"java", "-(2147483648)", "2147483648"}, {"java", "1 - 2147483648", "2147483648"}, {"java", "2147483648", "2147483648"},
            {"java", "-9223372036854775808", "9223372036854775808"}, {"rs", "128i8", "128i8"}, {"rs", "1 - 128i8", "128i8"},
            {"rs", "-129i8", "129i8"},
        };
        for (String[] r : refuse) {
            Parsed p = parse(TEMPLATE.get(r[0]).apply(r[1]), "T.runar." + r[0]);
            assertNotNull(p.error, r[1] + ": accepted");
            assertTrue(p.error.contains(IntLiteral.invalid(r[0], r[2])), r[1] + ": " + p.error);
        }
    }

    private static String zig(String params, String body) {
        return "const runar = @import(\"runar\");\n\npub const T = struct {\n    pub const Contract = runar.SmartContract;\n\n"
            + "    target: i64,\n\n    pub fn init(target: i64) T {\n        return .{ .target = target };\n    }\n\n"
            + "    pub fn verify(self: *const T, amount: i64" + params + ") void {\n        _ = self;\n" + body + "\n    }\n};\n";
    }

    private static String py(String params, String body) {
        return "from runar import SmartContract, Bigint, ByteString, public, assert_\n\nclass T(SmartContract):\n"
            + "    target: Bigint\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n"
            + "        self.target = target\n\n    @public\n    def verify(self, amount: Bigint" + params + "):\n" + body + "\n";
    }

    @Test
    void exploitShapesReadTheLiteral() throws Exception {
        Parsed p = parse(zig(", b1010: runar.ByteString", "        runar.assert(amount > 0b1010);"), "T.runar.zig");
        assertNull(p.error, p.error);
        assertEquals(List.of(BigInteger.TEN), literals(p.contract));
        p = parse(zig(", B1010: i64", "        runar.assert(amount > 0B1010);\n        runar.assert(B1010 == B1010);"), "T.runar.zig");
        assertTrue(p.error != null && p.error.contains(IntLiteral.invalid("zig", "0B1010")), String.valueOf(p.error));
        for (String lit : new String[] {"0b1010", "0o12", "0xa"}) {
            p = parse("const runar = @import(\"runar\");\n\npub const T = struct {\n    pub const Contract = runar.SmartContract;\n\n"
                + "    target: i64 = " + lit + ",\n\n    pub fn verify(self: *const T, amount: i64) void {\n"
                + "        runar.assert(amount > self.target);\n    }\n};\n", "T.runar.zig");
            assertNull(p.error, lit + ": " + p.error);
            assertEquals(new BigIntLiteral(BigInteger.TEN), p.contract.properties().get(0).initializer(), lit);
        }
        p = parse(py(", b1010: Bigint", "        lim = 0b1010\n        assert_(amount > lim)"), "T.runar.py");
        assertNull(p.error, p.error);
        assertEquals(List.of(BigInteger.TEN), literals(p.contract));
        for (String lit : new String[] {"0o12", "0b1010"}) {
            p = parse("from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n"
                + "    limit: Bigint = " + lit + "\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n"
                + "        self.target = target\n\n    @public\n    def verify(self, amount: Bigint):\n        assert_(amount > self.limit)\n", "T.runar.py");
            assertNull(p.error, lit + ": " + p.error);
            assertEquals(new BigIntLiteral(BigInteger.TEN), p.contract.properties().get(1).initializer(), lit);
        }
        for (String lit : new String[] {"0b102", "0o19"}) {
            p = parse(TEMPLATE.get("ts").apply(lit), "T.runar.ts");
            assertTrue(p.error != null && p.error.contains(IntLiteral.invalid("ts", lit)), String.valueOf(p.error));
        }
    }

    @Test
    void absorbingPaths() {
        Parsed p = parse(zig(", b: i64", "        runar.assert(runar.within(amount b, 20));"), "T.runar.zig");
        assertTrue(p.error != null && p.error.contains(ZIG_COMMA), String.valueOf(p.error));
        p = parse(zig(", b: i64", "        runar.assert(runar.within(amount, b, 20,));"), "T.runar.zig");
        assertFalse(p.error != null && p.error.contains(ZIG_COMMA), String.valueOf(p.error));
        p = parse(zig("", "        const xs = [ 1 2, 3 ];\n        runar.assert(amount > xs[0]);"), "T.runar.zig");
        assertTrue(p.error != null && p.error.contains(ZIG_COMMA), String.valueOf(p.error));
        p = parse(zig("", "        const xs: [3]i64 = .{ 1, 2 3 };\n        runar.assert(amount > xs[0]);"), "T.runar.zig");
        assertTrue(p.error != null && p.error.contains(ZIG_COMMA), String.valueOf(p.error));
        p = parse(py(", b: Bigint", "        lim = 10 b\n        assert_(amount > lim)"), "T.runar.py");
        assertTrue(p.error != null && p.error.contains(PY_LINE_BREAK), String.valueOf(p.error));
        p = parse(py("", "        assert_(amount > 1) assert_(amount > 2)"), "T.runar.py");
        assertTrue(p.error != null && p.error.contains(PY_LINE_BREAK), String.valueOf(p.error));
        p = parse("from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n"
            + "    target: Bigint = 10 extra\n\n    @public\n    def verify(self, amount: Bigint):\n        assert_(amount > self.target)\n", "T.runar.py");
        assertTrue(p.error != null && p.error.contains(PY_LINE_BREAK), String.valueOf(p.error));
        p = parse(TEMPLATE.get("ts").apply("10").replace("assert(a > 10);", "assert(a > 10;"), "T.runar.ts");
        assertNotNull(p.error, "ts unclosed call accepted");
    }
}
