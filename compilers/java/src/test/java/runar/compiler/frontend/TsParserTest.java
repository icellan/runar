package runar.compiler.frontend;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BigIntLiteral;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.BoolLiteral;
import runar.compiler.ir.ast.ByteStringLiteral;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.CustomType;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.FixedArrayType;
import runar.compiler.ir.ast.ForStatement;
import runar.compiler.ir.ast.Identifier;
import runar.compiler.ir.ast.IfStatement;
import runar.compiler.ir.ast.IndexAccessExpr;
import runar.compiler.ir.ast.MemberExpr;
import runar.compiler.ir.ast.ParentClass;
import runar.compiler.ir.ast.PrimitiveType;
import runar.compiler.ir.ast.PrimitiveTypeName;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.PropertyNode;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.TernaryExpr;
import runar.compiler.ir.ast.TypeNode;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TsParserTest {

    // ---------------------------------------------------------------
    // Conformance fixtures
    // ---------------------------------------------------------------

    /**
     * Locate the canonical TypeScript contract for a conformance fixture.
     * Since commit 4dc929c the fixtures point at {@code examples/ts/...} as
     * the canonical source rather than carrying a per-fixture .runar.ts
     * file, so this helper resolves the example path directly.
     */
    private static Path conformanceFile(String exampleDir, String name) {
        // Working directory at test time is compilers/java. Walk up to the repo root.
        Path repoRoot = Path.of("").toAbsolutePath().getParent().getParent();
        return repoRoot.resolve("examples/ts").resolve(exampleDir).resolve(name);
    }

    private static String readFixture(String exampleDir, String name) throws IOException {
        return Files.readString(conformanceFile(exampleDir, name));
    }

    @Test
    void parsesBasicP2pkhFixture() throws Exception {
        String src = readFixture("p2pkh", "P2PKH.runar.ts");
        ContractNode c = TsParser.parse(src, "P2PKH.runar.ts");

        assertEquals("P2PKH", c.name());
        assertEquals(ParentClass.SMART_CONTRACT, c.parentClass());
        assertEquals("P2PKH.runar.ts", c.sourceFile());
        assertEquals(1, c.properties().size());
        assertEquals("pubKeyHash", c.properties().get(0).name());
        assertTrue(c.properties().get(0).readonly());
        assertEquals(new PrimitiveType(PrimitiveTypeName.ADDR), c.properties().get(0).type());
        assertEquals(1, c.methods().size());
        assertEquals("unlock", c.methods().get(0).name());
        assertEquals(Visibility.PUBLIC, c.methods().get(0).visibility());
        assertEquals(2, c.methods().get(0).params().size());
        assertEquals("constructor", c.constructor().name());
        assertEquals(1, c.constructor().params().size());
    }

    @Test
    void parsesArithmeticFixture() throws Exception {
        String src = readFixture("arithmetic", "Arithmetic.runar.ts");
        ContractNode c = TsParser.parse(src, "Arithmetic.runar.ts");
        assertEquals("Arithmetic", c.name());
        assertEquals(ParentClass.SMART_CONTRACT, c.parentClass());
        assertEquals(1, c.properties().size());
        assertEquals("target", c.properties().get(0).name());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT), c.properties().get(0).type());
        assertEquals(1, c.methods().size());
        var verify = c.methods().get(0);
        assertEquals("verify", verify.name());
        assertEquals(2, verify.params().size());
        // Body has 5 variable decls + 1 assert call
        assertEquals(6, verify.body().size());
        assertInstanceOf(VariableDeclStatement.class, verify.body().get(0));
    }

    @Test
    void parsesEscrowFixture() throws Exception {
        String src = readFixture("escrow", "Escrow.runar.ts");
        ContractNode c = TsParser.parse(src, "Escrow.runar.ts");
        assertEquals("Escrow", c.name());
        assertEquals(ParentClass.SMART_CONTRACT, c.parentClass());
        assertEquals(3, c.properties().size());
        // Two public methods: release and refund
        assertEquals(2, c.methods().size());
        assertEquals("release", c.methods().get(0).name());
        assertEquals("refund", c.methods().get(1).name());
        // Constructor takes 3 params
        assertEquals(3, c.constructor().params().size());
        // Constructor body: super + 3 assignments = 4 statements
        assertEquals(4, c.constructor().body().size());
    }

    // ---------------------------------------------------------------
    // Failure modes
    // ---------------------------------------------------------------

    @Test
    void failsOnSourceWithNoContractClass() {
        String src = "import { SmartContract } from 'runar-lang';\n";
        TsParser.ParseException e = assertThrows(TsParser.ParseException.class,
            () -> TsParser.parse(src, "Empty.runar.ts"));
        assertTrue(e.getMessage().contains("no class extending SmartContract"));
    }

    @Test
    void failsOnUnknownParentClass() {
        String src = "class Bad extends Frobulator { constructor() { super(); } }\n";
        TsParser.ParseException e = assertThrows(TsParser.ParseException.class,
            () -> TsParser.parse(src, "Bad.runar.ts"));
        assertTrue(e.getMessage().contains("no class extending SmartContract"));
    }

    @Test
    void failsOnContractWithoutConstructor() {
        String src = """
            class C extends SmartContract {
              public foo(): void {
                assert(true);
              }
            }
            """;
        TsParser.ParseException e = assertThrows(TsParser.ParseException.class,
            () -> TsParser.parse(src, "C.runar.ts"));
        assertTrue(e.getMessage().contains("must have a constructor"));
    }

    @Test
    void failsOnPropertyWithoutTypeAnnotation() {
        String src = """
            class C extends SmartContract {
              readonly foo;
              constructor() { super(); }
            }
            """;
        TsParser.ParseException e = assertThrows(TsParser.ParseException.class,
            () -> TsParser.parse(src, "C.runar.ts"));
        assertTrue(e.getMessage().contains("must have an explicit type annotation"));
    }

    // ---------------------------------------------------------------
    // Each statement / expression form
    // ---------------------------------------------------------------

    private static ContractNode parseSnippet(String classBody) throws Exception {
        String src = """
            class C extends SmartContract {
              %s
            }
            """.formatted(classBody);
        return TsParser.parse(src, "C.runar.ts");
    }

    @Test
    void parsesIfElseStatement() throws Exception {
        ContractNode c = parseSnippet("""
              constructor() { super(); }
              public foo(x: bigint): void {
                if (x > 0n) {
                  assert(true);
                } else {
                  assert(false);
                }
              }
            """);
        var foo = c.methods().get(0);
        IfStatement ifs = (IfStatement) foo.body().get(0);
        assertInstanceOf(BinaryExpr.class, ifs.condition());
        assertEquals(1, ifs.thenBody().size());
        assertNotNull(ifs.elseBody());
        assertEquals(1, ifs.elseBody().size());
    }

    @Test
    void parsesIfWithoutElse() throws Exception {
        ContractNode c = parseSnippet("""
              constructor() { super(); }
              public foo(x: bigint): void {
                if (x > 0n) { assert(true); }
              }
            """);
        var foo = c.methods().get(0);
        IfStatement ifs = (IfStatement) foo.body().get(0);
        assertNull(ifs.elseBody());
    }

    @Test
    void parsesElseIfChain() throws Exception {
        ContractNode c = parseSnippet("""
              constructor() { super(); }
              public foo(x: bigint): void {
                if (x > 0n) {
                  assert(true);
                } else if (x < 0n) {
                  assert(false);
                } else {
                  assert(true);
                }
              }
            """);
        var foo = c.methods().get(0);
        IfStatement outer = (IfStatement) foo.body().get(0);
        assertEquals(1, outer.elseBody().size());
        assertInstanceOf(IfStatement.class, outer.elseBody().get(0));
    }

    @Test
    void parsesForLoop() throws Exception {
        ContractNode c = parseSnippet("""
              constructor() { super(); }
              public foo(): void {
                for (let i: bigint = 0n; i < 10n; i++) {
                  assert(true);
                }
              }
            """);
        var foo = c.methods().get(0);
        ForStatement fs = (ForStatement) foo.body().get(0);
        assertEquals("i", fs.init().name());
        assertInstanceOf(BinaryExpr.class, fs.condition());
        assertNotNull(fs.update());
        assertEquals(1, fs.body().size());
    }

    @Test
    void parsesReturnWithAndWithoutValue() throws Exception {
        ContractNode c = parseSnippet("""
              constructor() { super(); }
              public valued(): bigint {
                return 7n;
              }
              public bare(): void {
                return;
              }
            """);
        ReturnStatement valued = (ReturnStatement) c.methods().get(0).body().get(0);
        assertNotNull(valued.value());
        assertInstanceOf(BigIntLiteral.class, valued.value());
        assertEquals(BigInteger.valueOf(7), ((BigIntLiteral) valued.value()).value());

        ReturnStatement bare = (ReturnStatement) c.methods().get(1).body().get(0);
        assertNull(bare.value());
    }

    @Test
    void parsesLetAndConstDeclarations() throws Exception {
        ContractNode c = parseSnippet("""
              constructor() { super(); }
              public foo(): void {
                let x: bigint = 1n;
                const y: bigint = 2n;
                let z = 3n;
                assert(x + y + z === 6n);
              }
            """);
        var foo = c.methods().get(0);
        VariableDeclStatement x = (VariableDeclStatement) foo.body().get(0);
        VariableDeclStatement y = (VariableDeclStatement) foo.body().get(1);
        VariableDeclStatement z = (VariableDeclStatement) foo.body().get(2);
        assertEquals("x", x.name());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT), x.type());
        assertEquals("y", y.name());
        assertEquals("z", z.name());
        assertNull(z.type()); // no annotation
    }

    @Test
    void parsesAssignmentStatement() throws Exception {
        String src = """
            class C extends StatefulSmartContract {
              count: bigint;
              constructor(count: bigint) { super(count); this.count = count; }
              public bump(): void {
                this.count = this.count + 1n;
              }
            }
            """;
        ContractNode c = TsParser.parse(src, "C.runar.ts");
        var bump = c.methods().get(0);
        AssignmentStatement a = (AssignmentStatement) bump.body().get(0);
        assertInstanceOf(PropertyAccessExpr.class, a.target());
        assertInstanceOf(BinaryExpr.class, a.value());
    }

    @Test
    void parsesCompoundAssignment() throws Exception {
        String src = """
            class C extends StatefulSmartContract {
              count: bigint;
              constructor(count: bigint) { super(count); this.count = count; }
              public bump(): void {
                this.count += 5n;
              }
            }
            """;
        ContractNode c = TsParser.parse(src, "C.runar.ts");
        var bump = c.methods().get(0);
        AssignmentStatement a = (AssignmentStatement) bump.body().get(0);
        BinaryExpr add = (BinaryExpr) a.value();
        assertEquals(Expression.BinaryOp.ADD, add.op());
    }

    @Test
    void parsesArithmeticOperators() throws Exception {
        ContractNode c = parseSnippet("""
              constructor() { super(); }
              public foo(a: bigint, b: bigint): void {
                let x = a + b * 2n - 4n / 2n % 1n;
                assert(x === 0n);
              }
            """);
        var foo = c.methods().get(0);
        VariableDeclStatement decl = (VariableDeclStatement) foo.body().get(0);
        // Make sure we have some BinaryExpr tree
        assertInstanceOf(BinaryExpr.class, decl.init());
    }

    @Test
    void parsesBitwiseAndShiftOperators() throws Exception {
        ContractNode c = parseSnippet("""
              constructor() { super(); }
              public foo(a: bigint, b: bigint): void {
                let x = (a & b) | (a ^ b);
                let y = a << 2n;
                let z = a >> 1n;
                let w = ~a;
                assert(x === y);
                assert(z === w);
              }
            """);
        var foo = c.methods().get(0);
        VariableDeclStatement xDecl = (VariableDeclStatement) foo.body().get(0);
        BinaryExpr or = (BinaryExpr) xDecl.init();
        assertEquals(Expression.BinaryOp.BIT_OR, or.op());
        BinaryExpr leftAnd = (BinaryExpr) or.left();
        assertEquals(Expression.BinaryOp.BIT_AND, leftAnd.op());

        VariableDeclStatement yDecl = (VariableDeclStatement) foo.body().get(1);
        BinaryExpr shl = (BinaryExpr) yDecl.init();
        assertEquals(Expression.BinaryOp.SHL, shl.op());

        VariableDeclStatement zDecl = (VariableDeclStatement) foo.body().get(2);
        assertEquals(Expression.BinaryOp.SHR, ((BinaryExpr) zDecl.init()).op());

        VariableDeclStatement wDecl = (VariableDeclStatement) foo.body().get(3);
        UnaryExpr bitNot = (UnaryExpr) wDecl.init();
        assertEquals(Expression.UnaryOp.BIT_NOT, bitNot.op());
    }

    @Test
    void parsesComparisonOperators() throws Exception {
        ContractNode c = parseSnippet("""
              constructor() { super(); }
              public foo(a: bigint, b: bigint): void {
                assert(a < b);
                assert(a <= b);
                assert(a > b);
                assert(a >= b);
                assert(a === b);
                assert(a !== b);
                assert(a == b);
                assert(a != b);
              }
            """);
        var foo = c.methods().get(0);
        var ops = new Expression.BinaryOp[] {
            Expression.BinaryOp.LT, Expression.BinaryOp.LE,
            Expression.BinaryOp.GT, Expression.BinaryOp.GE,
            Expression.BinaryOp.EQ, Expression.BinaryOp.NEQ,
            Expression.BinaryOp.EQ, Expression.BinaryOp.NEQ
        };
        for (int i = 0; i < ops.length; i++) {
            ExpressionStatement es = (ExpressionStatement) foo.body().get(i);
            CallExpr call = (CallExpr) es.expression();
            BinaryExpr be = (BinaryExpr) call.args().get(0);
            assertEquals(ops[i], be.op(), "op[" + i + "]");
        }
    }

    @Test
    void parsesLogicalAndUnaryOperators() throws Exception {
        ContractNode c = parseSnippet("""
              constructor() { super(); }
              public foo(a: boolean, b: boolean, x: bigint): void {
                assert(a && b);
                assert(a || b);
                assert(!a);
                assert(-x === 0n);
              }
            """);
        var foo = c.methods().get(0);
        var s0 = (ExpressionStatement) foo.body().get(0);
        var s1 = (ExpressionStatement) foo.body().get(1);
        var s2 = (ExpressionStatement) foo.body().get(2);
        var s3 = (ExpressionStatement) foo.body().get(3);

        var ce0 = (CallExpr) s0.expression();
        var ce1 = (CallExpr) s1.expression();
        var ce2 = (CallExpr) s2.expression();
        var ce3 = (CallExpr) s3.expression();

        assertEquals(Expression.BinaryOp.AND, ((BinaryExpr) ce0.args().get(0)).op());
        assertEquals(Expression.BinaryOp.OR, ((BinaryExpr) ce1.args().get(0)).op());
        assertEquals(Expression.UnaryOp.NOT, ((UnaryExpr) ce2.args().get(0)).op());
        BinaryExpr eq = (BinaryExpr) ce3.args().get(0);
        assertEquals(Expression.BinaryOp.EQ, eq.op());
        assertEquals(Expression.UnaryOp.NEG, ((UnaryExpr) eq.left()).op());
    }

    @Test
    void parsesTernaryExpression() throws Exception {
        ContractNode c = parseSnippet("""
              constructor() { super(); }
              public foo(x: bigint): bigint {
                return x > 0n ? x : -x;
              }
            """);
        ReturnStatement ret = (ReturnStatement) c.methods().get(0).body().get(0);
        assertInstanceOf(TernaryExpr.class, ret.value());
    }

    @Test
    void parsesArrayIndexAndMemberAccess() throws Exception {
        String src = """
            class C extends SmartContract {
              readonly nums: FixedArray<bigint, 4>;
              constructor(nums: FixedArray<bigint, 4>) { super(nums); this.nums = nums; }
              public foo(): void {
                assert(this.nums[0] === 0n);
              }
            }
            """;
        ContractNode c = TsParser.parse(src, "C.runar.ts");
        var prop = c.properties().get(0);
        assertInstanceOf(FixedArrayType.class, prop.type());
        FixedArrayType fa = (FixedArrayType) prop.type();
        assertEquals(4, fa.length());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT), fa.element());

        var foo = c.methods().get(0);
        ExpressionStatement es = (ExpressionStatement) foo.body().get(0);
        CallExpr assertCall = (CallExpr) es.expression();
        BinaryExpr eq = (BinaryExpr) assertCall.args().get(0);
        assertInstanceOf(IndexAccessExpr.class, eq.left());
        IndexAccessExpr ia = (IndexAccessExpr) eq.left();
        assertInstanceOf(PropertyAccessExpr.class, ia.object());
        assertEquals("nums", ((PropertyAccessExpr) ia.object()).property());
    }

    @Test
    void parsesMethodCallsAndChainedMemberAccess() throws Exception {
        String src = """
            class C extends SmartContract {
              readonly addr: Addr;
              constructor(addr: Addr) { super(addr); this.addr = addr; }
              public foo(sig: Sig, pk: PubKey): void {
                assert(checkSig(sig, pk));
                this.helper(sig);
              }
              private helper(sig: Sig): void {
                assert(true);
              }
            }
            """;
        ContractNode c = TsParser.parse(src, "C.runar.ts");
        var foo = c.methods().get(0);
        ExpressionStatement es = (ExpressionStatement) foo.body().get(0);
        CallExpr assertCall = (CallExpr) es.expression();
        CallExpr inner = (CallExpr) assertCall.args().get(0);
        assertEquals("checkSig", ((Identifier) inner.callee()).name());
        assertEquals(2, inner.args().size());

        ExpressionStatement helperStmt = (ExpressionStatement) foo.body().get(1);
        CallExpr helperCall = (CallExpr) helperStmt.expression();
        // this.helper(sig) → CallExpr(MemberExpr(Identifier("this"), "helper"), [sig])
        assertInstanceOf(MemberExpr.class, helperCall.callee());
        MemberExpr me = (MemberExpr) helperCall.callee();
        assertEquals("helper", me.property());
        assertInstanceOf(Identifier.class, me.object());
        assertEquals("this", ((Identifier) me.object()).name());

        var helperMethod = c.methods().get(1);
        assertEquals(Visibility.PRIVATE, helperMethod.visibility());
    }

    @Test
    void parsesByteStringLiteralWithAsCast() throws Exception {
        String src = """
            class C extends SmartContract {
              readonly magic: ByteString;
              constructor(magic: ByteString) { super(magic); this.magic = magic; }
              public foo(): void {
                let m: ByteString = "deadbeef" as ByteString;
                assert(m === this.magic);
              }
            }
            """;
        ContractNode c = TsParser.parse(src, "C.runar.ts");
        var foo = c.methods().get(0);
        VariableDeclStatement m = (VariableDeclStatement) foo.body().get(0);
        assertInstanceOf(ByteStringLiteral.class, m.init());
        assertEquals("deadbeef", ((ByteStringLiteral) m.init()).value());
    }

    @Test
    void parsesBigintHexAndBoolLiterals() throws Exception {
        ContractNode c = parseSnippet("""
              constructor() { super(); }
              public foo(): void {
                let h: bigint = 0xff;
                let n: bigint = 7n;
                let t: boolean = true;
                let f: boolean = false;
                assert(t);
              }
            """);
        var foo = c.methods().get(0);
        BigIntLiteral h = (BigIntLiteral) ((VariableDeclStatement) foo.body().get(0)).init();
        BigIntLiteral n = (BigIntLiteral) ((VariableDeclStatement) foo.body().get(1)).init();
        BoolLiteral t = (BoolLiteral) ((VariableDeclStatement) foo.body().get(2)).init();
        BoolLiteral f = (BoolLiteral) ((VariableDeclStatement) foo.body().get(3)).init();
        assertEquals(BigInteger.valueOf(255), h.value());
        assertEquals(BigInteger.valueOf(7), n.value());
        assertTrue(t.value());
        assertFalse(f.value());
    }

    @Test
    void parsesIncrementAndDecrement() throws Exception {
        ContractNode c = parseSnippet("""
              constructor() { super(); }
              public foo(): void {
                for (let i: bigint = 0n; i < 4n; i++) { assert(true); }
                for (let j: bigint = 4n; j > 0n; --j) { assert(true); }
              }
            """);
        var foo = c.methods().get(0);
        ForStatement fs0 = (ForStatement) foo.body().get(0);
        // i++ → IncrementExpr(prefix=false) wrapped in ExpressionStatement
        ExpressionStatement update0 = (ExpressionStatement) fs0.update();
        assertInstanceOf(runar.compiler.ir.ast.IncrementExpr.class, update0.expression());

        ForStatement fs1 = (ForStatement) foo.body().get(1);
        ExpressionStatement update1 = (ExpressionStatement) fs1.update();
        assertInstanceOf(runar.compiler.ir.ast.DecrementExpr.class, update1.expression());
    }

    @Test
    void parsesPropertyInitializer() throws Exception {
        String src = """
            class Counter extends StatefulSmartContract {
              count: bigint = 0n;
              constructor() { super(); }
            }
            """;
        ContractNode c = TsParser.parse(src, "Counter.runar.ts");
        PropertyNode p = c.properties().get(0);
        assertNotNull(p.initializer());
        assertInstanceOf(BigIntLiteral.class, p.initializer());
        assertEquals(BigInteger.ZERO, ((BigIntLiteral) p.initializer()).value());
    }

    @Test
    void parsesStatefulSmartContract() throws Exception {
        String src = """
            class Counter extends StatefulSmartContract {
              count: bigint;
              constructor(count: bigint) { super(count); this.count = count; }
              public bump(): void { this.count = this.count + 1n; }
            }
            """;
        ContractNode c = TsParser.parse(src, "Counter.runar.ts");
        assertEquals(ParentClass.STATEFUL_SMART_CONTRACT, c.parentClass());
    }
}
