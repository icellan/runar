package runar.compiler.frontend;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BigIntLiteral;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.ForStatement;
import runar.compiler.ir.ast.Identifier;
import runar.compiler.ir.ast.IfStatement;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.ParentClass;
import runar.compiler.ir.ast.PrimitiveType;
import runar.compiler.ir.ast.PrimitiveTypeName;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;

import static org.junit.jupiter.api.Assertions.*;

class ZigParserTest {

    private static final String P2PKH = """
        const runar = @import("runar");

        pub const P2PKH = struct {
            pub const Contract = runar.SmartContract;

            pubKeyHash: runar.Addr,

            pub fn init(pubKeyHash: runar.Addr) P2PKH {
                return .{ .pubKeyHash = pubKeyHash };
            }

            pub fn unlock(self: *const P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
                runar.assert(runar.bytesEq(runar.hash160(pubKey), self.pubKeyHash));
                runar.assert(runar.checkSig(sig, pubKey));
            }
        };
        """;

    private static final String COUNTER = """
        const runar = @import("runar");

        pub const Counter = struct {
            pub const Contract = runar.StatefulSmartContract;

            count: i64 = 0,

            pub fn init(count: i64) Counter {
                return .{ .count = count };
            }

            pub fn increment(self: *Counter) void {
                self.count += 1;
            }

            pub fn decrement(self: *Counter) void {
                runar.assert(self.count > 0);
                self.count -= 1;
            }
        };
        """;

    @Test
    void parsesP2pkhContractShape() throws ZigParser.ParseException {
        ContractNode c = ZigParser.parse(P2PKH, "P2PKH.runar.zig");

        assertEquals("P2PKH", c.name());
        assertEquals(ParentClass.SMART_CONTRACT, c.parentClass());
        assertEquals("P2PKH.runar.zig", c.sourceFile());
        assertEquals(1, c.properties().size());

        var pkh = c.properties().get(0);
        assertEquals("pubKeyHash", pkh.name());
        // SmartContract → all properties are forced readonly.
        assertTrue(pkh.readonly());
        assertEquals(new PrimitiveType(PrimitiveTypeName.ADDR), pkh.type());
        // ctor param overrides → initializer should be null.
        assertNull(pkh.initializer());
    }

    @Test
    void parsesP2pkhConstructorWithSuperAndAssignment() throws ZigParser.ParseException {
        ContractNode c = ZigParser.parse(P2PKH, "P2PKH.runar.zig");
        MethodNode ctor = c.constructor();
        assertEquals("constructor", ctor.name());
        assertEquals(Visibility.PUBLIC, ctor.visibility());
        assertEquals(1, ctor.params().size());
        assertEquals("pubKeyHash", ctor.params().get(0).name());

        // Body should be: super(pubKeyHash); this.pubKeyHash = pubKeyHash;
        assertEquals(2, ctor.body().size());

        var superStmt = (ExpressionStatement) ctor.body().get(0);
        var superCall = (CallExpr) superStmt.expression();
        assertEquals("super", ((Identifier) superCall.callee()).name());
        assertEquals(1, superCall.args().size());
        assertEquals("pubKeyHash", ((Identifier) superCall.args().get(0)).name());

        var assignStmt = (AssignmentStatement) ctor.body().get(1);
        assertEquals("pubKeyHash", ((PropertyAccessExpr) assignStmt.target()).property());
        assertEquals("pubKeyHash", ((Identifier) assignStmt.value()).name());
    }

    @Test
    void parsesP2pkhUnlockMethod() throws ZigParser.ParseException {
        ContractNode c = ZigParser.parse(P2PKH, "P2PKH.runar.zig");
        assertEquals(1, c.methods().size());
        var unlock = c.methods().get(0);
        assertEquals("unlock", unlock.name());
        assertEquals(Visibility.PUBLIC, unlock.visibility());
        // self is filtered out, so we get 2 params.
        assertEquals(2, unlock.params().size());
        assertEquals(new PrimitiveType(PrimitiveTypeName.SIG), unlock.params().get(0).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.PUB_KEY), unlock.params().get(1).type());

        // First stmt: runar.assert(runar.bytesEq(runar.hash160(pubKey), self.pubKeyHash))
        // → assert(bytesEq lowered to BinaryExpr(===, hash160(pubKey), this.pubKeyHash))
        var stmt0 = (ExpressionStatement) unlock.body().get(0);
        var assertCall = (CallExpr) stmt0.expression();
        assertEquals("assert", ((Identifier) assertCall.callee()).name());
        assertEquals(1, assertCall.args().size());
        var eqExpr = (BinaryExpr) assertCall.args().get(0);
        assertEquals(Expression.BinaryOp.EQ, eqExpr.op());
        // LHS: hash160(pubKey)
        var lhs = (CallExpr) eqExpr.left();
        assertEquals("hash160", ((Identifier) lhs.callee()).name());
        // RHS: this.pubKeyHash → PropertyAccessExpr (self resolved)
        var rhs = (PropertyAccessExpr) eqExpr.right();
        assertEquals("pubKeyHash", rhs.property());
    }

    @Test
    void parsesStatefulCounter() throws ZigParser.ParseException {
        ContractNode c = ZigParser.parse(COUNTER, "Counter.runar.zig");
        assertEquals("Counter", c.name());
        assertEquals(ParentClass.STATEFUL_SMART_CONTRACT, c.parentClass());

        // count property is mutated by increment/decrement → not readonly.
        assertEquals(1, c.properties().size());
        var count = c.properties().get(0);
        assertEquals("count", count.name());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT), count.type());
        assertFalse(count.readonly(), "mutated stateful field must not be readonly");

        // Methods: init was lifted out. Increment + decrement remain.
        assertEquals(2, c.methods().size());
        var increment = c.methods().get(0);
        assertEquals("increment", increment.name());
        // self.count += 1 → AssignmentStatement(this.count, BinaryExpr(ADD, this.count, 1))
        var inc = (AssignmentStatement) increment.body().get(0);
        assertEquals("count", ((PropertyAccessExpr) inc.target()).property());
        var rhs = (BinaryExpr) inc.value();
        assertEquals(Expression.BinaryOp.ADD, rhs.op());
        assertEquals("count", ((PropertyAccessExpr) rhs.left()).property());
        assertEquals(BigInteger.ONE, ((BigIntLiteral) rhs.right()).value());
    }

    @Test
    void parsesIfElseAndComparison() throws ZigParser.ParseException {
        String src = """
            const runar = @import("runar");
            pub const C = struct {
                pub const Contract = runar.SmartContract;
                limit: i64,
                pub fn init(limit: i64) C { return .{ .limit = limit }; }
                pub fn check(self: *const C, x: i64) void {
                    if (x < self.limit) {
                        runar.assert(true);
                    } else {
                        runar.assert(false);
                    }
                }
            };
            """;
        ContractNode c = ZigParser.parse(src, "C.runar.zig");
        var check = c.methods().get(0);
        assertEquals(1, check.body().size());
        var ifStmt = (IfStatement) check.body().get(0);
        var cond = (BinaryExpr) ifStmt.condition();
        assertEquals(Expression.BinaryOp.LT, cond.op());
        assertEquals("x", ((Identifier) cond.left()).name());
        assertEquals("limit", ((PropertyAccessExpr) cond.right()).property());
        assertEquals(1, ifStmt.thenBody().size());
        assertNotNull(ifStmt.elseBody());
        assertEquals(1, ifStmt.elseBody().size());
    }

    @Test
    void parsesWhileLoopWithVarDeclMerged() throws ZigParser.ParseException {
        // The `var i = 0; while (i < 10) : (i += 1) { ... }` Zig idiom should
        // collapse into a single ForStatement whose init is the var decl.
        String src = """
            const runar = @import("runar");
            pub const C = struct {
                pub const Contract = runar.SmartContract;
                target: i64,
                pub fn init(target: i64) C { return .{ .target = target }; }
                pub fn loopy(self: *const C) void {
                    var sum: i64 = 0;
                    var i: i64 = 0;
                    while (i < 10) : (i += 1) {
                        sum += 1;
                    }
                    runar.assert(sum == self.target);
                }
            };
            """;
        ContractNode c = ZigParser.parse(src, "C.runar.zig");
        var loopy = c.methods().get(0);
        // body should be: var sum, ForStmt, assert(...)
        assertEquals(3, loopy.body().size());
        assertTrue(loopy.body().get(0) instanceof VariableDeclStatement);
        var fs = (ForStatement) loopy.body().get(1);
        // init merged
        assertNotNull(fs.init());
        assertEquals("i", fs.init().name());
        // condition is i < 10
        var cond = (BinaryExpr) fs.condition();
        assertEquals(Expression.BinaryOp.LT, cond.op());
    }

    @Test
    void rewritesBareMethodCallsToThisDot() throws ZigParser.ParseException {
        String src = """
            const runar = @import("runar");
            pub const C = struct {
                pub const Contract = runar.SmartContract;
                a: i64,
                pub fn init(a: i64) C { return .{ .a = a }; }
                fn helper(self: *const C, x: i64) i64 { return x + self.a; }
                pub fn entry(self: *const C, y: i64) void {
                    runar.assert(helper(y) == self.a);
                }
            };
            """;
        ContractNode c = ZigParser.parse(src, "C.runar.zig");
        // entry's body: assert(helper(y) == self.a)
        // → bare helper(y) should be rewritten to this.helper(y)
        MethodNode entry = c.methods().stream()
            .filter(m -> m.name().equals("entry")).findFirst().orElseThrow();
        var stmt = (ExpressionStatement) entry.body().get(0);
        var assertCall = (CallExpr) stmt.expression();
        var cmp = (BinaryExpr) assertCall.args().get(0);
        assertEquals(Expression.BinaryOp.EQ, cmp.op());
        var helperCall = (CallExpr) cmp.left();
        // Callee should be PropertyAccessExpr("helper") — not Identifier("helper").
        assertInstanceOf(PropertyAccessExpr.class, helperCall.callee(),
            "bare helper(...) call must be rewritten to this.helper(...)");
        assertEquals("helper", ((PropertyAccessExpr) helperCall.callee()).property());
    }

    @Test
    void parsesZigBuiltinDivTrunc() throws ZigParser.ParseException {
        String src = """
            const runar = @import("runar");
            pub const C = struct {
                pub const Contract = runar.SmartContract;
                a: i64,
                pub fn init(a: i64) C { return .{ .a = a }; }
                pub fn check(self: *const C, x: i64, y: i64) void {
                    runar.assert(@divTrunc(x, y) == self.a);
                }
            };
            """;
        ContractNode c = ZigParser.parse(src, "C.runar.zig");
        var stmt = (ExpressionStatement) c.methods().get(0).body().get(0);
        var assertCall = (CallExpr) stmt.expression();
        var cmp = (BinaryExpr) assertCall.args().get(0);
        var divExpr = (BinaryExpr) cmp.left();
        assertEquals(Expression.BinaryOp.DIV, divExpr.op());
    }

    @Test
    void parsesNumericLiteralsIncludingHex() throws ZigParser.ParseException {
        String src = """
            const runar = @import("runar");
            pub const C = struct {
                pub const Contract = runar.SmartContract;
                a: i64,
                pub fn init(a: i64) C { return .{ .a = a }; }
                pub fn check(self: *const C) void {
                    runar.assert(self.a == 0xff);
                }
            };
            """;
        ContractNode c = ZigParser.parse(src, "C.runar.zig");
        var stmt = (ExpressionStatement) c.methods().get(0).body().get(0);
        var assertCall = (CallExpr) stmt.expression();
        var cmp = (BinaryExpr) assertCall.args().get(0);
        assertEquals(BigInteger.valueOf(0xff), ((BigIntLiteral) cmp.right()).value());
    }

    @Test
    void parsesPropertyInitializerWithoutCtorParam() throws ZigParser.ParseException {
        // Zig field with default and no matching ctor param keeps its
        // initializer through to the AST.
        String src = """
            const runar = @import("runar");
            pub const C = struct {
                pub const Contract = runar.StatefulSmartContract;
                count: i64 = 7,
                pub fn init() C { return .{ .count = 7 }; }
                pub fn bump(self: *C) void { self.count += 1; }
            };
            """;
        ContractNode c = ZigParser.parse(src, "C.runar.zig");
        assertEquals(1, c.properties().size());
        var count = c.properties().get(0);
        // No ctor param named `count`, so the initializer survives.
        assertNotNull(count.initializer());
        assertEquals(BigInteger.valueOf(7),
            ((BigIntLiteral) count.initializer()).value());
        // Stateful + mutated → not readonly.
        assertFalse(count.readonly());
    }

    // -----------------------------------------------------------------
    // Malformed input
    // -----------------------------------------------------------------

    @Test
    void rejectsMissingRunarImport() {
        String src = """
            pub const C = struct {
                pub const Contract = runar.SmartContract;
                a: i64,
                pub fn init(a: i64) C { return .{ .a = a }; }
            };
            """;
        ZigParser.ParseException e = assertThrows(ZigParser.ParseException.class,
            () -> ZigParser.parse(src, "C.runar.zig"));
        assertTrue(e.getMessage().contains("@import"),
            "error must mention the missing runar import: " + e.getMessage());
    }

    @Test
    void rejectsSourceWithoutContractStruct() {
        String src = """
            const runar = @import("runar");
            // no contract here
            """;
        ZigParser.ParseException e = assertThrows(ZigParser.ParseException.class,
            () -> ZigParser.parse(src, "Empty.runar.zig"));
        assertTrue(e.getMessage().contains("Expected Zig contract declaration"),
            "error must mention the missing struct: " + e.getMessage());
    }

    @Test
    void reportsForLoopAsUnsupported() {
        String src = """
            const runar = @import("runar");
            pub const C = struct {
                pub const Contract = runar.SmartContract;
                a: i64,
                pub fn init(a: i64) C { return .{ .a = a }; }
                pub fn loopy(self: *const C) void {
                    for (0..10) |i| { runar.assert(i >= 0); }
                }
            };
            """;
        ZigParser.ParseException e = assertThrows(ZigParser.ParseException.class,
            () -> ZigParser.parse(src, "C.runar.zig"));
        assertTrue(e.getMessage().toLowerCase().contains("for"),
            "error must mention unsupported for-loop: " + e.getMessage());
    }
}
