package runar.compiler.frontend;

import org.junit.jupiter.api.Test;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BigIntLiteral;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.Identifier;
import runar.compiler.ir.ast.IfStatement;
import runar.compiler.ir.ast.IncrementExpr;
import runar.compiler.ir.ast.MemberExpr;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.ParentClass;
import runar.compiler.ir.ast.PrimitiveType;
import runar.compiler.ir.ast.PrimitiveTypeName;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.PropertyNode;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class SolParserTest {

    private static final String P2PKH_SOURCE = """
        pragma runar ^0.1.0;

        contract P2PKH is SmartContract {
            Addr immutable pubKeyHash;

            constructor(Addr _pubKeyHash) {
                pubKeyHash = _pubKeyHash;
            }

            function unlock(Sig sig, PubKey pubKey) public {
                require(hash160(pubKey) == pubKeyHash);
                require(checkSig(sig, pubKey));
            }
        }
        """;

    @Test
    void parsesP2pkhIntoExpectedContractShape() throws SolParser.ParseException {
        ContractNode c = SolParser.parse(P2PKH_SOURCE, "P2PKH.runar.sol");
        assertEquals("P2PKH", c.name());
        assertEquals(ParentClass.SMART_CONTRACT, c.parentClass());
        assertEquals("P2PKH.runar.sol", c.sourceFile());
        assertEquals(1, c.properties().size());

        PropertyNode pkh = c.properties().get(0);
        assertEquals("pubKeyHash", pkh.name());
        assertTrue(pkh.readonly(), "immutable should map to readonly");
        assertEquals(new PrimitiveType(PrimitiveTypeName.ADDR), pkh.type());
        assertNull(pkh.initializer());
    }

    @Test
    void parsesConstructorWithSuperAndPropAssignment() throws SolParser.ParseException {
        ContractNode c = SolParser.parse(P2PKH_SOURCE, "P2PKH.runar.sol");
        MethodNode ctor = c.constructor();
        assertEquals("constructor", ctor.name());
        assertEquals(Visibility.PUBLIC, ctor.visibility());
        assertEquals(1, ctor.params().size());
        assertEquals("pubKeyHash", ctor.params().get(0).name(),
            "leading underscore should be stripped from constructor params");

        // body[0] = super(pubKeyHash)
        ExpressionStatement superStmt = (ExpressionStatement) ctor.body().get(0);
        CallExpr superCall = (CallExpr) superStmt.expression();
        assertEquals("super", ((Identifier) superCall.callee()).name());
        assertEquals(1, superCall.args().size());
        assertEquals("pubKeyHash", ((Identifier) superCall.args().get(0)).name());

        // body[1] = this.pubKeyHash = pubKeyHash
        AssignmentStatement assign = (AssignmentStatement) ctor.body().get(1);
        assertEquals("pubKeyHash", ((PropertyAccessExpr) assign.target()).property());
        assertEquals("pubKeyHash", ((Identifier) assign.value()).name());
    }

    @Test
    void parsesUnlockMethodWithRequireLoweredToAssert() throws SolParser.ParseException {
        ContractNode c = SolParser.parse(P2PKH_SOURCE, "P2PKH.runar.sol");
        assertEquals(1, c.methods().size());
        MethodNode unlock = c.methods().get(0);
        assertEquals("unlock", unlock.name());
        assertEquals(Visibility.PUBLIC, unlock.visibility());
        assertEquals(2, unlock.params().size());

        // require(...) -> assertCall
        ExpressionStatement firstStmt = (ExpressionStatement) unlock.body().get(0);
        CallExpr assertCall = (CallExpr) firstStmt.expression();
        assertEquals("assert", ((Identifier) assertCall.callee()).name());

        // hash160(pubKey) == pubKeyHash; pubKeyHash should be rewritten
        // to PropertyAccessExpr because the bare identifier matches a
        // contract property name.
        BinaryExpr cmp = (BinaryExpr) assertCall.args().get(0);
        assertEquals(Expression.BinaryOp.EQ, cmp.op());
        assertInstanceOf(PropertyAccessExpr.class, cmp.right());
        assertEquals("pubKeyHash", ((PropertyAccessExpr) cmp.right()).property());
    }

    // -----------------------------------------------------------------
    // Stateful counter
    // -----------------------------------------------------------------

    private static final String COUNTER_SOURCE = """
        pragma runar ^0.1.0;

        contract Counter is StatefulSmartContract {
            bigint count;

            constructor(bigint _count) {
                count = _count;
            }

            function increment() public {
                this.count++;
            }

            function decrement() public {
                require(this.count > 0);
                this.count--;
            }
        }
        """;

    @Test
    void parsesStatefulCounter() throws SolParser.ParseException {
        ContractNode c = SolParser.parse(COUNTER_SOURCE, "Counter.runar.sol");
        assertEquals("Counter", c.name());
        assertEquals(ParentClass.STATEFUL_SMART_CONTRACT, c.parentClass());
        assertEquals(1, c.properties().size());
        PropertyNode count = c.properties().get(0);
        assertEquals("count", count.name());
        assertFalse(count.readonly(), "non-immutable property is mutable state");
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT), count.type());

        assertEquals(2, c.methods().size());
        MethodNode increment = c.methods().get(0);
        assertEquals("increment", increment.name());
        assertEquals(Visibility.PUBLIC, increment.visibility());
        assertInstanceOf(ExpressionStatement.class, increment.body().get(0));
        assertInstanceOf(IncrementExpr.class,
            ((ExpressionStatement) increment.body().get(0)).expression());
    }

    // -----------------------------------------------------------------
    // Property initializers
    // -----------------------------------------------------------------

    @Test
    void parsesPropertyInitializers() throws SolParser.ParseException {
        String src = """
            contract Init is StatefulSmartContract {
                int count = 0;
                int immutable maxCount;
                bool immutable active = true;

                constructor(int _maxCount) {
                    maxCount = _maxCount;
                }
            }
            """;
        ContractNode c = SolParser.parse(src, "Init.runar.sol");
        assertEquals(3, c.properties().size());

        PropertyNode count = c.properties().get(0);
        assertEquals("count", count.name());
        assertNotNull(count.initializer(), "count should carry initializer");
        assertEquals(BigInteger.ZERO, ((BigIntLiteral) count.initializer()).value());

        PropertyNode maxCount = c.properties().get(1);
        assertEquals("maxCount", maxCount.name());
        assertTrue(maxCount.readonly());
        assertNull(maxCount.initializer());

        PropertyNode active = c.properties().get(2);
        assertEquals("active", active.name());
        assertTrue(active.readonly());
        assertNotNull(active.initializer());
    }

    // -----------------------------------------------------------------
    // Type-name mapping
    // -----------------------------------------------------------------

    @Test
    void mapsSolidityTypesToRunarPrimitives() throws SolParser.ParseException {
        String src = """
            contract Types is SmartContract {
                uint immutable a;
                uint256 immutable b;
                int immutable c;
                int256 immutable d;
                bool immutable e;
                bytes immutable f;
                address immutable g;

                constructor(uint _a, uint256 _b, int _c, int256 _d, bool _e, bytes _f, address _g) {
                    a = _a; b = _b; c = _c; d = _d; e = _e; f = _f; g = _g;
                }
            }
            """;
        ContractNode c = SolParser.parse(src, "Types.runar.sol");
        assertEquals(7, c.properties().size());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT), c.properties().get(0).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT), c.properties().get(1).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT), c.properties().get(2).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT), c.properties().get(3).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BOOLEAN), c.properties().get(4).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BYTE_STRING), c.properties().get(5).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.ADDR), c.properties().get(6).type());
    }

    // -----------------------------------------------------------------
    // require with message argument
    // -----------------------------------------------------------------

    @Test
    void requireWithMessageDropsMessage() throws SolParser.ParseException {
        String src = """
            contract R is SmartContract {
                int immutable x;
                constructor(int _x) { x = _x; }
                function check(int v) public {
                    require(v > 0, "must be positive");
                }
            }
            """;
        ContractNode c = SolParser.parse(src, "R.runar.sol");
        ExpressionStatement stmt = (ExpressionStatement) c.methods().get(0).body().get(0);
        CallExpr call = (CallExpr) stmt.expression();
        assertEquals("assert", ((Identifier) call.callee()).name());
        assertEquals(1, call.args().size(), "second require arg should be dropped");
    }

    // -----------------------------------------------------------------
    // Bare-property and bare-method-call rewrite
    // -----------------------------------------------------------------

    @Test
    void rewritesBarePropertyReferenceToThis() throws SolParser.ParseException {
        String src = """
            contract IfElse is SmartContract {
                int immutable limit;
                constructor(int _limit) { limit = _limit; }
                function check(int value, bool mode) public {
                    int result = 0;
                    if (mode) {
                        result = value + limit;
                    } else {
                        result = value - limit;
                    }
                    require(result > 0);
                }
            }
            """;
        ContractNode c = SolParser.parse(src, "IfElse.runar.sol");
        MethodNode check = c.methods().get(0);
        // body[0] = let result = 0
        // body[1] = if (mode) { ... } else { ... }
        IfStatement ifs = (IfStatement) check.body().get(1);
        AssignmentStatement thenAssign = (AssignmentStatement) ifs.thenBody().get(0);
        BinaryExpr add = (BinaryExpr) thenAssign.value();
        assertEquals(Expression.BinaryOp.ADD, add.op());
        // RHS: limit -> this.limit
        assertInstanceOf(PropertyAccessExpr.class, add.right());
        assertEquals("limit", ((PropertyAccessExpr) add.right()).property());
    }

    @Test
    void rewritesBareMethodCallToThisMethod() throws SolParser.ParseException {
        String src = """
            contract M is SmartContract {
                int immutable x;
                constructor(int _x) { x = _x; }
                function helper(int a) private returns (int) { return a + 1; }
                function caller(int v) public {
                    int t = helper(v);
                    require(t > 0);
                }
            }
            """;
        ContractNode c = SolParser.parse(src, "M.runar.sol");
        MethodNode caller = c.methods().stream().filter(m -> m.name().equals("caller")).findFirst().orElseThrow();
        VariableDeclStatement decl = (VariableDeclStatement) caller.body().get(0);
        CallExpr call = (CallExpr) decl.init();
        // Expect rewrite: helper(v) -> this.helper(v)
        MemberExpr callee = (MemberExpr) call.callee();
        assertEquals("helper", callee.property());
        assertEquals("this", ((Identifier) callee.object()).name());
    }

    @Test
    void localVariableShadowsProperty() throws SolParser.ParseException {
        String src = """
            contract S is SmartContract {
                int immutable count;
                constructor(int _count) { count = _count; }
                function inspect() public {
                    int count = 5;
                    require(count > 0);
                }
            }
            """;
        ContractNode c = SolParser.parse(src, "S.runar.sol");
        MethodNode inspect = c.methods().get(0);
        ExpressionStatement requireStmt = (ExpressionStatement) inspect.body().get(1);
        CallExpr assertCall = (CallExpr) requireStmt.expression();
        BinaryExpr cmp = (BinaryExpr) assertCall.args().get(0);
        // local 'count' must NOT be rewritten to this.count
        assertInstanceOf(Identifier.class, cmp.left());
        assertEquals("count", ((Identifier) cmp.left()).name());
    }

    // -----------------------------------------------------------------
    // Hex byte string literal
    // -----------------------------------------------------------------

    @Test
    void parsesHexLiteralAsByteString() throws SolParser.ParseException {
        String src = """
            contract H is SmartContract {
                bytes immutable magic;
                constructor(bytes _magic) { magic = _magic; }
                function check() public {
                    require(magic == 0xdeadbeef);
                }
            }
            """;
        ContractNode c = SolParser.parse(src, "H.runar.sol");
        ExpressionStatement stmt = (ExpressionStatement) c.methods().get(0).body().get(0);
        CallExpr assertCall = (CallExpr) stmt.expression();
        BinaryExpr cmp = (BinaryExpr) assertCall.args().get(0);
        assertInstanceOf(runar.compiler.ir.ast.ByteStringLiteral.class, cmp.right());
        assertEquals("deadbeef", ((runar.compiler.ir.ast.ByteStringLiteral) cmp.right()).value());
    }

    // -----------------------------------------------------------------
    // Conformance fixtures
    // -----------------------------------------------------------------

    @Test
    void parsesConformanceStatefulCounterFixture() throws Exception {
        Path fixture = Path.of(
            System.getProperty("user.dir"),
            "..", "..",
            "conformance", "tests", "stateful-counter", "stateful-counter.runar.sol"
        );
        if (!Files.exists(fixture)) {
            // Worktree layouts differ; fall back to walking up to repo root.
            fixture = Path.of(
                System.getProperty("user.dir"),
                "..", "..", "..", "..",
                "conformance", "tests", "stateful-counter", "stateful-counter.runar.sol"
            );
        }
        if (!Files.exists(fixture)) {
            // Skip — fixture not found in this layout.
            return;
        }
        String src = Files.readString(fixture);
        ContractNode c = SolParser.parse(src, "stateful-counter.runar.sol");
        assertEquals("Counter", c.name());
        assertEquals(ParentClass.STATEFUL_SMART_CONTRACT, c.parentClass());
        assertFalse(c.methods().isEmpty(), "Counter should have at least one method");
    }

    // -----------------------------------------------------------------
    // Malformed inputs
    // -----------------------------------------------------------------

    @Test
    void rejectsSourceMissingContractKeyword() {
        String src = "pragma runar ^0.1.0; class Bad is SmartContract { }";
        SolParser.ParseException e = assertThrows(SolParser.ParseException.class,
            () -> SolParser.parse(src, "Bad.runar.sol")
        );
        assertTrue(e.getMessage().contains("contract"),
            "expected error mentioning 'contract' keyword, got: " + e.getMessage());
    }

    @Test
    void rejectsUnknownParentClass() {
        String src = "contract Bad is Frobulator { }";
        SolParser.ParseException e = assertThrows(SolParser.ParseException.class,
            () -> SolParser.parse(src, "Bad.runar.sol")
        );
        assertTrue(e.getMessage().contains("Frobulator"));
    }

    @Test
    void reportsErrorForMissingSemicolon() {
        // Missing ; after property declaration triggers the recovery path
        // and the parser collects an error rather than crashing.
        String src = """
            contract Bad is SmartContract {
                int immutable x
                constructor(int _x) { x = _x; }
            }
            """;
        // The Python reference treats this as a parse error reported via
        // diagnostics. Our Java port surfaces collected errors via the
        // checked ParseException — assert one is thrown.
        assertThrows(SolParser.ParseException.class,
            () -> SolParser.parse(src, "Bad.runar.sol")
        );
    }
}
