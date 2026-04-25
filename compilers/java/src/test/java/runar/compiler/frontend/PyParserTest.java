package runar.compiler.frontend;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
import runar.compiler.ir.ast.MemberExpr;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.ParentClass;
import runar.compiler.ir.ast.PrimitiveType;
import runar.compiler.ir.ast.PrimitiveTypeName;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.PropertyNode;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.TernaryExpr;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;

import static org.junit.jupiter.api.Assertions.*;

class PyParserTest {

    // -----------------------------------------------------------------
    // Conformance fixture: basic-p2pkh.runar.py
    // -----------------------------------------------------------------

    @Test
    void parsesConformanceP2pkhFixture() throws Exception {
        Path fixture = Paths.get("..", "..", "conformance", "tests", "basic-p2pkh", "basic-p2pkh.runar.py")
            .toAbsolutePath().normalize();
        if (!Files.exists(fixture)) {
            // Worktree placement may differ; skip if fixture isn't where we
            // expect rather than failing the whole suite.
            return;
        }
        String src = Files.readString(fixture);
        ContractNode c = PyParser.parse(src, "basic-p2pkh.runar.py");
        assertEquals("P2PKH", c.name());
        assertEquals(ParentClass.SMART_CONTRACT, c.parentClass());
        // pub_key_hash → pubKeyHash via snake→camel transform.
        assertEquals(1, c.properties().size());
        assertEquals("pubKeyHash", c.properties().get(0).name());
        assertEquals(new PrimitiveType(PrimitiveTypeName.ADDR), c.properties().get(0).type());
        assertTrue(c.properties().get(0).readonly(),
            "stateless SmartContract properties are forced readonly");

        assertEquals("constructor", c.constructor().name());
        assertEquals(1, c.constructor().params().size());
        assertEquals("pubKeyHash", c.constructor().params().get(0).name());

        assertEquals(1, c.methods().size());
        MethodNode unlock = c.methods().get(0);
        assertEquals("unlock", unlock.name());
        assertEquals(Visibility.PUBLIC, unlock.visibility());
        assertEquals(2, unlock.params().size());
        assertEquals("sig", unlock.params().get(0).name());
        assertEquals("pubKey", unlock.params().get(1).name());
    }

    // -----------------------------------------------------------------
    // Inline P2PKH source
    // -----------------------------------------------------------------

    private static final String P2PKH = """
        from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig

        class P2PKH(SmartContract):
            pub_key_hash: Addr

            def __init__(self, pub_key_hash: Addr):
                super().__init__(pub_key_hash)
                self.pub_key_hash = pub_key_hash

            @public
            def unlock(self, sig: Sig, pub_key: PubKey):
                assert_(hash160(pub_key) == self.pub_key_hash)
                assert_(check_sig(sig, pub_key))
        """;

    @Test
    void parsesInlineP2pkhContractShape() throws Exception {
        ContractNode c = PyParser.parse(P2PKH, "P2PKH.runar.py");
        assertEquals("P2PKH", c.name());
        assertEquals(ParentClass.SMART_CONTRACT, c.parentClass());
        assertEquals(1, c.properties().size());
        PropertyNode prop = c.properties().get(0);
        assertEquals("pubKeyHash", prop.name());
        assertEquals(new PrimitiveType(PrimitiveTypeName.ADDR), prop.type());
        assertTrue(prop.readonly());
        assertNull(prop.initializer());
    }

    @Test
    void rewritesSuperCallInConstructor() throws Exception {
        ContractNode c = PyParser.parse(P2PKH, "P2PKH.runar.py");
        MethodNode ctor = c.constructor();
        assertEquals("constructor", ctor.name());
        assertEquals(Visibility.PUBLIC, ctor.visibility());
        assertEquals(1, ctor.params().size());
        assertEquals("pubKeyHash", ctor.params().get(0).name());

        // Body: super(pubKeyHash); self.pub_key_hash = pub_key_hash
        assertTrue(ctor.body().size() >= 2);
        ExpressionStatement first = (ExpressionStatement) ctor.body().get(0);
        CallExpr superCall = (CallExpr) first.expression();
        assertEquals("super", ((Identifier) superCall.callee()).name());
        assertEquals(1, superCall.args().size());
        assertEquals("pubKeyHash", ((Identifier) superCall.args().get(0)).name());

        // The assignment of self.pub_key_hash = pub_key_hash should appear
        // as an assignment to a property access.
        AssignmentStatement assign = (AssignmentStatement) ctor.body().get(1);
        assertEquals("pubKeyHash", ((PropertyAccessExpr) assign.target()).property());
        assertEquals("pubKeyHash", ((Identifier) assign.value()).name());
    }

    @Test
    void parsesUnlockMethodAndConvertsBuiltins() throws Exception {
        ContractNode c = PyParser.parse(P2PKH, "P2PKH.runar.py");
        assertEquals(1, c.methods().size());
        MethodNode unlock = c.methods().get(0);
        assertEquals("unlock", unlock.name());
        assertEquals(Visibility.PUBLIC, unlock.visibility());
        assertEquals(2, unlock.params().size());
        assertEquals(new PrimitiveType(PrimitiveTypeName.SIG), unlock.params().get(0).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.PUB_KEY), unlock.params().get(1).type());
        assertEquals(2, unlock.body().size());

        // First: assert_(hash160(pub_key) == self.pub_key_hash)
        ExpressionStatement firstAssert = (ExpressionStatement) unlock.body().get(0);
        CallExpr callA = (CallExpr) firstAssert.expression();
        assertEquals("assert", ((Identifier) callA.callee()).name());
        BinaryExpr cmp = (BinaryExpr) callA.args().get(0);
        assertEquals(Expression.BinaryOp.EQ, cmp.op());
        // hash160(pub_key) — name preserved (already a special-name key).
        CallExpr h160 = (CallExpr) cmp.left();
        assertEquals("hash160", ((Identifier) h160.callee()).name());
        // Single arg: pub_key → pubKey via snake→camel.
        assertEquals("pubKey", ((Identifier) h160.args().get(0)).name());
        // Right side: self.pub_key_hash → PropertyAccess(pubKeyHash)
        assertEquals("pubKeyHash", ((PropertyAccessExpr) cmp.right()).property());

        // Second: assert_(check_sig(sig, pub_key)) — check_sig → checkSig
        ExpressionStatement secondAssert = (ExpressionStatement) unlock.body().get(1);
        CallExpr callB = (CallExpr) secondAssert.expression();
        assertEquals("assert", ((Identifier) callB.callee()).name());
        CallExpr checkSig = (CallExpr) callB.args().get(0);
        assertEquals("checkSig", ((Identifier) checkSig.callee()).name());
    }

    // -----------------------------------------------------------------
    // Stateful counter
    // -----------------------------------------------------------------

    private static final String COUNTER = """
        from runar import StatefulSmartContract, public, assert_, Readonly, Bigint

        class Counter(StatefulSmartContract):
            count: Bigint
            owner_hash: Readonly[Bigint] = 7

            def __init__(self, count: Bigint, owner_hash: Bigint):
                super().__init__(count, owner_hash)
                self.count = count
                self.owner_hash = owner_hash

            @public
            def increment(self, delta: Bigint):
                assert_(delta > 0)
                self.count = self.count + delta
        """;

    @Test
    void parsesStatefulCounter() throws Exception {
        ContractNode c = PyParser.parse(COUNTER, "Counter.runar.py");
        assertEquals(ParentClass.STATEFUL_SMART_CONTRACT, c.parentClass());
        assertEquals(2, c.properties().size());

        PropertyNode count = c.properties().get(0);
        assertEquals("count", count.name());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT), count.type());
        assertFalse(count.readonly(),
            "stateful properties without Readonly[] are mutable state");
        assertNull(count.initializer());

        PropertyNode owner = c.properties().get(1);
        assertEquals("ownerHash", owner.name());
        assertTrue(owner.readonly(),
            "Readonly[Bigint] should mark the property readonly");
        assertNotNull(owner.initializer());
        assertInstanceOf(BigIntLiteral.class, owner.initializer());
        assertEquals(BigInteger.valueOf(7), ((BigIntLiteral) owner.initializer()).value());

        // Method body: assert + assignment.
        MethodNode increment = c.methods().get(0);
        assertEquals("increment", increment.name());
        assertEquals(Visibility.PUBLIC, increment.visibility());
        // delta: Bigint
        assertEquals("delta", increment.params().get(0).name());
        assertEquals(2, increment.body().size());
        // 2nd statement: self.count = self.count + delta → assignment
        AssignmentStatement assign = (AssignmentStatement) increment.body().get(1);
        assertEquals("count", ((PropertyAccessExpr) assign.target()).property());
        BinaryExpr rhs = (BinaryExpr) assign.value();
        assertEquals(Expression.BinaryOp.ADD, rhs.op());
        assertEquals("count", ((PropertyAccessExpr) rhs.left()).property());
        assertEquals("delta", ((Identifier) rhs.right()).name());
    }

    // -----------------------------------------------------------------
    // snake → camel conversion edge cases
    // -----------------------------------------------------------------

    @Test
    void snakeToCamelEdgeCases() {
        // Special-name table.
        assertEquals("checkSig", PyParser.pyConvertName("check_sig"));
        assertEquals("verifySLHDSA_SHA2_128f", PyParser.pyConvertName("verify_slh_dsa_sha2_128f"));
        // Plain snake_case.
        assertEquals("pubKeyHash", PyParser.pyConvertName("pub_key_hash"));
        // Single-letter chunk.
        assertEquals("aB", PyParser.pyConvertName("a_b"));
        // No underscores.
        assertEquals("pubKey", PyParser.pyConvertName("pubKey"));
        // Leading single underscore stripped.
        assertEquals("helper", PyParser.pyConvertName("_helper"));
        // Dunder names: __init__ is in SPECIAL_NAMES → "constructor".
        assertEquals("constructor", PyParser.pyConvertName("__init__"));
        // Other dunders fall through unchanged.
        assertEquals("__call__", PyParser.pyConvertName("__call__"));
    }

    // -----------------------------------------------------------------
    // Control-flow shapes
    // -----------------------------------------------------------------

    @Test
    void parsesIfElifElse() throws Exception {
        String src = """
            from runar import SmartContract, public, assert_, Bigint

            class C(SmartContract):
                v: Bigint

                def __init__(self, v: Bigint):
                    super().__init__(v)
                    self.v = v

                @public
                def check(self, x: Bigint):
                    if x == 1:
                        assert_(True)
                    elif x == 2:
                        assert_(True)
                    else:
                        assert_(False)
            """;
        ContractNode c = PyParser.parse(src, "C.runar.py");
        MethodNode check = c.methods().get(0);
        IfStatement outer = (IfStatement) check.body().get(0);
        assertNotNull(outer.elseBody());
        assertEquals(1, outer.elseBody().size());
        IfStatement elif = (IfStatement) outer.elseBody().get(0);
        // elif's else should be the final else clause.
        assertNotNull(elif.elseBody());
        assertEquals(1, elif.elseBody().size());
    }

    @Test
    void parsesForRangeIntoCStyleFor() throws Exception {
        String src = """
            from runar import SmartContract, public, Bigint

            class C(SmartContract):
                v: Bigint

                def __init__(self, v: Bigint):
                    super().__init__(v)
                    self.v = v

                @public
                def loop(self):
                    sum: Bigint = 0
                    for i in range(10):
                        sum = sum + i
            """;
        ContractNode c = PyParser.parse(src, "C.runar.py");
        MethodNode loop = c.methods().get(0);
        // body[0]: sum: Bigint = 0
        VariableDeclStatement decl = (VariableDeclStatement) loop.body().get(0);
        assertEquals("sum", decl.name());
        // body[1]: for i in range(10) ...
        ForStatement fs = (ForStatement) loop.body().get(1);
        assertEquals("i", fs.init().name());
        // init = 0
        assertEquals(BigInteger.ZERO, ((BigIntLiteral) fs.init().init()).value());
        // condition: i < 10
        BinaryExpr cond = (BinaryExpr) fs.condition();
        assertEquals(Expression.BinaryOp.LT, cond.op());
        assertEquals("i", ((Identifier) cond.left()).name());
        assertEquals(BigInteger.TEN, ((BigIntLiteral) cond.right()).value());
    }

    // -----------------------------------------------------------------
    // Type annotation handling
    // -----------------------------------------------------------------

    @Test
    void parsesFixedArrayType() throws Exception {
        String src = """
            from runar import SmartContract, public, Bigint

            class C(SmartContract):
                xs: FixedArray[Bigint, 4]

                def __init__(self, xs: FixedArray[Bigint, 4]):
                    super().__init__(xs)
                    self.xs = xs
            """;
        ContractNode c = PyParser.parse(src, "C.runar.py");
        FixedArrayType fa = (FixedArrayType) c.properties().get(0).type();
        assertEquals(4, fa.length());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT), fa.element());
    }

    @Test
    void mapsCommonAliasesToPrimitives() throws Exception {
        String src = """
            from runar import SmartContract, public, Bigint, Bool, ByteString

            class C(SmartContract):
                a: int
                b: bool
                c: bytes
                d: Sha256Digest

                def __init__(self, a: int, b: bool, c: bytes, d: Sha256Digest):
                    super().__init__(a, b, c, d)
                    self.a = a
                    self.b = b
                    self.c = c
                    self.d = d
            """;
        ContractNode c = PyParser.parse(src, "C.runar.py");
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT), c.properties().get(0).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BOOLEAN), c.properties().get(1).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BYTE_STRING), c.properties().get(2).type());
        // Sha256Digest is aliased to Sha256.
        assertEquals(new PrimitiveType(PrimitiveTypeName.SHA_256), c.properties().get(3).type());
    }

    @Test
    void unknownTypeBecomesCustomType() throws Exception {
        String src = """
            from runar import SmartContract

            class C(SmartContract):
                weird: MyOpaque

                def __init__(self, weird: MyOpaque):
                    super().__init__(weird)
                    self.weird = weird
            """;
        ContractNode c = PyParser.parse(src, "C.runar.py");
        assertEquals(new CustomType("MyOpaque"), c.properties().get(0).type());
    }

    // -----------------------------------------------------------------
    // Literals
    // -----------------------------------------------------------------

    @Test
    void parsesByteStringLiteralFromBytesPrefix() throws Exception {
        String src = """
            from runar import SmartContract, public, ByteString

            class C(SmartContract):
                magic: ByteString = b'\\xde\\xad'

                def __init__(self):
                    super().__init__()
            """;
        ContractNode c = PyParser.parse(src, "C.runar.py");
        ByteStringLiteral bsl = (ByteStringLiteral) c.properties().get(0).initializer();
        assertEquals("dead", bsl.value());
    }

    @Test
    void parsesByteStringFromHexCall() throws Exception {
        String src = """
            from runar import SmartContract, public, ByteString

            class C(SmartContract):
                magic: ByteString = bytes.fromhex("cafebabe")

                def __init__(self):
                    super().__init__()
            """;
        ContractNode c = PyParser.parse(src, "C.runar.py");
        ByteStringLiteral bsl = (ByteStringLiteral) c.properties().get(0).initializer();
        assertEquals("cafebabe", bsl.value());
    }

    @Test
    void parsesBoolAndNumericLiterals() throws Exception {
        String src = """
            from runar import SmartContract, public, Bool, Bigint

            class C(SmartContract):
                t: Bool = True
                hex_const: Bigint = 0xff
                under: Bigint = 1_000

                def __init__(self):
                    super().__init__()
            """;
        ContractNode c = PyParser.parse(src, "C.runar.py");
        assertEquals(new BoolLiteral(true), c.properties().get(0).initializer());
        assertEquals(BigInteger.valueOf(255),
            ((BigIntLiteral) c.properties().get(1).initializer()).value());
        assertEquals(BigInteger.valueOf(1000),
            ((BigIntLiteral) c.properties().get(2).initializer()).value());
    }

    // -----------------------------------------------------------------
    // Malformed input
    // -----------------------------------------------------------------

    @Test
    void rejectsUnknownParentClass() {
        String src = """
            class C(Frobulator):
                pass
            """;
        assertThrows(PyParser.ParseException.class,
            () -> PyParser.parse(src, "C.runar.py"));
    }

    @Test
    void rejectsMissingClassKeyword() {
        String src = "x = 1\n";
        assertThrows(PyParser.ParseException.class,
            () -> PyParser.parse(src, "C.runar.py"));
    }

    @Test
    void rejectsBreakAndContinueInsideMethod() {
        String src = """
            from runar import SmartContract, public, Bigint

            class C(SmartContract):
                v: Bigint

                def __init__(self, v: Bigint):
                    super().__init__(v)
                    self.v = v

                @public
                def loop(self):
                    for i in range(10):
                        break
            """;
        assertThrows(PyParser.ParseException.class,
            () -> PyParser.parse(src, "C.runar.py"));
    }
}
