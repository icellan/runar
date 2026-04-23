package runar.compiler.frontend;

import org.junit.jupiter.api.Test;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.Identifier;
import runar.compiler.ir.ast.MemberExpr;
import runar.compiler.ir.ast.ParentClass;
import runar.compiler.ir.ast.PrimitiveType;
import runar.compiler.ir.ast.PrimitiveTypeName;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.Visibility;

import static org.junit.jupiter.api.Assertions.*;

class JavaParserTest {

    private static final String P2PKH_SOURCE = """
        package runar.examples.p2pkh;

        import runar.lang.SmartContract;
        import runar.lang.annotations.Public;
        import runar.lang.annotations.Readonly;
        import runar.lang.types.Addr;
        import runar.lang.types.PubKey;
        import runar.lang.types.Sig;
        import static runar.lang.Builtins.assertThat;
        import static runar.lang.Builtins.checkSig;
        import static runar.lang.Builtins.hash160;

        class P2PKH extends SmartContract {
            @Readonly Addr pubKeyHash;

            P2PKH(Addr pubKeyHash) {
                super(pubKeyHash);
                this.pubKeyHash = pubKeyHash;
            }

            @Public
            void unlock(Sig sig, PubKey pubKey) {
                assertThat(hash160(pubKey).equals(pubKeyHash));
                assertThat(checkSig(sig, pubKey));
            }
        }
        """;

    @Test
    void parsesP2pkhIntoExpectedContractShape() {
        ContractNode c = JavaParser.parse(P2PKH_SOURCE, "P2PKH.runar.java");
        assertEquals("P2PKH", c.name());
        assertEquals(ParentClass.SMART_CONTRACT, c.parentClass());
        assertEquals("P2PKH.runar.java", c.sourceFile());
        assertEquals(1, c.properties().size());
        var pkh = c.properties().get(0);
        assertEquals("pubKeyHash", pkh.name());
        assertTrue(pkh.readonly());
        assertEquals(new PrimitiveType(PrimitiveTypeName.ADDR), pkh.type());
        assertNull(pkh.initializer());
    }

    @Test
    void parsesConstructorWithSuperAndThisAssignment() {
        ContractNode c = JavaParser.parse(P2PKH_SOURCE, "P2PKH.runar.java");
        var ctor = c.constructor();
        assertEquals("constructor", ctor.name());
        assertEquals(1, ctor.params().size());
        assertEquals("pubKeyHash", ctor.params().get(0).name());

        assertEquals(2, ctor.body().size());
        // super(pubKeyHash)
        var superStmt = (ExpressionStatement) ctor.body().get(0);
        var superCall = (CallExpr) superStmt.expression();
        assertEquals("super", ((Identifier) superCall.callee()).name());
        assertEquals(1, superCall.args().size());
        assertEquals("pubKeyHash", ((Identifier) superCall.args().get(0)).name());

        // this.pubKeyHash = pubKeyHash
        var assignStmt = (AssignmentStatement) ctor.body().get(1);
        assertEquals("pubKeyHash", ((PropertyAccessExpr) assignStmt.target()).property());
        assertEquals("pubKeyHash", ((Identifier) assignStmt.value()).name());
    }

    @Test
    void parsesUnlockMethodWithStaticImportedCalls() {
        ContractNode c = JavaParser.parse(P2PKH_SOURCE, "P2PKH.runar.java");
        assertEquals(1, c.methods().size());
        var unlock = c.methods().get(0);
        assertEquals("unlock", unlock.name());
        assertEquals(Visibility.PUBLIC, unlock.visibility());
        assertEquals(2, unlock.params().size());
        assertEquals(new PrimitiveType(PrimitiveTypeName.SIG), unlock.params().get(0).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.PUB_KEY), unlock.params().get(1).type());

        assertEquals(2, unlock.body().size());

        // assertThat(hash160(pubKey).equals(pubKeyHash))
        var firstAssert = (ExpressionStatement) unlock.body().get(0);
        var firstCall = (CallExpr) firstAssert.expression();
        assertEquals("assertThat", ((Identifier) firstCall.callee()).name());
        assertEquals(1, firstCall.args().size());

        var equalsCall = (CallExpr) firstCall.args().get(0);
        var equalsCallee = (MemberExpr) equalsCall.callee();
        assertEquals("equals", equalsCallee.property());
        var hash160Call = (CallExpr) equalsCallee.object();
        assertEquals("hash160", ((Identifier) hash160Call.callee()).name());
    }

    @Test
    void rejectsContractWithoutExtendsClause() {
        String src = "class Bad { @Readonly Addr pkh; }";
        JavaParser.ParseException e = assertThrows(JavaParser.ParseException.class,
            () -> JavaParser.parse(src, "Bad.runar.java")
        );
        assertTrue(e.getMessage().contains("must extend"));
    }

    @Test
    void rejectsContractExtendingUnknownBaseClass() {
        String src = "class Bad extends Frobulator { }";
        JavaParser.ParseException e = assertThrows(JavaParser.ParseException.class,
            () -> JavaParser.parse(src, "Bad.runar.java")
        );
        assertTrue(e.getMessage().contains("Frobulator"));
    }

    @Test
    void acceptsStatefulSmartContract() {
        String src = """
            class Counter extends StatefulSmartContract {
                Bigint count;
                Counter(Bigint count) {
                    super(count);
                    this.count = count;
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Counter.runar.java");
        assertEquals(ParentClass.STATEFUL_SMART_CONTRACT, c.parentClass());
        assertEquals(1, c.properties().size());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT), c.properties().get(0).type());
        // count is not @Readonly so it becomes mutable state.
        assertFalse(c.properties().get(0).readonly());
    }

    @Test
    void parsesPropertyInitializer() {
        String src = """
            class Counter extends StatefulSmartContract {
                Bigint count = BigInteger.ZERO;
                @Readonly PubKey owner;
                Counter(PubKey owner) { super(owner); this.owner = owner; }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Counter.runar.java");
        assertEquals(2, c.properties().size());
        var count = c.properties().stream().filter(p -> p.name().equals("count")).findFirst().orElseThrow();
        assertNotNull(count.initializer(), "count should carry its initializer");
    }

    @Test
    void parsesBigIntegerValueOfAsLiteral() {
        String src = """
            class C extends SmartContract {
                @Readonly Bigint threshold;
                @Public void check(Bigint x) {
                    assertThat(x == BigInteger.valueOf(7));
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "C.runar.java");
        var check = c.methods().get(0);
        var stmt = (ExpressionStatement) check.body().get(0);
        var assertCall = (CallExpr) stmt.expression();
        var cmp = (BinaryExpr) assertCall.args().get(0);
        assertEquals(Expression.BinaryOp.EQ, cmp.op());
        // LHS: identifier x
        assertEquals("x", ((Identifier) cmp.left()).name());
        // RHS: BigIntLiteral(7) — should not be a CallExpr
        assertInstanceOf(runar.compiler.ir.ast.BigIntLiteral.class, cmp.right());
    }

    @Test
    void parsesByteStringFromHexAsLiteral() {
        String src = """
            class C extends SmartContract {
                @Readonly ByteString magic;
                @Public void check() {
                    assertThat(magic.equals(ByteString.fromHex("deadbeef")));
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "C.runar.java");
        var stmt = (ExpressionStatement) c.methods().get(0).body().get(0);
        var assertCall = (CallExpr) stmt.expression();
        var equalsCall = (CallExpr) assertCall.args().get(0);
        var magicEqualsArg = equalsCall.args().get(0);
        assertInstanceOf(runar.compiler.ir.ast.ByteStringLiteral.class, magicEqualsArg);
        var lit = (runar.compiler.ir.ast.ByteStringLiteral) magicEqualsArg;
        assertEquals("deadbeef", lit.value());
    }

    @Test
    void rejectsMultipleConstructors() {
        String src = """
            class Bad extends SmartContract {
                @Readonly Addr a;
                Bad() { super(); }
                Bad(Addr a) { super(a); this.a = a; }
            }
            """;
        JavaParser.ParseException e = assertThrows(JavaParser.ParseException.class,
            () -> JavaParser.parse(src, "Bad.runar.java")
        );
        assertTrue(e.getMessage().contains("more than one constructor"));
    }

    @Test
    void reportsJavacSyntaxErrors() {
        String src = "class Bad extends SmartContract { @Readonly Addr a }"; // missing semicolon
        JavaParser.ParseException e = assertThrows(JavaParser.ParseException.class,
            () -> JavaParser.parse(src, "Bad.runar.java")
        );
        assertTrue(e.getMessage().contains("javac reported errors"));
    }
}
