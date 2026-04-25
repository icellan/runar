package runar.compiler.frontend;

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
import runar.compiler.ir.ast.MemberExpr;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.ParentClass;
import runar.compiler.ir.ast.PrimitiveType;
import runar.compiler.ir.ast.PrimitiveTypeName;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.PropertyNode;
import runar.compiler.ir.ast.Visibility;

import static org.junit.jupiter.api.Assertions.*;

class MoveParserTest {

    private static final String P2PKH_SOURCE = """
        // P2PKH — Pay-to-Public-Key-Hash
        module P2PKH {
            use runar::types::{Addr, PubKey, Sig};
            use runar::crypto::{hash160, check_sig};

            resource struct P2PKH {
                pub_key_hash: Addr,
            }

            public fun unlock(contract: &P2PKH, sig: Sig, pub_key: PubKey) {
                assert!(hash160(pub_key) == contract.pub_key_hash, 0);
                assert!(check_sig(sig, pub_key), 0);
            }
        }
        """;

    private static final String COUNTER_SOURCE = """
        // Stateful counter
        module Counter {
            resource struct Counter {
                count: bigint,
            }

            public fun increment(contract: &mut Counter) {
                contract.count = contract.count + 1;
            }

            public fun decrement(contract: &mut Counter) {
                assert!(contract.count > 0, 0);
                contract.count = contract.count - 1;
            }
        }
        """;

    // -----------------------------------------------------------------
    // P2PKH fixture
    // -----------------------------------------------------------------

    @Test
    void parsesP2pkhIntoExpectedContractShape() throws Exception {
        ContractNode c = MoveParser.parse(P2PKH_SOURCE, "P2PKH.runar.move");
        assertEquals("P2PKH", c.name());
        assertEquals("P2PKH.runar.move", c.sourceFile());
        // resource struct → StatefulSmartContract even with all-readonly fields.
        assertEquals(ParentClass.STATEFUL_SMART_CONTRACT, c.parentClass());

        assertEquals(1, c.properties().size());
        PropertyNode pkh = c.properties().get(0);
        assertEquals("pubKeyHash", pkh.name());
        assertEquals(new PrimitiveType(PrimitiveTypeName.ADDR), pkh.type());
        assertTrue(pkh.readonly(), "non-&mut field should remain readonly");
        assertNull(pkh.initializer());
    }

    @Test
    void p2pkhConstructorIsSyntheticSuperPlusAssignment() throws Exception {
        ContractNode c = MoveParser.parse(P2PKH_SOURCE, "P2PKH.runar.move");
        MethodNode ctor = c.constructor();
        assertEquals("constructor", ctor.name());
        assertEquals(Visibility.PUBLIC, ctor.visibility());
        assertEquals(1, ctor.params().size());
        assertEquals("pubKeyHash", ctor.params().get(0).name());

        assertEquals(2, ctor.body().size());
        ExpressionStatement superStmt = (ExpressionStatement) ctor.body().get(0);
        CallExpr superCall = (CallExpr) superStmt.expression();
        assertEquals("super", ((Identifier) superCall.callee()).name());
        assertEquals(1, superCall.args().size());
        assertEquals("pubKeyHash", ((Identifier) superCall.args().get(0)).name());

        AssignmentStatement assign = (AssignmentStatement) ctor.body().get(1);
        assertEquals("pubKeyHash", ((PropertyAccessExpr) assign.target()).property());
        assertEquals("pubKeyHash", ((Identifier) assign.value()).name());
    }

    @Test
    void p2pkhUnlockMethodLowersAssertsAndContractAccess() throws Exception {
        ContractNode c = MoveParser.parse(P2PKH_SOURCE, "P2PKH.runar.move");
        assertEquals(1, c.methods().size());
        MethodNode unlock = c.methods().get(0);
        assertEquals("unlock", unlock.name());
        assertEquals(Visibility.PUBLIC, unlock.visibility());
        // `contract: &P2PKH` is filtered, leaving sig and pub_key (camelCased).
        assertEquals(2, unlock.params().size());
        assertEquals("sig", unlock.params().get(0).name());
        assertEquals("pubKey", unlock.params().get(1).name());
        assertEquals(new PrimitiveType(PrimitiveTypeName.SIG),     unlock.params().get(0).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.PUB_KEY), unlock.params().get(1).type());

        assertEquals(2, unlock.body().size());

        // assert!(hash160(pub_key) == contract.pub_key_hash, 0)
        //   → assert(hash160(pubKey) === this.pubKeyHash)
        ExpressionStatement firstAssert = (ExpressionStatement) unlock.body().get(0);
        CallExpr assertCall = (CallExpr) firstAssert.expression();
        assertEquals("assert", ((Identifier) assertCall.callee()).name());
        assertEquals(1, assertCall.args().size());
        BinaryExpr cmp = (BinaryExpr) assertCall.args().get(0);
        assertEquals(Expression.BinaryOp.EQ, cmp.op());
        CallExpr hashCall = (CallExpr) cmp.left();
        assertEquals("hash160", ((Identifier) hashCall.callee()).name());
        assertEquals("pubKey", ((Identifier) hashCall.args().get(0)).name());
        // RHS: this.pubKeyHash → PropertyAccessExpr
        assertEquals("pubKeyHash", ((PropertyAccessExpr) cmp.right()).property());

        // assert!(check_sig(sig, pub_key), 0) → assert(checkSig(sig, pubKey))
        ExpressionStatement secondAssert = (ExpressionStatement) unlock.body().get(1);
        CallExpr secondCall = (CallExpr) secondAssert.expression();
        CallExpr checkSigCall = (CallExpr) secondCall.args().get(0);
        assertEquals("checkSig", ((Identifier) checkSigCall.callee()).name());
        assertEquals("sig",    ((Identifier) checkSigCall.args().get(0)).name());
        assertEquals("pubKey", ((Identifier) checkSigCall.args().get(1)).name());
    }

    // -----------------------------------------------------------------
    // Counter fixture
    // -----------------------------------------------------------------

    @Test
    void parsesStatefulCounter() throws Exception {
        ContractNode c = MoveParser.parse(COUNTER_SOURCE, "Counter.runar.move");
        assertEquals("Counter", c.name());
        assertEquals(ParentClass.STATEFUL_SMART_CONTRACT, c.parentClass());

        assertEquals(1, c.properties().size());
        PropertyNode count = c.properties().get(0);
        assertEquals("count", count.name());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT), count.type());

        assertEquals(2, c.methods().size());
        assertEquals("increment", c.methods().get(0).name());
        assertEquals("decrement", c.methods().get(1).name());

        // increment: contract.count = contract.count + 1 → this.count = this.count + 1
        var incBody = c.methods().get(0).body();
        assertEquals(1, incBody.size());
        AssignmentStatement assign = (AssignmentStatement) incBody.get(0);
        assertEquals("count", ((PropertyAccessExpr) assign.target()).property());
        BinaryExpr add = (BinaryExpr) assign.value();
        assertEquals(Expression.BinaryOp.ADD, add.op());
        assertEquals("count", ((PropertyAccessExpr) add.left()).property());
        assertInstanceOf(BigIntLiteral.class, add.right());
    }

    // -----------------------------------------------------------------
    // Type mapping
    // -----------------------------------------------------------------

    @Test
    void mapsMoveTypesToRunarPrimitives() throws Exception {
        String src = """
            module Demo {
                struct Demo {
                    a: u64,
                    b: u128,
                    c: u256,
                    d: bool,
                    e: PubKey,
                    f: vector,
                }
            }
            """;
        ContractNode c = MoveParser.parse(src, "Demo.runar.move");
        assertEquals(6, c.properties().size());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT),      c.properties().get(0).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT),      c.properties().get(1).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT),      c.properties().get(2).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BOOLEAN),     c.properties().get(3).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.PUB_KEY),     c.properties().get(4).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BYTE_STRING), c.properties().get(5).type());
        // Plain `struct` (no resource, no &mut) → SmartContract.
        assertEquals(ParentClass.SMART_CONTRACT, c.parentClass());
    }

    @Test
    void detectsMutableFieldAsStateful() throws Exception {
        String src = """
            module M {
                struct M {
                    counter: &mut u64,
                }
            }
            """;
        ContractNode c = MoveParser.parse(src, "M.runar.move");
        assertEquals(1, c.properties().size());
        assertFalse(c.properties().get(0).readonly());
        assertEquals(ParentClass.STATEFUL_SMART_CONTRACT, c.parentClass());
    }

    // -----------------------------------------------------------------
    // Builtin name mapping
    // -----------------------------------------------------------------

    @Test
    void mapsSnakeCaseBuiltinsToCamelCase() throws Exception {
        String src = """
            module Demo {
                public fun go(contract: &Demo) {
                    let a = hash_160(contract);
                    let b = check_preimage(contract);
                    let c = num_2_bin(contract, a);
                }
            }
            """;
        ContractNode c = MoveParser.parse(src, "Demo.runar.move");
        var body = c.methods().get(0).body();
        assertEquals(3, body.size());
        var v0 = (runar.compiler.ir.ast.VariableDeclStatement) body.get(0);
        assertEquals("hash160",       ((Identifier) ((CallExpr) v0.init()).callee()).name());
        var v1 = (runar.compiler.ir.ast.VariableDeclStatement) body.get(1);
        assertEquals("checkPreimage", ((Identifier) ((CallExpr) v1.init()).callee()).name());
        var v2 = (runar.compiler.ir.ast.VariableDeclStatement) body.get(2);
        assertEquals("num2bin",       ((Identifier) ((CallExpr) v2.init()).callee()).name());
    }

    // -----------------------------------------------------------------
    // Control flow
    // -----------------------------------------------------------------

    @Test
    void parsesIfElseAndWhileFoldedAsFor() throws Exception {
        String src = """
            module Demo {
                public fun go(contract: &Demo, x: u64) {
                    let mut i = 0;
                    while (i < 10) {
                        if (i == 5) {
                            i = i + 1;
                        } else {
                            i = i + 2;
                        };
                        i = i + 1;
                    };
                }
            }
            """;
        ContractNode c = MoveParser.parse(src, "Demo.runar.move");
        var body = c.methods().get(0).body();
        // The while-as-for fold collapses the let+while into a single
        // ForStatement when the trailing body statement is `i = i + ...`.
        assertEquals(1, body.size());
        ForStatement loop = (ForStatement) body.get(0);
        assertEquals("i", loop.init().name());
        // Inside the for body, the if/else is preserved.
        IfStatement iff = (IfStatement) loop.body().get(0);
        assertEquals(Expression.BinaryOp.EQ, ((BinaryExpr) iff.condition()).op());
        assertNotNull(iff.elseBody());
    }

    // -----------------------------------------------------------------
    // assert_eq! lowering
    // -----------------------------------------------------------------

    @Test
    void lowersAssertEqMacroToBinaryEq() throws Exception {
        String src = """
            module Demo {
                public fun go(contract: &Demo, a: u64, b: u64) {
                    assert_eq!(a, b, 0);
                }
            }
            """;
        ContractNode c = MoveParser.parse(src, "Demo.runar.move");
        var stmt = (ExpressionStatement) c.methods().get(0).body().get(0);
        var call = (CallExpr) stmt.expression();
        assertEquals("assert", ((Identifier) call.callee()).name());
        var cmp = (BinaryExpr) call.args().get(0);
        assertEquals(Expression.BinaryOp.EQ, cmp.op());
        assertEquals("a", ((Identifier) cmp.left()).name());
        assertEquals("b", ((Identifier) cmp.right()).name());
    }

    // -----------------------------------------------------------------
    // Visibility
    // -----------------------------------------------------------------

    @Test
    void privateFunDefaultsToPrivateVisibility() throws Exception {
        String src = """
            module Demo {
                fun helper(contract: &Demo) {
                    let _x = 1;
                }
                public fun go(contract: &Demo) {
                    let _y = 2;
                }
            }
            """;
        ContractNode c = MoveParser.parse(src, "Demo.runar.move");
        assertEquals(2, c.methods().size());
        assertEquals(Visibility.PRIVATE, c.methods().get(0).visibility());
        assertEquals(Visibility.PUBLIC,  c.methods().get(1).visibility());
    }

    // -----------------------------------------------------------------
    // Hex byte-string literals
    // -----------------------------------------------------------------

    @Test
    void parsesEvenDigitHexLiteralsAsByteStrings() throws Exception {
        String src = """
            module Demo {
                struct Demo {
                    magic: ByteString = 0xdeadbeef,
                }
            }
            """;
        ContractNode c = MoveParser.parse(src, "Demo.runar.move");
        assertEquals(1, c.properties().size());
        var init = (runar.compiler.ir.ast.ByteStringLiteral) c.properties().get(0).initializer();
        assertEquals("deadbeef", init.value());
    }

    // -----------------------------------------------------------------
    // Member-call routing
    // -----------------------------------------------------------------

    @Test
    void routesContractMethodCallThroughThisReceiver() throws Exception {
        String src = """
            module Demo {
                public fun go(contract: &Demo) {
                    contract.helper();
                }
                fun helper(contract: &Demo) {
                    let _x = 1;
                }
            }
            """;
        ContractNode c = MoveParser.parse(src, "Demo.runar.move");
        var stmt = (ExpressionStatement) c.methods().get(0).body().get(0);
        var call = (CallExpr) stmt.expression();
        var callee = (MemberExpr) call.callee();
        assertEquals("helper", callee.property());
        assertEquals("this", ((Identifier) callee.object()).name());
    }

    // -----------------------------------------------------------------
    // Error handling
    // -----------------------------------------------------------------

    @Test
    void rejectsSourceWithoutModuleKeyword() {
        String src = """
            // not a module
            struct Foo { x: u64 }
            """;
        MoveParser.ParseException e = assertThrows(MoveParser.ParseException.class,
            () -> MoveParser.parse(src, "Foo.runar.move")
        );
        assertTrue(e.getMessage().contains("module"), "unexpected message: " + e.getMessage());
    }

    @Test
    void reportsMissingClosingBraceAsParseError() {
        String src = """
            module Bad {
                struct Bad { x: u64,
            """;
        // The recursive-descent parser surfaces lower-level token errors via
        // its accumulated error list, raised as a single ParseException.
        assertThrows(MoveParser.ParseException.class,
            () -> MoveParser.parse(src, "Bad.runar.move")
        );
    }
}
