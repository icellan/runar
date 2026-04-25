package runar.compiler.frontend;

import org.junit.jupiter.api.Test;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BigIntLiteral;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.CustomType;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.ForStatement;
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
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.Visibility;

import static org.junit.jupiter.api.Assertions.*;

class RbParserTest {

    private static final String P2PKH_SOURCE = """
        require 'runar'

        class P2PKH < Runar::SmartContract
          prop :pub_key_hash, Addr

          def initialize(pub_key_hash)
            super(pub_key_hash)
            @pub_key_hash = pub_key_hash
          end

          runar_public sig: Sig, pub_key: PubKey
          def unlock(sig, pub_key)
            assert hash160(pub_key) == @pub_key_hash
            assert check_sig(sig, pub_key)
          end
        end
        """;

    private static final String COUNTER_SOURCE = """
        require 'runar'

        class Counter < Runar::StatefulSmartContract
          prop :count, Bigint

          def initialize(count)
            super(count)
            @count = count
          end

          runar_public
          def increment
            @count += 1
          end

          runar_public
          def decrement
            assert @count > 0
            @count -= 1
          end
        end
        """;

    private static ContractNode parse(String src, String name) throws Exception {
        return RbParser.parse(src, name);
    }

    // ---------------------------------------------------------------
    // P2PKH (stateless)
    // ---------------------------------------------------------------

    @Test
    void parsesP2pkhContractShape() throws Exception {
        ContractNode c = parse(P2PKH_SOURCE, "P2PKH.runar.rb");
        assertEquals("P2PKH", c.name());
        assertEquals(ParentClass.SMART_CONTRACT, c.parentClass());
        assertEquals("P2PKH.runar.rb", c.sourceFile());
        assertEquals(1, c.properties().size());

        PropertyNode prop = c.properties().get(0);
        // snake_case → camelCase on property names
        assertEquals("pubKeyHash", prop.name());
        // Stateless contracts: every property is readonly.
        assertTrue(prop.readonly());
        assertEquals(new PrimitiveType(PrimitiveTypeName.ADDR), prop.type());
        assertNull(prop.initializer());
    }

    @Test
    void parsesP2pkhConstructor() throws Exception {
        ContractNode c = parse(P2PKH_SOURCE, "P2PKH.runar.rb");
        MethodNode ctor = c.constructor();
        assertEquals("constructor", ctor.name());
        assertEquals(Visibility.PUBLIC, ctor.visibility());
        assertEquals(1, ctor.params().size());
        assertEquals("pubKeyHash", ctor.params().get(0).name());
        // Constructor param type is back-filled from the matching prop.
        assertEquals(new PrimitiveType(PrimitiveTypeName.ADDR), ctor.params().get(0).type());

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
    void parsesP2pkhUnlockMethod() throws Exception {
        ContractNode c = parse(P2PKH_SOURCE, "P2PKH.runar.rb");
        assertEquals(1, c.methods().size());
        MethodNode unlock = c.methods().get(0);
        assertEquals("unlock", unlock.name());
        assertEquals(Visibility.PUBLIC, unlock.visibility());
        assertEquals(2, unlock.params().size());
        // snake_case (pub_key) → camelCase (pubKey)
        assertEquals("sig", unlock.params().get(0).name());
        assertEquals("pubKey", unlock.params().get(1).name());
        // Param types come from the runar_public DSL.
        assertEquals(new PrimitiveType(PrimitiveTypeName.SIG), unlock.params().get(0).type());
        assertEquals(new PrimitiveType(PrimitiveTypeName.PUB_KEY), unlock.params().get(1).type());

        assertEquals(2, unlock.body().size());

        // assert hash160(pub_key) == @pub_key_hash
        // → assert(hash160(pubKey) === this.pubKeyHash)
        ExpressionStatement first = (ExpressionStatement) unlock.body().get(0);
        CallExpr firstAssert = (CallExpr) first.expression();
        assertEquals("assert", ((Identifier) firstAssert.callee()).name());
        BinaryExpr cmp = (BinaryExpr) firstAssert.args().get(0);
        assertEquals(Expression.BinaryOp.EQ, cmp.op());
        CallExpr hash160 = (CallExpr) cmp.left();
        assertEquals("hash160", ((Identifier) hash160.callee()).name());
        assertEquals("pubKey", ((Identifier) hash160.args().get(0)).name());
        assertEquals("pubKeyHash", ((PropertyAccessExpr) cmp.right()).property());

        // assert check_sig(sig, pub_key) → assert(checkSig(sig, pubKey))
        ExpressionStatement second = (ExpressionStatement) unlock.body().get(1);
        CallExpr secondAssert = (CallExpr) second.expression();
        CallExpr checkSig = (CallExpr) secondAssert.args().get(0);
        // check_sig is mapped to checkSig via the special-name table.
        assertEquals("checkSig", ((Identifier) checkSig.callee()).name());
        assertEquals("sig", ((Identifier) checkSig.args().get(0)).name());
        assertEquals("pubKey", ((Identifier) checkSig.args().get(1)).name());
    }

    // ---------------------------------------------------------------
    // Counter (stateful) with compound assignment
    // ---------------------------------------------------------------

    @Test
    void parsesStatefulCounter() throws Exception {
        ContractNode c = parse(COUNTER_SOURCE, "Counter.runar.rb");
        assertEquals("Counter", c.name());
        assertEquals(ParentClass.STATEFUL_SMART_CONTRACT, c.parentClass());
        assertEquals(1, c.properties().size());
        PropertyNode count = c.properties().get(0);
        assertEquals("count", count.name());
        // Stateful contracts: properties are mutable unless explicitly readonly.
        assertFalse(count.readonly());
        assertEquals(new PrimitiveType(PrimitiveTypeName.BIGINT), count.type());
    }

    @Test
    void compoundAssignmentExpandsToBinaryExpr() throws Exception {
        ContractNode c = parse(COUNTER_SOURCE, "Counter.runar.rb");
        MethodNode increment = c.methods().stream()
            .filter(m -> m.name().equals("increment"))
            .findFirst().orElseThrow();
        assertEquals(Visibility.PUBLIC, increment.visibility());
        // @count += 1 → this.count = (this.count + 1)
        AssignmentStatement assign = (AssignmentStatement) increment.body().get(0);
        assertEquals("count", ((PropertyAccessExpr) assign.target()).property());
        BinaryExpr add = (BinaryExpr) assign.value();
        assertEquals(Expression.BinaryOp.ADD, add.op());
        assertEquals("count", ((PropertyAccessExpr) add.left()).property());
        assertEquals(java.math.BigInteger.ONE, ((BigIntLiteral) add.right()).value());
    }

    // ---------------------------------------------------------------
    // Auto-generated constructor
    // ---------------------------------------------------------------

    @Test
    void autoGeneratesConstructorWhenAbsent() throws Exception {
        String src = """
            require 'runar'
            class Auto < Runar::SmartContract
              prop :owner, PubKey
              prop :limit, Bigint

              runar_public
              def call
                assert true
              end
            end
            """;
        ContractNode c = parse(src, "Auto.runar.rb");
        MethodNode ctor = c.constructor();
        assertEquals("constructor", ctor.name());
        assertEquals(2, ctor.params().size());
        assertEquals("owner", ctor.params().get(0).name());
        assertEquals("limit", ctor.params().get(1).name());
        // body: super(owner, limit); this.owner = owner; this.limit = limit
        assertEquals(3, ctor.body().size());
        ExpressionStatement superStmt = (ExpressionStatement) ctor.body().get(0);
        CallExpr superCall = (CallExpr) superStmt.expression();
        assertEquals("super", ((Identifier) superCall.callee()).name());
        assertEquals(2, superCall.args().size());
    }

    // ---------------------------------------------------------------
    // For loop, if/elsif/else, unless
    // ---------------------------------------------------------------

    @Test
    void parsesForLoopWithExclusiveRange() throws Exception {
        String src = """
            require 'runar'
            class Loop < Runar::SmartContract
              prop :n, Bigint

              runar_public
              def go
                for i in 0...n do
                  assert i >= 0
                end
              end
            end
            """;
        ContractNode c = parse(src, "Loop.runar.rb");
        MethodNode go = c.methods().get(0);
        ForStatement fs = (ForStatement) go.body().get(0);
        assertEquals("i", fs.init().name());
        BinaryExpr cond = (BinaryExpr) fs.condition();
        // exclusive range → '<'
        assertEquals(Expression.BinaryOp.LT, cond.op());
        ExpressionStatement update = (ExpressionStatement) fs.update();
        IncrementExpr inc = (IncrementExpr) update.expression();
        assertFalse(inc.prefix());
        assertEquals(1, fs.body().size());
    }

    @Test
    void parsesIfElsifElse() throws Exception {
        String src = """
            require 'runar'
            class Branch < Runar::SmartContract
              prop :x, Bigint

              runar_public
              def go
                if @x > 10
                  assert true
                elsif @x > 5
                  assert true
                else
                  assert false
                end
              end
            end
            """;
        ContractNode c = parse(src, "Branch.runar.rb");
        MethodNode go = c.methods().get(0);
        IfStatement outer = (IfStatement) go.body().get(0);
        // outer cond: @x > 10
        BinaryExpr outerCond = (BinaryExpr) outer.condition();
        assertEquals(Expression.BinaryOp.GT, outerCond.op());
        // else-branch is a single nested IfStatement (the elsif arm).
        assertEquals(1, outer.elseBody().size());
        IfStatement elsif = (IfStatement) outer.elseBody().get(0);
        BinaryExpr elsifCond = (BinaryExpr) elsif.condition();
        assertEquals(Expression.BinaryOp.GT, elsifCond.op());
        assertEquals(1, elsif.elseBody().size());
    }

    @Test
    void parsesUnlessAsNegatedIf() throws Exception {
        String src = """
            require 'runar'
            class U < Runar::SmartContract
              prop :x, Bigint

              runar_public
              def go
                unless @x > 0
                  assert false
                end
              end
            end
            """;
        ContractNode c = parse(src, "U.runar.rb");
        IfStatement is = (IfStatement) c.methods().get(0).body().get(0);
        UnaryExpr neg = (UnaryExpr) is.condition();
        assertEquals(Expression.UnaryOp.NOT, neg.op());
    }

    // ---------------------------------------------------------------
    // Bare-call rewriting + private implicit return
    // ---------------------------------------------------------------

    @Test
    void rewritesBareCallToPrivateMethodAsThisCall() throws Exception {
        String src = """
            require 'runar'
            class C < Runar::SmartContract
              prop :a, Bigint

              runar_public
              def go
                assert helper(@a) > 0
              end

              def helper(x)
                x + 1
              end
            end
            """;
        ContractNode c = parse(src, "C.runar.rb");
        MethodNode go = c.methods().stream().filter(m -> m.name().equals("go")).findFirst().orElseThrow();
        ExpressionStatement stmt = (ExpressionStatement) go.body().get(0);
        CallExpr assertCall = (CallExpr) stmt.expression();
        BinaryExpr cmp = (BinaryExpr) assertCall.args().get(0);
        CallExpr helperCall = (CallExpr) cmp.left();
        // helper(...) was rewritten as this.helper(...) → callee is PropertyAccessExpr
        assertInstanceOf(PropertyAccessExpr.class, helperCall.callee());
        assertEquals("helper", ((PropertyAccessExpr) helperCall.callee()).property());

        // The private helper's last expression statement was promoted to a return.
        MethodNode helper = c.methods().stream().filter(m -> m.name().equals("helper")).findFirst().orElseThrow();
        assertEquals(Visibility.PRIVATE, helper.visibility());
        assertInstanceOf(ReturnStatement.class, helper.body().get(helper.body().size() - 1));
    }

    // ---------------------------------------------------------------
    // Special-name + passthrough mappings
    // ---------------------------------------------------------------

    @Test
    void mapsCheckSigAndAddOutputViaSpecialNames() throws Exception {
        String src = """
            require 'runar'
            class O < Runar::StatefulSmartContract
              prop :count, Bigint

              runar_public
              def go
                add_output(1000, @count)
              end
            end
            """;
        ContractNode c = parse(src, "O.runar.rb");
        MethodNode go = c.methods().get(0);
        ExpressionStatement stmt = (ExpressionStatement) go.body().get(0);
        CallExpr call = (CallExpr) stmt.expression();
        // add_output is an intrinsic → rewritten to this.addOutput(...)
        assertInstanceOf(PropertyAccessExpr.class, call.callee());
        assertEquals("addOutput", ((PropertyAccessExpr) call.callee()).property());
    }

    @Test
    void preservesEcConstantNameUnchanged() {
        // EC_P / EC_N / EC_G have uppercase letters after underscores so the
        // snake_case→camelCase regex must NOT touch them.
        assertEquals("EC_P", RbParser.snakeToCamel("EC_P"));
        assertEquals("EC_N", RbParser.snakeToCamel("EC_N"));
        // Mixed: lowercase after underscore *is* converted.
        assertEquals("pubKeyHash", RbParser.snakeToCamel("pub_key_hash"));
        // Leading underscore stripped, no capitalisation of first letter.
        assertEquals("requireOwner", RbParser.snakeToCamel("_require_owner"));
    }

    // ---------------------------------------------------------------
    // Malformed inputs
    // ---------------------------------------------------------------

    @Test
    void rejectsMissingClass() {
        String src = """
            require 'runar'
            # no class declaration here
            """;
        assertThrows(RbParser.ParseException.class, () -> parse(src, "Empty.runar.rb"));
    }

    @Test
    void rejectsUnknownParentClass() {
        String src = """
            require 'runar'
            class Bad < Runar::FrobulatorContract
              prop :a, Bigint
            end
            """;
        Exception e = assertThrows(RbParser.ParseException.class, () -> parse(src, "Bad.runar.rb"));
        assertTrue(e.getMessage().contains("FrobulatorContract"),
            "expected error to mention the unknown parent class, got: " + e.getMessage());
    }

    @Test
    void rejectsMalformedPropDeclaration() {
        // 'prop' without a leading symbol — should report an error.
        String src = """
            require 'runar'
            class Bad < Runar::SmartContract
              prop "not a symbol", Addr
            end
            """;
        assertThrows(RbParser.ParseException.class, () -> parse(src, "Bad.runar.rb"));
    }

    // ---------------------------------------------------------------
    // Property initializer (default: value)
    // ---------------------------------------------------------------

    @Test
    void parsesPropertyDefaultInitializer() throws Exception {
        String src = """
            require 'runar'
            class WithDefault < Runar::StatefulSmartContract
              prop :counter, Bigint, default: 0
              prop :owner, PubKey
            end
            """;
        ContractNode c = parse(src, "WithDefault.runar.rb");
        PropertyNode counter = c.properties().get(0);
        assertNotNull(counter.initializer(), "counter prop should carry its initializer");
        assertEquals(java.math.BigInteger.ZERO, ((BigIntLiteral) counter.initializer()).value());
        // Auto-generated constructor should exclude the prop with a default.
        MethodNode ctor = c.constructor();
        assertEquals(1, ctor.params().size());
        assertEquals("owner", ctor.params().get(0).name());
    }

    // ---------------------------------------------------------------
    // Readonly toggle on a stateful contract
    // ---------------------------------------------------------------

    @Test
    void readonlyKeywordOnStatefulPropMakesItReadonly() throws Exception {
        String src = """
            require 'runar'
            class Mixed < Runar::StatefulSmartContract
              prop :owner, PubKey, readonly: true
              prop :counter, Bigint
            end
            """;
        ContractNode c = parse(src, "Mixed.runar.rb");
        PropertyNode owner = c.properties().get(0);
        PropertyNode counter = c.properties().get(1);
        assertTrue(owner.readonly());
        assertFalse(counter.readonly());
    }

    // ---------------------------------------------------------------
    // Custom type fallback
    // ---------------------------------------------------------------

    @Test
    void unknownTypeNameBecomesCustomType() throws Exception {
        // Types not in the canonical primitive set fall back to CustomType.
        String src = """
            require 'runar'
            class C < Runar::SmartContract
              prop :owner, MyOwnType
            end
            """;
        ContractNode c = parse(src, "C.runar.rb");
        PropertyNode p = c.properties().get(0);
        assertInstanceOf(CustomType.class, p.type());
        assertEquals("MyOwnType", ((CustomType) p.type()).name());
    }

    // ---------------------------------------------------------------
    // Bare super clause (no Runar:: prefix)
    // ---------------------------------------------------------------

    @Test
    void acceptsBareSuperclassNameWithoutRunarPrefix() throws Exception {
        String src = """
            require 'runar'
            class Bare < SmartContract
              prop :x, Bigint
            end
            """;
        ContractNode c = parse(src, "Bare.runar.rb");
        assertEquals(ParentClass.SMART_CONTRACT, c.parentClass());
    }
}
