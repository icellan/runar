package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BigIntLiteral;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.FixedArrayType;
import runar.compiler.ir.ast.IfStatement;
import runar.compiler.ir.ast.IndexAccessExpr;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.PrimitiveType;
import runar.compiler.ir.ast.PrimitiveTypeName;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.PropertyNode;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.SourceLocation;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.TernaryExpr;
import runar.compiler.ir.ast.TypeNode;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;

/**
 * Tests for {@link ExpandFixedArrays}.
 *
 * <p>Mirrors the behaviour validated by:
 * <ul>
 *   <li>{@code packages/runar-compiler/src/passes/__tests__/03b-expand-fixed-arrays.test.ts}</li>
 *   <li>{@code compilers/python/tests/test_expand_fixed_arrays.py}</li>
 * </ul>
 *
 * <p>Many cases construct the contract AST directly rather than going
 * through {@link JavaParser} because the Java parser emits FixedArray
 * length only via integer literals in type-args, which is awkward for
 * exotic shapes. Direct AST construction keeps the test focused on the
 * pass behaviour itself.
 */
class ExpandFixedArraysTest {

    private static final SourceLocation LOC = new SourceLocation("test.runar.java", 1, 1);

    // ------------------------------------------------------------------
    // AST construction helpers
    // ------------------------------------------------------------------

    private static PropertyNode prop(String name, TypeNode type, boolean readonly) {
        return new PropertyNode(name, type, readonly, null, LOC, null);
    }

    private static PropertyNode propWithInit(
        String name, TypeNode type, boolean readonly, Expression init
    ) {
        return new PropertyNode(name, type, readonly, init, LOC, null);
    }

    private static ContractNode contractWith(List<PropertyNode> props, MethodNode... methods) {
        MethodNode ctor = new MethodNode(
            "constructor", List.of(), List.of(), Visibility.PUBLIC, LOC
        );
        return new ContractNode(
            "Test",
            runar.compiler.ir.ast.ParentClass.STATEFUL_SMART_CONTRACT,
            props,
            ctor,
            List.of(methods),
            "test.runar.java"
        );
    }

    private static MethodNode method(String name, List<Statement> body) {
        return new MethodNode(name, List.of(), body, Visibility.PUBLIC, LOC);
    }

    private static FixedArrayType bigintArr(int length) {
        return new FixedArrayType(new PrimitiveType(PrimitiveTypeName.BIGINT), length);
    }

    // ------------------------------------------------------------------
    // 1. Simple expansion
    // ------------------------------------------------------------------

    @Test
    void expandsSimpleBigIntArrayIntoScalarSiblings() {
        // FixedArray<bigint, 3> nums  →  nums__0, nums__1, nums__2
        ContractNode in = contractWith(List.of(
            prop("nums", bigintArr(3), false)
        ));

        ContractNode out = ExpandFixedArrays.run(in);

        List<PropertyNode> props = out.properties();
        assertEquals(3, props.size(), "expected 3 scalar siblings");
        assertEquals("nums__0", props.get(0).name());
        assertEquals("nums__1", props.get(1).name());
        assertEquals("nums__2", props.get(2).name());

        for (PropertyNode p : props) {
            assertTrue(p.type() instanceof PrimitiveType);
            assertEquals(PrimitiveTypeName.BIGINT, ((PrimitiveType) p.type()).name());
            assertFalse(p.readonly());
            assertNotNull(p.syntheticArrayChain());
            assertEquals(1, p.syntheticArrayChain().size());
            assertEquals("nums", p.syntheticArrayChain().get(0).base());
            assertEquals(3, p.syntheticArrayChain().get(0).length());
        }
        assertEquals(0, props.get(0).syntheticArrayChain().get(0).index());
        assertEquals(1, props.get(1).syntheticArrayChain().get(0).index());
        assertEquals(2, props.get(2).syntheticArrayChain().get(0).index());
    }

    @Test
    void preservesNonArrayPropertiesUnchanged() {
        PropertyNode count = prop("count", new PrimitiveType(PrimitiveTypeName.BIGINT), false);
        ContractNode in = contractWith(List.of(
            count,
            prop("vec", bigintArr(2), false)
        ));

        ContractNode out = ExpandFixedArrays.run(in);

        // count (unchanged) + 2 vec scalars
        assertEquals(3, out.properties().size());
        assertEquals("count", out.properties().get(0).name());
        assertNull(out.properties().get(0).syntheticArrayChain());
        assertEquals("vec__0", out.properties().get(1).name());
        assertEquals("vec__1", out.properties().get(2).name());
    }

    @Test
    void noFixedArrayPropertiesReturnsContractUnchanged() {
        ContractNode in = contractWith(List.of(
            prop("a", new PrimitiveType(PrimitiveTypeName.BIGINT), false),
            prop("b", new PrimitiveType(PrimitiveTypeName.BOOLEAN), false)
        ));
        ContractNode out = ExpandFixedArrays.run(in);
        // No FixedArray properties — the pass should return the same instance.
        assertSame(in, out);
    }

    // ------------------------------------------------------------------
    // 2. Initializer distribution ("constructor splat" style)
    // ------------------------------------------------------------------

    @Test
    void distributesArrayLiteralInitializerToEachSlot() {
        // FixedArray<bigint, 3> nums = [10, 20, 30];
        Expression init = new runar.compiler.ir.ast.ArrayLiteralExpr(List.of(
            new BigIntLiteral(BigInteger.valueOf(10)),
            new BigIntLiteral(BigInteger.valueOf(20)),
            new BigIntLiteral(BigInteger.valueOf(30))
        ));
        ContractNode in = contractWith(List.of(
            propWithInit("nums", bigintArr(3), true, init)
        ));

        ContractNode out = ExpandFixedArrays.run(in);

        assertEquals(3, out.properties().size());
        for (int i = 0; i < 3; i++) {
            PropertyNode p = out.properties().get(i);
            assertTrue(p.readonly(), "readonly preserved on slot " + i);
            assertNotNull(p.initializer(), "slot " + i + " must have initializer");
            assertTrue(p.initializer() instanceof BigIntLiteral);
            BigInteger expected = BigInteger.valueOf(10L * (i + 1));
            assertEquals(expected, ((BigIntLiteral) p.initializer()).value());
        }
    }

    @Test
    void rejectsInitializerLengthMismatch() {
        Expression init = new runar.compiler.ir.ast.ArrayLiteralExpr(List.of(
            new BigIntLiteral(BigInteger.ONE),
            new BigIntLiteral(BigInteger.TWO)
        ));
        ContractNode in = contractWith(List.of(
            propWithInit("nums", bigintArr(3), true, init)
        ));

        ExpandFixedArrays.Result result = ExpandFixedArrays.runCollecting(in);
        assertFalse(result.errors().isEmpty(), "expected length-mismatch error");
        assertTrue(
            result.errors().get(0).contains("Initializer length 2"),
            "got: " + result.errors().get(0)
        );
    }

    @Test
    void rejectsNonArrayLiteralInitializer() {
        ContractNode in = contractWith(List.of(
            propWithInit("nums", bigintArr(3), true, new BigIntLiteral(BigInteger.ONE))
        ));

        ExpandFixedArrays.Result result = ExpandFixedArrays.runCollecting(in);
        assertFalse(result.errors().isEmpty());
        assertTrue(
            result.errors().get(0).contains("array literal initializer"),
            "got: " + result.errors().get(0)
        );
    }

    // ------------------------------------------------------------------
    // 3. Index access rewriting
    // ------------------------------------------------------------------

    @Test
    void literalIndexReadRewritesToDirectPropertyAccess() {
        // method body: { return this.nums[1]; }  →  return this.nums__1;
        IndexAccessExpr access = new IndexAccessExpr(
            new PropertyAccessExpr("nums"),
            new BigIntLiteral(BigInteger.ONE)
        );
        ReturnStatement ret = new ReturnStatement(access, LOC);
        MethodNode m = method("getOne", List.of(ret));

        ContractNode in = contractWith(List.of(prop("nums", bigintArr(3), true)), m);

        ContractNode out = ExpandFixedArrays.run(in);

        ReturnStatement outRet = (ReturnStatement) out.methods().get(0).body().get(0);
        assertTrue(outRet.value() instanceof PropertyAccessExpr,
            "expected property_access, got " + outRet.value().getClass().getSimpleName());
        assertEquals("nums__1", ((PropertyAccessExpr) outRet.value()).property());
    }

    @Test
    void literalIndexWriteRewritesToDirectAssignment() {
        // this.nums[2] = 42n;  →  this.nums__2 = 42n;
        AssignmentStatement assign = new AssignmentStatement(
            new IndexAccessExpr(
                new PropertyAccessExpr("nums"),
                new BigIntLiteral(BigInteger.TWO)
            ),
            new BigIntLiteral(BigInteger.valueOf(42)),
            LOC
        );
        MethodNode m = method("set", List.of(assign));

        ContractNode in = contractWith(List.of(prop("nums", bigintArr(3), false)), m);
        ContractNode out = ExpandFixedArrays.run(in);

        AssignmentStatement outAssign = (AssignmentStatement) out.methods().get(0).body().get(0);
        assertTrue(outAssign.target() instanceof PropertyAccessExpr);
        assertEquals("nums__2", ((PropertyAccessExpr) outAssign.target()).property());
        assertTrue(outAssign.value() instanceof BigIntLiteral);
    }

    @Test
    void literalIndexOutOfRangeIsCompileError() {
        IndexAccessExpr access = new IndexAccessExpr(
            new PropertyAccessExpr("nums"),
            new BigIntLiteral(BigInteger.valueOf(7))
        );
        MethodNode m = method("oob", List.of(new ReturnStatement(access, LOC)));

        ContractNode in = contractWith(List.of(prop("nums", bigintArr(3), true)), m);

        ExpandFixedArrays.Result result = ExpandFixedArrays.runCollecting(in);
        assertFalse(result.errors().isEmpty(), "expected OOB error");
        assertTrue(
            result.errors().get(0).contains("Index 7 is out of range"),
            "got: " + result.errors().get(0)
        );
    }

    // ------------------------------------------------------------------
    // 4. Runtime (non-constant) index — read & write
    // ------------------------------------------------------------------

    @Test
    void runtimeIndexReadInExpressionContextProducesTernaryChain() {
        // return this.nums[i];  with `i` an identifier (impure not, but
        // not a literal) → ternary dispatch chain.
        ReturnStatement ret = new ReturnStatement(
            new IndexAccessExpr(
                new PropertyAccessExpr("nums"),
                new runar.compiler.ir.ast.Identifier("i")
            ),
            LOC
        );
        MethodNode m = method("read", List.of(ret));

        ContractNode in = contractWith(List.of(prop("nums", bigintArr(3), true)), m);
        ContractNode out = ExpandFixedArrays.run(in);

        ReturnStatement outRet = (ReturnStatement) out.methods().get(0).body().get(0);
        assertTrue(outRet.value() instanceof TernaryExpr,
            "expected ternary, got " + outRet.value().getClass().getSimpleName());

        // Walk the chain: should be (i===0)?nums__0:((i===1)?nums__1:nums__2)
        TernaryExpr top = (TernaryExpr) outRet.value();
        assertEquals("nums__0", ((PropertyAccessExpr) top.consequent()).property());
        TernaryExpr inner = (TernaryExpr) top.alternate();
        assertEquals("nums__1", ((PropertyAccessExpr) inner.consequent()).property());
        // Terminal alternate is the last slot (no bounds check, by design).
        assertEquals("nums__2", ((PropertyAccessExpr) inner.alternate()).property());
    }

    @Test
    void runtimeIndexWriteEmitsIfChainEndingInAssertFalse() {
        AssignmentStatement assign = new AssignmentStatement(
            new IndexAccessExpr(
                new PropertyAccessExpr("nums"),
                new runar.compiler.ir.ast.Identifier("i")
            ),
            new BigIntLiteral(BigInteger.valueOf(99)),
            LOC
        );
        MethodNode m = method("write", List.of(assign));

        ContractNode in = contractWith(List.of(prop("nums", bigintArr(3), false)), m);
        ContractNode out = ExpandFixedArrays.run(in);

        // The body should now be one IfStatement (the dispatch chain).
        List<Statement> body = out.methods().get(0).body();
        assertEquals(1, body.size());
        assertTrue(body.get(0) instanceof IfStatement);

        // Walk to the bottom of the chain — the terminal `else` must be
        // an `assert(false)` ExpressionStatement.
        IfStatement top = (IfStatement) body.get(0);
        Statement deepest = drillToTerminal(top);
        assertTrue(deepest instanceof ExpressionStatement,
            "deepest else must be an expression_statement, got " + deepest.getClass().getSimpleName());
        ExpressionStatement es = (ExpressionStatement) deepest;
        assertTrue(es.expression() instanceof runar.compiler.ir.ast.CallExpr);
        runar.compiler.ir.ast.CallExpr ce = (runar.compiler.ir.ast.CallExpr) es.expression();
        assertTrue(ce.callee() instanceof runar.compiler.ir.ast.Identifier);
        assertEquals("assert", ((runar.compiler.ir.ast.Identifier) ce.callee()).name());
        assertEquals(1, ce.args().size());
        assertTrue(ce.args().get(0) instanceof runar.compiler.ir.ast.BoolLiteral);
        assertFalse(((runar.compiler.ir.ast.BoolLiteral) ce.args().get(0)).value());
    }

    private static Statement drillToTerminal(IfStatement node) {
        IfStatement cursor = node;
        while (true) {
            List<Statement> elseBody = cursor.elseBody();
            if (elseBody == null || elseBody.isEmpty()) return cursor;
            Statement next = elseBody.get(0);
            if (next instanceof IfStatement nestedIf) {
                cursor = nestedIf;
            } else {
                return next;
            }
        }
    }

    // ------------------------------------------------------------------
    // 5. Statement-form runtime read (variable_decl init)
    // ------------------------------------------------------------------

    @Test
    void variableDeclWithRuntimeIndexReadEmitsFallbackPlusIfChain() {
        // let v = this.nums[i];  →  let v = nums__2; if (i===0) v = nums__0;
        //                                          else if (i===1) v = nums__1;
        VariableDeclStatement decl = new VariableDeclStatement(
            "v", null,
            new IndexAccessExpr(
                new PropertyAccessExpr("nums"),
                new runar.compiler.ir.ast.Identifier("i")
            ),
            LOC
        );
        MethodNode m = method("read", List.of(decl));

        ContractNode in = contractWith(List.of(prop("nums", bigintArr(3), true)), m);
        ContractNode out = ExpandFixedArrays.run(in);

        List<Statement> body = out.methods().get(0).body();
        // At least the new variable_decl + an if-chain follow it.
        assertTrue(body.size() >= 2, "expected fallback decl + if chain, got " + body.size());
        assertTrue(body.get(0) instanceof VariableDeclStatement);
        VariableDeclStatement newDecl = (VariableDeclStatement) body.get(0);
        // Fallback initialised from the last slot.
        assertTrue(newDecl.init() instanceof PropertyAccessExpr);
        assertEquals("nums__2", ((PropertyAccessExpr) newDecl.init()).property());
        assertTrue(body.get(1) instanceof IfStatement);
    }

    // ------------------------------------------------------------------
    // 6. Empty / single-element edge cases
    // ------------------------------------------------------------------

    @Test
    void rejectsZeroLengthArray() {
        ContractNode in = contractWith(List.of(
            prop("nums", bigintArr(0), true)
        ));

        ExpandFixedArrays.Result result = ExpandFixedArrays.runCollecting(in);
        assertFalse(result.errors().isEmpty());
        assertTrue(
            result.errors().get(0).contains("positive integer"),
            "got: " + result.errors().get(0)
        );
    }

    @Test
    void singleElementArrayExpandsToOneSlot() {
        ContractNode in = contractWith(List.of(
            prop("solo", bigintArr(1), true)
        ));
        ContractNode out = ExpandFixedArrays.run(in);
        assertEquals(1, out.properties().size());
        assertEquals("solo__0", out.properties().get(0).name());
    }

    // ------------------------------------------------------------------
    // 7. Nested FixedArray<FixedArray<bigint, 2>, 2>
    // ------------------------------------------------------------------

    @Test
    void nestedArrayProducesDoubleUnderscoreLeaves() {
        FixedArrayType inner = bigintArr(2);
        FixedArrayType outer = new FixedArrayType(inner, 2);
        ContractNode in = contractWith(List.of(prop("grid", outer, true)));

        ContractNode out = ExpandFixedArrays.run(in);

        assertEquals(4, out.properties().size());
        assertEquals("grid__0__0", out.properties().get(0).name());
        assertEquals("grid__0__1", out.properties().get(1).name());
        assertEquals("grid__1__0", out.properties().get(2).name());
        assertEquals("grid__1__1", out.properties().get(3).name());

        // Each leaf carries a 2-entry synthetic chain.
        for (PropertyNode p : out.properties()) {
            assertEquals(2, p.syntheticArrayChain().size());
        }
    }

    @Test
    void nestedLiteralChainResolvesInOneHop() {
        // return this.grid[0][1];  →  return this.grid__0__1;
        ReturnStatement ret = new ReturnStatement(
            new IndexAccessExpr(
                new IndexAccessExpr(
                    new PropertyAccessExpr("grid"),
                    new BigIntLiteral(BigInteger.ZERO)
                ),
                new BigIntLiteral(BigInteger.ONE)
            ),
            LOC
        );
        MethodNode m = method("get01", List.of(ret));

        FixedArrayType inner = bigintArr(2);
        FixedArrayType outer = new FixedArrayType(inner, 2);
        ContractNode in = contractWith(List.of(prop("grid", outer, true)), m);

        ContractNode out = ExpandFixedArrays.run(in);

        ReturnStatement outRet = (ReturnStatement) out.methods().get(0).body().get(0);
        assertTrue(outRet.value() instanceof PropertyAccessExpr);
        assertEquals("grid__0__1", ((PropertyAccessExpr) outRet.value()).property());
    }

    @Test
    void runtimeIndexOnNestedArrayIsRejected() {
        // return this.grid[i];  — runtime index on an outer array whose
        // slots are themselves arrays — is not supported.
        ReturnStatement ret = new ReturnStatement(
            new IndexAccessExpr(
                new PropertyAccessExpr("grid"),
                new runar.compiler.ir.ast.Identifier("i")
            ),
            LOC
        );
        MethodNode m = method("read", List.of(ret));

        FixedArrayType inner = bigintArr(2);
        FixedArrayType outer = new FixedArrayType(inner, 2);
        ContractNode in = contractWith(List.of(prop("grid", outer, true)), m);

        ExpandFixedArrays.Result result = ExpandFixedArrays.runCollecting(in);
        assertFalse(result.errors().isEmpty(), "expected nested-runtime error");
        assertTrue(
            result.errors().get(0).contains("nested FixedArray"),
            "got: " + result.errors().get(0)
        );
    }

    // ------------------------------------------------------------------
    // 8. Idempotence — running the pass twice gives the same result
    // ------------------------------------------------------------------

    @Test
    void runningPassTwiceProducesEquivalentResult() {
        // After expansion the contract has only scalar (non-FixedArray)
        // properties, so a second pass must be a no-op (returns the same
        // instance because there's nothing to expand).
        ContractNode in = contractWith(List.of(
            prop("nums", bigintArr(2), false)
        ));
        ContractNode once = ExpandFixedArrays.run(in);
        ContractNode twice = ExpandFixedArrays.run(once);
        assertSame(once, twice, "second invocation must be a no-op");
    }
}
