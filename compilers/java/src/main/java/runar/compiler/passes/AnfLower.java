package runar.compiler.passes;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import runar.compiler.ir.anf.AddDataOutput;
import runar.compiler.ir.anf.AddOutput;
import runar.compiler.ir.anf.AddRawOutput;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfProperty;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.ArrayLiteral;
import runar.compiler.ir.anf.Assert;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.anf.BinOp;
import runar.compiler.ir.anf.BoolConst;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.CheckPreimage;
import runar.compiler.ir.anf.ConstValue;
import runar.compiler.ir.anf.DeserializeState;
import runar.compiler.ir.anf.GetStateScript;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;
import runar.compiler.ir.anf.LoadProp;
import runar.compiler.ir.anf.Loop;
import runar.compiler.ir.anf.MethodCall;
import runar.compiler.ir.anf.UnaryOp;
import runar.compiler.ir.anf.UpdateProp;
import runar.compiler.ir.ast.ArrayLiteralExpr;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BigIntLiteral;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.BoolLiteral;
import runar.compiler.ir.ast.ByteStringLiteral;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.CustomType;
import runar.compiler.ir.ast.DecrementExpr;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.FixedArrayType;
import runar.compiler.ir.ast.ForStatement;
import runar.compiler.ir.ast.Identifier;
import runar.compiler.ir.ast.IfStatement;
import runar.compiler.ir.ast.IncrementExpr;
import runar.compiler.ir.ast.IndexAccessExpr;
import runar.compiler.ir.ast.MemberExpr;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.ParamNode;
import runar.compiler.ir.ast.ParentClass;
import runar.compiler.ir.ast.PrimitiveType;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.PropertyNode;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.TernaryExpr;
import runar.compiler.ir.ast.TypeNode;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;

/**
 * AST &rarr; ANF lowering for the Rúnar Java compiler.
 *
 * <p>Direct port of {@code compilers/python/runar_compiler/frontend/anf_lower.py}
 * and {@code packages/runar-compiler/src/passes/04-anf-lower.ts}. Every
 * expression is flattened into a sequence of let-bindings with fresh temp
 * names ({@code t0}, {@code t1}, &hellip;) scoped per method.
 *
 * <p>Byte-identical canonical JSON parity with the other compilers is the
 * conformance boundary for this pass.
 */
public final class AnfLower {

    private AnfLower() {}

    // ------------------------------------------------------------------
    // Byte-typed expression detection (mirrors Python _BYTE_TYPES / TS
    // BYTE_TYPES). Used to decide whether === / !== / + / &amp; / | / ^
    // bindings carry the {@code result_type: "bytes"} annotation.
    // ------------------------------------------------------------------

    private static final Set<String> BYTE_TYPES = Set.of(
        "ByteString", "PubKey", "Sig", "Sha256", "Ripemd160", "Addr",
        "SigHashPreimage", "RabinSig", "RabinPubKey",
        "Point", "P256Point", "P384Point"
    );

    private static final Set<String> BYTE_RETURNING_FUNCTIONS = Set.of(
        "sha256", "ripemd160", "hash160", "hash256",
        "cat", "substr", "num2bin", "reverseBytes", "left", "right",
        "int2str", "toByteString", "pack",
        "ecAdd", "ecMul", "ecMulGen", "ecNegate", "ecMakePoint", "ecEncodeCompressed",
        "blake3Compress", "blake3Hash",
        "p256Add", "p256Mul", "p256MulGen", "p256Negate", "p256EncodeCompressed",
        "p384Add", "p384Mul", "p384MulGen", "p384Negate", "p384EncodeCompressed"
    );

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /** Lower a (validated, type-checked) contract AST to ANF IR. */
    public static AnfProgram run(ContractNode contract) {
        List<AnfProperty> properties = lowerProperties(contract);
        List<AnfMethod> methods = lowerMethods(contract);

        // Post-pass: lift update_prop from if-else branches into flat
        // conditional assignments. Mirrors the TS reference compiler's
        // liftBranchUpdateProps. Prevents phantom stack entries in stack
        // lowering for position-dispatch patterns.
        List<AnfMethod> lifted = new ArrayList<>(methods.size());
        for (AnfMethod m : methods) {
            List<AnfBinding> newBody = liftBranchUpdateProps(m.body());
            lifted.add(new AnfMethod(m.name(), m.params(), newBody, m.isPublic()));
        }

        return new AnfProgram(contract.name(), properties, lifted);
    }

    // ------------------------------------------------------------------
    // Properties
    // ------------------------------------------------------------------

    private static List<AnfProperty> lowerProperties(ContractNode contract) {
        List<AnfProperty> out = new ArrayList<>(contract.properties().size());
        for (PropertyNode p : contract.properties()) {
            ConstValue init = p.initializer() != null ? extractLiteralValue(p.initializer()) : null;
            out.add(new AnfProperty(p.name(), typeToString(p.type()), p.readonly(), init));
        }
        return out;
    }

    private static ConstValue extractLiteralValue(Expression e) {
        if (e instanceof BigIntLiteral bi) return new BigIntConst(bi.value());
        if (e instanceof BoolLiteral b) return new BoolConst(b.value());
        if (e instanceof ByteStringLiteral bs) return new BytesConst(bs.value());
        if (e instanceof UnaryExpr u
            && u.op() == Expression.UnaryOp.NEG
            && u.operand() instanceof BigIntLiteral bil) {
            return new BigIntConst(bil.value().negate());
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Methods
    // ------------------------------------------------------------------

    private static List<AnfMethod> lowerMethods(ContractNode contract) {
        List<AnfMethod> out = new ArrayList<>();

        // Constructor
        if (contract.constructor() != null) {
            LowerCtx ctx = new LowerCtx(contract);
            ctx.setMethodParamTypes(contract.constructor().params());
            ctx.lowerStatements(contract.constructor().body());
            out.add(new AnfMethod(
                "constructor",
                lowerParams(contract.constructor().params()),
                ctx.bindings,
                false
            ));
        }

        // Methods
        for (MethodNode method : contract.methods()) {
            LowerCtx ctx = new LowerCtx(contract);
            ctx.setMethodParamTypes(method.params());

            boolean isStatefulPublic = contract.parentClass() == ParentClass.STATEFUL_SMART_CONTRACT
                && method.visibility() == Visibility.PUBLIC;

            if (isStatefulPublic) {
                boolean hasDataOutput = methodHasAddDataOutput(method);
                boolean hasAddOutput = methodHasAddOutput(method);
                boolean mutates = methodMutatesState(method, contract);
                boolean needsChange = mutates || hasAddOutput || hasDataOutput;
                boolean needsNewAmount = (mutates || hasDataOutput) && !hasAddOutput;

                if (needsChange) {
                    ctx.addParam("_changePKH");
                    ctx.addParam("_changeAmount");
                }
                if (needsNewAmount) {
                    ctx.addParam("_newAmount");
                }
                ctx.addParam("txPreimage");

                // checkPreimage(txPreimage) at the start
                String preimageRef = ctx.emit(new LoadParam("txPreimage"));
                String checkResult = ctx.emit(new CheckPreimage(preimageRef));
                ctx.emit(new Assert(checkResult));

                // Deserialize mutable state from the preimage's scriptCode
                boolean hasStateProp = false;
                for (PropertyNode p : contract.properties()) {
                    if (!p.readonly()) { hasStateProp = true; break; }
                }
                if (hasStateProp) {
                    String preimageRef3 = ctx.emit(new LoadParam("txPreimage"));
                    ctx.emit(new DeserializeState(preimageRef3));
                }

                // Developer's method body
                ctx.lowerStatements(method.body());

                // Continuation-hash construction
                List<String> addOutputRefs = ctx.addOutputRefs;
                List<String> addDataOutputRefs = ctx.addDataOutputRefs;
                if (!addOutputRefs.isEmpty() || !addDataOutputRefs.isEmpty() || mutates) {
                    String changePkhRef = ctx.emit(new LoadParam("_changePKH"));
                    String changeAmountRef = ctx.emit(new LoadParam("_changeAmount"));
                    String changeOutputRef = ctx.emit(new Call("buildChangeOutput", List.of(changePkhRef, changeAmountRef)));

                    if (!addOutputRefs.isEmpty()) {
                        String accumulated = addOutputRefs.get(0);
                        for (int i = 1; i < addOutputRefs.size(); i++) {
                            accumulated = ctx.emit(new Call("cat", List.of(accumulated, addOutputRefs.get(i))));
                        }
                        for (String dref : addDataOutputRefs) {
                            accumulated = ctx.emit(new Call("cat", List.of(accumulated, dref)));
                        }
                        accumulated = ctx.emit(new Call("cat", List.of(accumulated, changeOutputRef)));
                        String hashRef = ctx.emit(new Call("hash256", List.of(accumulated)));
                        String preimageRef2 = ctx.emit(new LoadParam("txPreimage"));
                        String outputHashRef = ctx.emit(new Call("extractOutputHash", List.of(preimageRef2)));
                        String eqRef = ctx.emit(new BinOp("===", hashRef, outputHashRef, "bytes"));
                        ctx.emit(new Assert(eqRef));
                    } else {
                        String stateScriptRef = ctx.emit(new GetStateScript());
                        String preimageRef2 = ctx.emit(new LoadParam("txPreimage"));
                        String newAmountRef = ctx.emit(new LoadParam("_newAmount"));
                        String contractOutputRef = ctx.emit(new Call("computeStateOutput", List.of(preimageRef2, stateScriptRef, newAmountRef)));
                        String accumulated = contractOutputRef;
                        for (String dref : addDataOutputRefs) {
                            accumulated = ctx.emit(new Call("cat", List.of(accumulated, dref)));
                        }
                        String allOutputs = ctx.emit(new Call("cat", List.of(accumulated, changeOutputRef)));
                        String hashRef = ctx.emit(new Call("hash256", List.of(allOutputs)));
                        String preimageRef4 = ctx.emit(new LoadParam("txPreimage"));
                        String outputHashRef = ctx.emit(new Call("extractOutputHash", List.of(preimageRef4)));
                        String eqRef = ctx.emit(new BinOp("===", hashRef, outputHashRef, "bytes"));
                        ctx.emit(new Assert(eqRef));
                    }
                }

                List<AnfParam> augmented = new ArrayList<>(lowerParams(method.params()));
                if (needsChange) {
                    augmented.add(new AnfParam("_changePKH", "Ripemd160"));
                    augmented.add(new AnfParam("_changeAmount", "bigint"));
                }
                if (needsNewAmount) {
                    augmented.add(new AnfParam("_newAmount", "bigint"));
                }
                augmented.add(new AnfParam("txPreimage", "SigHashPreimage"));

                out.add(new AnfMethod(method.name(), augmented, ctx.bindings, true));
            } else {
                ctx.lowerStatements(method.body());
                out.add(new AnfMethod(
                    method.name(),
                    lowerParams(method.params()),
                    ctx.bindings,
                    method.visibility() == Visibility.PUBLIC
                ));
            }
        }

        return out;
    }

    private static List<AnfParam> lowerParams(List<ParamNode> params) {
        List<AnfParam> out = new ArrayList<>(params.size());
        for (ParamNode p : params) {
            out.add(new AnfParam(p.name(), typeToString(p.type())));
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Lowering context
    // ------------------------------------------------------------------

    private static final class LowerCtx {
        final List<AnfBinding> bindings = new ArrayList<>();
        int counter = 0;
        final ContractNode contract;
        final Set<String> localNames = new HashSet<>();
        final Set<String> paramNames = new HashSet<>();
        /** Type table for the CURRENT method's parameters. Method-scoped
         *  (not contract-scoped) so a parameter named `x` in one method
         *  doesn't bleed into byte-typed analysis of a different method
         *  that uses `x` as a local. See issue #34. */
        final Map<String, String> methodParamTypes = new HashMap<>();
        final List<String> addOutputRefs = new ArrayList<>();
        final List<String> addDataOutputRefs = new ArrayList<>();
        final Map<String, String> localAliases = new HashMap<>();
        final Set<String> localByteVars = new HashSet<>();

        LowerCtx(ContractNode contract) {
            this.contract = contract;
        }

        /** Populate the method-scoped param-type table for the current method
         *  (or constructor). See issue #34. */
        void setMethodParamTypes(List<ParamNode> params) {
            methodParamTypes.clear();
            for (ParamNode p : params) {
                methodParamTypes.put(p.name(), typeToString(p.type()));
            }
        }

        String freshTemp() {
            String name = "t" + counter++;
            return name;
        }

        String emit(AnfValue value) {
            String name = freshTemp();
            bindings.add(new AnfBinding(name, value, null));
            return name;
        }

        void emitNamed(String name, AnfValue value) {
            bindings.add(new AnfBinding(name, value, null));
        }

        void addLocal(String name) { localNames.add(name); }
        boolean isLocal(String name) { return localNames.contains(name); }
        void addParam(String name) { paramNames.add(name); }
        boolean isParam(String name) { return paramNames.contains(name); }

        void setLocalAlias(String local, String ref) {
            localAliases.put(local, ref);
        }

        String getLocalAlias(String local) {
            return localAliases.get(local);
        }

        boolean isProperty(String name) {
            for (PropertyNode p : contract.properties()) {
                if (p.name().equals(name)) return true;
            }
            return false;
        }

        boolean isPrivateMethod(String name) {
            for (MethodNode m : contract.methods()) {
                if (m.name().equals(name) && !m.name().equals("constructor")
                    && m.visibility() != Visibility.PUBLIC) {
                    return true;
                }
            }
            return false;
        }

        String getParamType(String name) {
            // Method-scoped lookup. See issue #34.
            return methodParamTypes.get(name);
        }

        String getPropertyType(String name) {
            for (PropertyNode p : contract.properties()) {
                if (p.name().equals(name)) return typeToString(p.type());
            }
            return null;
        }

        LowerCtx subContext() {
            LowerCtx sub = new LowerCtx(contract);
            sub.counter = this.counter;
            sub.localNames.addAll(this.localNames);
            sub.paramNames.addAll(this.paramNames);
            sub.methodParamTypes.putAll(this.methodParamTypes);
            sub.localAliases.putAll(this.localAliases);
            sub.localByteVars.addAll(this.localByteVars);
            return sub;
        }

        void syncCounter(LowerCtx sub) {
            if (sub.counter > this.counter) {
                this.counter = sub.counter;
            }
        }

        // -----------------------------------------------------------
        // Statement lowering
        // -----------------------------------------------------------

        void lowerStatements(List<Statement> stmts) {
            for (int i = 0; i < stmts.size(); i++) {
                Statement stmt = stmts.get(i);
                // Early-return nesting: if an if-statement's then-block ends
                // with return and no else-branch, the remaining statements
                // logically belong in the else-branch.
                if (stmt instanceof IfStatement is
                    && is.elseBody() == null
                    && i + 1 < stmts.size()
                    && branchEndsWithReturn(is.thenBody())) {
                    List<Statement> remaining = stmts.subList(i + 1, stmts.size());
                    IfStatement modified = new IfStatement(
                        is.condition(), is.thenBody(), new ArrayList<>(remaining), is.sourceLocation()
                    );
                    lowerStatement(modified);
                    return;
                }
                lowerStatement(stmt);
            }
        }

        void lowerStatement(Statement stmt) {
            if (stmt instanceof VariableDeclStatement v) {
                lowerVariableDecl(v);
            } else if (stmt instanceof AssignmentStatement a) {
                lowerAssignment(a);
            } else if (stmt instanceof IfStatement i) {
                lowerIfStatement(i);
            } else if (stmt instanceof ForStatement f) {
                lowerForStatement(f);
            } else if (stmt instanceof ExpressionStatement e) {
                lowerExprToRef(e.expression());
            } else if (stmt instanceof ReturnStatement r) {
                if (r.value() != null) {
                    String ref = lowerExprToRef(r.value());
                    // If the returned ref is not the name of the last emitted
                    // binding, emit an explicit load so the return value is
                    // the last (top-of-stack) binding.
                    if (!bindings.isEmpty() && !bindings.get(bindings.size() - 1).name().equals(ref)) {
                        emit(makeLoadConstString("@ref:" + ref));
                    }
                }
            }
        }

        void lowerVariableDecl(VariableDeclStatement stmt) {
            String valueRef = lowerExprToRef(stmt.init());
            addLocal(stmt.name());
            if (isByteTypedExpr(stmt.init())) {
                localByteVars.add(stmt.name());
            }
            emitNamed(stmt.name(), makeLoadConstString("@ref:" + valueRef));
        }

        void lowerAssignment(AssignmentStatement stmt) {
            String valueRef = lowerExprToRef(stmt.value());
            if (stmt.target() instanceof PropertyAccessExpr pa) {
                emit(new UpdateProp(pa.property(), valueRef));
                return;
            }
            if (stmt.target() instanceof Identifier id) {
                emitNamed(id.name(), makeLoadConstString("@ref:" + valueRef));
                return;
            }
            // Fallback
            lowerExprToRef(stmt.target());
        }

        void lowerIfStatement(IfStatement stmt) {
            String condRef = lowerExprToRef(stmt.condition());

            LowerCtx thenCtx = subContext();
            thenCtx.lowerStatements(stmt.thenBody());
            syncCounter(thenCtx);

            LowerCtx elseCtx = subContext();
            if (stmt.elseBody() != null) {
                elseCtx.lowerStatements(stmt.elseBody());
            }
            syncCounter(elseCtx);

            boolean thenHasOutputs = !thenCtx.addOutputRefs.isEmpty();
            boolean elseHasOutputs = !elseCtx.addOutputRefs.isEmpty();
            boolean thenHasData = !thenCtx.addDataOutputRefs.isEmpty();
            boolean elseHasData = !elseCtx.addDataOutputRefs.isEmpty();

            String ifName = emit(new If(condRef, thenCtx.bindings, elseCtx.bindings));

            if (thenHasOutputs || elseHasOutputs) {
                addOutputRefs.add(ifName);
            }
            if (thenHasData || elseHasData) {
                addDataOutputRefs.add(ifName);
            }

            // If both branches end by reassigning the same local variable,
            // alias that variable to the if-expression result
            if (!thenCtx.bindings.isEmpty() && !elseCtx.bindings.isEmpty()) {
                AnfBinding thenLast = thenCtx.bindings.get(thenCtx.bindings.size() - 1);
                AnfBinding elseLast = elseCtx.bindings.get(elseCtx.bindings.size() - 1);
                if (thenLast.name().equals(elseLast.name()) && isLocal(thenLast.name())) {
                    setLocalAlias(thenLast.name(), ifName);
                }
            }
        }

        void lowerForStatement(ForStatement stmt) {
            int count = extractLoopCount(stmt);

            LowerCtx bodyCtx = subContext();
            bodyCtx.lowerStatements(stmt.body());
            syncCounter(bodyCtx);

            String iterVar = stmt.init() != null ? stmt.init().name() : "";
            emit(new Loop(count, bodyCtx.bindings, iterVar));
        }

        // -----------------------------------------------------------
        // Expression lowering
        // -----------------------------------------------------------

        String lowerExprToRef(Expression expr) {
            if (expr == null) {
                return emit(makeLoadConstInt(BigInteger.ZERO));
            }
            if (expr instanceof BigIntLiteral bi) {
                return emit(makeLoadConstInt(bi.value()));
            }
            if (expr instanceof BoolLiteral b) {
                return emit(makeLoadConstBool(b.value()));
            }
            if (expr instanceof ByteStringLiteral bs) {
                return emit(makeLoadConstString(bs.value()));
            }
            if (expr instanceof Identifier id) {
                return lowerIdentifier(id);
            }
            if (expr instanceof PropertyAccessExpr pa) {
                if (isParam(pa.property())) {
                    return emit(new LoadParam(pa.property()));
                }
                return emit(new LoadProp(pa.property()));
            }
            if (expr instanceof MemberExpr me) {
                return lowerMemberExpr(me);
            }
            if (expr instanceof BinaryExpr be) {
                String leftRef = lowerExprToRef(be.left());
                String rightRef = lowerExprToRef(be.right());
                String resultType = null;
                String opCanonical = be.op().canonical();
                if ((opCanonical.equals("===") || opCanonical.equals("!=="))
                    && (isByteTypedExpr(be.left()) || isByteTypedExpr(be.right()))) {
                    resultType = "bytes";
                }
                if (opCanonical.equals("+")
                    && (isByteTypedExpr(be.left()) || isByteTypedExpr(be.right()))) {
                    resultType = "bytes";
                }
                if ((opCanonical.equals("&") || opCanonical.equals("|") || opCanonical.equals("^"))
                    && (isByteTypedExpr(be.left()) || isByteTypedExpr(be.right()))) {
                    resultType = "bytes";
                }
                return emit(new BinOp(opCanonical, leftRef, rightRef, resultType));
            }
            if (expr instanceof UnaryExpr ue) {
                String operandRef = lowerExprToRef(ue.operand());
                String opCanonical = ue.op().canonical();
                String resultType = null;
                if (opCanonical.equals("~") && isByteTypedExpr(ue.operand())) {
                    resultType = "bytes";
                }
                return emit(new UnaryOp(opCanonical, operandRef, resultType));
            }
            if (expr instanceof CallExpr ce) {
                return lowerCallExpr(ce);
            }
            if (expr instanceof TernaryExpr te) {
                return lowerTernaryExpr(te);
            }
            if (expr instanceof IndexAccessExpr ia) {
                String objRef = lowerExprToRef(ia.object());
                String indexRef = lowerExprToRef(ia.index());
                return emit(new Call("__array_access", List.of(objRef, indexRef)));
            }
            if (expr instanceof IncrementExpr ie) {
                return lowerIncrementExpr(ie);
            }
            if (expr instanceof DecrementExpr de) {
                return lowerDecrementExpr(de);
            }
            if (expr instanceof ArrayLiteralExpr al) {
                List<String> elementRefs = new ArrayList<>(al.elements().size());
                for (Expression el : al.elements()) {
                    elementRefs.add(lowerExprToRef(el));
                }
                return emit(new ArrayLiteral(elementRefs));
            }
            return emit(makeLoadConstInt(BigInteger.ZERO));
        }

        private String lowerIdentifier(Identifier id) {
            String name = id.name();

            if ("this".equals(name)) {
                return emit(makeLoadConstString("@this"));
            }

            if (isParam(name)) {
                return emit(new LoadParam(name));
            }

            if (isLocal(name)) {
                String alias = getLocalAlias(name);
                if (alias != null) return alias;
                return name;
            }

            if (isProperty(name)) {
                return emit(new LoadProp(name));
            }

            return emit(new LoadParam(name));
        }

        private String lowerMemberExpr(MemberExpr e) {
            if (e.object() instanceof Identifier id && "this".equals(id.name())) {
                return emit(new LoadProp(e.property()));
            }
            if (e.object() instanceof Identifier id2 && "SigHash".equals(id2.name())) {
                BigInteger val = switch (e.property()) {
                    case "ALL" -> BigInteger.valueOf(0x01);
                    case "NONE" -> BigInteger.valueOf(0x02);
                    case "SINGLE" -> BigInteger.valueOf(0x03);
                    case "FORKID" -> BigInteger.valueOf(0x40);
                    case "ANYONECANPAY" -> BigInteger.valueOf(0x80);
                    default -> null;
                };
                if (val != null) {
                    return emit(makeLoadConstInt(val));
                }
            }
            String objRef = lowerExprToRef(e.object());
            return emit(new MethodCall(objRef, e.property(), List.of()));
        }

        private String lowerCallExpr(CallExpr e) {
            Expression callee = e.callee();

            // super(...) call
            boolean isSuper = (callee instanceof Identifier sid && "super".equals(sid.name()))
                || (callee instanceof MemberExpr msm
                    && msm.object() instanceof Identifier sid2
                    && "super".equals(sid2.name()));
            if (isSuper) {
                List<String> argRefs = lowerArgs(e.args());
                return emit(new Call("super", argRefs));
            }

            // assert / assertThat
            if (callee instanceof Identifier id
                && ("assert".equals(id.name()) || "assertThat".equals(id.name()))) {
                if (!e.args().isEmpty()) {
                    String valueRef = lowerExprToRef(e.args().get(0));
                    return emit(new Assert(valueRef));
                }
                String falseRef = emit(makeLoadConstBool(false));
                return emit(new Assert(falseRef));
            }

            // checkPreimage(preimage)
            if (callee instanceof Identifier id2 && "checkPreimage".equals(id2.name())) {
                if (!e.args().isEmpty()) {
                    String preimageRef = lowerExprToRef(e.args().get(0));
                    return emit(new CheckPreimage(preimageRef));
                }
            }

            // this.addOutput(satoshis, val1, val2, ...)
            if (isThisPropCall(callee, "addOutput")) {
                List<Expression> flatArgs = flattenAddOutputArgs(e.args());
                List<String> argRefs = lowerArgs(flatArgs);
                String satoshis = argRefs.get(0);
                List<String> stateValues = argRefs.subList(1, argRefs.size());
                String ref = emit(new AddOutput(satoshis, new ArrayList<>(stateValues), ""));
                addOutputRefs.add(ref);
                return ref;
            }

            // this.addRawOutput(satoshis, scriptBytes)
            if (isThisPropCall(callee, "addRawOutput")) {
                List<String> argRefs = lowerArgs(e.args());
                String satoshis = argRefs.get(0);
                String scriptBytesRef = argRefs.get(1);
                String ref = emit(new AddRawOutput(satoshis, scriptBytesRef));
                addOutputRefs.add(ref);
                return ref;
            }

            // this.addDataOutput(satoshis, scriptBytes)
            if (isThisPropCall(callee, "addDataOutput")) {
                List<String> argRefs = lowerArgs(e.args());
                String satoshis = argRefs.get(0);
                String scriptBytesRef = argRefs.get(1);
                String ref = emit(new AddDataOutput(satoshis, scriptBytesRef));
                addDataOutputRefs.add(ref);
                return ref;
            }

            // this.getStateScript()
            if (isThisPropCall(callee, "getStateScript")) {
                return emit(new GetStateScript());
            }

            // this.method(...) via PropertyAccessExpr
            if (callee instanceof PropertyAccessExpr pa) {
                List<String> argRefs = lowerArgs(e.args());
                String thisRef = emit(makeLoadConstString("@this"));
                return emit(new MethodCall(thisRef, pa.property(), argRefs));
            }

            // this.method(...) via MemberExpr
            if (callee instanceof MemberExpr me
                && me.object() instanceof Identifier oid
                && "this".equals(oid.name())) {
                List<String> argRefs = lowerArgs(e.args());
                String thisRef = emit(makeLoadConstString("@this"));
                return emit(new MethodCall(thisRef, me.property(), argRefs));
            }

            // Java-specific: a.equals(b) on a ByteString-subtyped receiver
            // lowers to the same === bin_op the other compilers' `===`
            // operator produces. Mirrors the design resolution in
            // docs/java-tier-plan.md: "the validator coerces a.equals(b)
            // to the == AST node for ByteString-subtyped values".
            if (callee instanceof MemberExpr meq
                && meq.property().equals("equals")
                && e.args().size() == 1) {
                Expression receiver = meq.object();
                Expression other = e.args().get(0);
                boolean leftBytes = isByteTypedExpr(receiver);
                boolean rightBytes = isByteTypedExpr(other);
                if (leftBytes || rightBytes) {
                    String leftRef = lowerExprToRef(receiver);
                    String rightRef = lowerExprToRef(other);
                    return emit(new BinOp("===", leftRef, rightRef, "bytes"));
                }
            }

            // Bare identifier calls
            if (callee instanceof Identifier id3) {
                List<String> argRefs = lowerArgs(e.args());
                if (isPrivateMethod(id3.name())) {
                    String thisRef = emit(makeLoadConstString("@this"));
                    return emit(new MethodCall(thisRef, id3.name(), argRefs));
                }
                return emit(new Call(id3.name(), argRefs));
            }

            // General call: foo.bar(args) where foo is not `this`
            String calleeRef = lowerExprToRef(callee);
            List<String> argRefs = lowerArgs(e.args());
            return emit(new MethodCall(calleeRef, "call", argRefs));
        }

        private static boolean isThisPropCall(Expression callee, String name) {
            if (callee instanceof PropertyAccessExpr pa && pa.property().equals(name)) {
                return true;
            }
            if (callee instanceof MemberExpr me
                && me.object() instanceof Identifier id
                && "this".equals(id.name())
                && me.property().equals(name)) {
                return true;
            }
            return false;
        }

        private List<String> lowerArgs(List<Expression> args) {
            List<String> out = new ArrayList<>(args.size());
            for (Expression arg : args) {
                out.add(lowerExprToRef(arg));
            }
            return out;
        }

        private String lowerTernaryExpr(TernaryExpr e) {
            String condRef = lowerExprToRef(e.condition());

            LowerCtx thenCtx = subContext();
            thenCtx.lowerExprToRef(e.consequent());
            syncCounter(thenCtx);

            LowerCtx elseCtx = subContext();
            elseCtx.lowerExprToRef(e.alternate());
            syncCounter(elseCtx);

            return emit(new If(condRef, thenCtx.bindings, elseCtx.bindings));
        }

        private String lowerIncrementExpr(IncrementExpr e) {
            String operandRef = lowerExprToRef(e.operand());
            String oneRef = emit(makeLoadConstInt(BigInteger.ONE));
            String result = emit(new BinOp("+", operandRef, oneRef, null));

            if (e.operand() instanceof Identifier id) {
                emitNamed(id.name(), makeLoadConstString("@ref:" + result));
            }
            if (e.operand() instanceof PropertyAccessExpr pa) {
                emit(new UpdateProp(pa.property(), result));
            }
            return e.prefix() ? result : operandRef;
        }

        private String lowerDecrementExpr(DecrementExpr e) {
            String operandRef = lowerExprToRef(e.operand());
            String oneRef = emit(makeLoadConstInt(BigInteger.ONE));
            String result = emit(new BinOp("-", operandRef, oneRef, null));

            if (e.operand() instanceof Identifier id) {
                emitNamed(id.name(), makeLoadConstString("@ref:" + result));
            }
            if (e.operand() instanceof PropertyAccessExpr pa) {
                emit(new UpdateProp(pa.property(), result));
            }
            return e.prefix() ? result : operandRef;
        }

        // -----------------------------------------------------------
        // Byte-typed expression detection (uses the lower context for
        // local-variable typing information).
        // -----------------------------------------------------------

        private boolean isByteTypedExpr(Expression expr) {
            if (expr == null) return false;
            if (expr instanceof ByteStringLiteral) return true;
            if (expr instanceof Identifier id) {
                String t = getParamType(id.name());
                if (t != null && BYTE_TYPES.contains(t)) return true;
                t = getPropertyType(id.name());
                if (t != null && BYTE_TYPES.contains(t)) return true;
                if (localByteVars.contains(id.name())) return true;
                return false;
            }
            if (expr instanceof PropertyAccessExpr pa) {
                String t = getPropertyType(pa.property());
                return t != null && BYTE_TYPES.contains(t);
            }
            if (expr instanceof MemberExpr me
                && me.object() instanceof Identifier id2
                && "this".equals(id2.name())) {
                String t = getPropertyType(me.property());
                return t != null && BYTE_TYPES.contains(t);
            }
            if (expr instanceof CallExpr ce) {
                if (ce.callee() instanceof Identifier cid) {
                    if (BYTE_RETURNING_FUNCTIONS.contains(cid.name())) return true;
                    if (cid.name().length() >= 7
                        && cid.name().substring(0, 7).equals("extract")) {
                        return true;
                    }
                }
                return false;
            }
            return false;
        }
    }

    // ------------------------------------------------------------------
    // AnfValue constructors
    // ------------------------------------------------------------------

    private static AnfValue makeLoadConstInt(BigInteger v) {
        return new LoadConst(new BigIntConst(v));
    }

    private static AnfValue makeLoadConstBool(boolean v) {
        return new LoadConst(new BoolConst(v));
    }

    private static AnfValue makeLoadConstString(String v) {
        // BytesConst serialises as a bare string via ConstValue.raw(); we
        // piggy-back on that mechanism for sentinel strings like
        // "@ref:t5" / "@this".
        return new LoadConst(new BytesConst(v));
    }

    private static List<Expression> flattenAddOutputArgs(List<Expression> args) {
        if (args.size() == 2 && args.get(1) instanceof ArrayLiteralExpr al) {
            List<Expression> out = new ArrayList<>(1 + al.elements().size());
            out.add(args.get(0));
            out.addAll(al.elements());
            return out;
        }
        return args;
    }

    // ------------------------------------------------------------------
    // State mutation analysis
    // ------------------------------------------------------------------

    private static boolean methodMutatesState(MethodNode method, ContractNode contract) {
        Set<String> mutable = new HashSet<>();
        for (PropertyNode p : contract.properties()) {
            if (!p.readonly()) mutable.add(p.name());
        }
        if (mutable.isEmpty()) return false;
        return bodyMutatesState(method.body(), mutable);
    }

    private static boolean bodyMutatesState(List<Statement> stmts, Set<String> mutable) {
        for (Statement s : stmts) {
            if (stmtMutatesState(s, mutable)) return true;
        }
        return false;
    }

    private static boolean stmtMutatesState(Statement stmt, Set<String> mutable) {
        if (stmt instanceof AssignmentStatement a) {
            return a.target() instanceof PropertyAccessExpr pa && mutable.contains(pa.property());
        }
        if (stmt instanceof ExpressionStatement es) {
            return exprMutatesState(es.expression(), mutable);
        }
        if (stmt instanceof IfStatement i) {
            if (bodyMutatesState(i.thenBody(), mutable)) return true;
            return i.elseBody() != null && bodyMutatesState(i.elseBody(), mutable);
        }
        if (stmt instanceof ForStatement f) {
            if (f.update() != null && stmtMutatesState(f.update(), mutable)) return true;
            return bodyMutatesState(f.body(), mutable);
        }
        return false;
    }

    private static boolean exprMutatesState(Expression expr, Set<String> mutable) {
        if (expr == null) return false;
        if (expr instanceof IncrementExpr ie
            && ie.operand() instanceof PropertyAccessExpr pa) {
            return mutable.contains(pa.property());
        }
        if (expr instanceof DecrementExpr de
            && de.operand() instanceof PropertyAccessExpr pa) {
            return mutable.contains(pa.property());
        }
        return false;
    }

    // ------------------------------------------------------------------
    // addOutput / addDataOutput detection
    // ------------------------------------------------------------------

    private static boolean methodHasAddOutput(MethodNode m) {
        return bodyHasAddOutput(m.body());
    }

    private static boolean bodyHasAddOutput(List<Statement> stmts) {
        for (Statement s : stmts) if (stmtHasAddOutput(s)) return true;
        return false;
    }

    private static boolean stmtHasAddOutput(Statement s) {
        if (s instanceof ExpressionStatement es) return exprHasAddOutput(es.expression());
        if (s instanceof IfStatement i) {
            if (bodyHasAddOutput(i.thenBody())) return true;
            return i.elseBody() != null && bodyHasAddOutput(i.elseBody());
        }
        if (s instanceof ForStatement f) return bodyHasAddOutput(f.body());
        return false;
    }

    private static boolean exprHasAddOutput(Expression e) {
        if (e == null) return false;
        if (e instanceof CallExpr c) {
            if (c.callee() instanceof PropertyAccessExpr pa
                && (pa.property().equals("addOutput") || pa.property().equals("addRawOutput"))) {
                return true;
            }
            if (c.callee() instanceof MemberExpr me
                && me.object() instanceof Identifier id
                && "this".equals(id.name())
                && (me.property().equals("addOutput") || me.property().equals("addRawOutput"))) {
                return true;
            }
        }
        return false;
    }

    private static boolean methodHasAddDataOutput(MethodNode m) {
        return bodyHasAddDataOutput(m.body());
    }

    private static boolean bodyHasAddDataOutput(List<Statement> stmts) {
        for (Statement s : stmts) if (stmtHasAddDataOutput(s)) return true;
        return false;
    }

    private static boolean stmtHasAddDataOutput(Statement s) {
        if (s instanceof ExpressionStatement es) return exprHasAddDataOutput(es.expression());
        if (s instanceof IfStatement i) {
            if (bodyHasAddDataOutput(i.thenBody())) return true;
            return i.elseBody() != null && bodyHasAddDataOutput(i.elseBody());
        }
        if (s instanceof ForStatement f) return bodyHasAddDataOutput(f.body());
        return false;
    }

    private static boolean exprHasAddDataOutput(Expression e) {
        if (e == null) return false;
        if (e instanceof CallExpr c) {
            if (c.callee() instanceof PropertyAccessExpr pa
                && pa.property().equals("addDataOutput")) {
                return true;
            }
            if (c.callee() instanceof MemberExpr me
                && me.object() instanceof Identifier id
                && "this".equals(id.name())
                && me.property().equals("addDataOutput")) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------
    // Loop count extraction
    // ------------------------------------------------------------------

    private static int extractLoopCount(ForStatement stmt) {
        BigInteger startVal = null;
        if (stmt.init() != null) {
            startVal = extractBigintValue(stmt.init().init());
        }

        if (stmt.condition() instanceof BinaryExpr be) {
            BigInteger boundVal = extractBigintValue(be.right());
            if (startVal != null && boundVal != null) {
                BigInteger start = startVal;
                BigInteger bound = boundVal;
                String op = be.op().canonical();
                return switch (op) {
                    case "<" -> Math.max(0, bound.subtract(start).intValue());
                    case "<=" -> Math.max(0, bound.subtract(start).add(BigInteger.ONE).intValue());
                    case ">" -> Math.max(0, start.subtract(bound).intValue());
                    case ">=" -> Math.max(0, start.subtract(bound).add(BigInteger.ONE).intValue());
                    default -> 0;
                };
            }
            if (boundVal != null) {
                String op = be.op().canonical();
                return switch (op) {
                    case "<" -> boundVal.intValue();
                    case "<=" -> boundVal.add(BigInteger.ONE).intValue();
                    default -> 0;
                };
            }
        }
        return 0;
    }

    private static BigInteger extractBigintValue(Expression expr) {
        if (expr == null) return null;
        if (expr instanceof BigIntLiteral bi) return bi.value();
        if (expr instanceof UnaryExpr u && u.op() == Expression.UnaryOp.NEG) {
            BigInteger inner = extractBigintValue(u.operand());
            if (inner != null) return inner.negate();
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static boolean branchEndsWithReturn(List<Statement> stmts) {
        if (stmts.isEmpty()) return false;
        Statement last = stmts.get(stmts.size() - 1);
        if (last instanceof ReturnStatement) return true;
        if (last instanceof IfStatement i && i.elseBody() != null) {
            return branchEndsWithReturn(i.thenBody()) && branchEndsWithReturn(i.elseBody());
        }
        return false;
    }

    private static String typeToString(TypeNode t) {
        if (t == null) return "<unknown>";
        if (t instanceof PrimitiveType p) return p.name().canonical();
        if (t instanceof FixedArrayType fa) return typeToString(fa.element()) + "[]";
        if (t instanceof CustomType c) return c.name();
        return "<unknown>";
    }

    // ==================================================================
    // Post-ANF pass: lift update_prop from if-else branches
    // ==================================================================
    //
    // Transforms if-else chains where each branch ends with ``update_prop``
    // into flat conditional assignments. Mirrors the TS and Python
    // references.
    // ==================================================================

    private static final class UpdateBranch {
        final List<AnfBinding> condSetupBindings;
        final String condRef; // null for final else
        final String propName;
        final List<AnfBinding> valueBindings;
        final String valueRef;

        UpdateBranch(List<AnfBinding> csb, String cr, String pn, List<AnfBinding> vb, String vr) {
            this.condSetupBindings = csb;
            this.condRef = cr;
            this.propName = pn;
            this.valueBindings = vb;
            this.valueRef = vr;
        }
    }

    private static int maxTempIndex(List<AnfBinding> bindings) {
        int max = -1;
        for (AnfBinding b : bindings) {
            String n = b.name();
            if (n.startsWith("t") && n.length() > 1) {
                try {
                    int v = Integer.parseInt(n.substring(1));
                    if (v > max) max = v;
                } catch (NumberFormatException ignored) {
                    // not a t<N> temp name
                }
            }
            if (b.value() instanceof If ifv) {
                int t = maxTempIndex(ifv.thenBranch());
                if (t > max) max = t;
                int e = maxTempIndex(ifv.elseBranch());
                if (e > max) max = e;
            } else if (b.value() instanceof Loop lp) {
                int l = maxTempIndex(lp.body());
                if (l > max) max = l;
            }
        }
        return max;
    }

    private static boolean isSideEffectFree(AnfValue v) {
        return v instanceof LoadProp
            || v instanceof LoadParam
            || v instanceof LoadConst
            || v instanceof BinOp
            || v instanceof UnaryOp;
    }

    private static boolean allBindingsSideEffectFree(List<AnfBinding> bindings) {
        for (AnfBinding b : bindings) {
            if (!isSideEffectFree(b.value())) return false;
        }
        return true;
    }

    private record BranchUpdate(String propName, List<AnfBinding> valueBindings, String valueRef) {}

    private static BranchUpdate extractBranchUpdate(List<AnfBinding> bindings) {
        if (bindings.isEmpty()) return null;
        AnfBinding last = bindings.get(bindings.size() - 1);
        if (!(last.value() instanceof UpdateProp up)) return null;
        List<AnfBinding> valueBindings = new ArrayList<>(bindings.subList(0, bindings.size() - 1));
        if (!allBindingsSideEffectFree(valueBindings)) return null;
        return new BranchUpdate(up.name(), valueBindings, up.value());
    }

    private static boolean isAssertFalseElse(List<AnfBinding> bindings) {
        if (bindings.isEmpty()) return false;
        AnfBinding last = bindings.get(bindings.size() - 1);
        if (!(last.value() instanceof Assert a)) return false;
        String assertRef = a.value();
        for (AnfBinding b : bindings) {
            if (b.name().equals(assertRef)
                && b.value() instanceof LoadConst lc
                && lc.value() instanceof BoolConst bc
                && !bc.value()) {
                return true;
            }
        }
        return false;
    }

    private static List<UpdateBranch> collectUpdateBranches(
        String ifCond, List<AnfBinding> thenBindings, List<AnfBinding> elseBindings) {
        BranchUpdate thenUpdate = extractBranchUpdate(thenBindings);
        if (thenUpdate == null) return null;

        List<UpdateBranch> branches = new ArrayList<>();
        branches.add(new UpdateBranch(
            new ArrayList<>(), ifCond, thenUpdate.propName(),
            thenUpdate.valueBindings(), thenUpdate.valueRef()
        ));

        if (elseBindings.isEmpty()) return null;

        AnfBinding lastElse = elseBindings.get(elseBindings.size() - 1);
        if (lastElse.value() instanceof If innerIf) {
            List<AnfBinding> condSetup = new ArrayList<>(elseBindings.subList(0, elseBindings.size() - 1));
            if (!allBindingsSideEffectFree(condSetup)) return null;

            List<UpdateBranch> inner = collectUpdateBranches(
                innerIf.cond(), innerIf.thenBranch(), innerIf.elseBranch()
            );
            if (inner == null) return null;

            // Prepend condition setup to first inner branch
            List<AnfBinding> newSetup = new ArrayList<>(condSetup);
            newSetup.addAll(inner.get(0).condSetupBindings);
            UpdateBranch first = inner.get(0);
            inner.set(0, new UpdateBranch(newSetup, first.condRef, first.propName,
                first.valueBindings, first.valueRef));
            branches.addAll(inner);
            return branches;
        }

        BranchUpdate elseUpdate = extractBranchUpdate(elseBindings);
        if (elseUpdate != null) {
            branches.add(new UpdateBranch(
                new ArrayList<>(), null, elseUpdate.propName(),
                elseUpdate.valueBindings(), elseUpdate.valueRef()
            ));
            return branches;
        }

        if (isAssertFalseElse(elseBindings)) {
            return branches;
        }

        return null;
    }

    // Map temp refs inside an AnfValue.
    private static AnfValue remapValueRefs(AnfValue value, Map<String, String> nameMap) {
        if (value instanceof LoadProp) return value;
        if (value instanceof LoadParam) return value;
        if (value instanceof GetStateScript) return value;
        if (value instanceof LoadConst lc) {
            if (lc.value() instanceof BytesConst bc && bc.hex().startsWith("@ref:")) {
                String target = bc.hex().substring(5);
                String mapped = nameMap.get(target);
                if (mapped != null) {
                    return new LoadConst(new BytesConst("@ref:" + mapped));
                }
            }
            return value;
        }
        if (value instanceof BinOp bo) {
            return new BinOp(bo.op(),
                mapOr(bo.left(), nameMap), mapOr(bo.right(), nameMap), bo.resultType());
        }
        if (value instanceof UnaryOp uo) {
            return new UnaryOp(uo.op(), mapOr(uo.operand(), nameMap), uo.resultType());
        }
        if (value instanceof Call c) {
            List<String> args = new ArrayList<>(c.args().size());
            for (String a : c.args()) args.add(mapOr(a, nameMap));
            return new Call(c.func(), args);
        }
        if (value instanceof MethodCall mc) {
            List<String> args = new ArrayList<>(mc.args().size());
            for (String a : mc.args()) args.add(mapOr(a, nameMap));
            return new MethodCall(mapOr(mc.object(), nameMap), mc.method(), args);
        }
        if (value instanceof If ifv) {
            return new If(mapOr(ifv.cond(), nameMap), ifv.thenBranch(), ifv.elseBranch());
        }
        if (value instanceof Loop lp) {
            return new Loop(lp.count(), lp.body(), lp.iterVar());
        }
        if (value instanceof Assert asv) {
            return new Assert(mapOr(asv.value(), nameMap));
        }
        if (value instanceof UpdateProp up) {
            return new UpdateProp(up.name(), mapOr(up.value(), nameMap));
        }
        if (value instanceof CheckPreimage cp) {
            return new CheckPreimage(mapOr(cp.preimage(), nameMap));
        }
        if (value instanceof DeserializeState ds) {
            return new DeserializeState(mapOr(ds.preimage(), nameMap));
        }
        if (value instanceof AddOutput ao) {
            List<String> sv = new ArrayList<>(ao.stateValues().size());
            for (String s : ao.stateValues()) sv.add(mapOr(s, nameMap));
            return new AddOutput(mapOr(ao.satoshis(), nameMap), sv, mapOr(ao.preimage(), nameMap));
        }
        if (value instanceof AddRawOutput ar) {
            return new AddRawOutput(mapOr(ar.satoshis(), nameMap), mapOr(ar.scriptBytes(), nameMap));
        }
        if (value instanceof AddDataOutput ad) {
            return new AddDataOutput(mapOr(ad.satoshis(), nameMap), mapOr(ad.scriptBytes(), nameMap));
        }
        if (value instanceof ArrayLiteral al) {
            List<String> els = new ArrayList<>(al.elements().size());
            for (String e : al.elements()) els.add(mapOr(e, nameMap));
            return new ArrayLiteral(els);
        }
        return value;
    }

    private static String mapOr(String s, Map<String, String> nameMap) {
        if (s == null) return null;
        return nameMap.getOrDefault(s, s);
    }

    static List<AnfBinding> liftBranchUpdateProps(List<AnfBinding> bindings) {
        final int[] nextIdx = { maxTempIndex(bindings) + 1 };
        List<AnfBinding> result = new ArrayList<>();

        for (AnfBinding binding : bindings) {
            if (!(binding.value() instanceof If ifv)) {
                result.add(binding);
                continue;
            }

            List<UpdateBranch> branches = collectUpdateBranches(
                ifv.cond(), ifv.thenBranch(), ifv.elseBranch()
            );

            if (branches == null || branches.size() < 2) {
                result.add(binding);
                continue;
            }

            // Transform: flatten into conditional assignments.
            Map<String, String> nameMap = new LinkedHashMap<>();
            List<String> condRefs = new ArrayList<>();

            for (UpdateBranch branch : branches) {
                for (AnfBinding csb : branch.condSetupBindings) {
                    String newName = "t" + (nextIdx[0]++);
                    nameMap.put(csb.name(), newName);
                    result.add(new AnfBinding(newName, remapValueRefs(csb.value(), nameMap), null));
                }
                if (branch.condRef != null) {
                    condRefs.add(nameMap.getOrDefault(branch.condRef, branch.condRef));
                } else {
                    condRefs.add(null);
                }
            }

            // Compute effective condition for each branch.
            List<String> effectiveConds = new ArrayList<>();
            List<String> negatedConds = new ArrayList<>();
            for (int i = 0; i < branches.size(); i++) {
                if (i == 0) {
                    effectiveConds.add(condRefs.get(0));
                    continue;
                }
                for (int j = negatedConds.size(); j < i; j++) {
                    if (condRefs.get(j) == null) continue;
                    String negName = "t" + (nextIdx[0]++);
                    result.add(new AnfBinding(negName,
                        new UnaryOp("!", condRefs.get(j), null), null));
                    negatedConds.add(negName);
                }
                String andRef = negatedConds.get(0);
                int limit = Math.min(i, negatedConds.size());
                for (int j = 1; j < limit; j++) {
                    String andName = "t" + (nextIdx[0]++);
                    result.add(new AnfBinding(andName,
                        new BinOp("&&", andRef, negatedConds.get(j), null), null));
                    andRef = andName;
                }
                if (condRefs.get(i) != null) {
                    String finalName = "t" + (nextIdx[0]++);
                    result.add(new AnfBinding(finalName,
                        new BinOp("&&", andRef, condRefs.get(i), null), null));
                    effectiveConds.add(finalName);
                } else {
                    effectiveConds.add(andRef);
                }
            }

            // Emit load_old, conditional if-expression, update_prop per branch.
            for (int i = 0; i < branches.size(); i++) {
                UpdateBranch branch = branches.get(i);

                String oldPropRef = "t" + (nextIdx[0]++);
                result.add(new AnfBinding(oldPropRef, new LoadProp(branch.propName), null));

                Map<String, String> branchMap = new LinkedHashMap<>(nameMap);
                List<AnfBinding> thenBindings = new ArrayList<>();
                for (AnfBinding vb : branch.valueBindings) {
                    String newName = "t" + (nextIdx[0]++);
                    branchMap.put(vb.name(), newName);
                    thenBindings.add(new AnfBinding(newName, remapValueRefs(vb.value(), branchMap), null));
                }

                String keepName = "t" + (nextIdx[0]++);
                List<AnfBinding> elseBindings = new ArrayList<>();
                elseBindings.add(new AnfBinding(keepName,
                    new LoadConst(new BytesConst("@ref:" + oldPropRef)), null));

                String condIfRef = "t" + (nextIdx[0]++);
                result.add(new AnfBinding(condIfRef,
                    new If(effectiveConds.get(i), thenBindings, elseBindings), null));

                String updateName = "t" + (nextIdx[0]++);
                result.add(new AnfBinding(updateName,
                    new UpdateProp(branch.propName, condIfRef), null));
            }
        }

        return result;
    }
}
