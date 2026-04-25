package runar.compiler.passes;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import runar.compiler.ir.ast.ArrayLiteralExpr;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BigIntLiteral;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.BoolLiteral;
import runar.compiler.ir.ast.ByteStringLiteral;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
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
import runar.compiler.ir.ast.PrimitiveType;
import runar.compiler.ir.ast.PrimitiveTypeName;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.PropertyNode;
import runar.compiler.ir.ast.PropertyNode.SyntheticArrayChainEntry;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.SourceLocation;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.TernaryExpr;
import runar.compiler.ir.ast.TypeNode;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;

/**
 * Pass 3b: Expand fixed-size array properties into scalar sibling fields.
 *
 * <p>Direct port of:
 * <ul>
 *   <li>{@code packages/runar-compiler/src/passes/03b-expand-fixed-arrays.ts}
 *       (TypeScript reference)</li>
 *   <li>{@code compilers/python/runar_compiler/frontend/expand_fixed_arrays.py}
 *       (Python authoritative behaviour)</li>
 *   <li>{@code compilers/go/frontend/expand_fixed_arrays.go}</li>
 *   <li>{@code compilers/ruby/lib/runar_compiler/frontend/expand_fixed_arrays.rb}</li>
 * </ul>
 *
 * <p>Runs between {@link Validate} and {@link Typecheck}. Takes a
 * {@link ContractNode} whose properties may contain {@link FixedArrayType}
 * declarations like {@code FixedArray<bigint, 9> board} and rewrites the
 * AST so every downstream pass sees an equivalent contract with 9 scalar
 * siblings {@code board__0 .. board__8} and all {@code this.board[i]}
 * reads/writes replaced by direct property access (literal index) or
 * dispatch (runtime index).
 *
 * <p>Cross-compiler conformance requires byte-identical output from
 * identical input, so synthetic names ({@code __0}, {@code __1}, &hellip;),
 * traversal order, and dispatch shape must match every other compiler
 * exactly.
 */
public final class ExpandFixedArrays {

    private ExpandFixedArrays() {}

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /** Result of an expansion run. */
    public record Result(ContractNode contract, List<String> errors) {
        public Result {
            errors = List.copyOf(errors);
        }
    }

    /** Aggregated list of expansion errors thrown on {@link #run}. */
    public static final class ExpandException extends RuntimeException {
        private final List<String> errors;

        public ExpandException(List<String> errors) {
            super(String.join("; ", errors));
            this.errors = List.copyOf(errors);
        }

        public List<String> errors() {
            return errors;
        }
    }

    /**
     * Expand FixedArray properties into scalar siblings and rewrite indexing.
     * Throws {@link ExpandException} if any errors are produced.
     */
    public static ContractNode run(ContractNode contract) {
        Result r = runCollecting(contract);
        if (!r.errors().isEmpty()) {
            throw new ExpandException(r.errors());
        }
        return r.contract();
    }

    /** Collect errors without throwing; returns the original contract on error. */
    public static Result runCollecting(ContractNode contract) {
        Ctx ctx = new Ctx(contract);

        if (!ctx.collectArrays()) {
            return new Result(contract, ctx.errors);
        }
        if (!ctx.errors.isEmpty()) {
            return new Result(contract, ctx.errors);
        }
        if (ctx.arrayMap.isEmpty()) {
            // No FixedArray properties — return unchanged.
            return new Result(contract, List.of());
        }

        List<PropertyNode> newProps = ctx.rewriteProperties();
        if (!ctx.errors.isEmpty()) {
            return new Result(contract, ctx.errors);
        }

        MethodNode newCtor = ctx.rewriteMethod(contract.constructor());
        List<MethodNode> newMethods = new ArrayList<>(contract.methods().size());
        for (MethodNode m : contract.methods()) {
            newMethods.add(ctx.rewriteMethod(m));
        }
        if (!ctx.errors.isEmpty()) {
            return new Result(contract, ctx.errors);
        }

        ContractNode rewritten = new ContractNode(
            contract.name(),
            contract.parentClass(),
            newProps,
            newCtor,
            newMethods,
            contract.sourceFile()
        );
        return new Result(rewritten, List.of());
    }

    // ------------------------------------------------------------------
    // Internal context
    // ------------------------------------------------------------------

    /** Per-level expansion metadata for a FixedArray property. */
    private static final class ArrayMeta {
        final String rootName;
        final FixedArrayType type;
        final List<String> slotNames;
        final boolean slotIsArray;
        final TypeNode elementType;
        final Map<String, ArrayMeta> nested = new HashMap<>();

        ArrayMeta(String rootName, FixedArrayType type, List<String> slotNames,
                  boolean slotIsArray, TypeNode elementType) {
            this.rootName = rootName;
            this.type = type;
            this.slotNames = slotNames;
            this.slotIsArray = slotIsArray;
            this.elementType = elementType;
        }
    }

    private static final class Ctx {
        final ContractNode contract;
        final List<String> errors = new ArrayList<>();
        // Top-level (user-declared) FixedArray properties keyed by original name.
        final Map<String, ArrayMeta> arrayMap = new HashMap<>();
        // Intermediate synthetic arrays (e.g. `grid__0` inside a 2D grid),
        // keyed by synthetic name.
        final Map<String, ArrayMeta> syntheticArrays = new HashMap<>();
        int tempCounter = 0;

        Ctx(ContractNode contract) {
            this.contract = contract;
        }

        void error(String msg, SourceLocation loc) {
            errors.add(formatAt(msg, loc));
        }

        private static String formatAt(String msg, SourceLocation loc) {
            if (loc == null) return msg;
            if (loc.file() != null && !loc.file().isEmpty() && loc.line() > 0) {
                return loc.file() + ":" + loc.line() + ":" + loc.column() + ": " + msg;
            }
            if (loc.file() != null && !loc.file().isEmpty()) {
                return loc.file() + ": " + msg;
            }
            return msg;
        }

        String freshIdxName() {
            int n = tempCounter++;
            return "__idx_" + n;
        }

        String freshValName() {
            int n = tempCounter++;
            return "__val_" + n;
        }

        // --------------------------------------------------------------
        // Collect phase
        // --------------------------------------------------------------

        boolean collectArrays() {
            for (PropertyNode prop : contract.properties()) {
                if (!(prop.type() instanceof FixedArrayType fa)) continue;
                ArrayMeta meta = buildArrayMeta(prop.name(), fa, prop.sourceLocation());
                if (meta == null) {
                    return false;
                }
                arrayMap.put(prop.name(), meta);
            }
            return true;
        }

        ArrayMeta buildArrayMeta(String rootName, FixedArrayType type, SourceLocation loc) {
            // FixedArray<void, N> rejection. Java's PrimitiveTypeName does
            // not list "void", so this only fires if a future parser adds it.
            if (type.element() instanceof PrimitiveType pt
                && "void".equals(pt.name().canonical())) {
                error(
                    "FixedArray element type cannot be 'void' (property '" + rootName + "')",
                    loc
                );
                return null;
            }
            if (type.length() <= 0) {
                error(
                    "FixedArray length must be a positive integer (property '" + rootName + "')",
                    loc
                );
                return null;
            }

            List<String> slotNames = new ArrayList<>(type.length());
            for (int i = 0; i < type.length(); i++) {
                slotNames.add(rootName + "__" + i);
            }
            boolean elemIsArray = type.element() instanceof FixedArrayType;
            ArrayMeta meta = new ArrayMeta(
                rootName, type, slotNames, elemIsArray, type.element()
            );
            if (elemIsArray) {
                FixedArrayType inner = (FixedArrayType) type.element();
                for (String slot : slotNames) {
                    ArrayMeta sub = buildArrayMeta(slot, inner, loc);
                    if (sub == null) {
                        return null;
                    }
                    meta.nested.put(slot, sub);
                    syntheticArrays.put(slot, sub);
                }
            }
            return meta;
        }

        // --------------------------------------------------------------
        // Property rewriting (initializer distribution)
        // --------------------------------------------------------------

        List<PropertyNode> rewriteProperties() {
            List<PropertyNode> out = new ArrayList<>();
            for (PropertyNode prop : contract.properties()) {
                if (!(prop.type() instanceof FixedArrayType)) {
                    out.add(prop);
                    continue;
                }
                ArrayMeta meta = arrayMap.get(prop.name());
                if (meta == null) continue;
                List<PropertyNode> expanded = expandPropertyRoot(prop, meta);
                out.addAll(expanded);
            }
            return out;
        }

        List<PropertyNode> expandPropertyRoot(PropertyNode prop, ArrayMeta meta) {
            ExtractResult er = extractArrayLiteralElements(prop, meta);
            if (er.error) {
                return List.of();
            }
            return expandArrayMeta(meta, prop.readonly(), prop.sourceLocation(),
                er.elements, List.of());
        }

        private static final class ExtractResult {
            final boolean error;
            final List<Expression> elements; // null if no initializer
            ExtractResult(boolean error, List<Expression> elements) {
                this.error = error;
                this.elements = elements;
            }
        }

        ExtractResult extractArrayLiteralElements(PropertyNode prop, ArrayMeta meta) {
            if (prop.initializer() == null) {
                return new ExtractResult(false, null);
            }
            if (!(prop.initializer() instanceof ArrayLiteralExpr arr)) {
                error(
                    "Property '" + prop.name()
                        + "' of type FixedArray must use an array literal initializer",
                    prop.sourceLocation()
                );
                return new ExtractResult(true, null);
            }
            if (arr.elements().size() != meta.type.length()) {
                error(
                    "Initializer length " + arr.elements().size()
                        + " does not match FixedArray length " + meta.type.length()
                        + " for property '" + prop.name() + "'",
                    prop.sourceLocation()
                );
                return new ExtractResult(true, null);
            }
            return new ExtractResult(false, arr.elements());
        }

        List<PropertyNode> expandArrayMeta(
            ArrayMeta meta,
            boolean readonly,
            SourceLocation loc,
            List<Expression> initializer,
            List<SyntheticArrayChainEntry> parentChain
        ) {
            List<PropertyNode> out = new ArrayList<>();
            for (int i = 0; i < meta.slotNames.size(); i++) {
                String slot = meta.slotNames.get(i);
                Expression slotInit = (initializer != null) ? initializer.get(i) : null;
                List<SyntheticArrayChainEntry> chainHere = new ArrayList<>(parentChain.size() + 1);
                chainHere.addAll(parentChain);
                chainHere.add(new SyntheticArrayChainEntry(
                    meta.rootName, i, meta.slotNames.size()
                ));

                if (meta.slotIsArray) {
                    ArrayMeta nestedMeta = meta.nested.get(slot);
                    List<Expression> nestedInit = null;
                    if (slotInit != null) {
                        if (!(slotInit instanceof ArrayLiteralExpr nested)) {
                            error("Nested FixedArray element must be an array literal", loc);
                            continue;
                        }
                        if (nested.elements().size() != nestedMeta.type.length()) {
                            error(
                                "Nested FixedArray initializer length "
                                    + nested.elements().size()
                                    + " does not match expected length "
                                    + nestedMeta.type.length(),
                                loc
                            );
                            continue;
                        }
                        nestedInit = nested.elements();
                    }
                    out.addAll(expandArrayMeta(nestedMeta, readonly, loc, nestedInit, chainHere));
                } else {
                    out.add(new PropertyNode(
                        slot,
                        meta.elementType,
                        readonly,
                        slotInit,
                        loc,
                        List.copyOf(chainHere)
                    ));
                }
            }
            return out;
        }

        // --------------------------------------------------------------
        // Method rewriting
        // --------------------------------------------------------------

        MethodNode rewriteMethod(MethodNode method) {
            if (method == null) return null;
            List<Statement> newBody = rewriteStatements(method.body());
            return new MethodNode(
                method.name(),
                method.params(),
                newBody,
                method.visibility(),
                method.sourceLocation()
            );
        }

        List<Statement> rewriteStatements(List<Statement> stmts) {
            List<Statement> out = new ArrayList<>();
            for (Statement s : stmts) {
                out.addAll(rewriteStatement(s));
            }
            return out;
        }

        List<Statement> rewriteStatement(Statement stmt) {
            if (stmt instanceof VariableDeclStatement v) return rewriteVariableDecl(v);
            if (stmt instanceof AssignmentStatement a) return rewriteAssignment(a);
            if (stmt instanceof IfStatement i) return rewriteIfStmt(i);
            if (stmt instanceof ForStatement f) return rewriteForStmt(f);
            if (stmt instanceof ReturnStatement r) return rewriteReturnStmt(r);
            if (stmt instanceof ExpressionStatement e) return rewriteExpressionStmt(e);
            return List.of(stmt);
        }

        List<Statement> rewriteVariableDecl(VariableDeclStatement stmt) {
            // Statement-form dispatch for `let v = this.board[i]` (runtime index).
            ReadAsStatements stmtForm = tryRewriteReadAsStatements(
                stmt.init(),
                new Identifier(stmt.name()),
                stmt.sourceLocation()
            );
            if (stmtForm != null) {
                VariableDeclStatement newDecl = new VariableDeclStatement(
                    stmt.name(),
                    stmt.type(),
                    stmtForm.fallbackInit,
                    stmt.sourceLocation()
                );
                List<Statement> outAll = new ArrayList<>(stmtForm.prelude);
                outAll.add(newDecl);
                outAll.addAll(stmtForm.dispatch);
                return outAll;
            }

            List<Statement> prelude = new ArrayList<>();
            Expression newInit = stmt.init() != null ? rewriteExpression(stmt.init(), prelude) : null;
            VariableDeclStatement newDecl = new VariableDeclStatement(
                stmt.name(),
                stmt.type(),
                newInit,
                stmt.sourceLocation()
            );
            List<Statement> outAll = new ArrayList<>(prelude);
            outAll.add(newDecl);
            return outAll;
        }

        List<Statement> rewriteAssignment(AssignmentStatement stmt) {
            List<Statement> prelude = new ArrayList<>();

            if (stmt.target() instanceof IndexAccessExpr idx) {
                // Try to resolve a fully literal nested chain.
                ResolveResult resolved = tryResolveLiteralIndexChain(idx);
                if (resolved.status == ResolveStatus.ERROR) {
                    return prelude;
                }
                if (resolved.status == ResolveStatus.OK) {
                    Expression rv = rewriteExpression(stmt.value(), prelude);
                    List<Statement> outAll = new ArrayList<>(prelude);
                    outAll.add(new AssignmentStatement(
                        new PropertyAccessExpr(resolved.name),
                        rv,
                        stmt.sourceLocation()
                    ));
                    return outAll;
                }

                // Top-level runtime/literal write on a known array.
                if (idx.object() instanceof PropertyAccessExpr pa
                    && arrayMap.containsKey(pa.property())) {
                    return rewriteArrayWrite(stmt, prelude);
                }

                // Non-fixed-array index target — recurse into sub-expressions.
                Expression newIndex = rewriteExpression(idx.index(), prelude);
                Expression newObj = rewriteExpression(idx.object(), prelude);
                Expression newValue = rewriteExpression(stmt.value(), prelude);
                List<Statement> outAll = new ArrayList<>(prelude);
                outAll.add(new AssignmentStatement(
                    new IndexAccessExpr(newObj, newIndex),
                    newValue,
                    stmt.sourceLocation()
                ));
                return outAll;
            }

            // Statement-form dispatch for `target = this.board[i]`.
            if (stmt.target() instanceof Identifier || stmt.target() instanceof PropertyAccessExpr) {
                ReadAsStatements sf = tryRewriteReadAsStatements(
                    stmt.value(), stmt.target(), stmt.sourceLocation()
                );
                if (sf != null) {
                    AssignmentStatement fallbackAssign = new AssignmentStatement(
                        stmt.target(),
                        sf.fallbackInit,
                        stmt.sourceLocation()
                    );
                    List<Statement> outAll = new ArrayList<>(sf.prelude);
                    outAll.add(fallbackAssign);
                    outAll.addAll(sf.dispatch);
                    return outAll;
                }
            }

            Expression newTarget = rewriteExpression(stmt.target(), prelude);
            Expression newValue = rewriteExpression(stmt.value(), prelude);
            List<Statement> outAll = new ArrayList<>(prelude);
            outAll.add(new AssignmentStatement(newTarget, newValue, stmt.sourceLocation()));
            return outAll;
        }

        List<Statement> rewriteIfStmt(IfStatement stmt) {
            List<Statement> prelude = new ArrayList<>();
            Expression newCond = rewriteExpression(stmt.condition(), prelude);
            List<Statement> newThen = rewriteStatements(stmt.thenBody());
            List<Statement> newElse = stmt.elseBody() != null
                ? rewriteStatements(stmt.elseBody())
                : null;
            List<Statement> outAll = new ArrayList<>(prelude);
            outAll.add(new IfStatement(newCond, newThen, newElse, stmt.sourceLocation()));
            return outAll;
        }

        List<Statement> rewriteForStmt(ForStatement stmt) {
            List<Statement> prelude = new ArrayList<>();
            Expression newCond = rewriteExpression(stmt.condition(), prelude);

            List<Statement> initPrelude = new ArrayList<>();
            Expression newInitInit = null;
            if (stmt.init() != null && stmt.init().init() != null) {
                newInitInit = rewriteExpression(stmt.init().init(), initPrelude);
            }
            if (!initPrelude.isEmpty()) {
                prelude.addAll(initPrelude);
            }

            List<Statement> newUpdateList = stmt.update() != null
                ? rewriteStatement(stmt.update())
                : List.of();
            List<Statement> newBody = rewriteStatements(stmt.body());
            Statement newUpdate = null;
            if (newUpdateList.size() == 1) {
                newUpdate = newUpdateList.get(0);
            } else if (!newUpdateList.isEmpty()) {
                newUpdate = newUpdateList.get(newUpdateList.size() - 1);
                newBody = new ArrayList<>(newBody);
                newBody.addAll(newUpdateList.subList(0, newUpdateList.size() - 1));
            }

            VariableDeclStatement newInitStmt = null;
            if (stmt.init() != null) {
                newInitStmt = new VariableDeclStatement(
                    stmt.init().name(),
                    stmt.init().type(),
                    newInitInit,
                    stmt.init().sourceLocation()
                );
            }

            List<Statement> outAll = new ArrayList<>(prelude);
            outAll.add(new ForStatement(
                newInitStmt,
                newCond,
                newUpdate,
                newBody,
                stmt.sourceLocation()
            ));
            return outAll;
        }

        List<Statement> rewriteReturnStmt(ReturnStatement stmt) {
            if (stmt.value() == null) return List.of(stmt);
            List<Statement> prelude = new ArrayList<>();
            Expression newValue = rewriteExpression(stmt.value(), prelude);
            List<Statement> outAll = new ArrayList<>(prelude);
            outAll.add(new ReturnStatement(newValue, stmt.sourceLocation()));
            return outAll;
        }

        List<Statement> rewriteExpressionStmt(ExpressionStatement stmt) {
            List<Statement> prelude = new ArrayList<>();
            Expression newExpr = stmt.expression() != null
                ? rewriteExpression(stmt.expression(), prelude)
                : null;
            List<Statement> outAll = new ArrayList<>(prelude);
            outAll.add(new ExpressionStatement(newExpr, stmt.sourceLocation()));
            return outAll;
        }

        // --------------------------------------------------------------
        // Expression rewriting
        // --------------------------------------------------------------

        Expression rewriteExpression(Expression expr, List<Statement> prelude) {
            if (expr == null) return null;
            if (expr instanceof IndexAccessExpr ia) {
                return rewriteIndexAccess(ia, prelude);
            }
            if (expr instanceof BinaryExpr be) {
                Expression left = rewriteExpression(be.left(), prelude);
                Expression right = rewriteExpression(be.right(), prelude);
                return new BinaryExpr(be.op(), left, right);
            }
            if (expr instanceof UnaryExpr ue) {
                Expression operand = rewriteExpression(ue.operand(), prelude);
                return new UnaryExpr(ue.op(), operand);
            }
            if (expr instanceof CallExpr ce) {
                Expression callee = rewriteExpression(ce.callee(), prelude);
                List<Expression> args = new ArrayList<>(ce.args().size());
                for (Expression a : ce.args()) {
                    args.add(rewriteExpression(a, prelude));
                }
                return new CallExpr(callee, args);
            }
            if (expr instanceof MemberExpr me) {
                Expression obj = rewriteExpression(me.object(), prelude);
                return new MemberExpr(obj, me.property());
            }
            if (expr instanceof TernaryExpr te) {
                Expression cond = rewriteExpression(te.condition(), prelude);
                Expression cons = rewriteExpression(te.consequent(), prelude);
                Expression alt = rewriteExpression(te.alternate(), prelude);
                return new TernaryExpr(cond, cons, alt);
            }
            if (expr instanceof IncrementExpr ie) {
                Expression operand = rewriteExpression(ie.operand(), prelude);
                return new IncrementExpr(operand, ie.prefix());
            }
            if (expr instanceof DecrementExpr de) {
                Expression operand = rewriteExpression(de.operand(), prelude);
                return new DecrementExpr(operand, de.prefix());
            }
            if (expr instanceof ArrayLiteralExpr al) {
                List<Expression> elements = new ArrayList<>(al.elements().size());
                for (Expression el : al.elements()) {
                    elements.add(rewriteExpression(el, prelude));
                }
                return new ArrayLiteralExpr(elements);
            }
            // Identifier, BigIntLiteral, BoolLiteral, ByteStringLiteral,
            // PropertyAccessExpr — leaf, no rewriting needed.
            return expr;
        }

        Expression rewriteIndexAccess(IndexAccessExpr expr, List<Statement> prelude) {
            // Nested fully-literal chains collapse in a single hop.
            ResolveResult nested = tryResolveLiteralIndexChain(expr);
            if (nested.status == ResolveStatus.ERROR) {
                return new BigIntLiteral(BigInteger.ZERO);
            }
            if (nested.status == ResolveStatus.OK) {
                return new PropertyAccessExpr(nested.name);
            }

            String baseName = tryResolveArrayBase(expr.object());
            if (baseName == null) {
                Expression obj = rewriteExpression(expr.object(), prelude);
                Expression idx = rewriteExpression(expr.index(), prelude);
                return new IndexAccessExpr(obj, idx);
            }

            ArrayMeta meta = arrayMap.get(baseName);
            if (meta == null) meta = syntheticArrays.get(baseName);
            if (meta == null) {
                Expression obj = rewriteExpression(expr.object(), prelude);
                Expression idx = rewriteExpression(expr.index(), prelude);
                return new IndexAccessExpr(obj, idx);
            }

            SourceLocation loc = new SourceLocation("", 0, 0);
            BigInteger lit = asLiteralIndex(expr.index());
            if (lit != null) {
                if (lit.signum() < 0
                    || lit.compareTo(BigInteger.valueOf(meta.type.length())) >= 0) {
                    error(
                        "Index " + lit + " is out of range for FixedArray of length " + meta.type.length(),
                        loc
                    );
                    return new BigIntLiteral(BigInteger.ZERO);
                }
                String slot = meta.slotNames.get(lit.intValueExact());
                return new PropertyAccessExpr(slot);
            }

            // Runtime index — nested arrays rejected, otherwise build ternary.
            if (meta.slotIsArray) {
                error("Runtime index access on a nested FixedArray is not supported", loc);
                return new BigIntLiteral(BigInteger.ZERO);
            }

            Expression rewrittenIndex = rewriteExpression(expr.index(), prelude);
            Expression indexRef = hoistIfImpure(rewrittenIndex, prelude, loc, "idx");
            return buildReadDispatchTernary(meta, indexRef);
        }

        // --------------------------------------------------------------
        // Statement-form runtime read
        // --------------------------------------------------------------

        private static final class ReadAsStatements {
            final List<Statement> prelude;
            final Expression fallbackInit;
            final List<Statement> dispatch;
            ReadAsStatements(List<Statement> prelude, Expression fallbackInit, List<Statement> dispatch) {
                this.prelude = prelude;
                this.fallbackInit = fallbackInit;
                this.dispatch = dispatch;
            }
        }

        ReadAsStatements tryRewriteReadAsStatements(
            Expression initExpr,
            Expression target,
            SourceLocation loc
        ) {
            if (!(initExpr instanceof IndexAccessExpr idx)) return null;
            String baseName = tryResolveArrayBase(idx.object());
            if (baseName == null) return null;
            ArrayMeta meta = arrayMap.get(baseName);
            if (meta == null) meta = syntheticArrays.get(baseName);
            if (meta == null) return null;
            // Literal-indexed reads handled by the expression rewriter.
            if (asLiteralIndex(idx.index()) != null) return null;
            if (meta.slotIsArray) return null;

            List<Statement> prelude = new ArrayList<>();
            Expression rewrittenIndex = rewriteExpression(idx.index(), prelude);
            Expression indexRef = hoistIfImpure(rewrittenIndex, prelude, loc, "idx");

            int n = meta.slotNames.size();
            if (n < 2) {
                return new ReadAsStatements(
                    prelude,
                    new PropertyAccessExpr(meta.slotNames.get(0)),
                    List.of()
                );
            }

            Expression fallbackInit = new PropertyAccessExpr(meta.slotNames.get(n - 1));

            List<Statement> tailElse = null;
            for (int i = n - 2; i >= 0; i--) {
                String slot = meta.slotNames.get(i);
                BinaryExpr cond = new BinaryExpr(
                    Expression.BinaryOp.EQ,
                    cloneExpression(indexRef),
                    new BigIntLiteral(BigInteger.valueOf(i))
                );
                AssignmentStatement assign = new AssignmentStatement(
                    cloneExpression(target),
                    new PropertyAccessExpr(slot),
                    loc
                );
                IfStatement ifStmt = new IfStatement(
                    cond,
                    List.of(assign),
                    tailElse, // null for innermost branch (no else)
                    loc
                );
                tailElse = List.of(ifStmt);
            }

            List<Statement> dispatch = tailElse != null
                ? new ArrayList<>(tailElse)
                : List.of();
            return new ReadAsStatements(prelude, fallbackInit, dispatch);
        }

        Expression buildReadDispatchTernary(ArrayMeta meta, Expression indexRef) {
            // Terminal = last legal slot (runtime reads do NOT bounds-check).
            Expression chain = new PropertyAccessExpr(meta.slotNames.get(meta.slotNames.size() - 1));
            for (int i = meta.slotNames.size() - 2; i >= 0; i--) {
                String slot = meta.slotNames.get(i);
                BinaryExpr cond = new BinaryExpr(
                    Expression.BinaryOp.EQ,
                    cloneExpression(indexRef),
                    new BigIntLiteral(BigInteger.valueOf(i))
                );
                chain = new TernaryExpr(cond, new PropertyAccessExpr(slot), chain);
            }
            return chain;
        }

        List<Statement> rewriteArrayWrite(AssignmentStatement stmt, List<Statement> prelude) {
            IndexAccessExpr idx = (IndexAccessExpr) stmt.target();
            PropertyAccessExpr obj = (PropertyAccessExpr) idx.object();
            ArrayMeta meta = arrayMap.get(obj.property());
            if (meta == null) {
                List<Statement> outAll = new ArrayList<>(prelude);
                outAll.add(stmt);
                return outAll;
            }

            Expression rewrittenValue = rewriteExpression(stmt.value(), prelude);
            Expression rewrittenIndex = rewriteExpression(idx.index(), prelude);
            SourceLocation loc = stmt.sourceLocation();

            BigInteger lit = asLiteralIndex(rewrittenIndex);
            if (lit != null) {
                if (lit.signum() < 0
                    || lit.compareTo(BigInteger.valueOf(meta.type.length())) >= 0) {
                    error(
                        "Index " + lit + " is out of range for FixedArray of length " + meta.type.length(),
                        loc
                    );
                    return new ArrayList<>(prelude);
                }
                if (meta.slotIsArray) {
                    error("Cannot assign to a nested FixedArray sub-array as a whole", loc);
                    return new ArrayList<>(prelude);
                }
                String slot = meta.slotNames.get(lit.intValueExact());
                List<Statement> outAll = new ArrayList<>(prelude);
                outAll.add(new AssignmentStatement(
                    new PropertyAccessExpr(slot),
                    rewrittenValue,
                    loc
                ));
                return outAll;
            }

            if (meta.slotIsArray) {
                error("Runtime index assignment on a nested FixedArray is not supported", loc);
                return new ArrayList<>(prelude);
            }

            Expression indexRef = hoistIfImpure(rewrittenIndex, prelude, loc, "idx");
            Expression valueRef = hoistIfImpure(rewrittenValue, prelude, loc, "val");
            IfStatement branches = buildWriteDispatchIf(meta, indexRef, valueRef, loc);
            List<Statement> outAll = new ArrayList<>(prelude);
            outAll.add(branches);
            return outAll;
        }

        IfStatement buildWriteDispatchIf(
            ArrayMeta meta,
            Expression indexRef,
            Expression valueRef,
            SourceLocation loc
        ) {
            // Final fallthrough = assert(false)
            ExpressionStatement assertFalse = new ExpressionStatement(
                new CallExpr(
                    new Identifier("assert"),
                    List.of(new BoolLiteral(false))
                ),
                loc
            );
            List<Statement> tail = new ArrayList<>();
            tail.add(assertFalse);
            for (int i = meta.slotNames.size() - 1; i >= 0; i--) {
                String slot = meta.slotNames.get(i);
                BinaryExpr cond = new BinaryExpr(
                    Expression.BinaryOp.EQ,
                    cloneExpression(indexRef),
                    new BigIntLiteral(BigInteger.valueOf(i))
                );
                AssignmentStatement branchAssign = new AssignmentStatement(
                    new PropertyAccessExpr(slot),
                    cloneExpression(valueRef),
                    loc
                );
                IfStatement ifStmt = new IfStatement(
                    cond,
                    List.of(branchAssign),
                    tail,
                    loc
                );
                tail = new ArrayList<>();
                tail.add(ifStmt);
            }
            return (IfStatement) tail.get(0);
        }

        // --------------------------------------------------------------
        // Helpers
        // --------------------------------------------------------------

        enum ResolveStatus { NONE, OK, ERROR }

        static final class ResolveResult {
            final ResolveStatus status;
            final String name;
            ResolveResult(ResolveStatus status, String name) {
                this.status = status;
                this.name = name;
            }
            static final ResolveResult NONE = new ResolveResult(ResolveStatus.NONE, null);
            static final ResolveResult ERR = new ResolveResult(ResolveStatus.ERROR, null);
        }

        ResolveResult tryResolveLiteralIndexChain(IndexAccessExpr expr) {
            // Collect literal indices innermost-to-outermost.
            List<Integer> literalIndices = new ArrayList<>();
            Expression cursor = expr;
            while (cursor instanceof IndexAccessExpr ia) {
                BigInteger lit = asLiteralIndex(ia.index());
                if (lit == null) return ResolveResult.NONE;
                if (lit.bitLength() >= 31) return ResolveResult.NONE; // can't fit in int
                literalIndices.add(lit.intValueExact());
                cursor = ia.object();
            }
            if (!(cursor instanceof PropertyAccessExpr pa)) return ResolveResult.NONE;
            ArrayMeta rootMeta = arrayMap.get(pa.property());
            if (rootMeta == null) return ResolveResult.NONE;

            // Reverse to outermost-first.
            List<Integer> rev = new ArrayList<>(literalIndices);
            java.util.Collections.reverse(rev);

            ArrayMeta meta = rootMeta;
            for (int level = 0; level < rev.size(); level++) {
                int idx = rev.get(level);
                if (idx < 0 || idx >= meta.type.length()) {
                    error(
                        "Index " + idx + " is out of range for FixedArray of length "
                            + meta.type.length(),
                        new SourceLocation("", 0, 0)
                    );
                    return ResolveResult.ERR;
                }
                String slot = meta.slotNames.get(idx);
                if (level == rev.size() - 1) {
                    if (meta.slotIsArray) return ResolveResult.NONE;
                    return new ResolveResult(ResolveStatus.OK, slot);
                }
                if (!meta.slotIsArray) return ResolveResult.NONE;
                meta = meta.nested.get(slot);
            }
            return ResolveResult.NONE;
        }

        String tryResolveArrayBase(Expression obj) {
            if (!(obj instanceof PropertyAccessExpr pa)) return null;
            if (arrayMap.containsKey(pa.property())) return pa.property();
            if (syntheticArrays.containsKey(pa.property())) return pa.property();
            return null;
        }

        BigInteger asLiteralIndex(Expression expr) {
            if (expr instanceof BigIntLiteral lit) return lit.value();
            if (expr instanceof UnaryExpr u
                && u.op() == Expression.UnaryOp.NEG
                && u.operand() instanceof BigIntLiteral lit2) {
                return lit2.value().negate();
            }
            return null;
        }

        Expression hoistIfImpure(
            Expression expr,
            List<Statement> prelude,
            SourceLocation loc,
            String tag
        ) {
            if (isPureReference(expr)) return expr;
            String name = "idx".equals(tag) ? freshIdxName() : freshValName();
            VariableDeclStatement decl = new VariableDeclStatement(
                name, null, expr, loc
            );
            prelude.add(decl);
            return new Identifier(name);
        }
    }

    // ------------------------------------------------------------------
    // Stateless helpers
    // ------------------------------------------------------------------

    private static boolean isPureReference(Expression expr) {
        if (expr instanceof Identifier
            || expr instanceof BigIntLiteral
            || expr instanceof BoolLiteral
            || expr instanceof ByteStringLiteral
            || expr instanceof PropertyAccessExpr) {
            return true;
        }
        if (expr instanceof UnaryExpr u
            && u.op() == Expression.UnaryOp.NEG
            && u.operand() instanceof BigIntLiteral) {
            return true;
        }
        return false;
    }

    private static Expression cloneExpression(Expression expr) {
        if (expr instanceof BigIntLiteral lit) return new BigIntLiteral(lit.value());
        if (expr instanceof BoolLiteral lit) return new BoolLiteral(lit.value());
        if (expr instanceof ByteStringLiteral lit) return new ByteStringLiteral(lit.value());
        if (expr instanceof Identifier id) return new Identifier(id.name());
        if (expr instanceof PropertyAccessExpr pa) return new PropertyAccessExpr(pa.property());
        if (expr instanceof BinaryExpr be) {
            return new BinaryExpr(be.op(), cloneExpression(be.left()), cloneExpression(be.right()));
        }
        if (expr instanceof UnaryExpr ue) {
            return new UnaryExpr(ue.op(), cloneExpression(ue.operand()));
        }
        if (expr instanceof CallExpr ce) {
            List<Expression> args = new ArrayList<>(ce.args().size());
            for (Expression a : ce.args()) args.add(cloneExpression(a));
            return new CallExpr(cloneExpression(ce.callee()), args);
        }
        if (expr instanceof MemberExpr me) {
            return new MemberExpr(cloneExpression(me.object()), me.property());
        }
        if (expr instanceof TernaryExpr te) {
            return new TernaryExpr(
                cloneExpression(te.condition()),
                cloneExpression(te.consequent()),
                cloneExpression(te.alternate())
            );
        }
        if (expr instanceof IndexAccessExpr ia) {
            return new IndexAccessExpr(cloneExpression(ia.object()), cloneExpression(ia.index()));
        }
        if (expr instanceof IncrementExpr ie) {
            return new IncrementExpr(cloneExpression(ie.operand()), ie.prefix());
        }
        if (expr instanceof DecrementExpr de) {
            return new DecrementExpr(cloneExpression(de.operand()), de.prefix());
        }
        if (expr instanceof ArrayLiteralExpr al) {
            List<Expression> elements = new ArrayList<>(al.elements().size());
            for (Expression e : al.elements()) elements.add(cloneExpression(e));
            return new ArrayLiteralExpr(elements);
        }
        return expr;
    }
}
