package runar.compiler.passes;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import runar.compiler.builtins.BuiltinRegistry;
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
import runar.compiler.ir.ast.PrimitiveTypeName;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.PropertyNode;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.SourceLocation;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.TernaryExpr;
import runar.compiler.ir.ast.TypeNode;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;

/**
 * Validation pass for the Rúnar Java frontend.
 *
 * <p>Direct analog of {@code compilers/python/runar_compiler/frontend/validator.py}
 * and {@code packages/runar-compiler/src/passes/02-validate.ts}. Checks the
 * AST produced by {@link runar.compiler.frontend.JavaParser} against the
 * Rúnar language subset constraints without mutating it.
 *
 * <p>Errors are accumulated and reported together, so a single run surfaces
 * every problem in a source file rather than bailing on the first one.
 */
public final class Validate {

    private Validate() {}

    // Valid property primitive types (mirrors Python _VALID_PROP_TYPES).
    private static final Set<String> VALID_PROP_TYPES = Set.of(
        "bigint", "boolean", "ByteString", "PubKey", "Sig", "Sha256",
        "Ripemd160", "Addr", "SigHashPreimage", "RabinSig", "RabinPubKey",
        "Point", "P256Point", "P384Point"
    );

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /** Result of a validation run. */
    public record Result(List<String> errors, List<String> warnings) {
        public Result {
            errors = List.copyOf(errors);
            warnings = List.copyOf(warnings);
        }
    }

    /**
     * Throws {@link ValidationException} with the aggregated list of errors
     * if the contract violates the Rúnar subset. Returns the collected
     * warnings on success (possibly empty).
     */
    public static List<String> run(ContractNode contract) {
        Result r = runCollecting(contract);
        if (!r.errors().isEmpty()) {
            throw new ValidationException(r.errors());
        }
        return r.warnings();
    }

    /** Collect both errors and warnings without throwing. */
    public static Result runCollecting(ContractNode contract) {
        Ctx ctx = new Ctx(contract);

        if (contract.name() == null || contract.name().isEmpty()) {
            ctx.error("Contract name must not be empty", null);
            return new Result(ctx.errors, ctx.warnings);
        }

        ctx.validateProperties();
        ctx.validateConstructor();
        ctx.validateMethods();
        ctx.checkNoRecursion();

        return new Result(ctx.errors, ctx.warnings);
    }

    /** Unchecked exception carrying every aggregated validation error. */
    public static final class ValidationException extends RuntimeException {
        private final List<String> errors;

        public ValidationException(List<String> errors) {
            super(String.join("; ", errors));
            this.errors = List.copyOf(errors);
        }

        public List<String> errors() {
            return errors;
        }
    }

    // ------------------------------------------------------------------
    // Internal state
    // ------------------------------------------------------------------

    private static final class Ctx {
        final ContractNode contract;
        final List<String> errors = new ArrayList<>();
        final List<String> warnings = new ArrayList<>();

        Ctx(ContractNode contract) {
            this.contract = contract;
        }

        void error(String msg, SourceLocation loc) {
            errors.add(formatAt(msg, loc));
        }

        void warn(String msg, SourceLocation loc) {
            warnings.add(formatAt(msg, loc));
        }

        private static String formatAt(String msg, SourceLocation loc) {
            if (loc == null) {
                return msg;
            }
            if (loc.file() != null && !loc.file().isEmpty() && loc.line() > 0) {
                return loc.file() + ":" + loc.line() + ":" + loc.column() + ": " + msg;
            }
            if (loc.file() != null && !loc.file().isEmpty()) {
                return loc.file() + ": " + msg;
            }
            return msg;
        }

        // --------------------------------------------------------------
        // Properties
        // --------------------------------------------------------------

        void validateProperties() {
            for (PropertyNode prop : contract.properties()) {
                validatePropertyType(prop.type(), prop.sourceLocation());

                if (contract.parentClass() == ParentClass.STATEFUL_SMART_CONTRACT
                    && "txPreimage".equals(prop.name())) {
                    error(
                        "'txPreimage' is an implicit property of StatefulSmartContract "
                            + "and must not be declared",
                        prop.sourceLocation()
                    );
                }

                if (prop.initializer() != null) {
                    validatePropertyInitializer(prop);
                }
            }

            if (contract.parentClass() == ParentClass.SMART_CONTRACT) {
                for (PropertyNode p : contract.properties()) {
                    if (!p.readonly()) {
                        error(
                            "Property '" + p.name() + "' in SmartContract must be readonly. "
                                + "Use StatefulSmartContract for mutable state.",
                            p.sourceLocation()
                        );
                    }
                }
            }

            if (contract.parentClass() == ParentClass.STATEFUL_SMART_CONTRACT) {
                boolean hasMutable = false;
                for (PropertyNode p : contract.properties()) {
                    if (!p.readonly()) {
                        hasMutable = true;
                        break;
                    }
                }
                if (!hasMutable) {
                    warn(
                        "StatefulSmartContract has no mutable properties; "
                            + "consider using SmartContract instead",
                        contract.constructor().sourceLocation()
                    );
                }
            }
        }

        private void validatePropertyType(TypeNode t, SourceLocation loc) {
            if (t == null) {
                return;
            }
            if (t instanceof PrimitiveType pt) {
                String name = pt.name().canonical();
                if (!VALID_PROP_TYPES.contains(name)) {
                    error("invalid property type '" + name + "'", loc);
                }
            } else if (t instanceof FixedArrayType fa) {
                if (fa.length() <= 0) {
                    error("FixedArray length must be a positive integer", loc);
                }
                validatePropertyType(fa.element(), loc);
            } else if (t instanceof CustomType ct) {
                error(
                    "Unsupported type '" + ct.name() + "' in property declaration",
                    loc
                );
            }
        }

        private void validatePropertyInitializer(PropertyNode prop) {
            Expression init = prop.initializer();
            if (prop.type() instanceof FixedArrayType) {
                if (!isArrayLiteralOfLiterals(init)) {
                    error(
                        "Property '" + prop.name()
                            + "' initializer must be an array literal of literal values",
                        prop.sourceLocation()
                    );
                }
            } else if (!isLiteralExpression(init)) {
                error(
                    "Property '" + prop.name()
                        + "' initializer must be a literal value "
                        + "(bigint, boolean, or hex byte string)",
                    prop.sourceLocation()
                );
            }
        }

        // --------------------------------------------------------------
        // Constructor
        // --------------------------------------------------------------

        void validateConstructor() {
            MethodNode ctor = contract.constructor();
            if (ctor == null) {
                error("contract has no constructor", null);
                return;
            }

            for (ParamNode p : ctor.params()) {
                if (p.type() instanceof FixedArrayType) {
                    error(
                        "Constructor parameter '" + p.name() + "' cannot be a FixedArray. "
                            + "Use initialized properties or pass each element as a separate parameter.",
                        ctor.sourceLocation()
                    );
                }
            }

            if (ctor.body().isEmpty()) {
                error("constructor must call super() as its first statement", ctor.sourceLocation());
                return;
            }

            if (!isSuperCall(ctor.body().get(0))) {
                error("constructor must call super() as its first statement", ctor.sourceLocation());
            }

            Set<String> assignedProps = new HashSet<>();
            for (Statement s : ctor.body()) {
                if (s instanceof AssignmentStatement a && a.target() instanceof PropertyAccessExpr pa) {
                    assignedProps.add(pa.property());
                }
            }
            Set<String> propsWithInit = new HashSet<>();
            for (PropertyNode p : contract.properties()) {
                if (p.initializer() != null) {
                    propsWithInit.add(p.name());
                }
            }

            for (PropertyNode p : contract.properties()) {
                if (!assignedProps.contains(p.name()) && !propsWithInit.contains(p.name())) {
                    error(
                        "property '" + p.name() + "' must be assigned in the constructor",
                        ctor.sourceLocation()
                    );
                }
            }

            for (Statement s : ctor.body()) {
                validateStatement(s);
            }
        }

        // --------------------------------------------------------------
        // Methods
        // --------------------------------------------------------------

        void validateMethods() {
            for (MethodNode m : contract.methods()) {
                validateMethod(m);
            }
        }

        private void validateMethod(MethodNode m) {
            for (ParamNode p : m.params()) {
                if (p.type() instanceof FixedArrayType) {
                    error(
                        "Parameter '" + p.name() + "' in method '" + m.name()
                            + "' cannot be a FixedArray. "
                            + "Arrays are only allowed as contract properties.",
                        m.sourceLocation()
                    );
                }
            }

            // Public methods must not return a value. Private methods may.
            if (m.visibility() == Visibility.PUBLIC) {
                walkReturnsInBody(m.body(), returnStmt -> {
                    if (returnStmt.value() != null) {
                        error(
                            "public method '" + m.name()
                                + "' must not return a value (returned from a spending entry point)",
                            returnStmt.sourceLocation()
                        );
                    }
                });
            }

            // Public methods must end with an assert() call (unless stateful,
            // in which case the compiler auto-injects the final assert).
            if (m.visibility() == Visibility.PUBLIC
                && contract.parentClass() != ParentClass.STATEFUL_SMART_CONTRACT) {
                if (!endsWithAssert(m.body())) {
                    error(
                        "public method '" + m.name() + "' must end with an assert() / assertThat() call",
                        m.sourceLocation()
                    );
                }
            }

            for (Statement s : m.body()) {
                validateStatement(s);
            }
        }

        // --------------------------------------------------------------
        // Statements
        // --------------------------------------------------------------

        private void validateStatement(Statement s) {
            if (s instanceof VariableDeclStatement v) {
                if (v.type() instanceof FixedArrayType) {
                    error(
                        "Local variable '" + v.name() + "' cannot be a FixedArray. "
                            + "Arrays are only allowed as contract properties.",
                        v.sourceLocation()
                    );
                }
                validateExpression(v.init());
            } else if (s instanceof AssignmentStatement a) {
                validateExpression(a.target());
                validateExpression(a.value());
            } else if (s instanceof IfStatement i) {
                validateExpression(i.condition());
                for (Statement st : i.thenBody()) {
                    validateStatement(st);
                }
                if (i.elseBody() != null) {
                    for (Statement st : i.elseBody()) {
                        validateStatement(st);
                    }
                }
            } else if (s instanceof ForStatement f) {
                validateForStatement(f);
            } else if (s instanceof ExpressionStatement e) {
                validateExpression(e.expression());
            } else if (s instanceof ReturnStatement r) {
                if (r.value() != null) {
                    validateExpression(r.value());
                }
            }
        }

        private void validateForStatement(ForStatement f) {
            // Bounded, literal iteration count — check the right-hand side of
            // the comparison in the loop condition.
            if (f.condition() instanceof BinaryExpr be) {
                if (!isCompileTimeConstant(be.right())) {
                    error("for-loop bound must be a compile-time constant", f.sourceLocation());
                }
            } else {
                error("for-loop condition must be a comparison against a compile-time constant",
                    f.sourceLocation());
            }
            validateExpression(f.condition());
            if (f.init() != null) {
                validateExpression(f.init().init());
            }
            for (Statement s : f.body()) {
                validateStatement(s);
            }
        }

        // --------------------------------------------------------------
        // Expressions
        // --------------------------------------------------------------

        private void validateExpression(Expression e) {
            if (e == null) {
                return;
            }
            if (e instanceof BinaryExpr be) {
                validateExpression(be.left());
                validateExpression(be.right());
            } else if (e instanceof UnaryExpr ue) {
                validateExpression(ue.operand());
            } else if (e instanceof CallExpr c) {
                validateCall(c);
            } else if (e instanceof MemberExpr me) {
                validateExpression(me.object());
            } else if (e instanceof TernaryExpr te) {
                validateExpression(te.condition());
                validateExpression(te.consequent());
                validateExpression(te.alternate());
            } else if (e instanceof IndexAccessExpr ia) {
                validateExpression(ia.object());
                validateExpression(ia.index());
            } else if (e instanceof IncrementExpr ie) {
                validateExpression(ie.operand());
            } else if (e instanceof DecrementExpr de) {
                validateExpression(de.operand());
            } else if (e instanceof ByteStringLiteral bsl) {
                validateByteString(bsl);
            } else if (e instanceof ArrayLiteralExpr al) {
                for (Expression el : al.elements()) {
                    validateExpression(el);
                }
            }
        }

        private void validateCall(CallExpr call) {
            // Reject unknown free-function calls (not a builtin, not a
            // known method, not a known value-in-scope). The type-checker
            // re-does this with richer information; here we only care
            // about obviously-bogus callees so the validator surfaces the
            // issue as an error even if the typecheck pass is skipped.
            Expression callee = call.callee();
            if (callee instanceof Identifier id) {
                String name = id.name();
                if (!"super".equals(name)
                    && !BuiltinRegistry.isBuiltin(name)
                    && !isContractMethod(name)) {
                    error(
                        "unknown function '" + name + "' — only Rúnar built-in "
                            + "functions and contract methods are allowed",
                        null
                    );
                }
            }
            validateExpression(call.callee());
            boolean isAssert = callee instanceof Identifier idc
                && ("assert".equals(idc.name()) || "assertThat".equals(idc.name()));
            for (int i = 0; i < call.args().size(); i++) {
                // assert() allows a string message as the 2nd argument; skip
                // the hex-literal validator there (strings are rejected at
                // parse time anyway, but keep the structure consistent with
                // the Python/TS reference).
                if (isAssert && i >= 1) {
                    continue;
                }
                validateExpression(call.args().get(i));
            }
        }

        private boolean isContractMethod(String name) {
            for (MethodNode m : contract.methods()) {
                if (m.name().equals(name)) {
                    return true;
                }
            }
            return false;
        }

        private void validateByteString(ByteStringLiteral lit) {
            String v = lit.value();
            if (v == null) {
                error("ByteString literal has null value", null);
                return;
            }
            if (v.isEmpty()) {
                return;
            }
            if (v.length() % 2 != 0) {
                error(
                    "ByteString literal '" + v + "' has odd length (" + v.length()
                        + ") — hex strings must have an even number of characters",
                    null
                );
                return;
            }
            for (int i = 0; i < v.length(); i++) {
                char c = v.charAt(i);
                boolean ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!ok) {
                    error(
                        "ByteString literal '" + v + "' contains non-hex characters "
                            + "— only 0-9, a-f, A-F are allowed",
                        null
                    );
                    return;
                }
            }
        }

        // --------------------------------------------------------------
        // Recursion detection
        // --------------------------------------------------------------

        void checkNoRecursion() {
            Set<String> methodNames = new HashSet<>();
            for (MethodNode m : contract.methods()) {
                methodNames.add(m.name());
            }
            java.util.Map<String, Set<String>> callGraph = new java.util.HashMap<>();
            for (MethodNode m : contract.methods()) {
                Set<String> calls = new HashSet<>();
                collectMethodCalls(m.body(), calls);
                callGraph.put(m.name(), calls);
            }
            for (MethodNode m : contract.methods()) {
                if (hasCycle(m.name(), callGraph, methodNames, new HashSet<>(), new HashSet<>())) {
                    error(
                        "recursion detected: method '" + m.name()
                            + "' calls itself directly or indirectly",
                        m.sourceLocation()
                    );
                }
            }
        }

        private static boolean hasCycle(
            String name,
            java.util.Map<String, Set<String>> callGraph,
            Set<String> methodNames,
            Set<String> visited,
            Set<String> stack
        ) {
            if (stack.contains(name)) {
                return true;
            }
            if (visited.contains(name)) {
                return false;
            }
            visited.add(name);
            stack.add(name);
            Set<String> callees = callGraph.getOrDefault(name, Set.of());
            for (String callee : callees) {
                if (methodNames.contains(callee)) {
                    if (hasCycle(callee, callGraph, methodNames, visited, stack)) {
                        return true;
                    }
                }
            }
            stack.remove(name);
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Shared static helpers
    // ------------------------------------------------------------------

    private static boolean isLiteralExpression(Expression e) {
        if (e instanceof BigIntLiteral) return true;
        if (e instanceof BoolLiteral) return true;
        if (e instanceof ByteStringLiteral) return true;
        if (e instanceof UnaryExpr u
            && u.op() == Expression.UnaryOp.NEG
            && u.operand() instanceof BigIntLiteral) {
            return true;
        }
        return false;
    }

    private static boolean isArrayLiteralOfLiterals(Expression e) {
        if (!(e instanceof ArrayLiteralExpr arr)) {
            return false;
        }
        for (Expression el : arr.elements()) {
            if (el instanceof ArrayLiteralExpr) {
                if (!isArrayLiteralOfLiterals(el)) {
                    return false;
                }
            } else if (!isLiteralExpression(el)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isSuperCall(Statement s) {
        if (!(s instanceof ExpressionStatement es)) return false;
        if (!(es.expression() instanceof CallExpr c)) return false;
        Expression callee = c.callee();
        if (callee instanceof Identifier id) {
            return "super".equals(id.name());
        }
        if (callee instanceof MemberExpr me) {
            return me.object() instanceof Identifier id && "super".equals(id.name());
        }
        return false;
    }

    private static boolean endsWithAssert(List<Statement> body) {
        if (body.isEmpty()) return false;
        Statement last = body.get(body.size() - 1);
        if (last instanceof ExpressionStatement es) {
            return isAssertCall(es.expression());
        }
        if (last instanceof IfStatement it) {
            boolean thenEnds = endsWithAssert(it.thenBody());
            boolean elseEnds = it.elseBody() != null && endsWithAssert(it.elseBody());
            return thenEnds && elseEnds;
        }
        return false;
    }

    private static boolean isAssertCall(Expression e) {
        if (!(e instanceof CallExpr c)) return false;
        if (!(c.callee() instanceof Identifier id)) return false;
        return "assert".equals(id.name()) || "assertThat".equals(id.name());
    }

    private static boolean isCompileTimeConstant(Expression e) {
        if (e == null) return false;
        if (e instanceof BigIntLiteral) return true;
        if (e instanceof BoolLiteral) return true;
        // An identifier may refer to a local `final` constant — trust it.
        if (e instanceof Identifier) return true;
        if (e instanceof UnaryExpr u && u.op() == Expression.UnaryOp.NEG) {
            return isCompileTimeConstant(u.operand());
        }
        return false;
    }

    // ------------------------------------------------------------------
    // Return-walker: invokes the callback on every ReturnStatement.
    // ------------------------------------------------------------------

    @FunctionalInterface
    private interface ReturnSink {
        void accept(ReturnStatement r);
    }

    private static void walkReturnsInBody(List<Statement> body, ReturnSink sink) {
        for (Statement s : body) {
            walkReturnsInStmt(s, sink);
        }
    }

    private static void walkReturnsInStmt(Statement s, ReturnSink sink) {
        if (s instanceof ReturnStatement r) {
            sink.accept(r);
        } else if (s instanceof IfStatement i) {
            walkReturnsInBody(i.thenBody(), sink);
            if (i.elseBody() != null) {
                walkReturnsInBody(i.elseBody(), sink);
            }
        } else if (s instanceof ForStatement f) {
            walkReturnsInBody(f.body(), sink);
        }
    }

    // ------------------------------------------------------------------
    // Call-graph collection for recursion check
    // ------------------------------------------------------------------

    private static void collectMethodCalls(List<Statement> body, Set<String> out) {
        for (Statement s : body) {
            collectMethodCallsInStmt(s, out);
        }
    }

    private static void collectMethodCallsInStmt(Statement s, Set<String> out) {
        if (s instanceof ExpressionStatement es) {
            collectMethodCallsInExpr(es.expression(), out);
        } else if (s instanceof VariableDeclStatement v) {
            collectMethodCallsInExpr(v.init(), out);
        } else if (s instanceof AssignmentStatement a) {
            collectMethodCallsInExpr(a.target(), out);
            collectMethodCallsInExpr(a.value(), out);
        } else if (s instanceof IfStatement i) {
            collectMethodCallsInExpr(i.condition(), out);
            collectMethodCalls(i.thenBody(), out);
            if (i.elseBody() != null) {
                collectMethodCalls(i.elseBody(), out);
            }
        } else if (s instanceof ForStatement f) {
            collectMethodCallsInExpr(f.condition(), out);
            collectMethodCalls(f.body(), out);
        } else if (s instanceof ReturnStatement r) {
            if (r.value() != null) {
                collectMethodCallsInExpr(r.value(), out);
            }
        }
    }

    private static void collectMethodCallsInExpr(Expression e, Set<String> out) {
        if (e == null) return;
        if (e instanceof CallExpr c) {
            if (c.callee() instanceof PropertyAccessExpr pa) {
                out.add(pa.property());
            }
            if (c.callee() instanceof MemberExpr me
                && me.object() instanceof Identifier id
                && "this".equals(id.name())) {
                out.add(me.property());
            }
            collectMethodCallsInExpr(c.callee(), out);
            for (Expression arg : c.args()) {
                collectMethodCallsInExpr(arg, out);
            }
        } else if (e instanceof BinaryExpr be) {
            collectMethodCallsInExpr(be.left(), out);
            collectMethodCallsInExpr(be.right(), out);
        } else if (e instanceof UnaryExpr ue) {
            collectMethodCallsInExpr(ue.operand(), out);
        } else if (e instanceof MemberExpr me) {
            collectMethodCallsInExpr(me.object(), out);
        } else if (e instanceof TernaryExpr te) {
            collectMethodCallsInExpr(te.condition(), out);
            collectMethodCallsInExpr(te.consequent(), out);
            collectMethodCallsInExpr(te.alternate(), out);
        } else if (e instanceof IndexAccessExpr ia) {
            collectMethodCallsInExpr(ia.object(), out);
            collectMethodCallsInExpr(ia.index(), out);
        } else if (e instanceof IncrementExpr ie) {
            collectMethodCallsInExpr(ie.operand(), out);
        } else if (e instanceof DecrementExpr de) {
            collectMethodCallsInExpr(de.operand(), out);
        } else if (e instanceof ArrayLiteralExpr al) {
            for (Expression el : al.elements()) {
                collectMethodCallsInExpr(el, out);
            }
        }
    }

    @SuppressWarnings("unused")
    private static String primitiveName(PrimitiveTypeName p) {
        return p == null ? "<unknown>" : p.canonical();
    }
}
