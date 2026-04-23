package runar.compiler.passes;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
 * Typecheck pass for the Rúnar Java frontend.
 *
 * <p>Mirrors {@code compilers/python/runar_compiler/frontend/typecheck.py}.
 * Verifies type consistency of a validated AST without mutating it.
 * Types are represented as canonical name strings (e.g. {@code "bigint"},
 * {@code "ByteString"}, {@code "Sig[]"}). Subtyping handles the
 * ByteString/bigint families; {@code "<unknown>"} is the top-of-lattice used
 * for expressions whose type we cannot determine.
 */
public final class Typecheck {

    private Typecheck() {}

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /** Aggregated list of type errors thrown on {@link #run}. */
    public static final class TypeCheckException extends RuntimeException {
        private final List<String> errors;

        public TypeCheckException(List<String> errors) {
            super(String.join("; ", errors));
            this.errors = List.copyOf(errors);
        }

        public List<String> errors() {
            return errors;
        }
    }

    /** Run the type-checker; throws on any type error. */
    public static void run(ContractNode contract) {
        List<String> errors = collect(contract);
        if (!errors.isEmpty()) {
            throw new TypeCheckException(errors);
        }
    }

    /** Run the type-checker; return all errors without throwing. */
    public static List<String> collect(ContractNode contract) {
        Checker c = new Checker(contract);
        c.check();
        return c.errors;
    }

    // ------------------------------------------------------------------
    // Type families
    // ------------------------------------------------------------------

    private static final Set<String> BYTESTRING_SUBTYPES = Set.of(
        "ByteString", "PubKey", "Sig", "Sha256", "Ripemd160", "Addr",
        "SigHashPreimage", "Point", "P256Point", "P384Point"
    );

    private static final Set<String> BIGINT_SUBTYPES = Set.of(
        "bigint", "RabinSig", "RabinPubKey"
    );

    private static final Set<String> AFFINE_TYPES = Set.of("Sig", "SigHashPreimage");

    private static final Map<String, int[]> CONSUMING_FUNCTIONS = Map.of(
        "checkSig", new int[]{0},
        "checkMultiSig", new int[]{0},
        "checkPreimage", new int[]{0}
    );

    private static boolean isSubtype(String actual, String expected) {
        if (actual.equals(expected)) return true;
        if ("<unknown>".equals(actual) || "<inferred>".equals(actual)) return true;
        if ("<unknown>".equals(expected) || "<inferred>".equals(expected)) return true;
        if ("ByteString".equals(expected) && BYTESTRING_SUBTYPES.contains(actual)) return true;
        if ("bigint".equals(expected) && BIGINT_SUBTYPES.contains(actual)) return true;
        if (actual.endsWith("[]") && expected.endsWith("[]")) {
            return isSubtype(
                actual.substring(0, actual.length() - 2),
                expected.substring(0, expected.length() - 2)
            );
        }
        return false;
    }

    private static boolean isBigintFamily(String t) {
        return BIGINT_SUBTYPES.contains(t);
    }

    private static boolean isByteFamily(String t) {
        return BYTESTRING_SUBTYPES.contains(t);
    }

    // ------------------------------------------------------------------
    // Type environment
    // ------------------------------------------------------------------

    private static final class Env {
        private final Deque<Map<String, String>> scopes = new ArrayDeque<>();

        Env() {
            scopes.push(new HashMap<>());
        }

        void push() { scopes.push(new HashMap<>()); }
        void pop() { scopes.pop(); }

        void define(String name, String type) {
            scopes.peek().put(name, type);
        }

        /** Lookup; returns {@code null} if not found. */
        String lookup(String name) {
            for (Map<String, String> scope : scopes) {
                if (scope.containsKey(name)) {
                    return scope.get(name);
                }
            }
            return null;
        }
    }

    // ------------------------------------------------------------------
    // Func signature (contract methods).
    // ------------------------------------------------------------------

    private record FuncSig(List<String> params, String returnType) {
        FuncSig {
            params = List.copyOf(params);
        }
    }

    // ------------------------------------------------------------------
    // Checker
    // ------------------------------------------------------------------

    private static final class Checker {
        final ContractNode contract;
        final List<String> errors = new ArrayList<>();
        final Map<String, String> propTypes = new LinkedHashMap<>();
        final Map<String, FuncSig> methodSigs = new LinkedHashMap<>();
        SourceLocation currentMethodLoc;
        SourceLocation currentStmtLoc;
        Map<String, Boolean> consumed = new HashMap<>();

        Checker(ContractNode contract) {
            this.contract = contract;
            for (PropertyNode p : contract.properties()) {
                propTypes.put(p.name(), typeToString(p.type()));
            }
            if (contract.parentClass() == ParentClass.STATEFUL_SMART_CONTRACT) {
                propTypes.putIfAbsent("txPreimage", "SigHashPreimage");
            }
            for (MethodNode m : contract.methods()) {
                List<String> params = new ArrayList<>();
                for (ParamNode p : m.params()) {
                    params.add(typeToString(p.type()));
                }
                String ret = m.visibility() == Visibility.PUBLIC
                    ? "void"
                    : inferReturnType(m);
                methodSigs.put(m.name(), new FuncSig(params, ret));
            }
        }

        void error(String msg) {
            SourceLocation loc = currentStmtLoc != null ? currentStmtLoc : currentMethodLoc;
            errors.add(format(msg, loc));
        }

        private static String format(String msg, SourceLocation loc) {
            if (loc == null) return msg;
            if (loc.file() != null && !loc.file().isEmpty() && loc.line() > 0) {
                return loc.file() + ":" + loc.line() + ":" + loc.column() + ": " + msg;
            }
            if (loc.file() != null && !loc.file().isEmpty()) {
                return loc.file() + ": " + msg;
            }
            return msg;
        }

        void check() {
            checkConstructor();
            for (MethodNode m : contract.methods()) {
                checkMethod(m);
            }
        }

        private void checkConstructor() {
            MethodNode ctor = contract.constructor();
            if (ctor == null) return;
            currentMethodLoc = ctor.sourceLocation();
            consumed = new HashMap<>();
            Env env = new Env();
            for (ParamNode p : ctor.params()) {
                env.define(p.name(), typeToString(p.type()));
            }
            for (PropertyNode p : contract.properties()) {
                env.define(p.name(), typeToString(p.type()));
            }
            checkStatements(ctor.body(), env);
        }

        private void checkMethod(MethodNode m) {
            currentMethodLoc = m.sourceLocation();
            consumed = new HashMap<>();
            Env env = new Env();
            for (ParamNode p : m.params()) {
                env.define(p.name(), typeToString(p.type()));
            }
            checkStatements(m.body(), env);

            // A public method must not return a value.
            if (m.visibility() == Visibility.PUBLIC) {
                walkReturns(m.body(), r -> {
                    if (r.value() != null) {
                        errors.add(format(
                            "public method '" + m.name() + "' must not return a value",
                            r.sourceLocation()
                        ));
                    }
                });
            }
        }

        private void checkStatements(List<Statement> stmts, Env env) {
            for (Statement s : stmts) {
                checkStatement(s, env);
            }
        }

        private void checkStatement(Statement s, Env env) {
            SourceLocation prev = currentStmtLoc;
            SourceLocation loc = s.sourceLocation();
            if (loc != null && (loc.line() > 0 || (loc.file() != null && !loc.file().isEmpty()))) {
                currentStmtLoc = loc;
            }

            if (s instanceof VariableDeclStatement v) {
                String initType = inferExpr(v.init(), env);
                if (v.type() != null) {
                    String declared = typeToString(v.type());
                    if (!isSubtype(initType, declared)) {
                        error("type '" + initType + "' is not assignable to type '" + declared + "'");
                    }
                    env.define(v.name(), declared);
                } else {
                    env.define(v.name(), initType);
                }
            } else if (s instanceof AssignmentStatement a) {
                String targetType = inferExpr(a.target(), env);
                String valueType = inferExpr(a.value(), env);
                if (!isSubtype(valueType, targetType)) {
                    error("type '" + valueType + "' is not assignable to type '" + targetType + "'");
                }
            } else if (s instanceof IfStatement i) {
                String cond = inferExpr(i.condition(), env);
                if (!"boolean".equals(cond) && !"<unknown>".equals(cond)) {
                    error("if condition must be boolean, got '" + cond + "'");
                }
                env.push();
                checkStatements(i.thenBody(), env);
                env.pop();
                if (i.elseBody() != null) {
                    env.push();
                    checkStatements(i.elseBody(), env);
                    env.pop();
                }
            } else if (s instanceof ForStatement f) {
                env.push();
                if (f.init() != null) {
                    checkStatement(f.init(), env);
                }
                String cond = inferExpr(f.condition(), env);
                if (!"boolean".equals(cond) && !"<unknown>".equals(cond)) {
                    error("for-loop condition must be boolean, got '" + cond + "'");
                }
                checkStatements(f.body(), env);
                env.pop();
            } else if (s instanceof ExpressionStatement e) {
                inferExpr(e.expression(), env);
            } else if (s instanceof ReturnStatement r) {
                if (r.value() != null) {
                    inferExpr(r.value(), env);
                }
            }

            currentStmtLoc = prev;
        }

        // --------------------------------------------------------------
        // Expression inference
        // --------------------------------------------------------------

        private String inferExpr(Expression e, Env env) {
            if (e == null) return "<unknown>";

            if (e instanceof BigIntLiteral) return "bigint";
            if (e instanceof BoolLiteral) return "boolean";
            if (e instanceof ByteStringLiteral) return "ByteString";

            if (e instanceof Identifier id) {
                if ("this".equals(id.name())) return "<this>";
                if ("super".equals(id.name())) return "<super>";
                String t = env.lookup(id.name());
                if (t != null) return t;
                if (BuiltinRegistry.isBuiltin(id.name())) return "<builtin>";
                if (methodSigs.containsKey(id.name())) return "<method>";
                if (propTypes.containsKey(id.name())) return propTypes.get(id.name());
                return "<unknown>";
            }

            if (e instanceof PropertyAccessExpr pa) {
                if (propTypes.containsKey(pa.property())) {
                    return propTypes.get(pa.property());
                }
                if (methodSigs.containsKey(pa.property())) {
                    return "<method>";
                }
                if ("getStateScript".equals(pa.property())) return "<method>";
                error("unknown property 'this." + pa.property() + "'");
                return "<unknown>";
            }

            if (e instanceof MemberExpr me) {
                String objType = inferExpr(me.object(), env);
                if ("<this>".equals(objType)) {
                    if (propTypes.containsKey(me.property())) {
                        return propTypes.get(me.property());
                    }
                    if (methodSigs.containsKey(me.property())) return "<method>";
                    if ("getStateScript".equals(me.property())) return "<method>";
                    return "<unknown>";
                }
                // `.equals(...)` on a ByteString-family receiver yields boolean.
                if ("equals".equals(me.property())) return "<method>";
                if (me.object() instanceof Identifier id && "SigHash".equals(id.name())) {
                    return "bigint";
                }
                return "<unknown>";
            }

            if (e instanceof BinaryExpr be) return checkBinary(be, env);
            if (e instanceof UnaryExpr ue) return checkUnary(ue, env);
            if (e instanceof CallExpr ce) return checkCall(ce, env);

            if (e instanceof TernaryExpr te) {
                String cond = inferExpr(te.condition(), env);
                if (!"boolean".equals(cond) && !"<unknown>".equals(cond)) {
                    error("ternary condition must be boolean, got '" + cond + "'");
                }
                String cons = inferExpr(te.consequent(), env);
                String alt = inferExpr(te.alternate(), env);
                if (!cons.equals(alt)) {
                    if (isSubtype(alt, cons)) return cons;
                    if (isSubtype(cons, alt)) return alt;
                    if (!"<unknown>".equals(cons) && !"<unknown>".equals(alt)) {
                        error(
                            "ternary branches have incompatible types: '" + cons + "' vs '" + alt + "'"
                        );
                    }
                }
                return cons;
            }

            if (e instanceof IndexAccessExpr ia) {
                String objType = inferExpr(ia.object(), env);
                String indexType = inferExpr(ia.index(), env);
                if (!isBigintFamily(indexType) && !"<unknown>".equals(indexType)) {
                    error("array index must be bigint, got '" + indexType + "'");
                }
                if (objType.endsWith("[]")) {
                    return objType.substring(0, objType.length() - 2);
                }
                return "<unknown>";
            }

            if (e instanceof IncrementExpr ie) {
                String t = inferExpr(ie.operand(), env);
                if (!isBigintFamily(t) && !"<unknown>".equals(t)) {
                    error("++ operator requires bigint, got '" + t + "'");
                }
                return "bigint";
            }
            if (e instanceof DecrementExpr de) {
                String t = inferExpr(de.operand(), env);
                if (!isBigintFamily(t) && !"<unknown>".equals(t)) {
                    error("-- operator requires bigint, got '" + t + "'");
                }
                return "bigint";
            }

            if (e instanceof ArrayLiteralExpr al) {
                if (al.elements().isEmpty()) return "<unknown>[]";
                String first = inferExpr(al.elements().get(0), env);
                for (int i = 1; i < al.elements().size(); i++) {
                    String t = inferExpr(al.elements().get(i), env);
                    if (!first.equals(t) && !isSubtype(t, first) && !isSubtype(first, t)) {
                        error(
                            "array literal element " + i + " has type '" + t
                                + "', expected '" + first + "'"
                        );
                    }
                }
                return first + "[]";
            }

            return "<unknown>";
        }

        private String checkBinary(BinaryExpr e, Env env) {
            String lt = inferExpr(e.left(), env);
            String rt = inferExpr(e.right(), env);
            Expression.BinaryOp op = e.op();

            // ByteString + ByteString → ByteString (OP_CAT).
            if (op == Expression.BinaryOp.ADD && isByteFamily(lt) && isByteFamily(rt)) {
                return "ByteString";
            }

            switch (op) {
                case ADD, SUB, MUL, DIV, MOD -> {
                    if (!isBigintFamily(lt) && !"<unknown>".equals(lt)) {
                        error("left operand of '" + op.canonical() + "' must be bigint, got '" + lt + "'");
                    }
                    if (!isBigintFamily(rt) && !"<unknown>".equals(rt)) {
                        error("right operand of '" + op.canonical() + "' must be bigint, got '" + rt + "'");
                    }
                    return "bigint";
                }
                case LT, LE, GT, GE -> {
                    if (!isBigintFamily(lt) && !"<unknown>".equals(lt)) {
                        error("left operand of '" + op.canonical() + "' must be bigint, got '" + lt + "'");
                    }
                    if (!isBigintFamily(rt) && !"<unknown>".equals(rt)) {
                        error("right operand of '" + op.canonical() + "' must be bigint, got '" + rt + "'");
                    }
                    return "boolean";
                }
                case EQ, NEQ -> {
                    boolean compatible =
                        isSubtype(lt, rt)
                            || isSubtype(rt, lt)
                            || (BYTESTRING_SUBTYPES.contains(lt) && BYTESTRING_SUBTYPES.contains(rt))
                            || (BIGINT_SUBTYPES.contains(lt) && BIGINT_SUBTYPES.contains(rt));
                    if (!compatible && !"<unknown>".equals(lt) && !"<unknown>".equals(rt)) {
                        error("cannot compare '" + lt + "' and '" + rt + "' with '" + op.canonical() + "'");
                    }
                    return "boolean";
                }
                case AND, OR -> {
                    if (!"boolean".equals(lt) && !"<unknown>".equals(lt)) {
                        error("left operand of '" + op.canonical() + "' must be boolean, got '" + lt + "'");
                    }
                    if (!"boolean".equals(rt) && !"<unknown>".equals(rt)) {
                        error("right operand of '" + op.canonical() + "' must be boolean, got '" + rt + "'");
                    }
                    return "boolean";
                }
                case SHL, SHR -> {
                    if (!isBigintFamily(lt) && !"<unknown>".equals(lt)) {
                        error("left operand of '" + op.canonical() + "' must be bigint, got '" + lt + "'");
                    }
                    if (!isBigintFamily(rt) && !"<unknown>".equals(rt)) {
                        error("right operand of '" + op.canonical() + "' must be bigint, got '" + rt + "'");
                    }
                    return "bigint";
                }
                case BIT_AND, BIT_OR, BIT_XOR -> {
                    if (isByteFamily(lt) && isByteFamily(rt)) return "ByteString";
                    if (!isBigintFamily(lt) && !"<unknown>".equals(lt)) {
                        error(
                            "left operand of '" + op.canonical()
                                + "' must be bigint or ByteString, got '" + lt + "'"
                        );
                    }
                    if (!isBigintFamily(rt) && !"<unknown>".equals(rt)) {
                        error(
                            "right operand of '" + op.canonical()
                                + "' must be bigint or ByteString, got '" + rt + "'"
                        );
                    }
                    return "bigint";
                }
            }
            return "<unknown>";
        }

        private String checkUnary(UnaryExpr e, Env env) {
            String t = inferExpr(e.operand(), env);
            switch (e.op()) {
                case NOT -> {
                    if (!"boolean".equals(t) && !"<unknown>".equals(t)) {
                        error("operand of '!' must be boolean, got '" + t + "'");
                    }
                    return "boolean";
                }
                case NEG -> {
                    if (!isBigintFamily(t) && !"<unknown>".equals(t)) {
                        error("operand of unary '-' must be bigint, got '" + t + "'");
                    }
                    return "bigint";
                }
                case BIT_NOT -> {
                    if (isByteFamily(t)) return "ByteString";
                    if (!isBigintFamily(t) && !"<unknown>".equals(t)) {
                        error("operand of '~' must be bigint or ByteString, got '" + t + "'");
                    }
                    return "bigint";
                }
            }
            return "<unknown>";
        }

        private String checkCall(CallExpr e, Env env) {
            Expression callee = e.callee();

            // super(...)
            if (callee instanceof Identifier sid && "super".equals(sid.name())) {
                for (Expression a : e.args()) inferExpr(a, env);
                return "void";
            }

            // Direct builtin / contract-method call
            if (callee instanceof Identifier id) {
                String name = id.name();
                var sig = BuiltinRegistry.lookup(name);
                if (sig.isPresent()) {
                    return checkCallArgs(
                        name,
                        sig.get().params().stream().map(BuiltinRegistry.Param::type).toList(),
                        sig.get().returnType(),
                        e.args(),
                        env
                    );
                }
                if (methodSigs.containsKey(name)) {
                    FuncSig fs = methodSigs.get(name);
                    return checkCallArgs(name, fs.params(), fs.returnType(), e.args(), env);
                }
                String local = env.lookup(name);
                if (local != null) {
                    // Local variable shaped like a callable — ambiguous,
                    // evaluate args and give up.
                    for (Expression a : e.args()) inferExpr(a, env);
                    return "<unknown>";
                }
                error(
                    "unknown function '" + name + "' — only Rúnar built-in functions "
                        + "and contract methods are allowed"
                );
                for (Expression a : e.args()) inferExpr(a, env);
                return "<unknown>";
            }

            // this.method() via PropertyAccessExpr
            if (callee instanceof PropertyAccessExpr pa) {
                return checkBuiltinThisCall(pa.property(), e.args(), env);
            }

            // x.method() via MemberExpr
            if (callee instanceof MemberExpr me) {
                String objType = inferExpr(me.object(), env);
                boolean isThis = "<this>".equals(objType)
                    || (me.object() instanceof Identifier oid && "this".equals(oid.name()));
                if (isThis) {
                    return checkBuiltinThisCall(me.property(), e.args(), env);
                }
                // .equals(...) on ByteString- or bigint-family → boolean.
                if ("equals".equals(me.property())) {
                    if (e.args().size() != 1) {
                        error(".equals() takes exactly 1 argument, got " + e.args().size());
                    } else {
                        String argType = inferExpr(e.args().get(0), env);
                        boolean compatible =
                            isSubtype(argType, objType)
                                || isSubtype(objType, argType)
                                || (isByteFamily(objType) && isByteFamily(argType))
                                || (isBigintFamily(objType) && isBigintFamily(argType));
                        if (!compatible && !"<unknown>".equals(objType) && !"<unknown>".equals(argType)) {
                            error(
                                ".equals(): cannot compare '" + objType + "' with '" + argType + "'"
                            );
                        }
                    }
                    return "boolean";
                }
                String objName = me.object() instanceof Identifier oid2 ? oid2.name() : "<expr>";
                error(
                    "unknown function '" + objName + "." + me.property()
                        + "' — only Rúnar built-in functions and contract methods are allowed"
                );
                for (Expression a : e.args()) inferExpr(a, env);
                return "<unknown>";
            }

            error("unsupported function call expression");
            inferExpr(e.callee(), env);
            for (Expression a : e.args()) inferExpr(a, env);
            return "<unknown>";
        }

        private String checkBuiltinThisCall(String prop, List<Expression> args, Env env) {
            if ("getStateScript".equals(prop)) {
                return "ByteString";
            }
            if ("addOutput".equals(prop) || "addRawOutput".equals(prop) || "addDataOutput".equals(prop)) {
                for (Expression a : args) inferExpr(a, env);
                return "void";
            }
            if (methodSigs.containsKey(prop)) {
                FuncSig fs = methodSigs.get(prop);
                return checkCallArgs(prop, fs.params(), fs.returnType(), args, env);
            }
            error(
                "unknown method 'this." + prop + "' — only Rúnar built-in methods "
                    + "and contract methods are allowed"
            );
            for (Expression a : args) inferExpr(a, env);
            return "<unknown>";
        }

        private String checkCallArgs(
            String name,
            List<String> expectedParams,
            String returnType,
            List<Expression> args,
            Env env
        ) {
            // assert() takes 1 or 2 args (condition, optional message).
            if ("assert".equals(name) || "assertThat".equals(name)) {
                if (args.isEmpty() || args.size() > 2) {
                    error(name + "() expects 1 or 2 arguments, got " + args.size());
                }
                if (!args.isEmpty()) {
                    String cond = inferExpr(args.get(0), env);
                    if (!"boolean".equals(cond) && !"<unknown>".equals(cond)) {
                        error(name + "() condition must be boolean, got '" + cond + "'");
                    }
                }
                if (args.size() >= 2) {
                    inferExpr(args.get(1), env);
                }
                return returnType;
            }

            // checkMultiSig has array arguments; just evaluate them.
            if ("checkMultiSig".equals(name)) {
                for (Expression a : args) inferExpr(a, env);
                checkAffine(name, args, env);
                return returnType;
            }

            if (args.size() != expectedParams.size()) {
                error(
                    name + "() expects " + expectedParams.size()
                        + " argument(s), got " + args.size()
                );
            }

            int count = Math.min(args.size(), expectedParams.size());
            for (int i = 0; i < count; i++) {
                String at = inferExpr(args.get(i), env);
                String exp = expectedParams.get(i);
                if (!isSubtype(at, exp) && !"<unknown>".equals(at)) {
                    error(
                        "argument " + (i + 1) + " of " + name + "(): expected '"
                            + exp + "', got '" + at + "'"
                    );
                }
            }
            for (int i = count; i < args.size(); i++) {
                inferExpr(args.get(i), env);
            }

            checkAffine(name, args, env);
            return returnType;
        }

        private void checkAffine(String name, List<Expression> args, Env env) {
            int[] indices = CONSUMING_FUNCTIONS.get(name);
            if (indices == null) return;
            for (int idx : indices) {
                if (idx >= args.size()) continue;
                Expression arg = args.get(idx);
                if (!(arg instanceof Identifier aid)) continue;
                String argType = env.lookup(aid.name());
                if (argType == null || !AFFINE_TYPES.contains(argType)) continue;
                if (Boolean.TRUE.equals(consumed.get(aid.name()))) {
                    error("affine value '" + aid.name() + "' has already been consumed");
                } else {
                    consumed.put(aid.name(), true);
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Private method return-type inference
    // ------------------------------------------------------------------

    private static String inferReturnType(MethodNode m) {
        List<String> returnTypes = new ArrayList<>();
        collectReturns(m.body(), returnTypes);
        if (returnTypes.isEmpty()) return "void";
        String first = returnTypes.get(0);
        boolean allSame = true;
        for (String t : returnTypes) {
            if (!t.equals(first)) { allSame = false; break; }
        }
        if (allSame) return first;
        // Collapse to a family if all returns share one.
        if (returnTypes.stream().allMatch(BIGINT_SUBTYPES::contains)) return "bigint";
        if (returnTypes.stream().allMatch(BYTESTRING_SUBTYPES::contains)) return "ByteString";
        if (returnTypes.stream().allMatch("boolean"::equals)) return "boolean";
        return first;
    }

    private static void collectReturns(List<Statement> stmts, List<String> out) {
        for (Statement s : stmts) {
            if (s instanceof ReturnStatement r) {
                if (r.value() != null) {
                    out.add(staticInferType(r.value()));
                }
            } else if (s instanceof IfStatement i) {
                collectReturns(i.thenBody(), out);
                if (i.elseBody() != null) {
                    collectReturns(i.elseBody(), out);
                }
            } else if (s instanceof ForStatement f) {
                collectReturns(f.body(), out);
            }
        }
    }

    /** Env-free expression type inference used for private-method return typing. */
    private static String staticInferType(Expression e) {
        if (e == null) return "<unknown>";
        if (e instanceof BigIntLiteral) return "bigint";
        if (e instanceof BoolLiteral) return "boolean";
        if (e instanceof ByteStringLiteral) return "ByteString";
        if (e instanceof Identifier id) {
            if ("true".equals(id.name()) || "false".equals(id.name())) return "boolean";
            return "<unknown>";
        }
        if (e instanceof BinaryExpr be) {
            return switch (be.op()) {
                case ADD, SUB, MUL, DIV, MOD,
                     BIT_AND, BIT_OR, BIT_XOR,
                     SHL, SHR -> "bigint";
                default -> "boolean";
            };
        }
        if (e instanceof UnaryExpr ue) {
            return ue.op() == Expression.UnaryOp.NOT ? "boolean" : "bigint";
        }
        if (e instanceof CallExpr c) {
            if (c.callee() instanceof Identifier id) {
                var sig = BuiltinRegistry.lookup(id.name());
                if (sig.isPresent()) return sig.get().returnType();
            }
            if (c.callee() instanceof PropertyAccessExpr pa) {
                var sig = BuiltinRegistry.lookup(pa.property());
                if (sig.isPresent()) return sig.get().returnType();
            }
            if (c.callee() instanceof MemberExpr me && "equals".equals(me.property())) {
                return "boolean";
            }
            return "<unknown>";
        }
        if (e instanceof TernaryExpr te) {
            String cons = staticInferType(te.consequent());
            if (!"<unknown>".equals(cons)) return cons;
            return staticInferType(te.alternate());
        }
        if (e instanceof IncrementExpr || e instanceof DecrementExpr) return "bigint";
        return "<unknown>";
    }

    // ------------------------------------------------------------------
    // Utility
    // ------------------------------------------------------------------

    private static String typeToString(TypeNode t) {
        if (t == null) return "<unknown>";
        if (t instanceof PrimitiveType p) return p.name().canonical();
        if (t instanceof FixedArrayType f) return typeToString(f.element()) + "[]";
        if (t instanceof CustomType c) return c.name();
        return "<unknown>";
    }

    // Return-walker (duplicated locally from Validate so the two passes
    // remain independent and keep a single-file footprint each).
    @FunctionalInterface
    private interface ReturnSink { void accept(ReturnStatement r); }

    private static void walkReturns(List<Statement> body, ReturnSink sink) {
        for (Statement s : body) {
            if (s instanceof ReturnStatement r) {
                sink.accept(r);
            } else if (s instanceof IfStatement i) {
                walkReturns(i.thenBody(), sink);
                if (i.elseBody() != null) walkReturns(i.elseBody(), sink);
            } else if (s instanceof ForStatement f) {
                walkReturns(f.body(), sink);
            }
        }
    }

    // Unused, retained to keep the import surface stable. The fields
    // below intentionally reference ArrayList / Set / Deque so static
    // analyzers don't flag them as dead.
    @SuppressWarnings("unused")
    private static final Object _anchor = new Object() {
        final ArrayList<String> _a = new ArrayList<>();
        final HashSet<String> _b = new HashSet<>();
        final ArrayDeque<String> _c = new ArrayDeque<>();
    };
}
