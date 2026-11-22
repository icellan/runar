package runar.compiler.passes;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
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
import runar.compiler.ir.ast.OperandTypeSlot.OperandType;
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

    /** F-024 (R14): the one diagnostic every tier emits for a write to continuationAmount(). */
    public static final String CONTINUATION_AMOUNT_READ_ONLY =
        "continuationAmount() is read-only and cannot be assigned";

    private Typecheck() {}

    /** N-464: the N-463 expression position rule, for the validator's anchors. */
    static SourceLocation exprLoc(Expression e) {
        return Checker.exprLoc(e);
    }

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

    /**
     * N-076: this is the SINGLE source of truth for "is a value of this type a
     * byte string or a script number?", and {@code AnfLower} consults it
     * through {@link #isByteStringFamily} rather than keeping a second copy.
     * The copy it replaces carried {@code RabinSig} and {@code RabinPubKey},
     * which {@link #BIGINT_SUBTYPES} right below files as NUMBERS -- so
     * {@code ===} on a Rabin value emitted OP_EQUAL and, far worse, {@code +}
     * on one emitted OP_CAT where the source said addition.
     */
    static final Set<String> BYTESTRING_SUBTYPES = Set.of(
        "ByteString", "PubKey", "Sig", "Sha256", "Ripemd160", "Addr",
        "SigHashPreimage", "Point", "P256Point", "P384Point"
    );

    /**
     * Whether a value of this type sits on the stack as a BYTE STRING rather
     * than as a script NUMBER. Anything NOT in this family is numeric:
     * compared with OP_NUMEQUAL, added with OP_ADD.
     */
    static boolean isByteStringFamily(String typeName) {
        return BYTESTRING_SUBTYPES.contains(typeName);
    }

    /**
     * Whether the builtin {@code name} returns a ByteString-family value.
     *
     * <p>N-347: {@code AnfLower} answers "is {@code f(x)} a byte string?" from
     * this, i.e. from the return type {@link BuiltinRegistry} records for the
     * builtin, instead of keeping its own hand-written list. That list drifted
     * twice (N-054, N-345) and was still missing merkleRootSha256 /
     * merkleRootHash256 / bn254G1Add / bn254G1Negate / bn254G1ScalarMul, so
     * {@code f(a) === f(b)} on them was not annotated {@code bytes}.
     */
    static boolean isByteReturningBuiltin(String name) {
        return BuiltinRegistry.lookup(name)
            .map(sig -> isByteStringFamily(sig.returnType()))
            .orElse(false);
    }

    private static final Set<String> BIGINT_SUBTYPES = Set.of(
        "bigint", "RabinSig", "RabinPubKey"
    );

    private static final Set<String> AFFINE_TYPES = Set.of("Sig", "SigHashPreimage");

    private static final Map<String, int[]> CONSUMING_FUNCTIONS = Map.of(
        "checkSig", new int[]{0},
        "checkMultiSig", new int[]{0},
        "checkPreimage", new int[]{0}
    );

    /**
     * Whether a value of type {@code actual} may be used where {@code expected}
     * is required. The port of {@code isSubtype} in
     * {@code packages/runar-compiler/src/passes/03-typecheck.ts}; it must stay
     * clause-for-clause identical to it.
     *
     * <p>N-104: this tier used to carry only the {@code subtype -> base}
     * direction of each family, so assignment inside a family worked one way
     * and not the other — {@code const b: ByteString = pkh} compiled and
     * {@code const h: Sha256 = pkh} did not, while the reference tier accepted
     * both. Measured as a full bidirectional matrix over every ordered pair of
     * family members in all seven tiers, 85 of 196 cells disagreed. The
     * asymmetry was already known to be wrong at the callsites that tripped
     * over it — this class used to carry a private
     * {@code outputStateValueMatches} that re-added the missing clauses just
     * for {@code addOutput}'s state values, and four tiers had independently
     * grown the same patch. The general predicate carries them now, and the
     * patches are gone.
     *
     * <p>Cross-family moves (a ByteString into a bigint slot or the reverse)
     * are still refused, in every tier; that is what
     * {@code conformance/negatives} N02/N16/N17/N19/N21 pin.
     */
    private static boolean isSubtype(String actual, String expected) {
        if (actual.equals(expected)) return true;
        if ("<unknown>".equals(actual) || "<inferred>".equals(actual)) return true;
        if ("<unknown>".equals(expected) || "<inferred>".equals(expected)) return true;
        // ByteString subtypes. BIDIRECTIONAL, and both-in-family — an Addr
        // value satisfies a Ripemd160 slot and vice versa.
        if ("ByteString".equals(expected) && BYTESTRING_SUBTYPES.contains(actual)) return true;
        if ("ByteString".equals(actual) && BYTESTRING_SUBTYPES.contains(expected)) return true;
        if (BYTESTRING_SUBTYPES.contains(actual) && BYTESTRING_SUBTYPES.contains(expected)) {
            return true;
        }
        // bigint subtypes — same shape.
        if ("bigint".equals(expected) && BIGINT_SUBTYPES.contains(actual)) return true;
        if ("bigint".equals(actual) && BIGINT_SUBTYPES.contains(expected)) return true;
        if (BIGINT_SUBTYPES.contains(actual) && BIGINT_SUBTYPES.contains(expected)) return true;
        if (actual.endsWith("[]") && expected.endsWith("[]")) {
            return isSubtype(
                actual.substring(0, actual.length() - 2),
                expected.substring(0, expected.length() - 2)
            );
        }
        return false;
    }

    /**
     * R-092: there is deliberately NO {@code <unknown>} escape here, and none at
     * any callsite. {@code isSubtype} treats {@code <unknown>} as top-of-lattice
     * (compatible with everything), which is what {@code ===} and argument
     * passing want. The operand positions that demand a NUMBER — arithmetic,
     * relational, shift, bitwise, unary {@code -}, unary {@code ~},
     * {@code ++}/{@code --} and array index — go through this predicate instead,
     * and they want the opposite: an operand whose type the frontend could not
     * pin down must not silently become a script number.
     *
     * <p>This tier used to carry {@code && !"<unknown>".equals(t)} at all eight,
     * so Java alone accepted programs the other six tiers reject — including
     * {@code helperReturningPubKey() > x}, which pushes 33 bytes into
     * OP_GREATERTHAN. Post-Genesis that succeeds and computes a meaningless
     * comparison, so the guard the author wrote is not the guard that reaches
     * the chain. `conformance/negatives/N15-unknown-operand-type.runar.ts` is
     * the cross-tier gate; {@code R092UnknownOperandRejectionTest} is the unit
     * gate.
     */
    // Package-visible (N-133): ExpandFixedArrays needs the same question
    // answered for FixedArray initializer elements, and must not keep a
    // second copy of BIGINT_SUBTYPES.
    static boolean isBigintFamily(String t) {
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

        /** Index (outermost = 0) of the innermost scope binding {@code name}, or -1. */
        int scopeIndexOf(String name) {
            int i = scopes.size() - 1;
            for (Map<String, String> scope : scopes) {
                if (scope.containsKey(name)) return i;
                i--;
            }
            return -1;
        }

        /** Index the next {@link #push()} will occupy. */
        int depth() { return scopes.size(); }
    }

    /**
     * F-110: whether a for-statement may execute its body two or more times.
     * Mirrors the trip count AnfLower unrolls; a shape it cannot resolve is
     * refused elsewhere and is treated as repeating here.
     */
    private static boolean loopMayRunTwice(ForStatement f) {
        BigInteger start = f.init() == null ? null : loopLiteral(f.init().init());
        if (start == null || !(f.condition() instanceof BinaryExpr b)) return true;
        BigInteger bound = loopLiteral(b.right());
        if (bound == null) return true;
        BigInteger count;
        switch (b.op()) {
            case LT -> count = bound.subtract(start);
            case LE -> count = bound.subtract(start).add(BigInteger.ONE);
            case GT -> count = start.subtract(bound);
            case GE -> count = start.subtract(bound).add(BigInteger.ONE);
            default -> { return true; }
        }
        return count.compareTo(BigInteger.TWO) >= 0;
    }

    private static BigInteger loopLiteral(Expression e) {
        if (e instanceof BigIntLiteral l) return l.value();
        if (e instanceof UnaryExpr u && u.op() == Expression.UnaryOp.NEG) {
            BigInteger inner = loopLiteral(u.operand());
            return inner == null ? null : inner.negate();
        }
        return null;
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

    /**
     * Names that are legal without being a local, a builtin, a method or a
     * property: the {@code SigHash} namespace object and the three secp256k1
     * constants from runar-lang. Every frontend hands them to the typechecker
     * as bare identifiers. They used to be carried by the {@code "<unknown>"}
     * fall-through; once that fall-through raises they have to be listed,
     * exactly as the TS reference tier lists them in KNOWN_GLOBALS.
     */
    private static final Map<String, String> KNOWN_GLOBALS = Map.of(
            "SigHash", "<namespace>",
            "EC_P", "bigint",
            "EC_N", "bigint",
            "EC_G", "Point");

    private static final class Checker {
        final ContractNode contract;
        final List<String> errors = new ArrayList<>();
        final Map<String, String> propTypes = new LinkedHashMap<>();
        final Map<String, FuncSig> methodSigs = new LinkedHashMap<>();
        SourceLocation currentMethodLoc;
        SourceLocation currentStmtLoc;
        Map<String, Boolean> consumed = new HashMap<>();
        // Maps a local name to the canonical affine origin it
        // aliases. 2026-04-30 audit finding F6.
        Map<String, String> affineAliases = new HashMap<>();
        // F-110: for every enclosing loop that may run two or more times, the
        // env scope index its init/body bindings live at (innermost last). A
        // bounded loop is unrolled `count` times, so consuming an affine value
        // bound below the innermost index happens once per iteration.
        final Deque<Integer> repeatingLoopScopes = new ArrayDeque<>();
        // N-109: for every contract method, the indices of the parameters it
        // consumes (directly or through further helper calls). Private helpers
        // are inlined, so a call consumes the arguments at those positions.
        // N-288: each entry also carries the "prop:<name>" origins the method
        // consumes, which a call consumes in the caller.
        // Computed lazily by consumedParamSummary.
        Map<String, MethodConsumption> consumedParams;

        /**
         * D12 FE-F4: inferred return types of undeclared private methods.
         * Shared by reference with every scratch checker this one creates, so
         * the recursion guard ({@code <unknown>} while a helper's own type is
         * being inferred) holds across them.
         */
        Map<MethodNode, String> returnMemo = new IdentityHashMap<>();

        /** D12 FE-F4: types of the {@code return} values seen (inference scratch only). */
        List<String> returnTypeSink;

        /** D12 FE-F4: the method being checked, whose declared return type is enforced. */
        MethodNode currentMethod;

        /** D12 FE-F4: types of the {@code return} values of the method being checked. */
        List<String> currentReturnTypes = new ArrayList<>();

        /**
         * D12 FE-F4: a return-type inference scratch checker only needs types;
         * it skips the affine bookkeeping (whose diagnostics it discards),
         * which would otherwise build a helper summary per inference.
         */
        boolean skipAffine;

        /**
         * N-109 / N-288: what a contract method consumes when it is called (it
         * is inlined): the indices of its affine parameters and the
         * {@code prop:<name>} origin keys of the affine properties it consumes.
         */
        private record MethodConsumption(int[] params, List<String> props) {}

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
                // D12 FE-F4: a private method's return type is resolved on
                // first use by methodSig (declared, else inferred from the
                // body with the full environment); this is a placeholder.
                String ret = m.visibility() == Visibility.PUBLIC ? "void" : "<unknown>";
                methodSigs.put(m.name(), new FuncSig(params, ret));
            }
        }

        /**
         * F-024 (R14): {@code continuationAmount()} is a read-only view of the
         * auto-injected {@code _newAmount}. Without this check an assignment to
         * it would lower as a plain read and silently drop the write.
         */
        /**
         * The signature a call of contract method {@code name} sees, with a
         * private method's return type resolved (D12 FE-F4).
         */
        FuncSig methodSig(String name) {
            FuncSig fs = methodSigs.get(name);
            if (fs == null) return null;
            for (MethodNode m : contract.methods()) {
                if (m.name().equals(name)) {
                    if (m.visibility() != Visibility.PUBLIC) {
                        return new FuncSig(fs.params(), methodReturnType(m));
                    }
                    break;
                }
            }
            return fs;
        }

        /**
         * D12 FE-F4: what a call of private method {@code m} evaluates to.
         *
         * <p>A declared return type is authoritative (checkStatement enforces
         * it on every {@code return}). Without one (Ruby has no syntax for it;
         * TypeScript may omit it) the body is type-checked by a scratch
         * checker with the real parameter environment and the types of its
         * {@code return} values are unified. Values that do not unify, and a
         * helper reached again while its own type is being inferred, are
         * {@code <unknown>}: every operator whose lowering depends on the type
         * then refuses to compile instead of guessing. Mirrors
         * {@code methodReturnType} in the TS reference 03-typecheck.ts.
         */
        String methodReturnType(MethodNode m) {
            if (m.returnType() != null) return typeToString(m.returnType());
            String known = returnMemo.get(m);
            if (known != null) return known;
            returnMemo.put(m, "<unknown>"); // recursion guard; validation refuses recursion
            Checker scratch = new Checker(contract);
            scratch.returnMemo = returnMemo;
            scratch.consumedParams = consumedParams;
            scratch.skipAffine = true;
            scratch.returnTypeSink = new ArrayList<>();
            scratch.checkMethodBody(m);
            String inferred = unifyReturnTypes(scratch.returnTypeSink);
            returnMemo.put(m, inferred);
            return inferred;
        }

        void refuseContinuationAmountWrite(Expression target) {
            if (target instanceof CallExpr c
                && c.callee() instanceof Identifier id
                && "continuationAmount".equals(id.name())) {
                error(CONTINUATION_AMOUNT_READ_ONLY);
            }
        }

        void error(String msg) {
            SourceLocation loc = currentStmtLoc != null ? currentStmtLoc : currentMethodLoc;
            errors.add(format(msg, loc));
        }

        /**
         * N-463: an error about an expression is anchored at that expression,
         * as in TS, when its position is known (the {@code .runar.ts} parser
         * records it); otherwise at the statement, then the method, as
         * {@link #error(String)} does.
         */
        void errorAt(String msg, Expression at) {
            SourceLocation loc = at == null ? null : exprLoc(at);
            if (loc == null) {
                error(msg);
            } else {
                errors.add(format(msg, loc));
            }
        }

        /**
         * N-472: an operand type error is anchored at the operand with no
         * fallback, as TS does with {@code operand.sourceLocation}. A bigint
         * or boolean literal carries no location in any TS parser, so the
         * diagnostic prints none rather than the statement. Any other operand
         * without a recorded position (a surface that does not record it)
         * keeps {@link #errorAt}'s statement anchor.
         */
        void operandErrorAt(String msg, Expression operand) {
            if (exprLoc(operand) == null && (operand instanceof BigIntLiteral || operand instanceof BoolLiteral)) {
                errors.add(format(msg, null));
                return;
            }
            errorAt(msg, operand);
        }

        /**
         * N-463: the position of {@code e}'s first token, or null when unknown.
         * Only identifiers ({@code this} included), {@code this.x} and
         * ByteString literals record a position, and only on
         * {@code .runar.ts}. A composite expression starts where its leftmost
         * child starts, which is the position TS reports for it (a
         * parenthesised leftmost child is the exception: TS points at the
         * {@code (}).
         */
        static SourceLocation exprLoc(Expression e) {
            while (true) {
                if (e instanceof Identifier id) return id.sourceLocation();
                if (e instanceof PropertyAccessExpr pa) return pa.sourceLocation();
                if (e instanceof ByteStringLiteral bs) return bs.sourceLocation();
                // N-472: the parser records where the whole
                // expression starts, which a leading `(` moves left of the
                // leftmost leaf.
                if (e instanceof BinaryExpr be) {
                    if (be.sourceLocation() != null) return be.sourceLocation();
                    e = be.left();
                }
                else if (e instanceof UnaryExpr ue) return ue.sourceLocation();
                else if (e instanceof CallExpr ce) e = ce.callee();
                else if (e instanceof MemberExpr me) e = me.object();
                else if (e instanceof IndexAccessExpr ie) e = ie.object();
                else if (e instanceof TernaryExpr te) e = te.condition();
                else return null;
            }
        }

        /** N-321: cap on a typecheck message; mirrored in every tier. */
        static final int MAX_DIAGNOSTIC_CHARS = 1024;

        private static String format(String msg, SourceLocation loc) {
            if (msg.length() > MAX_DIAGNOSTIC_CHARS) {
                int cut = MAX_DIAGNOSTIC_CHARS;
                if (Character.isLowSurrogate(msg.charAt(cut))) cut--;
                msg = msg.substring(0, cut) + "...(" + (msg.length() - cut) + " more bytes elided)";
            }
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
            checkPropertyInitializers();
            checkConstructor();
            for (MethodNode m : contract.methods()) {
                checkMethod(m);
            }
            // GK-GAP-010: see PreimageChecked.
            for (PreimageChecked.Finding f : PreimageChecked.check(contract)) {
                errors.add(format(f.message(), f.loc()));
            }
            // D14: see ExtractorPreimage.
            for (PreimageChecked.Finding f : ExtractorPreimage.check(contract)) {
                errors.add(format(f.message(), f.loc()));
            }
        }

        /**
         * N-234: a scalar property initializer whose literal type does not
         * match the declared property type compiled without complaint on
         * every tier ({@code readonly x: bigint = toByteString('ab')}
         * emitted a locking script that pushes a byte string where the
         * contract's own arithmetic expects a script NUMBER). Validation
         * only checks that an initializer IS a literal of one of the three
         * families, never that it is a literal OF THE DECLARED TYPE.
         * {@code FixedArray} properties are skipped here: their
         * element-type check already lives in {@code ExpandFixedArrays}
         * (N-133), which runs on the expanded array elements, not the
         * whole-array initializer this pass sees. Mirrors the TS
         * reference's method of the same name in {@code 03-typecheck.ts}.
         */
        private void checkPropertyInitializers() {
            for (PropertyNode p : contract.properties()) {
                if (p.initializer() == null) continue;
                if (p.type() instanceof FixedArrayType) continue;
                String initType = staticInferType(p.initializer());
                if ("<unknown>".equals(initType)) continue;
                String declaredType = typeToString(p.type());
                if (!isSubtype(initType, declaredType)) {
                    currentMethodLoc = p.sourceLocation();
                    currentStmtLoc = null;
                    error("type '" + initType + "' is not assignable to type '" + declaredType + "'");
                }
            }
        }

        private void checkConstructor() {
            MethodNode ctor = contract.constructor();
            if (ctor == null) return;
            currentMethodLoc = ctor.sourceLocation();
            consumed = new HashMap<>();
            affineAliases = new HashMap<>();
            Env env = new Env();
            for (ParamNode p : ctor.params()) {
                env.define(p.name(), typeToString(p.type()));
            }
            for (PropertyNode p : contract.properties()) {
                env.define(p.name(), typeToString(p.type()));
            }
            checkStatements(ctor.body(), env);
        }

        /** The body of {@code m} in a fresh environment of its parameters. */
        private void checkMethodBody(MethodNode m) {
            currentMethodLoc = m.sourceLocation();
            consumed = new HashMap<>();
            affineAliases = new HashMap<>();
            Env env = new Env();
            for (ParamNode p : m.params()) {
                env.define(p.name(), typeToString(p.type()));
            }
            MethodNode prevMethod = currentMethod;
            currentMethod = m;
            currentReturnTypes = new ArrayList<>();
            try {
                checkStatements(m.body(), env);
            } finally {
                currentMethod = prevMethod;
            }
        }

        private void checkMethod(MethodNode m) {
            checkMethodBody(m);

            // D12 FE-F4: an undeclared private return type is inferred by
            // unifying the returned values. Values that do not unify used to be
            // typed by the FIRST return (so `if (c) return 1n; return true;` was
            // a bigint); now the call would be `<unknown>`, which `assert` / `if`
            // still accept. Refuse it here, as the TS reference does.
            if (m.visibility() != Visibility.PUBLIC && m.returnType() == null) {
                List<String> seen = currentReturnTypes;
                if (!seen.isEmpty() && !seen.contains("<unknown>")
                    && "<unknown>".equals(unifyReturnTypes(seen))) {
                    errors.add(format(
                        incompatibleReturnTypesMessage(m.name(), new java.util.ArrayList<>(new java.util.LinkedHashSet<>(seen))),
                        m.sourceLocation()));
                }
            }

            // N-511: a private method that declares a non-void return type
            // must return a value on every path (rule: returnsOnEveryPath).
            if (m.visibility() != Visibility.PUBLIC && m.returnType() != null) {
                String declared = typeToString(m.returnType());
                if (!"void".equals(declared)
                    && (hasBareReturn(m.body()) || !returnsOnEveryPath(m.body(), true, false))) {
                    errors.add(format(missingReturnMessage(m.name(), declared), m.sourceLocation()));
                }
            }

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

            // Crit-3 — reject mixing requireOutputP2PKH with addDataOutput in
            // the same method body. The intrinsic's compile-time output-offset
            // computation assumes a fixed 34-byte stride per output, which is
            // silently wrong when an OP_RETURN output (variable length)
            // precedes the indexed P2PKH output. v1 forbids the mix; v2 may
            // relax with a variable-stride decoder.
            //
            // F-075: all three guards here read the method's effects through
            // AnfLower's transitive continuation predicates, which follow the
            // private-helper call graph — the same analysis ANF lowering
            // injects the continuation from, and ANF lowering inlines private
            // helpers. A body-local walk let a developer disable every guard by
            // moving the triggering call into a helper.
            boolean hasRequireP2PKH = AnfLower.methodCallsRequireOutputP2PKH(m, contract, false);
            boolean hasAddDataOutput = AnfLower.methodHasAddDataOutput(m, contract);
            if (hasRequireP2PKH && hasAddDataOutput) {
                errors.add(format(
                    "method '" + m.name() + "' mixes requireOutputP2PKH() with "
                        + "addDataOutput() — v1 of the intrinsic assumes a fixed "
                        + "34-byte output stride and variable-length OP_RETURN "
                        + "outputs break the offset computation; split the "
                        + "addDataOutput call into a separate method",
                    m.sourceLocation()
                ));
            }

            // Reject requireOutputP2PKH(0) in a method whose implicit
            // single-output state continuation ALSO claims output 0. A
            // StatefulSmartContract method that mutates state but uses no
            // this.addOutput()/addRawOutput() re-creates the contract's own
            // (large codePart) script at output 0; requiring output 0 to also
            // be a 34-byte P2PKH is impossible (codePart >= 253 bytes forces a
            // 3-byte CompactSize length prefix, never the P2PKH template's
            // 0x19), so the contract is PERMANENTLY unspendable. The terminal
            // case (no state mutation -> no continuation) stays valid.
            //
            // R-300: "addOutput/addRawOutput layouts are left to the developer"
            // used to finish that sentence, and it was wrong — no layout the
            // developer can pick makes the offsets work. this.addOutput(...)
            // writes the continuation (codePart plus serialised state, hundreds
            // of bytes) at output 0, so outputIndex*34 lands INSIDE that script
            // for every index. addRawOutput's length is a runtime value, so the
            // stride cannot be proven there either. See
            // conformance/negatives/N34-p2pkh-index-with-state-output.runar.ts.
            // Mirrors the guard in
            // packages/runar-compiler/src/passes/03-typecheck.ts.
            if (contract.parentClass() == ParentClass.STATEFUL_SMART_CONTRACT) {
                boolean hasStateOutput = AnfLower.methodHasAddOutput(m, contract);
                if (hasRequireP2PKH && hasStateOutput) {
                    errors.add(format(
                        "method '" + m.name() + "' mixes requireOutputP2PKH() with "
                            + "this.addOutput()/addRawOutput() — the intrinsic reads output i "
                            + "at byte offset i*34, which is only correct when every earlier "
                            + "output is exactly 34 bytes, and a state-continuation output "
                            + "never is (codePart plus serialised state). The assertion would "
                            + "read bytes from the middle of the contract's own locking "
                            + "script, so the contract would be permanently unspendable. "
                            + "Assert the payment from a separate method that emits no output "
                            + "of its own",
                        m.sourceLocation()
                    ));
                }
                if (AnfLower.methodCallsRequireOutputP2PKH(m, contract, true)
                        && ContinuationRules.mutatesState(m, contract)
                        && !hasStateOutput) {
                    errors.add(format(
                        "method '" + m.name() + "' calls requireOutputP2PKH(0, ...) but also "
                            + "mutates state without this.addOutput()/addRawOutput() — the "
                            + "auto-injected single-output state continuation already claims "
                            + "output 0 (the contract's codePart), so output 0 cannot "
                            + "simultaneously be the required 34-byte P2PKH. This contract "
                            + "would be permanently unspendable. Assert the bond on a "
                            + "non-continuation output index, or make the method terminal "
                            + "(no state mutation)",
                        m.sourceLocation()
                    ));
                }

                // D18: in a method that declares its own outputs, a path that
                // writes state and reaches no addOutput drops its write (see
                // ContinuationRules).
                ContinuationRules.Verdict continuation = m.visibility() == Visibility.PUBLIC
                    ? ContinuationRules.continuationVerdict(m, contract)
                    : ContinuationRules.Verdict.NONE;
                if (continuation == ContinuationRules.Verdict.DROPPED) {
                    errors.add(format(ContinuationRules.droppedContinuationMessage(m.name()), m.sourceLocation()));
                }
                // D27: a write after a path's last addOutput is dead on chain
                // (see ContinuationRules).
                if (continuation == ContinuationRules.Verdict.DEAD_WRITE) {
                    errors.add(format(ContinuationRules.deadStateWriteMessage(m.name()), m.sourceLocation()));
                }
            }

            // D26: a lower-bound locktime gate needs an asserted domain pin on
            // its path (LocktimeDomain), in stateless and stateful contracts
            // alike. Here, beside D18 / D27, so a contract's other typecheck
            // errors (D14's unchecked-preimage extractor among them) are still
            // reported with it.
            if (m.visibility() == Visibility.PUBLIC
                && LocktimeDomain.contractReadsLocktime(contract)
                && LocktimeDomain.hasUnpinnedLocktimeGate(contract, m)) {
                errors.add(format(LocktimeDomain.locktimeDomainMessage(m.name()), m.sourceLocation()));
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
                String declType;
                if (v.type() != null) {
                    String declared = typeToString(v.type());
                    if (!isSubtype(initType, declared)) {
                        error("type '" + initType + "' is not assignable to type '" + declared + "'");
                    }
                    env.define(v.name(), declared);
                    declType = declared;
                } else {
                    env.define(v.name(), initType);
                    declType = initType;
                }
                // Affine alias tracking — 2026-04-30 audit F6.
                if (AFFINE_TYPES.contains(declType)) {
                    String origin = affineOriginOfExpr(v.init());
                    if (origin != null) {
                        affineAliases.put(v.name(), origin);
                    }
                }
            } else if (s instanceof AssignmentStatement a) {
                refuseContinuationAmountWrite(a.target());
                String targetType = inferExpr(a.target(), env);
                String valueType = inferExpr(a.value(), env);
                if (!isSubtype(valueType, targetType)) {
                    error("type '" + valueType + "' is not assignable to type '" + targetType + "'");
                }
            } else if (s instanceof IfStatement i) {
                String cond = inferExpr(i.condition(), env);
                // N-101: no <unknown> escape here, and none on the for-loop or
                // ternary condition below. TS, Go, Rust, Python, Zig and Ruby all
                // leave these three strict; this tier alone carried
                // `&& !"<unknown>".equals(cond)` and alone ACCEPTED
                // `if (this.hp())` for a private helper whose return type no tier
                // derives. That lowered a 33-byte PubKey into a branch condition,
                // where post-Genesis it is simply truthy. Ninth instance of the
                // class R-092 (bca3bb4f) closed eight of, and the one it filed.
                //
                // assert()'s escape is NOT part of this: all seven tiers carry it
                // and all seven compile `assert(this.hp())` to the same bytes.
                if (!"boolean".equals(cond)) {
                    error("if condition must be boolean, got '" + cond + "'");
                }
                // F-222: the arms are mutually exclusive, so each is checked
                // against the consumed set as it stood before the if;
                // afterwards a value consumed in either arm counts as consumed.
                Map<String, Boolean> consumedBefore = new HashMap<>(consumed);
                env.push();
                checkStatements(i.thenBody(), env);
                env.pop();
                Map<String, Boolean> consumedAfterThen = consumed;
                consumed = consumedBefore;
                if (i.elseBody() != null) {
                    env.push();
                    checkStatements(i.elseBody(), env);
                    env.pop();
                }
                consumed.putAll(consumedAfterThen);
            } else if (s instanceof ForStatement f) {
                int loopScope = env.depth();
                boolean repeats = loopMayRunTwice(f);
                env.push();
                if (f.init() != null) {
                    checkStatement(f.init(), env);
                }
                String cond = inferExpr(f.condition(), env);
                // N-101 (see the `if` above). Deleted as DEAD CODE rather than as
                // a behaviour change: Validate refuses a for-loop condition that
                // is not a comparison against a compile-time constant, three
                // passes before this runs, so no source reaches here with an
                // <unknown> condition. Characterised in
                // N101UnknownBooleanConditionTest#forConditionNeverReachesTheTypechecker.
                if (!"boolean".equals(cond)) {
                    error("for-loop condition must be boolean, got '" + cond + "'");
                }
                // R-065: the update clause used to be skipped entirely, so
                // `for (let i = 0n; i < 3n; undefinedFn())` compiled clean -- a hole in the
                // rule that only Rúnar builtins and contract methods are callable (CLAUDE.md
                // names `console.log` explicitly). Validate separately restricts the clause to
                // a unit-step advance; this is the type-level half of the same guard.
                if (f.update() != null) {
                    checkStatement(f.update(), env);
                }
                // F-110: the body runs once per iteration; see repeatingLoopScopes.
                if (repeats) repeatingLoopScopes.push(loopScope);
                checkStatements(f.body(), env);
                if (repeats) repeatingLoopScopes.pop();
                env.pop();
            } else if (s instanceof ExpressionStatement e) {
                inferExpr(e.expression(), env);
            } else if (s instanceof ReturnStatement r) {
                if (r.value() != null) {
                    String valueType = inferExpr(r.value(), env);
                    if (returnTypeSink != null) returnTypeSink.add(valueType);
                    currentReturnTypes.add(valueType);
                    // D12 FE-F4: the declared return type is enforced, strictly
                    // -- an unresolved value is not assignable to anything here.
                    if (currentMethod != null && currentMethod.returnType() != null) {
                        String declared = typeToString(currentMethod.returnType());
                        if ("<unknown>".equals(valueType) || !isSubtype(valueType, declared)) {
                            error(declaredReturnMismatchMessage(currentMethod.name(), valueType, declared));
                        }
                    }
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
                if ("true".equals(id.name()) || "false".equals(id.name())) return "boolean";
                // The blank identifier. `_ = x` is the Go / Rust / Zig discard idiom and
                // the Go DSL frontend emits it as an assignment TARGET, so it reaches the
                // identifier arm as a name to be typed. It is a discard, not a reference:
                // nothing is being looked up, so `undefined` is the wrong word for it.
                // Measured at the parent commit, go/rust/python/zig/ruby/java all compiled
                // `_ = doubled` to the same 7652957c009c77 while TS alone refused it with
                // "Undefined variable '_'" — invariant 1 (all seven parse all nine
                // surfaces) already broken for this shape. Listing it here rather than
                // letting the new fall-through reject it keeps the six tiers' bytes and
                // brings the seventh into line.
                if ("_".equals(id.name())) return "<unknown>";
                String t = env.lookup(id.name());
                if (t != null) return t;
                if (BuiltinRegistry.isBuiltin(id.name())) return "<builtin>";
                if (methodSigs.containsKey(id.name())) return "<method>";
                if (propTypes.containsKey(id.name())) return propTypes.get(id.name());
                String global = KNOWN_GLOBALS.get(id.name());
                if (global != null) return global;
                // GK-BUG-009 -- a name that resolves to nothing is an error HERE,
                // at the only pass that can see the binding environment. It used
                // to return "<unknown>" silently, and "<unknown>" is compatible
                // with everything under isSubtype by design (R-092), so
                // `notAThing === 1n` raised nothing. `notAThing > 1n` did raise
                // -- the bigint-family check does not admit "<unknown>" -- which
                // is why R-085's `>` pin read as closed while the `===` path was
                // wide open. Where the reference is reachable from codegen,
                // stack lowering later refuses to emit an OP_0 placeholder and
                // the compile still fails, but for the wrong reason; where it is
                // NOT reachable (an uncalled private helper, a zero-iteration
                // loop) nothing fired at all and the contract compiled to a
                // locking script.
                error("Undefined variable '" + id.name() + "'");
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
                error("Property '" + pa.property() + "' does not exist on the contract");
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
                // N-101 (see the `if` above). Six tiers leave this strict.
                if (!"boolean".equals(cond)) {
                    error("ternary condition must be boolean, got '" + cond + "'");
                }
                String cons = inferExpr(te.consequent(), env);
                String alt = inferExpr(te.alternate(), env);
                if (!cons.equals(alt)) {
                    if (isSubtype(alt, cons)) return cons;
                    if (isSubtype(cons, alt)) return alt;
                    if (!"<unknown>".equals(cons) && !"<unknown>".equals(alt)) {
                        errorAt(
                            "ternary branches have incompatible types: '" + cons + "' vs '" + alt + "'",
                            te
                        );
                    }
                }
                return cons;
            }

            if (e instanceof IndexAccessExpr ia) {
                String objType = inferExpr(ia.object(), env);
                String indexType = inferExpr(ia.index(), env);
                if (!isBigintFamily(indexType)) {
                    error("array index must be bigint, got '" + indexType + "'");
                }
                if (objType.endsWith("[]")) {
                    return objType.substring(0, objType.length() - 2);
                }
                return "<unknown>";
            }

            if (e instanceof IncrementExpr ie) {
                refuseContinuationAmountWrite(ie.operand());
                String t = inferExpr(ie.operand(), env);
                if (!isBigintFamily(t)) {
                    error("++ operator requires bigint, got '" + t + "'");
                }
                return "bigint";
            }
            if (e instanceof DecrementExpr de) {
                refuseContinuationAmountWrite(de.operand());
                String t = inferExpr(de.operand(), env);
                if (!isBigintFamily(t)) {
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

            // D12 FE-F1: the operators whose opcode depends on the operand
            // family record the family the TYPE CHECKER resolved; ANF lowering
            // reads it and nothing else. `+` and `& | ^` already refuse an
            // operand that is neither a byte string nor a number (below);
            // equality accepted `<unknown>`, so it is refused here rather than
            // lowered as a guess.
            if (isTypedBinaryOp(op)) {
                OperandType lf = operandFamily(lt);
                OperandType rf = operandFamily(rt);
                if (lf != null && lf == rf) {
                    e.operandType().set(lf);
                } else if ((lf == null || rf == null)
                        && (op == Expression.BinaryOp.EQ || op == Expression.BinaryOp.NEQ)) {
                    errorAt(unresolvedOperandTypesMessage(op.canonical(), lt, rt), e);
                }
            }

            // ByteString + ByteString → ByteString (OP_CAT).
            if (op == Expression.BinaryOp.ADD && isByteFamily(lt) && isByteFamily(rt)) {
                return "ByteString";
            }

            switch (op) {
                case ADD, SUB, MUL, DIV, MOD -> {
                    if (!isBigintFamily(lt)) {
                        operandErrorAt("left operand of '" + op.canonical() + "' must be bigint, got '" + lt + "'", e.left());
                    }
                    if (!isBigintFamily(rt)) {
                        operandErrorAt("right operand of '" + op.canonical() + "' must be bigint, got '" + rt + "'", e.right());
                    }
                    return "bigint";
                }
                case LT, LE, GT, GE -> {
                    if (!isBigintFamily(lt)) {
                        operandErrorAt("left operand of '" + op.canonical() + "' must be bigint, got '" + lt + "'", e.left());
                    }
                    if (!isBigintFamily(rt)) {
                        operandErrorAt("right operand of '" + op.canonical() + "' must be bigint, got '" + rt + "'", e.right());
                    }
                    return "boolean";
                }
                case EQ, NEQ -> {
                    // Exactly the reference tier's rule: each side is tried as
                    // a subtype of the other, and nothing else. The
                    // both-in-family clauses that used to sit here were this
                    // tier's local patch for an isSubtype that lacked them
                    // (N-104); isSubtype carries them now, so repeating them
                    // here would be a second copy of the lattice to drift.
                    boolean compatible = isSubtype(lt, rt) || isSubtype(rt, lt);
                    if (!compatible && !"<unknown>".equals(lt) && !"<unknown>".equals(rt)) {
                        errorAt("cannot compare '" + lt + "' and '" + rt + "' with '" + op.canonical() + "'", e);
                    }
                    return "boolean";
                }
                case AND, OR -> {
                    if (!"boolean".equals(lt) && !"<unknown>".equals(lt)) {
                        operandErrorAt("left operand of '" + op.canonical() + "' must be boolean, got '" + lt + "'", e.left());
                    }
                    if (!"boolean".equals(rt) && !"<unknown>".equals(rt)) {
                        operandErrorAt("right operand of '" + op.canonical() + "' must be boolean, got '" + rt + "'", e.right());
                    }
                    return "boolean";
                }
                case SHL, SHR -> {
                    if (!isBigintFamily(lt)) {
                        operandErrorAt("left operand of '" + op.canonical() + "' must be bigint, got '" + lt + "'", e.left());
                    }
                    if (!isBigintFamily(rt)) {
                        operandErrorAt("right operand of '" + op.canonical() + "' must be bigint, got '" + rt + "'", e.right());
                    }
                    return "bigint";
                }
                case BIT_AND, BIT_OR, BIT_XOR -> {
                    if (isByteFamily(lt) && isByteFamily(rt)) return "ByteString";
                    if (!isBigintFamily(lt)) {
                        operandErrorAt(
                            "left operand of '" + op.canonical()
                                + "' must be bigint or ByteString, got '" + lt + "'",
                            e.left()
                        );
                    }
                    if (!isBigintFamily(rt)) {
                        operandErrorAt(
                            "right operand of '" + op.canonical()
                                + "' must be bigint or ByteString, got '" + rt + "'",
                            e.right()
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
                        errorAt("operand of '!' must be boolean, got '" + t + "'", e);
                    }
                    return "boolean";
                }
                case NEG -> {
                    if (!isBigintFamily(t)) {
                        errorAt("operand of unary '-' must be bigint, got '" + t + "'", e);
                    }
                    return "bigint";
                }
                case BIT_NOT -> {
                    // D12 FE-F1: see checkBinary.
                    if (isByteFamily(t)) {
                        e.operandType().set(OperandType.BYTES);
                        return "ByteString";
                    }
                    if (isBigintFamily(t)) e.operandType().set(OperandType.NUMERIC);
                    if (!isBigintFamily(t)) {
                        errorAt("operand of '~' must be bigint or ByteString, got '" + t + "'", e);
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

            // asm is a compile-time intrinsic — the parser has already
            // rewritten the { body, in_arity?, out_arity? } object-literal
            // argument into three positional args (body, in_arity,
            // out_arity). The statement form returns void; the expression
            // form asm<T>({...}) carries the captured return type on
            // asmReturnType and produces a value of that type.
            if (callee instanceof Identifier asmId && "asm".equals(asmId.name())) {
                for (Expression a : e.args()) inferExpr(a, env);
                String rt = e.asmReturnType();
                if (rt != null && !rt.isEmpty()) return rt;
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
                    FuncSig fs = methodSig(name);
                    return checkCallArgs(name, fs.params(), fs.returnType(), e.args(), env);
                }
                String local = env.lookup(name);
                if (local != null) {
                    // F-208: Rúnar has no first-class functions, so a bound
                    // local can never be called. This used to evaluate args
                    // and give up with NO diagnostic, silently accepting
                    // `const f: bigint = a; const r = f(a, a, a);`.
                    error(
                        "local variable '" + name + "' is not callable — Rúnar has no "
                            + "first-class functions; only built-in functions and "
                            + "contract methods can be called"
                    );
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
                        // Same rule as `===` above, for the same reason: the
                        // both-in-family clauses are `isSubtype`'s job (N-104).
                        boolean compatible =
                            isSubtype(argType, objType) || isSubtype(objType, argType);
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

        /**
         * Type-check the FIRST argument of an output intrinsic — the output's
         * SATOSHI AMOUNT.
         *
         * <p>N-098: this tier used to accept any type there. That is not a
         * missing lint. {@code lowerAddOutput} prepends the operand as
         * {@code OP_8 OP_NUM2BIN}, so a ByteString in that slot is
         * reinterpreted as a script number with no conversion and becomes the
         * amount the covenant commits to: {@code blob: ByteString} and
         * {@code blob: bigint} compiled to the SAME script, byte for byte. On
         * the real {@code @bsv/sdk} Spend engine with {@code blob = 0x2a} only
         * a 42-satoshi continuation validates, and blobs wider than 8 bytes
         * abort at {@code OP_NUM2BIN}, making the UTXO unspendable.
         *
         * <p>Ported from the TypeScript reference, wording included.
         *
         * <p>{@code <unknown>} is escaped exactly as TS escapes it — a private
         * helper's declared return type is discarded at parse time in every
         * tier, so {@code this.sats()} infers as {@code <unknown>} and must
         * keep compiling. This is the one escape R-092 did NOT delete, because
         * the reference tier has it too.
         */
        private void checkSatoshisArg(String prop, Expression arg, Env env) {
            String t = inferExpr(arg, env);
            if (!isBigintFamily(t) && !"<unknown>".equals(t)) {
                errorAt(prop + "() first argument (satoshis) must be bigint, got '" + t + "'", arg);
            }
        }

        /**
         * Type-check the SECOND argument of addRawOutput / addDataOutput — the
         * created output's LOCKING SCRIPT.
         *
         * <p>N-105: this tier used to accept any type there too.
         * {@code lowerAddRawOutput} takes {@code OP_SIZE} of the operand,
         * varint-prefixes it and concatenates it after the amount — no
         * conversion — so {@code n: bigint} and {@code n: ByteString} compiled
         * to the SAME script, byte for byte. A script number on the stack is
         * its minimal little-endian encoding, so the covenant commits to an
         * output whose locking script IS those bytes. Executed on the real
         * {@code @bsv/sdk} Spend engine against the exact opcode window this
         * tier emits: n=0 gives an EMPTY locking script, n=81 gives
         * {@code OP_1} and n=118 gives {@code OP_DUP} — all three
         * anyone-can-spend — while n=1000 gives {@code 0xe8 0x03}, an invalid
         * opcode, and the output is unspendable.
         *
         * <p>Ported from the TypeScript reference, wording included. TS uses
         * {@code isSubtype} against ByteString, not equality, so every
         * ByteString subtype (PubKey, Ripemd160, Sig, ...) stays accepted, and
         * {@code <unknown>} is escaped exactly as TS escapes it.
         */
        private void checkScriptBytesArg(String prop, Expression arg, Env env) {
            String t = inferExpr(arg, env);
            if (!isSubtype(t, "ByteString") && !"<unknown>".equals(t)) {
                errorAt(prop + "() second argument (scriptBytes) must be ByteString, got '" + t + "'", arg);
            }
        }

        /**
         * N-105 (2/2): addOutput's arity and state-value types, and the
         * StatefulSmartContract gate shared by all three intrinsics.
         *
         * <p>Each was a hole with an executed consequence:
         * {@code addOutput(1000n)} dropped the state value from the
         * continuation entirely, a surplus value was appended to a state
         * serialization the next spend deserializes by fixed offsets, a
         * ByteString state value was serialized where an 8-byte LE number
         * belongs, and addRawOutput in a stateless SmartContract emitted a
         * "continuation" for a contract with no state.
         *
         * <p>Ported from the TypeScript reference, wording included.
         */
        private String checkAddOutputArgs(List<Expression> args, Env env) {
            // Mirror flattenAddOutputArgs in AnfLower: when addOutput is called
            // as `this.addOutput(satoshis, .{ v1, v2, ... })` (the surface form
            // Zig / Move tuple syntax produce), unwrap the trailing array
            // literal so each element is type-checked individually instead of
            // triggering ArrayLiteralExpr's homogeneous-element rule (state
            // values intentionally have heterogeneous types — owner: PubKey,
            // balance: bigint, ...). The satoshis argument is args.get(0) in
            // BOTH forms.
            List<Expression> normalized = args;
            if (args.size() == 2 && args.get(1) instanceof ArrayLiteralExpr al) {
                normalized = new ArrayList<>(1 + al.elements().size());
                normalized.add(args.get(0));
                normalized.addAll(al.elements());
            }

            // N-107: count the state slots the continuation will actually
            // carry, not the DECLARED mutable properties. ExpandFixedArrays
            // splits `board: FixedArray<bigint, 3>` into `board__0 .. board__2`,
            // so a contract declaring `board` and `n` emits FOUR state values.
            // addOutput is positional against the emitted values, which is why
            // the declared count answers the wrong question.
            //
            // Until N-106 this tier got the right number for the wrong reason:
            // ExpandFixedArrays ran BEFORE Typecheck here and AFTER it in the
            // other six, so the properties reaching this method were already
            // scalar and the ported `shapeCheckable` opt-out never fired. That
            // pass order is now aligned with the six, so the count has to be
            // computed here — the two findings are one root cause, and fixing
            // the ordering without this would have made Java start rejecting
            // Boardy (in
            // compilers/python/tests/test_r025_expand_fixed_arrays_field_preservation.py),
            // which every tier compiles. Gate:
            // conformance/negatives/N26-addoutput-arity-fixedarray and
            // conformance/subtype-parity/FixedArrayOutputShape.
            List<StateSlot> mutableProps = expandedStateSlots(contract.properties());
            int expected = 1 + mutableProps.size();
            if (normalized.size() != expected) {
                error("addOutput() expects " + expected + " argument(s): satoshis + "
                    + mutableProps.size() + " state value(s), got " + normalized.size());
            }
            if (!normalized.isEmpty()) {
                checkSatoshisArg("addOutput", normalized.get(0), env);
            }
            // Every state value is inferred, surplus ones included, so a type
            // error inside one is not swallowed by the arity diagnostic.
            for (int i = 1; i < normalized.size(); i++) {
                String argType = inferExpr(normalized.get(i), env);
                if (i - 1 >= mutableProps.size()) continue;
                if ("<unknown>".equals(argType)) continue;
                StateSlot slot = mutableProps.get(i - 1);
                String propType = typeToString(slot.type());
                if (!isSubtype(argType, propType)) {
                    errorAt("addOutput() argument " + (i + 1) + " (" + slot.name() + ") must be '"
                        + propType + "', got '" + argType + "'", normalized.get(i));
                }
            }
            return "void";
        }

        /** One emitted state value: what the state continuation actually carries. */
        private record StateSlot(String name, TypeNode type) {}

        /**
         * The mutable state as {@code addOutput} sees it — one slot per value
         * the continuation carries, NOT one per declared property.
         *
         * <p>N-107: {@code ExpandFixedArrays} splits a FixedArray property into
         * one scalar sibling per element, so the DECLARED property list is not
         * the emitted state. The flattening mirrors that pass's own naming
         * ({@code <root>__<i>}, recursing through nested arrays) so a diagnostic
         * names the synthetic property the expansion will create.
         *
         * <p>A non-positive length is already a parse/validate error; the
         * property is kept whole in that case so this rule never fires on a
         * contract that is going to be rejected for a better reason.
         */
        private static List<StateSlot> expandedStateSlots(List<PropertyNode> properties) {
            List<StateSlot> slots = new ArrayList<>();
            for (PropertyNode p : properties) {
                if (!p.readonly()) pushStateSlot(p.name(), p.type(), slots);
            }
            return slots;
        }

        private static void pushStateSlot(String name, TypeNode type, List<StateSlot> out) {
            if (type instanceof FixedArrayType fa && fa.length() > 0) {
                for (int i = 0; i < fa.length(); i++) {
                    pushStateSlot(name + "__" + i, fa.element(), out);
                }
                return;
            }
            out.add(new StateSlot(name, type));
        }

        private String checkBuiltinThisCall(String prop, List<Expression> args, Env env) {
            if ("getStateScript".equals(prop)) {
                // R-173: the builtin takes none — it returns the contract's own
                // state script, a property of the contract rather than of
                // anything a caller could pass. Five tiers used to accept
                // arguments and DISCARD them, emitting hex byte-identical to
                // the zero-argument spelling, so an author who believed the
                // arguments meant something got a script that ignored them with
                // no diagnostic. Message is the reference tier's.
                if (args != null && !args.isEmpty()) {
                    error("getStateScript() takes no arguments");
                }
                return "ByteString";
            }
            if ("addOutput".equals(prop) || "addRawOutput".equals(prop) || "addDataOutput".equals(prop)) {
                // N-105: all three intrinsics build an OUTPUT, and an output
                // only exists in a stateful contract. TS refuses the call
                // outright and checks nothing else, so the early return is part
                // of the ported behaviour.
                if (contract == null
                        || contract.parentClass() != ParentClass.STATEFUL_SMART_CONTRACT) {
                    error(prop + "() is only available in StatefulSmartContract");
                    return "void";
                }
                if ("addOutput".equals(prop)) {
                    return checkAddOutputArgs(args, env);
                }
                // addRawOutput / addDataOutput — (satoshis, scriptBytes).
                if (args.size() != 2) {
                    error(prop + "() expects 2 arguments (satoshis, scriptBytes), got "
                        + args.size());
                }
                if (!args.isEmpty()) {
                    checkSatoshisArg(prop, args.get(0), env);
                }
                if (args.size() >= 2) {
                    checkScriptBytesArg(prop, args.get(1), env);
                }
                for (int i = 2; i < args.size(); i++) inferExpr(args.get(i), env);
                return "void";
            }
            if (methodSigs.containsKey(prop)) {
                FuncSig fs = methodSig(prop);
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

            // checkMultiSig special case (Sig[] / PubKey[] arrays).
            // Only arity is special; arg-type validation falls
            // through to the standard subtype loop below so callers
            // cannot pass bigint[] or other element types.
            // 2026-04-30 audit finding F5.
            if ("checkMultiSig".equals(name)) {
                if (args.size() != 2) {
                    error("checkMultiSig() expects 2 arguments, got " + args.size());
                    for (Expression a : args) inferExpr(a, env);
                    checkAffine(name, args, env);
                    return returnType;
                }
                // Fall through to the standard subtype check below.
            }

            // extractPrevOutputScript / requireOutputP2PKH — the index arg
            // MUST be a compile-time integer literal so the ANF lowering
            // can derive a stable auto-injected witness-param name
            // (extractPrevOutputScript) or a constant byte offset
            // (requireOutputP2PKH). Mirrors compilers/go/frontend/typecheck.go.
            if ("extractPrevOutputScript".equals(name) || "requireOutputP2PKH".equals(name)) {
                if (!args.isEmpty()) {
                    Expression idxArg = args.get(0);
                    BigIntLiteral lit = null;
                    if (idxArg instanceof BigIntLiteral b) {
                        lit = b;
                    } else if (idxArg instanceof UnaryExpr u
                        && u.op() == Expression.UnaryOp.NEG
                        && u.operand() instanceof BigIntLiteral inner
                        && inner.value() != null
                        // N-060: this arm exists ONLY to reach the
                        // "must be >= 0" message below, so it must surrender
                        // anything that is not actually negative. `-0`
                        // negates to 0 and would sail past that bound check,
                        // but AnfLower matches on a bare BigIntLiteral: on a
                        // UnaryExpr it falls through to `load_const ""` and
                        // the covenant the intrinsic was supposed to install
                        // is silently absent. Let it fall to the
                        // non-literal-index diagnostic instead.
                        && inner.value().negate().signum() < 0) {
                        // Accept `-N` so the bounds check below produces a
                        // clear "must be >= 0" rather than the misleading
                        // "must be an integer literal" message.
                        lit = new BigIntLiteral(inner.value().negate());
                    }
                    if (lit == null) {
                        error(name + "() argument 1 (index) must be an integer literal");
                    } else if (lit.value() != null) {
                        // R-2: bound the index literal. For requireOutputP2PKH,
                        // the emitted Stack-IR computes byte-offset = idx * 34;
                        // require 0 <= idx <= 1000 to keep the offset well
                        // under script-int max and reject obvious nonsense
                        // (negative or astronomically large).
                        BigInteger v = lit.value();
                        BigInteger min64 = BigInteger.valueOf(Long.MIN_VALUE);
                        BigInteger max64 = BigInteger.valueOf(Long.MAX_VALUE);
                        if (v.compareTo(min64) < 0 || v.compareTo(max64) > 0) {
                            error(name + "() argument 1 (index) must fit in int64; got " + v);
                        } else {
                            long idx = v.longValueExact();
                            if (idx < 0) {
                                error(name + "() argument 1 (index) must be >= 0; got " + idx);
                            }
                            if ("requireOutputP2PKH".equals(name) && idx > 0) {
                                error("requireOutputP2PKH() argument 1 (outputIndex) must be 0 in v1; got " + idx + ". The emitted Stack-IR reads output i at byte offset i*34, but Bitcoin outputs are variable length, so for i > 0 that offset is not an output boundary: an attacker sizes output 0 freely and places the expected 34 P2PKH bytes inside its OP_RETURN payload, leaving the transaction's real output i to pay whoever they like. Offset 0 IS a boundary, so index 0 is sound; other indexes need a CompactSize walk the v1 codegen does not emit");
                            }
                        }
                    }
                }
            }

            // extractPrevOutputScript variable-arity special case (2-arg
            // full-hash or 3-arg prefix-hash form, Crit-2). Validates types
            // + literal-only on the optional prefixLen, then returns the
            // signature's return type to bypass the standard arg-count
            // check below (which would reject the 3-arg form against the
            // 2-arg sig table entry).
            if ("extractPrevOutputScript".equals(name)) {
                if (args.size() != 2 && args.size() != 3) {
                    error("extractPrevOutputScript() expects 2 or 3 arguments, got "
                        + args.size());
                }
                if (!args.isEmpty()) {
                    inferExpr(args.get(0), env); // already validated as literal above
                }
                if (args.size() >= 2) {
                    String argType = inferExpr(args.get(1), env);
                    if (!isSubtype(argType, "ByteString") && !"<unknown>".equals(argType)) {
                        error("argument 2 of extractPrevOutputScript(): expected "
                            + "'ByteString', got '" + argType + "'");
                    }
                }
                if (args.size() == 3) {
                    Expression preArg = args.get(2);
                    BigIntLiteral preLit = null;
                    if (preArg instanceof BigIntLiteral b) {
                        preLit = b;
                    } else if (preArg instanceof UnaryExpr u
                        && u.op() == Expression.UnaryOp.NEG
                        && u.operand() instanceof BigIntLiteral inner
                        && inner.value() != null) {
                        preLit = new BigIntLiteral(inner.value().negate());
                    }
                    if (preLit == null) {
                        error("extractPrevOutputScript() argument 3 (prefixLen) "
                            + "must be an integer literal when supplied");
                    } else if (preLit.value() != null) {
                        // R-4: bound the prefixLen literal. The intrinsic
                        // hashes substr(witness, 0, prefixLen) and compares
                        // against a 32-byte SHA-256 hash. prefixLen < 32 is
                        // suspicious (the prefix doesn't cover a hash-sized
                        // chunk). prefixLen > 4 MiB exceeds MAX_SCRIPT_BYTES.
                        BigInteger v = preLit.value();
                        BigInteger min64 = BigInteger.valueOf(Long.MIN_VALUE);
                        BigInteger max64 = BigInteger.valueOf(Long.MAX_VALUE);
                        if (v.compareTo(min64) < 0 || v.compareTo(max64) > 0) {
                            error("extractPrevOutputScript() argument 3 (prefixLen) "
                                + "must fit in int64; got " + v);
                        } else {
                            long n = v.longValueExact();
                            if (n < 32) {
                                error("extractPrevOutputScript() argument 3 (prefixLen) "
                                    + "must be >= 32 (the hash assertion compares a "
                                    + "32-byte SHA-256); got " + n);
                            }
                            if (n > 4L * 1024L * 1024L) {
                                error("extractPrevOutputScript() argument 3 (prefixLen) "
                                    + "must be <= MAX_SCRIPT_BYTES (4 MiB); got " + n);
                            }
                        }
                    }
                    inferExpr(args.get(2), env);
                }
                // Any trailing args beyond 3 still get walked for type-check
                // side effects but the arity error above already fired.
                for (int i = 3; i < args.size(); i++) inferExpr(args.get(i), env);
                return returnType;
            }

            // requireOutputP2PKH, currentBlockHeight and continuationAmount
            // need the auto-injected txPreimage / _newAmount — only available
            // in StatefulSmartContract methods.
            if ("requireOutputP2PKH".equals(name) || "currentBlockHeight".equals(name)
                || "continuationAmount".equals(name)) {
                if (contract != null && contract.parentClass() != ParentClass.STATEFUL_SMART_CONTRACT) {
                    error(name + "() is only available in StatefulSmartContract methods");
                }
            }

            // F-265: substr(witness, start, len) lowers to a raw OP_SPLIT
            // argument. A literal negative start used to type-check as
            // plain 'bigint' (the standard subtype loop below never
            // inspects a literal's VALUE) and compile to a script that
            // aborts at runtime -- `-5n` minimal-encodes to `<85>`, which
            // OP_SPLIT rejects. Catch the literal case (bare or
            // unary-negated BigIntLiteral) at compile time, mirroring the
            // extractPrevOutputScript/requireOutputP2PKH "must be >= 0"
            // pattern above. A non-literal start (a variable or computed
            // expression) has no static value to check and is unaffected.
            if ("substr".equals(name) && args.size() >= 2) {
                Expression startArg = args.get(1);
                BigIntLiteral startLit = null;
                if (startArg instanceof BigIntLiteral b) {
                    startLit = b;
                } else if (startArg instanceof UnaryExpr u
                    && u.op() == Expression.UnaryOp.NEG
                    && u.operand() instanceof BigIntLiteral inner
                    && inner.value() != null) {
                    startLit = new BigIntLiteral(inner.value().negate());
                }
                if (startLit != null && startLit.value() != null
                    && startLit.value().signum() < 0) {
                    error("substr() argument 2 (start) must be >= 0; got " + startLit.value());
                }
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

        /**
         * Track consumption by *origin*, not variable name, so aliases
         * (`const again = sig`) and property accesses (`this.sig`)
         * cannot launder a double-consumption past the affine check.
         * 2026-04-30 audit finding F6.
         */
        private void checkAffine(String name, List<Expression> args, Env env) {
            if (skipAffine) return;
            int[] indices = CONSUMING_FUNCTIONS.get(name);
            List<String> consumedProps = List.of();
            if (indices == null) {
                // N-109: a call to a contract method consumes the arguments at
                // the parameter positions that method consumes.
                if (BuiltinRegistry.lookup(name).isPresent() || !methodSigs.containsKey(name)) return;
                if (consumedParams == null) consumedParams = consumedParamSummary(contract, returnMemo);
                MethodConsumption mc = consumedParams.getOrDefault(name, new MethodConsumption(new int[0], List.of()));
                indices = mc.params();
                consumedProps = mc.props();
            }
            for (int idx : indices) {
                if (idx >= args.size()) continue;
                Expression arg = args.get(idx);
                String argType = affineExprType(arg, env);
                if (argType == null || !AFFINE_TYPES.contains(argType)) continue;
                String origin = affineOriginOfExpr(arg);
                if (origin == null) continue;

                String label;
                if (arg instanceof Identifier aid) label = aid.name();
                else if (arg instanceof PropertyAccessExpr pa) label = "this." + pa.property();
                else label = origin;

                if (Boolean.TRUE.equals(consumed.get(origin)) || consumedPerLoopIteration(origin, env)) {
                    errorAt("affine value '" + label + "' has already been consumed", arg);
                } else {
                    consumed.put(origin, true);
                }
            }

            // N-288: the call also consumes every property the method consumes.
            for (String origin : consumedProps) {
                if (Boolean.TRUE.equals(consumed.get(origin)) || consumedPerLoopIteration(origin, env)) {
                    errorAt(
                        "affine value 'this." + origin.substring("prop:".length()) + "' has already been consumed",
                        args.isEmpty() ? null : args.get(0)
                    );
                } else {
                    consumed.put(origin, true);
                }
            }
        }

        /**
         * N-109: run the affine checker over each method body with throwaway
         * diagnostics and record which parameters (and, N-288, which
         * {@code prop:<name>} property origins) end up consumed. Reusing the
         * checker inherits alias, if-arm and loop handling. Consumption only
         * grows as summaries grow, so iterating until no entry changes
         * terminates, also for recursive call graphs (refused separately by
         * validation). Mirrors {@code consumedParamSummary} in the TS reference
         * {@code 03-typecheck.ts}.
         */
        private static Map<String, MethodConsumption> consumedParamSummary(ContractNode contract, Map<MethodNode, String> returnMemo) {
            Map<String, MethodConsumption> summary = new HashMap<>();
            for (MethodNode m : contract.methods()) summary.put(m.name(), new MethodConsumption(new int[0], List.of()));
            boolean changed = true;
            while (changed) {
                changed = false;
                for (MethodNode m : contract.methods()) {
                    Checker scratch = new Checker(contract);
                    scratch.returnMemo = returnMemo; // D12 FE-F4: shared return-type memo
                    scratch.consumedParams = summary;
                    MethodConsumption consumed = scratch.consumedParamIndices(m);
                    MethodConsumption prev = summary.get(m.name());
                    if (consumed.params().length != prev.params().length
                        || consumed.props().size() != prev.props().size()) {
                        summary.put(m.name(), consumed);
                        changed = true;
                    }
                }
            }
            return summary;
        }

        /**
         * N-109: the indices of {@code m}'s parameters its body consumes, and
         * (N-288) the {@code prop:<name>} property origins it consumes.
         */
        private MethodConsumption consumedParamIndices(MethodNode m) {
            currentMethodLoc = m.sourceLocation();
            consumed = new HashMap<>();
            affineAliases = new HashMap<>();
            Env env = new Env();
            for (ParamNode p : m.params()) {
                env.define(p.name(), typeToString(p.type()));
            }
            checkStatements(m.body(), env);
            List<Integer> out = new ArrayList<>();
            for (int i = 0; i < m.params().size(); i++) {
                if (Boolean.TRUE.equals(consumed.get(m.params().get(i).name()))) out.add(i);
            }
            List<String> props = new ArrayList<>();
            for (Map.Entry<String, Boolean> e : consumed.entrySet()) {
                if (Boolean.TRUE.equals(e.getValue()) && e.getKey().startsWith("prop:")) props.add(e.getKey());
            }
            props.sort(null);
            return new MethodConsumption(out.stream().mapToInt(Integer::intValue).toArray(), props);
        }

        /**
         * F-110: true when {@code origin} is bound outside the innermost
         * enclosing loop that may run two or more times, so this one syntactic
         * consumption is executed once per iteration -- a double use. A
         * property, or a name the env does not bind (a bare-identifier
         * property), is always outside.
         */
        private boolean consumedPerLoopIteration(String origin, Env env) {
            Integer innermost = repeatingLoopScopes.peek();
            if (innermost == null) return false;
            if (origin.startsWith("prop:")) return true;
            return env.scopeIndexOf(origin) < innermost;
        }

        /** Resolve the canonical affine origin for an expression. */
        private String affineOriginOfExpr(Expression expr) {
            if (expr instanceof Identifier id) {
                String aliased = affineAliases.get(id.name());
                return aliased != null ? aliased : id.name();
            }
            if (expr instanceof PropertyAccessExpr pa) {
                return "prop:" + pa.property();
            }
            return null;
        }

        /** Look up the type of an expression for affine purposes. */
        private String affineExprType(Expression expr, Env env) {
            if (expr instanceof Identifier id) return env.lookup(id.name());
            if (expr instanceof PropertyAccessExpr pa) return propTypes.get(pa.property());
            return null;
        }
    }

    // ------------------------------------------------------------------
    // Private method return-type inference
    // ------------------------------------------------------------------

    /**
     * D12 FE-F4: unify the types of a private method's {@code return} values
     * (inferred with the full environment). No value-returning {@code return}
     * = void; values in one family unify to that family; anything else is
     * {@code <unknown>} -- never a best-effort pick, because every typed
     * operator refuses {@code <unknown>}.
     */
    private static String unifyReturnTypes(List<String> returnTypes) {
        if (returnTypes.isEmpty()) return "void";
        String first = returnTypes.get(0);
        if (returnTypes.stream().allMatch(first::equals)) return first;
        if (returnTypes.stream().allMatch(BIGINT_SUBTYPES::contains)) return "bigint";
        if (returnTypes.stream().allMatch(BYTESTRING_SUBTYPES::contains)) return "ByteString";
        return "<unknown>";
    }

    /** Binary operators whose lowering depends on the operand family (D12 FE-F1). */
    public static boolean isTypedBinaryOp(Expression.BinaryOp op) {
        return switch (op) {
            case ADD, EQ, NEQ, BIT_AND, BIT_OR, BIT_XOR -> true;
            default -> false;
        };
    }

    /** The lowering family of a resolved type: bytes, a script number, or none. */
    private static OperandType operandFamily(String t) {
        if (BYTESTRING_SUBTYPES.contains(t)) return OperandType.BYTES;
        if (BIGINT_SUBTYPES.contains(t) || "boolean".equals(t)) return OperandType.NUMERIC;
        return null;
    }

    /** D12 FE-F1: the one wording every tier emits. */
    public static String unresolvedOperandTypesMessage(String op, String left, String right) {
        return "Cannot resolve the operand types of '" + op + "' (got '" + left + "' and '" + right + "'): "
            + "it must be known whether the operands are byte strings or numbers";
    }

    /** D12 FE-F4: the one wording every tier emits (types in first-seen order). */
    public static String incompatibleReturnTypesMessage(String method, List<String> types) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < types.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append('\'').append(types.get(i)).append('\'');
        }
        return "Method '" + method + "' returns values of incompatible types (" + sb + "); declare its return type";
    }

    /** D12 FE-F4: the one wording every tier emits. */
    /** N-511: the one wording every tier emits. */
    public static String missingReturnMessage(String method, String declared) {
        return "Method '" + method + "' declares return type '" + declared
            + "' but does not return a value on every path";
    }

    /**
     * N-511: whether a statement list returns a value on every path. A list
     * returns when one of its statements does; {@code return <value>} returns;
     * an {@code if} returns only when it has an else and both arms return; a
     * loop never counts. Tail value: an expression statement counts when it is
     * the last statement of an arm of an if/else that is itself last in its
     * list, recursively up to the method body (the .runar.rs / .runar.move tail
     * if-expression). A top-level trailing expression is not credited.
     */
    static boolean returnsOnEveryPath(List<Statement> stmts, boolean tail, boolean inArm) {
        for (int i = 0; i < stmts.size(); i++) {
            boolean last = i == stmts.size() - 1;
            Statement s = stmts.get(i);
            if (s instanceof ReturnStatement r) {
                if (r.value() != null) return true;
            } else if (s instanceof IfStatement f) {
                if (f.elseBody() != null
                    && returnsOnEveryPath(f.thenBody(), tail && last, true)
                    && returnsOnEveryPath(f.elseBody(), tail && last, true)) return true;
            } else if (s instanceof ExpressionStatement) {
                if (tail && last && inArm) return true;
            }
        }
        return false;
    }

    /** N-511: whether a value-less {@code return} appears anywhere in the list. */
    static boolean hasBareReturn(List<Statement> stmts) {
        if (stmts == null) return false;
        for (Statement s : stmts) {
            if (s instanceof ReturnStatement r) {
                if (r.value() == null) return true;
            } else if (s instanceof IfStatement f) {
                if (hasBareReturn(f.thenBody()) || hasBareReturn(f.elseBody())) return true;
            } else if (s instanceof ForStatement f) {
                if (hasBareReturn(f.body())) return true;
            }
        }
        return false;
    }

    public static String declaredReturnMismatchMessage(String method, String actual, String declared) {
        return "Method '" + method + "' returns '" + actual + "', which is not assignable to its declared return type '"
            + declared + "'";
    }

    /** Env-free expression type inference used for property initializers. */
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
        if (e instanceof ArrayLiteralExpr) return "<unknown>[]";
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

}
