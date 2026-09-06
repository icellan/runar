package runar.compiler.passes;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
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
        ctx.warnStrippedReadonlyFields();

        // Issue #123: reject preimage-field reads / output bindings that are
        // unsound under a method's declared @sighash mode (security core). Emits
        // both errors (unsound usages) and warnings (e.g. an explicit single-output
        // SINGLE covenant whose same-index value cannot be pinned statically).
        for (SighashValidate.Diag d : SighashValidate.validate(contract)) {
            if (d.isWarning()) {
                ctx.warn(d.message(), d.loc());
            } else {
                ctx.error(d.message(), d.loc());
            }
        }

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

            if (contract.parentClass() == ParentClass.SMART_CONTRACT
                || contract.parentClass() == ParentClass.UNSAFE_SMART_CONTRACT) {
                String label = contract.parentClass() == ParentClass.UNSAFE_SMART_CONTRACT
                    ? "UnsafeSmartContract" : "SmartContract";
                for (PropertyNode p : contract.properties()) {
                    if (!p.readonly()) {
                        error(
                            "Property '" + p.name() + "' in " + label + " must be readonly. "
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

            validateConstructorSlotBijection(ctor);
        }

        /**
         * Enforce the NEW-002 invariant: every constructor parameter
         * initialises exactly one property that needs a deploy-time value, and
         * the i-th parameter initialises the i-th such property.
         *
         * <p>A property's deploy-time value comes from a constructor ARGUMENT,
         * and the artifact addresses those arguments POSITIONALLY: the ABI
         * constructor params come from the constructor SIGNATURE while a
         * constructor slot's {@code paramIndex} is an index into the properties
         * with no {@code initialValue}, and the SDK splices
         * {@code constructorArgs[slot.paramIndex]} into the slot's bytes. Two
         * independently built lists, assumed to line up. Where they disagree a
         * deploy argument lands in ANOTHER property's slot, silently — a
         * deployed contract authorising a value the developer never passed for
         * that property.
         *
         * <p>"Needs a deploy-time value" mirrors
         * {@code constructorAssignedProperties} in {@code AnfLower} exactly: a
         * property carries a compile-time {@code initialValue} iff it has an
         * initializer the constructor does NOT override by assigning it a bare
         * parameter.
         */
        void validateConstructorSlotBijection(MethodNode ctor) {
            Map<String, Integer> paramIndex = new LinkedHashMap<>();
            for (int i = 0; i < ctor.params().size(); i++) {
                paramIndex.put(ctor.params().get(i).name(), i);
            }

            // property -> distinct bare parameters assigned to it; a property
            // with any non-parameter assignment is recorded with an EMPTY set.
            Map<String, Set<String>> propToParams = new LinkedHashMap<>();
            Map<String, Set<String>> paramToProps = new LinkedHashMap<>();
            for (Statement stmt : ctor.body()) {
                if (!(stmt instanceof AssignmentStatement assign)) continue;
                if (!(assign.target() instanceof PropertyAccessExpr target)) continue;
                String prop = target.property();
                if (!(assign.value() instanceof Identifier id) || !paramIndex.containsKey(id.name())) {
                    propToParams.put(prop, new TreeSet<>());
                    continue;
                }
                propToParams.computeIfAbsent(prop, k -> new TreeSet<>()).add(id.name());
                paramToProps.computeIfAbsent(id.name(), k -> new TreeSet<>()).add(prop);
            }

            int before = errors.size();

            // (a) One parameter feeding several properties: only one of them
            // could own the argument, so the rest keep a default or deploy
            // undefined.
            for (ParamNode param : ctor.params()) {
                Set<String> props = paramToProps.get(param.name());
                if (props != null && props.size() > 1) {
                    error(
                        "constructor parameter '" + param.name() + "' initialises more than one "
                            + "property (" + String.join(", ", props) + "). Each constructor "
                            + "parameter is spliced into exactly one property's deploy-time slot, "
                            + "so only the first would receive the argument. Declare one parameter "
                            + "per property.",
                        ctor.sourceLocation()
                    );
                }
            }

            // (b) One property fed by several parameters — no single argument owns it.
            for (PropertyNode p : contract.properties()) {
                Set<String> params = propToParams.get(p.name());
                if (params != null && params.size() > 1) {
                    error(
                        "property '" + p.name() + "' is assigned more than one constructor "
                            + "parameter (" + String.join(", ", params) + "). Each property that "
                            + "needs a deploy-time value corresponds to exactly one constructor "
                            + "parameter.",
                        ctor.sourceLocation()
                    );
                }
            }

            // (c) A property that needs a deploy-time value but whose
            // constructor assignment is not a parameter. A property assigned
            // NOTHING is already reported above, so it is skipped here rather
            // than double-reported.
            for (PropertyNode p : contract.properties()) {
                if (p.initializer() != null) continue;
                Set<String> params = propToParams.get(p.name());
                if (params == null || !params.isEmpty()) continue;
                error(
                    "property '" + p.name() + "' has no initializer and is not assigned a "
                        + "constructor parameter, so it has no deploy-time value. The constructor "
                        + "body is not compiled into the locking script — give the property a "
                        + "literal initializer or assign it a constructor parameter (this."
                        + p.name() + " = " + p.name() + ").",
                    ctor.sourceLocation()
                );
            }

            // (d) A parameter that initialises nothing: its argument is dropped
            // and, because slots are positional, every later argument lands in
            // the wrong slot.
            for (ParamNode param : ctor.params()) {
                if (paramToProps.containsKey(param.name())) continue;
                error(
                    "constructor parameter '" + param.name() + "' does not initialise any "
                        + "property. Constructor arguments are spliced into property slots "
                        + "positionally, so an unused parameter drops its own argument and shifts "
                        + "every later one into the wrong property's slot. Assign it (this."
                        + param.name() + " = " + param.name() + ") or remove the parameter.",
                    ctor.sourceLocation()
                );
            }

            // (e) Order. Only meaningful once (a)-(d) hold, otherwise the
            // positions being compared are themselves the thing that is broken.
            if (errors.size() != before) return;
            int slot = 0;
            for (PropertyNode p : contract.properties()) {
                Set<String> params = propToParams.get(p.name());
                String single = params != null && params.size() == 1 ? params.iterator().next() : null;
                if (p.initializer() != null && single == null) continue;
                if (single != null) {
                    int declared = paramIndex.get(single);
                    if (declared != slot) {
                        String abiName = slot < ctor.params().size()
                            ? ctor.params().get(slot).name()
                            : "?";
                        error(
                            "property '" + p.name() + "' occupies deploy-time slot " + slot
                                + ", but the constructor parameter that initialises it ('" + single
                                + "') is declared at position " + declared + ". Constructor "
                                + "arguments are spliced positionally, so the deployed script "
                                + "would carry argument " + slot + " — advertised by the ABI as "
                                + "parameter '" + abiName + "' — in this property's slot. Declare "
                                + "the parameters in the same order as the properties they "
                                + "initialise.",
                            ctor.sourceLocation()
                        );
                    }
                }
                slot++;
            }
        }

        // --------------------------------------------------------------
        // Methods
        // --------------------------------------------------------------

        void validateMethods() {
            // A contract with no public methods has no spending entry points
            // and compiles to an empty script — never what the author meant
            // (usually a missing `public` modifier; methods default to
            // private).
            boolean hasPublic = false;
            for (MethodNode m : contract.methods()) {
                if (m.visibility() == Visibility.PUBLIC) {
                    hasPublic = true;
                    break;
                }
            }
            if (!hasPublic) {
                error(
                    "Contract '" + contract.name() + "' has no public methods — no spending "
                        + "entry points; add 'public' to at least one method",
                    null
                );
            }

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

            // `return` is a PRIVATE-helper construct only (NEW-012).
            //
            // spec/grammar.md:161 ("Public methods MUST return `void`") is why
            // this tier already rejected `return expr;` — alone among the seven,
            // which is how the other six shipped a FAIL-OPEN miscompile: the
            // returned value became the enclosing branch's result and therefore
            // the script's final truthiness, so any truthy expr spent the
            // contract WITHOUT reaching the guarding assert.
            //
            // The bare `return;` was the hole THIS tier had. spec/grammar.md:162
            // requires a public method to end with the assert that encodes its
            // spending condition, and spec/semantics.md gives `return` no
            // early-exit meaning at all: §4.6 defines it ONLY as "the value of
            // this method is v" (the inlining semantics), while §4.7 sequences
            // statements UNCONDITIONALLY. Elsewhere a bare `return;` left the
            // enclosing branch with no result, its arm yielded OP_0, and the
            // whole script evaluated FALSE — an unspendable UTXO from source
            // that compiled clean.
            //
            // So: reject BOTH spellings, everywhere in a public body.
            if (m.visibility() == Visibility.PUBLIC) {
                walkReturnsInBody(m.body(), returnStmt ->
                    error(
                        "public method '" + m.name()
                            + "' must not use `return`: public methods are spending entry"
                            + " points, they return void (spec/grammar.md:161) and must end"
                            + " with an assert() that encodes the spending condition"
                            + " (spec/grammar.md:162). Rúnar has no early exit — restructure"
                            + " the guard as an if/else, or move the logic into a private"
                            + " helper, where `return` is allowed.",
                        returnStmt.sourceLocation()
                    )
                );
            }

            // Public methods must end with an assert() call (unless
            // stateful, where the compiler auto-injects the final assert;
            // or UnsafeSmartContract, where a terminal asm({..., out_arity:
            // 1}) provides the truthy stack value).
            if (m.visibility() == Visibility.PUBLIC
                && contract.parentClass() == ParentClass.SMART_CONTRACT) {
                if (!endsWithAssert(m.body())) {
                    error(
                        "public method '" + m.name() + "' must end with an assert() / assertThat() call",
                        m.sourceLocation()
                    );
                }
            }
            if (m.visibility() == Visibility.PUBLIC
                && contract.parentClass() == ParentClass.UNSAFE_SMART_CONTRACT) {
                if (!endsWithAssert(m.body()) && !endsWithTerminalAsm(m.body())) {
                    error(
                        "public method '" + m.name()
                            + "' must end with an assert() call or a terminal asm({...}) with out_arity 1",
                        m.sourceLocation()
                    );
                }
            }

            // #131: warn when a public method gates on extractLocktime but
            // never asserts the spending tx is non-final
            // (extractSequence < 0xffffffff). Advisory only — no effect on the
            // emitted bytecode.
            if (m.visibility() == Visibility.PUBLIC) {
                warnLocktimeWithoutSequenceGuard(m, this);
            }

            // Gate asm({...}) calls on UnsafeSmartContract and check the
            // structural args.
            validateAsmUsage(m);

            // readonly properties may only be assigned in the constructor.
            checkReadonlyWrites(m);

            for (Statement s : m.body()) {
                validateStatement(s);
            }
        }

        // --------------------------------------------------------------
        // Readonly property writes
        // --------------------------------------------------------------

        /**
         * Report every write to a readonly contract property in a method body.
         *
         * <p>{@code spec/semantics.md}:
         * {@code <this.p = e, env, sigma> ==> ERROR: cannot assign to readonly property}
         *
         * <p>The constructor is exempt — that is where every contract
         * initialises its readonly properties — so this runs per METHOD only
         * ({@code validateConstructor} never calls in here, even though it
         * shares {@code validateStatement}).
         *
         * <p>Three AST shapes reach {@code update_prop} in ANF lowering and are
         * all covered: {@code this.p = e}, {@code this.p++} / {@code this.p--},
         * and {@code this.arr[i] = e}.
         */
        private void checkReadonlyWrites(MethodNode m) {
            Set<String> readonly = new HashSet<>();
            for (PropertyNode p : contract.properties()) {
                if (p.readonly()) {
                    readonly.add(p.name());
                }
            }
            if (readonly.isEmpty()) {
                return;
            }
            visitReadonlyWrites(m, m.body(), readonly);
        }

        private void visitReadonlyWrites(MethodNode m, List<Statement> stmts, Set<String> readonly) {
            for (Statement s : stmts) {
                if (s instanceof AssignmentStatement a) {
                    reportIfReadonly(m, writtenProperty(a.target()), readonly, a.sourceLocation());
                    visitReadonlyMutations(m, a.target(), readonly, a.sourceLocation());
                    visitReadonlyMutations(m, a.value(), readonly, a.sourceLocation());
                } else if (s instanceof VariableDeclStatement v) {
                    visitReadonlyMutations(m, v.init(), readonly, v.sourceLocation());
                } else if (s instanceof ExpressionStatement e) {
                    visitReadonlyMutations(m, e.expression(), readonly, e.sourceLocation());
                } else if (s instanceof ReturnStatement r) {
                    visitReadonlyMutations(m, r.value(), readonly, r.sourceLocation());
                } else if (s instanceof IfStatement i) {
                    visitReadonlyMutations(m, i.condition(), readonly, i.sourceLocation());
                    visitReadonlyWrites(m, i.thenBody(), readonly);
                    if (i.elseBody() != null) {
                        visitReadonlyWrites(m, i.elseBody(), readonly);
                    }
                } else if (s instanceof ForStatement f) {
                    List<Statement> head = new ArrayList<>();
                    if (f.init() != null) head.add(f.init());
                    if (f.update() != null) head.add(f.update());
                    visitReadonlyWrites(m, head, readonly);
                    visitReadonlyMutations(m, f.condition(), readonly, f.sourceLocation());
                    visitReadonlyWrites(m, f.body(), readonly);
                }
            }
        }

        /** Flag {@code this.p++} / {@code this.p--} anywhere inside an expression. */
        private void visitReadonlyMutations(
            MethodNode m, Expression expr, Set<String> readonly, SourceLocation loc
        ) {
            walkExpression(expr, e -> {
                Expression operand;
                if (e instanceof IncrementExpr ie) {
                    operand = ie.operand();
                } else if (e instanceof DecrementExpr de) {
                    operand = de.operand();
                } else {
                    return;
                }
                reportIfReadonly(m, writtenProperty(operand), readonly, loc);
            });
        }

        private void reportIfReadonly(
            MethodNode m, String name, Set<String> readonly, SourceLocation loc
        ) {
            if (name == null || !readonly.contains(name)) {
                return;
            }
            error(
                "cannot assign to readonly property '" + name + "' in method '"
                    + m.name() + "'. readonly properties may only be assigned "
                    + "in the constructor.",
                loc
            );
        }

        /**
         * Resolve the contract property an assignment target writes to, or
         * {@code null}. Unwraps {@code IndexAccessExpr} chains so
         * {@code this.grid[i][j] = v} resolves to {@code grid}.
         */
        private static String writtenProperty(Expression target) {
            Expression node = target;
            while (node instanceof IndexAccessExpr ia) {
                node = ia.object();
            }
            return node instanceof PropertyAccessExpr pa ? pa.property() : null;
        }

        // --------------------------------------------------------------
        // asm() intrinsic validation
        // --------------------------------------------------------------

        /**
         * Walk a method body and validate every asm({...}) call. Gates the
         * intrinsic on UnsafeSmartContract, confirms the
         * parser-normalised arg shape, and enforces the
         * expression-form-out-arity-1 invariant.
         */
        private void validateAsmUsage(MethodNode m) {
            walkExpressionsInBody(m.body(), expr -> {
                if (!isAsmCall(expr)) return;
                CallExpr call = (CallExpr) expr;

                if (contract.parentClass() != ParentClass.UNSAFE_SMART_CONTRACT) {
                    error(
                        "'asm' is only available in contracts extending UnsafeSmartContract; "
                            + "got " + contract.parentClass().canonical()
                            + ". Move the call into a class that extends UnsafeSmartContract "
                            + "(and import { UnsafeSmartContract } from 'runar-lang').",
                        m.sourceLocation()
                    );
                    return;
                }

                if (call.args().size() != 3) {
                    error(
                        "asm() expects exactly one object-literal argument "
                            + "{ body, in_arity?, out_arity? }",
                        m.sourceLocation()
                    );
                    return;
                }

                Expression bodyArg = call.args().get(0);
                if (!(bodyArg instanceof ByteStringLiteral bsl)) {
                    error("asm() body must be a hex string literal", m.sourceLocation());
                } else {
                    String body = bsl.value();
                    if (body == null || body.isEmpty()) {
                        error("asm() body must be a non-empty hex string literal", m.sourceLocation());
                    } else if ((body.length() & 1) != 0) {
                        error(
                            "asm() body has odd hex length (" + body.length()
                                + "); each opcode byte requires two hex characters",
                            m.sourceLocation()
                        );
                    } else if (!isHexString(body)) {
                        error(
                            "asm() body contains non-hex characters; only 0-9, a-f, A-F are allowed",
                            m.sourceLocation()
                        );
                    }
                }

                Expression inArg = call.args().get(1);
                if (!(inArg instanceof BigIntLiteral inBi) || inBi.value().signum() < 0) {
                    error("asm() in_arity must be a non-negative integer literal", m.sourceLocation());
                }

                Expression outArg = call.args().get(2);
                BigIntLiteral outBi = outArg instanceof BigIntLiteral b ? b : null;
                if (outBi == null || outBi.value().signum() < 0) {
                    error("asm() out_arity must be a non-negative integer literal", m.sourceLocation());
                }

                // Expression-form asm<T>({...}) returns a value that flows
                // into a let-binding — exactly ONE stack value, so out_arity
                // must be 1.
                String returnType = call.asmReturnType();
                if (returnType != null && !returnType.isEmpty()
                    && outBi != null
                    && !outBi.value().equals(java.math.BigInteger.ONE)) {
                    error(
                        "Expression-form asm<" + returnType + ">() must have out_arity 1 "
                            + "(got " + outBi.value().toString()
                            + "); only a single stack value can be bound to the result variable.",
                        m.sourceLocation()
                    );
                }
            });
        }

        private static boolean isAsmCall(Expression expr) {
            if (!(expr instanceof CallExpr call)) return false;
            return call.callee() instanceof Identifier id && "asm".equals(id.name());
        }

        /**
         * Issue #109 (Option 4): warn when DCE will strip an un-annotated
         * readonly field. Such a field carries no compile-time value (no
         * initializer), is referenced by no method body, and is not marked
         * {@code /** @embedAlways *&#47;}, so it is eliminated from the locking
         * script entirely — silently dropping deploy-time metadata an author may
         * intend to recover from the on-chain script later. Rides the warning
         * channel; {@code @embedAlways} fields are forced back into the script
         * during ANF lowering and so are excluded here (never warn).
         */
        private void warnStrippedReadonlyFields() {
            java.util.Set<String> referenced = new java.util.HashSet<>();
            for (MethodNode m : contract.methods()) {
                walkExpressionsInBody(m.body(), expr -> {
                    if (expr instanceof PropertyAccessExpr pa) {
                        referenced.add(pa.property());
                    } else if (expr instanceof MemberExpr me
                            && me.object() instanceof Identifier id
                            && "this".equals(id.name())) {
                        referenced.add(me.property());
                    } else if (expr instanceof Identifier id) {
                        referenced.add(id.name());
                    }
                });
            }
            for (PropertyNode prop : contract.properties()) {
                if (prop.readonly()
                        && !prop.embedAlways()
                        && prop.initializer() == null
                        && !referenced.contains(prop.name())) {
                    warn(
                        "readonly field '" + prop.name() + "' is not referenced in any method body "
                            + "and was eliminated by DCE; annotate it /** @embedAlways */ to preserve "
                            + "it in the on-chain script",
                        prop.sourceLocation());
                }
            }
        }

        @FunctionalInterface
        private interface ExprSink {
            void accept(Expression expr);
        }

        private static void walkExpressionsInBody(List<Statement> body, ExprSink sink) {
            for (Statement s : body) walkExpressionsInStmt(s, sink);
        }

        private static void walkExpressionsInStmt(Statement s, ExprSink sink) {
            if (s instanceof ExpressionStatement es) {
                walkExpression(es.expression(), sink);
            } else if (s instanceof VariableDeclStatement v) {
                walkExpression(v.init(), sink);
            } else if (s instanceof AssignmentStatement a) {
                walkExpression(a.target(), sink);
                walkExpression(a.value(), sink);
            } else if (s instanceof IfStatement i) {
                walkExpression(i.condition(), sink);
                walkExpressionsInBody(i.thenBody(), sink);
                if (i.elseBody() != null) walkExpressionsInBody(i.elseBody(), sink);
            } else if (s instanceof ForStatement f) {
                walkExpression(f.condition(), sink);
                walkExpressionsInBody(f.body(), sink);
            } else if (s instanceof ReturnStatement r) {
                if (r.value() != null) walkExpression(r.value(), sink);
            }
        }

        private static void walkExpression(Expression e, ExprSink sink) {
            if (e == null) return;
            sink.accept(e);
            if (e instanceof BinaryExpr be) {
                walkExpression(be.left(), sink);
                walkExpression(be.right(), sink);
            } else if (e instanceof UnaryExpr ue) {
                walkExpression(ue.operand(), sink);
            } else if (e instanceof CallExpr c) {
                walkExpression(c.callee(), sink);
                for (Expression a : c.args()) walkExpression(a, sink);
            } else if (e instanceof MemberExpr me) {
                walkExpression(me.object(), sink);
            } else if (e instanceof TernaryExpr te) {
                walkExpression(te.condition(), sink);
                walkExpression(te.consequent(), sink);
                walkExpression(te.alternate(), sink);
            } else if (e instanceof IndexAccessExpr ia) {
                walkExpression(ia.object(), sink);
                walkExpression(ia.index(), sink);
            } else if (e instanceof IncrementExpr ie) {
                walkExpression(ie.operand(), sink);
            } else if (e instanceof DecrementExpr de) {
                walkExpression(de.operand(), sink);
            } else if (e instanceof ArrayLiteralExpr al) {
                for (Expression el : al.elements()) walkExpression(el, sink);
            }
        }

        private static boolean isHexString(String s) {
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                boolean ok = (c >= '0' && c <= '9')
                    || (c >= 'a' && c <= 'f')
                    || (c >= 'A' && c <= 'F');
                if (!ok) return false;
            }
            return true;
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
            // the comparison in the loop condition. Non-zero starts and
            // countdown loops (`i--` with `>`/`>=`) are supported: the ANF loop
            // node carries an explicit start value and step direction (issue
            // #121), so lowering binds `iterVar = start + i*step` on each
            // unrolled iteration.
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
                    && !"asm".equals(name)
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

    /**
     * Reports whether the last statement of {@code body} is an
     * {@code asm({...})} call with the parser-normalised positional args
     * {@code (body, in_arity, out_arity)} and an {@code out_arity} literal
     * equal to 1. If/else branches that both terminate in a terminal asm
     * (or assert) also count, mirroring the asserts-on-both-branches rule.
     */
    private static boolean endsWithTerminalAsm(List<Statement> body) {
        if (body.isEmpty()) return false;
        Statement last = body.get(body.size() - 1);
        if (last instanceof ExpressionStatement es) {
            Expression expr = es.expression();
            if (!(expr instanceof CallExpr c)) return false;
            if (!(c.callee() instanceof Identifier id) || !"asm".equals(id.name())) return false;
            // The parser always rewrites asm({...}) into positional
            // (body, in_arity, out_arity).
            if (c.args().size() == 3
                && c.args().get(2) instanceof BigIntLiteral outArity
                && outArity.value().equals(java.math.BigInteger.ONE)) {
                return true;
            }
            return false;
        }
        if (last instanceof IfStatement it) {
            boolean thenEnds = endsWithTerminalAsm(it.thenBody()) || endsWithAssert(it.thenBody());
            boolean elseEnds = it.elseBody() != null
                && (endsWithTerminalAsm(it.elseBody()) || endsWithAssert(it.elseBody()));
            return thenEnds && elseEnds;
        }
        return false;
    }

    // Only integer literals (and their negation) can be unrolled into fixed
    // Bitcoin Script by anf-lower. A bare identifier bound (e.g. `final N`) or a
    // runtime member access (`this.x`) is NOT resolvable and must be rejected
    // here with a graceful diagnostic — anf-lower's extractLoopShape would
    // otherwise throw. Mirrors the reference TS compiler's observable behavior:
    // only literal loop bounds compile.
    private static boolean isCompileTimeConstant(Expression e) {
        if (e == null) return false;
        if (e instanceof BigIntLiteral) return true;
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

    // ------------------------------------------------------------------
    // #131: locktime soundness — extractLocktime needs an extractSequence guard
    // ------------------------------------------------------------------

    /** Sentinel maximum nSequence: a tx is FINAL (ignores locktime) at this value. */
    private static final java.math.BigInteger SEQUENCE_FINAL =
        java.math.BigInteger.valueOf(0xffffffffL);

    /** True when {@code expr} is a direct call to the named intrinsic, e.g. {@code f(...)}. */
    private static boolean isCallToNamed(Expression expr, String name) {
        return expr instanceof CallExpr c
            && c.callee() instanceof Identifier id
            && name.equals(id.name());
    }

    /**
     * True when {@code expr} reads the transaction locktime. Both the raw
     * intrinsic {@code extractLocktime(preimage)} and its ergonomic sugar
     * {@code currentBlockHeight()} (which the ANF pass desugars to
     * {@code extractLocktime(txPreimage)}) count — either read is unsound
     * without a sequence-finality guard.
     */
    private static boolean isLocktimeRead(Expression expr) {
        return isCallToNamed(expr, "extractLocktime")
            || isCallToNamed(expr, "currentBlockHeight");
    }

    /**
     * True when {@code expr} is an {@code extractSequence(...) < <final>}-style
     * comparison (the guard that makes a locktime gate consensus-enforced).
     * Accepts the two natural spellings: {@code extractSequence(pre) < N} /
     * {@code <= N}, and the reversed {@code N > extractSequence(pre)} /
     * {@code >= ...}. {@code N} must be a bigint literal no greater than the
     * finality sentinel, so the guard genuinely forces non-finality.
     */
    private static boolean isSequenceFinalityGuard(Expression expr) {
        if (!(expr instanceof BinaryExpr be)) return false;
        Expression.BinaryOp op = be.op();
        if ((op == Expression.BinaryOp.LT || op == Expression.BinaryOp.LE)
            && isCallToNamed(be.left(), "extractSequence") && isSequenceBound(be.right())) {
            return true;
        }
        if ((op == Expression.BinaryOp.GT || op == Expression.BinaryOp.GE)
            && isCallToNamed(be.right(), "extractSequence") && isSequenceBound(be.left())) {
            return true;
        }
        return false;
    }

    private static boolean isSequenceBound(Expression e) {
        return e instanceof BigIntLiteral lit && lit.value().compareTo(SEQUENCE_FINAL) <= 0;
    }

    /**
     * #131: warn when {@code method} (transitively, through the private-helper
     * call graph) reads the tx locktime but never asserts the tx is non-final.
     * A locktime gate is not consensus-enforced unless
     * {@code extractSequence < 0xffffffff} is also asserted — otherwise an
     * all-final-sequence spend bypasses it. Advisory (warning) only — no effect
     * on emitted bytecode.
     */
    private static void warnLocktimeWithoutSequenceGuard(MethodNode method, Ctx ctx) {
        java.util.Map<String, MethodNode> privateMethods = new java.util.HashMap<>();
        for (MethodNode m : ctx.contract.methods()) {
            if (m.visibility() == Visibility.PRIVATE) {
                privateMethods.put(m.name(), m);
            }
        }

        boolean[] readsLocktime = {false};
        boolean[] hasSequenceGuard = {false};
        Set<String> visited = new HashSet<>();
        visited.add(method.name());
        java.util.Deque<MethodNode> queue = new java.util.ArrayDeque<>();
        queue.add(method);

        while (!queue.isEmpty()) {
            MethodNode current = queue.poll();
            Ctx.walkExpressionsInBody(current.body(), expr -> {
                if (isLocktimeRead(expr)) readsLocktime[0] = true;
                if (isSequenceFinalityGuard(expr)) hasSequenceGuard[0] = true;
            });
            // Follow calls into private helpers so a guard (or locktime read)
            // supplied by an inlined helper is seen by the public entry point.
            Set<String> calls = new HashSet<>();
            collectMethodCalls(current.body(), calls);
            for (String callee : calls) {
                if (!visited.contains(callee) && privateMethods.containsKey(callee)) {
                    visited.add(callee);
                    queue.add(privateMethods.get(callee));
                }
            }
        }

        if (readsLocktime[0] && !hasSequenceGuard[0]) {
            ctx.warn(
                "method '" + method.name() + "' reads extractLocktime but does not assert "
                    + "extractSequence < 0xffffffff; a locktime gate is not consensus-enforced "
                    + "unless the tx is non-final — add "
                    + "assert(extractSequence(this.txPreimage) < 0xffffffffn)",
                method.sourceLocation());
        }
    }

    @SuppressWarnings("unused")
    private static String primitiveName(PrimitiveTypeName p) {
        return p == null ? "<unknown>" : p.canonical();
    }
}
