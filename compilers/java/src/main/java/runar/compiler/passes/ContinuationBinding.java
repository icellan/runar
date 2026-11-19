package runar.compiler.passes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import runar.compiler.ir.ast.ArrayLiteralExpr;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.ByteStringLiteral;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.ForStatement;
import runar.compiler.ir.ast.Identifier;
import runar.compiler.ir.ast.IfStatement;
import runar.compiler.ir.ast.IndexAccessExpr;
import runar.compiler.ir.ast.MemberExpr;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.ParentClass;
import runar.compiler.ir.ast.PrimitiveType;
import runar.compiler.ir.ast.PrimitiveTypeName;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.PropertyNode;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.TernaryExpr;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;

/**
 * D25: bind every state continuation to the input that made it.
 *
 * <p>SECURITY CORE (fund safety). Java port of the TypeScript reference
 * {@code packages/runar-compiler/src/passes/continuation-binding.ts}: same
 * classification, same hidden field name, same diagnostics.
 *
 * <p>Before D25 every stateful covenant checked {@code hash256(continuation ||
 * change) == hashOutputs} over the WHOLE output list, and the BIP-143 preimage
 * carries no input position, so two UTXOs of one contract spent in one
 * transaction that reach the same post-state were BOTH satisfied by ONE
 * continuation output. The binding is a property of the CONTRACT:
 *
 * <ul>
 *   <li>{@code single}: every continuation-producing public method is
 *       mutate-only and reads nothing SINGLE zeroes or redefines. Those
 *       methods default to SIGHASH_SINGLE|FORKID (ALL|ANYONECANPAY|FORKID
 *       becomes SINGLE|ANYONECANPAY|FORKID); an explicit
 *       {@code @sighash ALL|FORKID} is refused.</li>
 *   <li>{@code bind}: at least one auto-continuation method, but not
 *       {@code single}: a hidden last state field
 *       {@code _spentOutpointHash = sha256(extractOutpoint(txPreimage))} is
 *       written by every continuation.</li>
 *   <li>{@code explicit}: every continuation method sizes its own outputs:
 *       unchanged bytes, a warning on an unsigned
 *       {@code addOutput(extractAmount(...))}.</li>
 *   <li>{@code none}: stateless, or no public method produces a
 *       continuation.</li>
 * </ul>
 *
 * <p>The AST is immutable here, so where the TS pass writes
 * {@code method.sighashType} in place, {@link #resolve} returns the resolved
 * contract next to the diagnostics, and {@link #apply} (resolution plus the
 * {@code bind} injection) is what the pipeline lowers.
 */
public final class ContinuationBinding {

    private ContinuationBinding() {}

    /** The hidden state field of a 'bind' contract (reserved; last mutable property). */
    public static final String TWIN_BINDING_FIELD = "_spentOutpointHash";

    /** SIGHASH_SINGLE|FORKID. */
    public static final int SIGHASH_SINGLE_FORKID = SighashDirective.BASE_SINGLE | SighashDirective.FLAG_FORKID;

    /** The contract's D25 class. */
    public enum ContinuationClass { NONE, SINGLE, BIND, EXPLICIT }

    /** Builtins whose meaning SINGLE zeroes or redefines (a mutate-only method reading one keeps ALL). */
    private static final Set<String> SINGLE_INCOMPATIBLE_READS = Set.of(
        "extractHashSequence",
        "extractOutputHash",
        "extractOutputs",
        "extractSigHashType",
        "requireOutputP2PKH"
    );

    /** D25: the shared error text for an explicit ALL sibling in a 'single' contract. */
    public static String explicitAllSiblingMessage(String method) {
        return "method '" + method + "': @sighash ALL|FORKID on a state-continuation method of a contract whose "
            + "continuation methods are all mutate-only reopens twin-input theft: such a contract commits each "
            + "continuation under SIGHASH_SINGLE (one output per input), and one ALL method lets its input reuse "
            + "a sibling's output while its own value leaves as change. Remove the directive (the default is "
            + "SINGLE|FORKID) or write @sighash SINGLE|FORKID";
    }

    /** D25: the shared warning text for an unsigned value-conserving addOutput (D12 C1). */
    public static String unsignedAddOutputMessage(String method) {
        return "method '" + method + "' re-creates the contract with addOutput(extractAmount(...), ...) and checks no "
            + "signature: two UTXOs of this contract spent in one transaction that reach the same state are both "
            + "satisfied by ONE such output, and the other input's value leaves as anyone's change (twin-input "
            + "aliasing). A method that sizes its own outputs is not bound to its input; require a signature, or "
            + "let the compiler size the continuation (write state instead of calling addOutput)";
    }

    /** A resolved contract and the diagnostics resolution produced. */
    public record Resolution(ContractNode contract, List<SighashValidate.Diag> diagnostics) {}

    private record Classification(ContinuationClass cls, List<MethodNode> continuationMethods) {}

    private static String calleeName(Expression callee) {
        if (callee instanceof Identifier id) return id.name();
        if (callee instanceof PropertyAccessExpr pa) return pa.property();
        if (callee instanceof MemberExpr me) return me.property();
        return null;
    }

    private static Map<String, MethodNode> privatesOf(ContractNode contract) {
        Map<String, MethodNode> m = new HashMap<>();
        for (MethodNode x : contract.methods()) if (x.visibility() == Visibility.PRIVATE) m.put(x.name(), x);
        return m;
    }

    /** Every call name reachable from {@code body}, through private helpers (cycle-guarded). */
    private static Set<String> reachableCalls(List<Statement> body, Map<String, MethodNode> privates) {
        Set<String> names = new HashSet<>();
        new Object() {
            final Set<String> visiting = new HashSet<>();

            void stmts(List<Statement> ss) {
                if (ss != null) for (Statement s : ss) stmt(s);
            }

            void stmt(Statement s) {
                if (s instanceof AssignmentStatement a) {
                    expr(a.target());
                    expr(a.value());
                } else if (s instanceof ExpressionStatement es) {
                    expr(es.expression());
                } else if (s instanceof IfStatement is) {
                    expr(is.condition());
                    stmts(is.thenBody());
                    stmts(is.elseBody());
                } else if (s instanceof ForStatement fs) {
                    stmt(fs.init());
                    expr(fs.condition());
                    stmt(fs.update());
                    stmts(fs.body());
                } else if (s instanceof ReturnStatement rs) {
                    expr(rs.value());
                } else if (s instanceof VariableDeclStatement vd) {
                    expr(vd.init());
                }
            }

            void expr(Expression e) {
                if (e instanceof CallExpr c) {
                    String n = calleeName(c.callee());
                    if (n != null) {
                        names.add(n);
                        MethodNode t = privates.get(n);
                        if (t != null && !visiting.contains(n)) {
                            visiting.add(n);
                            stmts(t.body());
                            visiting.remove(n);
                        }
                    }
                    for (Expression a : c.args()) expr(a);
                    if (!(c.callee() instanceof Identifier)) expr(c.callee());
                } else if (e instanceof BinaryExpr b) {
                    expr(b.left());
                    expr(b.right());
                } else if (e instanceof UnaryExpr u) {
                    expr(u.operand());
                } else if (e instanceof TernaryExpr t) {
                    expr(t.condition());
                    expr(t.consequent());
                    expr(t.alternate());
                } else if (e instanceof IndexAccessExpr ia) {
                    expr(ia.object());
                    expr(ia.index());
                } else if (e instanceof MemberExpr me) {
                    expr(me.object());
                } else if (e instanceof ArrayLiteralExpr al) {
                    for (Expression x : al.elements()) expr(x);
                }
            }
        }.stmts(body);
        return names;
    }

    private static Classification classify(ContractNode contract) {
        if (contract.parentClass() != ParentClass.STATEFUL_SMART_CONTRACT) {
            return new Classification(ContinuationClass.NONE, List.of());
        }
        Map<String, MethodNode> privates = privatesOf(contract);
        List<MethodNode> continuationMethods = new ArrayList<>();
        boolean anyAuto = false;
        boolean allSingleEligible = true;
        for (MethodNode m : contract.methods()) {
            if (m.visibility() != Visibility.PUBLIC) continue;
            // The side-effect summary (side-effect-summary.ts): state
            // mutation (FixedArray element writes included), state outputs
            // (addOutput / addRawOutput), data outputs.
            boolean mutates = ContinuationRules.mutatesState(m, contract);
            boolean stateOut = AnfLower.methodHasAddOutput(m, contract);
            boolean dataOut = AnfLower.methodHasAddDataOutput(m, contract);
            if (!(mutates || stateOut || dataOut)) continue;
            continuationMethods.add(m);
            if (!stateOut) anyAuto = true;
            Integer mode = m.sighashType();
            int base = mode == null ? SighashDirective.BASE_ALL : mode & SighashDirective.BASE_TYPE_MASK;
            boolean modeOk = base == SighashDirective.BASE_ALL || base == SighashDirective.BASE_SINGLE;
            boolean readsOk = true;
            for (String n : reachableCalls(m.body(), privates)) {
                if (SINGLE_INCOMPATIBLE_READS.contains(n)) {
                    readsOk = false;
                    break;
                }
            }
            if (stateOut || dataOut || !modeOk || !readsOk) allSingleEligible = false;
        }
        if (continuationMethods.isEmpty()) return new Classification(ContinuationClass.NONE, continuationMethods);
        if (!anyAuto) return new Classification(ContinuationClass.EXPLICIT, continuationMethods);
        return new Classification(
            allSingleEligible ? ContinuationClass.SINGLE : ContinuationClass.BIND, continuationMethods);
    }

    /** The contract's D25 class (read by the injection pass and tests). */
    public static ContinuationClass continuationClass(ContractNode contract) {
        return classify(contract).cls();
    }

    /**
     * D25 resolution, run by {@link Validate} right before the {@code @sighash}
     * field checks (so they see the effective mode) and by {@link #apply}. In a
     * 'single' contract it sets each continuation method's {@code sighashType};
     * it refuses an explicit pure-ALL directive there; in an 'explicit'
     * contract it warns about unsigned value-conserving addOutput methods.
     * Idempotent.
     */
    public static Resolution resolve(ContractNode contract) {
        List<SighashValidate.Diag> diags = new ArrayList<>();
        Classification c = classify(contract);
        if (c.cls() == ContinuationClass.SINGLE) {
            Map<MethodNode, Integer> resolved = new HashMap<>();
            for (MethodNode m : c.continuationMethods()) {
                Integer mode = m.sighashType();
                if (mode == null) {
                    resolved.put(m, SIGHASH_SINGLE_FORKID);
                } else if ((mode & SighashDirective.BASE_TYPE_MASK) == SighashDirective.BASE_ALL) {
                    if ((mode & SighashDirective.FLAG_ANYONECANPAY) != 0) {
                        resolved.put(m, (mode & ~SighashDirective.BASE_TYPE_MASK) | SighashDirective.BASE_SINGLE);
                    } else {
                        diags.add(new SighashValidate.Diag(explicitAllSiblingMessage(m.name()), m.sourceLocation(), false));
                    }
                }
            }
            if (!resolved.isEmpty()) {
                List<MethodNode> methods = new ArrayList<>(contract.methods().size());
                for (MethodNode m : contract.methods()) {
                    Integer mode = resolved.get(m);
                    methods.add(mode == null ? m : new MethodNode(
                        m.name(), m.params(), m.body(), m.visibility(), m.sourceLocation(), mode, m.bindingVariant()));
                }
                contract = new ContractNode(contract.name(), contract.parentClass(), contract.properties(),
                    contract.constructor(), methods, contract.sourceFile());
            }
        } else if (c.cls() == ContinuationClass.EXPLICIT) {
            Map<String, MethodNode> privates = privatesOf(contract);
            for (MethodNode m : c.continuationMethods()) {
                Integer mode = m.sighashType();
                if (mode != null && (mode & SighashDirective.BASE_TYPE_MASK) != SighashDirective.BASE_ALL) continue;
                if (unsignedValueConservingAddOutput(m, privates)) {
                    // The Java AST carries no call-site location, so the
                    // warning points at the method (TS points at the addOutput).
                    diags.add(new SighashValidate.Diag(unsignedAddOutputMessage(m.name()), m.sourceLocation(), true));
                }
            }
        }
        return new Resolution(contract, diags);
    }

    private static boolean isSignatureCheck(String name) {
        return name.equals("checkSig") || name.equals("checkMultiSig") || name.startsWith("verify");
    }

    /**
     * D12 C1: whether the method has an {@code addOutput} whose satoshis
     * argument reads {@code extractAmount} (directly, or through a local
     * initialised from it) while verifying no signature.
     */
    private static boolean unsignedValueConservingAddOutput(MethodNode method, Map<String, MethodNode> privates) {
        for (String n : reachableCalls(method.body(), privates)) if (isSignatureCheck(n)) return false;
        Set<String> amountLocals = new HashSet<>();
        boolean[] found = {false};
        new Object() {
            final Set<String> visiting = new HashSet<>();

            boolean readsAmount(Expression e) {
                if (e instanceof CallExpr c) {
                    if ("extractAmount".equals(calleeName(c.callee()))) return true;
                    for (Expression a : c.args()) if (readsAmount(a)) return true;
                    return false;
                }
                if (e instanceof Identifier id) return amountLocals.contains(id.name());
                if (e instanceof BinaryExpr b) return readsAmount(b.left()) || readsAmount(b.right());
                if (e instanceof UnaryExpr u) return readsAmount(u.operand());
                if (e instanceof TernaryExpr t) {
                    return readsAmount(t.condition()) || readsAmount(t.consequent()) || readsAmount(t.alternate());
                }
                return false;
            }

            void stmts(List<Statement> ss) {
                if (ss != null) for (Statement s : ss) stmt(s);
            }

            void stmt(Statement s) {
                if (s instanceof VariableDeclStatement vd) {
                    if (vd.init() != null && readsAmount(vd.init())) amountLocals.add(vd.name());
                    expr(vd.init());
                } else if (s instanceof AssignmentStatement a) {
                    expr(a.value());
                } else if (s instanceof ExpressionStatement es) {
                    expr(es.expression());
                } else if (s instanceof IfStatement is) {
                    expr(is.condition());
                    stmts(is.thenBody());
                    stmts(is.elseBody());
                } else if (s instanceof ForStatement fs) {
                    stmts(fs.body());
                } else if (s instanceof ReturnStatement rs) {
                    expr(rs.value());
                }
            }

            void expr(Expression e) {
                if (!(e instanceof CallExpr c)) return;
                String n = calleeName(c.callee());
                if ("addOutput".equals(n) && !c.args().isEmpty() && readsAmount(c.args().get(0))) found[0] = true;
                MethodNode t = n == null ? null : privates.get(n);
                if (t != null && !visiting.contains(t.name())) {
                    visiting.add(t.name());
                    stmts(t.body());
                    visiting.remove(t.name());
                }
                for (Expression a : c.args()) expr(a);
            }
        }.stmts(method.body());
        return found[0];
    }

    /**
     * D25 injection, run after typecheck (before fixed-array expansion): a
     * 'bind' contract gains the hidden {@code _spentOutpointHash: Sha256 =
     * 0x00..00} as its LAST property. ANF lowering then writes it in every
     * auto-continuation and appends it to every addOutput. The zero
     * initializer keeps it out of the constructor ABI. Any other class is
     * returned unchanged.
     */
    public static ContractNode inject(ContractNode contract) {
        if (classify(contract).cls() != ContinuationClass.BIND) return contract;
        for (PropertyNode p : contract.properties()) if (TWIN_BINDING_FIELD.equals(p.name())) return contract;
        PropertyNode field = new PropertyNode(
            TWIN_BINDING_FIELD,
            new PrimitiveType(PrimitiveTypeName.SHA_256),
            false,
            new ByteStringLiteral("00".repeat(32), null),
            contract.constructor() == null ? null : contract.constructor().sourceLocation(),
            null
        );
        List<PropertyNode> props = new ArrayList<>(contract.properties());
        props.add(field);
        return new ContractNode(contract.name(), contract.parentClass(), props,
            contract.constructor(), contract.methods(), contract.sourceFile());
    }

    /**
     * The contract the backend lowers: {@link #resolve resolved} sighash modes
     * plus the {@link #inject 'bind' field}. Idempotent; diagnostics are
     * {@link Validate}'s to report.
     */
    public static ContractNode apply(ContractNode contract) {
        return inject(resolve(contract).contract());
    }

    /** Whether the contract carries the hidden spent-outpoint field ('bind' class, injected). */
    public static boolean bindsOutpoint(ContractNode contract) {
        for (PropertyNode p : contract.properties()) if (TWIN_BINDING_FIELD.equals(p.name())) return true;
        return false;
    }
}
