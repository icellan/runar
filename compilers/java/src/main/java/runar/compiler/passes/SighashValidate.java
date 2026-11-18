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
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.DecrementExpr;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.ForStatement;
import runar.compiler.ir.ast.Identifier;
import runar.compiler.ir.ast.IfStatement;
import runar.compiler.ir.ast.IncrementExpr;
import runar.compiler.ir.ast.IndexAccessExpr;
import runar.compiler.ir.ast.MemberExpr;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.ParentClass;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.SourceLocation;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.TernaryExpr;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;

/**
 * Field-usage validation for per-method {@code @sighash} modes (issue #123) —
 * Java port of {@code packages/runar-compiler/src/passes/sighash-validate.ts}.
 *
 * <p>SECURITY CORE. A relaxed sighash flag ZEROES specific BIP-143 preimage
 * fields; a covenant that still reads one of those fields (or binds an output
 * the flag no longer commits to) is exploitable. This pass rejects, at compile
 * time, every field read / output binding that becomes unsound under the
 * method's declared mode. The walk is transitive through private helpers and
 * covers for-loop headers (init + condition) and assignment targets.
 *
 * <p>Methods with no directive (default ALL|FORKID) are never flagged.
 */
public final class SighashValidate {
    private SighashValidate() {}

    /** Builtins that read the all-inputs prevouts digest (zeroed under ANYONECANPAY). */
    private static final Set<String> HASHPREVOUTS_READERS = Set.of("extractHashPrevouts");
    /** Builtins that read the all-inputs sequence digest (zeroed unless pure ALL). */
    private static final Set<String> HASHSEQUENCE_READERS = Set.of("extractHashSequence");
    /** Builtins that read the outputs digest (zeroed under NONE). */
    private static final Set<String> HASHOUTPUTS_READERS = Set.of("extractOutputHash", "extractOutputs");
    /** Intrinsic that binds a companion input's prevout script (needs hashPrevouts). */
    private static final Set<String> PREVOUT_SCRIPT_INTRINSICS = Set.of("extractPrevOutputScript");
    /** Intrinsics that assert an output (bound via hashOutputs). */
    private static final Set<String> OUTPUT_ASSERT_INTRINSICS = Set.of("requireOutputP2PKH");
    /** Output-emitting intrinsics (state continuation outputs). */
    private static final Set<String> STATE_OUTPUT_INTRINSICS = Set.of("addOutput", "addRawOutput");
    private static final Set<String> DATA_OUTPUT_INTRINSICS = Set.of("addDataOutput");

    /** A diagnostic produced by this pass. */
    public record Diag(String message, SourceLocation loc, boolean isWarning) {}

    /** Flagged builtin/intrinsic usages of one method (with source locations). */
    private static final class MethodScan {
        final List<String> hashPrevoutsReads = new ArrayList<>();
        final List<String> hashSequenceReads = new ArrayList<>();
        final List<String> hashOutputsReads = new ArrayList<>();
        final List<String> prevoutScriptReads = new ArrayList<>();
        final List<String> outputAsserts = new ArrayList<>();
        int stateOutputCount = 0;
        int dataOutputCount = 0;
    }

    /**
     * Validate every public method's {@code @sighash} field usage. Returns
     * diagnostics (errors + warnings); empty when all modes are used soundly.
     */
    public static List<Diag> validate(ContractNode contract) {
        List<Diag> out = new ArrayList<>();
        boolean isStateful = contract.parentClass() == ParentClass.STATEFUL_SMART_CONTRACT;

        Map<String, MethodNode> privateByName = new HashMap<>();
        for (MethodNode m : contract.methods()) {
            if (m.visibility() == Visibility.PRIVATE) {
                privateByName.put(m.name(), m);
            }
        }

        for (MethodNode method : contract.methods()) {
            if (method.visibility() != Visibility.PUBLIC) {
                continue;
            }
            if (method.sighashType() == null) {
                continue; // default ALL|FORKID — allow all
            }

            int mode = method.sighashType();
            int base = mode & SighashDirective.BASE_TYPE_MASK;
            boolean acp = (mode & SighashDirective.FLAG_ANYONECANPAY) != 0;
            String label = SighashDirective.describeSighash(mode);
            SourceLocation loc = method.sourceLocation();

            MethodScan scan = scanMethod(method, privateByName);

            // State-continuation binding (stateful auto-injected hashOutputs).
            boolean needsContinuation = isStateful
                // ContinuationRules.mutatesState also counts FixedArray element
                // writes, which this unexpanded contract still spells as such.
                && (ContinuationRules.mutatesState(method, contract)
                    || AnfLower.methodHasAddOutput(method, contract)
                    || AnfLower.methodHasAddDataOutput(method, contract));

            // ---- ANYONECANPAY: only THIS input is signed ----------------------
            if (acp) {
                for (String u : scan.hashPrevoutsReads) {
                    out.add(err(loc, "@sighash " + label + ": '" + u
                        + "' reads hashPrevouts, which is zeroed under ANYONECANPAY (only this input is"
                        + " signed) — the covenant cannot constrain the input set, so any check on it is"
                        + " trivially bypassable. Remove ANYONECANPAY or drop the " + u + " read."));
                }
                for (String u : scan.prevoutScriptReads) {
                    out.add(err(loc, "@sighash " + label + ": '" + u
                        + "' binds a companion input's prevout script, but ANYONECANPAY zeroes"
                        + " hashPrevouts so the input set is unconstrained — an attacker can substitute"
                        + " inputs freely. Companion-input covenants require the full prevout set to be"
                        + " committed (drop ANYONECANPAY)."));
                }
            }

            // ---- hashSequence is committed only under pure ALL (no ACP) --------
            boolean hashSequenceSound = base == SighashDirective.BASE_ALL && !acp;
            if (!hashSequenceSound) {
                for (String u : scan.hashSequenceReads) {
                    out.add(err(loc, "@sighash " + label + ": '" + u
                        + "' reads hashSequence, which is zeroed under any mode other than SIGHASH_ALL"
                        + " (NONE / SINGLE / ANYONECANPAY all clear it) — the read yields attacker-chosen"
                        + " zeros. Use SIGHASH_ALL or drop the " + u + " read."));
                }
            }

            // ---- NONE commits to NO outputs -----------------------------------
            if (base == SighashDirective.BASE_NONE) {
                if (needsContinuation) {
                    out.add(err(loc, "@sighash " + label + ": this stateful method binds a"
                        + " state-continuation output via hashOutputs, but NONE commits to NO outputs"
                        + " (hashOutputs is zeroed) — the continuation is unenforceable, so the next-state"
                        + " covenant is meaningless and the spend is unsound. A continuation covenant"
                        + " cannot use NONE."));
                }
                for (String u : scan.hashOutputsReads) {
                    out.add(err(loc, "@sighash " + label + ": '" + u
                        + "' reads hashOutputs, which is zeroed under NONE — the read yields attacker-chosen"
                        + " zeros. Drop the output read or use ALL/SINGLE."));
                }
                for (String u : scan.outputAsserts) {
                    out.add(err(loc, "@sighash " + label + ": '" + u
                        + "' asserts an output, but NONE commits to no outputs — the assertion cannot be"
                        + " enforced. Use ALL/SINGLE."));
                }
                int emitted = scan.stateOutputCount + scan.dataOutputCount;
                if (emitted > 0) {
                    out.add(err(loc, "@sighash " + label + ": this method emits " + emitted
                        + " output(s) (addOutput/addRawOutput/addDataOutput), but NONE commits to no"
                        + " outputs — those outputs are unenforceable. Use ALL/SINGLE."));
                }
            }

            // ---- SINGLE commits ONLY to the same-index output -----------------
            if (base == SighashDirective.BASE_SINGLE) {
                // A fixed-index output assertion (requireOutputP2PKH) cannot be
                // proven to land at THIS input's index (F4).
                for (String u : scan.outputAsserts) {
                    out.add(err(loc, "@sighash " + label + ": '" + u
                        + "' asserts an output at a fixed index, but SINGLE commits ONLY to the output at"
                        + " THIS input's index — the asserted index cannot be statically proven equal to"
                        + " the input index, so the assertion may bind an uncommitted (attacker-controllable)"
                        + " output or silently brick the spend. Use ALL."));
                }

                // A stateful mutate-only (or data-only) method auto-injects a
                // single state-continuation output whose value is the caller-chosen
                // `_newAmount`; under SINGLE that continuation is value-skimmable (F1).
                boolean isMutateOnlyAutoContinuation =
                    needsContinuation && scan.stateOutputCount == 0 && scan.dataOutputCount == 0;

                int stateOutputs = scan.stateOutputCount > 0
                    ? scan.stateOutputCount
                    : (needsContinuation ? 1 : 0);
                int committed = stateOutputs + scan.dataOutputCount;

                if (isMutateOnlyAutoContinuation) {
                    out.add(err(loc, "@sighash " + label + ": this stateful method's state continuation is"
                        + " sized by the caller-chosen _newAmount, but SINGLE commits ONLY to the same-index"
                        + " output WITHOUT pinning its value — a spender can set _newAmount to dust, drive the"
                        + " change output to zero, and append a draining output while the covenant + OP_PUSH_TX"
                        + " binding still validate (value skim); an honest change>0 leaves the UTXO"
                        + " unspendable. A mutate-only SINGLE continuation is unsound. Use ALL, or emit an"
                        + " explicit addOutput/addRawOutput that carries the full protected value at this"
                        + " input's index."));
                } else if (committed > 1) {
                    out.add(err(loc, "@sighash " + label + ": SINGLE commits ONLY to the output at this"
                        + " input's index, but this method binds " + committed + " outputs ("
                        + scan.stateOutputCount + " addOutput + " + scan.dataOutputCount + " addDataOutput"
                        + (stateOutputs > scan.stateOutputCount ? " + state continuation" : "")
                        + "). Outputs beyond the same-index one are uncommitted and attacker-controllable."
                        + " A SINGLE covenant must bind exactly one same-index output."));
                } else if (committed == 1) {
                    out.add(warn(loc, "@sighash " + label + ": SINGLE commits ONLY to the output at this"
                        + " input's index. This method binds exactly one output there, which is sound ONLY"
                        + " if that output carries the FULL protected value — SINGLE does not pin the amount,"
                        + " so a short-changed same-index output cannot be caught at compile time. Ensure the"
                        + " caller places the fully-valued output at this input's index."));
                }
            }
        }

        return out;
    }

    private static Diag err(SourceLocation loc, String msg) {
        return new Diag(msg, loc, false);
    }

    private static Diag warn(SourceLocation loc, String msg) {
        return new Diag(msg, loc, true);
    }

    // ------------------------------------------------------------------
    // Transitive walk (through private helpers, for-loop headers, assignment
    // targets) collecting every flagged builtin/intrinsic usage.
    // ------------------------------------------------------------------

    private static MethodScan scanMethod(MethodNode method, Map<String, MethodNode> privateByName) {
        MethodScan scan = new MethodScan();
        Set<String> visiting = new HashSet<>();
        walkBody(method.body(), scan, privateByName, visiting);
        return scan;
    }

    private static void walkBody(List<Statement> stmts, MethodScan scan,
                                 Map<String, MethodNode> privateByName, Set<String> visiting) {
        for (Statement s : stmts) {
            walkStmt(s, scan, privateByName, visiting);
        }
    }

    private static void walkStmt(Statement stmt, MethodScan scan,
                                 Map<String, MethodNode> privateByName, Set<String> visiting) {
        if (stmt instanceof AssignmentStatement a) {
            // Walk BOTH sides: a forbidden field read can hide in the target (F3).
            walkExpr(a.target(), scan, privateByName, visiting);
            walkExpr(a.value(), scan, privateByName, visiting);
        } else if (stmt instanceof ExpressionStatement es) {
            walkExpr(es.expression(), scan, privateByName, visiting);
        } else if (stmt instanceof IfStatement i) {
            walkExpr(i.condition(), scan, privateByName, visiting);
            walkBody(i.thenBody(), scan, privateByName, visiting);
            if (i.elseBody() != null) {
                walkBody(i.elseBody(), scan, privateByName, visiting);
            }
        } else if (stmt instanceof ForStatement f) {
            // Walk the full loop header: init + condition can hide a forbidden
            // field read just as easily as the body/update do (F3).
            if (f.init() != null) {
                walkStmt(f.init(), scan, privateByName, visiting);
            }
            walkExpr(f.condition(), scan, privateByName, visiting);
            if (f.update() != null) {
                walkStmt(f.update(), scan, privateByName, visiting);
            }
            walkBody(f.body(), scan, privateByName, visiting);
        } else if (stmt instanceof ReturnStatement r) {
            if (r.value() != null) {
                walkExpr(r.value(), scan, privateByName, visiting);
            }
        } else if (stmt instanceof VariableDeclStatement v) {
            walkExpr(v.init(), scan, privateByName, visiting);
        }
    }

    private static String calleeName(Expression callee) {
        if (callee instanceof Identifier id) {
            return id.name();
        }
        if (callee instanceof PropertyAccessExpr pa) {
            return pa.property();
        }
        if (callee instanceof MemberExpr me) {
            return me.property();
        }
        return null;
    }

    private static void walkExpr(Expression expr, MethodScan scan,
                                 Map<String, MethodNode> privateByName, Set<String> visiting) {
        if (expr == null) {
            return;
        }
        if (expr instanceof CallExpr call) {
            String name = calleeName(call.callee());
            if (name != null) {
                if (HASHPREVOUTS_READERS.contains(name)) scan.hashPrevoutsReads.add(name);
                if (HASHSEQUENCE_READERS.contains(name)) scan.hashSequenceReads.add(name);
                if (HASHOUTPUTS_READERS.contains(name)) scan.hashOutputsReads.add(name);
                if (PREVOUT_SCRIPT_INTRINSICS.contains(name)) scan.prevoutScriptReads.add(name);
                if (OUTPUT_ASSERT_INTRINSICS.contains(name)) scan.outputAsserts.add(name);
                if (STATE_OUTPUT_INTRINSICS.contains(name)) scan.stateOutputCount += 1;
                if (DATA_OUTPUT_INTRINSICS.contains(name)) scan.dataOutputCount += 1;
                // Recurse into a private helper so its usages surface to the caller.
                MethodNode target = privateByName.get(name);
                if (target != null && !visiting.contains(name)) {
                    visiting.add(name);
                    walkBody(target.body(), scan, privateByName, visiting);
                    visiting.remove(name);
                }
            }
            for (Expression a : call.args()) {
                walkExpr(a, scan, privateByName, visiting);
            }
            if (!(call.callee() instanceof Identifier)) {
                walkExpr(call.callee(), scan, privateByName, visiting);
            }
        } else if (expr instanceof BinaryExpr be) {
            walkExpr(be.left(), scan, privateByName, visiting);
            walkExpr(be.right(), scan, privateByName, visiting);
        } else if (expr instanceof UnaryExpr ue) {
            walkExpr(ue.operand(), scan, privateByName, visiting);
        } else if (expr instanceof TernaryExpr te) {
            walkExpr(te.condition(), scan, privateByName, visiting);
            walkExpr(te.consequent(), scan, privateByName, visiting);
            walkExpr(te.alternate(), scan, privateByName, visiting);
        } else if (expr instanceof IndexAccessExpr ia) {
            walkExpr(ia.object(), scan, privateByName, visiting);
            walkExpr(ia.index(), scan, privateByName, visiting);
        } else if (expr instanceof MemberExpr me) {
            walkExpr(me.object(), scan, privateByName, visiting);
        } else if (expr instanceof IncrementExpr ie) {
            walkExpr(ie.operand(), scan, privateByName, visiting);
        } else if (expr instanceof DecrementExpr de) {
            walkExpr(de.operand(), scan, privateByName, visiting);
        } else if (expr instanceof ArrayLiteralExpr al) {
            for (Expression el : al.elements()) {
                walkExpr(el, scan, privateByName, visiting);
            }
        }
        // PropertyAccessExpr / literals: nothing to walk.
    }
}
