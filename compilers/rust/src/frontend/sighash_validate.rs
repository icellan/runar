//! Field-usage validation for per-method `@sighash` modes (issue #123).
//!
//! SECURITY CORE. A relaxed sighash flag ZEROES specific BIP-143 preimage
//! fields; a covenant that still reads one of those fields (or binds an output
//! the flag no longer commits to) is exploitable — the attacker gets a free
//! hand over exactly the part of the transaction the covenant believed it had
//! pinned. This pass rejects, at compile time, every field read / output
//! binding that becomes unsound under the method's declared mode.
//!
//! BIP-143 field availability by sighash type (✓ = signed/committed, ✗ = ZEROED):
//!
//!   field                 ALL    NONE   SINGLE   +ANYONECANPAY
//!   ---------------------------------------------------------
//!   hashPrevouts           ✓      ✓      ✓         ✗   (all-inputs digest)
//!   hashSequence           ✓      ✗      ✗         ✗   (all-inputs digest)
//!   hashOutputs            ✓      ✗      same-idx   (per base)
//!
//! Mirrors the TypeScript reference `sighash-validate.ts` (plus the
//! security-audit hardening: SINGLE value-skim reject, requireOutputP2PKH
//! reject under SINGLE, transitive walk through for-loop headers + assignment
//! targets). Default ALL|FORKID methods (no directive) are never flagged.

use std::collections::{HashMap, HashSet};

use super::ast::{ContractNode, Expression, MethodNode, SourceLocation, Statement, Visibility};
use super::diagnostic::Diagnostic;
use super::side_effect_summary::{compute_side_effect_summary, ContinuationShape};
use super::sighash_directive::{
    describe_sighash, BASE_ALL, BASE_NONE, BASE_SINGLE, BASE_TYPE_MASK, FLAG_ANYONECANPAY,
};

/// Builtins that read the all-inputs prevouts digest (zeroed under ANYONECANPAY).
const HASHPREVOUTS_READERS: &[&str] = &["extractHashPrevouts"];
/// Builtins that read the all-inputs sequence digest (zeroed unless pure ALL).
const HASHSEQUENCE_READERS: &[&str] = &["extractHashSequence"];
/// Builtins that read the outputs digest (zeroed under NONE).
const HASHOUTPUTS_READERS: &[&str] = &["extractOutputHash", "extractOutputs"];
/// Intrinsic that binds a companion input's prevout script (needs hashPrevouts).
const PREVOUT_SCRIPT_INTRINSICS: &[&str] = &["extractPrevOutputScript"];
/// Intrinsics that assert an output (bound via hashOutputs).
const OUTPUT_ASSERT_INTRINSICS: &[&str] = &["requireOutputP2PKH"];
/// Output-emitting intrinsics (state continuation outputs).
const STATE_OUTPUT_INTRINSICS: &[&str] = &["addOutput", "addRawOutput"];
const DATA_OUTPUT_INTRINSICS: &[&str] = &["addDataOutput"];

#[derive(Clone)]
struct Usage {
    name: String,
    loc: Option<SourceLocation>,
}

#[derive(Default)]
struct MethodScan {
    hash_prevouts_reads: Vec<Usage>,
    hash_sequence_reads: Vec<Usage>,
    hash_outputs_reads: Vec<Usage>,
    prevout_script_reads: Vec<Usage>,
    output_asserts: Vec<Usage>,
    state_output_count: usize,
    data_output_count: usize,
}

/// Validate every public method's `@sighash` field usage. Returns diagnostics
/// (errors for unsound usages, warnings for the pin-the-value SINGLE case);
/// empty when all modes are used soundly. Methods with no directive (default
/// ALL|FORKID) are never flagged.
pub fn validate_sighash_usage(contract: &ContractNode) -> Vec<Diagnostic> {
    let mut out: Vec<Diagnostic> = Vec::new();
    let is_stateful = contract.parent_class == "StatefulSmartContract";
    let side_effects = compute_side_effect_summary(contract);

    let mut private_by_name: HashMap<String, &MethodNode> = HashMap::new();
    for m in &contract.methods {
        if m.visibility == Visibility::Private {
            private_by_name.insert(m.name.clone(), m);
        }
    }

    for method in &contract.methods {
        if method.visibility != Visibility::Public {
            continue;
        }
        let mode = match method.sighash_type {
            Some(v) => v,
            None => continue, // default ALL|FORKID — allow all
        };

        let base = mode & BASE_TYPE_MASK;
        let acp = (mode & FLAG_ANYONECANPAY) != 0;
        let label = describe_sighash(mode);

        let scan = scan_method(method, &private_by_name);

        // ---- state-continuation binding (stateful auto-injected hashOutputs) --
        let needs_continuation = is_stateful
            && side_effects
                .get(&method.name)
                .map(|eff| ContinuationShape::for_effects(eff).needs_change)
                .unwrap_or(false);

        let method_loc = method.source_location.clone();
        let push_err = |out: &mut Vec<Diagnostic>, u_loc: &Option<SourceLocation>, msg: String| {
            out.push(Diagnostic::error(msg, Some(u_loc.clone().unwrap_or(method_loc.clone()))));
        };
        let push_warn = |out: &mut Vec<Diagnostic>, u_loc: &Option<SourceLocation>, msg: String| {
            out.push(Diagnostic::warning(msg, Some(u_loc.clone().unwrap_or(method_loc.clone()))));
        };

        // ---- ANYONECANPAY: only THIS input is signed -----------------------
        if acp {
            for u in &scan.hash_prevouts_reads {
                push_err(&mut out, &u.loc, format!(
                    "@sighash {}: '{}' reads hashPrevouts, which is zeroed under ANYONECANPAY (only this input is signed) — the covenant cannot constrain the input set, so any check on it is trivially bypassable. Remove ANYONECANPAY or drop the {} read.",
                    label, u.name, u.name));
            }
            for u in &scan.prevout_script_reads {
                push_err(&mut out, &u.loc, format!(
                    "@sighash {}: '{}' binds a companion input's prevout script, but ANYONECANPAY zeroes hashPrevouts so the input set is unconstrained — an attacker can substitute inputs freely. Companion-input covenants require the full prevout set to be committed (drop ANYONECANPAY).",
                    label, u.name));
            }
        }

        // ---- hashSequence is committed only under pure ALL (no ACP) --------
        let hash_sequence_sound = base == BASE_ALL && !acp;
        if !hash_sequence_sound {
            for u in &scan.hash_sequence_reads {
                push_err(&mut out, &u.loc, format!(
                    "@sighash {}: '{}' reads hashSequence, which is zeroed under any mode other than SIGHASH_ALL (NONE / SINGLE / ANYONECANPAY all clear it) — the read yields attacker-chosen zeros. Use SIGHASH_ALL or drop the {} read.",
                    label, u.name, u.name));
            }
        }

        // ---- NONE commits to NO outputs ------------------------------------
        if base == BASE_NONE {
            if needs_continuation {
                push_err(&mut out, &Some(method.source_location.clone()), format!(
                    "@sighash {}: this stateful method binds a state-continuation output via hashOutputs, but NONE commits to NO outputs (hashOutputs is zeroed) — the continuation is unenforceable, so the next-state covenant is meaningless and the spend is unsound. A continuation covenant cannot use NONE.",
                    label));
            }
            for u in &scan.hash_outputs_reads {
                push_err(&mut out, &u.loc, format!(
                    "@sighash {}: '{}' reads hashOutputs, which is zeroed under NONE — the read yields attacker-chosen zeros. Drop the output read or use ALL/SINGLE.",
                    label, u.name));
            }
            for u in &scan.output_asserts {
                push_err(&mut out, &u.loc, format!(
                    "@sighash {}: '{}' asserts an output, but NONE commits to no outputs — the assertion cannot be enforced. Use ALL/SINGLE.",
                    label, u.name));
            }
            if scan.state_output_count + scan.data_output_count > 0 {
                push_err(&mut out, &Some(method.source_location.clone()), format!(
                    "@sighash {}: this method emits {} output(s) (addOutput/addRawOutput/addDataOutput), but NONE commits to no outputs — those outputs are unenforceable. Use ALL/SINGLE.",
                    label, scan.state_output_count + scan.data_output_count));
            }
        }

        // ---- SINGLE commits ONLY to the same-index output ------------------
        if base == BASE_SINGLE {
            // A fixed-index output assertion (requireOutputP2PKH) cannot be
            // proven to land at THIS input's index, the only output SINGLE
            // commits to.
            for u in &scan.output_asserts {
                push_err(&mut out, &u.loc, format!(
                    "@sighash {}: '{}' asserts an output at a fixed index, but SINGLE commits ONLY to the output at THIS input's index — the asserted index cannot be statically proven equal to the input index, so the assertion may bind an uncommitted (attacker-controllable) output or silently brick the spend. Use ALL.",
                    label, u.name));
            }

            // A stateful mutate-only (or data-only) method has NO explicit
            // output intrinsic, so the compiler auto-injects a single
            // state-continuation output whose value is the caller-chosen
            // `_newAmount`. Under SINGLE, BIP-143 commits ONLY to the
            // same-index output and does NOT pin its value → value-skimmable.
            let is_mutate_only_auto_continuation =
                needs_continuation && scan.state_output_count == 0 && scan.data_output_count == 0;

            let state_outputs = if scan.state_output_count > 0 {
                scan.state_output_count
            } else if needs_continuation {
                1
            } else {
                0
            };
            let committed = state_outputs + scan.data_output_count;

            if is_mutate_only_auto_continuation {
                push_err(&mut out, &Some(method.source_location.clone()), format!(
                    "@sighash {}: this stateful method's state continuation is sized by the caller-chosen _newAmount, but SINGLE commits ONLY to the same-index output WITHOUT pinning its value — a spender can set _newAmount to dust, drive the change output to zero, and append a draining output while the covenant + OP_PUSH_TX binding still validate (value skim); an honest change>0 leaves the UTXO unspendable. A mutate-only SINGLE continuation is unsound. Use ALL, or emit an explicit addOutput/addRawOutput that carries the full protected value at this input's index.",
                    label));
            } else if committed > 1 {
                let plus_cont = if state_outputs > scan.state_output_count {
                    " + state continuation"
                } else {
                    ""
                };
                push_err(&mut out, &Some(method.source_location.clone()), format!(
                    "@sighash {}: SINGLE commits ONLY to the output at this input's index, but this method binds {} outputs ({} addOutput + {} addDataOutput{}). Outputs beyond the same-index one are uncommitted and attacker-controllable. A SINGLE covenant must bind exactly one same-index output.",
                    label, committed, scan.state_output_count, scan.data_output_count, plus_cont));
            } else if committed == 1 {
                // Legitimate pairwise input↔output covenant: exactly one
                // explicit addOutput/addRawOutput (or single data output). The
                // same-index output IS committed, but SINGLE does not let the
                // compiler prove statically that its VALUE equals the full
                // protected amount — a runtime obligation on the caller.
                push_warn(&mut out, &Some(method.source_location.clone()), format!(
                    "@sighash {}: SINGLE commits ONLY to the output at this input's index. This method binds exactly one output there, which is sound ONLY if that output carries the FULL protected value — SINGLE does not pin the amount, so a short-changed same-index output cannot be caught at compile time. Ensure the caller places the fully-valued output at this input's index.",
                    label));
            }
        }
    }

    out
}

/// Walk a method body (transitively through private-method calls) collecting
/// every flagged builtin/intrinsic usage. Cycle-guarded.
fn scan_method(method: &MethodNode, private_by_name: &HashMap<String, &MethodNode>) -> MethodScan {
    let mut scan = MethodScan::default();
    let mut visiting: HashSet<String> = HashSet::new();
    walk_body(&method.body, &mut scan, private_by_name, &mut visiting, &None);
    scan
}

fn walk_body(
    stmts: &[Statement],
    scan: &mut MethodScan,
    private_by_name: &HashMap<String, &MethodNode>,
    visiting: &mut HashSet<String>,
    loc: &Option<SourceLocation>,
) {
    for s in stmts {
        walk_stmt(s, scan, private_by_name, visiting, loc);
    }
}

fn walk_stmt(
    stmt: &Statement,
    scan: &mut MethodScan,
    private_by_name: &HashMap<String, &MethodNode>,
    visiting: &mut HashSet<String>,
    _loc: &Option<SourceLocation>,
) {
    match stmt {
        Statement::Assignment { target, value, source_location } => {
            let l = Some(source_location.clone());
            // Walk BOTH sides: a forbidden field read can hide in the
            // assignment target, not just the value.
            walk_expr(target, scan, private_by_name, visiting, &l);
            walk_expr(value, scan, private_by_name, visiting, &l);
        }
        Statement::ExpressionStatement { expression, source_location } => {
            walk_expr(expression, scan, private_by_name, visiting, &Some(source_location.clone()));
        }
        Statement::IfStatement { condition, then_branch, else_branch, source_location } => {
            let l = Some(source_location.clone());
            walk_expr(condition, scan, private_by_name, visiting, &l);
            walk_body(then_branch, scan, private_by_name, visiting, &l);
            if let Some(eb) = else_branch {
                walk_body(eb, scan, private_by_name, visiting, &l);
            }
        }
        Statement::ForStatement { init, condition, update, body, source_location } => {
            let l = Some(source_location.clone());
            // Walk the full loop header: init and condition can hide a
            // forbidden field read just as easily as the body/update do.
            walk_stmt(init, scan, private_by_name, visiting, &l);
            walk_expr(condition, scan, private_by_name, visiting, &l);
            walk_stmt(update, scan, private_by_name, visiting, &l);
            walk_body(body, scan, private_by_name, visiting, &l);
        }
        Statement::ReturnStatement { value, source_location } => {
            if let Some(v) = value {
                walk_expr(v, scan, private_by_name, visiting, &Some(source_location.clone()));
            }
        }
        Statement::VariableDecl { init, source_location, .. } => {
            walk_expr(init, scan, private_by_name, visiting, &Some(source_location.clone()));
        }
    }
}

/// The callee's simple name: identifier, or the `property` of a member /
/// property access (mirrors the TS `calleeName`).
fn callee_name(callee: &Expression) -> Option<&str> {
    match callee {
        Expression::Identifier { name, .. } => Some(name.as_str()),
        Expression::PropertyAccess { property, .. } => Some(property.as_str()),
        Expression::MemberExpr { property, .. } => Some(property.as_str()),
        _ => None,
    }
}

fn walk_expr(
    expr: &Expression,
    scan: &mut MethodScan,
    private_by_name: &HashMap<String, &MethodNode>,
    visiting: &mut HashSet<String>,
    loc: &Option<SourceLocation>,
) {
    match expr {
        Expression::CallExpr { callee, args, .. } => {
            if let Some(name) = callee_name(callee) {
                let u = || Usage { name: name.to_string(), loc: loc.clone() };
                if HASHPREVOUTS_READERS.contains(&name) {
                    scan.hash_prevouts_reads.push(u());
                }
                if HASHSEQUENCE_READERS.contains(&name) {
                    scan.hash_sequence_reads.push(u());
                }
                if HASHOUTPUTS_READERS.contains(&name) {
                    scan.hash_outputs_reads.push(u());
                }
                if PREVOUT_SCRIPT_INTRINSICS.contains(&name) {
                    scan.prevout_script_reads.push(u());
                }
                if OUTPUT_ASSERT_INTRINSICS.contains(&name) {
                    scan.output_asserts.push(u());
                }
                if STATE_OUTPUT_INTRINSICS.contains(&name) {
                    scan.state_output_count += 1;
                }
                if DATA_OUTPUT_INTRINSICS.contains(&name) {
                    scan.data_output_count += 1;
                }
                // Recurse into a private helper so its usages surface here.
                let owned = name.to_string();
                if let Some(target) = private_by_name.get(&owned) {
                    if !visiting.contains(&owned) {
                        visiting.insert(owned.clone());
                        let body = target.body.clone();
                        walk_body(&body, scan, private_by_name, visiting, loc);
                        visiting.remove(&owned);
                    }
                }
            }
            for a in args {
                walk_expr(a, scan, private_by_name, visiting, loc);
            }
            if !matches!(callee.as_ref(), Expression::Identifier { .. }) {
                walk_expr(callee, scan, private_by_name, visiting, loc);
            }
        }
        Expression::BinaryExpr { left, right, .. } => {
            walk_expr(left, scan, private_by_name, visiting, loc);
            walk_expr(right, scan, private_by_name, visiting, loc);
        }
        Expression::UnaryExpr { operand, .. }
        | Expression::IncrementExpr { operand, .. }
        | Expression::DecrementExpr { operand, .. } => {
            walk_expr(operand, scan, private_by_name, visiting, loc);
        }
        Expression::TernaryExpr { condition, consequent, alternate } => {
            walk_expr(condition, scan, private_by_name, visiting, loc);
            walk_expr(consequent, scan, private_by_name, visiting, loc);
            walk_expr(alternate, scan, private_by_name, visiting, loc);
        }
        Expression::IndexAccess { object, index } => {
            walk_expr(object, scan, private_by_name, visiting, loc);
            walk_expr(index, scan, private_by_name, visiting, loc);
        }
        Expression::MemberExpr { object, .. } => {
            walk_expr(object, scan, private_by_name, visiting, loc);
        }
        Expression::ArrayLiteral { elements } => {
            for el in elements {
                walk_expr(el, scan, private_by_name, visiting, loc);
            }
        }
        // Leaves: identifier, property access, literals.
        _ => {}
    }
}
