//! Dead Code Elimination pass for ANF IR.
//!
//! Removes bindings whose results are never referenced by other bindings,
//! preserving bindings with observable side effects (assert, update_prop,
//! check_preimage, add_output, add_raw_output, add_data_output, call,
//! method_call, raw_script) and any `if` / `loop` whose nested bindings carry
//! one. Iterates to a fixed point so transitively dead bindings are also
//! removed.
//!
//! "Results" is plural on purpose (N-140). A binding does not only define its
//! own `name`: an `if` that merges branch locals also defines every name in
//! `results`, and both an `if` and a `loop` define the names their nested
//! bindings bind. Liveness used to test `refs.contains(&b.name)` alone, so an
//! `if` named `t9` carrying `results: ["a","b"]` — a name nothing ever
//! references, because callers reference `a` and `b` — was deleted whenever its
//! arms happened to be pure, and the merged locals kept their pre-branch
//! values. See `conformance/dce/live-if.test.ts`.
//!
//! This module is the canonical DEFINITION of DCE for the Rust compiler, but
//! it is not a standalone pipeline pass (F-219). Its only production caller is
//! `anf_optimize::optimize_ec`, and only after that function's `any_changed`
//! early exit, so a program in which no EC rewrite fires is never DCE'd. (The
//! `lib.rs` issue-#109 probe runs `eliminate_dead_code` on a copy, for a
//! warning only; it does not change what is compiled.) Running it on every
//! program breaks conformance fixtures until N-140's liveness work lands
//! (R-194). It mirrors the Zig reference implementation in
//! `compilers/zig/src/passes/dce.zig`. The earlier inline implementation in
//! `anf_optimize.rs` has been surgically extracted here.
//!
//! Behaviour: byte-for-byte identical, at the time of that extraction, to the
//! previous inline DCE in `anf_optimize.rs`. Verified by the conformance suite
//! (cross-tier hex parity) and the optimizer unit tests.
//!
//! N-140 is a deliberate behaviour change since: liveness considers the
//! names a binding DEFINES, not only its own `name`. F-108 is the other: a
//! private method's last binding (its return value) is a liveness root.

use std::collections::{HashMap, HashSet};

use crate::ir::{ANFBinding, ANFMethod, ANFProgram, ANFValue};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Eliminate dead bindings across every method in the program.
/// Returns a new program; the input is consumed.
pub fn eliminate_dead_code(program: ANFProgram) -> ANFProgram {
    let methods: Vec<ANFMethod> = program
        .methods
        .iter()
        .map(eliminate_dead_bindings_method)
        .collect();

    ANFProgram {
        contract_name: program.contract_name,
        parent_class: program.parent_class,
        properties: program.properties,
        methods,
    }
}

/// Eliminate dead (unreferenced, side-effect-free) bindings, iterating to fixed point.
pub fn eliminate_dead_bindings_method(method: &ANFMethod) -> ANFMethod {
    eliminate_dead_bindings_filtered(method, None)
}

/// `eliminate_dead_bindings_method` restricted to bindings whose name is in
/// `candidates`: every other binding is kept as if live (N-138). The constant
/// folder uses it to drop the operand bindings its own rewrites orphaned (the
/// `1` under a folded `-1n`) without also deleting bindings that were already
/// dead before folding, so fold-ON output does not move for a program the
/// folder did not change.
pub fn eliminate_dead_bindings_among(
    method: &ANFMethod,
    candidates: &HashSet<String>,
) -> ANFMethod {
    let mut out = eliminate_dead_bindings_filtered(method, Some(candidates));
    // N-446: the fold also orphans operands INSIDE `if` arms and loop bodies
    // (`-5n` in an else arm). Filtering only the top level left them there,
    // stack lowering pushed them, and the arms ended at different depths.
    // Prune the nested scopes too, then re-filter the top level, to a fixed
    // point (a nested removal can orphan a top-level operand).
    while prune_nested_orphans(&mut out.body, candidates) {
        out = eliminate_dead_bindings_filtered(&out, Some(candidates));
    }
    out
}

/// N-446: remove fold-orphaned pure bindings from every nested scope (`if`
/// arms, `loop` bodies, recursively); returns whether anything was removed.
///
/// A nested binding is removed only if it is a candidate (referenced before
/// folding), is referenced by NO binding anywhere in the method now (arm
/// bindings can be read after the `if` by name, so an arm is never filtered
/// against its own references alone), is not one of its `if`'s declared
/// `results` (stack lowering requires those slots in both arms), is
/// side-effect free, and is not itself an `if` / `loop` (those are recursed
/// into instead). Only the candidate-restricted fold prune calls this; the
/// EC-gated DCE stays top-level, so fold-OFF output cannot move.
fn prune_nested_orphans(body: &mut Vec<ANFBinding>, candidates: &HashSet<String>) -> bool {
    fn filter_scope(
        scope: &mut Vec<ANFBinding>,
        nested: bool,
        protect: &HashSet<String>,
        refs: &HashSet<String>,
        candidates: &HashSet<String>,
    ) -> bool {
        let mut changed = false;
        for b in scope.iter_mut() {
            match &mut b.value {
                ANFValue::If {
                    then,
                    else_branch,
                    results,
                    ..
                } => {
                    let res: HashSet<String> = results.iter().cloned().collect();
                    changed |= filter_scope(then, true, &res, refs, candidates);
                    changed |= filter_scope(else_branch, true, &res, refs, candidates);
                }
                ANFValue::Loop { body, .. } => {
                    changed |= filter_scope(body, true, &HashSet::new(), refs, candidates);
                }
                _ => {}
            }
        }
        if nested {
            let before = scope.len();
            scope.retain(|b| {
                matches!(b.value, ANFValue::If { .. } | ANFValue::Loop { .. })
                    || !candidates.contains(&b.name)
                    || refs.contains(&b.name)
                    || protect.contains(&b.name)
                    || has_side_effect(&b.value)
            });
            changed |= scope.len() != before;
        }
        changed
    }

    let mut any = false;
    loop {
        let mut refs = HashSet::new();
        for b in body.iter() {
            collect_refs_from_value(&b.value, &mut refs);
        }
        if !filter_scope(body, false, &HashSet::new(), &refs, candidates) {
            return any;
        }
        any = true;
    }
}

fn eliminate_dead_bindings_filtered(
    method: &ANFMethod,
    candidates: Option<&HashSet<String>>,
) -> ANFMethod {
    let keep_last = returns_last_binding(method);
    let mut body = method.body.clone();
    loop {
        let own_refs: Vec<HashSet<String>> = body
            .iter()
            .map(|binding| {
                let mut refs = HashSet::new();
                collect_refs_from_value(&binding.value, &mut refs);
                refs
            })
            .collect();
        let mut ref_count: HashMap<&String, usize> = HashMap::new();
        for refs in &own_refs {
            for name in refs {
                *ref_count.entry(name).or_insert(0) += 1;
            }
        }

        let before_len = body.len();
        let mut index = 0usize;
        body.retain(|b| {
            let keep = (keep_last && index + 1 == before_len)
                || candidates.map_or(false, |c| !c.contains(&b.name))
                || is_referenced_externally(b, &own_refs[index], &ref_count)
                || has_side_effect(&b.value);
            index += 1;
            keep
        });

        if body.len() == before_len {
            break;
        }
    }

    ANFMethod {
        name: method.name.clone(),
        params: method.params.clone(),
        body,
        is_public: method.is_public,
        sighash_type: method.sighash_type,
    }
}

/// F-108: whether `method`'s LAST binding is its return value. Stack lowering
/// inlines a private method at each `method_call` and takes that binding as the
/// call's result, so it is a liveness root even though nothing inside the
/// method references it; without the root a pure return expression
/// (`return n + 1n`) was deleted and the helper emptied. The predicate is the
/// one stack lowering uses to collect inlinable private methods. A public
/// method's last binding is never a return value.
fn returns_last_binding(method: &ANFMethod) -> bool {
    method.name != "constructor" && !method.is_public
}

// ---------------------------------------------------------------------------
// Core algorithm
// ---------------------------------------------------------------------------

/// Every SSA name a binding brings into scope: its own `name`, plus — for the
/// two nesting kinds — an `if`'s declared `results` (the merged branch locals /
/// property slots both arms leave behind) and the names bound inside `then`,
/// `else` and a `loop` body, recursively.
///
/// `iter_var` is deliberately absent: it is the loop's own induction variable,
/// referenced only from inside the body, so counting it as defined would make
/// every non-trivial loop unconditionally live.
pub fn collect_defined_names(binding: &ANFBinding, out: &mut HashSet<String>) {
    out.insert(binding.name.clone());
    collect_defined_names_from_value(&binding.value, out);
}

fn collect_defined_names_from_value(value: &ANFValue, out: &mut HashSet<String>) {
    match value {
        ANFValue::If {
            then,
            else_branch,
            results,
            ..
        } => {
            for r in results {
                out.insert(r.clone());
            }
            for b in then {
                collect_defined_names(b, out);
            }
            for b in else_branch {
                collect_defined_names(b, out);
            }
        }
        ANFValue::Loop { body, .. } => {
            for b in body {
                collect_defined_names(b, out);
            }
        }
        _ => {}
    }
}

/// Is any name this binding defines referenced by some OTHER binding?
///
/// `ref_count` maps a name to the number of DISTINCT bindings referencing it;
/// `own_refs` is this binding's own contribution. Subtracting it is what keeps
/// the rule from degenerating into "never delete an `if` or a `loop`": an arm's
/// bindings almost always reference each other, and counting those
/// self-references would make every nesting node immortal.
///
/// For a non-nesting binding this is exactly the old `refs.contains(&b.name)`:
/// ANF has no self-reference, so `own_refs` never holds the binding's own name.
fn is_referenced_externally(
    binding: &ANFBinding,
    own_refs: &HashSet<String>,
    ref_count: &HashMap<&String, usize>,
) -> bool {
    let mut defined = HashSet::new();
    collect_defined_names(binding, &mut defined);
    defined.iter().any(|name| {
        let total = ref_count.get(name).copied().unwrap_or(0);
        let own = usize::from(own_refs.contains(name));
        total > own
    })
}

/// Collect all referenced binding names from a value.
pub fn collect_refs_from_value(value: &ANFValue, refs: &mut HashSet<String>) {
    match value {
        ANFValue::LoadParam { name } => {
            // N-356: a reassigned parameter is bound under its own name and
            // read back as `load_param <name>`; count the read so DCE keeps
            // the rebinding. Matches TS collectRefsFromValue.
            refs.insert(name.clone());
        }
        ANFValue::LoadProp { .. } | ANFValue::GetStateScript {} => {}
        // raw_script — opaque byte span, no SSA operand refs. Stack effect is
        // declared via in_arity / out_arity.
        ANFValue::RawScript { .. } => {}
        ANFValue::LoadConst { value } => {
            // Track @ref: aliases as references to prevent DCE
            if let serde_json::Value::String(s) = value {
                if let Some(target) = s.strip_prefix("@ref:") {
                    refs.insert(target.to_string());
                }
            }
        }
        ANFValue::BinOp { left, right, .. } => {
            refs.insert(left.clone());
            refs.insert(right.clone());
        }
        ANFValue::UnaryOp { operand, .. } => {
            refs.insert(operand.clone());
        }
        ANFValue::Call { args, .. } => {
            for arg in args {
                refs.insert(arg.clone());
            }
        }
        ANFValue::MethodCall { object, args, .. } => {
            refs.insert(object.clone());
            for arg in args {
                refs.insert(arg.clone());
            }
        }
        ANFValue::If {
            cond,
            then: then_branch,
            else_branch,
            ..
        } => {
            refs.insert(cond.clone());
            for b in then_branch {
                collect_refs_from_value(&b.value, refs);
            }
            for b in else_branch {
                collect_refs_from_value(&b.value, refs);
            }
        }
        ANFValue::Loop { body, .. } => {
            for b in body {
                collect_refs_from_value(&b.value, refs);
            }
        }
        ANFValue::Assert { value, .. } => {
            refs.insert(value.clone());
        }
        ANFValue::UpdateProp { value, .. } => {
            refs.insert(value.clone());
        }
        ANFValue::CheckPreimage { preimage, .. } => {
            refs.insert(preimage.clone());
        }
        ANFValue::DeserializeState { preimage } => {
            refs.insert(preimage.clone());
        }
        ANFValue::AddOutput {
            satoshis,
            state_values,
            preimage,
        } => {
            refs.insert(satoshis.clone());
            for sv in state_values {
                refs.insert(sv.clone());
            }
            if !preimage.is_empty() {
                refs.insert(preimage.clone());
            }
        }
        ANFValue::AddRawOutput { satoshis, script_bytes } => {
            refs.insert(satoshis.clone());
            refs.insert(script_bytes.clone());
        }
        ANFValue::AddDataOutput { satoshis, script_bytes } => {
            refs.insert(satoshis.clone());
            refs.insert(script_bytes.clone());
        }
        ANFValue::ArrayLiteral { elements } => {
            for elem in elements {
                refs.insert(elem.clone());
            }
        }
    }
}

/// Returns true if the binding has side effects and must not be eliminated.
///
/// An exhaustive `match` — NOT `matches!` — so a newly-added `ANFValue`
/// variant is a compile error here rather than silently defaulting to
/// "effect-free" and being deleted by DCE.
///
/// `If` and `Loop` recurse into their nested bindings: those bindings live
/// inside the parent node rather than flattened into the method body, so
/// retention is all-or-nothing. Dropping an unreferenced `if` would take
/// every nested `assert` / `check_preimage` / `add_output` with it. Mirrors
/// the Go tier's `frontend.HasSideEffect`.
pub fn has_side_effect(value: &ANFValue) -> bool {
    match value {
        ANFValue::Assert { .. }
        | ANFValue::UpdateProp { .. }
        | ANFValue::CheckPreimage { .. }
        | ANFValue::DeserializeState { .. }
        | ANFValue::AddOutput { .. }
        | ANFValue::AddRawOutput { .. }
        | ANFValue::AddDataOutput { .. }
        | ANFValue::MethodCall { .. }
        | ANFValue::Call { .. }
        // opaque byte span — DCE must never eliminate it
        | ANFValue::RawScript { .. } => true,

        // Effectful only if some nested binding is.
        ANFValue::If { then, else_branch, .. } => {
            then.iter().any(|b| has_side_effect(&b.value))
                || else_branch.iter().any(|b| has_side_effect(&b.value))
        }
        ANFValue::Loop { body, .. } => body.iter().any(|b| has_side_effect(&b.value)),

        // Issue #109 (`@embedAlways`): a `load_prop` injected to force a
        // readonly field into the deployed locking script carries
        // `preserve = true`, so DCE must keep it even though nothing
        // references it. Ordinary load_props (preserve = false) remain freely
        // eliminable. Mirrors `compilers/zig/src/passes/dce.zig`.
        ANFValue::LoadProp { preserve, .. } => *preserve,

        ANFValue::LoadParam { .. }
        | ANFValue::LoadConst { .. }
        | ANFValue::BinOp { .. }
        | ANFValue::UnaryOp { .. }
        | ANFValue::GetStateScript {}
        | ANFValue::ArrayLiteral { .. } => false,
    }
}
