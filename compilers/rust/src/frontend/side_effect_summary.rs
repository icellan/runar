//! Side-effect summary pass.
//!
//! Mirrors `packages/runar-compiler/src/passes/side-effect-summary.ts`.
//!
//! Classifies each method on a `ContractNode` by the side effects it has
//! on the contract's continuation requirements. Walks the
//! private-method call graph so effects buried inside private helpers
//! surface to their public callers.
//!
//! Consumed by `anf_lower.rs` for:
//!   - Auto-injecting continuation parameters (`_changePKH`,
//!     `_changeAmount`, `_newAmount`, `txPreimage`) on public stateful
//!     methods.
//!   - Gating emission of the hashOutputs continuation assertion.
//!   - Deciding whether a private-helper call should be inlined into
//!     the caller's binding stream so its `add_output` /
//!     `add_data_output` ANF nodes register on the caller's
//!     continuation hash.
//!
//! Recursion across private methods is forbidden by the language
//! validator, so the call-graph walk terminates.

use std::collections::{HashMap, HashSet};

use super::ast::{ContractNode, Expression, MethodNode, Statement, Visibility};

/// Effects a method has on the contract's continuation. Each flag is
/// `true` if the effect occurs anywhere reachable from the method
/// body, including transitively via private-method calls.
#[derive(Debug, Default, Clone, Copy)]
pub struct MethodEffects {
    /// Mutates a non-readonly property (assignment or `++`/`--`).
    pub mutates_state: bool,
    /// Calls `this.addOutput(...)` or `this.addRawOutput(...)`.
    pub has_state_output: bool,
    /// Calls `this.addDataOutput(...)`.
    pub has_data_output: bool,
    /// Calls `checkPreimage(...)` (manually, outside auto-injected one).
    pub uses_preimage: bool,
}

impl MethodEffects {
    fn union(&mut self, other: &MethodEffects) {
        self.mutates_state |= other.mutates_state;
        self.has_state_output |= other.has_state_output;
        self.has_data_output |= other.has_data_output;
        self.uses_preimage |= other.uses_preimage;
    }
}

/// Map from method name to that method's effects. Includes the
/// constructor under the key `"constructor"`.
pub type SideEffectSummary = HashMap<String, MethodEffects>;

/// Continuation-shape decision derived from MethodEffects.
///
/// `needs_change` controls injection of `_changePKH` and
/// `_changeAmount`. `needs_new_amount` controls injection of
/// `_newAmount`. The pair maps directly to ANF auto-param insertion;
/// both sites must agree for a deployed contract to be spendable.
#[derive(Debug, Clone, Copy)]
pub struct ContinuationShape {
    pub needs_change: bool,
    pub needs_new_amount: bool,
    pub is_terminal: bool,
}

impl ContinuationShape {
    pub fn for_effects(eff: &MethodEffects) -> Self {
        let needs_change = eff.mutates_state || eff.has_state_output || eff.has_data_output;
        // addOutput / addRawOutput already specify per-output amounts,
        // so when those are present the single-output _newAmount is
        // redundant. Otherwise the single-output continuation path
        // needs _newAmount to size the new state UTXO.
        let needs_new_amount =
            (eff.mutates_state || eff.has_data_output) && !eff.has_state_output;
        ContinuationShape {
            needs_change,
            needs_new_amount,
            is_terminal: !needs_change,
        }
    }
}

const STATE_OUTPUT_INTRINSICS: &[&str] = &["addOutput", "addRawOutput"];
const DATA_OUTPUT_INTRINSICS: &[&str] = &["addDataOutput"];

/// Compute the side-effect summary for every method on the contract.
/// On-demand DFS with memoization. The caller does not need a
/// topological sort.
pub fn compute_side_effect_summary(contract: &ContractNode) -> SideEffectSummary {
    let mut summary: SideEffectSummary = HashMap::new();
    let mutable_props: HashSet<String> = contract
        .properties
        .iter()
        .filter(|p| !p.readonly)
        .map(|p| p.name.clone())
        .collect();
    let private_by_name: HashMap<String, &MethodNode> = contract
        .methods
        .iter()
        .filter(|m| !matches!(m.visibility, Visibility::Public))
        .map(|m| (m.name.clone(), m))
        .collect();

    let mut in_progress: HashSet<String> = HashSet::new();

    // Classify every method up front so callers do not need to
    // know about lazy evaluation order.
    classify(
        "constructor",
        &contract.constructor.body,
        &mutable_props,
        &private_by_name,
        &mut summary,
        &mut in_progress,
    );
    for m in &contract.methods {
        classify(
            &m.name,
            &m.body,
            &mutable_props,
            &private_by_name,
            &mut summary,
            &mut in_progress,
        );
    }
    summary
}

fn classify(
    method_name: &str,
    body: &[Statement],
    mutable_props: &HashSet<String>,
    private_by_name: &HashMap<String, &MethodNode>,
    summary: &mut SideEffectSummary,
    in_progress: &mut HashSet<String>,
) -> MethodEffects {
    if let Some(cached) = summary.get(method_name) {
        return *cached;
    }
    if in_progress.contains(method_name) {
        // Defensive: validation should reject recursion before we
        // get here. Returning empty avoids infinite recursion.
        return MethodEffects::default();
    }
    in_progress.insert(method_name.to_string());

    let mut effects = MethodEffects::default();
    for s in body {
        collect_stmt(s, &mut effects, mutable_props, private_by_name, summary, in_progress);
    }

    in_progress.remove(method_name);
    summary.insert(method_name.to_string(), effects);
    effects
}

fn collect_stmt(
    stmt: &Statement,
    into: &mut MethodEffects,
    mutable_props: &HashSet<String>,
    private_by_name: &HashMap<String, &MethodNode>,
    summary: &mut SideEffectSummary,
    in_progress: &mut HashSet<String>,
) {
    match stmt {
        Statement::Assignment { target, value, .. } => {
            if let Expression::PropertyAccess { property } = target {
                if mutable_props.contains(property) {
                    into.mutates_state = true;
                }
            }
            collect_expr(value, into, mutable_props, private_by_name, summary, in_progress);
        }
        Statement::ExpressionStatement { expression, .. } => {
            collect_expr(expression, into, mutable_props, private_by_name, summary, in_progress);
        }
        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            ..
        } => {
            collect_expr(condition, into, mutable_props, private_by_name, summary, in_progress);
            for inner in then_branch {
                collect_stmt(inner, into, mutable_props, private_by_name, summary, in_progress);
            }
            if let Some(else_body) = else_branch {
                for inner in else_body {
                    collect_stmt(inner, into, mutable_props, private_by_name, summary, in_progress);
                }
            }
        }
        Statement::ForStatement { update, body, .. } => {
            collect_stmt(update, into, mutable_props, private_by_name, summary, in_progress);
            for inner in body {
                collect_stmt(inner, into, mutable_props, private_by_name, summary, in_progress);
            }
        }
        Statement::ReturnStatement { value, .. } => {
            if let Some(expr) = value {
                collect_expr(expr, into, mutable_props, private_by_name, summary, in_progress);
            }
        }
        Statement::VariableDecl { init, .. } => {
            collect_expr(init, into, mutable_props, private_by_name, summary, in_progress);
        }
    }
}

fn collect_expr(
    expr: &Expression,
    into: &mut MethodEffects,
    mutable_props: &HashSet<String>,
    private_by_name: &HashMap<String, &MethodNode>,
    summary: &mut SideEffectSummary,
    in_progress: &mut HashSet<String>,
) {
    match expr {
        Expression::IncrementExpr { operand, .. } | Expression::DecrementExpr { operand, .. } => {
            if let Expression::PropertyAccess { property } = operand.as_ref() {
                if mutable_props.contains(property) {
                    into.mutates_state = true;
                }
            }
        }
        Expression::CallExpr { callee, args } => {
            // this.X(...) or member.X(...) — output intrinsics or
            // private method calls.
            let callee_name: Option<&str> = match callee.as_ref() {
                Expression::PropertyAccess { property } => Some(property.as_str()),
                Expression::MemberExpr { property, .. } => Some(property.as_str()),
                _ => None,
            };
            if let Some(name) = callee_name {
                if STATE_OUTPUT_INTRINSICS.contains(&name) {
                    into.has_state_output = true;
                }
                if DATA_OUTPUT_INTRINSICS.contains(&name) {
                    into.has_data_output = true;
                }
                if let Some(target) = private_by_name.get(name) {
                    let target_eff = classify(
                        &target.name,
                        &target.body,
                        mutable_props,
                        private_by_name,
                        summary,
                        in_progress,
                    );
                    into.union(&target_eff);
                }
            }

            // Bareword calls: identifiers that resolve to private
            // methods (Go/Rust DSL surfaces route private helpers as
            // bare identifiers) or to builtins like checkPreimage.
            if let Expression::Identifier { name } = callee.as_ref() {
                if name == "checkPreimage" {
                    into.uses_preimage = true;
                }
                if let Some(target) = private_by_name.get(name) {
                    let target_eff = classify(
                        &target.name,
                        &target.body,
                        mutable_props,
                        private_by_name,
                        summary,
                        in_progress,
                    );
                    into.union(&target_eff);
                }
            }

            for arg in args {
                collect_expr(arg, into, mutable_props, private_by_name, summary, in_progress);
            }
            // Walk the callee subexpression too, except for plain
            // identifiers (already handled above).
            if !matches!(callee.as_ref(), Expression::Identifier { .. }) {
                collect_expr(callee, into, mutable_props, private_by_name, summary, in_progress);
            }
        }
        Expression::BinaryExpr { left, right, .. } => {
            collect_expr(left, into, mutable_props, private_by_name, summary, in_progress);
            collect_expr(right, into, mutable_props, private_by_name, summary, in_progress);
        }
        Expression::UnaryExpr { operand, .. } => {
            collect_expr(operand, into, mutable_props, private_by_name, summary, in_progress);
        }
        Expression::TernaryExpr {
            condition,
            consequent,
            alternate,
        } => {
            collect_expr(condition, into, mutable_props, private_by_name, summary, in_progress);
            collect_expr(consequent, into, mutable_props, private_by_name, summary, in_progress);
            collect_expr(alternate, into, mutable_props, private_by_name, summary, in_progress);
        }
        Expression::IndexAccess { object, index } => {
            collect_expr(object, into, mutable_props, private_by_name, summary, in_progress);
            collect_expr(index, into, mutable_props, private_by_name, summary, in_progress);
        }
        Expression::MemberExpr { object, .. } => {
            collect_expr(object, into, mutable_props, private_by_name, summary, in_progress);
        }
        Expression::ArrayLiteral { elements } => {
            for el in elements {
                collect_expr(el, into, mutable_props, private_by_name, summary, in_progress);
            }
        }
        _ => {}
    }
}
