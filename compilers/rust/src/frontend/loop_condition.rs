//! N-115 — normalise a reversed loop comparison to the canonical spelling.
//!
//! Every later pass reads a loop's iterator off the LEFT-hand side of its
//! condition (W4, `validate_for_condition_tests_iterator`) and its bound off
//! the right. `10 > i` says the same thing as `i < 10`, so the parser rewrites
//! it once instead of every pass learning a second spelling:
//!
//! ```text
//!   N >  i  ->  i <  N        N <  i  ->  i >  N
//!   N >= i  ->  i <= N        N <= i  ->  i >= N
//! ```
//!
//! The rule, identical in all seven tiers: the condition is a `<`/`<=`/`>`/`>=`
//! comparison, its RIGHT operand is the loop variable, and its LEFT operand is
//! not -> swap the operands and mirror the operator. Nothing else is touched,
//! so the W4 refusals (N40, N41) and the direction rule (N42) keep firing.

use super::ast::{BinaryOp, ContractNode, Expression, Statement};

fn mirrored(op: &BinaryOp) -> Option<BinaryOp> {
    match op {
        BinaryOp::Lt => Some(BinaryOp::Gt),
        BinaryOp::Le => Some(BinaryOp::Ge),
        BinaryOp::Gt => Some(BinaryOp::Lt),
        BinaryOp::Ge => Some(BinaryOp::Le),
        _ => None,
    }
}

/// The canonical form of `cond` for a loop over `iter` (or `cond` itself).
pub fn normalize_loop_condition(cond: &Expression, iter: &str) -> Expression {
    if let Expression::BinaryExpr { op, left, right } = cond {
        let is_iter = |e: &Expression| matches!(e, Expression::Identifier { name } if name == iter);
        if let Some(m) = mirrored(op) {
            if is_iter(right) && !is_iter(left) {
                return Expression::BinaryExpr { op: m, left: right.clone(), right: left.clone() };
            }
        }
    }
    cond.clone()
}

fn normalize_statements(stmts: &mut [Statement]) {
    for stmt in stmts.iter_mut() {
        match stmt {
            Statement::ForStatement { init, condition, body, .. } => {
                if let Statement::VariableDecl { name, .. } = init.as_ref() {
                    *condition = normalize_loop_condition(condition, name);
                }
                normalize_statements(body);
            }
            Statement::IfStatement { then_branch, else_branch, .. } => {
                normalize_statements(then_branch);
                if let Some(e) = else_branch {
                    normalize_statements(e);
                }
            }
            _ => {}
        }
    }
}

/// Rewrite every loop condition in `contract` to its canonical spelling.
pub fn normalize_loop_conditions(contract: &mut ContractNode) {
    normalize_statements(&mut contract.constructor.body);
    for method in contract.methods.iter_mut() {
        normalize_statements(&mut method.body);
    }
}
