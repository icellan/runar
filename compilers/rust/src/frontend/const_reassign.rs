//! N-342 — a `const` local on the `.runar.ts` surface cannot be reassigned.
//!
//! spec/grammar.md §9: "`const` variables cannot be reassigned." The parser
//! recorded `mutable: false` for `const` and nothing ever read it, so
//! `const s = 1n; s = s + x;` compiled. Refused, with one sentence in all
//! seven tiers: `x = e` (and the compound forms the parser desugars to it),
//! `x++` / `++x` / `x--` / `--x`, and a `const` for-initializer, which the
//! loop's own `i++` then advances. Element writes (`x[0] = e`) are not
//! touched. Scoping follows blocks. Runs on the `.runar.ts` parse result only:
//! other surfaces spell immutability differently and several parsers record
//! `mutable` as a constant.

use std::collections::HashMap;

use super::ast::{ContractNode, Expression, SourceLocation, Statement};
use super::diagnostic::Diagnostic;

/// The one sentence every tier emits for reassigning const `name`.
pub fn const_reassign_message(name: &str) -> String {
    format!("Cannot assign to '{}' because it is a constant.", name)
}

type Scope = HashMap<String, bool>;

fn lookup(scopes: &[Scope], name: &str) -> Option<bool> {
    scopes.iter().rev().find_map(|s| s.get(name).copied())
}

fn check_target(target: &Expression, scopes: &[Scope], loc: &SourceLocation, out: &mut Vec<Diagnostic>) {
    if let Expression::Identifier { name } = target {
        if lookup(scopes, name) == Some(false) {
            out.push(Diagnostic::error(const_reassign_message(name), Some(loc.clone())));
        }
    }
}

fn check_expr(e: &Expression, scopes: &[Scope], loc: &SourceLocation, out: &mut Vec<Diagnostic>) {
    match e {
        Expression::IncrementExpr { operand, .. } | Expression::DecrementExpr { operand, .. } => {
            check_target(operand, scopes, loc, out)
        }
        _ => {}
    }
}

fn check_simple(stmt: &Statement, scopes: &[Scope], out: &mut Vec<Diagnostic>) {
    match stmt {
        Statement::Assignment { target, source_location, .. } => {
            check_target(target, scopes, source_location, out)
        }
        Statement::ExpressionStatement { expression, source_location } => {
            check_expr(expression, scopes, source_location, out)
        }
        _ => {}
    }
}

fn walk(stmts: &[Statement], scopes: &mut Vec<Scope>, out: &mut Vec<Diagnostic>) {
    scopes.push(Scope::new());
    for stmt in stmts {
        match stmt {
            Statement::VariableDecl { name, mutable, .. } => {
                scopes.last_mut().unwrap().insert(name.clone(), *mutable);
            }
            Statement::IfStatement { then_branch, else_branch, .. } => {
                walk(then_branch, scopes, out);
                if let Some(e) = else_branch {
                    walk(e, scopes, out);
                }
            }
            Statement::ForStatement { init, update, body, .. } => {
                let mut loop_scope = Scope::new();
                if let Statement::VariableDecl { name, mutable, .. } = init.as_ref() {
                    loop_scope.insert(name.clone(), *mutable);
                }
                scopes.push(loop_scope);
                check_simple(update, scopes, out);
                walk(body, scopes, out);
                scopes.pop();
            }
            other => check_simple(other, scopes, out),
        }
    }
    scopes.pop();
}

/// A diagnostic for every reassigned `const` local in `contract`.
pub fn check_const_reassignment(contract: &ContractNode) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    walk(&contract.constructor.body, &mut Vec::new(), &mut out);
    for method in &contract.methods {
        walk(&method.body, &mut Vec::new(), &mut out);
    }
    out
}
