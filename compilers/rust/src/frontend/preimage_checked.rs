//! GK-GAP-010: a public method's SigHashPreimage parameter must reach
//! `checkPreimage` on every path.
//!
//! spec/type-system.md 4.2: a SigHashPreimage parameter of a public method is
//! checked exactly once. The affine checker refuses a second consumption;
//! this refuses none. Every field an extractor reads from an unchecked
//! preimage is chosen by the spender.
//!
//! A must-analysis over the AST. A parameter counts as checked by a statement
//! list when it is passed to `checkPreimage` (directly, through a local alias,
//! or through a private method that itself checks that parameter on every
//! path) at a point every execution of the list reaches:
//!   - an `if` checks it only if both arms do (a missing else checks nothing);
//!   - a ternary checks it only if both arms do;
//!   - the right operand of `&&` / `||` checks nothing (short-circuit);
//!   - a `for` loop body checks nothing (the bound may be zero);
//!   - a `return` ends its path: a private method checks a parameter only if
//!     every `return` (and the fall-through end) is reached after the check,
//!     and an arm that returns drops out of the join after its `if`.
//!
//! A name assigned anywhere in the method body (the parameter itself or a
//! local) never stands for a parameter: after `a = other` it no longer holds
//! the parameter's value on every path.

use std::collections::{HashMap, HashSet};

use super::ast::*;
use super::diagnostic::Diagnostic;

/// The diagnostic every tier shares.
pub fn preimage_not_checked_message(method: &str, param: &str) -> String {
    format!(
        "public method '{}' must pass its SigHashPreimage parameter '{}' to checkPreimage() on every path",
        method, param
    )
}

type Origins = HashSet<String>;
type Aliases = HashMap<String, String>;

fn is_preimage(t: &TypeNode) -> bool {
    matches!(t, TypeNode::Primitive(PrimitiveTypeName::SigHashPreimage))
}

struct Checker<'a> {
    privates: HashMap<&'a str, &'a MethodNode>,
    memo: HashMap<String, HashSet<usize>>,
    reassigned: HashSet<String>,
}

fn collect_reassigned(stmts: &[Statement], out: &mut HashSet<String>) {
    for st in stmts {
        match st {
            Statement::Assignment { target: Expression::Identifier { name, .. }, .. } => {
                out.insert(name.clone());
            }
            Statement::IfStatement { then_branch, else_branch, .. } => {
                collect_reassigned(then_branch, out);
                if let Some(e) = else_branch {
                    collect_reassigned(e, out);
                }
            }
            Statement::ForStatement { body, .. } => collect_reassigned(body, out),
            _ => {}
        }
    }
}

impl<'a> Checker<'a> {
    fn resolve(&self, e: &Expression, aliases: &Aliases) -> Option<String> {
        match e {
            Expression::Identifier { name, .. } if !self.reassigned.contains(name) => aliases.get(name).cloned(),
            _ => None,
        }
    }

    fn private_target(&self, callee: &Expression) -> Option<&'a MethodNode> {
        let name = match callee {
            Expression::PropertyAccess { property, .. } => property.as_str(),
            Expression::MemberExpr { property, .. } => property.as_str(),
            Expression::Identifier { name, .. } => name.as_str(),
            _ => return None,
        };
        self.privates.get(name).copied()
    }

    fn must_params(&mut self, m: &'a MethodNode, stack: &HashSet<String>) -> HashSet<usize> {
        if let Some(r) = self.memo.get(&m.name) {
            return r.clone();
        }
        if stack.contains(&m.name) {
            return HashSet::new();
        }
        let mut aliases = Aliases::new();
        for p in &m.params {
            if is_preimage(&p.param_type) {
                aliases.insert(p.name.clone(), p.name.clone());
            }
        }
        let mut inner = stack.clone();
        inner.insert(m.name.clone());
        let mut fresh = HashSet::new();
        collect_reassigned(&m.body, &mut fresh);
        let outer = std::mem::replace(&mut self.reassigned, fresh);
        let done = self.walk_method(&m.body, &mut aliases.clone(), &inner);
        self.reassigned = outer;
        let result: HashSet<usize> = m
            .params
            .iter()
            .enumerate()
            .filter(|(_, p)| aliases.contains_key(&p.name) && done.contains(&p.name))
            .map(|(i, _)| i)
            .collect();
        self.memo.insert(m.name.clone(), result.clone());
        result
    }

    fn expr_must(&mut self, e: &Expression, aliases: &Aliases, stack: &HashSet<String>) -> Origins {
        match e {
            Expression::CallExpr { callee, args, .. } => {
                let mut out = Origins::new();
                for a in args {
                    out.extend(self.expr_must(a, aliases, stack));
                }
                if let Expression::MemberExpr { object, .. } = callee.as_ref() {
                    out.extend(self.expr_must(object, aliases, stack));
                }
                if let Expression::Identifier { name, .. } = callee.as_ref() {
                    if name == "checkPreimage" {
                        if let Some(o) = args.first().and_then(|a| self.resolve(a, aliases)) {
                            out.insert(o);
                        }
                        return out;
                    }
                }
                if let Some(target) = self.private_target(callee) {
                    for i in self.must_params(target, stack) {
                        if let Some(o) = args.get(i).and_then(|a| self.resolve(a, aliases)) {
                            out.insert(o);
                        }
                    }
                }
                out
            }
            Expression::BinaryExpr { op, left, right, .. } => {
                let mut out = self.expr_must(left, aliases, stack);
                if !matches!(op, BinaryOp::And | BinaryOp::Or) {
                    out.extend(self.expr_must(right, aliases, stack));
                }
                out
            }
            Expression::TernaryExpr { condition, consequent, alternate } => {
                let mut out = self.expr_must(condition, aliases, stack);
                let a = self.expr_must(consequent, aliases, stack);
                let b = self.expr_must(alternate, aliases, stack);
                out.extend(a.intersection(&b).cloned());
                out
            }
            Expression::UnaryExpr { operand, .. } => self.expr_must(operand, aliases, stack),
            Expression::IndexAccess { object, index } => {
                let mut out = self.expr_must(object, aliases, stack);
                out.extend(self.expr_must(index, aliases, stack));
                out
            }
            Expression::MemberExpr { object, .. } => self.expr_must(object, aliases, stack),
            Expression::ArrayLiteral { elements } => {
                let mut out = Origins::new();
                for el in elements {
                    out.extend(self.expr_must(el, aliases, stack));
                }
                out
            }
            _ => Origins::new(),
        }
    }

    /// Intersects the checked sets of every `return` and of the fall-through
    /// end of a method body.
    fn walk_method(&mut self, body: &[Statement], aliases: &mut Aliases, stack: &HashSet<String>) -> Origins {
        let mut exits: Vec<Origins> = Vec::new();
        if let Some(fall) = self.walk(body, &Origins::new(), aliases, stack, &mut exits) {
            exits.push(fall);
        }
        let mut it = exits.into_iter();
        let first = it.next().unwrap_or_default();
        it.fold(first, |acc, e| acc.intersection(&e).cloned().collect())
    }

    /// The parameters checked at the end of `stmts`, or `None` when every path
    /// through `stmts` returns first. Each `return` records its own checked
    /// set in `exits`.
    fn walk(
        &mut self,
        stmts: &[Statement],
        done_in: &Origins,
        aliases: &mut Aliases,
        stack: &HashSet<String>,
        exits: &mut Vec<Origins>,
    ) -> Option<Origins> {
        let mut done = done_in.clone();
        for st in stmts {
            match st {
                Statement::VariableDecl { name, init, .. } => {
                    done.extend(self.expr_must(init, aliases, stack));
                    match self.resolve(init, aliases) {
                        Some(o) => {
                            aliases.insert(name.clone(), o);
                        }
                        None => {
                            aliases.remove(name);
                        }
                    }
                }
                Statement::Assignment { value, .. } => done.extend(self.expr_must(value, aliases, stack)),
                Statement::ExpressionStatement { expression, .. } => {
                    done.extend(self.expr_must(expression, aliases, stack))
                }
                Statement::ReturnStatement { value, .. } => {
                    let mut at_exit = done.clone();
                    if let Some(v) = value {
                        at_exit.extend(self.expr_must(v, aliases, stack));
                    }
                    exits.push(at_exit);
                    return None;
                }
                Statement::IfStatement { condition, then_branch, else_branch, .. } => {
                    done.extend(self.expr_must(condition, aliases, stack));
                    let then_done = self.walk(then_branch, &done, &mut aliases.clone(), stack, exits);
                    let empty: Vec<Statement> = Vec::new();
                    let else_stmts = else_branch.as_ref().unwrap_or(&empty);
                    let else_done = self.walk(else_stmts, &done, &mut aliases.clone(), stack, exits);
                    done = match (then_done, else_done) {
                        (None, None) => return None,
                        (None, Some(e)) => e,
                        (Some(t), None) => t,
                        (Some(t), Some(e)) => t.intersection(&e).cloned().collect(),
                    };
                }
                Statement::ForStatement { body, .. } => {
                    // The body checks nothing for the code after the loop, but
                    // a `return` inside it still ends a path.
                    self.walk(body, &done, &mut aliases.clone(), stack, exits);
                }
                _ => {}
            }
        }
        Some(done)
    }
}

pub fn check_preimage_checked_on_every_path(contract: &ContractNode) -> Vec<Diagnostic> {
    let mut checker = Checker { privates: HashMap::new(), memo: HashMap::new(), reassigned: HashSet::new() };
    for m in &contract.methods {
        if m.visibility != Visibility::Public {
            checker.privates.insert(m.name.as_str(), m);
        }
    }
    let mut errors = Vec::new();
    for m in &contract.methods {
        if m.visibility != Visibility::Public {
            continue;
        }
        let tracked: Vec<&str> =
            m.params.iter().filter(|p| is_preimage(&p.param_type)).map(|p| p.name.as_str()).collect();
        if tracked.is_empty() {
            continue;
        }
        let mut aliases: Aliases = tracked.iter().map(|n| (n.to_string(), n.to_string())).collect();
        let mut stack = HashSet::new();
        stack.insert(m.name.clone());
        let mut fresh = HashSet::new();
        collect_reassigned(&m.body, &mut fresh);
        checker.reassigned = fresh;
        let done = checker.walk_method(&m.body, &mut aliases, &stack);
        for name in tracked {
            if !done.contains(name) {
                errors.push(Diagnostic::error(
                    preimage_not_checked_message(&m.name, name),
                    Some(m.source_location.clone()),
                ));
            }
        }
    }
    errors
}
