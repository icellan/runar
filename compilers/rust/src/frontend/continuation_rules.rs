//! Two rules about where a StatefulSmartContract's satoshis can go, both
//! read off the side-effect summary, so they see exactly the effects the
//! continuation is injected from. Mirrors
//! `packages/runar-compiler/src/passes/continuation-rules.ts` (same texts in
//! all seven tiers).
//!
//! #199 (warning, validator): no public method is terminal and none sizes its
//! own outputs (addOutput / addRawOutput, directly or via a private helper),
//! so every spend takes the default continuation whose F-024 floor never lets
//! the value shrink: the satoshis can never leave.
//!
//! D18 (error, typecheck; re-derived on the ANF for `--ir` in
//! `ir/continuation_rules.rs`), PER PATH: any addOutput / addRawOutput
//! anywhere in a public method (directly or in a private helper, on any
//! branch) removes the auto-injected continuation for the whole method, and
//! only addOutput carries state, so a path that writes state and reaches no
//! addOutput drops its write and the contract's value leaves with the spend.
//! A path that writes nothing is terminal by design and is accepted.
//!
//! D27 (error, typecheck; `--ir` likewise), PER PATH, same family: in such a
//! method a state write after the path's last addOutput is dead on chain (the
//! script commits only the values its addOutput calls carry), so an SDK that
//! builds the continuation from the final state is refused on every honest
//! call. D18 wins when a method has both.

use std::collections::{HashMap, HashSet};

use super::ast::{ContractNode, Expression, MethodNode, Statement, Visibility};
use super::side_effect_summary::{ContinuationShape, MethodEffects, SideEffectSummary};

/// #199: the shared warning text.
pub fn release_trap_message(contract: &str) -> String {
    format!(
        "contract '{contract}' has no terminal method and no public method that calls \
addOutput/addRawOutput; its satoshis can never leave instances of '{contract}'"
    )
}

/// D18: the shared error text.
pub fn dropped_continuation_message(method: &str) -> String {
    format!(
        "method '{method}' writes contract state on a path that reaches no addOutput(): a method \
that declares its own outputs (addOutput/addRawOutput) gets no auto-injected continuation, \
so on that path the state write would be lost and the contract's satoshis would leave with \
the spend. Add this.addOutput(satoshis, ...) on every path that writes state, or stop \
writing state on a path meant to end the contract"
    )
}

/// D27: the shared error text (D18's sibling).
pub fn dead_state_write_message(method: &str) -> String {
    format!(
        "method '{method}' writes contract state after the last addOutput() on a path: a method that declares its own \
outputs (addOutput/addRawOutput) commits only the values passed to its addOutput() calls, so on that path the \
write never reaches the chain and a caller that tracks the final state builds a continuation the script \
refuses. Pass the new value to addOutput(...) instead, or remove the write"
    )
}

/// Path-state bits: state written / addOutput reached / state written since
/// the path's last addOutput (D27; an addOutput clears it).
pub(crate) const PATH_W: u8 = 1;
pub(crate) const PATH_A: u8 = 2;
pub(crate) const PATH_D: u8 = 4;

/// D18 / D27 verdict of a method's exit states (D18 wins when both apply).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ContinuationVerdict {
    Dropped,
    DeadWrite,
}

/// Run a callee's exit state `y` after the caller's `x`: an addOutput in the
/// callee clears the caller's pending write.
fn then(x: u8, y: u8) -> u8 {
    let d = if y & PATH_A != 0 { y & PATH_D } else { (x | y) & PATH_D };
    ((x | y) & !PATH_D) | d
}

/// A set of path states (each 0..=7) as an 8-bit mask: bit `x` set = state `x`
/// is present. At most eight distinct states, so nothing explodes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct PathSet(u8);

impl PathSet {
    pub(crate) const EMPTY: PathSet = PathSet(0);
    /// `{0}`: a fresh path.
    pub(crate) const FRESH: PathSet = PathSet(1);

    pub(crate) fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub(crate) fn union(self, o: PathSet) -> PathSet {
        PathSet(self.0 | o.0)
    }
    fn states(self) -> impl Iterator<Item = u8> {
        (0u8..8).filter(move |x| self.0 & (1 << x) != 0)
    }
    /// `{x | bits for x in self}`.
    pub(crate) fn or_all(self, bits: u8) -> PathSet {
        PathSet(self.states().fold(0, |m, x| m | (1 << (x | bits))))
    }
    /// A state write: sets W and D.
    pub(crate) fn write(self) -> PathSet {
        self.or_all(PATH_W | PATH_D)
    }
    /// An addOutput: sets A and clears D.
    pub(crate) fn add_output(self) -> PathSet {
        PathSet(self.states().fold(0, |m, x| m | (1 << ((x | PATH_A) & !PATH_D))))
    }
    /// `{then(x, y) for x in self, y in o}` (D18 / D27 helper composition).
    pub(crate) fn compose(self, o: PathSet) -> PathSet {
        PathSet(self.states().fold(0, |m, x| o.states().fold(m, |m, y| m | (1 << then(x, y)))))
    }
    /// `{x | y for x in self, y in o}` (plain-OR composition, D26).
    pub(crate) fn compose_or(self, o: PathSet) -> PathSet {
        PathSet(self.states().fold(0, |m, x| o.states().fold(m, |m, y| m | (1 << (x | y)))))
    }
    /// Some path wrote state and reached no addOutput.
    pub(crate) fn dropped(self) -> bool {
        self.states().any(|x| x & PATH_W != 0 && x & PATH_A == 0)
    }
    /// D27: some path reached an addOutput and wrote state after its last one.
    pub(crate) fn dead_write(self) -> bool {
        self.states().any(|x| x & PATH_A != 0 && x & PATH_D != 0)
    }
    /// D18 / D27 verdict: D18 wins.
    pub(crate) fn verdict(self) -> Option<ContinuationVerdict> {
        if self.dropped() {
            Some(ContinuationVerdict::Dropped)
        } else if self.dead_write() {
            Some(ContinuationVerdict::DeadWrite)
        } else {
            None
        }
    }
    /// Some path carries a gate (bit 1) and no pin (bit 2) (D26).
    pub(crate) fn unpinned(self, gate: u8, pin: u8) -> bool {
        self.states().any(|x| x & gate != 0 && x & pin == 0)
    }
}

/// D18 + D27 (source path), per path, in a method that declares a state
/// output somewhere (so it gets no auto-continuation): `Dropped` when some
/// path writes state and reaches no addOutput, else `DeadWrite` when some path
/// writes state after its last addOutput. Mirrors `continuationVerdict` /
/// `SourcePaths` in continuation-rules.ts.
pub fn continuation_verdict(
    contract: &ContractNode,
    method: &MethodNode,
    effects: &MethodEffects,
) -> Option<ContinuationVerdict> {
    if !effects.has_state_output {
        return None;
    }
    SourcePaths::new(contract).exits(&method.body).verdict()
}

struct SourcePaths<'a> {
    mutable: HashSet<&'a str>,
    privates: HashMap<&'a str, &'a MethodNode>,
    helper_exits: HashMap<&'a str, PathSet>,
}

impl<'a> SourcePaths<'a> {
    fn new(contract: &'a ContractNode) -> Self {
        let mut sp = SourcePaths {
            mutable: contract.properties.iter().filter(|p| !p.readonly).map(|p| p.name.as_str()).collect(),
            privates: contract
                .methods
                .iter()
                .filter(|m| m.visibility == Visibility::Private)
                .map(|m| (m.name.as_str(), m))
                .collect(),
            helper_exits: HashMap::new(),
        };
        sp.precompute_helpers(contract);
        sp
    }

    /// N-264: a chain of D helpers each calling the next under K nested ifs
    /// would need D*K host frames if helper exits were computed by recursing
    /// from the caller's walk (as the TS reference does). Instead every
    /// helper's exits are computed callees-first, in an iterative post-order
    /// over the private call graph, so one body walk only ever recurses as
    /// deep as that body's own nesting. Memoized results are order-independent
    /// on an acyclic graph, so this is exactly the TS result; a cycle (refused
    /// by the validator) contributes `{0}`, as in TS.
    fn precompute_helpers(&mut self, contract: &'a ContractNode) {
        let privates = self.privates.clone();
        let mut done: HashSet<&'a str> = HashSet::new();
        let mut on_stack: HashSet<&'a str> = HashSet::new();
        for m in contract.methods.iter().filter(|m| m.visibility == Visibility::Private) {
            if done.contains(m.name.as_str()) {
                continue;
            }
            // (method, its direct private callees, next callee index)
            let mut work: Vec<(&'a MethodNode, Vec<&'a str>, usize)> = vec![(m, direct_callees(&m.body, &privates), 0)];
            on_stack.insert(m.name.as_str());
            while let Some((cur, callees, idx)) = work.last_mut() {
                if *idx < callees.len() {
                    let next = callees[*idx];
                    *idx += 1;
                    if done.contains(next) || on_stack.contains(next) {
                        continue;
                    }
                    let target = privates[next];
                    on_stack.insert(next);
                    work.push((target, direct_callees(&target.body, &privates), 0));
                    continue;
                }
                let cur = *cur;
                let ex = self.exits(&cur.body);
                self.helper_exits.insert(cur.name.as_str(), ex);
                on_stack.remove(cur.name.as_str());
                done.insert(cur.name.as_str());
                work.pop();
            }
        }
    }

    /// Exit states (fallthrough and return) of a body entered with a fresh path.
    fn exits(&self, body: &[Statement]) -> PathSet {
        let (live, returned) = self.stmts(body, PathSet::FRESH);
        live.union(returned)
    }

    fn stmts(&self, stmts: &[Statement], states: PathSet) -> (PathSet, PathSet) {
        let mut live = states;
        let mut returned = PathSet::EMPTY;
        for st in stmts {
            if live.is_empty() {
                break;
            }
            let (l, r) = self.stmt(st, live);
            returned = returned.union(r);
            live = l;
        }
        (live, returned)
    }

    fn stmt(&self, st: &Statement, states: PathSet) -> (PathSet, PathSet) {
        let none = PathSet::EMPTY;
        match st {
            Statement::Assignment { target, value, .. } => {
                let mut s = self.expr(target, states);
                s = self.expr(value, s);
                if self.writes_mutable(target) {
                    s = s.write();
                }
                (s, none)
            }
            Statement::ExpressionStatement { expression, .. } => (self.expr(expression, states), none),
            Statement::VariableDecl { init, .. } => (self.expr(init, states), none),
            Statement::ReturnStatement { value, .. } => match value {
                Some(v) => (none, self.expr(v, states)),
                None => (none, states),
            },
            Statement::IfStatement { condition, then_branch, else_branch, .. } => {
                let c = self.expr(condition, states);
                let (tl, tr) = self.stmts(then_branch, c);
                let (el, er) = match else_branch {
                    Some(e) => self.stmts(e, c),
                    None => (c, none),
                };
                (tl.union(el), tr.union(er))
            }
            Statement::ForStatement { init, condition, update, body, .. } => {
                let (il, ir) = self.stmt(init, states);
                let c = self.expr(condition, il);
                let (bl, br) = self.stmts(body, c);
                let (ul, ur) = self.stmt(update, bl);
                (c.union(ul), ir.union(br).union(ur))
            }
        }
    }

    fn writes_mutable(&self, target: &Expression) -> bool {
        let mut t = target;
        while let Expression::IndexAccess { object, .. } = t {
            t = object.as_ref();
        }
        matches!(t, Expression::PropertyAccess { property, .. } if self.mutable.contains(property.as_str()))
    }

    /// Every call in `e` runs, in evaluation order.
    fn expr(&self, e: &Expression, states: PathSet) -> PathSet {
        match e {
            Expression::IncrementExpr { operand, .. } | Expression::DecrementExpr { operand, .. } => {
                let s = self.expr(operand, states);
                if self.writes_mutable(operand) {
                    s.write()
                } else {
                    s
                }
            }
            Expression::CallExpr { callee, args, .. } => {
                let mut s = states;
                if !matches!(callee.as_ref(), Expression::Identifier { .. }) {
                    s = self.expr(callee, s);
                }
                for a in args {
                    s = self.expr(a, s);
                }
                let (name, member) = callee_name(callee);
                if member && name == Some("addOutput") {
                    return s.add_output();
                }
                if let Some(n) = name {
                    if self.privates.contains_key(n) {
                        // A helper not yet computed is on a cycle: `{0}`.
                        let ex = self.helper_exits.get(n).copied().unwrap_or(PathSet::FRESH);
                        return s.compose(ex);
                    }
                }
                s
            }
            Expression::BinaryExpr { left, right, .. } => self.expr(right, self.expr(left, states)),
            Expression::UnaryExpr { operand, .. } => self.expr(operand, states),
            Expression::TernaryExpr { condition, consequent, alternate } => {
                let c = self.expr(condition, states);
                self.expr(consequent, c).union(self.expr(alternate, c))
            }
            Expression::IndexAccess { object, index } => self.expr(index, self.expr(object, states)),
            Expression::MemberExpr { object, .. } => self.expr(object, states),
            Expression::ArrayLiteral { elements } => elements.iter().fold(states, |s, el| self.expr(el, s)),
            _ => states,
        }
    }
}

/// The callee's name and whether it is a member form (`this.x` / `a.x`).
fn callee_name(callee: &Expression) -> (Option<&str>, bool) {
    match callee {
        Expression::PropertyAccess { property, .. } | Expression::MemberExpr { property, .. } => {
            (Some(property.as_str()), true)
        }
        Expression::Identifier { name, .. } => (Some(name.as_str()), false),
        _ => (None, false),
    }
}

/// The private methods `body` calls directly (any position), in first-call order.
fn direct_callees<'a>(body: &[Statement], privates: &HashMap<&'a str, &'a MethodNode>) -> Vec<&'a str> {
    fn stmt<'a>(st: &Statement, p: &HashMap<&'a str, &'a MethodNode>, out: &mut Vec<&'a str>) {
        match st {
            Statement::Assignment { target, value, .. } => {
                expr(target, p, out);
                expr(value, p, out);
            }
            Statement::ExpressionStatement { expression, .. } => expr(expression, p, out),
            Statement::VariableDecl { init, .. } => expr(init, p, out),
            Statement::ReturnStatement { value, .. } => {
                if let Some(v) = value {
                    expr(v, p, out);
                }
            }
            Statement::IfStatement { condition, then_branch, else_branch, .. } => {
                expr(condition, p, out);
                then_branch.iter().for_each(|s| stmt(s, p, out));
                if let Some(e) = else_branch {
                    e.iter().for_each(|s| stmt(s, p, out));
                }
            }
            Statement::ForStatement { init, condition, update, body, .. } => {
                stmt(init, p, out);
                expr(condition, p, out);
                body.iter().for_each(|s| stmt(s, p, out));
                stmt(update, p, out);
            }
        }
    }
    fn expr<'a>(e: &Expression, p: &HashMap<&'a str, &'a MethodNode>, out: &mut Vec<&'a str>) {
        match e {
            Expression::IncrementExpr { operand, .. } | Expression::DecrementExpr { operand, .. } => expr(operand, p, out),
            Expression::CallExpr { callee, args, .. } => {
                if !matches!(callee.as_ref(), Expression::Identifier { .. }) {
                    expr(callee, p, out);
                }
                args.iter().for_each(|a| expr(a, p, out));
                if let (Some(n), _) = callee_name(callee) {
                    if let Some((k, _)) = p.get_key_value(n) {
                        if !out.contains(k) {
                            out.push(*k);
                        }
                    }
                }
            }
            Expression::BinaryExpr { left, right, .. } => {
                expr(left, p, out);
                expr(right, p, out);
            }
            Expression::UnaryExpr { operand, .. } => expr(operand, p, out),
            Expression::TernaryExpr { condition, consequent, alternate } => {
                expr(condition, p, out);
                expr(consequent, p, out);
                expr(alternate, p, out);
            }
            Expression::IndexAccess { object, index } => {
                expr(object, p, out);
                expr(index, p, out);
            }
            Expression::MemberExpr { object, .. } => expr(object, p, out),
            Expression::ArrayLiteral { elements } => elements.iter().for_each(|el| expr(el, p, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    body.iter().for_each(|s| stmt(s, privates, &mut out));
    out
}

/// #199: the contract-level warning text, when it applies.
pub fn release_trap_warning(contract: &ContractNode, summary: &SideEffectSummary) -> Option<String> {
    if contract.parent_class != "StatefulSmartContract" {
        return None;
    }
    let mut publics = contract.methods.iter().filter(|m| m.visibility == Visibility::Public).peekable();
    publics.peek()?;
    let trapped = publics.all(|m| match summary.get(&m.name) {
        Some(eff) => !ContinuationShape::for_effects(eff).is_terminal && !eff.has_state_output,
        None => false,
    });
    trapped.then(|| release_trap_message(&contract.name))
}
