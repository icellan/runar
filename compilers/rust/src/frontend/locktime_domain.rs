//! D26: a block-height locktime gate must pin the locktime domain. Mirrors
//! `packages/runar-compiler/src/passes/locktime-domain.ts` (same rule and text
//! in all seven tiers); see that file for the full rule.
//!
//! Consensus reads an nLockTime below 500,000,000 as a block height and one at
//! or above it as a Unix timestamp, so `assert(extractLocktime(p) >= H)` for a
//! height H is passed at once by any timestamp-domain locktime. A GATE is a
//! lower-bound compare on a locktime read; a PIN is an asserted domain bound
//! on one (the asserted condition itself or a top-level `&&` conjunct of it).
//! PER PATH, with D18's path walk and two bits (gate seen / pin seen): every
//! path through a public method that carries a gate must also carry a pin. A
//! value DERIVED from a read (arithmetic, a ternary arm, a builtin call, or a
//! local with a non-direct binding) is a gate under any lower bound and never
//! a pin. The `--ir` path re-derives the same rule from the ANF.

use std::collections::{HashMap, HashSet};

use num_bigint::BigInt;
use num_traits::Signed;

use super::ast::{BinaryOp, ContractNode, Expression, MethodNode, Statement, Visibility};
use super::continuation_rules::PathSet;
use crate::ir::{ANFBinding, ANFMethod, ANFProgram, ANFValue, ConstValue};

/// D26: the shared error text.
pub fn locktime_domain_message(method: &str) -> String {
    format!(
        "method '{method}' compares extractLocktime against a lower bound without pinning the locktime domain: \
consensus reads an nLockTime of 500000000 or more as a Unix timestamp, so on that path any such locktime \
passes a block-height gate at once. On every path that compares, assert(extractLocktime(preimage) < \
500000000n) for a block-height gate, or assert(extractLocktime(preimage) >= 500000000n) for a timestamp gate"
    )
}

/// The first nLockTime value consensus reads as a Unix timestamp.
const LOCKTIME_THRESHOLD: i64 = 500_000_000;

/// Path-state bits: gate seen / pin seen.
const G: u8 = 1;
const P: u8 = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Gate,
    Pin,
    None,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Cmp {
    Lt,
    Le,
    Gt,
    Ge,
}

impl Cmp {
    fn from_str(op: &str) -> Option<Cmp> {
        match op {
            "<" => Some(Cmp::Lt),
            "<=" => Some(Cmp::Le),
            ">" => Some(Cmp::Gt),
            ">=" => Some(Cmp::Ge),
            _ => None,
        }
    }
    fn flip(self) -> Cmp {
        match self {
            Cmp::Lt => Cmp::Gt,
            Cmp::Le => Cmp::Ge,
            Cmp::Gt => Cmp::Lt,
            Cmp::Ge => Cmp::Le,
        }
    }
    fn lower(self) -> bool {
        matches!(self, Cmp::Gt | Cmp::Ge)
    }
}

/// Classify `lt <op> other` (the locktime read on the left); `other` is the
/// literal's value, or None when it is not a bigint literal.
fn classify(op: Cmp, other: Option<&BigInt>) -> Kind {
    let t = BigInt::from(LOCKTIME_THRESHOLD);
    if op.lower() {
        // `>= 0` is vacuous (every locktime passes it): no gate. Only literal 0:
        // a negative bound is a negation in source but may be a literal in IR.
        if op == Cmp::Ge && other.is_some_and(|o| o.sign() == num_bigint::Sign::NoSign) {
            return Kind::None;
        }
        let ts = match other {
            Some(o) if op == Cmp::Ge => *o >= t,
            Some(o) => *o >= &t - 1,
            None => false,
        };
        return if ts { Kind::Pin } else { Kind::Gate };
    }
    let Some(o) = other else { return Kind::None };
    let height = if op == Cmp::Lt { o.is_positive() && *o <= t } else { !o.is_negative() && *o < t };
    if height {
        Kind::Pin
    } else {
        Kind::None
    }
}

/// Taint level of a value: not a locktime read / a direct read / derived from one.
const NONE: u8 = 0;
const DIRECT: u8 = 1;
const DERIVED: u8 = 2;

/// Binary / unary operators whose result derives from their operands.
fn propagates(op: &str) -> bool {
    matches!(op, "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" | "<<" | ">>")
}
fn propagates_unary(op: &str) -> bool {
    matches!(op, "-" | "~")
}

/// Least fixpoint for the tainted set, then greatest fixpoint (within it) for
/// the names all of whose bindings are direct reads.
fn solve_taint<B>(
    binds: &[(String, B)],
    tainted: impl Fn(&B, &HashSet<String>) -> bool,
    direct: impl Fn(&B, &HashSet<String>) -> bool,
) -> HashMap<String, u8> {
    let mut t: HashSet<String> = HashSet::new();
    let mut changed = true;
    while changed {
        changed = false;
        for (name, b) in binds {
            if !t.contains(name) && tainted(b, &t) {
                t.insert(name.clone());
                changed = true;
            }
        }
    }
    let mut d = t.clone();
    changed = true;
    while changed {
        changed = false;
        for (name, b) in binds {
            if d.contains(name) && !direct(b, &d) {
                d.remove(name);
                changed = true;
            }
        }
    }
    t.into_iter().map(|n| {
        let lv = if d.contains(&n) { DIRECT } else { DERIVED };
        (n, lv)
    }).collect()
}

/// Classify a compare given its operands' taint levels: a direct read
/// classifies against the other side's literal; a derived value is a gate
/// under any lower bound and never a pin. A gate on either side wins.
fn classify_compare<T: ?Sized>(
    op: &str,
    left: &T,
    right: &T,
    level: &dyn Fn(&T) -> u8,
    literal: &dyn Fn(&T) -> Option<BigInt>,
) -> Kind {
    let Some(op) = Cmp::from_str(op) else { return Kind::None };
    let side = |lv: u8, o: Cmp, other: &T| -> Kind {
        match lv {
            DIRECT => classify(o, literal(other).as_ref()),
            DERIVED if o.lower() => Kind::Gate,
            _ => Kind::None,
        }
    };
    let a = side(level(left), op, right);
    let b = side(level(right), op.flip(), left);
    if a == Kind::Gate || b == Kind::Gate {
        Kind::Gate
    } else if a == Kind::Pin || b == Kind::Pin {
        Kind::Pin
    } else {
        Kind::None
    }
}

fn helper_key(name: &str, params: &[&str], levels: &HashMap<String, u8>) -> String {
    let sig: Vec<String> = params.iter().map(|p| levels.get(*p).copied().unwrap_or(NONE).to_string()).collect();
    format!("{name}|{}", sig.join(","))
}

// ---------------------------------------------------------------------------
// Source path
// ---------------------------------------------------------------------------

fn is_call_to(e: &Expression, name: &str) -> bool {
    matches!(e, Expression::CallExpr { callee, .. }
        if matches!(callee.as_ref(), Expression::Identifier { name: n, .. } if n == name))
}

fn is_read(e: &Expression) -> bool {
    is_call_to(e, "extractLocktime") || is_call_to(e, "currentBlockHeight")
}

/// D26 prefilter: some method body calls extractLocktime or currentBlockHeight
/// anywhere. Mirrors `contractReadsLocktime`.
pub fn contract_reads_locktime(contract: &ContractNode) -> bool {
    fn expr(e: &Expression) -> bool {
        if is_read(e) {
            return true;
        }
        match e {
            Expression::BinaryExpr { left, right, .. } => expr(left) || expr(right),
            Expression::UnaryExpr { operand, .. }
            | Expression::IncrementExpr { operand, .. }
            | Expression::DecrementExpr { operand, .. } => expr(operand),
            Expression::CallExpr { callee, args, .. } => expr(callee) || args.iter().any(expr),
            Expression::MemberExpr { object, .. } => expr(object),
            Expression::TernaryExpr { condition, consequent, alternate } => {
                expr(condition) || expr(consequent) || expr(alternate)
            }
            Expression::IndexAccess { object, index } => expr(object) || expr(index),
            Expression::ArrayLiteral { elements } => elements.iter().any(expr),
            _ => false,
        }
    }
    fn stmt(st: &Statement) -> bool {
        match st {
            Statement::VariableDecl { init, .. } => expr(init),
            Statement::Assignment { target, value, .. } => expr(target) || expr(value),
            Statement::IfStatement { condition, then_branch, else_branch, .. } => {
                expr(condition)
                    || then_branch.iter().any(stmt)
                    || else_branch.as_ref().is_some_and(|e| e.iter().any(stmt))
            }
            Statement::ForStatement { init, condition, update, body, .. } => {
                stmt(init) || expr(condition) || stmt(update) || body.iter().any(stmt)
            }
            Statement::ReturnStatement { value, .. } => value.as_ref().is_some_and(expr),
            Statement::ExpressionStatement { expression, .. } => expr(expression),
        }
    }
    contract.methods.iter().any(|m| m.body.iter().any(stmt))
}

/// D26 (source path): true iff some path through public `method` carries an unpinned gate.
pub fn has_unpinned_locktime_gate(contract: &ContractNode, method: &MethodNode) -> bool {
    SourceGates::new(contract).exits(method, HashMap::new()).unpinned(G, P)
}

struct SourceGates<'a> {
    privates: HashMap<&'a str, &'a MethodNode>,
    /// Helper exits, by helper name and the taint level of each argument.
    helper_exits: HashMap<String, PathSet>,
    in_progress: HashSet<String>,
    /// Taint level of the locals and parameters of the method being walked.
    locals: HashMap<String, u8>,
}

impl<'a> SourceGates<'a> {
    fn new(contract: &'a ContractNode) -> Self {
        SourceGates {
            privates: contract
                .methods
                .iter()
                .filter(|m| m.visibility == Visibility::Private)
                .map(|m| (m.name.as_str(), m))
                .collect(),
            helper_exits: HashMap::new(),
            in_progress: HashSet::new(),
            locals: HashMap::new(),
        }
    }

    fn exits(&mut self, method: &MethodNode, params: HashMap<String, u8>) -> PathSet {
        let locals = collect_locktime_locals(&method.body, &params);
        let saved = std::mem::replace(&mut self.locals, locals);
        let (live, returned) = self.stmts(&method.body, PathSet::FRESH);
        self.locals = saved;
        live.union(returned)
    }

    fn level(&self, e: &Expression) -> u8 {
        expr_level(e, &self.locals)
    }

    fn compare(&self, e: &Expression) -> Kind {
        let Expression::BinaryExpr { op, left, right, .. } = e else { return Kind::None };
        let level = |x: &Expression| self.level(x);
        let literal = |x: &Expression| match x {
            Expression::BigIntLiteral { value } => Some(value.clone()),
            _ => None,
        };
        classify_compare(op.as_str(), left.as_ref(), right.as_ref(), &level, &literal)
    }

    fn asserted_pin(&self, e: &Expression) -> bool {
        if self.compare(e) == Kind::Pin {
            return true;
        }
        match e {
            Expression::BinaryExpr { op: BinaryOp::And, left, right, .. } => {
                self.asserted_pin(left) || self.asserted_pin(right)
            }
            _ => false,
        }
    }

    fn stmts(&mut self, stmts: &[Statement], states: PathSet) -> (PathSet, PathSet) {
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

    fn stmt(&mut self, st: &Statement, states: PathSet) -> (PathSet, PathSet) {
        let none = PathSet::EMPTY;
        match st {
            Statement::Assignment { target, value, .. } => {
                let s = self.expr(target, states);
                (self.expr(value, s), none)
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

    fn expr(&mut self, e: &Expression, states: PathSet) -> PathSet {
        match e {
            Expression::CallExpr { callee, args, .. } => {
                let mut s = states;
                if !matches!(callee.as_ref(), Expression::Identifier { .. }) {
                    s = self.expr(callee, s);
                }
                for a in args {
                    s = self.expr(a, s);
                }
                if is_call_to(e, "assert") && args.first().is_some_and(|a| self.asserted_pin(a)) {
                    return s.or_all(P);
                }
                let name = match callee.as_ref() {
                    Expression::PropertyAccess { property, .. } | Expression::MemberExpr { property, .. } => {
                        Some(property.as_str())
                    }
                    _ => None,
                };
                if let Some(helper) = name.and_then(|n| self.privates.get(n).copied()) {
                    let levels: Vec<u8> = args.iter().map(|a| self.level(a)).collect();
                    let ex = self.helper(helper, &levels);
                    return s.compose_or(ex);
                }
                s
            }
            Expression::BinaryExpr { left, right, .. } => {
                let s = self.expr(left, states);
                let s = self.expr(right, s);
                if self.compare(e) == Kind::Gate {
                    s.or_all(G)
                } else {
                    s
                }
            }
            Expression::UnaryExpr { operand, .. } => self.expr(operand, states),
            Expression::TernaryExpr { condition, consequent, alternate } => {
                let c = self.expr(condition, states);
                let a = self.expr(consequent, c);
                a.union(self.expr(alternate, c))
            }
            Expression::IndexAccess { object, index } => {
                let s = self.expr(object, states);
                self.expr(index, s)
            }
            Expression::MemberExpr { object, .. } => self.expr(object, states),
            Expression::IncrementExpr { operand, .. } | Expression::DecrementExpr { operand, .. } => {
                self.expr(operand, states)
            }
            Expression::ArrayLiteral { elements } => {
                let mut s = states;
                for el in elements {
                    s = self.expr(el, s);
                }
                s
            }
            _ => states,
        }
    }

    fn helper(&mut self, m: &'a MethodNode, arg_levels: &[u8]) -> PathSet {
        let mut params = HashMap::new();
        for (i, p) in m.params.iter().enumerate() {
            let lv = arg_levels.get(i).copied().unwrap_or(NONE);
            if lv != NONE {
                params.insert(p.name.clone(), lv);
            }
        }
        let names: Vec<&str> = m.params.iter().map(|p| p.name.as_str()).collect();
        let key = helper_key(&m.name, &names, &params);
        if let Some(ex) = self.helper_exits.get(&key) {
            return *ex;
        }
        // Recursion is refused by the validator; a cycle contributes nothing.
        if self.in_progress.contains(&m.name) {
            return PathSet::FRESH;
        }
        self.in_progress.insert(m.name.clone());
        let ex = self.exits(m, params);
        self.in_progress.remove(&m.name);
        self.helper_exits.insert(key, ex);
        ex
    }
}

/// Taint level of a source expression, given the taint of the names in scope.
fn expr_level(e: &Expression, names: &HashMap<String, u8>) -> u8 {
    if is_read(e) {
        return DIRECT;
    }
    let any = |xs: &[&Expression]| if xs.iter().any(|x| expr_level(x, names) != NONE) { DERIVED } else { NONE };
    match e {
        Expression::Identifier { name, .. } => names.get(name).copied().unwrap_or(NONE),
        Expression::BinaryExpr { op, left, right, .. } if propagates(op.as_str()) => any(&[left, right]),
        Expression::UnaryExpr { op, operand, .. } if propagates_unary(op.as_str()) => any(&[operand]),
        Expression::TernaryExpr { consequent, alternate, .. } => any(&[consequent, alternate]),
        // A builtin (identifier callee); a helper's return is not followed.
        Expression::CallExpr { callee, args, .. } if matches!(callee.as_ref(), Expression::Identifier { .. }) => {
            let xs: Vec<&Expression> = args.iter().collect();
            any(&xs)
        }
        _ => NONE,
    }
}

/// One binding of a local: an expression, or (for a tainted parameter) the
/// level its call passes it.
enum SourceBind<'e> {
    Expr(&'e Expression),
    Level(u8),
}

/// Taint of the method's locals and parameters, from every binding in the
/// body (declaration or assignment, anywhere) plus one binding per tainted
/// parameter. Order-blind on purpose.
fn collect_locktime_locals(body: &[Statement], params: &HashMap<String, u8>) -> HashMap<String, u8> {
    fn visit<'e>(stmts: &'e [Statement], binds: &mut Vec<(String, SourceBind<'e>)>) {
        for st in stmts {
            match st {
                Statement::VariableDecl { name, init, .. } => binds.push((name.clone(), SourceBind::Expr(init))),
                Statement::Assignment { target: Expression::Identifier { name, .. }, value, .. } => {
                    binds.push((name.clone(), SourceBind::Expr(value)))
                }
                Statement::IfStatement { then_branch, else_branch, .. } => {
                    visit(then_branch, binds);
                    if let Some(e) = else_branch {
                        visit(e, binds);
                    }
                }
                Statement::ForStatement { init, body, .. } => {
                    visit(std::slice::from_ref(init.as_ref()), binds);
                    visit(body, binds);
                }
                _ => {}
            }
        }
    }
    let mut binds: Vec<(String, SourceBind)> =
        params.iter().map(|(n, lv)| (n.clone(), SourceBind::Level(*lv))).collect();
    visit(body, &mut binds);
    let as_map = |t: &HashSet<String>| -> HashMap<String, u8> { t.iter().map(|n| (n.clone(), DIRECT)).collect() };
    solve_taint(
        &binds,
        |b, t| match b {
            SourceBind::Level(lv) => *lv != NONE,
            SourceBind::Expr(e) => expr_level(e, &as_map(t)) != NONE,
        },
        |b, d| match b {
            SourceBind::Level(lv) => *lv == DIRECT,
            SourceBind::Expr(e) => {
                is_read(e) || matches!(e, Expression::Identifier { name, .. } if d.contains(name))
            }
        },
    )
}

// ---------------------------------------------------------------------------
// --ir path
// ---------------------------------------------------------------------------

fn ref_of(v: &ANFValue) -> Option<&str> {
    match v {
        ANFValue::LoadConst { value: serde_json::Value::String(s) } => s.strip_prefix("@ref:"),
        _ => None,
    }
}

/// D26 on the `--ir` path: `--ir` skips typecheck, so the rule is re-derived
/// from the ANF of every public method (stateless and stateful). Mirrors
/// `assertIrLocktimeDomain`.
pub fn assert_ir_locktime_domain(program: &ANFProgram) -> Result<(), String> {
    // Prefilter (as contract_reads_locktime): no extractLocktime call, no gate.
    fn reads(bs: &[ANFBinding]) -> bool {
        bs.iter().any(|b| match &b.value {
            ANFValue::Call { func, .. } => func == "extractLocktime",
            ANFValue::If { then, else_branch, .. } => reads(then) || reads(else_branch),
            ANFValue::Loop { body, .. } => reads(body),
            _ => false,
        })
    }
    if !program.methods.iter().any(|m| reads(&m.body)) {
        return Ok(());
    }
    let privates: HashMap<&str, &ANFMethod> = program
        .methods
        .iter()
        .filter(|m| !m.is_public && m.name != "constructor")
        .map(|m| (m.name.as_str(), m))
        .collect();
    let mut walk = IrWalk { privates, exits_of: HashMap::new(), in_progress: HashSet::new() };
    for m in &program.methods {
        if !m.is_public || m.name == "constructor" {
            continue;
        }
        if walk.exits(m, &[]).unpinned(G, P) {
            return Err(locktime_domain_message(&m.name));
        }
    }
    Ok(())
}

struct IrWalk<'a> {
    privates: HashMap<&'a str, &'a ANFMethod>,
    exits_of: HashMap<String, PathSet>,
    in_progress: HashSet<String>,
}

impl<'a> IrWalk<'a> {
    fn exits(&mut self, m: &'a ANFMethod, arg_levels: &[u8]) -> PathSet {
        let mut params = HashMap::new();
        for (i, p) in m.params.iter().enumerate() {
            let lv = arg_levels.get(i).copied().unwrap_or(NONE);
            if lv != NONE {
                params.insert(p.name.clone(), lv);
            }
        }
        let names: Vec<&str> = m.params.iter().map(|p| p.name.as_str()).collect();
        let key = helper_key(&m.name, &names, &params);
        if let Some(ex) = self.exits_of.get(&key) {
            return *ex;
        }
        if self.in_progress.contains(&m.name) {
            return PathSet::FRESH;
        }
        self.in_progress.insert(m.name.clone());
        let gates = IrGates::new(m, &params);
        let ex = gates.run(&m.body, PathSet::FRESH, self);
        self.in_progress.remove(&m.name);
        self.exits_of.insert(key, ex);
        ex
    }
}

struct IrGates<'a> {
    /// Every binding of the method, by name (a name bound more than once keeps all its values).
    defs: HashMap<&'a str, Vec<&'a ANFValue>>,
    /// Taint level of every temp.
    taint: HashMap<String, u8>,
}

impl<'a> IrGates<'a> {
    fn new(method: &'a ANFMethod, params: &HashMap<String, u8>) -> Self {
        fn index<'a>(bs: &'a [ANFBinding], defs: &mut HashMap<&'a str, Vec<&'a ANFValue>>, binds: &mut Vec<(String, &'a ANFValue)>) {
            for b in bs {
                defs.entry(b.name.as_str()).or_default().push(&b.value);
                binds.push((b.name.clone(), &b.value));
                match &b.value {
                    ANFValue::If { then, else_branch, .. } => {
                        index(then, defs, binds);
                        index(else_branch, defs, binds);
                    }
                    ANFValue::Loop { body, .. } => index(body, defs, binds),
                    _ => {}
                }
            }
        }
        let mut defs = HashMap::new();
        let mut binds = Vec::new();
        index(&method.body, &mut defs, &mut binds);
        let last = |arm: &[ANFBinding]| arm.last().map(|b| b.name.clone());
        let taint = solve_taint(
            &binds,
            |v, t| {
                if let Some(r) = ref_of(v) {
                    return t.contains(r);
                }
                match v {
                    ANFValue::Call { func, args, .. } => func == "extractLocktime" || args.iter().any(|a| t.contains(a)),
                    ANFValue::LoadParam { name } => params.get(name).copied().unwrap_or(NONE) != NONE,
                    ANFValue::BinOp { op, left, right, .. } => propagates(op) && (t.contains(left) || t.contains(right)),
                    ANFValue::UnaryOp { op, operand, .. } => propagates_unary(op) && t.contains(operand),
                    ANFValue::If { then, else_branch, .. } => {
                        [last(then), last(else_branch)].iter().flatten().any(|n| t.contains(n))
                    }
                    _ => false,
                }
            },
            |v, d| {
                if let Some(r) = ref_of(v) {
                    return d.contains(r);
                }
                match v {
                    ANFValue::Call { func, .. } => func == "extractLocktime",
                    ANFValue::LoadParam { name } => params.get(name).copied() == Some(DIRECT),
                    _ => false,
                }
            },
        );
        IrGates { defs, taint }
    }

    fn level(&self, name: &str) -> u8 {
        self.taint.get(name).copied().unwrap_or(NONE)
    }

    fn literal(&self, name: &str) -> Option<BigInt> {
        let mut name = name;
        let mut seen = HashSet::new();
        while seen.insert(name) {
            let vs = self.defs.get(name)?;
            if vs.len() != 1 {
                return None;
            }
            let v = vs[0];
            if !matches!(v, ANFValue::LoadConst { .. }) {
                return None;
            }
            if let Some(ConstValue::Int(i)) = v.const_value() {
                return Some(i);
            }
            name = ref_of(v)?;
        }
        None
    }

    fn compare(&self, v: &ANFValue) -> Kind {
        let ANFValue::BinOp { op, left, right, .. } = v else { return Kind::None };
        let level = |x: &str| self.level(x);
        let literal = |x: &str| self.literal(x);
        classify_compare(op.as_str(), left.as_str(), right.as_str(), &level, &literal)
    }

    /// Does `assert(name)` imply a pin?
    fn asserted_pin<'s>(&'s self, name: &'s str, seen: &mut HashSet<&'s str>) -> bool {
        if !seen.insert(name) {
            return false;
        }
        let Some(vs) = self.defs.get(name) else { return false };
        if vs.len() != 1 {
            return false;
        }
        let v = vs[0];
        if self.compare(v) == Kind::Pin {
            return true;
        }
        if let Some(r) = ref_of(v) {
            return self.asserted_pin(r, seen);
        }
        // `a && b` lowers to `if a then [..., b] else [false]`.
        if let ANFValue::If { cond, then, else_branch, .. } = v {
            if is_const_false_arm(else_branch) {
                if let Some(lastb) = then.last() {
                    return self.asserted_pin(cond, seen) || self.asserted_pin(&lastb.name, seen);
                }
            }
        }
        false
    }

    fn run(&self, bs: &'a [ANFBinding], states: PathSet, walk: &mut IrWalk<'a>) -> PathSet {
        let mut s = states;
        for b in bs {
            match &b.value {
                v @ ANFValue::BinOp { .. } => {
                    if self.compare(v) == Kind::Gate {
                        s = s.or_all(G);
                    }
                }
                ANFValue::Assert { value, .. } => {
                    if self.asserted_pin(value, &mut HashSet::new()) {
                        s = s.or_all(P);
                    }
                }
                ANFValue::MethodCall { method, args, .. } => {
                    if let Some(t) = walk.privates.get(method.as_str()).copied() {
                        let levels: Vec<u8> = args.iter().map(|a| self.level(a)).collect();
                        let ex = walk.exits(t, &levels);
                        s = s.compose_or(ex);
                    }
                }
                ANFValue::If { then, else_branch, .. } => {
                    let t = self.run(then, s, walk);
                    let e = self.run(else_branch, s, walk);
                    s = t.union(e);
                }
                ANFValue::Loop { body, .. } => {
                    let r = self.run(body, s, walk);
                    s = s.union(r);
                }
                _ => {}
            }
        }
        s
    }
}

fn is_const_false_arm(arm: &[ANFBinding]) -> bool {
    arm.len() == 1 && matches!(&arm[0].value, ANFValue::LoadConst { value: serde_json::Value::Bool(false) })
}
