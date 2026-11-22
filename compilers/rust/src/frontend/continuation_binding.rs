//! D25 — bind every state continuation to the input that made it.
//!
//! SECURITY CORE (fund safety). Mirrors the TypeScript reference
//! `packages/runar-compiler/src/passes/continuation-binding.ts` exactly (same
//! classification, field name and diagnostics in all seven tiers).
//!
//! Before D25 every stateful covenant checked `hash256(continuation || change)
//! == hashOutputs` over the WHOLE output list, and the BIP-143 preimage carries
//! no input position, so two UTXOs of one contract spent in one transaction
//! that reach the same post-state were BOTH satisfied by ONE continuation
//! output (twin-input theft). The contract is classified once:
//!
//!   'single'    every continuation-producing public method is mutate-only and
//!               reads nothing SINGLE zeroes or redefines: those methods
//!               default to SIGHASH_SINGLE|FORKID (ALL|ANYONECANPAY|FORKID
//!               becomes SINGLE|ANYONECANPAY|FORKID); an explicit pure
//!               `@sighash ALL|FORKID` is refused.
//!   'bind'      at least one auto-continuation method but not 'single': a
//!               hidden last state field `_spentOutpointHash` =
//!               sha256(extractOutpoint(txPreimage)) in every continuation.
//!   'explicit'  every continuation method sizes its own outputs: unchanged,
//!               warning on an unsigned `addOutput(extractAmount(...))`.
//!   'none'      stateless, or no public method produces a continuation.

use std::collections::{HashMap, HashSet};

use super::ast::{
    ContractNode, Expression, MethodNode, PrimitiveTypeName, PropertyNode, SourceLocation, Statement,
    TypeNode, Visibility,
};
use super::diagnostic::Diagnostic;
use super::side_effect_summary::{compute_side_effect_summary, ContinuationShape};
use super::sighash_directive::{BASE_ALL, BASE_SINGLE, BASE_TYPE_MASK, FLAG_ANYONECANPAY, FLAG_FORKID};

/// The hidden state field of a 'bind' contract (reserved; last mutable property).
pub const TWIN_BINDING_FIELD: &str = "_spentOutpointHash";

/// SIGHASH_SINGLE|FORKID.
pub const SIGHASH_SINGLE_FORKID: i64 = BASE_SINGLE | FLAG_FORKID;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuationClass {
    None,
    Single,
    Bind,
    Explicit,
}

/// Builtins whose meaning SINGLE zeroes or redefines (a mutate-only method reading one keeps ALL).
const SINGLE_INCOMPATIBLE_READS: &[&str] = &[
    "extractHashSequence",
    "extractOutputHash",
    "extractOutputs",
    "extractSigHashType",
    "requireOutputP2PKH",
];

/// D25: the shared error text for an explicit ALL sibling in a 'single' contract.
pub fn explicit_all_sibling_message(method: &str) -> String {
    format!(
        "method '{}': @sighash ALL|FORKID on a state-continuation method of a contract whose \
continuation methods are all mutate-only reopens twin-input theft: such a contract commits each \
continuation under SIGHASH_SINGLE (one output per input), and one ALL method lets its input reuse \
a sibling's output while its own value leaves as change. Remove the directive (the default is \
SINGLE|FORKID) or write @sighash SINGLE|FORKID",
        method
    )
}

/// D25: the shared warning text for an unsigned value-conserving addOutput (D12 C1).
pub fn unsigned_add_output_message(method: &str) -> String {
    format!(
        "method '{}' re-creates the contract with addOutput(extractAmount(...), ...) and checks no \
signature: two UTXOs of this contract spent in one transaction that reach the same state are both \
satisfied by ONE such output, and the other input's value leaves as anyone's change (twin-input \
aliasing). A method that sizes its own outputs is not bound to its input; require a signature, or \
let the compiler size the continuation (write state instead of calling addOutput)",
        method
    )
}

fn callee_name(callee: &Expression) -> Option<&str> {
    match callee {
        Expression::Identifier { name, .. } => Some(name.as_str()),
        Expression::PropertyAccess { property, .. } | Expression::MemberExpr { property, .. } => {
            Some(property.as_str())
        }
        _ => None,
    }
}

struct Reach<'a> {
    privates: &'a HashMap<String, &'a MethodNode>,
    names: HashSet<String>,
    visiting: HashSet<String>,
}

impl<'a> Reach<'a> {
    fn stmts(&mut self, ss: &[Statement]) {
        for s in ss {
            self.stmt(s);
        }
    }
    fn stmt(&mut self, s: &Statement) {
        match s {
            Statement::Assignment { target, value, .. } => {
                self.expr(target);
                self.expr(value);
            }
            Statement::ExpressionStatement { expression, .. } => self.expr(expression),
            Statement::IfStatement { condition, then_branch, else_branch, .. } => {
                self.expr(condition);
                self.stmts(then_branch);
                if let Some(e) = else_branch {
                    self.stmts(e);
                }
            }
            Statement::ForStatement { init, condition, update, body, .. } => {
                self.stmt(init);
                self.expr(condition);
                self.stmt(update);
                self.stmts(body);
            }
            Statement::ReturnStatement { value, .. } => {
                if let Some(v) = value {
                    self.expr(v);
                }
            }
            Statement::VariableDecl { init, .. } => self.expr(init),
        }
    }
    fn expr(&mut self, e: &Expression) {
        match e {
            Expression::CallExpr { callee, args, .. } => {
                if let Some(n) = callee_name(callee) {
                    self.names.insert(n.to_string());
                    let privates = self.privates;
                    if let Some(t) = privates.get(n) {
                        if !self.visiting.contains(n) {
                            self.visiting.insert(n.to_string());
                            self.stmts(&t.body);
                            self.visiting.remove(n);
                        }
                    }
                }
                for a in args {
                    self.expr(a);
                }
                if !matches!(**callee, Expression::Identifier { .. }) {
                    self.expr(callee);
                }
            }
            Expression::BinaryExpr { left, right, .. } => {
                self.expr(left);
                self.expr(right);
            }
            Expression::UnaryExpr { operand, .. } => self.expr(operand),
            Expression::TernaryExpr { condition, consequent, alternate } => {
                self.expr(condition);
                self.expr(consequent);
                self.expr(alternate);
            }
            Expression::IndexAccess { object, index } => {
                self.expr(object);
                self.expr(index);
            }
            Expression::MemberExpr { object, .. } => self.expr(object),
            Expression::ArrayLiteral { elements } => {
                for x in elements {
                    self.expr(x);
                }
            }
            _ => {}
        }
    }
}

/// Every call name reachable from `body`, through private helpers (cycle-guarded).
fn reachable_calls(body: &[Statement], privates: &HashMap<String, &MethodNode>) -> HashSet<String> {
    let mut r = Reach { privates, names: HashSet::new(), visiting: HashSet::new() };
    r.stmts(body);
    r.names
}

fn privates_of(contract: &ContractNode) -> HashMap<String, &MethodNode> {
    contract
        .methods
        .iter()
        .filter(|m| m.visibility == Visibility::Private)
        .map(|m| (m.name.clone(), m))
        .collect()
}

/// Classify a contract; returns the class and the indices (into
/// `contract.methods`) of the public continuation methods, in declaration order.
fn classify(contract: &ContractNode) -> (ContinuationClass, Vec<usize>) {
    if contract.parent_class != "StatefulSmartContract" {
        return (ContinuationClass::None, Vec::new());
    }
    let effects = compute_side_effect_summary(contract);
    let privates = privates_of(contract);
    let mut continuation_methods: Vec<usize> = Vec::new();
    let mut any_auto = false;
    let mut all_single_eligible = true;
    for (i, m) in contract.methods.iter().enumerate() {
        if m.visibility != Visibility::Public {
            continue;
        }
        let e = match effects.get(&m.name) {
            Some(e) => e,
            None => continue,
        };
        if !ContinuationShape::for_effects(e).needs_change {
            continue;
        }
        continuation_methods.push(i);
        if !e.has_state_output {
            any_auto = true;
        }
        let base = match m.sighash_type {
            None => BASE_ALL,
            Some(mode) => mode & BASE_TYPE_MASK,
        };
        let mode_ok = base == BASE_ALL || base == BASE_SINGLE;
        let reads = reachable_calls(&m.body, &privates);
        let reads_ok = !reads.iter().any(|n| SINGLE_INCOMPATIBLE_READS.contains(&n.as_str()));
        if e.has_state_output || e.has_data_output || !mode_ok || !reads_ok {
            all_single_eligible = false;
        }
    }
    if continuation_methods.is_empty() {
        return (ContinuationClass::None, continuation_methods);
    }
    if !any_auto {
        return (ContinuationClass::Explicit, continuation_methods);
    }
    let cls = if all_single_eligible { ContinuationClass::Single } else { ContinuationClass::Bind };
    (cls, continuation_methods)
}

/// The contract's D25 class (read by the injection pass and tests).
pub fn continuation_class(contract: &ContractNode) -> ContinuationClass {
    classify(contract).0
}

/// D25 resolution, run by pass 2 (validate) right before the `@sighash` field
/// checks: in a 'single' contract it sets each continuation method's
/// `sighash_type`; it refuses an explicit pure-ALL directive there; in an
/// 'explicit' contract it warns about unsigned value-conserving addOutput
/// methods. Idempotent. The source pipelines re-apply it (diagnostics
/// discarded) to the contract they carry into typecheck and ANF lowering.
pub fn resolve_continuation_binding(contract: &mut ContractNode) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let (cls, continuation_methods) = classify(contract);
    match cls {
        ContinuationClass::Single => {
            for i in continuation_methods {
                let m = &mut contract.methods[i];
                match m.sighash_type {
                    None => m.sighash_type = Some(SIGHASH_SINGLE_FORKID),
                    Some(mode) if (mode & BASE_TYPE_MASK) == BASE_ALL => {
                        if (mode & FLAG_ANYONECANPAY) != 0 {
                            m.sighash_type = Some((mode & !BASE_TYPE_MASK) | BASE_SINGLE);
                        } else {
                            diags.push(Diagnostic::error(
                                explicit_all_sibling_message(&m.name),
                                Some(m.source_location.clone()),
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
        ContinuationClass::Explicit => {
            let privates = privates_of(contract);
            for i in continuation_methods {
                let m = &contract.methods[i];
                if let Some(mode) = m.sighash_type {
                    if (mode & BASE_TYPE_MASK) != BASE_ALL {
                        continue;
                    }
                }
                if let Some(loc) = unsigned_value_conserving_add_output(m, &privates) {
                    diags.push(Diagnostic::warning(
                        unsigned_add_output_message(&m.name),
                        Some(loc.unwrap_or_else(|| m.source_location.clone())),
                    ));
                }
            }
        }
        _ => {}
    }
    diags
}

/// A call name that verifies a signature (any scheme).
fn is_signature_check(name: &str) -> bool {
    name == "checkSig" || name == "checkMultiSig" || name.starts_with("verify")
}

struct AmountScan<'a> {
    privates: &'a HashMap<String, &'a MethodNode>,
    amount_locals: HashSet<String>,
    /// `Some(loc)` once found; the inner `None` means "no location of its own".
    found: Option<Option<SourceLocation>>,
    visiting: HashSet<String>,
    /// Location of the statement being walked (Rust call expressions carry none).
    stmt_loc: Option<SourceLocation>,
}

impl<'a> AmountScan<'a> {
    fn reads_amount(&self, e: &Expression) -> bool {
        match e {
            Expression::CallExpr { callee, args, .. } => {
                callee_name(callee) == Some("extractAmount") || args.iter().any(|a| self.reads_amount(a))
            }
            Expression::Identifier { name, .. } => self.amount_locals.contains(name),
            Expression::BinaryExpr { left, right, .. } => self.reads_amount(left) || self.reads_amount(right),
            Expression::UnaryExpr { operand, .. } => self.reads_amount(operand),
            Expression::TernaryExpr { condition, consequent, alternate } => {
                self.reads_amount(condition) || self.reads_amount(consequent) || self.reads_amount(alternate)
            }
            _ => false,
        }
    }
    fn stmts(&mut self, ss: &[Statement]) {
        for s in ss {
            self.stmt(s);
        }
    }
    fn stmt(&mut self, s: &Statement) {
        let saved = self.stmt_loc.replace(s.source_location().clone());
        match s {
            Statement::VariableDecl { name, init, .. } => {
                if self.reads_amount(init) {
                    self.amount_locals.insert(name.clone());
                }
                self.expr(init);
            }
            Statement::Assignment { value, .. } => self.expr(value),
            Statement::ExpressionStatement { expression, .. } => self.expr(expression),
            Statement::IfStatement { condition, then_branch, else_branch, .. } => {
                self.expr(condition);
                self.stmts(then_branch);
                if let Some(e) = else_branch {
                    self.stmts(e);
                }
            }
            Statement::ForStatement { body, .. } => self.stmts(body),
            Statement::ReturnStatement { value, .. } => {
                if let Some(v) = value {
                    self.expr(v);
                }
            }
        }
        self.stmt_loc = saved;
    }
    fn expr(&mut self, e: &Expression) {
        let (callee, args) = match e {
            Expression::CallExpr { callee, args, .. } => (callee, args),
            _ => return,
        };
        let n = callee_name(callee);
        if n == Some("addOutput") && !args.is_empty() && self.reads_amount(&args[0]) && self.found.is_none() {
            self.found = Some(self.stmt_loc.clone());
        }
        let privates = self.privates;
        if let Some(t) = n.and_then(|n| privates.get(n)) {
            if !self.visiting.contains(&t.name) {
                self.visiting.insert(t.name.clone());
                self.stmts(&t.body);
                self.visiting.remove(&t.name);
            }
        }
        for a in args {
            self.expr(a);
        }
    }
}

/// D12 C1: the location of an `addOutput` whose satoshis argument reads
/// `extractAmount` (directly, or through a local initialised from it) in a
/// method that verifies no signature; `None` when there is none.
fn unsigned_value_conserving_add_output(
    method: &MethodNode,
    privates: &HashMap<String, &MethodNode>,
) -> Option<Option<SourceLocation>> {
    let calls = reachable_calls(&method.body, privates);
    if calls.iter().any(|n| is_signature_check(n)) {
        return None;
    }
    let mut scan = AmountScan {
        privates,
        amount_locals: HashSet::new(),
        found: None,
        visiting: HashSet::new(),
        stmt_loc: None,
    };
    scan.stmts(&method.body);
    scan.found
}

/// D25 injection, run after typecheck (before fixed-array expansion): a 'bind'
/// contract gains the hidden `_spentOutpointHash: Sha256 = 0x00..00` as its
/// LAST property. ANF lowering then writes it in every auto-continuation and
/// appends it to every addOutput (`stateful_scaffold.rs`). The zero
/// initializer keeps it out of the constructor ABI. Any other class is
/// returned unchanged.
pub fn inject_continuation_binding(contract: &ContractNode) -> ContractNode {
    let mut out = contract.clone();
    if continuation_class(contract) != ContinuationClass::Bind
        || contract.properties.iter().any(|p| p.name == TWIN_BINDING_FIELD)
    {
        return out;
    }
    out.properties.push(PropertyNode {
        name: TWIN_BINDING_FIELD.to_string(),
        prop_type: TypeNode::Primitive(PrimitiveTypeName::Sha256),
        readonly: false,
        initializer: Some(Expression::ByteStringLiteral { value: "00".repeat(32), source_location: None }),
        embed_always: false,
        source_location: contract.constructor.source_location.clone(),
        synthetic_array_chain: None,
    });
    out
}
