//! DoS-bound input limits + typed errors for the Rust frontend.
//!
//! Mirrors `InputLimits` from `packages/runar-ir-schema/src/input-limits.ts`.
//! See `compilers/go/frontend/input_limits.go` for the reference shape.

use std::fmt;

/// Mirrors `InputLimits.MAX_SOURCE_BYTES` (4 MiB) from the TS schema package.
/// Rúnar source files larger than this are rejected at the parser entry
/// point (`parse_source` / `parse`) BEFORE the tokenizer touches the
/// input. BUG-008 follow-up.
pub const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;

/// Mirrors `InputLimits.MAX_SOURCE_NESTING` (128) from
/// `packages/runar-ir-schema/src/input-limits.ts` (F-213): the nesting bound
/// for Rúnar source, on both measures defined there -- (A) parse nesting,
/// counted by the parsers, and (B) AST nesting of the finished tree. The
/// byte bound above never bounded recursion: 2,000 nested parens is a 4 KB
/// file, and it SIGABRTed this tier.
pub const MAX_SOURCE_NESTING: usize = 128;

/// The one diagnostic every tier emits for an over-nested source.
pub const SOURCE_NESTING_MESSAGE: &str =
    "source nesting depth exceeds MAX_SOURCE_NESTING (limit=128)";

/// Mirrors `InputLimits.MAX_CALL_DEPTH` (128) from
/// `packages/runar-ir-schema/src/input-limits.ts` (N-180). The call depth of a
/// method is 0 if it calls no contract method, else 1 + the largest call depth
/// among the contract methods it calls. Private methods are inlined at every
/// call site, so this is the inlining depth; the validator refuses a method
/// that does not reach a call cycle and sits deeper than this, naming the first
/// such method in declaration order with [`call_depth_message`].
pub const MAX_CALL_DEPTH: usize = 128;

/// The one diagnostic every tier emits for a call chain past [`MAX_CALL_DEPTH`].
pub fn call_depth_message(method: &str) -> String {
    format!(
        "call depth of method '{}' exceeds MAX_CALL_DEPTH (limit={})",
        method, MAX_CALL_DEPTH
    )
}

/// Returned when a source payload exceeds [`MAX_SOURCE_BYTES`] at a public
/// parser entry point. Distinct typed error so callers can distinguish
/// DoS-bound rejection from generic syntax errors.
#[derive(Debug, Clone)]
pub struct SourceSizeExceededError {
    pub limit: usize,
    pub actual: usize,
}

impl fmt::Display for SourceSizeExceededError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source exceeds MAX_SOURCE_BYTES (limit={}, actual={})",
            self.limit, self.actual
        )
    }
}

impl std::error::Error for SourceSizeExceededError {}

/// Returns `Some(SourceSizeExceededError)` if `source.len() > MAX_SOURCE_BYTES`,
/// `None` otherwise.
pub fn assert_source_bytes_under_limit(source: &str) -> Option<SourceSizeExceededError> {
    let n = source.len();
    if n > MAX_SOURCE_BYTES {
        Some(SourceSizeExceededError {
            limit: MAX_SOURCE_BYTES,
            actual: n,
        })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// F-213: source nesting limit
// ---------------------------------------------------------------------------
//
// Mirrors packages/runar-compiler/src/passes/source-limits.ts. A source is
// refused with [`SOURCE_NESTING_MESSAGE`] when (A) the parse-nesting counter
// a parser keeps ([`NestingCounter`]) or (B) the AST nesting of the finished
// tree ([`ast_nesting_violation`]) passes [`MAX_SOURCE_NESTING`].
//
// Rust adds one rule the TS reference does not need: a stack overflow is an
// abort here, and dropping a `Box<Expression>` tree recurses once per level,
// so a parser must never BUILD a tree much deeper than the limit -- not even
// one it is about to refuse. Every loop that wraps the accumulated expression
// in a new node (binary precedence loops, postfix `.x` / `(args)` / `[i]`
// chains) asks [`DepthTracker`] first and refuses once the new node's
// expression depth passes the limit. That is measure (B) evaluated early (an
// expression slot is at statement level >= 0, so its B is at least the depth
// of any node inside it); it adds no refusal (B) would not make, except for an
// over-deep expression a parser parses and then discards.

use super::ast::{ContractNode, Expression, SourceLocation, Statement, TypeNode};
use super::diagnostic::Diagnostic;
use super::parser::ParseResult;

/// Measure (A): the parse-nesting counter. A parser calls [`enter`] on entry
/// to each counted construct (a statement, a full-expression parse, a
/// prefix-unary operand, a nested type argument) and [`exit`] when it leaves.
/// [`enter`] refuses to go past the limit and latches [`exceeded`], so the
/// parser's own recursion never gets deeper than `MAX_SOURCE_NESTING` counted
/// frames; the parser then unwinds by treating the rest of the input as ended.
///
/// [`enter`]: NestingCounter::enter
/// [`exit`]: NestingCounter::exit
/// [`exceeded`]: NestingCounter::exceeded
#[derive(Debug, Default)]
pub struct NestingCounter {
    depth: usize,
    exceeded: bool,
}

impl NestingCounter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enter one counted construct. Returns `false` -- without entering --
    /// when that would pass the limit, or once the limit has been hit.
    pub fn enter(&mut self) -> bool {
        if self.exceeded || self.depth >= MAX_SOURCE_NESTING {
            self.exceeded = true;
            return false;
        }
        self.depth += 1;
        true
    }

    /// Leave a construct entered by a successful [`NestingCounter::enter`].
    pub fn exit(&mut self) {
        self.depth -= 1;
    }

    /// Record a refusal found some other way (a [`DepthTracker`] check).
    pub fn refuse(&mut self) {
        self.exceeded = true;
    }

    /// True once the source has been found too deep.
    pub fn exceeded(&self) -> bool {
        self.exceeded
    }
}

/// Visit the direct sub-expressions of `e` (the children measure (B) counts).
fn for_each_child<'a>(e: &'a Expression, mut f: impl FnMut(&'a Expression) -> bool) -> bool {
    match e {
        Expression::BinaryExpr { left, right, .. } => f(left) || f(right),
        Expression::UnaryExpr { operand, .. }
        | Expression::IncrementExpr { operand, .. }
        | Expression::DecrementExpr { operand, .. } => f(operand),
        Expression::CallExpr { callee, args, .. } => f(callee) || args.iter().any(|a| f(a)),
        Expression::MemberExpr { object, .. } => f(object),
        Expression::TernaryExpr { condition, consequent, alternate } => {
            f(condition) || f(consequent) || f(alternate)
        }
        Expression::IndexAccess { object, index } => f(object) || f(index),
        Expression::ArrayLiteral { elements } => elements.iter().any(|x| f(x)),
        Expression::Identifier { .. }
        | Expression::BigIntLiteral { .. }
        | Expression::BoolLiteral { .. }
        | Expression::ByteStringLiteral { .. }
        | Expression::PropertyAccess { .. } => false,
    }
}

/// True iff some node of `e`, with `e` itself at nesting `level`, is deeper
/// than the limit. Never recurses more than `MAX_SOURCE_NESTING + 1` frames:
/// it stops the moment `level` passes the limit.
fn expr_too_deep(e: &Expression, level: usize) -> bool {
    level > MAX_SOURCE_NESTING || for_each_child(e, |c| expr_too_deep(c, level + 1))
}

/// `exprDepth(e)` (a leaf is 1), or any value above `cap` once it exceeds
/// `cap`. Recursion is bounded by `cap + 1` frames.
pub fn expr_depth_capped(e: &Expression, cap: usize) -> usize {
    let mut depth = 1;
    if cap == 0 {
        return depth;
    }
    for_each_child(e, |c| {
        depth = depth.max(1 + expr_depth_capped(c, cap - 1));
        depth > cap
    });
    depth
}

/// Tracks the expression depth of the value a parser loop keeps wrapping
/// (`left = Binary(left, right)`, `expr = Member(expr)`, ...), so the loop can
/// refuse BEFORE it builds a node deeper than the limit. The accumulated
/// value's depth is computed once and then updated incrementally; each new
/// operand is measured once (bounded by the limit), so a long chain costs
/// linear time.
#[derive(Debug, Default)]
pub struct DepthTracker {
    acc: Option<usize>,
}

impl DepthTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Account for wrapping `acc` (the accumulated value) together with
    /// `others` in one new node. Returns `false` when that node would be
    /// deeper than `MAX_SOURCE_NESTING`; the caller must then not build it.
    pub fn wrap(&mut self, acc: &Expression, others: &[&Expression]) -> bool {
        let cap = MAX_SOURCE_NESTING;
        let mut inner = *self.acc.get_or_insert_with(|| expr_depth_capped(acc, cap));
        for o in others {
            inner = inner.max(expr_depth_capped(o, cap));
        }
        let depth = 1 + inner;
        self.acc = Some(depth);
        depth <= cap
    }
}

/// `typeDepth(t)` > limit (a fixed-array type is one deeper than its element).
pub fn type_too_deep(t: &TypeNode) -> bool {
    let mut depth = 0;
    let mut cur = Some(t);
    while let Some(node) = cur {
        depth += 1;
        if depth > MAX_SOURCE_NESTING {
            return true;
        }
        cur = match node {
            TypeNode::FixedArray { element, .. } => Some(element),
            _ => None,
        };
    }
    false
}

fn stmt_loc(st: &Statement) -> &SourceLocation {
    match st {
        Statement::VariableDecl { source_location, .. }
        | Statement::Assignment { source_location, .. }
        | Statement::IfStatement { source_location, .. }
        | Statement::ForStatement { source_location, .. }
        | Statement::ReturnStatement { source_location, .. }
        | Statement::ExpressionStatement { source_location, .. } => source_location,
    }
}

/// The statement whose subtree breaks the limit, or `None`. Recursion stops
/// once `level` passes the limit.
fn stmts_too_deep(stmts: &[Statement], level: usize) -> Option<&Statement> {
    for st in stmts {
        if level > MAX_SOURCE_NESTING {
            return Some(st);
        }
        let mut slots: Vec<&Expression> = Vec::new();
        let mut nested: Vec<Vec<&Statement>> = Vec::new();
        match st {
            Statement::VariableDecl { var_type, init, .. } => {
                if var_type.as_ref().is_some_and(type_too_deep) {
                    return Some(st);
                }
                slots.push(init);
            }
            Statement::Assignment { target, value, .. } => {
                slots.push(target);
                slots.push(value);
            }
            Statement::ExpressionStatement { expression, .. } => slots.push(expression),
            Statement::ReturnStatement { value, .. } => slots.extend(value.as_ref()),
            Statement::IfStatement { condition, then_branch, else_branch, .. } => {
                slots.push(condition);
                nested.push(then_branch.iter().collect());
                if let Some(e) = else_branch {
                    nested.push(e.iter().collect());
                }
            }
            Statement::ForStatement { init, condition, update, body, .. } => {
                slots.push(condition);
                nested.push(vec![&**init, &**update]);
                nested.push(body.iter().collect());
            }
        }
        if slots.iter().any(|e| expr_too_deep(e, level + 1)) {
            return Some(st);
        }
        for list in nested {
            for s in list {
                if let Some(bad) = stmts_too_deep(std::slice::from_ref(s), level + 1) {
                    return Some(bad);
                }
            }
        }
    }
    None
}

/// Measure (B): AST nesting. `None` when the contract is within the limit,
/// else `Some(location to report)`.
pub fn ast_nesting_violation(contract: &ContractNode) -> Option<Option<SourceLocation>> {
    for p in &contract.properties {
        if type_too_deep(&p.prop_type) || p.initializer.as_ref().is_some_and(|e| expr_too_deep(e, 1)) {
            return Some(Some(p.source_location.clone()));
        }
    }
    for m in std::iter::once(&contract.constructor).chain(contract.methods.iter()) {
        if m.params.iter().any(|p| type_too_deep(&p.param_type)) {
            return Some(Some(m.source_location.clone()));
        }
        if let Some(bad) = stmts_too_deep(&m.body, 1) {
            return Some(Some(stmt_loc(bad).clone()));
        }
    }
    None
}

/// Size of the stack segment every source parser runs on
/// ([`run_on_parse_stack`]). Reserved, not committed: only the pages actually
/// touched cost memory.
///
/// Measured (remediation-logs/F-213/rust/stack-measure.txt): swc parsing a
/// .runar.ts source its depth guard stops at (~512 nested parens, the most
/// stack-hungry shape) uses ~3.5 MB in a release build and ~16 MB in a debug
/// build; a hand-written parser at the limit uses ~1 MB (release) to ~3 MB
/// (debug). 64 MiB leaves a wide margin for both.
pub const PARSE_STACK_BYTES: usize = 64 * 1024 * 1024;

/// Run a parse on a fresh stack segment of [`PARSE_STACK_BYTES`]. The limit
/// bounds every parser's recursion, but a debug build's frames are large
/// enough that a parse at the limit outgrows a 2 MiB thread (the default for
/// spawned threads, where `compile_check` may run); on its own segment the
/// parse no longer depends on the caller's stack.
pub fn run_on_parse_stack<R>(f: impl FnOnce() -> R) -> R {
    stacker::grow(PARSE_STACK_BYTES, f)
}

/// The parse result for an over-nested source: the shared diagnostic alone.
pub fn nesting_refusal(loc: Option<SourceLocation>) -> ParseResult {
    ParseResult {
        contract: None,
        errors: vec![Diagnostic::error(SOURCE_NESTING_MESSAGE, loc)],
        source_size_err: None,
    }
}

/// Apply measure (B) to a finished parse, at the end of every parser entry
/// point: an over-nested contract is dropped and the shared diagnostic is
/// appended to whatever the parser reported.
pub fn enforce_ast_nesting(mut result: ParseResult) -> ParseResult {
    if let Some(contract) = &result.contract {
        if let Some(loc) = ast_nesting_violation(contract) {
            result.contract = None;
            result.errors.push(Diagnostic::error(SOURCE_NESTING_MESSAGE, loc));
        }
    }
    result
}
