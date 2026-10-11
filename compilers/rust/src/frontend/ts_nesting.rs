//! F-213 on the `.runar.ts` surface, which is parsed by swc.
//!
//! The hand-written surfaces count measure (A) inside their own recursive
//! descent. swc cannot be instrumented, its recursion is not bounded, and a
//! stack overflow aborts a Rust process; dropping a deep swc AST recurses as
//! well. So this surface gets three layers:
//!
//! 1. [`GuardedTokens`] wraps the swc lexer. It sees exactly the tokens the
//!    parser consumes (including the parser's own regex / template / `>>`
//!    re-lexing) and keeps an estimate of how deep the AST under construction
//!    is. When the estimate passes [`PRESCAN_LIMIT`], or the stack the parser
//!    runs on is nearly used up, it reports end of input: swc stops with an
//!    "unexpected eof" error, nothing deeper is built, and the caller reports
//!    the shared nesting diagnostic. This is a crash guard, not measure (A);
//!    the argument that it never refuses a source the TS tier accepts is in
//!    the comment on [`Model`].
//! 2. [`parse_nesting_violation`] computes measure (A) exactly as the TS
//!    reference does over its library AST (`tsChildNesting` in
//!    packages/runar-compiler/src/passes/01-parse.ts), by a walk of the swc
//!    AST that stops as soon as the count passes the limit. It is what makes
//!    the .runar.ts boundary (126 nested parens accepted, 127 refused) match
//!    the TS tier.
//! 3. Measure (B) runs on the converted Rúnar AST, as on every surface.
//!
//! The swc parse, the walk, the conversion and the drop of the swc AST all run
//! on a dedicated stack segment
//! ([`run_on_parse_stack`](super::input_limits::run_on_parse_stack)), so the
//! depth that layer 1 lets through fits regardless of the caller's stack (a
//! 2 MiB thread calling `compile_check`, a debug build).

use std::cell::Cell;
use std::rc::Rc;

use swc_common::BytePos;
use swc_ecma_ast as swc;
use swc_ecma_ast::EsVersion;
use swc_ecma_parser::error::Error as SwcError;
use swc_ecma_parser::lexer::TokenContexts;
use swc_ecma_parser::token::{BinOpToken, Keyword, Token, TokenAndSpan, Word};
use swc_ecma_parser::{Context, Syntax, Tokens};

use super::input_limits::MAX_SOURCE_NESTING;

/// The crash-guard bound on the estimated swc AST depth: 4 x
/// `MAX_SOURCE_NESTING`. See [`Model`] for why no source the TS tier accepts
/// comes near it.
pub const PRESCAN_LIMIT: u32 = 4 * MAX_SOURCE_NESTING as u32;

/// The token stream ends once less than this much of the parse stack is left.
/// A backstop for the depth estimate, which does not track recursion-only
/// nesting (prefix operators, keyword-introduced statements, type operators):
/// swc uses only kilobytes between two token fetches, so the parse can never
/// get from above this line to the end of the segment.
const PARSE_STACK_RED_ZONE: usize = 8 * 1024 * 1024;

/// Upper bound on the recursion of the measure-(A) walk. A source the TS tier
/// accepts has an swc AST far shallower than this (see [`Model`]); past it
/// the walk stops and the source is refused rather than walked further.
const WALK_DEPTH_CAP: usize = 8 * MAX_SOURCE_NESTING;

// ---------------------------------------------------------------------------
// Layer 1: the token-stream guard
// ---------------------------------------------------------------------------

/// Binding strength of the operators the depth estimate tracks. Higher binds
/// tighter. Prefix operators are not tracked (they are parsed by recursion,
/// which the stack check bounds, and they never lengthen a loop-built chain).
mod prec {
    pub const ELSE: u8 = 1;
    pub const COMMA: u8 = 2;
    pub const ASSIGN: u8 = 3; // = op= =>
    pub const COND: u8 = 4; // ? :
    pub const NULLISH: u8 = 5;
    pub const OR: u8 = 6;
    pub const AND: u8 = 7;
    pub const BIT_OR: u8 = 8;
    pub const BIT_XOR: u8 = 9;
    pub const BIT_AND: u8 = 10;
    pub const EQUALITY: u8 = 11;
    pub const RELATIONAL: u8 = 12; // < > <= >= in instanceof as satisfies ...
    pub const SHIFT: u8 = 13;
    pub const ADDITIVE: u8 = 14;
    pub const MULTIPLICATIVE: u8 = 15;
    pub const EXPONENT: u8 = 16;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LevelKind {
    /// `(` `[` `{` where an operand is expected: a parenthesised group, an
    /// array or object literal, a block, a template substitution.
    Group,
    /// `(` `[` `{` right after an operand: call arguments, an index, a class
    /// or function body after its header.
    Apply,
    /// The `( ... )` after `if` / `while` / `for` / `switch` / `catch` /
    /// `with`: the statement body follows it.
    Header,
    /// A template literal between its backquotes.
    Template,
    /// A tagged template: like `Template`, applied to the tag before it.
    TaggedTemplate,
}

#[derive(Clone, Copy, Debug)]
enum FrameKind {
    Level { kind: LevelKind, stmt_block: bool, inner_max: u32 },
    Op { prec: u8, right_assoc: bool, max_combine: bool },
    Val { depth: u32 },
}

/// One frame of the persistent (structurally shared) estimator stack. swc
/// clones its token source to parse speculatively, so cloning the guard must
/// be O(1): the stack is an immutable linked list.
#[derive(Debug)]
struct Frame {
    kind: FrameKind,
    /// Level and Op frames at or below this one.
    pending: u32,
    /// The deepest estimated node on the path through any frame at or below
    /// this one.
    hi: u32,
    parent: Option<Rc<Frame>>,
}

type Stack = Option<Rc<Frame>>;

fn push(parent: Stack, kind: FrameKind) -> Stack {
    let (pp, ph) = parent.as_ref().map(|p| (p.pending, p.hi)).unwrap_or((0, 0));
    let (pending, score) = match kind {
        FrameKind::Val { depth } => (pp, depth.saturating_add(pp)),
        _ => (pp + 1, pp + 1),
    };
    Some(Rc::new(Frame { kind, pending, hi: ph.max(score), parent }))
}

/// What the previous significant token was, as far as the estimate cares.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Prev {
    Start,
    Other,
    /// `if` `while` `for` `switch` `catch` `with`: a `(` after it is a header.
    HeaderKeyword,
    /// The `)` that closed a header, or `else` / `do` / `try` / `finally`, or
    /// a statement boundary: a `{` here opens a statement block.
    StatementStart,
    /// `?` (so a following `.` is optional chaining).
    Question,
}

/// The depth estimate the guard keeps over the token stream.
///
/// It is a precedence (shunting-yard) evaluation of the token stream that
/// tracks, for every operand, the depth of the subtree swc will build for it,
/// per bracket level: binary operators reduce by precedence exactly as swc's
/// loop-built binary chains nest; a postfix `.x` / `?.x` / `!` / `(args)` /
/// `[i]` / tagged template adds one level to the operand it follows (swc
/// builds those chains in a loop too); a group adds one level around its
/// content; `=` `?` `:` `=>` `**` and `else` are right-associative, so their
/// chains accumulate (an `else if` chain is right-nested, and swc builds it
/// iteratively). Prefix operators and keywords add nothing (swc parses them by
/// recursion, which the stack check bounds). A statement boundary -- `;`, the
/// `}` of a statement block, or two operands in a row (ASI) -- ends the
/// statement's estimate, except before `else`.
///
/// Why this never refuses a source the TS tier accepts: on such a source
/// every bracket level is a counted construct of measure (A) (a parenthesised
/// group, call arguments, an index, an array literal, a statement block, an
/// if/for header) except the class body and a method's parameter list and
/// body, and every operator chain the estimate accumulates is part of one
/// expression tree whose depth measure (B) bounds (`else` chains are counted
/// by (A); `as` / `satisfies`, which the Rúnar AST drops, add nothing). Along
/// any path, the estimate is therefore at most (A) + (B) + 4 <= 2 x 128 + 4,
/// against a limit of 4 x 128. One construct falls outside that argument: a
/// postfix non-null `x!`, which the Rúnar AST also drops but swc builds in a
/// loop, counts one level -- only a run of hundreds of consecutive `!`
/// assertions could be refused for it.
///
/// Why it bounds what swc builds: every nesting swc creates WITHOUT recursion
/// -- a left-associative binary chain, a postfix / call / index chain, an
/// `else if` chain, a qualified name, an array type `T[][]` -- is an operator
/// chain or a postfix the estimate counts within its bracket level, and a
/// bracket level only ends at the matching close; a statement boundary only
/// ends chains that swc also ends there. Everything swc nests BY recursion is
/// bounded by the stack check.
#[derive(Clone, Debug)]
struct Model {
    top: Stack,
    expect_operand: bool,
    prev: Prev,
    /// After `;` or the `}` of a statement block: end the statement's
    /// estimate unless the next token is `else`.
    pending_stmt_end: bool,
    /// After a postfix `.`: the next word is a member name.
    after_dot: bool,
}

impl Model {
    fn new() -> Self {
        Model { top: None, expect_operand: true, prev: Prev::Start, pending_stmt_end: false, after_dot: false }
    }

    fn estimate(&self) -> u32 {
        self.top.as_ref().map(|f| f.hi).unwrap_or(0)
    }

    fn top_kind(&self) -> Option<FrameKind> {
        self.top.as_ref().map(|f| f.kind)
    }

    fn pop(&mut self) -> Option<FrameKind> {
        let f = self.top.take()?;
        self.top = f.parent.clone();
        Some(f.kind)
    }

    fn push(&mut self, kind: FrameKind) {
        self.top = push(self.top.take(), kind);
    }

    fn push_val(&mut self, depth: u32) {
        self.push(FrameKind::Val { depth });
        self.expect_operand = false;
    }

    /// Add one level to the operand on top (a postfix node around it).
    fn postfix(&mut self) {
        let depth = match self.top_kind() {
            Some(FrameKind::Val { depth }) => {
                self.pop();
                depth
            }
            _ => 1,
        };
        self.push_val(depth.saturating_add(1));
    }

    /// Reduce one `Val Op Val` on top. Returns false when the top is not one.
    fn reduce_once(&mut self) -> bool {
        let Some(top) = self.top.as_ref() else { return false };
        let FrameKind::Val { depth: r } = top.kind else { return false };
        let Some(op_frame) = top.parent.as_ref() else { return false };
        let FrameKind::Op { max_combine, .. } = op_frame.kind else { return false };
        let below = op_frame.parent.clone();
        let (l, rest) = match below.as_ref().map(|f| (f.kind, f.parent.clone())) {
            Some((FrameKind::Val { depth }, rest)) => (depth, rest),
            _ => (1, below),
        };
        self.top = rest;
        let combined = if max_combine { l.max(r) } else { l.max(r).saturating_add(1) };
        self.push_val(combined);
        true
    }

    /// The operator directly under the operand on top, if any.
    fn op_under_top(&self) -> Option<(u8, bool)> {
        let top = self.top.as_ref()?;
        if !matches!(top.kind, FrameKind::Val { .. }) {
            return None;
        }
        match top.parent.as_ref()?.kind {
            FrameKind::Op { prec, right_assoc, .. } => Some((prec, right_assoc)),
            _ => None,
        }
    }

    /// Close the current segment: supply a missing operand, reduce every
    /// operator of the innermost level.
    fn finish_segment(&mut self) {
        if self.expect_operand && matches!(self.top_kind(), Some(FrameKind::Op { .. })) {
            self.push_val(1);
        }
        while self.reduce_once() {}
    }

    /// A `;` ended a statement: reduce its operators, but not the `else`
    /// operators below it -- an `else` after the `;` continues that chain.
    fn finish_statement(&mut self) {
        if self.expect_operand && matches!(self.top_kind(), Some(FrameKind::Op { .. })) {
            self.push_val(1);
        }
        while let Some((top_prec, _)) = self.op_under_top() {
            if top_prec <= prec::ELSE {
                break;
            }
            self.reduce_once();
        }
    }

    fn binop(&mut self, p: u8, right_assoc: bool, max_combine: bool) {
        if self.expect_operand {
            self.push_val(1);
        }
        while let Some((top_prec, _)) = self.op_under_top() {
            if top_prec > p || (top_prec == p && !right_assoc) {
                self.reduce_once();
            } else {
                break;
            }
        }
        self.push(FrameKind::Op { prec: p, right_assoc, max_combine });
        self.expect_operand = true;
    }

    /// A statement ended: fold its estimate into the enclosing level and start
    /// the next statement from an empty operator stack.
    fn end_statement(&mut self) {
        self.finish_segment();
        if let Some(FrameKind::Val { depth }) = self.top_kind() {
            self.pop();
            if let Some(FrameKind::Level { kind, stmt_block, inner_max }) = self.top_kind() {
                self.pop();
                self.push(FrameKind::Level { kind, stmt_block, inner_max: inner_max.max(depth) });
            }
        }
        self.expect_operand = true;
        self.prev = Prev::StatementStart;
    }

    fn open(&mut self, tok: &Token) {
        let kind = if *tok == Token::LParen && self.prev == Prev::HeaderKeyword {
            LevelKind::Header
        } else if self.expect_operand {
            LevelKind::Group
        } else {
            LevelKind::Apply
        };
        let stmt_block = *tok == Token::LBrace
            && kind == LevelKind::Group
            && matches!(self.prev, Prev::Start | Prev::StatementStart);
        self.push(FrameKind::Level { kind, stmt_block, inner_max: 0 });
        self.expect_operand = true;
        self.prev = Prev::Other;
    }

    /// Close the innermost level (any bracket kind: an unbalanced source is a
    /// syntax error swc reports; the estimate only has to stay an estimate).
    fn close(&mut self) {
        if !self.has_level() {
            return;
        }
        self.finish_segment();
        let mut inner = 0;
        if let Some(FrameKind::Val { depth }) = self.top_kind() {
            self.pop();
            inner = depth;
        }
        let Some(FrameKind::Level { kind, stmt_block, inner_max }) = self.pop() else { return };
        let inner = inner.max(inner_max);
        match kind {
            // Opened where an operand was expected: the group is that operand.
            LevelKind::Group | LevelKind::Template => {
                self.push_val(inner.saturating_add(1));
                self.prev = Prev::Other;
            }
            // Opened right after an operand: one node around it.
            LevelKind::Apply | LevelKind::TaggedTemplate => {
                let depth = match self.top_kind() {
                    Some(FrameKind::Val { depth }) => {
                        self.pop();
                        depth
                    }
                    _ => 1,
                };
                self.push_val(depth.max(inner).saturating_add(1));
                self.prev = Prev::Other;
            }
            LevelKind::Header => {
                self.expect_operand = true;
                self.prev = Prev::StatementStart;
            }
        }
        if stmt_block {
            self.pending_stmt_end = true;
        }
    }

    fn has_level(&self) -> bool {
        let mut probe = self.top.as_ref();
        while let Some(f) = probe {
            if matches!(f.kind, FrameKind::Level { .. }) {
                return true;
            }
            probe = f.parent.as_ref();
        }
        false
    }

    fn innermost_level_kind(&self) -> Option<LevelKind> {
        let mut probe = self.top.as_ref();
        while let Some(f) = probe {
            if let FrameKind::Level { kind, .. } = f.kind {
                return Some(kind);
            }
            probe = f.parent.as_ref();
        }
        None
    }

    /// An operand token.
    fn operand(&mut self) {
        if !self.expect_operand {
            self.end_statement();
        }
        self.push_val(1);
        self.prev = Prev::Other;
    }

    fn feed(&mut self, t: &TokenAndSpan) {
        let tok = &t.token;
        if self.pending_stmt_end {
            self.pending_stmt_end = false;
            if !matches!(tok, Token::Word(Word::Keyword(Keyword::Else))) {
                self.end_statement();
            }
        }
        if self.after_dot {
            self.after_dot = false;
            match tok {
                Token::Word(_) => {
                    self.prev = Prev::Other;
                    return;
                }
                Token::Hash => {
                    self.after_dot = true;
                    return;
                }
                _ => {}
            }
        }
        let was_question = self.prev == Prev::Question;
        match tok {
            Token::DollarLBrace => {
                // A substitution inside a template: its value is one more
                // element of the template (a flat list in swc), not an
                // operand the previous substitution applies to.
                if matches!(self.top_kind(), Some(FrameKind::Val { .. })) {
                    self.end_statement();
                }
                self.open(tok);
            }
            Token::LParen | Token::LBracket | Token::LBrace => self.open(tok),
            Token::RParen | Token::RBracket | Token::RBrace => self.close(),
            Token::BackQuote => {
                if matches!(self.innermost_level_kind(), Some(LevelKind::Template | LevelKind::TaggedTemplate)) {
                    self.close();
                } else {
                    let kind = if self.expect_operand { LevelKind::Template } else { LevelKind::TaggedTemplate };
                    self.push(FrameKind::Level { kind, stmt_block: false, inner_max: 0 });
                    self.expect_operand = true;
                    self.prev = Prev::Other;
                }
            }
            Token::Template { .. } => {}
            Token::Semi => {
                // The statement ends, but an `else` may still follow and
                // attach to an open `if`: keep the pending `else` chain.
                self.finish_statement();
                self.pending_stmt_end = true;
                self.prev = Prev::StatementStart;
            }
            Token::Comma => {
                self.binop(prec::COMMA, false, true);
                self.prev = Prev::Other;
            }
            Token::Dot => {
                if self.expect_operand && was_question {
                    // `?.`: the `?` just pushed was optional chaining.
                    if matches!(self.top_kind(), Some(FrameKind::Op { prec: prec::COND, .. })) {
                        self.pop();
                        self.expect_operand = false;
                    }
                }
                if !self.expect_operand {
                    self.postfix();
                }
                self.after_dot = true;
                self.prev = Prev::Other;
            }
            Token::QuestionMark => {
                self.binop(prec::COND, true, false);
                self.prev = Prev::Question;
            }
            Token::Colon => {
                self.binop(prec::COND, true, false);
                self.prev = Prev::Other;
            }
            Token::Arrow | Token::AssignOp(_) => {
                self.binop(prec::ASSIGN, true, false);
                self.prev = Prev::Other;
            }
            Token::BinOp(op) => {
                let prefix_capable = matches!(op, BinOpToken::Add | BinOpToken::Sub);
                if !(self.expect_operand && prefix_capable) {
                    let (p, right) = binop_prec(*op);
                    self.binop(p, right, false);
                }
                self.prev = Prev::Other;
            }
            Token::Bang | Token::PlusPlus | Token::MinusMinus => {
                if !self.expect_operand && !t.had_line_break {
                    // Postfix: TS non-null `!`, `x++`, `x--`.
                    self.postfix();
                } else if !self.expect_operand {
                    // After a line break this starts a new statement (ASI).
                    self.end_statement();
                }
                self.prev = Prev::Other;
            }
            Token::Tilde | Token::DotDotDot | Token::At | Token::Hash => {
                if !self.expect_operand {
                    self.end_statement();
                }
                self.prev = Prev::Other;
            }
            Token::Word(Word::Keyword(kw)) => self.keyword(*kw),
            Token::Word(Word::Ident(ident)) => {
                let text: &str = match ident {
                    swc_ecma_parser::token::IdentLike::Known(k) => (*k).into(),
                    swc_ecma_parser::token::IdentLike::Other(a) => a.as_ref(),
                };
                let binary_word = matches!(text, "as" | "satisfies" | "is" | "implements" | "of" | "asserts");
                if !self.expect_operand && !t.had_line_break && binary_word {
                    // `x as T` / `x satisfies T`: the Rúnar AST drops the
                    // assertion, so it must not count toward the estimate
                    // (a type-asserted chain the TS tier accepts would
                    // otherwise be refused); swc builds it by recursion, which
                    // the stack check bounds. It still binds like a relational
                    // operator, so a chain continues across it.
                    let wrapper = matches!(text, "as" | "satisfies");
                    self.binop(prec::RELATIONAL, false, wrapper);
                    self.prev = Prev::Other;
                } else {
                    self.operand();
                }
            }
            Token::Word(_)
            | Token::Str { .. }
            | Token::Num { .. }
            | Token::BigInt { .. }
            | Token::Regex(..)
            | Token::JSXName { .. }
            | Token::JSXText { .. }
            | Token::JSXTagStart
            | Token::JSXTagEnd
            | Token::Shebang(_)
            | Token::Error(_) => self.operand(),
        }
    }

    fn keyword(&mut self, kw: Keyword) {
        match kw {
            Keyword::This | Keyword::Super => self.operand(),
            Keyword::In | Keyword::InstanceOf | Keyword::Extends => {
                self.binop(prec::RELATIONAL, false, false);
                self.prev = Prev::Other;
            }
            Keyword::Else => {
                self.binop(prec::ELSE, true, false);
                self.prev = Prev::StatementStart;
            }
            _ => {
                if !self.expect_operand {
                    self.end_statement();
                }
                self.expect_operand = true;
                self.prev = match kw {
                    Keyword::If | Keyword::While | Keyword::For | Keyword::Switch | Keyword::Catch | Keyword::With => {
                        Prev::HeaderKeyword
                    }
                    Keyword::Do | Keyword::Try | Keyword::Finally => Prev::StatementStart,
                    _ => Prev::Other,
                };
            }
        }
    }
}

fn binop_prec(op: BinOpToken) -> (u8, bool) {
    use BinOpToken::*;
    match op {
        EqEq | NotEq | EqEqEq | NotEqEq => (prec::EQUALITY, false),
        Lt | LtEq | Gt | GtEq => (prec::RELATIONAL, false),
        LShift | RShift | ZeroFillRShift => (prec::SHIFT, false),
        Add | Sub => (prec::ADDITIVE, false),
        Mul | Div | Mod => (prec::MULTIPLICATIVE, false),
        BitOr => (prec::BIT_OR, false),
        BitXor => (prec::BIT_XOR, false),
        BitAnd => (prec::BIT_AND, false),
        Exp => (prec::EXPONENT, true),
        LogicalOr => (prec::OR, false),
        LogicalAnd => (prec::AND, false),
        NullishCoalescing => (prec::NULLISH, false),
    }
}

/// The swc lexer, with the F-213 depth estimate and stack check in front of
/// the parser (see the module docs). Once either trips, it reports end of
/// input forever and sets the shared `tripped` flag.
#[derive(Clone)]
pub struct GuardedTokens<I: Tokens> {
    inner: I,
    model: Model,
    tripped: Rc<Cell<bool>>,
}

impl<I: Tokens> GuardedTokens<I> {
    pub fn new(inner: I) -> Self {
        GuardedTokens { inner, model: Model::new(), tripped: Rc::new(Cell::new(false)) }
    }

    /// Shared flag: true once the guard cut the input (the source is too
    /// deep). Survives the parser's speculative clones.
    pub fn tripped_flag(&self) -> Rc<Cell<bool>> {
        self.tripped.clone()
    }
}

impl<I: Tokens> Iterator for GuardedTokens<I> {
    type Item = TokenAndSpan;

    fn next(&mut self) -> Option<TokenAndSpan> {
        if self.tripped.get() {
            return None;
        }
        if stacker::remaining_stack().is_some_and(|r| r < PARSE_STACK_RED_ZONE) {
            self.tripped.set(true);
            return None;
        }
        let t = self.inner.next()?;
        self.model.feed(&t);
        if self.model.estimate() > PRESCAN_LIMIT {
            self.tripped.set(true);
            return None;
        }
        Some(t)
    }
}

impl<I: Tokens> Tokens for GuardedTokens<I> {
    fn set_ctx(&mut self, ctx: Context) {
        self.inner.set_ctx(ctx)
    }
    fn ctx(&self) -> Context {
        self.inner.ctx()
    }
    fn syntax(&self) -> Syntax {
        self.inner.syntax()
    }
    fn target(&self) -> EsVersion {
        self.inner.target()
    }
    fn start_pos(&self) -> BytePos {
        self.inner.start_pos()
    }
    fn set_expr_allowed(&mut self, allow: bool) {
        self.inner.set_expr_allowed(allow)
    }
    fn set_next_regexp(&mut self, start: Option<BytePos>) {
        self.inner.set_next_regexp(start)
    }
    fn token_context(&self) -> &TokenContexts {
        self.inner.token_context()
    }
    fn token_context_mut(&mut self) -> &mut TokenContexts {
        self.inner.token_context_mut()
    }
    fn set_token_context(&mut self, c: TokenContexts) {
        self.inner.set_token_context(c)
    }
    fn add_error(&self, error: SwcError) {
        self.inner.add_error(error)
    }
    fn add_module_mode_error(&self, error: SwcError) {
        self.inner.add_module_mode_error(error)
    }
    fn end_pos(&self) -> BytePos {
        self.inner.end_pos()
    }
    fn take_errors(&mut self) -> Vec<SwcError> {
        self.inner.take_errors()
    }
}

// ---------------------------------------------------------------------------
// Layer 2: measure (A) over the swc AST
// ---------------------------------------------------------------------------

/// Measure (A) for the .runar.ts surface: the counter the hand-written
/// surfaces keep, recomputed over the swc AST with the TS reference's
/// `tsChildNesting` rules -- +1 for a statement inside a body (a block is free
/// unless it is itself a statement of a block), each expression slot of a
/// statement / declaration / property / parameter initializer, a
/// parenthesised group, a call or `new` argument, an index, an array element,
/// a ternary arm, a prefix `!` `-` `+` `~` `++` `--` operand, and a type
/// argument of a type reference; +0 for everything else. Returns the span of
/// the first node past the limit (or past the walk's own depth cap).
pub fn parse_nesting_violation(module: &swc::Module) -> Option<swc_common::Span> {
    let mut w = Walk { depth: 0, hit: None };
    for item in &module.body {
        let stop = match item {
            swc::ModuleItem::Stmt(s) => w.stmt(s, 0),
            swc::ModuleItem::ModuleDecl(d) => w.module_decl(d, 0),
        };
        if stop {
            break;
        }
    }
    w.hit
}

struct Walk {
    depth: usize,
    hit: Option<swc_common::Span>,
}

macro_rules! guard {
    ($w:expr, $level:expr, $span:expr) => {
        if $level > MAX_SOURCE_NESTING || $w.depth >= WALK_DEPTH_CAP {
            $w.hit = Some($span);
            return true;
        }
    };
}

impl Walk {
    fn enter(&mut self) {
        self.depth += 1;
    }
    fn leave(&mut self) {
        self.depth -= 1;
    }

    fn module_decl(&mut self, d: &swc::ModuleDecl, level: usize) -> bool {
        use swc_common::Spanned;
        guard!(self, level, d.span());
        self.enter();
        let stop = match d {
            swc::ModuleDecl::ExportDecl(e) => self.decl(&e.decl, level),
            swc::ModuleDecl::ExportDefaultDecl(e) => match &e.decl {
                swc::DefaultDecl::Class(c) => self.class(&c.class, level),
                swc::DefaultDecl::Fn(f) => self.function(&f.function, level),
                swc::DefaultDecl::TsInterfaceDecl(i) => self.type_elements(&i.body.body, level),
            },
            swc::ModuleDecl::ExportDefaultExpr(e) => self.expr(&e.expr, level),
            swc::ModuleDecl::TsExportAssignment(e) => self.expr(&e.expr, level),
            _ => false,
        };
        self.leave();
        stop
    }

    /// Statements of a block at `level`: each is one level deeper.
    fn stmts(&mut self, stmts: &[swc::Stmt], level: usize) -> bool {
        stmts.iter().any(|s| self.child_stmt(s, level))
    }

    /// A statement whose parent (a block or a statement) is at `level`. Only
    /// a variable statement counts as a statement for the TS reference: a
    /// class / function / type declaration nested in a block stays at the
    /// parent's level.
    fn child_stmt(&mut self, s: &swc::Stmt, level: usize) -> bool {
        match s {
            swc::Stmt::Decl(d) if !matches!(d, swc::Decl::Var(_) | swc::Decl::Using(_)) => self.decl(d, level),
            other => self.stmt(other, level + 1),
        }
    }

    /// The body statement of a statement at `level`: a block is free (its
    /// statements are at `level + 1`); any other statement is a child.
    fn body(&mut self, s: &swc::Stmt, level: usize) -> bool {
        match s {
            swc::Stmt::Block(b) => self.stmts(&b.stmts, level),
            other => self.child_stmt(other, level),
        }
    }

    fn stmt(&mut self, s: &swc::Stmt, level: usize) -> bool {
        use swc_common::Spanned;
        guard!(self, level, s.span());
        self.enter();
        let stop = match s {
            swc::Stmt::Block(b) => self.stmts(&b.stmts, level),
            swc::Stmt::Expr(e) => self.expr(&e.expr, level + 1),
            swc::Stmt::If(i) => {
                self.expr(&i.test, level + 1)
                    || self.body(&i.cons, level)
                    || i.alt.as_ref().is_some_and(|a| self.body(a, level))
            }
            swc::Stmt::Return(r) => r.arg.as_ref().is_some_and(|a| self.expr(a, level + 1)),
            swc::Stmt::Throw(t) => self.expr(&t.arg, level + 1),
            swc::Stmt::While(wh) => self.expr(&wh.test, level + 1) || self.body(&wh.body, level),
            swc::Stmt::DoWhile(d) => self.body(&d.body, level) || self.expr(&d.test, level + 1),
            swc::Stmt::Switch(sw) => {
                // Case clauses are not statements: their statements stay at
                // the switch's level (the TS reference walks it that way).
                self.expr(&sw.discriminant, level + 1)
                    || sw.cases.iter().any(|c| {
                        c.test.as_ref().is_some_and(|t| self.expr(t, level))
                            || c.cons.iter().any(|st| self.stmt(st, level))
                    })
            }
            swc::Stmt::For(f) => {
                let init = match &f.init {
                    Some(swc::VarDeclOrExpr::VarDecl(v)) => self.var_decl(v, level),
                    Some(swc::VarDeclOrExpr::Expr(e)) => self.expr(e, level + 1),
                    None => false,
                };
                init || f.test.as_ref().is_some_and(|t| self.expr(t, level + 1))
                    || f.update.as_ref().is_some_and(|u| self.expr(u, level + 1))
                    || self.body(&f.body, level)
            }
            swc::Stmt::ForIn(f) => self.for_head(&f.left, level) || self.expr(&f.right, level) || self.body(&f.body, level),
            swc::Stmt::ForOf(f) => self.for_head(&f.left, level) || self.expr(&f.right, level) || self.body(&f.body, level),
            swc::Stmt::Labeled(l) => self.body(&l.body, level),
            swc::Stmt::With(wi) => self.expr(&wi.obj, level) || self.body(&wi.body, level),
            swc::Stmt::Try(t) => {
                self.stmts(&t.block.stmts, level)
                    || t.handler.as_ref().is_some_and(|h| {
                        h.param.as_ref().is_some_and(|p| self.pat(p, level)) || self.stmts(&h.body.stmts, level)
                    })
                    || t.finalizer.as_ref().is_some_and(|f| self.stmts(&f.stmts, level))
            }
            swc::Stmt::Decl(d) => self.decl(d, level),
            swc::Stmt::Empty(_) | swc::Stmt::Debugger(_) | swc::Stmt::Break(_) | swc::Stmt::Continue(_) => false,
        };
        self.leave();
        stop
    }

    fn decl(&mut self, d: &swc::Decl, level: usize) -> bool {
        match d {
            swc::Decl::Class(c) => self.class(&c.class, level),
            swc::Decl::Fn(f) => self.function(&f.function, level),
            swc::Decl::Var(v) => self.var_decl(v, level),
            swc::Decl::Using(u) => u.decls.iter().any(|v| self.declarator(v, level)),
            swc::Decl::TsInterface(i) => self.type_elements(&i.body.body, level),
            swc::Decl::TsTypeAlias(a) => self.ty(&a.type_ann, level),
            swc::Decl::TsEnum(e) => e.members.iter().any(|m| m.init.as_ref().is_some_and(|i| self.expr(i, level))),
            swc::Decl::TsModule(m) => match &m.body {
                Some(swc::TsNamespaceBody::TsModuleBlock(b)) => b.body.iter().any(|item| match item {
                    swc::ModuleItem::Stmt(s) => self.stmt(s, level),
                    swc::ModuleItem::ModuleDecl(md) => self.module_decl(md, level),
                }),
                _ => false,
            },
        }
    }

    fn var_decl(&mut self, v: &swc::VarDecl, level: usize) -> bool {
        v.decls.iter().any(|d| self.declarator(d, level))
    }

    fn declarator(&mut self, d: &swc::VarDeclarator, level: usize) -> bool {
        self.pat(&d.name, level) || d.init.as_ref().is_some_and(|i| self.expr(i, level + 1))
    }

    fn for_head(&mut self, h: &swc::ForHead, level: usize) -> bool {
        match h {
            swc::ForHead::VarDecl(v) => self.var_decl(v, level),
            swc::ForHead::UsingDecl(u) => u.decls.iter().any(|d| self.declarator(d, level)),
            swc::ForHead::Pat(p) => self.pat(p, level),
        }
    }

    fn class(&mut self, c: &swc::Class, level: usize) -> bool {
        if c.decorators.iter().any(|d| self.expr(&d.expr, level)) {
            return true;
        }
        if c.super_class.as_ref().is_some_and(|s| self.expr(s, level)) {
            return true;
        }
        if c.super_type_params.as_ref().is_some_and(|t| t.params.iter().any(|p| self.ty(p, level))) {
            return true;
        }
        c.body.iter().any(|m| match m {
            swc::ClassMember::Constructor(k) => {
                k.params.iter().any(|p| match p {
                    swc::ParamOrTsParamProp::Param(p) => self.param(p, level),
                    swc::ParamOrTsParamProp::TsParamProp(tp) => match &tp.param {
                        swc::TsParamPropParam::Ident(i) => self.binding_ident(i, level),
                        swc::TsParamPropParam::Assign(a) => self.pat(&a.left, level) || self.expr(&a.right, level + 1),
                    },
                }) || k.body.as_ref().is_some_and(|b| self.stmts(&b.stmts, level))
            }
            swc::ClassMember::Method(m) => self.prop_name(&m.key, level) || self.function(&m.function, level),
            swc::ClassMember::PrivateMethod(m) => self.function(&m.function, level),
            swc::ClassMember::ClassProp(p) => {
                self.prop_name(&p.key, level)
                    || p.decorators.iter().any(|d| self.expr(&d.expr, level))
                    || p.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level))
                    || p.value.as_ref().is_some_and(|v| self.expr(v, level + 1))
            }
            swc::ClassMember::PrivateProp(p) => {
                p.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level))
                    || p.value.as_ref().is_some_and(|v| self.expr(v, level + 1))
            }
            swc::ClassMember::AutoAccessor(p) => {
                p.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level))
                    || p.value.as_ref().is_some_and(|v| self.expr(v, level + 1))
            }
            swc::ClassMember::TsIndexSignature(s) => s.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level)),
            swc::ClassMember::StaticBlock(b) => self.stmts(&b.body.stmts, level),
            swc::ClassMember::Empty(_) => false,
        })
    }

    fn prop_name(&mut self, k: &swc::PropName, level: usize) -> bool {
        match k {
            swc::PropName::Computed(c) => self.expr(&c.expr, level),
            _ => false,
        }
    }

    fn function(&mut self, f: &swc::Function, level: usize) -> bool {
        f.decorators.iter().any(|d| self.expr(&d.expr, level))
            || f.params.iter().any(|p| self.param(p, level))
            || f.return_type.as_ref().is_some_and(|t| self.ty(&t.type_ann, level))
            || f.body.as_ref().is_some_and(|b| self.stmts(&b.stmts, level))
    }

    /// A parameter: its initializer (`x = e`) is one level deeper.
    fn param(&mut self, p: &swc::Param, level: usize) -> bool {
        p.decorators.iter().any(|d| self.expr(&d.expr, level)) || self.param_pat(&p.pat, level)
    }

    fn param_pat(&mut self, p: &swc::Pat, level: usize) -> bool {
        match p {
            swc::Pat::Assign(a) => self.pat(&a.left, level) || self.expr(&a.right, level + 1),
            other => self.pat(other, level),
        }
    }

    fn binding_ident(&mut self, b: &swc::BindingIdent, level: usize) -> bool {
        b.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level))
    }

    fn pat(&mut self, p: &swc::Pat, level: usize) -> bool {
        use swc_common::Spanned;
        guard!(self, level, p.span());
        self.enter();
        let stop = match p {
            swc::Pat::Ident(b) => self.binding_ident(b, level),
            swc::Pat::Array(a) => {
                a.elems.iter().flatten().any(|e| self.pat(e, level))
                    || a.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level))
            }
            swc::Pat::Object(o) => {
                o.props.iter().any(|prop| match prop {
                    swc::ObjectPatProp::KeyValue(kv) => self.prop_name(&kv.key, level) || self.pat(&kv.value, level),
                    swc::ObjectPatProp::Assign(a) => a.value.as_ref().is_some_and(|v| self.expr(v, level)),
                    swc::ObjectPatProp::Rest(r) => self.pat(&r.arg, level),
                }) || o.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level))
            }
            swc::Pat::Rest(r) => self.pat(&r.arg, level) || r.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level)),
            swc::Pat::Assign(a) => self.pat(&a.left, level) || self.expr(&a.right, level),
            swc::Pat::Expr(e) => self.expr(e, level),
            swc::Pat::Invalid(_) => false,
        };
        self.leave();
        stop
    }

    fn args(&mut self, args: &[swc::ExprOrSpread], level: usize) -> bool {
        args.iter().any(|a| self.expr(&a.expr, level + 1))
    }

    fn type_args(&mut self, t: &Option<Box<swc::TsTypeParamInstantiation>>, level: usize) -> bool {
        t.as_ref().is_some_and(|t| t.params.iter().any(|p| self.ty(p, level)))
    }

    fn member_prop(&mut self, p: &swc::MemberProp, level: usize) -> bool {
        match p {
            swc::MemberProp::Computed(c) => self.expr(&c.expr, level + 1),
            _ => false,
        }
    }

    fn expr(&mut self, e: &swc::Expr, level: usize) -> bool {
        use swc_common::Spanned;
        guard!(self, level, e.span());
        self.enter();
        let stop = match e {
            swc::Expr::Paren(p) => self.expr(&p.expr, level + 1),
            swc::Expr::Unary(u) => {
                let counted = !matches!(u.op, swc::UnaryOp::TypeOf | swc::UnaryOp::Void | swc::UnaryOp::Delete);
                self.expr(&u.arg, if counted { level + 1 } else { level })
            }
            swc::Expr::Update(u) => self.expr(&u.arg, if u.prefix { level + 1 } else { level }),
            swc::Expr::Array(a) => a.elems.iter().flatten().any(|el| self.expr(&el.expr, level + 1)),
            swc::Expr::Call(c) => {
                let callee = match &c.callee {
                    swc::Callee::Expr(x) => self.expr(x, level),
                    _ => false,
                };
                callee || self.type_args(&c.type_args, level) || self.args(&c.args, level)
            }
            swc::Expr::New(n) => {
                self.expr(&n.callee, level)
                    || self.type_args(&n.type_args, level)
                    || n.args.as_ref().is_some_and(|a| self.args(a, level))
            }
            swc::Expr::Member(m) => self.expr(&m.obj, level) || self.member_prop(&m.prop, level),
            swc::Expr::SuperProp(s) => match &s.prop {
                swc::SuperProp::Computed(c) => self.expr(&c.expr, level + 1),
                _ => false,
            },
            swc::Expr::OptChain(o) => match &*o.base {
                swc::OptChainBase::Member(m) => self.expr(&m.obj, level) || self.member_prop(&m.prop, level),
                swc::OptChainBase::Call(c) => {
                    self.expr(&c.callee, level) || self.type_args(&c.type_args, level) || self.args(&c.args, level)
                }
            },
            swc::Expr::Cond(c) => {
                self.expr(&c.test, level) || self.expr(&c.cons, level + 1) || self.expr(&c.alt, level + 1)
            }
            swc::Expr::Bin(b) => self.expr(&b.left, level) || self.expr(&b.right, level),
            swc::Expr::Assign(a) => {
                let left = match &a.left {
                    swc::AssignTarget::Simple(s) => self.simple_target(s, level),
                    swc::AssignTarget::Pat(p) => match p {
                        swc::AssignTargetPat::Array(ap) => ap.elems.iter().flatten().any(|el| self.pat(el, level)),
                        swc::AssignTargetPat::Object(op) => op.props.iter().any(|prop| match prop {
                            swc::ObjectPatProp::KeyValue(kv) => self.pat(&kv.value, level),
                            swc::ObjectPatProp::Assign(asg) => asg.value.as_ref().is_some_and(|v| self.expr(v, level)),
                            swc::ObjectPatProp::Rest(r) => self.pat(&r.arg, level),
                        }),
                        swc::AssignTargetPat::Invalid(_) => false,
                    },
                };
                left || self.expr(&a.right, level)
            }
            swc::Expr::Seq(s) => s.exprs.iter().any(|x| self.expr(x, level)),
            swc::Expr::Tpl(t) => t.exprs.iter().any(|x| self.expr(x, level)),
            swc::Expr::TaggedTpl(t) => {
                self.expr(&t.tag, level)
                    || self.type_args(&t.type_params, level)
                    || t.tpl.exprs.iter().any(|x| self.expr(x, level))
            }
            swc::Expr::Arrow(a) => {
                a.params.iter().any(|p| self.param_pat(p, level))
                    || a.return_type.as_ref().is_some_and(|t| self.ty(&t.type_ann, level))
                    || match &*a.body {
                        swc::BlockStmtOrExpr::BlockStmt(b) => self.stmts(&b.stmts, level),
                        swc::BlockStmtOrExpr::Expr(x) => self.expr(x, level),
                    }
            }
            swc::Expr::Fn(f) => self.function(&f.function, level),
            swc::Expr::Class(c) => self.class(&c.class, level),
            swc::Expr::Object(o) => o.props.iter().any(|p| match p {
                swc::PropOrSpread::Spread(s) => self.expr(&s.expr, level),
                swc::PropOrSpread::Prop(p) => match &**p {
                    swc::Prop::KeyValue(kv) => self.prop_name(&kv.key, level) || self.expr(&kv.value, level),
                    swc::Prop::Assign(a) => self.expr(&a.value, level),
                    swc::Prop::Getter(g) => {
                        self.prop_name(&g.key, level) || g.body.as_ref().is_some_and(|b| self.stmts(&b.stmts, level))
                    }
                    swc::Prop::Setter(s) => {
                        self.prop_name(&s.key, level)
                            || self.param_pat(&s.param, level)
                            || s.body.as_ref().is_some_and(|b| self.stmts(&b.stmts, level))
                    }
                    swc::Prop::Method(m) => self.prop_name(&m.key, level) || self.function(&m.function, level),
                    swc::Prop::Shorthand(_) => false,
                },
            }),
            swc::Expr::Yield(y) => y.arg.as_ref().is_some_and(|a| self.expr(a, level)),
            swc::Expr::Await(a) => self.expr(&a.arg, level),
            swc::Expr::TsTypeAssertion(t) => self.ty(&t.type_ann, level) || self.expr(&t.expr, level),
            swc::Expr::TsConstAssertion(t) => self.expr(&t.expr, level),
            swc::Expr::TsNonNull(t) => self.expr(&t.expr, level),
            swc::Expr::TsAs(t) => self.expr(&t.expr, level) || self.ty(&t.type_ann, level),
            swc::Expr::TsSatisfies(t) => self.expr(&t.expr, level) || self.ty(&t.type_ann, level),
            swc::Expr::TsInstantiation(t) => {
                self.expr(&t.expr, level) || t.type_args.params.iter().any(|p| self.ty(p, level))
            }
            swc::Expr::This(_)
            | swc::Expr::Ident(_)
            | swc::Expr::Lit(_)
            | swc::Expr::MetaProp(_)
            | swc::Expr::PrivateName(_)
            | swc::Expr::Invalid(_)
            | swc::Expr::JSXMember(_)
            | swc::Expr::JSXNamespacedName(_)
            | swc::Expr::JSXEmpty(_)
            | swc::Expr::JSXElement(_)
            | swc::Expr::JSXFragment(_) => false,
        };
        self.leave();
        stop
    }

    fn simple_target(&mut self, s: &swc::SimpleAssignTarget, level: usize) -> bool {
        match s {
            swc::SimpleAssignTarget::Ident(b) => self.binding_ident(b, level),
            swc::SimpleAssignTarget::Member(m) => self.expr(&m.obj, level) || self.member_prop(&m.prop, level),
            swc::SimpleAssignTarget::SuperProp(sp) => match &sp.prop {
                swc::SuperProp::Computed(c) => self.expr(&c.expr, level + 1),
                _ => false,
            },
            swc::SimpleAssignTarget::Paren(p) => self.expr(&p.expr, level + 1),
            swc::SimpleAssignTarget::OptChain(o) => match &*o.base {
                swc::OptChainBase::Member(m) => self.expr(&m.obj, level) || self.member_prop(&m.prop, level),
                swc::OptChainBase::Call(c) => self.expr(&c.callee, level) || self.args(&c.args, level),
            },
            swc::SimpleAssignTarget::TsAs(t) => self.expr(&t.expr, level) || self.ty(&t.type_ann, level),
            swc::SimpleAssignTarget::TsSatisfies(t) => self.expr(&t.expr, level) || self.ty(&t.type_ann, level),
            swc::SimpleAssignTarget::TsNonNull(t) => self.expr(&t.expr, level),
            swc::SimpleAssignTarget::TsTypeAssertion(t) => self.ty(&t.type_ann, level) || self.expr(&t.expr, level),
            swc::SimpleAssignTarget::TsInstantiation(t) => {
                self.expr(&t.expr, level) || t.type_args.params.iter().any(|p| self.ty(p, level))
            }
            swc::SimpleAssignTarget::Invalid(_) => false,
        }
    }

    fn fn_params(&mut self, params: &[swc::TsFnParam], level: usize) -> bool {
        params.iter().any(|p| match p {
            swc::TsFnParam::Ident(b) => self.binding_ident(b, level),
            swc::TsFnParam::Array(a) => a.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level)),
            swc::TsFnParam::Rest(r) => r.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level)),
            swc::TsFnParam::Object(o) => o.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level)),
        })
    }

    fn type_elements(&mut self, members: &[swc::TsTypeElement], level: usize) -> bool {
        members.iter().any(|m| match m {
            swc::TsTypeElement::TsPropertySignature(p) => p.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level)),
            swc::TsTypeElement::TsMethodSignature(p) => {
                self.fn_params(&p.params, level) || p.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level))
            }
            swc::TsTypeElement::TsCallSignatureDecl(p) => {
                self.fn_params(&p.params, level) || p.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level))
            }
            swc::TsTypeElement::TsConstructSignatureDecl(p) => {
                self.fn_params(&p.params, level) || p.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level))
            }
            swc::TsTypeElement::TsGetterSignature(p) => p.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level)),
            swc::TsTypeElement::TsSetterSignature(p) => self.fn_params(std::slice::from_ref(&p.param), level),
            swc::TsTypeElement::TsIndexSignature(p) => {
                self.fn_params(&p.params, level) || p.type_ann.as_ref().is_some_and(|t| self.ty(&t.type_ann, level))
            }
        })
    }

    fn ty(&mut self, t: &swc::TsType, level: usize) -> bool {
        use swc_common::Spanned;
        guard!(self, level, t.span());
        self.enter();
        let stop = match t {
            // The one counted type position: a type reference's arguments.
            swc::TsType::TsTypeRef(r) => {
                r.type_params.as_ref().is_some_and(|tp| tp.params.iter().any(|p| self.ty(p, level + 1)))
            }
            swc::TsType::TsArrayType(a) => self.ty(&a.elem_type, level),
            swc::TsType::TsTupleType(tt) => tt.elem_types.iter().any(|el| self.ty(&el.ty, level)),
            swc::TsType::TsOptionalType(o) => self.ty(&o.type_ann, level),
            swc::TsType::TsRestType(r) => self.ty(&r.type_ann, level),
            swc::TsType::TsUnionOrIntersectionType(u) => match u {
                swc::TsUnionOrIntersectionType::TsUnionType(x) => x.types.iter().any(|y| self.ty(y, level)),
                swc::TsUnionOrIntersectionType::TsIntersectionType(x) => x.types.iter().any(|y| self.ty(y, level)),
            },
            swc::TsType::TsConditionalType(c) => {
                self.ty(&c.check_type, level)
                    || self.ty(&c.extends_type, level)
                    || self.ty(&c.true_type, level)
                    || self.ty(&c.false_type, level)
            }
            swc::TsType::TsParenthesizedType(p) => self.ty(&p.type_ann, level),
            swc::TsType::TsTypeOperator(o) => self.ty(&o.type_ann, level),
            swc::TsType::TsIndexedAccessType(i) => self.ty(&i.obj_type, level) || self.ty(&i.index_type, level),
            swc::TsType::TsMappedType(m) => {
                m.name_type.as_ref().is_some_and(|n| self.ty(n, level)) || m.type_ann.as_ref().is_some_and(|x| self.ty(x, level))
            }
            swc::TsType::TsTypeLit(l) => self.type_elements(&l.members, level),
            swc::TsType::TsFnOrConstructorType(f) => match f {
                swc::TsFnOrConstructorType::TsFnType(x) => self.fn_params(&x.params, level) || self.ty(&x.type_ann.type_ann, level),
                swc::TsFnOrConstructorType::TsConstructorType(x) => {
                    self.fn_params(&x.params, level) || self.ty(&x.type_ann.type_ann, level)
                }
            },
            swc::TsType::TsTypeQuery(q) => self.type_args(&q.type_args, level),
            swc::TsType::TsImportType(i) => self.type_args(&i.type_args, level),
            swc::TsType::TsTypePredicate(p) => p.type_ann.as_ref().is_some_and(|x| self.ty(&x.type_ann, level)),
            swc::TsType::TsLitType(_)
            | swc::TsType::TsKeywordType(_)
            | swc::TsType::TsThisType(_)
            | swc::TsType::TsInferType(_) => false,
        };
        self.leave();
        stop
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swc_common::sync::Lrc;
    use swc_common::{FileName, SourceMap};
    use swc_ecma_parser::lexer::Lexer;
    use swc_ecma_parser::{StringInput, TsSyntax};

    /// The largest estimate the guard reaches over `source`, lexed standalone.
    ///
    /// CK13-FU3: unlike the production path (swc parse under
    /// [`GuardedTokens`], which stops supplying tokens once the estimate
    /// passes [`PRESCAN_LIMIT`]), this helper used to feed every token to
    /// [`Model`] regardless of the running estimate. On a hostile, deeply
    /// unbalanced source `Model.top` is an `Rc` linked list with one frame
    /// per still-open level and no upper bound; dropping a
    /// multi-hundred-thousand-frame chain recurses once per frame and
    /// overflows the stack -- the very crash F-213 exists to prevent,
    /// reached inside the guard's own test helper. Stop at the same bound
    /// [`GuardedTokens::next`] does, so this helper can never be the thing
    /// that overflows, whatever source it is handed.
    fn max_estimate(source: &str) -> u32 {
        let cm: Lrc<SourceMap> = Lrc::new(SourceMap::default());
        let fm = cm.new_source_file(Lrc::new(FileName::Custom("t.ts".into())), source.to_string());
        let lexer = Lexer::new(
            Syntax::Typescript(TsSyntax::default()),
            EsVersion::Es2022,
            StringInput::from(&*fm),
            None,
        );
        let mut model = Model::new();
        let mut max = 0;
        for t in lexer {
            model.feed(&t);
            let e = model.estimate();
            max = max.max(e);
            if e > PRESCAN_LIMIT {
                break;
            }
        }
        max
    }

    fn wrap(body: &str) -> String {
        format!(
            "class P extends SmartContract {{\n  constructor(a: bigint) {{ super(a); }}\n  public m(value: bigint): void {{\n    let result: bigint = 0n;\n{body}\n  }}\n}}\n"
        )
    }

    #[test]
    fn the_estimate_tracks_the_canonical_shapes() {
        let parens = max_estimate(&wrap(&format!("result = {}value{};", "(".repeat(126), ")".repeat(126))));
        let chain = max_estimate(&wrap(&format!("result = {};", vec!["value"; 127].join(" + "))));
        let ifs = max_estimate(&wrap(&format!("{}result = value;{}", "if (m) {".repeat(126), "}".repeat(126))));
        for (name, e) in [("parens-126", parens), ("chain-127", chain), ("if-126", ifs)] {
            assert!((126..=140).contains(&e), "{name}: estimate {e}");
        }
    }

    #[test]
    fn sequential_statements_do_not_accumulate() {
        let many = "if (m) { result = value; }\nresult = value + value;\n".repeat(2000);
        assert!(max_estimate(&wrap(&many)) < 10);
        let if_else = "if (m) { result = value; } else { result = value; }\nif (m) result = value; else result = value;\n".repeat(2000);
        assert!(max_estimate(&wrap(&if_else)) < 10);
        let no_semicolons = "result = value\n".repeat(2000);
        assert!(max_estimate(&wrap(&no_semicolons)) < 10);
        let args = format!("result = f({});", vec!["value"; 5000].join(", "));
        assert!(max_estimate(&wrap(&args)) < 10);
    }

    #[test]
    fn loop_built_chains_and_else_chains_accumulate() {
        let members = format!("result = value{};", ".a".repeat(1000));
        assert!(max_estimate(&wrap(&members)) > PRESCAN_LIMIT);
        let elses = format!("if (m) {{}}{}", " else if (m) {}".repeat(1000));
        assert!(max_estimate(&wrap(&elses)) > PRESCAN_LIMIT);
        let dangling = format!("{}result = value;", "if (m) result = value; else ".repeat(1000));
        assert!(max_estimate(&wrap(&dangling)) > PRESCAN_LIMIT);
        let groups = format!("result = {};", vec!["(value)"; 1000].join(" + "));
        assert!(max_estimate(&wrap(&groups)) > PRESCAN_LIMIT, "a group must not end the chain");
        let calls = format!("result = {};", vec!["f(value)"; 1000].join(" + "));
        assert!(max_estimate(&wrap(&calls)) > PRESCAN_LIMIT);
        let tagged = format!("result = value{};", "`x`".repeat(1000));
        assert!(max_estimate(&wrap(&tagged)) > PRESCAN_LIMIT, "tagged templates chain");
        let substitutions = format!("result = `{}`;", "${value}".repeat(2000));
        assert!(max_estimate(&wrap(&substitutions)) < 10, "template substitutions are a flat list");
        let casts = format!("result = value{};", " as bigint".repeat(1000));
        assert!(max_estimate(&wrap(&casts)) < 10, "as-casts are dropped by the Rúnar AST");
    }

    /// CK13-FU3 regression: on a hostile source `max_estimate` must stop
    /// feeding tokens to `Model` at the same bound the production
    /// `GuardedTokens` guard does, rather than reflect the source's full,
    /// unbounded depth. Before the fix this input (300,000 unclosed
    /// `switch` headers, never balanced) made `Model.top` grow to a
    /// 300,000-frame `Rc` chain and overflowed the stack when it dropped.
    ///
    /// What this proves: the helper itself can no longer be made to
    /// overflow by a sufficiently deep/unbalanced source, independent of
    /// where that source came from.
    /// What this does not prove: that no OTHER unbounded-growth path exists
    /// in `Model` (e.g. a construct that grows `pending`/`hi` without also
    /// growing the `Rc` chain by the same amount would not be caught by this
    /// bound). The production path remains the authority on refusal
    /// semantics; this only has to avoid crashing.
    #[test]
    fn max_estimate_stops_at_the_prescan_limit_on_hostile_input() {
        let hostile = "switch(a){".repeat(300_000);
        let e = max_estimate(&hostile);
        assert!(e > PRESCAN_LIMIT, "expected the estimate to cross the limit: {e}");
        assert!(
            (e as u64) <= PRESCAN_LIMIT as u64 + 10,
            "expected the helper to stop just past the limit, not reflect the full 300000-deep input: {e}"
        );
    }

    /// The git-tracked `.runar.ts` sources under the repo root, same scoping
    /// rule as the walk the TS tier uses for the equivalent corpus check
    /// (R188-FU, `git show 805a481b`): `git ls-files` rather than a
    /// filesystem walk, so scratch adversarial fixtures and other untracked
    /// clutter under the repo root are never part of this corpus.
    fn corpus_runar_ts_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let output = std::process::Command::new("git")
            .args(["ls-files", "-z", "--", "*.runar.ts"])
            .current_dir(root)
            .output();
        let Ok(output) = output else { return Vec::new() };
        if !output.status.success() {
            return Vec::new();
        }
        output
            .stdout
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| root.join(String::from_utf8_lossy(s).into_owned()))
            .collect()
    }

    /// CK13-FU3 regression: a filesystem walk from the repo root also picks
    /// up untracked files -- scratch adversarial fixtures left by other
    /// remediation work, nested worktree copies -- that are not part of the
    /// corpus `the_corpus_stays_far_below_the_limit` is making a claim
    /// about. One such fixture (deeply unbalanced nesting) reproduced a
    /// SIGABRT ("stack overflow") in that test; `git ls-files` makes the
    /// corpus immune to it regardless of what shape the untracked file is.
    ///
    /// What this proves: an untracked `.runar.ts` placed directly under the
    /// corpus root is excluded from the file list this crate's corpus test
    /// walks.
    /// What this does not prove: behaviour for a file that is untracked but
    /// `.gitignore`d differently, or staged-but-uncommitted (`git ls-files`
    /// without `--others` already excludes both, which is what we want
    /// here, but this test only exercises the plain untracked case that
    /// actually reproduced the crash).
    #[test]
    fn the_corpus_ignores_untracked_sources() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let scratch_dir = root.join("ck13fu3_untracked_scratch");
        std::fs::create_dir_all(&scratch_dir).expect("create scratch dir");
        let hostile = scratch_dir.join("hostile.runar.ts");
        std::fs::write(&hostile, "switch(a){".repeat(300_000)).expect("write scratch file");

        let found = corpus_runar_ts_files(&root);
        std::fs::remove_dir_all(&scratch_dir).ok();

        assert!(
            !found.iter().any(|p| p.ends_with("hostile.runar.ts")),
            "corpus walk must only see git-tracked .runar.ts files, found untracked {}",
            hostile.display()
        );
    }

    /// Headroom on every git-tracked .runar.ts source: the estimate stays far
    /// below the limit (the claim in the comment on `Model`).
    ///
    /// What this proves: every source this crate ships (not scratch/
    /// untracked clutter) stays far under the crash-guard bound.
    /// What this does not prove: anything about sources outside the repo,
    /// or about sources added after this test last ran.
    #[test]
    fn the_corpus_stays_far_below_the_limit() {
        let files = corpus_runar_ts_files(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."));
        assert!(files.len() > 100, "corpus not found ({} files)", files.len());
        let (worst, file) = files
            .iter()
            .filter_map(|f| std::fs::read_to_string(f).ok().map(|s| (max_estimate(&s), f.clone())))
            .max_by_key(|(e, _)| *e)
            .unwrap();
        assert!(worst <= 2 * MAX_SOURCE_NESTING as u32, "{}: estimate {worst}", file.display());
        eprintln!("F-213 corpus: {} .runar.ts files, max estimate {worst} ({})", files.len(), file.display());
    }
}
