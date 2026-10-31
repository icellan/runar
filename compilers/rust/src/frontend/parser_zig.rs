//! Zig parser for Rúnar contracts (.runar.zig).
//!
//! Parses Zig-style contract definitions using a hand-written tokenizer
//! and recursive descent parser. Produces the same AST as the TypeScript
//! and other format parsers.
//!
//! ## Expected format
//!
//! ```zig
//! const runar = @import("runar");
//!
//! pub const P2PKH = struct {
//!     pub const Contract = runar.SmartContract;
//!
//!     pubKeyHash: runar.Addr,
//!
//!     pub fn init(pubKeyHash: runar.Addr) P2PKH {
//!         return .{ .pubKeyHash = pubKeyHash };
//!     }
//!
//!     pub fn unlock(self: *const P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
//!         runar.assert(runar.hash160(pubKey) == self.pubKeyHash);
//!         runar.assert(runar.checkSig(sig, pubKey));
//!     }
//! };
//! ```
//!
//! Key mappings:
//! - `const runar = @import("runar")` — skipped import
//! - `pub const Name = struct { ... };` — contract definition
//! - `pub const Contract = runar.SmartContract` — contract marker
//! - `pub fn method(self: *const Name, ...)` — public method (self filtered)
//! - `fn helper(...)` — private method
//! - `pub fn init(...)` — constructor
//! - `self.property` — PropertyAccess
//! - `runar.builtin(...)` — strips `runar.` prefix
//! - `==`/`!=` -> StrictEq/StrictNe
//! - `and`/`or` -> And/Or
//! - `@divTrunc(a,b)` -> `/`, `@mod(a,b)` -> `%`
//! - `@shlExact(a,b)` -> `<<`, `@shrExact(a,b)` -> `>>`
//! - `@intCast(e)`, `@truncate(e)`, `@as(T, e)` -> inner expression
//! - `while (cond) : (update) { body }` -> ForStatement
//! - `.{ ... }` -> ArrayLiteral
//! - Compound assignment desugaring (`+=`, `-=`, etc.)

use num_bigint::BigInt;
use num_traits::ToPrimitive;
use super::ast::{
    BinaryOp, ContractNode, Expression, MethodNode, ParamNode, PrimitiveTypeName, PropertyNode,
    SourceLocation, Statement, TypeNode, UnaryOp, Visibility,
};
use super::diagnostic::{char_index_positions, lex_error_at_index, static_method_message, unexpected_struct_body_token_message, unknown_return_type_message, UNTERMINATED_STRING_LITERAL, ZIG_LIST_COMMA, ZIG_STRUCT_INIT_DOT};
use super::int_literal::{invalid_integer_literal, parse_int_literal, scan_number_end};
use super::input_limits::{enforce_ast_nesting, nesting_refusal, DepthTracker, NestingCounter};
use super::parser::ParseResult;
use super::sighash_directive::{lost_directive_message, resolve_native_sighash};
use std::collections::HashSet;

/// The `while (cond) : (upd) { ... }` desugaring's merge placeholder (N-009).
/// `parse_while_statement` always synthesizes this name as the ForStatement's
/// init; `parse_block_statements` replaces it with the real preceding
/// declaration when one matches the update target. A LEADING SPACE makes the
/// name unspellable in `.runar.zig` source (no surface's identifier lexer
/// produces a token containing whitespace), so a developer local can never
/// collide with it -- a plain-identifier placeholder would let a local
/// literally named "__while_no_init" that is not adjacent to its while alias
/// the placeholder by string equality, and the ANF lowerer's
/// condition-iterator check would then compare equal and silently unroll from
/// this placeholder's start of 0 instead of the developer's real start.
const WHILE_NO_INIT_PLACEHOLDER: &str = " __while_no_init";

/// The `ctx.<member>` intrinsics a StatefulContext handle exposes.
const ZIG_STATEFUL_CONTEXT_MEMBERS: [&str; 5] =
    ["txPreimage", "getStateScript", "addOutput", "addRawOutput", "addDataOutput"];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a Zig-format Rúnar contract source.
pub fn parse_zig(source: &str, file_name: Option<&str>) -> ParseResult {
    use super::diagnostic::Diagnostic;

    // DoS-bound size guard, enforced at every exported parser entry, not
    // just parse_source. N-136.
    if let Some(sse) = super::input_limits::assert_source_bytes_under_limit(source) {
        return ParseResult {
            contract: None,
            errors: vec![Diagnostic::error(sse.to_string(), None)],
            source_size_err: Some(sse),
        };
    }
    // F-213: the parse runs on its own stack segment, so its bounded
    // recursion fits whatever stack the caller runs on (a 2 MiB thread,
    // a debug build).
    super::input_limits::run_on_parse_stack(|| parse_zig_on_parse_stack(source, file_name))
}

/// The body of [`parse_zig`], on the parse stack segment.
fn parse_zig_on_parse_stack(source: &str, file_name: Option<&str>) -> ParseResult {
    use super::diagnostic::Diagnostic;
    let file = file_name.unwrap_or("contract.runar.zig");
    let mut str_errors: Vec<String> = Vec::new();

    let mut lex_errors: Vec<Diagnostic> = Vec::new();
    let (tokens, positions) = tokenize(source, file, &mut lex_errors);
    let mut parser = ZigParser::new(tokens, positions, file, &mut str_errors);

    let contract = parser.parse_contract();
    // F-213 measure (A), then measure (B) on the finished tree.
    if parser.nest.exceeded() {
        return nesting_refusal(None);
    }

    let mut errors = lex_errors;
    errors.extend(str_errors.into_iter().map(|msg| Diagnostic::error(msg, None)));

    enforce_ast_nesting(ParseResult { contract, errors, source_size_err: None })
}

// ---------------------------------------------------------------------------
// Type mapping
// ---------------------------------------------------------------------------

/// N-448 -- every tier's .runar.zig parser emits this verbatim.
fn zig_bare_string_literal_message(lit: &str) -> String {
    format!(
        "bare string literal \"{lit}\" is ambiguous in .runar.zig source: natively it is ASCII text but the compiler reads it as hex \u{2014} write runar.hexToBytes(\"{lit}\") for hex bytes"
    )
}

/// Map Zig type names to Rúnar primitive type names.
fn map_zig_type(name: &str) -> &str {
    match name {
        "i8" | "i16" | "i32" | "i64" | "i128" | "isize" => "bigint",
        "u8" | "u16" | "u32" | "u64" | "u128" | "usize" => "bigint",
        "comptime_int" => "bigint",
        "Bigint" | "BigintBig" => "bigint",
        "bool" => "boolean",
        "void" => "void",
        "ByteString" => "ByteString",
        "PubKey" => "PubKey",
        "Sig" => "Sig",
        "Sha256" => "Sha256",
        "Sha256Digest" => "Sha256",
        "Ripemd160" => "Ripemd160",
        "Addr" => "Addr",
        "SigHashPreimage" => "SigHashPreimage",
        "RabinSig" => "RabinSig",
        "RabinPubKey" => "RabinPubKey",
        "Point" => "Point",
        "P256Point" => "P256Point",
        "P384Point" => "P384Point",
        _ => name,
    }
}

/// Build a TypeNode from a mapped type name.
fn make_type_node(mapped: &str) -> TypeNode {
    if let Some(prim) = PrimitiveTypeName::from_str(mapped) {
        TypeNode::Primitive(prim)
    } else {
        TypeNode::Custom(mapped.to_string())
    }
}

// ---------------------------------------------------------------------------
// Tokeniser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    // Keywords
    Pub,
    Const,
    Var,
    Fn,
    Struct,
    If,
    Else,
    For,
    While,
    Return,
    TrueLit,
    FalseLit,
    Void,

    /// A character the lexer has no token for. Never produced by a valid
    /// source; exists so the parser reports it instead of the lexer dropping
    /// it (N-144).
    Unknown(char),

    // Identifiers and literals
    Ident(String),
    NumberLit(BigInt),
    StringLit(String),

    // Operators
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    EqEq,    // ==
    NotEq,   // !=
    Lt,
    Le,
    Gt,
    Ge,
    LShift,  // <<
    RShift,  // >>
    AndAnd,  // &&
    OrOr,    // ||
    BitAnd,  // &
    BitOr,   // |
    BitXor,  // ^
    Tilde,   // ~
    Bang,    // !
    Eq,      // =
    PlusEq,  // +=
    MinusEq, // -=
    StarEq,  // *=
    SlashEq, // /=
    PercentEq, // %=
    At,      // @

    // Delimiters
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Semicolon,
    Comma,
    Dot,
    Colon,

    // Special
    Eof,
}

/// N-410: a token's source text for a diagnostic.
fn zig_token_text(tok: &Token) -> String {
    match tok {
        Token::Pub => "pub".into(),
        Token::Const => "const".into(),
        Token::Var => "var".into(),
        Token::Fn => "fn".into(),
        Token::Struct => "struct".into(),
        Token::If => "if".into(),
        Token::Else => "else".into(),
        Token::For => "for".into(),
        Token::While => "while".into(),
        Token::Return => "return".into(),
        Token::TrueLit => "true".into(),
        Token::FalseLit => "false".into(),
        Token::Void => "void".into(),
        Token::Unknown(c) => c.to_string(),
        Token::Ident(name) => name.clone(),
        Token::NumberLit(n) => n.to_string(),
        Token::StringLit(s) => s.clone(),
        Token::Plus => "+".into(),
        Token::Minus => "-".into(),
        Token::Star => "*".into(),
        Token::Slash => "/".into(),
        Token::Percent => "%".into(),
        Token::EqEq => "==".into(),
        Token::NotEq => "!=".into(),
        Token::Lt => "<".into(),
        Token::Le => "<=".into(),
        Token::Gt => ">".into(),
        Token::Ge => ">=".into(),
        Token::LShift => "<<".into(),
        Token::RShift => ">>".into(),
        Token::AndAnd => "&&".into(),
        Token::OrOr => "||".into(),
        Token::BitAnd => "&".into(),
        Token::BitOr => "|".into(),
        Token::BitXor => "^".into(),
        Token::Tilde => "~".into(),
        Token::Bang => "!".into(),
        Token::Eq => "=".into(),
        Token::PlusEq => "+=".into(),
        Token::MinusEq => "-=".into(),
        Token::StarEq => "*=".into(),
        Token::SlashEq => "/=".into(),
        Token::PercentEq => "%=".into(),
        Token::At => "@".into(),
        Token::LParen => "(".into(),
        Token::RParen => ")".into(),
        Token::LBrace => "{".into(),
        Token::RBrace => "}".into(),
        Token::LBracket => "[".into(),
        Token::RBracket => "]".into(),
        Token::Semicolon => ";".into(),
        Token::Comma => ",".into(),
        Token::Dot => ".".into(),
        Token::Colon => ":".into(),
        Token::Eof => "eof".into(),
    }
}

/// Returns the tokens and, index for index, the (1-based line, 1-based
/// column — the AST convention; codegen/emit.rs converts) where each one
/// starts (F-337).
fn tokenize(
    source: &str,
    file: &str,
    errors: &mut Vec<super::diagnostic::Diagnostic>,
) -> (Vec<Token>, Vec<(usize, usize)>) {
    let mut tokens = Vec::new();
    // F-337: char index where each token starts.
    let mut starts: Vec<usize> = Vec::new();
    let mut at = 0usize;
    let chars: Vec<char> = source.chars().collect();
    let mut pos = 0;

    while pos < chars.len() {
        // Tokens pushed by the previous iteration started at `at`.
        starts.resize(tokens.len(), at);
        at = pos;
        let ch = chars[pos];

        // Whitespace
        if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
            pos += 1;
            continue;
        }

        // Line comment: //
        if ch == '/' && pos + 1 < chars.len() && chars[pos + 1] == '/' {
            while pos < chars.len() && chars[pos] != '\n' {
                pos += 1;
            }
            continue;
        }

        // Block comment: /* ... */
        if ch == '/' && pos + 1 < chars.len() && chars[pos + 1] == '*' {
            pos += 2;
            while pos + 1 < chars.len() {
                if chars[pos] == '*' && chars[pos + 1] == '/' {
                    pos += 2;
                    break;
                }
                pos += 1;
            }
            continue;
        }

        // Two-char operators
        if pos + 1 < chars.len() {
            let next = chars[pos + 1];
            match (ch, next) {
                ('=', '=') => { tokens.push(Token::EqEq); pos += 2; continue; }
                ('!', '=') => { tokens.push(Token::NotEq); pos += 2; continue; }
                ('<', '=') => { tokens.push(Token::Le); pos += 2; continue; }
                ('>', '=') => { tokens.push(Token::Ge); pos += 2; continue; }
                ('<', '<') => { tokens.push(Token::LShift); pos += 2; continue; }
                ('>', '>') => { tokens.push(Token::RShift); pos += 2; continue; }
                ('&', '&') => { tokens.push(Token::AndAnd); pos += 2; continue; }
                ('|', '|') => { tokens.push(Token::OrOr); pos += 2; continue; }
                ('+', '=') => { tokens.push(Token::PlusEq); pos += 2; continue; }
                ('-', '=') => { tokens.push(Token::MinusEq); pos += 2; continue; }
                ('*', '=') => { tokens.push(Token::StarEq); pos += 2; continue; }
                ('/', '=') => { tokens.push(Token::SlashEq); pos += 2; continue; }
                ('%', '=') => { tokens.push(Token::PercentEq); pos += 2; continue; }
                _ => {}
            }
        }

        // Single-char operators and delimiters
        match ch {
            '(' => { tokens.push(Token::LParen); pos += 1; continue; }
            ')' => { tokens.push(Token::RParen); pos += 1; continue; }
            '{' => { tokens.push(Token::LBrace); pos += 1; continue; }
            '}' => { tokens.push(Token::RBrace); pos += 1; continue; }
            '[' => { tokens.push(Token::LBracket); pos += 1; continue; }
            ']' => { tokens.push(Token::RBracket); pos += 1; continue; }
            ';' => { tokens.push(Token::Semicolon); pos += 1; continue; }
            ',' => { tokens.push(Token::Comma); pos += 1; continue; }
            '.' => { tokens.push(Token::Dot); pos += 1; continue; }
            ':' => { tokens.push(Token::Colon); pos += 1; continue; }
            '@' => { tokens.push(Token::At); pos += 1; continue; }
            '+' => { tokens.push(Token::Plus); pos += 1; continue; }
            '-' => { tokens.push(Token::Minus); pos += 1; continue; }
            '*' => { tokens.push(Token::Star); pos += 1; continue; }
            '/' => { tokens.push(Token::Slash); pos += 1; continue; }
            '%' => { tokens.push(Token::Percent); pos += 1; continue; }
            '<' => { tokens.push(Token::Lt); pos += 1; continue; }
            '>' => { tokens.push(Token::Gt); pos += 1; continue; }
            '=' => { tokens.push(Token::Eq); pos += 1; continue; }
            '&' => { tokens.push(Token::BitAnd); pos += 1; continue; }
            '|' => { tokens.push(Token::BitOr); pos += 1; continue; }
            '^' => { tokens.push(Token::BitXor); pos += 1; continue; }
            '~' => { tokens.push(Token::Tilde); pos += 1; continue; }
            '!' => { tokens.push(Token::Bang); pos += 1; continue; }
            _ => {}
        }

        // String literals: "..."
        if ch == '"' {
            let open = pos;
            pos += 1;
            let mut val = String::new();
            // F-011: a Zig string literal cannot span lines; one that reaches
            // a line break (escaped or not) or end of file is unterminated.
            while pos < chars.len() && chars[pos] != '"' && chars[pos] != '\n' && chars[pos] != '\r' {
                if chars[pos] == '\\' && pos + 1 < chars.len() && chars[pos + 1] != '\n' && chars[pos + 1] != '\r' {
                    pos += 1; // skip backslash
                    val.push(chars[pos]);
                    pos += 1;
                } else if chars[pos] == '\\' {
                    break;
                } else {
                    val.push(chars[pos]);
                    pos += 1;
                }
            }
            if pos < chars.len() && chars[pos] == '"' {
                pos += 1; // skip closing quote
            } else {
                errors.push(lex_error_at_index(UNTERMINATED_STRING_LITERAL, file, &chars, open));
            }
            tokens.push(Token::StringLit(val));
            continue;
        }

        // Numbers (F-026): the whole glued [0-9A-Za-z_] run is one Zig
        // integer literal; stopping at the first non-digit read `0b1010` as
        // `0` + `b1010`.
        if ch.is_ascii_digit() {
            let start = pos;
            pos = scan_number_end(&chars, pos);
            let text: String = chars[start..pos].iter().collect();
            let val = match parse_int_literal("zig", &text) {
                Some(lit) => lit.value,
                None => {
                    errors.push(lex_error_at_index(&invalid_integer_literal("zig", &text), file, &chars, start));
                    BigInt::from(0)
                }
            };
            tokens.push(Token::NumberLit(val));
            continue;
        }

        // Identifiers and keywords
        if ch.is_ascii_alphabetic() || ch == '_' {
            let start = pos;
            while pos < chars.len() && (chars[pos].is_ascii_alphanumeric() || chars[pos] == '_') {
                pos += 1;
            }
            let word: String = chars[start..pos].iter().collect();
            let tok = match word.as_str() {
                "pub" => Token::Pub,
                "const" => Token::Const,
                "var" => Token::Var,
                "fn" => Token::Fn,
                "struct" => Token::Struct,
                "if" => Token::If,
                "else" => Token::Else,
                "for" => Token::For,
                "while" => Token::While,
                "return" => Token::Return,
                "true" => Token::TrueLit,
                "false" => Token::FalseLit,
                "void" => Token::Void,
                "and" => Token::AndAnd,
                "or" => Token::OrOr,
                _ => Token::Ident(word),
            };
            tokens.push(tok);
            continue;
        }

        // A character the Zig surface has no meaning for. Carry it through as a
        // token so the parser can refuse it (N-144).
        //
        // This used to `pos += 1` in silence, so `sum = sum ?? i;` lexed as
        // `sum = sum i;` — two statements, both well-formed — and the contract
        // COMPILED, to a different script than the one the author read. Every
        // other tier refuses the same source. No `.runar.zig` in the repo (92
        // files, string literals and comments excluded) contains a character
        // this arm reaches, so nothing that parsed before stops parsing.
        //
        // N-214: the token alone gave a refusal with no position ("Unexpected
        // token in expression: Unknown('§')"); report TS's diagnostic at the
        // character too, ahead of whatever the parser then says.
        errors.push(lex_error_at_index(&format!("Unexpected character '{}'", ch), file, &chars, pos));
        tokens.push(Token::Unknown(ch));
        pos += 1;
    }

    tokens.push(Token::Eof);
    starts.resize(tokens.len(), at);
    let positions = char_index_positions(&chars, &starts);
    (tokens, positions)
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct ZigParser<'a> {
    tokens: Vec<Token>,
    /// F-337: start (line, column) of each token in `tokens`.
    positions: Vec<(usize, usize)>,
    pos: usize,
    file: &'a str,
    errors: &'a mut Vec<String>,
    contract_name: String,
    /// Names used as `self` receiver (first parameter whose type == contract name).
    self_names: HashSet<String>,
    /// Names of parameters typed as `StatefulContext`.
    stateful_context_names: HashSet<String>,
    /// F-213 measure (A): parse nesting.
    nest: NestingCounter,
    /// N-448: token indexes of string literals whose bare use is legal (the
    /// argument of `runar.hexToBytes`, the body of `runar.asm`).
    bare_literal_ok: HashSet<usize>,
}

impl<'a> ZigParser<'a> {
    fn new(
        tokens: Vec<Token>,
        positions: Vec<(usize, usize)>,
        file: &'a str,
        errors: &'a mut Vec<String>,
    ) -> Self {
        Self {
            tokens,
            positions,
            pos: 0,
            file,
            errors,
            contract_name: String::new(),
            self_names: HashSet::new(),
            stateful_context_names: HashSet::new(),
            nest: NestingCounter::new(),
            bare_literal_ok: HashSet::new(),
        }
    }

    /// F-213: the source is too deep. Latch the refusal and treat the rest
    /// of the input as ended, so every loop above unwinds without building
    /// anything deeper.
    fn bail(&mut self) {
        self.nest.refuse();
        self.pos = self.tokens.len();
    }

    /// Run `f` one counted nesting level deeper (measure A), or return
    /// `fallback` once the limit is reached.
    fn nested<T>(&mut self, fallback: T, f: impl FnOnce(&mut Self) -> T) -> T {
        if !self.nest.enter() {
            self.bail();
            return fallback;
        }
        let out = f(self);
        self.nest.exit();
        out
    }

    /// May a loop wrap `acc` (and `others`) in one more node? Refuses once
    /// that node would be deeper than MAX_SOURCE_NESTING (F-213).
    fn grow(&mut self, dt: &mut DepthTracker, acc: &Expression, others: &[&Expression]) -> bool {
        if dt.wrap(acc, others) {
            return true;
        }
        self.bail();
        false
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn peek_at(&self, offset: usize) -> &Token {
        self.tokens.get(self.pos + offset).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        let t = self.tokens.get(self.pos).cloned().unwrap_or(Token::Eof);
        self.pos += 1;
        t
    }

    fn expect(&mut self, expected: &Token) -> bool {
        if std::mem::discriminant(self.peek()) == std::mem::discriminant(expected) {
            self.advance();
            true
        } else {
            self.errors.push(format!(
                "Expected {:?}, got {:?}",
                expected,
                self.peek()
            ));
            false
        }
    }

    fn match_tok(&mut self, expected: &Token) -> bool {
        if std::mem::discriminant(self.peek()) == std::mem::discriminant(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect_ident(&mut self) -> String {
        match self.advance() {
            Token::Ident(name) => name,
            other => {
                self.errors
                    .push(format!("Expected identifier, got {:?}", other));
                "_error".to_string()
            }
        }
    }

    /// Where the current token starts (F-337).
    fn loc(&self) -> SourceLocation {
        let (line, column) = self
            .positions
            .get(self.pos)
            .or_else(|| self.positions.last())
            .copied()
            .unwrap_or((1, 0));
        SourceLocation {
            file: self.file.to_string(),
            line,
            column,
        }
    }

    // -----------------------------------------------------------------------
    // Top-level parsing
    // -----------------------------------------------------------------------

    fn parse_contract(&mut self) -> Option<ContractNode> {
        // Skip `const runar = @import("runar");`
        self.skip_runar_import();

        // Look for `pub const Name = struct { ... };`
        while *self.peek() != Token::Eof {
            if *self.peek() == Token::Pub
                && *self.peek_at(1) == Token::Const
                && matches!(self.peek_at(2), Token::Ident(_))
                && *self.peek_at(3) == Token::Eq
            {
                if let Some(contract) = self.try_parse_contract_decl() {
                    return Some(contract);
                }
            }
            self.advance();
        }

        self.errors
            .push("Expected Zig contract declaration `pub const Name = struct { ... };`".to_string());
        None
    }

    fn skip_runar_import(&mut self) {
        let start = self.pos;

        if *self.peek() != Token::Const {
            self.errors
                .push("Expected `const runar = @import(\"runar\");` at the top of the file".to_string());
            return;
        }
        self.advance(); // const

        if !matches!(self.peek(), Token::Ident(ref n) if n == "runar") {
            self.pos = start;
            self.errors
                .push("Expected `const runar = @import(\"runar\");` at the top of the file".to_string());
            return;
        }
        self.advance(); // runar

        if !self.match_tok(&Token::Eq) {
            self.pos = start;
            self.errors
                .push("Expected `const runar = @import(\"runar\");` at the top of the file".to_string());
            return;
        }

        if *self.peek() == Token::At {
            self.advance(); // @
            if matches!(self.peek(), Token::Ident(ref n) if n == "import") {
                self.advance(); // import
                self.expect(&Token::LParen);
                // Skip the string argument
                if matches!(self.peek(), Token::StringLit(_)) {
                    self.advance();
                }
                self.expect(&Token::RParen);
                self.match_tok(&Token::Semicolon);
                return;
            }
        }

        self.pos = start;
        self.errors
            .push("Expected `const runar = @import(\"runar\");` at the top of the file".to_string());
    }

    fn try_parse_contract_decl(&mut self) -> Option<ContractNode> {
        let start = self.pos;

        self.expect(&Token::Pub);   // pub
        self.expect(&Token::Const); // const

        let name = self.expect_ident(); // Name
        if *self.peek() != Token::Eq {
            self.pos = start;
            return None;
        }
        self.advance(); // =

        if *self.peek() != Token::Struct {
            self.pos = start;
            return None;
        }
        self.advance(); // struct

        self.expect(&Token::LBrace); // {

        self.contract_name = name.clone();
        let mut parent_class = "SmartContract".to_string();
        let mut properties: Vec<PropertyNode> = Vec::new();
        let mut methods: Vec<MethodNode> = Vec::new();
        let mut constructor: Option<MethodNode> = None;

        while *self.peek() != Token::RBrace && *self.peek() != Token::Eof {
            // Contract marker: `pub const Contract = runar.SmartContract;`
            if *self.peek() == Token::Pub
                && *self.peek_at(1) == Token::Const
                && matches!(self.peek_at(2), Token::Ident(ref n) if n == "Contract")
            {
                parent_class = self.parse_contract_marker();
                continue;
            }

            // Public method: `pub fn name(...)`
            if *self.peek() == Token::Pub && *self.peek_at(1) == Token::Fn {
                if let Some(method) = self.parse_method(true) {
                    if method.name == "constructor" {
                        constructor = Some(method);
                    } else {
                        methods.push(method);
                    }
                }
                continue;
            }

            // Private method: `fn name(...)`
            if *self.peek() == Token::Fn {
                if let Some(method) = self.parse_method(false) {
                    if method.name == "constructor" {
                        constructor = Some(method);
                    } else {
                        methods.push(method);
                    }
                }
                continue;
            }

            // Field: `name: type [= value],`
            if matches!(self.peek(), Token::Ident(_)) {
                if let Some(prop) = self.parse_field() {
                    properties.push(prop);
                }
                continue;
            }

            // N-410: any other token is refused, never skipped.
            let text = zig_token_text(self.peek());
            self.push_error_at_current(&unexpected_struct_body_token_message(&text));
            self.advance();
        }

        self.expect(&Token::RBrace); // }
        self.match_tok(&Token::Semicolon); // optional ;

        // Collect set of property names mutated in any method body so we can
        // mark them as non-readonly in stateful contracts (matches TS rule).
        let mut mutated: HashSet<String> = HashSet::new();
        for m in &methods {
            collect_mutated_properties(&m.body, &mut mutated);
        }

        // Auto-generate constructor if not provided
        let constructor = constructor.unwrap_or_else(|| build_constructor(&properties, self.file));

        // Post-process:
        // - SmartContract: all properties readonly.
        // - StatefulSmartContract: readonly iff explicitly marked, OR has no
        //   initializer AND is not mutated in any method body.
        // - The initializer of a property the constructor assigns is no
        //   longer stripped here. anf_lower.rs now applies that rule to
        //   EVERY surface (see constructor_assigned_properties), keyed on
        //   the constructor assignment rather than on a name match, so the
        //   Zig surface no longer needs -- and must not keep -- a private
        //   copy that only fired when the struct field and the `init`
        //   parameter happened to share a name. readonly inference still
        //   reads the ORIGINAL initializer, exactly as it did when the
        //   strip ran in the same expression.
        for prop in &mut properties {
            let had_initializer = prop.initializer.is_some();
            if parent_class == "SmartContract" || parent_class == "UnsafeSmartContract" {
                prop.readonly = true;
            } else if !prop.readonly && !had_initializer && !mutated.contains(&prop.name) {
                prop.readonly = true;
            }
        }

        // Rewrite bare method calls to this.method() style
        let mut method_names: HashSet<String> =
            methods.iter().map(|m| m.name.clone()).collect();
        method_names.insert("addOutput".to_string());
        method_names.insert("addRawOutput".to_string());
        method_names.insert("addDataOutput".to_string());
        method_names.insert("getStateScript".to_string());
        let mut final_methods = methods;
        for method in &mut final_methods {
            rewrite_bare_method_calls(&mut method.body, &method_names);
        }
        let mut final_constructor = constructor;
        rewrite_bare_method_calls(&mut final_constructor.body, &method_names);

        Some(ContractNode {
            name,
            parent_class,
            properties,
            constructor: final_constructor,
            methods: final_methods,
            source_file: self.file.to_string(),
        })
    }

    fn parse_contract_marker(&mut self) -> String {
        self.advance(); // pub
        self.advance(); // const
        self.advance(); // Contract (ident)
        self.expect(&Token::Eq);

        let mut parent = "SmartContract".to_string();
        if matches!(self.peek(), Token::Ident(ref n) if n == "runar") {
            self.advance(); // runar
            self.expect(&Token::Dot);
            let name_loc = self.loc();
            let name = self.expect_ident();
            if name == "StatefulSmartContract" {
                parent = "StatefulSmartContract".to_string();
            } else if name == "UnsafeSmartContract" {
                parent = "UnsafeSmartContract".to_string();
            } else if name != "SmartContract" {
                // N-014: an unknown base is refused, never folded to SmartContract.
                self.errors.push(format!(
                    "{}:{}:{}: unknown parent class: '{}', expected SmartContract, StatefulSmartContract, or UnsafeSmartContract",
                    name_loc.file, name_loc.line, name_loc.column, name
                ));
            }
        }

        self.match_tok(&Token::Semicolon);
        parent
    }

    // -----------------------------------------------------------------------
    // Fields
    // -----------------------------------------------------------------------

    fn parse_field(&mut self) -> Option<PropertyNode> {
        let name = self.expect_ident();
        self.expect(&Token::Colon);
        let (type_node, is_readonly, embed_always) = self.parse_type_full();
        let mut initializer: Option<Expression> = None;

        // Optional field initializer: `= value`
        if *self.peek() == Token::Eq {
            self.advance();
            initializer = Some(self.parse_expression());
        }

        // N-033: fields are separated by `,`; only the last before `}` may omit it.
        self.expect_list_separator(&Token::RBrace);

        Some(PropertyNode {
            name,
            prop_type: type_node,
            readonly: is_readonly,
            initializer,
            source_location: self.loc(),
            synthetic_array_chain: None,
            embed_always,
        })
    }

    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    /// Parse a type, returning (TypeNode, is_readonly).
    fn parse_type(&mut self) -> (TypeNode, bool) {
        let (t, readonly, _) = self.parse_type_full();
        (t, readonly)
    }

    /// Parse a type, returning (TypeNode, is_readonly, embed_always). N-093:
    /// `runar.EmbedAlways(T)` is the native spelling of `@embedAlways`; it
    /// composes with `runar.Readonly(T)` in either order. As in the TS
    /// reference (01-parse-zig.ts `parseType`), an array type does not carry
    /// its element's `EmbedAlways`.
    fn parse_type_full(&mut self) -> (TypeNode, bool, bool) {
        // Array type: [N]T
        if *self.peek() == Token::LBracket {
            self.advance(); // [
            let length = match self.advance() {
                Token::NumberLit(n) => n.to_usize().unwrap_or(0),
                _ => {
                    self.errors.push("Expected array length".to_string());
                    0
                }
            };
            self.expect(&Token::RBracket);
            // F-213: a nested element type is one level deeper (+1).
            let (element, readonly) =
                self.nested((TypeNode::Custom("_error".to_string()), false), |p| p.parse_type());
            return (
                TypeNode::FixedArray {
                    element: Box::new(element),
                    length,
                },
                readonly,
                false,
            );
        }

        // Qualified type: `runar.TypeName` or `runar.Readonly(T)`
        if matches!(self.peek(), Token::Ident(ref n) if n == "runar")
            && *self.peek_at(1) == Token::Dot
        {
            self.advance(); // runar
            self.advance(); // .
            let name = self.expect_ident();

            // runar.Readonly(T)
            if name == "Readonly" && *self.peek() == Token::LParen {
                self.advance(); // (
                let (inner, _, embed) = self
                    .nested((TypeNode::Custom("_error".to_string()), false, false), |p| p.parse_type_full());
                self.expect(&Token::RParen);
                return (inner, true, embed);
            }

            // runar.EmbedAlways(T)
            if name == "EmbedAlways" && *self.peek() == Token::LParen {
                self.advance(); // (
                let (inner, readonly, _) = self
                    .nested((TypeNode::Custom("_error".to_string()), false, false), |p| p.parse_type_full());
                self.expect(&Token::RParen);
                return (inner, readonly, true);
            }

            let mapped = map_zig_type(&name);
            return (make_type_node(mapped), false, false);
        }

        // void keyword
        if *self.peek() == Token::Void {
            self.advance();
            return (TypeNode::Primitive(PrimitiveTypeName::Void), false, false);
        }

        // Plain identifier type
        if matches!(self.peek(), Token::Ident(_)) {
            let name = self.expect_ident();
            let mapped = map_zig_type(&name);
            return (make_type_node(mapped), false, false);
        }

        // Fallback
        self.advance();
        (TypeNode::Custom("unknown".to_string()), false, false)
    }

    /// Parse a parameter type, skipping pointer/const qualifiers.
    fn parse_param_type(&mut self) -> (TypeNode, bool, String) {
        // Skip pointer qualifiers: *, &
        while *self.peek() == Token::Star || *self.peek() == Token::BitAnd {
            self.advance();
        }
        // Skip const qualifier
        if *self.peek() == Token::Const {
            self.advance();
        }

        // Get the raw type name before mapping, for receiver detection
        let raw_name = if matches!(self.peek(), Token::Ident(ref n) if n == "runar")
            && *self.peek_at(1) == Token::Dot
        {
            // Don't advance yet -- parse_type will handle it
            let save = self.pos;
            self.advance(); // runar
            self.advance(); // .
            let n = self.expect_ident();
            self.pos = save; // revert
            n
        } else if matches!(self.peek(), Token::Ident(_)) {
            match self.peek() {
                Token::Ident(n) => n.clone(),
                _ => "unknown".to_string(),
            }
        } else {
            "unknown".to_string()
        };

        let (type_node, is_readonly) = self.parse_type();
        (type_node, is_readonly, raw_name)
    }

    // -----------------------------------------------------------------------
    // Methods
    // -----------------------------------------------------------------------

    fn parse_method(&mut self, is_public: bool) -> Option<MethodNode> {
        if is_public {
            self.advance(); // pub
        }
        self.advance(); // fn

        let method_name = self.expect_ident();

        let (params, receiver_name, stateful_ctx_names) = self.parse_param_list();

        // N-050: a `pub fn` without a receiver of the contract type is a
        // namespace (static) function, not a contract method. A private one
        // stays a helper (the multi-method golden's computeThreshold), like R9.
        if is_public && receiver_name.is_none() && method_name != "init" {
            self.errors.push(static_method_message(&method_name));
        }

        // Return type. N-093: `runar.Sighash("FLAGS")` in its place is the
        // native spelling of the `@sighash` directive (natively it is `void`).
        let mut sighash_specs: Vec<Option<String>> = Vec::new();
        if matches!(self.peek(), Token::Ident(n) if n == "runar")
            && *self.peek_at(1) == Token::Dot
            && matches!(self.peek_at(2), Token::Ident(n) if n == "Sighash")
        {
            self.advance(); // runar
            self.advance(); // .
            self.advance(); // Sighash
            self.expect(&Token::LParen);
            let arg = self.peek().clone();
            let mut count = 0;
            let mut depth: i32 = 0;
            while *self.peek() != Token::Eof {
                let t = self.peek().clone();
                if t == Token::RParen && depth == 0 {
                    break;
                }
                if t == Token::LParen {
                    depth += 1;
                }
                if t == Token::RParen {
                    depth -= 1;
                }
                self.advance();
                count += 1;
            }
            self.expect(&Token::RParen);
            sighash_specs.push(match arg {
                Token::StringLit(v) if count == 1 => Some(v),
                _ => None,
            });
        } else if *self.peek() != Token::LBrace {
            // The AST keeps no return type (everything before '{'); N-331
            // refuses an unknown name. `init` returns the contract struct
            // itself, which is not a type to check.
            let (ret_type, _) = self.parse_type();
            if method_name != "init" {
                if let Some(msg) = unknown_return_type_message(&ret_type, &method_name, is_public) {
                    self.errors.push(msg);
                }
            }
        }

        // Save/restore self names
        let prev_self_names = self.self_names.clone();
        let prev_stateful_ctx = self.stateful_context_names.clone();
        self.self_names = if let Some(ref r) = receiver_name {
            let mut s = HashSet::new();
            s.insert(r.clone());
            s
        } else {
            HashSet::new()
        };
        self.stateful_context_names = stateful_ctx_names;

        if method_name == "init" {
            // N-093: the constructor is not a spending entry point.
            if !sighash_specs.is_empty() {
                self.errors.push(lost_directive_message("@sighash"));
            }
            // Constructor
            let body = self.parse_constructor_body(&params);
            self.self_names = prev_self_names;
            self.stateful_context_names = prev_stateful_ctx;
            return Some(MethodNode {
                name: "constructor".to_string(),
                params,
                body,
                visibility: Visibility::Public,
                source_location: self.loc(),
                sighash_type: None,
            });
        }

        let body = self.parse_block_statements();
        self.self_names = prev_self_names;
        self.stateful_context_names = prev_stateful_ctx;

        let sighash_type = match resolve_native_sighash(&method_name, is_public, &sighash_specs) {
            Some(Ok(v)) => Some(v),
            Some(Err(msg)) => {
                self.errors.push(msg);
                None
            }
            None => None,
        };

        Some(MethodNode {
            name: method_name,
            params,
            body,
            visibility: if is_public {
                Visibility::Public
            } else {
                Visibility::Private
            },
            source_location: self.loc(),
            sighash_type,
        })
    }

    fn parse_param_list(
        &mut self,
    ) -> (Vec<ParamNode>, Option<String>, HashSet<String>) {
        self.expect(&Token::LParen);
        let mut params = Vec::new();
        let mut receiver_name: Option<String> = None;
        let mut stateful_ctx_names = HashSet::new();
        let mut index = 0;

        while *self.peek() != Token::RParen && *self.peek() != Token::Eof {
            let param_name = self.expect_ident();
            self.expect(&Token::Colon);
            let (type_node, _is_readonly, raw_name) = self.parse_param_type();

            let is_receiver = index == 0 && raw_name == self.contract_name;

            if is_receiver {
                receiver_name = Some(param_name);
            } else if raw_name == "StatefulContext" {
                // Zig stateful contracts thread an explicit StatefulContext
                // parameter through every state-mutating method body
                // (e.g. `ctx.txPreimage`, `ctx.addOutput(...)`). The compiler
                // re-injects this context when lowering, so the parameter is
                // dropped from the canonical IR — matching the Zig compiler's
                // own parse_zig.zig behavior. Recording the binding name lets
                // later passes rewrite `ctx.txPreimage` -> `this.txPreimage`
                // and `ctx.addOutput(...)` -> `this.addOutput(...)`.
                stateful_ctx_names.insert(param_name);
            } else {
                params.push(ParamNode {
                    name: param_name,
                    param_type: type_node,
                });
            }

            index += 1;
            // N-033: parameters are separated by `,` (a trailing one is allowed).
            if !self.expect_list_separator(&Token::RParen) {
                break;
            }
        }

        self.expect(&Token::RParen);
        (params, receiver_name, stateful_ctx_names)
    }

    // -----------------------------------------------------------------------
    // Constructor body
    // -----------------------------------------------------------------------

    fn parse_constructor_body(&mut self, params: &[ParamNode]) -> Vec<Statement> {
        self.expect(&Token::LBrace);
        let mut body: Vec<Statement> = vec![self.create_super_call(params)];
        let mut found_return_struct = false;

        while *self.peek() != Token::RBrace && *self.peek() != Token::Eof {
            // Detect `return .{ ... };` pattern
            if *self.peek() == Token::Return
                && *self.peek_at(1) == Token::Dot
                && *self.peek_at(2) == Token::LBrace
            {
                self.advance(); // return
                body.extend(self.parse_struct_return_assignments());
                found_return_struct = true;
                self.match_tok(&Token::Semicolon);
                continue;
            }

            if let Some(stmt) = self.parse_statement() {
                body.push(stmt);
            }
        }

        self.expect(&Token::RBrace);

        // If no struct return was found, auto-assign params to properties
        if !found_return_struct {
            // We don't have access to properties here directly, but the
            // fallback constructor handles that. For user-written init()
            // with explicit assignments, nothing extra is needed.
        }

        body
    }

    fn parse_struct_return_assignments(&mut self) -> Vec<Statement> {
        let mut assignments = Vec::new();
        self.expect(&Token::Dot);  // .
        self.expect(&Token::LBrace); // {

        while *self.peek() != Token::RBrace && *self.peek() != Token::Eof {
            // .field = value
            // N-410: Zig requires the leading `.` of a struct-init field.
            if *self.peek() == Token::Dot {
                self.advance(); // .
            } else {
                self.push_error_at_current(ZIG_STRUCT_INIT_DOT);
            }
            let field = self.expect_ident();
            self.expect(&Token::Eq);
            let value = self.parse_expression();
            assignments.push(Statement::Assignment {
                target: Expression::PropertyAccess {
                    property: field,
                    source_location: None,
                },
                value,
                source_location: self.loc(),
            });
            // N-033: struct-init fields are separated by `,` (a trailing one is allowed).
            if !self.expect_list_separator(&Token::RBrace) {
                break;
            }
        }

        self.expect(&Token::RBrace);
        assignments
    }

    fn create_super_call(&self, params: &[ParamNode]) -> Statement {
        let super_args: Vec<Expression> = params
            .iter()
            .map(|p| Expression::Identifier {
                name: p.name.clone(),
                source_location: None,
            })
            .collect();
        Statement::ExpressionStatement {
            expression: Expression::CallExpr {
                callee: Box::new(Expression::Identifier {
                    name: "super".to_string(),
                    source_location: None,
                }),
                args: super_args,
                asm_return_type: None,
            },
            source_location: self.loc(),
        }
    }

    // -----------------------------------------------------------------------
    // Statements
    // -----------------------------------------------------------------------

    fn parse_block_statements(&mut self) -> Vec<Statement> {
        self.expect(&Token::LBrace);
        let mut stmts = Vec::new();
        while *self.peek() != Token::RBrace && *self.peek() != Token::Eof {
            if let Some(stmt) = self.parse_statement() {
                // Merge `var i = 0; while (i < N) : (i += 1) { ... }` into a single ForStatement
                let merge = if let Statement::ForStatement {
                    ref init,
                    ..
                } = stmt
                {
                    if let Statement::VariableDecl { ref name, .. } = init.as_ref() {
                        if name == WHILE_NO_INIT_PLACEHOLDER {
                            // Check if previous statement is a variable decl for the loop variable
                            if let Some(Statement::VariableDecl { name: prev_name, .. }) = stmts.last() {
                                // Check the loop update target
                                let update_target = get_loop_update_target(&stmt);
                                if update_target.as_deref() == Some(prev_name.as_str()) {
                                    true
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };

                if merge {
                    let prev = stmts.pop().unwrap();
                    // Replace the dummy init with the actual var decl
                    if let Statement::ForStatement {
                        init: _,
                        condition,
                        update,
                        body,
                        source_location,
                    } = stmt
                    {
                        stmts.push(Statement::ForStatement {
                            init: Box::new(prev),
                            condition,
                            update,
                            body,
                            source_location,
                        });
                    }
                } else {
                    stmts.push(stmt);
                }
            }
        }
        self.expect(&Token::RBrace);
        stmts
    }

    fn parse_statement(&mut self) -> Option<Statement> {
        // F-337: a statement is located at its first token; the inner
        // parsers build it only after consuming it.
        let start = self.loc();
        let mut stmt = self.nested(None, |p| p.parse_statement_inner());
        if let Some(s) = stmt.as_mut() {
            *s.source_location_mut() = start;
        }
        stmt
    }

    fn parse_statement_inner(&mut self) -> Option<Statement> {
        // return
        if *self.peek() == Token::Return {
            return Some(self.parse_return_statement());
        }

        // if
        if *self.peek() == Token::If {
            return Some(self.parse_if_statement());
        }

        // const / var
        if *self.peek() == Token::Const || *self.peek() == Token::Var {
            return Some(self.parse_variable_decl());
        }

        // _ = expr; (discard). N-053: Zig's discard drops the VALUE, not the
        // evaluation -- a helper called for its asserts must keep them, so
        // `expr` lowers as an expression statement. Only a bare name (the
        // unused-binding idiom `_ = self;` / `_ = param;`) is dropped:
        // reading a name has no effect.
        if matches!(self.peek(), Token::Ident(ref n) if n == "_")
            && *self.peek_at(1) == Token::Eq
        {
            self.advance(); // _
            self.advance(); // =
            let expression = self.parse_expression();
            self.match_tok(&Token::Semicolon);
            if matches!(expression, Expression::Identifier { .. }) {
                return None;
            }
            return Some(Statement::ExpressionStatement {
                expression,
                source_location: self.loc(),
            });
        }

        // while
        if *self.peek() == Token::While {
            return Some(self.parse_while_statement());
        }

        // for (unsupported, emit error)
        if *self.peek() == Token::For {
            self.errors.push(
                "Unsupported Zig 'for' syntax -- use 'while' loops instead".to_string(),
            );
            self.skip_unsupported_block();
            return None;
        }

        // Expression / assignment
        let target = self.parse_expression();

        // Simple assignment: expr = value
        if *self.peek() == Token::Eq {
            self.advance();
            let value = self.parse_expression();
            self.match_tok(&Token::Semicolon);
            return Some(Statement::Assignment {
                target,
                value,
                source_location: self.loc(),
            });
        }

        // Compound assignment: +=, -=, *=, /=, %=
        if let Some(bin_op) = self.parse_compound_op() {
            let rhs = self.parse_expression();
            self.match_tok(&Token::Semicolon);
            return Some(Statement::Assignment {
                target: target.clone(),
                value: Expression::BinaryExpr {
                    op: bin_op,
                    left: Box::new(target),
                    right: Box::new(rhs),
                    source_location: None,
                },
                source_location: self.loc(),
            });
        }

        self.match_tok(&Token::Semicolon);
        Some(Statement::ExpressionStatement {
            expression: target,
            source_location: self.loc(),
        })
    }

    fn parse_return_statement(&mut self) -> Statement {
        self.advance(); // return
        let value = if *self.peek() != Token::Semicolon
            && *self.peek() != Token::RBrace
            && *self.peek() != Token::Eof
        {
            Some(self.parse_expression())
        } else {
            None
        };
        self.match_tok(&Token::Semicolon);
        Statement::ReturnStatement {
            value,
            source_location: self.loc(),
        }
    }

    fn parse_if_statement(&mut self) -> Statement {
        // F-337: located at the `if` token (an `else if` never passes
        // through parse_statement).
        let loc = self.loc();
        self.advance(); // if

        // Optional parentheses around condition
        let has_paren = self.match_tok(&Token::LParen);
        let condition = self.parse_expression();
        if has_paren {
            self.expect(&Token::RParen);
        }

        let then_branch = self.parse_block_statements();

        let else_branch = if *self.peek() == Token::Else {
            self.advance(); // else
            if *self.peek() == Token::If {
                // F-213: the nested `if` is a statement of the else branch (+1).
                self.nested(Some(Vec::new()), |p| Some(vec![p.parse_if_statement()]))
            } else {
                Some(self.parse_block_statements())
            }
        } else {
            None
        };

        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            source_location: loc,
        }
    }

    fn parse_variable_decl(&mut self) -> Statement {
        let is_mutable = *self.peek() == Token::Var;
        self.advance(); // const or var

        let name = self.expect_ident();

        // Optional type annotation: `: type`
        let var_type = if *self.peek() == Token::Colon {
            self.advance(); // :
            let (t, _) = self.parse_type();
            Some(t)
        } else {
            None
        };

        self.expect(&Token::Eq);
        let init = self.parse_expression();
        self.match_tok(&Token::Semicolon);

        Statement::VariableDecl {
            name,
            var_type,
            mutable: is_mutable,
            init,
            source_location: self.loc(),
        }
    }

    /// Parse Zig while loop: `while (condition) : (continue_expr) { body }`
    ///
    /// Emits a ForStatement. The init is synthesized as the unspellable
    /// `WHILE_NO_INIT_PLACEHOLDER` sentinel bound to 0
    /// unless `parse_block_statements` merges the preceding variable decl.
    fn parse_while_statement(&mut self) -> Statement {
        self.advance(); // while

        // Condition: while (i < 5)
        let has_paren = self.match_tok(&Token::LParen);
        let condition = self.parse_expression();
        if has_paren {
            self.expect(&Token::RParen);
        }

        // Continue expression: : (i += 1)
        let update: Statement;
        if *self.peek() == Token::Colon {
            self.advance(); // :
            let has_paren = self.match_tok(&Token::LParen);
            let update_target = self.parse_expression();

            if let Some(bin_op) = self.parse_compound_op() {
                let rhs = self.parse_expression();
                update = Statement::Assignment {
                    target: update_target.clone(),
                    value: Expression::BinaryExpr {
                        op: bin_op,
                        left: Box::new(update_target),
                        right: Box::new(rhs),
                        source_location: None,
                    },
                    source_location: self.loc(),
                };
            } else {
                update = Statement::ExpressionStatement {
                    expression: update_target,
                    source_location: self.loc(),
                };
            }
            if has_paren {
                self.expect(&Token::RParen);
            }
        } else {
            // No continue expression -- synthesize a no-op
            update = Statement::ExpressionStatement {
                expression: Expression::BigIntLiteral { value: BigInt::from(0) },
                source_location: self.loc(),
            };
        }

        let body = self.parse_block_statements();

        // Emit a for_statement. The init will be patched by parse_block_statements
        // if the preceding statement was a variable_decl for the loop variable.
        Statement::ForStatement {
            init: Box::new(Statement::VariableDecl {
                name: WHILE_NO_INIT_PLACEHOLDER.to_string(),
                var_type: None,
                mutable: true,
                init: Expression::BigIntLiteral { value: BigInt::from(0) },
                source_location: self.loc(),
            }),
            condition,
            update: Box::new(update),
            body,
            source_location: self.loc(),
        }
    }

    fn parse_compound_op(&mut self) -> Option<BinaryOp> {
        match self.peek() {
            Token::PlusEq => { self.advance(); Some(BinaryOp::Add) }
            Token::MinusEq => { self.advance(); Some(BinaryOp::Sub) }
            Token::StarEq => { self.advance(); Some(BinaryOp::Mul) }
            Token::SlashEq => { self.advance(); Some(BinaryOp::Div) }
            Token::PercentEq => { self.advance(); Some(BinaryOp::Mod) }
            _ => None,
        }
    }

    fn skip_unsupported_block(&mut self) {
        while *self.peek() != Token::LBrace
            && *self.peek() != Token::Semicolon
            && *self.peek() != Token::Eof
        {
            self.advance();
        }

        if *self.peek() == Token::Semicolon {
            self.advance();
            return;
        }

        if *self.peek() != Token::LBrace {
            return;
        }

        let mut depth = 0;
        while *self.peek() != Token::Eof {
            if *self.peek() == Token::LBrace {
                depth += 1;
            }
            if *self.peek() == Token::RBrace {
                depth -= 1;
                self.advance();
                if depth <= 0 {
                    break;
                }
                continue;
            }
            self.advance();
        }
    }

    // -----------------------------------------------------------------------
    // Expressions (precedence climbing)
    // -----------------------------------------------------------------------

    fn parse_expression(&mut self) -> Expression {
        self.nested(zero(), |p| p.parse_ternary())
    }

    /// No ternary operator in Zig, but parse_ternary provides the top level.
    fn parse_ternary(&mut self) -> Expression {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Expression {
        let mut left = self.parse_and();
        let mut dt = DepthTracker::new();
        while *self.peek() == Token::OrOr {
            self.advance();
            let right = self.parse_and();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr {
                op: BinaryOp::Or,
                left: Box::new(left),
                right: Box::new(right),
                source_location: None,
            };
        }
        left
    }

    fn parse_and(&mut self) -> Expression {
        let mut left = self.parse_bit_or();
        let mut dt = DepthTracker::new();
        while *self.peek() == Token::AndAnd {
            self.advance();
            let right = self.parse_bit_or();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr {
                op: BinaryOp::And,
                left: Box::new(left),
                right: Box::new(right),
                source_location: None,
            };
        }
        left
    }

    fn parse_bit_or(&mut self) -> Expression {
        let mut left = self.parse_bit_xor();
        let mut dt = DepthTracker::new();
        while *self.peek() == Token::BitOr {
            self.advance();
            let right = self.parse_bit_xor();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr {
                op: BinaryOp::BitOr,
                left: Box::new(left),
                right: Box::new(right),
                source_location: None,
            };
        }
        left
    }

    fn parse_bit_xor(&mut self) -> Expression {
        let mut left = self.parse_bit_and();
        let mut dt = DepthTracker::new();
        while *self.peek() == Token::BitXor {
            self.advance();
            let right = self.parse_bit_and();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr {
                op: BinaryOp::BitXor,
                left: Box::new(left),
                right: Box::new(right),
                source_location: None,
            };
        }
        left
    }

    fn parse_bit_and(&mut self) -> Expression {
        let mut left = self.parse_equality();
        let mut dt = DepthTracker::new();
        while *self.peek() == Token::BitAnd {
            self.advance();
            let right = self.parse_equality();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr {
                op: BinaryOp::BitAnd,
                left: Box::new(left),
                right: Box::new(right),
                source_location: None,
            };
        }
        left
    }

    fn parse_equality(&mut self) -> Expression {
        let mut left = self.parse_comparison();
        let mut dt = DepthTracker::new();
        loop {
            match self.peek() {
                Token::EqEq => {
                    self.advance();
                    let right = self.parse_comparison();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    // == maps to ===
                    left = Expression::BinaryExpr {
                        op: BinaryOp::StrictEq,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: None,
                    };
                }
                Token::NotEq => {
                    self.advance();
                    let right = self.parse_comparison();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    // != maps to !==
                    left = Expression::BinaryExpr {
                        op: BinaryOp::StrictNe,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: None,
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_comparison(&mut self) -> Expression {
        let mut left = self.parse_shift();
        let mut dt = DepthTracker::new();
        loop {
            match self.peek() {
                Token::Lt => {
                    self.advance();
                    let right = self.parse_shift();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Lt,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: None,
                    };
                }
                Token::Le => {
                    self.advance();
                    let right = self.parse_shift();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Le,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: None,
                    };
                }
                Token::Gt => {
                    self.advance();
                    let right = self.parse_shift();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Gt,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: None,
                    };
                }
                Token::Ge => {
                    self.advance();
                    let right = self.parse_shift();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Ge,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: None,
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_shift(&mut self) -> Expression {
        let mut left = self.parse_additive();
        let mut dt = DepthTracker::new();
        loop {
            match self.peek() {
                Token::LShift => {
                    self.advance();
                    let right = self.parse_additive();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Shl,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: None,
                    };
                }
                Token::RShift => {
                    self.advance();
                    let right = self.parse_additive();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Shr,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: None,
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_additive(&mut self) -> Expression {
        let mut left = self.parse_multiplicative();
        let mut dt = DepthTracker::new();
        loop {
            match self.peek() {
                Token::Plus => {
                    self.advance();
                    let right = self.parse_multiplicative();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Add,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: None,
                    };
                }
                Token::Minus => {
                    self.advance();
                    let right = self.parse_multiplicative();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Sub,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: None,
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_multiplicative(&mut self) -> Expression {
        let mut left = self.parse_unary();
        let mut dt = DepthTracker::new();
        loop {
            match self.peek() {
                Token::Star => {
                    self.advance();
                    let right = self.parse_unary();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Mul,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: None,
                    };
                }
                Token::Slash => {
                    self.advance();
                    let right = self.parse_unary();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Div,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: None,
                    };
                }
                Token::Percent => {
                    self.advance();
                    let right = self.parse_unary();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Mod,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: None,
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_unary(&mut self) -> Expression {
        match self.peek() {
            Token::Bang => {
                self.advance();
                let operand = self.nested(zero(), |p| p.parse_unary());
                Expression::UnaryExpr {
                    op: UnaryOp::Not,
                    operand: Box::new(operand),
                    source_location: None,
                }
            }
            Token::Minus => {
                self.advance();
                let operand = self.nested(zero(), |p| p.parse_unary());
                Expression::UnaryExpr {
                    op: UnaryOp::Neg,
                    operand: Box::new(operand),
                    source_location: None,
                }
            }
            Token::Tilde => {
                self.advance();
                let operand = self.nested(zero(), |p| p.parse_unary());
                Expression::UnaryExpr {
                    op: UnaryOp::BitNot,
                    operand: Box::new(operand),
                    source_location: None,
                }
            }
            // Zig's `&` is the address-of operator used for slice coercion
            // at call sites like `&.{sig1, sig2}` (an anonymous-struct
            // literal coerced to a slice) and typed forms like
            // `&[_]T{...}`. Slices have no Rúnar IR analogue -- the inner
            // array literal IS the IR node -- so we simply skip the `&` and
            // parse the operand. Recurse into parse_primary directly,
            // mirroring 01-parse-zig.ts and parse_zig.zig: `&.foo()` is not
            // legal Zig and `&` never pairs with a postfix chain in
            // practice.
            Token::BitAnd => {
                self.advance();
                self.parse_primary()
            }
            _ => {
                let expr = self.parse_primary();
                self.parse_postfix(expr)
            }
        }
    }

    fn parse_primary(&mut self) -> Expression {
        // Slice-literal: &.{ ... } -> array literal. Zig coerces an
        // anonymous tuple to `[]const T` via this leading-`&` form
        // (e.g. `&.{ sig1, sig2 }` for runar.checkMultiSig). The `&`
        // carries no Rúnar semantics. `&` is otherwise a binary
        // bitwise-and consumed at expression level and cannot appear
        // at primary position.
        if *self.peek() == Token::BitAnd
            && *self.peek_at(1) == Token::Dot
            && *self.peek_at(2) == Token::LBrace
        {
            self.advance(); // &
            self.advance(); // .
            self.advance(); // {
            let elements = self.parse_list_elements(&Token::RBrace);
            self.expect(&Token::RBrace);
            return Expression::ArrayLiteral { elements };
        }

        // Anonymous struct literal: .{ ... }
        if *self.peek() == Token::Dot && *self.peek_at(1) == Token::LBrace {
            self.advance(); // .
            self.advance(); // {
            let elements = self.parse_list_elements(&Token::RBrace);
            self.expect(&Token::RBrace);
            return Expression::ArrayLiteral { elements };
        }

        // Number literal
        if matches!(self.peek(), Token::NumberLit(_)) {
            if let Token::NumberLit(v) = self.advance() {
                return Expression::BigIntLiteral { value: v };
            }
        }

        // String literal (hex ByteString)
        if matches!(self.peek(), Token::StringLit(_)) {
            // N-448: a bare non-empty literal is refused (natively ASCII text,
            // to the compiler hex). Exempt: "", the argument of
            // runar.hexToBytes and the body of runar.asm.
            let ok = self.bare_literal_ok.contains(&self.pos);
            let at = self.loc();
            if let Token::StringLit(v) = self.advance() {
                if !v.is_empty() && !ok {
                    self.errors.push(format!(
                        "{}:{}:{}: {}",
                        at.file,
                        at.line,
                        at.column.saturating_sub(1),
                        zig_bare_string_literal_message(&v)
                    ));
                }
                return Expression::ByteStringLiteral { value: v, source_location: Some(at) };
            }
        }

        // Boolean literals
        if *self.peek() == Token::TrueLit {
            self.advance();
            return Expression::BoolLiteral { value: true };
        }
        if *self.peek() == Token::FalseLit {
            self.advance();
            return Expression::BoolLiteral { value: false };
        }

        // Parenthesised expression
        if *self.peek() == Token::LParen {
            self.advance();
            let expr = self.parse_expression();
            self.expect(&Token::RParen);
            return expr;
        }

        // `[_]T{...}` — typed array literal with inferred length. The
        // element type is parsed and discarded; Rúnar infers element types
        // from the literal contents. The element list is the same `{...}`
        // form used by `.{...}` anon-struct literals. Mirrors
        // 01-parse-zig.ts and parse_zig.zig.
        if *self.peek() == Token::LBracket
            && matches!(self.peek_at(1), Token::Ident(n) if n == "_")
            && *self.peek_at(2) == Token::RBracket
        {
            self.advance(); // '['
            self.advance(); // '_'
            self.advance(); // ']'
            self.parse_type(); // discard element type
            self.expect(&Token::LBrace);
            let elements = self.parse_list_elements(&Token::RBrace);
            self.expect(&Token::RBrace);
            return Expression::ArrayLiteral { elements };
        }

        // Array literal: [ ... ]
        if *self.peek() == Token::LBracket {
            self.advance();
            let elements = self.parse_list_elements(&Token::RBracket);
            self.expect(&Token::RBracket);
            return Expression::ArrayLiteral { elements };
        }

        // @builtin: @divTrunc, @mod, @shlExact, @shrExact, @intCast, @truncate, @as, etc.
        if *self.peek() == Token::At {
            self.advance(); // @
            let builtin_name = self.expect_ident();
            return self.parse_at_builtin(&builtin_name);
        }

        // Identifier (including `runar.xxx` stripping)
        if matches!(self.peek(), Token::Ident(_)) {
            let ident_loc = self.loc();
            if let Token::Ident(name) = self.advance() {
                // `runar.xxx` -> strip prefix
                if name == "runar" && *self.peek() == Token::Dot {
                    self.advance(); // .
                    let builtin = self.expect_ident();

                    // runar.bytesEq(a, b) -> a === b
                    if builtin == "bytesEq" && *self.peek() == Token::LParen {
                        self.advance(); // (
                        let left = self.parse_expression();
                        self.expect(&Token::Comma);
                        let right = self.parse_expression();
                        self.expect(&Token::RParen);
                        return Expression::BinaryExpr {
                            op: BinaryOp::StrictEq,
                            left: Box::new(left),
                            right: Box::new(right),
                            source_location: None,
                        };
                    }

                    // runar.hexToBytes("deadbeef") -> ByteString literal "deadbeef".
                    // Mirrors 01-parse-zig.ts and parse_zig.zig (N-090).
                    if builtin == "hexToBytes" && *self.peek() == Token::LParen {
                        self.advance(); // (
                        if matches!(self.peek(), Token::StringLit(_)) {
                            self.bare_literal_ok.insert(self.pos); // N-448: the explicit hex spelling
                        }
                        let arg = self.parse_expression();
                        self.expect(&Token::RParen);
                        if let Expression::ByteStringLiteral { value, source_location } = arg {
                            return Expression::ByteStringLiteral { value, source_location };
                        }
                        self.errors.push(
                            "runar.hexToBytes expects a string literal argument".to_string(),
                        );
                        return Expression::ByteStringLiteral { value: String::new(), source_location: None };
                    }

                    // N-448: the first argument of runar.asm(...) is an opcode body.
                    if builtin == "asm"
                        && *self.peek() == Token::LParen
                        && matches!(self.peek_at(1), Token::StringLit(_))
                    {
                        self.bare_literal_ok.insert(self.pos + 1);
                    }

                    return Expression::Identifier { name: builtin, source_location: None };
                }

                return Expression::Identifier { name, source_location: Some(ident_loc) };
            }
        }

        // Nothing in the grammar starts with this token. Say so (N-144).
        //
        // This used to `self.advance()` and return the literal 0 in silence, so
        // `sum = sum +++ ?? i;` parsed as an expression tree with zeros in it
        // and COMPILED — to a different, well-formed script than the contract
        // the author wrote. parser_ruby.rs has always pushed an error here; this
        // parser was the one missing the arm.
        //
        // The placeholder stays: with `errors` non-empty `parse_source` reports
        // a parse failure and nothing downstream ever sees it. Advancing is what
        // keeps the loop making progress, including at Eof.
        let offending = format!("{:?}", self.peek());
        self.errors
            .push(format!("Unexpected token in expression: {}", offending));
        if *self.peek() != Token::Eof {
            self.advance();
        }
        Expression::BigIntLiteral { value: BigInt::from(0) }
    }

    fn parse_at_builtin(&mut self, name: &str) -> Expression {
        match name {
            // Binary operator builtins
            "divTrunc" | "mod" | "shlExact" | "shrExact" => {
                self.expect(&Token::LParen);
                let left = self.parse_expression();
                self.expect(&Token::Comma);
                let right = self.parse_expression();
                self.expect(&Token::RParen);
                let op = match name {
                    "divTrunc" => BinaryOp::Div,
                    "mod" => BinaryOp::Mod,
                    "shlExact" => BinaryOp::Shl,
                    "shrExact" => BinaryOp::Shr,
                    _ => unreachable!(),
                };
                Expression::BinaryExpr {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                    source_location: None,
                }
            }
            // Cast builtins: return inner expression
            "intCast" | "truncate" => {
                self.expect(&Token::LParen);
                let inner = self.parse_expression();
                self.expect(&Token::RParen);
                inner
            }
            // @as(Type, expr) -> expr
            "as" => {
                self.expect(&Token::LParen);
                self.parse_type(); // skip type argument
                self.expect(&Token::Comma);
                let inner = self.parse_expression();
                self.expect(&Token::RParen);
                inner
            }
            // @import -> skip
            "import" => {
                self.expect(&Token::LParen);
                self.parse_expression();
                self.expect(&Token::RParen);
                Expression::Identifier {
                    name: "__import".to_string(),
                    source_location: None,
                }
            }
            // @embedFile -> return arg
            "embedFile" => {
                self.expect(&Token::LParen);
                let arg = self.parse_expression();
                self.expect(&Token::RParen);
                arg
            }
            // Unknown @builtin
            _ => {
                if *self.peek() == Token::LParen {
                    self.advance(); // (
                    let mut args = Vec::new();
                    if *self.peek() != Token::RParen {
                        args.push(self.parse_expression());
                        while *self.peek() == Token::Comma {
                            self.advance();
                            args.push(self.parse_expression());
                        }
                    }
                    self.expect(&Token::RParen);
                    self.errors
                        .push(format!("Unsupported Zig builtin '@{}'", name));
                    Expression::CallExpr {
                        callee: Box::new(Expression::Identifier {
                            name: name.to_string(),
                            source_location: None,
                        }),
                        args,
                        asm_return_type: None,
                    }
                } else {
                    self.errors
                        .push(format!("Unsupported Zig builtin '@{}'", name));
                    Expression::Identifier {
                        name: name.to_string(),
                        source_location: None,
                    }
                }
            }
        }
    }

    /// F-026: the elements of a call argument list or array literal up to
    /// (not including) `close`. Zig requires `,` between elements (a trailing
    /// one is allowed); without it a stray token after a literal used to
    /// become an extra element.
    fn parse_list_elements(&mut self, close: &Token) -> Vec<Expression> {
        let mut elements = Vec::new();
        while self.peek() != close && *self.peek() != Token::Eof {
            elements.push(self.parse_expression());
            if self.match_tok(&Token::Comma) {
                continue;
            }
            if self.peek() != close {
                self.errors.push(ZIG_LIST_COMMA.to_string());
            }
            break;
        }
        elements
    }

    /// N-033: after a field, parameter or struct-init entry, consume the `,`
    /// that separates it from the next one. Reports ZIG_LIST_COMMA at the
    /// current token and returns false when that token is neither `,` nor
    /// `close`; never consumes `close`.
    fn expect_list_separator(&mut self, close: &Token) -> bool {
        if self.match_tok(&Token::Comma) || self.peek() == close {
            return true;
        }
        let loc = self.loc();
        self.errors.push(format!(
            "{}:{}:{}: {}",
            loc.file,
            loc.line,
            loc.column.saturating_sub(1),
            ZIG_LIST_COMMA
        ));
        false
    }

    /// Report `msg` at the current token, in the `file:line:col: msg` shape
    /// `expect_list_separator` uses (column 0-based).
    fn push_error_at_current(&mut self, msg: &str) {
        let loc = self.loc();
        self.errors.push(format!(
            "{}:{}:{}: {}",
            loc.file,
            loc.line,
            loc.column.saturating_sub(1),
            msg
        ));
    }

    /// Parse postfix operations: `.prop`, `(args)`, `[index]`.
    fn parse_postfix(&mut self, mut expr: Expression) -> Expression {
        let mut dt = DepthTracker::new();
        loop {
            match self.peek() {
                Token::LParen => {
                    self.advance(); // (
                    let mut args = self.parse_list_elements(&Token::RParen);
                    self.expect(&Token::RParen);
                    // N-453: the StatefulContext parameter is elided from every
                    // method's parameter list, so a `self.helper(ctx, ...)` call
                    // drops the bare handle too and the arities agree. Anywhere
                    // else (including the output intrinsics) a bare `ctx` stays
                    // an identifier and is refused as an undefined variable.
                    if let Expression::PropertyAccess { ref property, .. } = expr {
                        if !ZIG_STATEFUL_CONTEXT_MEMBERS.contains(&property.as_str()) {
                            let ctx_names = &self.stateful_context_names;
                            args.retain(|a| {
                                !matches!(a, Expression::Identifier { name, .. } if ctx_names.contains(name))
                            });
                        }
                    }
                    let arg_refs: Vec<&Expression> = args.iter().collect();
                    if !self.grow(&mut dt, &expr, &arg_refs) { break; }
                    expr = Expression::CallExpr {
                        callee: Box::new(expr),
                        args,
                        asm_return_type: None,
                    };
                }
                Token::Dot => {
                    self.advance(); // .
                    let prop = self.expect_ident();

                    // self.property -> PropertyAccess
                    if let Expression::Identifier { ref name, .. } = expr {
                        if self.self_names.contains(name) {
                            expr = Expression::PropertyAccess {
                                property: prop,
                                source_location: None,
                            };
                            dt = DepthTracker::new();
                            continue;
                        }
                        // StatefulContext param -> PropertyAccess for intrinsics
                        if self.stateful_context_names.contains(name) {
                            if prop == "txPreimage"
                                || prop == "getStateScript"
                                || prop == "addOutput"
                                || prop == "addRawOutput"
                                || prop == "addDataOutput"
                            {
                                expr = Expression::PropertyAccess { property: prop, source_location: None };
                                dt = DepthTracker::new();
                                continue;
                            }
                        }
                    }

                    if !self.grow(&mut dt, &expr, &[]) { break; }
                    expr = Expression::MemberExpr {
                        object: Box::new(expr),
                        property: prop,
                    };
                }
                Token::LBracket => {
                    self.advance(); // [
                    let index = self.parse_expression();
                    self.expect(&Token::RBracket);
                    if !self.grow(&mut dt, &expr, &[&index]) { break; }
                    expr = Expression::IndexAccess {
                        object: Box::new(expr),
                        index: Box::new(index),
                    };
                }
                _ => break,
            }
        }
        expr
    }
}

/// Placeholder expression returned by a parse cut short by the F-213 limit.
fn zero() -> Expression {
    Expression::BigIntLiteral { value: BigInt::from(0) }
}

// ---------------------------------------------------------------------------
// Constructor builder (auto-generate when no init() provided)
// ---------------------------------------------------------------------------

fn build_constructor(properties: &[PropertyNode], file: &str) -> MethodNode {
    // Properties with initializers do not need constructor parameters.
    let required_props: Vec<&PropertyNode> =
        properties.iter().filter(|p| p.initializer.is_none()).collect();

    let params: Vec<ParamNode> = required_props
        .iter()
        .map(|p| ParamNode {
            name: p.name.clone(),
            param_type: p.prop_type.clone(),
        })
        .collect();

    let mut body: Vec<Statement> = Vec::new();

    // super(...) call
    let super_args: Vec<Expression> = required_props
        .iter()
        .map(|p| Expression::Identifier {
            name: p.name.clone(),
            source_location: None,
        })
        .collect();
    body.push(Statement::ExpressionStatement {
        expression: Expression::CallExpr {
            callee: Box::new(Expression::Identifier {
                name: "super".to_string(),
                source_location: None,
            }),
            args: super_args,
            asm_return_type: None,
        },
        source_location: SourceLocation {
            file: file.to_string(),
            line: 1,
            column: 0,
        },
    });

    // this.x = x for each required property
    for p in &required_props {
        body.push(Statement::Assignment {
            target: Expression::PropertyAccess {
                property: p.name.clone(),
                source_location: None,
            },
            value: Expression::Identifier {
                name: p.name.clone(),
                source_location: None,
            },
            source_location: SourceLocation {
                file: file.to_string(),
                line: 1,
                column: 0,
            },
        });
    }

    MethodNode {
        name: "constructor".to_string(),
        params,
        body,
        visibility: Visibility::Public,
        source_location: SourceLocation {
            file: file.to_string(),
            line: 1,
            column: 0,
        },
        sighash_type: None,
    }
}

// ---------------------------------------------------------------------------
// Helper: get loop update target name from a ForStatement
// ---------------------------------------------------------------------------

fn get_loop_update_target(stmt: &Statement) -> Option<String> {
    if let Statement::ForStatement { update, .. } = stmt {
        match update.as_ref() {
            Statement::Assignment { target, .. } => {
                if let Expression::Identifier { name, .. } = target {
                    return Some(name.clone());
                }
            }
            Statement::ExpressionStatement { expression, .. } => {
                if let Expression::Identifier { name, .. } = expression {
                    return Some(name.clone());
                }
            }
            _ => {}
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Bare method call rewriter
// ---------------------------------------------------------------------------

/// Rewrite bare function calls to declared contract methods as `this.method()` calls.
/// In Zig, `computeThreshold(a, b)` is equivalent to `self.computeThreshold(a, b)`.
fn rewrite_bare_method_calls(stmts: &mut [Statement], method_names: &HashSet<String>) {
    for stmt in stmts.iter_mut() {
        rewrite_stmt(stmt, method_names);
    }
}

fn rewrite_expr(expr: &mut Expression, method_names: &HashSet<String>) {
    match expr {
        Expression::CallExpr { callee, args, .. } => {
            for arg in args.iter_mut() {
                rewrite_expr(arg, method_names);
            }
            if let Expression::Identifier { name, .. } = callee.as_ref() {
                if method_names.contains(name) {
                    *callee = Box::new(Expression::PropertyAccess {
                        property: name.clone(),
                        source_location: None,
                    });
                }
            } else {
                rewrite_expr(callee.as_mut(), method_names);
            }
        }
        Expression::BinaryExpr { left, right, .. } => {
            rewrite_expr(left.as_mut(), method_names);
            rewrite_expr(right.as_mut(), method_names);
        }
        Expression::UnaryExpr { operand, .. } => {
            rewrite_expr(operand.as_mut(), method_names);
        }
        Expression::TernaryExpr {
            condition,
            consequent,
            alternate,
        } => {
            rewrite_expr(condition.as_mut(), method_names);
            rewrite_expr(consequent.as_mut(), method_names);
            rewrite_expr(alternate.as_mut(), method_names);
        }
        Expression::MemberExpr { object, .. } => {
            rewrite_expr(object.as_mut(), method_names);
        }
        Expression::IndexAccess { object, index } => {
            rewrite_expr(object.as_mut(), method_names);
            rewrite_expr(index.as_mut(), method_names);
        }
        Expression::ArrayLiteral { elements } => {
            for elem in elements.iter_mut() {
                rewrite_expr(elem, method_names);
            }
        }
        _ => {}
    }
}

fn rewrite_stmt(stmt: &mut Statement, method_names: &HashSet<String>) {
    match stmt {
        Statement::ExpressionStatement { expression, .. } => {
            rewrite_expr(expression, method_names);
        }
        Statement::VariableDecl { init, .. } => {
            rewrite_expr(init, method_names);
        }
        Statement::Assignment { target, value, .. } => {
            rewrite_expr(target, method_names);
            rewrite_expr(value, method_names);
        }
        Statement::ReturnStatement { value, .. } => {
            if let Some(v) = value {
                rewrite_expr(v, method_names);
            }
        }
        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            ..
        } => {
            rewrite_expr(condition, method_names);
            rewrite_bare_method_calls(then_branch, method_names);
            if let Some(else_stmts) = else_branch {
                rewrite_bare_method_calls(else_stmts, method_names);
            }
        }
        Statement::ForStatement {
            init,
            condition,
            update,
            body,
            ..
        } => {
            rewrite_stmt(init.as_mut(), method_names);
            rewrite_expr(condition, method_names);
            rewrite_stmt(update.as_mut(), method_names);
            rewrite_bare_method_calls(body, method_names);
        }
    }
}

// ---------------------------------------------------------------------------
// Mutation detection: walk method bodies to find `this.<prop> = …` writes.
// ---------------------------------------------------------------------------

fn collect_mutated_properties(body: &[Statement], out: &mut HashSet<String>) {
    for stmt in body {
        collect_mutated_in_stmt(stmt, out);
    }
}

fn collect_mutated_in_stmt(stmt: &Statement, out: &mut HashSet<String>) {
    match stmt {
        Statement::Assignment { target, value, .. } => {
            if let Expression::PropertyAccess { property, .. } = target {
                out.insert(property.clone());
            }
            collect_mutated_in_expr(target, out);
            collect_mutated_in_expr(value, out);
        }
        Statement::VariableDecl { init, .. } => {
            collect_mutated_in_expr(init, out);
        }
        Statement::ExpressionStatement { expression, .. } => {
            collect_mutated_in_expr(expression, out);
        }
        Statement::ReturnStatement { value, .. } => {
            if let Some(v) = value {
                collect_mutated_in_expr(v, out);
            }
        }
        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            ..
        } => {
            collect_mutated_in_expr(condition, out);
            collect_mutated_properties(then_branch, out);
            if let Some(els) = else_branch {
                collect_mutated_properties(els, out);
            }
        }
        Statement::ForStatement {
            init,
            condition,
            update,
            body,
            ..
        } => {
            collect_mutated_in_stmt(init, out);
            collect_mutated_in_expr(condition, out);
            collect_mutated_in_stmt(update, out);
            collect_mutated_properties(body, out);
        }
    }
}

fn collect_mutated_in_expr(expr: &Expression, out: &mut HashSet<String>) {
    match expr {
        Expression::BinaryExpr { left, right, .. } => {
            collect_mutated_in_expr(left, out);
            collect_mutated_in_expr(right, out);
        }
        Expression::UnaryExpr { operand, .. } => {
            collect_mutated_in_expr(operand, out);
        }
        Expression::CallExpr { callee, args, .. } => {
            collect_mutated_in_expr(callee, out);
            for a in args {
                collect_mutated_in_expr(a, out);
            }
        }
        Expression::MemberExpr { object, .. } => {
            collect_mutated_in_expr(object, out);
        }
        Expression::TernaryExpr {
            condition,
            consequent,
            alternate,
        } => {
            collect_mutated_in_expr(condition, out);
            collect_mutated_in_expr(consequent, out);
            collect_mutated_in_expr(alternate, out);
        }
        Expression::IndexAccess { object, index } => {
            collect_mutated_in_expr(object, out);
            collect_mutated_in_expr(index, out);
        }
        Expression::IncrementExpr { operand, .. } | Expression::DecrementExpr { operand, .. } => {
            if let Expression::PropertyAccess { property, .. } = operand.as_ref() {
                out.insert(property.clone());
            }
            collect_mutated_in_expr(operand, out);
        }
        Expression::ArrayLiteral { elements } => {
            for e in elements {
                collect_mutated_in_expr(e, out);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_mapping() {
        assert_eq!(map_zig_type("i64"), "bigint");
        assert_eq!(map_zig_type("u32"), "bigint");
        assert_eq!(map_zig_type("bool"), "boolean");
        assert_eq!(map_zig_type("void"), "void");
        assert_eq!(map_zig_type("Addr"), "Addr");
        assert_eq!(map_zig_type("PubKey"), "PubKey");
        assert_eq!(map_zig_type("ByteString"), "ByteString");
        assert_eq!(map_zig_type("CustomType"), "CustomType");
    }

    // N-182 / R93: runar.BigintBig is the 256-bit native spelling (u256 in
    // packages/runar-zig) for EC coordinates. Proves: it lowers to the same
    // AST bigint as runar.Bigint, for a property and a parameter. Does NOT
    // prove the native u256 runtime or any codegen.
    #[test]
    fn test_bigint_big_maps_to_bigint() {
        assert_eq!(map_zig_type("BigintBig"), "bigint");
        let source = r#"
const runar = @import("runar");

pub const BigCoord = struct {
    pub const Contract = runar.SmartContract;

    x: runar.BigintBig,

    pub fn init(x: runar.BigintBig) BigCoord {
        return .{ .x = x };
    }

    pub fn check(self: *const BigCoord, y: runar.BigintBig) void {
        runar.assert(self.x == y);
    }
};
"#;
        let result = parse_zig(source, Some("BigCoord.runar.zig"));
        assert!(
            result.errors.is_empty(),
            "Unexpected errors: {:?}",
            result.error_strings()
        );
        let contract = result.contract.unwrap();
        assert_eq!(contract.properties.len(), 1);
        assert!(
            matches!(contract.properties[0].prop_type, TypeNode::Primitive(PrimitiveTypeName::Bigint)),
            "expected bigint, got {:?}",
            contract.properties[0].prop_type
        );
        assert_eq!(contract.methods.len(), 1);
        assert_eq!(contract.methods[0].params.len(), 1);
        assert!(
            matches!(contract.methods[0].params[0].param_type, TypeNode::Primitive(PrimitiveTypeName::Bigint)),
            "expected bigint, got {:?}",
            contract.methods[0].params[0].param_type
        );
    }

    #[test]
    fn test_parse_simple_zig_contract() {
        let source = r#"
const runar = @import("runar");

pub const P2PKH = struct {
    pub const Contract = runar.SmartContract;

    pubKeyHash: runar.Addr,

    pub fn init(pubKeyHash: runar.Addr) P2PKH {
        return .{ .pubKeyHash = pubKeyHash };
    }

    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
        runar.assert(runar.hash160(pubKey) == self.pubKeyHash);
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
"#;

        let result = parse_zig(source, Some("P2PKH.runar.zig"));
        assert!(
            result.errors.is_empty(),
            "Unexpected errors: {:?}",
            result.error_strings()
        );
        let contract = result.contract.unwrap();
        assert_eq!(contract.name, "P2PKH");
        assert_eq!(contract.parent_class, "SmartContract");
        assert_eq!(contract.properties.len(), 1);
        assert_eq!(contract.properties[0].name, "pubKeyHash");
        assert!(contract.properties[0].readonly);
        assert_eq!(contract.constructor.name, "constructor");
        assert_eq!(contract.methods.len(), 1);
        assert_eq!(contract.methods[0].name, "unlock");
        assert_eq!(contract.methods[0].visibility, Visibility::Public);
        // unlock params: sig, pubKey (self is filtered)
        assert_eq!(contract.methods[0].params.len(), 2);
        assert_eq!(contract.methods[0].params[0].name, "sig");
        assert_eq!(contract.methods[0].params[1].name, "pubKey");
    }

    #[test]
    fn test_parse_stateful_counter() {
        let source = r#"
const runar = @import("runar");

pub const Counter = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,

    pub fn init(count: i64) Counter {
        return .{ .count = count };
    }

    pub fn increment(self: *Counter) void {
        self.count += 1;
    }

    pub fn decrement(self: *Counter) void {
        runar.assert(self.count > 0);
        self.count -= 1;
    }
};
"#;

        let result = parse_zig(source, Some("Counter.runar.zig"));
        assert!(
            result.errors.is_empty(),
            "Unexpected errors: {:?}",
            result.error_strings()
        );
        let contract = result.contract.unwrap();
        assert_eq!(contract.name, "Counter");
        assert_eq!(contract.parent_class, "StatefulSmartContract");
        assert_eq!(contract.properties.len(), 1);
        assert_eq!(contract.properties[0].name, "count");
        // count is mutated in increment/decrement -> not readonly.
        assert!(!contract.properties[0].readonly);
        // F-207: `count: i64 = 0` collides with `pub fn init(count: i64)`,
        // and the constructor assigns that param to `count`. The PARSER no
        // longer strips the initializer for this -- that decision now
        // belongs exclusively to anf_lower.rs's
        // `constructor_assigned_properties`, keyed on the actual
        // constructor assignment rather than a name coincidence, matching
        // the TS reference's explicit architecture (01-parse-zig.ts:424-434:
        // "no longer stripped here").
        assert!(contract.properties[0].initializer.is_some());
        assert_eq!(contract.methods.len(), 2);
        assert_eq!(contract.methods[0].name, "increment");
        assert_eq!(contract.methods[1].name, "decrement");
        // Both methods have self filtered
        assert_eq!(contract.methods[0].params.len(), 0);
        assert_eq!(contract.methods[1].params.len(), 0);
    }

    #[test]
    fn test_parse_while_loop() {
        let source = r#"
const runar = @import("runar");

pub const BoundedLoop = struct {
    pub const Contract = runar.SmartContract;

    expectedSum: i64,

    pub fn init(expectedSum: i64) BoundedLoop {
        return .{ .expectedSum = expectedSum };
    }

    pub fn verify(self: *const BoundedLoop, start: i64) void {
        var sum: i64 = 0;
        var i: i64 = 0;
        while (i < 5) : (i += 1) {
            sum = sum + start + i;
        }
        runar.assert(sum == self.expectedSum);
    }
};
"#;

        let result = parse_zig(source, Some("BoundedLoop.runar.zig"));
        assert!(
            result.errors.is_empty(),
            "Unexpected errors: {:?}",
            result.error_strings()
        );
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods.len(), 1);
        let verify = &contract.methods[0];
        assert_eq!(verify.name, "verify");
        // Should have a for statement (merged while + var init)
        let has_for = verify.body.iter().any(|s| matches!(s, Statement::ForStatement { .. }));
        assert!(has_for, "Expected a ForStatement in the verify method body");
    }

    #[test]
    fn test_parse_if_else() {
        let source = r#"
const runar = @import("runar");

pub const IfElse = struct {
    pub const Contract = runar.SmartContract;

    limit: i64,

    pub fn init(limit: i64) IfElse {
        return .{ .limit = limit };
    }

    pub fn check(self: *const IfElse, value: i64, mode: bool) void {
        var result: i64 = 0;
        if (mode) {
            result = value + self.limit;
        } else {
            result = value - self.limit;
        }
        runar.assert(result > 0);
    }
};
"#;

        let result = parse_zig(source, Some("IfElse.runar.zig"));
        assert!(
            result.errors.is_empty(),
            "Unexpected errors: {:?}",
            result.error_strings()
        );
        let contract = result.contract.unwrap();
        let check = &contract.methods[0];
        let has_if = check.body.iter().any(|s| matches!(s, Statement::IfStatement { .. }));
        assert!(has_if, "Expected an IfStatement in the check method body");
    }

    #[test]
    fn test_parse_multi_method_with_private() {
        let source = r#"
const runar = @import("runar");

pub const MultiMethod = struct {
    pub const Contract = runar.SmartContract;

    owner: runar.PubKey,
    backup: runar.PubKey,

    pub fn init(owner: runar.PubKey, backup: runar.PubKey) MultiMethod {
        return .{ .owner = owner, .backup = backup };
    }

    fn computeThreshold(a: i64, b: i64) i64 {
        return a * b + 1;
    }

    pub fn spendWithOwner(self: *const MultiMethod, sig: runar.Sig, amount: i64) void {
        const threshold = computeThreshold(amount, 2);
        runar.assert(threshold > 10);
        runar.assert(runar.checkSig(sig, self.owner));
    }

    pub fn spendWithBackup(self: *const MultiMethod, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.backup));
    }
};
"#;

        let result = parse_zig(source, Some("MultiMethod.runar.zig"));
        assert!(
            result.errors.is_empty(),
            "Unexpected errors: {:?}",
            result.error_strings()
        );
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods.len(), 3);
        // Private method
        assert_eq!(contract.methods[0].name, "computeThreshold");
        assert_eq!(contract.methods[0].visibility, Visibility::Private);
        // Private method has no self, so both params are kept
        assert_eq!(contract.methods[0].params.len(), 2);
        // Public methods
        assert_eq!(contract.methods[1].name, "spendWithOwner");
        assert_eq!(contract.methods[1].visibility, Visibility::Public);
        assert_eq!(contract.methods[2].name, "spendWithBackup");

        // The call to computeThreshold should be rewritten to this.computeThreshold
        let spend_body = &contract.methods[1].body;
        if let Statement::VariableDecl { init, .. } = &spend_body[0] {
            if let Expression::CallExpr { callee, .. } = init {
                assert!(
                    matches!(callee.as_ref(), Expression::PropertyAccess { property, .. } if property == "computeThreshold"),
                    "Expected computeThreshold call to be rewritten to PropertyAccess"
                );
            } else {
                panic!("Expected CallExpr as init of threshold variable");
            }
        } else {
            panic!("Expected VariableDecl as first statement in spendWithOwner");
        }
    }

    #[test]
    fn test_parse_divtrunc_builtin() {
        let source = r#"
const runar = @import("runar");

pub const Arithmetic = struct {
    pub const Contract = runar.SmartContract;

    target: i64,

    pub fn init(target: i64) Arithmetic {
        return .{ .target = target };
    }

    pub fn verify(self: *const Arithmetic, a: i64, b: i64) void {
        const quot = @divTrunc(a, b);
        runar.assert(quot == self.target);
    }
};
"#;

        let result = parse_zig(source, Some("Arithmetic.runar.zig"));
        assert!(
            result.errors.is_empty(),
            "Unexpected errors: {:?}",
            result.error_strings()
        );
        let contract = result.contract.unwrap();
        let verify = &contract.methods[0];
        // First statement should be `const quot = a / b;` (desugared @divTrunc)
        if let Statement::VariableDecl { init, .. } = &verify.body[0] {
            assert!(
                matches!(init, Expression::BinaryExpr { op: BinaryOp::Div, .. }),
                "Expected BinaryExpr with Div op from @divTrunc"
            );
        } else {
            panic!("Expected VariableDecl as first statement in verify");
        }
    }

    #[test]
    fn test_parse_property_initializers() {
        let source = r#"
const runar = @import("runar");

pub const PropertyInitializers = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,
    maxCount: i64,
    active: runar.Readonly(bool) = true,

    pub fn init(maxCount: i64) PropertyInitializers {
        return .{ .maxCount = maxCount };
    }

    pub fn increment(self: *PropertyInitializers, amount: i64) void {
        runar.assert(self.active);
        self.count = self.count + amount;
        runar.assert(self.count <= self.maxCount);
    }

    pub fn reset(self: *PropertyInitializers) void {
        self.count = 0;
    }
};
"#;

        let result = parse_zig(source, Some("PropertyInitializers.runar.zig"));
        assert!(
            result.errors.is_empty(),
            "Unexpected errors: {:?}",
            result.error_strings()
        );
        let contract = result.contract.unwrap();
        assert_eq!(contract.parent_class, "StatefulSmartContract");
        assert_eq!(contract.properties.len(), 3);

        // count: has initializer, not readonly (stateful + has initializer)
        assert_eq!(contract.properties[0].name, "count");
        assert!(!contract.properties[0].readonly);
        assert!(contract.properties[0].initializer.is_some());

        // maxCount: no initializer -> readonly
        assert_eq!(contract.properties[1].name, "maxCount");
        assert!(contract.properties[1].readonly);
        assert!(contract.properties[1].initializer.is_none());

        // active: has Readonly wrapper -> readonly
        assert_eq!(contract.properties[2].name, "active");
        assert!(contract.properties[2].readonly);
        assert!(contract.properties[2].initializer.is_some());

        // Constructor should only have maxCount as parameter
        assert_eq!(contract.constructor.params.len(), 1);
        assert_eq!(contract.constructor.params[0].name, "maxCount");
    }

    #[test]
    fn test_parse_auto_generated_constructor() {
        let source = r#"
const runar = @import("runar");

pub const Simple = struct {
    pub const Contract = runar.SmartContract;

    value: i64,

    pub fn check(self: *const Simple) void {
        runar.assert(self.value > 0);
    }
};
"#;

        let result = parse_zig(source, Some("Simple.runar.zig"));
        assert!(
            result.errors.is_empty(),
            "Unexpected errors: {:?}",
            result.error_strings()
        );
        let contract = result.contract.unwrap();
        // Auto-generated constructor
        assert_eq!(contract.constructor.name, "constructor");
        assert_eq!(contract.constructor.params.len(), 1);
        assert_eq!(contract.constructor.params[0].name, "value");
        // Should have super(...) call + this.value = value
        assert!(contract.constructor.body.len() >= 2);
    }
}
