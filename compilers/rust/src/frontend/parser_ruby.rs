//! Ruby parser for Rúnar contracts (.runar.rb).
//!
//! Parses Ruby-style contract definitions using a hand-written tokenizer
//! and recursive descent parser. Produces the same AST as the TypeScript
//! and Python parsers.
//!
//! ## Expected format
//!
//! ```ruby
//! require 'runar'
//!
//! class P2PKH < Runar::SmartContract
//!   prop :pub_key_hash, Addr
//!
//!   def initialize(pub_key_hash)
//!     super(pub_key_hash)
//!     @pub_key_hash = pub_key_hash
//!   end
//!
//!   runar_public sig: Sig, pub_key: PubKey
//!   def unlock(sig, pub_key)
//!     assert hash160(pub_key) == @pub_key_hash
//!     assert check_sig(sig, pub_key)
//!   end
//! end
//! ```
//!
//! Key mappings:
//! - `class Foo < Runar::SmartContract` -> contract
//! - `runar_public` -> Visibility::Public for the next method
//! - `params` -> pending param types for a private method
//! - `prop :name, Type` -> PropertyNode
//! - `@ivar` -> PropertyAccess (like `this.prop`)
//! - `assert expr` -> assert(expr)
//! - `**` -> pow() call
//! - `and`/`or`/`not` -> And/Or/Not operators
//! - `==`/`!=` -> StrictEq/StrictNe
//! - `for i in start...end` -> ForStatement (exclusive)
//! - `for i in start..end` -> ForStatement (inclusive)
//! - `unless` -> if with negated condition
//! - snake_case identifiers -> camelCase in AST

use super::ast::{
    BinaryOp, ContractNode, Expression, MethodNode, ParamNode, PrimitiveTypeName, PropertyNode,
    SourceLocation, Statement, TypeNode, UnaryOp, Visibility,
};
use super::parser::ParseResult;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a Ruby-format Rúnar contract source.
pub fn parse_ruby(source: &str, file_name: Option<&str>) -> ParseResult {
    use super::diagnostic::Diagnostic;

    let file = file_name.unwrap_or("contract.runar.rb");
    let mut str_errors: Vec<String> = Vec::new();

    let tokens = tokenize(source);
    let mut parser = RbParser::new(tokens, file, &mut str_errors);

    let contract = parser.parse_contract();

    let errors = str_errors
        .into_iter()
        .map(|msg| Diagnostic::error(msg, None))
        .collect();

    ParseResult { contract, errors }
}

// ---------------------------------------------------------------------------
// Name conversion helpers
// ---------------------------------------------------------------------------

/// Convert snake_case to camelCase. Single words pass through unchanged.
fn snake_to_camel(name: &str) -> String {
    // Strip leading underscores so `_require_owner` becomes `requireOwner` not `RequireOwner`.
    let stripped = name.trim_start_matches('_');
    if stripped.is_empty() {
        return name.to_string();
    }
    let mut result = String::new();
    let mut capitalize_next = false;

    for ch in stripped.chars() {
        if ch == '_' {
            capitalize_next = true;
        } else if capitalize_next {
            result.push(ch.to_ascii_uppercase());
            capitalize_next = false;
        } else {
            result.push(ch);
        }
    }

    result
}

/// Map Ruby builtin function names to Rúnar AST callee names.
fn map_builtin_name(name: &str) -> String {
    // Exact-match special cases (names that don't follow simple snake_case -> camelCase)
    match name {
        "verify_wots" => return "verifyWOTS".to_string(),
        "verify_slh_dsa_sha2_128s" => return "verifySLHDSA_SHA2_128s".to_string(),
        "verify_slh_dsa_sha2_128f" => return "verifySLHDSA_SHA2_128f".to_string(),
        "verify_slh_dsa_sha2_192s" => return "verifySLHDSA_SHA2_192s".to_string(),
        "verify_slh_dsa_sha2_192f" => return "verifySLHDSA_SHA2_192f".to_string(),
        "verify_slh_dsa_sha2_256s" => return "verifySLHDSA_SHA2_256s".to_string(),
        "verify_slh_dsa_sha2_256f" => return "verifySLHDSA_SHA2_256f".to_string(),
        "verify_rabin_sig" => return "verifyRabinSig".to_string(),
        "check_sig" => return "checkSig".to_string(),
        "check_multi_sig" => return "checkMultiSig".to_string(),
        "check_preimage" => return "checkPreimage".to_string(),
        "hash160" => return "hash160".to_string(),
        "hash256" => return "hash256".to_string(),
        "sha256" => return "sha256".to_string(),
        "ripemd160" => return "ripemd160".to_string(),
        "num2bin" => return "num2bin".to_string(),
        "reverse_bytes" => return "reverseBytes".to_string(),
        "extract_locktime" => return "extractLocktime".to_string(),
        "extract_output_hash" => return "extractOutputHash".to_string(),
        "extract_amount" => return "extractAmount".to_string(),
        "extract_version" => return "extractVersion".to_string(),
        "extract_sequence" => return "extractSequence".to_string(),
        "ec_add" => return "ecAdd".to_string(),
        "ec_mul" => return "ecMul".to_string(),
        "ec_mul_gen" => return "ecMulGen".to_string(),
        "ec_negate" => return "ecNegate".to_string(),
        "ec_on_curve" => return "ecOnCurve".to_string(),
        "ec_mod_reduce" => return "ecModReduce".to_string(),
        "ec_encode_compressed" => return "ecEncodeCompressed".to_string(),
        "ec_make_point" => return "ecMakePoint".to_string(),
        "ec_point_x" => return "ecPointX".to_string(),
        "ec_point_y" => return "ecPointY".to_string(),
        "mul_div" => return "mulDiv".to_string(),
        "percent_of" => return "percentOf".to_string(),
        "safe_div" => return "safediv".to_string(),
        "safe_mod" => return "safemod".to_string(),
        "div_mod" => return "divmod".to_string(),
        "bin2num" => return "bin2num".to_string(),
        "add_output" => return "addOutput".to_string(),
        "add_raw_output" => return "addRawOutput".to_string(),
        "get_state_script" => return "getStateScript".to_string(),
        // SHA-256 partial verification
        "sha256_compress" => return "sha256Compress".to_string(),
        "sha256_finalize" => return "sha256Finalize".to_string(),
        // Transaction intrinsics
        "extract_nsequence" => return "extractNSequence".to_string(),
        "extract_hash_prevouts" => return "extractHashPrevouts".to_string(),
        "extract_hash_sequence" => return "extractHashSequence".to_string(),
        "extract_outpoint" => return "extractOutpoint".to_string(),
        "extract_script_code" => return "extractScriptCode".to_string(),
        "extract_input_index" => return "extractInputIndex".to_string(),
        "extract_sig_hash_type" => return "extractSigHashType".to_string(),
        "extract_outputs" => return "extractOutputs".to_string(),
        // EC constants
        "EC_P" => return "EC_P".to_string(),
        "EC_N" => return "EC_N".to_string(),
        "EC_G" => return "EC_G".to_string(),
        _ => {}
    }

    // Names that pass through unchanged
    match name {
        "bool" | "abs" | "min" | "max" | "len" | "pow" | "cat" | "within" | "safediv"
        | "safemod" | "clamp" | "sign" | "sqrt" | "gcd" | "divmod" | "log2" | "substr" => {
            return name.to_string();
        }
        _ => {}
    }

    // Default: snake_case -> camelCase
    snake_to_camel(name)
}

/// Map Ruby type names to Rúnar AST types.
fn map_rb_type(name: &str) -> &str {
    match name {
        "Bigint" | "Integer" | "Int" => "bigint",
        "Boolean" => "boolean",
        "ByteString" => "ByteString",
        "PubKey" => "PubKey",
        "Sig" => "Sig",
        "Addr" => "Addr",
        "Sha256" => "Sha256",
        "Ripemd160" => "Ripemd160",
        "SigHashPreimage" => "SigHashPreimage",
        "RabinSig" => "RabinSig",
        "RabinPubKey" => "RabinPubKey",
        "Point" => "Point",
        _ => name,
    }
}

// ---------------------------------------------------------------------------
// Tokeniser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    // Keywords
    Class,
    Def,
    If,
    Elsif,
    Else,
    Unless,
    For,
    In,
    End,
    Return,
    TrueLit,
    FalseLit,
    NilLit,
    And,
    Or,
    Not,
    Super,
    Require,
    Assert,
    Do,

    // Identifiers and literals
    Ident(String),
    NumberLit(i64),
    HexStringLit(String),  // single-quoted strings
    StringLit(String),      // double-quoted strings
    Symbol(String),         // :name
    Ivar(String),           // @name

    // Operators
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    DoubleStar,   // **
    EqEq,         // ==
    NotEq,        // !=
    Lt,
    Le,
    Gt,
    Ge,
    LShift,       // <<
    RShift,       // >>
    AndAnd,       // &&
    OrOr,         // ||
    BitAnd,       // &
    BitOr,        // |
    BitXor,       // ^
    Tilde,        // ~
    Bang,         // !
    Eq,           // =
    PlusEq,       // +=
    MinusEq,      // -=
    StarEq,       // *=
    SlashEq,      // /=
    PercentEq,    // %=
    DotDotDot,    // ... (exclusive range)
    DotDot,       // ..  (inclusive range)
    Question,     // ?
    ColonColon,   // ::

    // Delimiters
    LParen,
    RParen,
    LBracket,
    RBracket,
    Colon,
    Comma,
    Dot,

    // Line separator
    Newline,

    // Special
    Eof,
}

fn tokenize(source: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let lines: Vec<&str> = source.split('\n').collect();
    let mut paren_depth: usize = 0;

    for raw_line in &lines {
        // Strip trailing \r
        let line = if raw_line.ends_with('\r') {
            &raw_line[..raw_line.len() - 1]
        } else {
            raw_line
        };

        // Skip blank lines and comment-only lines
        let stripped = line.trim_start();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }

        let chars: Vec<char> = line.chars().collect();
        let start_offset = chars.len() - stripped.len();
        let mut pos = start_offset;

        while pos < chars.len() {
            let ch = chars[pos];

            // Whitespace within line
            if ch == ' ' || ch == '\t' {
                pos += 1;
                continue;
            }

            // Comment
            if ch == '#' {
                break; // rest of line is comment
            }

            // Instance variable: @name
            if ch == '@' {
                pos += 1;
                let start = pos;
                while pos < chars.len()
                    && (chars[pos].is_ascii_alphanumeric() || chars[pos] == '_')
                {
                    pos += 1;
                }
                if pos > start {
                    let name: String = chars[start..pos].iter().collect();
                    tokens.push(Token::Ivar(name));
                } else {
                    // bare @ — unlikely but handle gracefully
                    tokens.push(Token::Ident("@".to_string()));
                }
                continue;
            }

            // Three-dot range operator: ...
            if ch == '.'
                && pos + 2 < chars.len()
                && chars[pos + 1] == '.'
                && chars[pos + 2] == '.'
            {
                tokens.push(Token::DotDotDot);
                pos += 3;
                continue;
            }

            // Two-dot range operator: ..
            if ch == '.' && pos + 1 < chars.len() && chars[pos + 1] == '.' {
                tokens.push(Token::DotDot);
                pos += 2;
                continue;
            }

            // Two-char operators: ** :: == != <= >= << >> && || += -= *= /= %=
            if ch == '*' && pos + 1 < chars.len() && chars[pos + 1] == '*' {
                tokens.push(Token::DoubleStar);
                pos += 2;
                continue;
            }
            if ch == ':' && pos + 1 < chars.len() && chars[pos + 1] == ':' {
                tokens.push(Token::ColonColon);
                pos += 2;
                continue;
            }
            if ch == '=' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::EqEq);
                pos += 2;
                continue;
            }
            if ch == '!' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::NotEq);
                pos += 2;
                continue;
            }
            if ch == '<' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::Le);
                pos += 2;
                continue;
            }
            if ch == '>' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::Ge);
                pos += 2;
                continue;
            }
            if ch == '<' && pos + 1 < chars.len() && chars[pos + 1] == '<' {
                tokens.push(Token::LShift);
                pos += 2;
                continue;
            }
            if ch == '>' && pos + 1 < chars.len() && chars[pos + 1] == '>' {
                tokens.push(Token::RShift);
                pos += 2;
                continue;
            }
            if ch == '&' && pos + 1 < chars.len() && chars[pos + 1] == '&' {
                tokens.push(Token::AndAnd);
                pos += 2;
                continue;
            }
            if ch == '|' && pos + 1 < chars.len() && chars[pos + 1] == '|' {
                tokens.push(Token::OrOr);
                pos += 2;
                continue;
            }
            if ch == '+' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::PlusEq);
                pos += 2;
                continue;
            }
            if ch == '-' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::MinusEq);
                pos += 2;
                continue;
            }
            if ch == '*' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::StarEq);
                pos += 2;
                continue;
            }
            if ch == '/' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::SlashEq);
                pos += 2;
                continue;
            }
            if ch == '%' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
                tokens.push(Token::PercentEq);
                pos += 2;
                continue;
            }

            // Parentheses (track depth for multi-line expressions)
            if ch == '(' {
                paren_depth += 1;
                tokens.push(Token::LParen);
                pos += 1;
                continue;
            }
            if ch == ')' {
                if paren_depth > 0 {
                    paren_depth -= 1;
                }
                tokens.push(Token::RParen);
                pos += 1;
                continue;
            }
            if ch == '[' {
                paren_depth += 1;
                tokens.push(Token::LBracket);
                pos += 1;
                continue;
            }
            if ch == ']' {
                if paren_depth > 0 {
                    paren_depth -= 1;
                }
                tokens.push(Token::RBracket);
                pos += 1;
                continue;
            }

            // Symbol literal: :name (but not ::)
            if ch == ':'
                && pos + 1 < chars.len()
                && (chars[pos + 1].is_ascii_alphabetic() || chars[pos + 1] == '_')
            {
                pos += 1; // skip ':'
                let start = pos;
                while pos < chars.len()
                    && (chars[pos].is_ascii_alphanumeric() || chars[pos] == '_')
                {
                    pos += 1;
                }
                let name: String = chars[start..pos].iter().collect();
                tokens.push(Token::Symbol(name));
                continue;
            }

            // Single-char operators & delimiters
            match ch {
                '+' => {
                    tokens.push(Token::Plus);
                    pos += 1;
                    continue;
                }
                '-' => {
                    tokens.push(Token::Minus);
                    pos += 1;
                    continue;
                }
                '*' => {
                    tokens.push(Token::Star);
                    pos += 1;
                    continue;
                }
                '/' => {
                    tokens.push(Token::Slash);
                    pos += 1;
                    continue;
                }
                '%' => {
                    tokens.push(Token::Percent);
                    pos += 1;
                    continue;
                }
                '<' => {
                    tokens.push(Token::Lt);
                    pos += 1;
                    continue;
                }
                '>' => {
                    tokens.push(Token::Gt);
                    pos += 1;
                    continue;
                }
                '!' => {
                    tokens.push(Token::Bang);
                    pos += 1;
                    continue;
                }
                '~' => {
                    tokens.push(Token::Tilde);
                    pos += 1;
                    continue;
                }
                '&' => {
                    tokens.push(Token::BitAnd);
                    pos += 1;
                    continue;
                }
                '|' => {
                    tokens.push(Token::BitOr);
                    pos += 1;
                    continue;
                }
                '^' => {
                    tokens.push(Token::BitXor);
                    pos += 1;
                    continue;
                }
                '=' => {
                    tokens.push(Token::Eq);
                    pos += 1;
                    continue;
                }
                ':' => {
                    tokens.push(Token::Colon);
                    pos += 1;
                    continue;
                }
                ',' => {
                    tokens.push(Token::Comma);
                    pos += 1;
                    continue;
                }
                '.' => {
                    tokens.push(Token::Dot);
                    pos += 1;
                    continue;
                }
                '?' => {
                    tokens.push(Token::Question);
                    pos += 1;
                    continue;
                }
                _ => {}
            }

            // Single-quoted string literals: hex ByteStrings
            if ch == '\'' {
                pos += 1;
                let mut val = String::new();
                while pos < chars.len() && chars[pos] != '\'' {
                    if chars[pos] == '\\' && pos + 1 < chars.len() {
                        pos += 1; // skip backslash
                        val.push(chars[pos]);
                        pos += 1;
                    } else {
                        val.push(chars[pos]);
                        pos += 1;
                    }
                }
                if pos < chars.len() {
                    pos += 1; // skip closing quote
                }
                tokens.push(Token::HexStringLit(val));
                continue;
            }

            // Double-quoted string literals
            if ch == '"' {
                pos += 1;
                let mut val = String::new();
                while pos < chars.len() && chars[pos] != '"' {
                    if chars[pos] == '\\' && pos + 1 < chars.len() {
                        pos += 1; // skip backslash
                        val.push(chars[pos]);
                        pos += 1;
                    } else {
                        val.push(chars[pos]);
                        pos += 1;
                    }
                }
                if pos < chars.len() {
                    pos += 1; // skip closing quote
                }
                tokens.push(Token::StringLit(val));
                continue;
            }

            // Numbers (decimal and hex)
            if ch.is_ascii_digit() {
                let mut num_str = String::new();
                if ch == '0'
                    && pos + 1 < chars.len()
                    && (chars[pos + 1] == 'x' || chars[pos + 1] == 'X')
                {
                    // Hex number
                    num_str.push_str("0x");
                    pos += 2;
                    while pos < chars.len()
                        && (chars[pos].is_ascii_hexdigit() || chars[pos] == '_')
                    {
                        if chars[pos] != '_' {
                            num_str.push(chars[pos]);
                        }
                        pos += 1;
                    }
                } else {
                    while pos < chars.len()
                        && (chars[pos].is_ascii_digit() || chars[pos] == '_')
                    {
                        if chars[pos] != '_' {
                            num_str.push(chars[pos]);
                        }
                        pos += 1;
                    }
                }
                let val = if num_str.starts_with("0x") || num_str.starts_with("0X") {
                    i64::from_str_radix(&num_str[2..], 16).unwrap_or(0)
                } else {
                    num_str.parse::<i64>().unwrap_or(0)
                };
                tokens.push(Token::NumberLit(val));
                continue;
            }

            // Identifiers and keywords
            if ch.is_ascii_alphabetic() || ch == '_' {
                let start = pos;
                while pos < chars.len()
                    && (chars[pos].is_ascii_alphanumeric() || chars[pos] == '_')
                {
                    pos += 1;
                }
                // Check for trailing ? or ! (Ruby method convention)
                if pos < chars.len() && (chars[pos] == '?' || chars[pos] == '!') {
                    pos += 1;
                }
                let word: String = chars[start..pos].iter().collect();
                let tok = match word.as_str() {
                    "class" => Token::Class,
                    "def" => Token::Def,
                    "if" => Token::If,
                    "elsif" => Token::Elsif,
                    "else" => Token::Else,
                    "unless" => Token::Unless,
                    "for" => Token::For,
                    "in" => Token::In,
                    "end" => Token::End,
                    "return" => Token::Return,
                    "true" => Token::TrueLit,
                    "false" => Token::FalseLit,
                    "nil" => Token::NilLit,
                    "and" => Token::And,
                    "or" => Token::Or,
                    "not" => Token::Not,
                    "super" => Token::Super,
                    "require" => Token::Require,
                    "assert" => Token::Assert,
                    "do" => Token::Do,
                    _ => Token::Ident(word),
                };
                tokens.push(tok);
                continue;
            }

            // Skip unrecognised characters
            pos += 1;
        }

        // Emit NEWLINE at end of significant line (only if not inside parens)
        if paren_depth == 0 {
            tokens.push(Token::Newline);
        }
    }

    tokens.push(Token::Eof);
    tokens
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct RbParser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    file: &'a str,
    errors: &'a mut Vec<String>,
    /// Track locally declared variables per method scope to distinguish decl from assignment.
    declared_locals: std::collections::HashSet<String>,
}

impl<'a> RbParser<'a> {
    fn new(tokens: Vec<Token>, file: &'a str, errors: &'a mut Vec<String>) -> Self {
        Self {
            tokens,
            pos: 0,
            file,
            errors,
            declared_locals: std::collections::HashSet::new(),
        }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
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

    /// Check if the current token is an identifier with a specific name.
    fn check_ident(&self, name: &str) -> bool {
        matches!(self.peek(), Token::Ident(ref n) if n == name)
    }

    fn loc(&self) -> SourceLocation {
        SourceLocation {
            file: self.file.to_string(),
            line: 1,
            column: 0,
        }
    }

    /// Skip NEWLINE tokens.
    fn skip_newlines(&mut self) {
        while *self.peek() == Token::Newline {
            self.advance();
        }
    }

    // -----------------------------------------------------------------------
    // Top-level parsing
    // -----------------------------------------------------------------------

    fn parse_contract(&mut self) -> Option<ContractNode> {
        self.skip_newlines();

        // Skip `require 'runar'` lines
        while *self.peek() == Token::Require {
            self.parse_require_line();
            self.skip_newlines();
        }

        self.skip_newlines();

        if *self.peek() != Token::Class {
            self.errors
                .push("Expected 'class' declaration".to_string());
            return None;
        }

        self.advance(); // consume 'class'
        let contract_name = self.expect_ident();

        // Expect `< Runar::SmartContract` or `< SmartContract`
        self.expect(&Token::Lt);

        // Parse parent class: could be `Runar::SmartContract` or just `SmartContract`
        let first_part = self.expect_ident();
        let parent_class = if *self.peek() == Token::ColonColon {
            self.advance(); // '::'
            self.expect_ident()
        } else {
            first_part
        };

        self.skip_newlines();

        if parent_class != "SmartContract" && parent_class != "StatefulSmartContract" {
            self.errors.push(format!(
                "Unknown parent class: {}",
                parent_class
            ));
            return None;
        }

        let mut properties = Vec::new();
        let mut methods = Vec::new();
        let mut constructor: Option<MethodNode> = None;

        // Pending visibility/param types for the next method
        let mut pending_visibility: Option<Visibility> = None;
        let mut pending_param_types: Option<HashMap<String, TypeNode>> = None;

        while *self.peek() != Token::End && *self.peek() != Token::Eof {
            self.skip_newlines();
            if *self.peek() == Token::End || *self.peek() == Token::Eof {
                break;
            }

            // `prop :name, Type [, readonly: true]`
            if self.check_ident("prop") {
                if let Some(prop) = self.parse_prop(&parent_class) {
                    properties.push(prop);
                }
                self.skip_newlines();
                continue;
            }

            // `runar_public [key: Type, ...]`
            if self.check_ident("runar_public") {
                self.advance(); // 'runar_public'
                pending_visibility = Some(Visibility::Public);
                pending_param_types = self.parse_optional_param_types();
                self.skip_newlines();
                continue;
            }

            // `params key: Type, ...`
            if self.check_ident("params") {
                self.advance(); // 'params'
                pending_param_types = self.parse_optional_param_types();
                self.skip_newlines();
                continue;
            }

            // Method definition
            if *self.peek() == Token::Def {
                let method = self.parse_method_def(
                    &pending_visibility,
                    &pending_param_types,
                );
                if method.name == "constructor" {
                    constructor = Some(method);
                } else {
                    methods.push(method);
                }
                pending_visibility = None;
                pending_param_types = None;
                self.skip_newlines();
                continue;
            }

            // Skip unknown tokens
            self.advance();
        }

        self.match_tok(&Token::End); // end of class

        // Auto-generate constructor if not provided
        let mut constructor =
            constructor.unwrap_or_else(|| build_constructor(&properties, self.file));

        // Back-fill constructor param types from prop declarations.
        // In Ruby, `def initialize(pub_key_hash)` has no type annotations —
        // we infer them from the matching `prop :pub_key_hash, Addr` declarations.
        for param in &mut constructor.params {
            if matches!(&param.param_type, TypeNode::Custom(n) if n == "unknown") {
                if let Some(prop) = properties.iter().find(|p| p.name == param.name) {
                    param.param_type = prop.prop_type.clone();
                }
            }
        }

        // Convert bare calls to declared methods and intrinsics into this.method() calls.
        // In Ruby, bare calls like `add_output(...)` are equivalent to
        // `self.add_output(...)` / `this.addOutput(...)`.
        let mut method_names: std::collections::HashSet<String> =
            methods.iter().map(|m| m.name.clone()).collect();
        // Intrinsic methods that must also be rewritten to property_access style.
        method_names.insert("addOutput".to_string());
        method_names.insert("addRawOutput".to_string());
        method_names.insert("getStateScript".to_string());
        for method in &mut methods {
            rewrite_bare_method_calls(&mut method.body, &method_names);
        }

        // Implicit return conversion for private methods.
        //
        // Ruby methods implicitly return the value of their last expression.
        // Private helper methods that return computed values (e.g. a fee
        // calculation) rely on this — without conversion, the calling method
        // would receive no return value and the type checker would reject
        // the call.  We detect ExpressionStatement as the final statement
        // and promote it to a ReturnStatement so the AST has an explicit
        // return node for ANF lowering and type checking to consume.
        for method in &mut methods {
            if method.visibility == Visibility::Private && !method.body.is_empty() {
                let last_idx = method.body.len() - 1;
                if let Statement::ExpressionStatement { expression, source_location } = &method.body[last_idx] {
                    let ret = Statement::ReturnStatement {
                        value: Some(expression.clone()),
                        source_location: source_location.clone(),
                    };
                    method.body[last_idx] = ret;
                }
            }
        }

        Some(ContractNode {
            name: contract_name,
            parent_class,
            properties,
            constructor,
            methods,
            source_file: self.file.to_string(),
        })
    }

    fn parse_require_line(&mut self) {
        self.advance(); // 'require'
        // consume the rest of the line
        while *self.peek() != Token::Newline && *self.peek() != Token::Eof {
            self.advance();
        }
        self.skip_newlines();
    }

    /// Parse optional key: Type pairs after `runar_public` or `params`.
    /// Returns None if there are no pairs (just a bare keyword).
    fn parse_optional_param_types(&mut self) -> Option<HashMap<String, TypeNode>> {
        // If the next token is NEWLINE or eof or def, there are no param types
        if *self.peek() == Token::Newline
            || *self.peek() == Token::Eof
            || *self.peek() == Token::Def
        {
            return None;
        }

        let mut param_types = HashMap::new();

        // Parse key: Type pairs
        while *self.peek() != Token::Newline && *self.peek() != Token::Eof {
            // Expect ident (param name)
            let raw_name = match self.advance() {
                Token::Ident(name) => name,
                _ => break,
            };

            // Expect ':'
            if !self.expect(&Token::Colon) {
                break;
            }

            // Parse type
            let type_node = self.parse_type();

            param_types.insert(raw_name, type_node);

            // Optional comma
            if !self.match_tok(&Token::Comma) {
                break;
            }
        }

        if param_types.is_empty() {
            None
        } else {
            Some(param_types)
        }
    }

    // -----------------------------------------------------------------------
    // Properties
    // -----------------------------------------------------------------------

    fn parse_prop(&mut self, parent_class: &str) -> Option<PropertyNode> {
        self.advance(); // 'prop'

        // Expect symbol :name
        let raw_name = match self.peek().clone() {
            Token::Symbol(name) => {
                self.advance();
                name
            }
            _ => {
                self.errors.push(format!(
                    "Expected symbol after 'prop', got {:?}",
                    self.peek()
                ));
                // Skip to end of line
                while *self.peek() != Token::Newline && *self.peek() != Token::Eof {
                    self.advance();
                }
                return None;
            }
        };

        self.expect(&Token::Comma);

        // Parse type
        let type_node = self.parse_type();

        // Check for optional trailing options: readonly: true/false, default: <literal>
        // Multiple options are comma-separated and may appear in any order.
        let mut is_readonly = false;
        let mut initializer: Option<Expression> = None;
        while *self.peek() == Token::Comma {
            self.advance(); // ','
            if self.check_ident("readonly") {
                self.advance(); // 'readonly'
                self.expect(&Token::Colon);
                if *self.peek() == Token::TrueLit {
                    self.advance();
                    is_readonly = true;
                } else if *self.peek() == Token::FalseLit {
                    self.advance();
                    is_readonly = false;
                }
            } else if self.check_ident("default") {
                self.advance(); // 'default'
                self.expect(&Token::Colon);
                initializer = Some(self.parse_unary());
            } else {
                // Unknown trailing option -- stop parsing options
                break;
            }
        }

        // In stateless contracts, all properties are readonly
        if parent_class == "SmartContract" {
            is_readonly = true;
        }

        // Skip rest of line
        while *self.peek() != Token::Newline
            && *self.peek() != Token::Eof
            && *self.peek() != Token::End
        {
            self.advance();
        }

        Some(PropertyNode {
            name: snake_to_camel(&raw_name),
            prop_type: type_node,
            readonly: is_readonly,
            initializer,
            source_location: self.loc(),
        })
    }

    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    fn parse_type(&mut self) -> TypeNode {
        let raw_name = self.expect_ident();

        // Check for FixedArray[T, N]
        if raw_name == "FixedArray" && *self.peek() == Token::LBracket {
            self.advance(); // '['
            let element = self.parse_type();
            self.expect(&Token::Comma);
            let length = match self.advance() {
                Token::NumberLit(n) => n as usize,
                _ => {
                    self.errors
                        .push("FixedArray requires numeric length".to_string());
                    0
                }
            };
            self.expect(&Token::RBracket);
            return TypeNode::FixedArray {
                element: Box::new(element),
                length,
            };
        }

        let mapped = map_rb_type(&raw_name);
        if let Some(prim) = PrimitiveTypeName::from_str(mapped) {
            TypeNode::Primitive(prim)
        } else {
            TypeNode::Custom(mapped.to_string())
        }
    }

    // -----------------------------------------------------------------------
    // Method definitions
    // -----------------------------------------------------------------------

    fn parse_method_def(
        &mut self,
        pending_visibility: &Option<Visibility>,
        pending_param_types: &Option<HashMap<String, TypeNode>>,
    ) -> MethodNode {
        self.expect(&Token::Def);

        let raw_name = match self.advance() {
            Token::Ident(name) => name,
            other => {
                self.errors
                    .push(format!("Expected method name, got {:?}", other));
                "_error".to_string()
            }
        };

        // Reset local variable tracking for this method scope
        self.declared_locals.clear();

        // Parse parameters (optional parentheses for no-arg methods)
        let params = if *self.peek() == Token::LParen {
            self.advance(); // '('
            let p = self.parse_params(pending_param_types);
            self.expect(&Token::RParen);
            p
        } else {
            Vec::new()
        };

        self.skip_newlines();

        // Parse body until 'end'
        let body = self.parse_statements();

        self.expect(&Token::End);

        // Determine if this is the constructor
        if raw_name == "initialize" {
            return MethodNode {
                name: "constructor".to_string(),
                params,
                body,
                visibility: Visibility::Public,
                source_location: self.loc(),
            };
        }

        let is_public = pending_visibility.as_ref() == Some(&Visibility::Public);
        let method_name = snake_to_camel(&raw_name);

        MethodNode {
            name: method_name,
            params,
            body,
            visibility: if is_public {
                Visibility::Public
            } else {
                Visibility::Private
            },
            source_location: self.loc(),
        }
    }

    fn parse_params(
        &mut self,
        param_types: &Option<HashMap<String, TypeNode>>,
    ) -> Vec<ParamNode> {
        let mut params = Vec::new();

        while *self.peek() != Token::RParen && *self.peek() != Token::Eof {
            let raw_name = self.expect_ident();
            let camel_name = snake_to_camel(&raw_name);

            // Look up the type from the preceding runar_public/params declaration
            let param_type = if let Some(ref types) = param_types {
                types
                    .get(&raw_name)
                    .cloned()
                    .unwrap_or_else(|| TypeNode::Custom("unknown".to_string()))
            } else {
                TypeNode::Custom("unknown".to_string())
            };

            params.push(ParamNode {
                name: camel_name,
                param_type,
            });

            if !self.match_tok(&Token::Comma) {
                break;
            }
        }

        params
    }

    // -----------------------------------------------------------------------
    // Statements
    // -----------------------------------------------------------------------

    fn parse_statements(&mut self) -> Vec<Statement> {
        let mut stmts = Vec::new();

        while *self.peek() != Token::End
            && *self.peek() != Token::Elsif
            && *self.peek() != Token::Else
            && *self.peek() != Token::Eof
        {
            self.skip_newlines();
            if *self.peek() == Token::End
                || *self.peek() == Token::Elsif
                || *self.peek() == Token::Else
                || *self.peek() == Token::Eof
            {
                break;
            }

            if let Some(stmt) = self.parse_statement() {
                stmts.push(stmt);
            }
            self.skip_newlines();
        }

        stmts
    }

    fn parse_statement(&mut self) -> Option<Statement> {
        match self.peek().clone() {
            // assert statement: assert expr
            Token::Assert => Some(self.parse_assert_statement()),

            // if statement
            Token::If => Some(self.parse_if_statement()),

            // unless statement (maps to if with negated condition)
            Token::Unless => Some(self.parse_unless_statement()),

            // for statement
            Token::For => Some(self.parse_for_statement()),

            // return statement
            Token::Return => Some(self.parse_return_statement()),

            // super(args...) — constructor super call
            Token::Super => Some(self.parse_super_call()),

            // Instance variable: @var = expr, @var += expr
            Token::Ivar(_) => Some(self.parse_ivar_statement()),

            // Variable declaration or expression statement
            Token::Ident(_) => Some(self.parse_ident_statement()),

            _ => {
                self.advance();
                None
            }
        }
    }

    fn parse_assert_statement(&mut self) -> Statement {
        self.advance(); // consume 'assert'
        let expr = self.parse_expression();
        Statement::ExpressionStatement {
            expression: Expression::CallExpr {
                callee: Box::new(Expression::Identifier {
                    name: "assert".to_string(),
                }),
                args: vec![expr],
            },
            source_location: self.loc(),
        }
    }

    fn parse_if_statement(&mut self) -> Statement {
        self.advance(); // consume 'if'
        let condition = self.parse_expression();
        // Optional newline after condition
        self.match_tok(&Token::Newline);
        self.skip_newlines();

        let then_branch = self.parse_statements();

        let else_branch = if *self.peek() == Token::Elsif {
            // elsif -> else { if ... }
            Some(vec![self.parse_elsif_statement()])
        } else if *self.peek() == Token::Else {
            self.advance(); // 'else'
            self.skip_newlines();
            let stmts = self.parse_statements();
            Some(stmts)
        } else {
            None
        };

        self.expect(&Token::End);

        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            source_location: self.loc(),
        }
    }

    fn parse_elsif_statement(&mut self) -> Statement {
        self.advance(); // consume 'elsif'
        let condition = self.parse_expression();
        self.skip_newlines();

        let then_branch = self.parse_statements();

        let else_branch = if *self.peek() == Token::Elsif {
            Some(vec![self.parse_elsif_statement()])
        } else if *self.peek() == Token::Else {
            self.advance(); // 'else'
            self.skip_newlines();
            let stmts = self.parse_statements();
            Some(stmts)
        } else {
            None
        };

        // Note: the outer `end` is consumed by the parent parse_if_statement.
        // elsif branches do not consume their own `end`.

        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            source_location: self.loc(),
        }
    }

    fn parse_unless_statement(&mut self) -> Statement {
        self.advance(); // consume 'unless'
        let raw_condition = self.parse_expression();
        self.skip_newlines();

        let body = self.parse_statements();

        self.expect(&Token::End);

        // Unless is if with negated condition
        let condition = Expression::UnaryExpr {
            op: UnaryOp::Not,
            operand: Box::new(raw_condition),
        };

        Statement::IfStatement {
            condition,
            then_branch: body,
            else_branch: None,
            source_location: self.loc(),
        }
    }

    fn parse_for_statement(&mut self) -> Statement {
        self.advance(); // consume 'for'

        let raw_var = self.expect_ident();
        let var_name = snake_to_camel(&raw_var);

        self.expect(&Token::In);

        // Parse start expression
        let start_expr = self.parse_expression();

        // Expect range operator: .. (inclusive) or ... (exclusive)
        let is_exclusive = if *self.peek() == Token::DotDotDot {
            self.advance();
            true
        } else if *self.peek() == Token::DotDot {
            self.advance();
            false
        } else {
            self.errors
                .push("Expected range operator '..' or '...' in for loop".to_string());
            true // default to exclusive
        };

        let end_expr = self.parse_expression();

        // Optional 'do' keyword
        self.match_tok(&Token::Do);
        self.skip_newlines();

        let body = self.parse_statements();
        self.expect(&Token::End);

        // Construct a C-style for loop AST node
        let init = Statement::VariableDecl {
            name: var_name.clone(),
            var_type: Some(TypeNode::Primitive(PrimitiveTypeName::Bigint)),
            mutable: true,
            init: start_expr,
            source_location: self.loc(),
        };

        let cmp_op = if is_exclusive {
            BinaryOp::Lt
        } else {
            BinaryOp::Le
        };

        let condition = Expression::BinaryExpr {
            op: cmp_op,
            left: Box::new(Expression::Identifier {
                name: var_name.clone(),
            }),
            right: Box::new(end_expr),
        };

        let update = Statement::ExpressionStatement {
            expression: Expression::IncrementExpr {
                operand: Box::new(Expression::Identifier { name: var_name }),
                prefix: false,
            },
            source_location: self.loc(),
        };

        Statement::ForStatement {
            init: Box::new(init),
            condition,
            update: Box::new(update),
            body,
            source_location: self.loc(),
        }
    }

    fn parse_return_statement(&mut self) -> Statement {
        self.advance(); // consume 'return'
        let value = if *self.peek() != Token::Newline
            && *self.peek() != Token::End
            && *self.peek() != Token::Eof
        {
            Some(self.parse_expression())
        } else {
            None
        };
        Statement::ReturnStatement {
            value,
            source_location: self.loc(),
        }
    }

    fn parse_super_call(&mut self) -> Statement {
        // super(args...) in Ruby constructor
        self.advance(); // 'super'
        self.expect(&Token::LParen);
        let mut args = Vec::new();
        while *self.peek() != Token::RParen && *self.peek() != Token::Eof {
            args.push(self.parse_expression());
            if !self.match_tok(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RParen);

        Statement::ExpressionStatement {
            expression: Expression::CallExpr {
                callee: Box::new(Expression::Identifier {
                    name: "super".to_string(),
                }),
                args,
            },
            source_location: self.loc(),
        }
    }

    fn parse_ivar_statement(&mut self) -> Statement {
        // @var = expr or @var += expr or @var as expression
        let raw_name = match self.advance() {
            Token::Ivar(name) => name,
            _ => "_error".to_string(),
        };
        let prop_name = snake_to_camel(&raw_name);
        let target = Expression::PropertyAccess {
            property: prop_name,
        };

        // Simple assignment: @var = expr
        if self.match_tok(&Token::Eq) {
            let value = self.parse_expression();
            return Statement::Assignment {
                target,
                value,
                source_location: self.loc(),
            };
        }

        // Compound assignments
        let compound_op = match self.peek() {
            Token::PlusEq => Some(BinaryOp::Add),
            Token::MinusEq => Some(BinaryOp::Sub),
            Token::StarEq => Some(BinaryOp::Mul),
            Token::SlashEq => Some(BinaryOp::Div),
            Token::PercentEq => Some(BinaryOp::Mod),
            _ => None,
        };

        if let Some(bin_op) = compound_op {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: bin_op,
                left: Box::new(target.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target,
                value,
                source_location: self.loc(),
            };
        }

        // Expression statement (e.g. @var.method(...))
        let expr = self.parse_postfix_from(target);

        Statement::ExpressionStatement {
            expression: expr,
            source_location: self.loc(),
        }
    }

    fn parse_ident_statement(&mut self) -> Statement {
        let raw_name = match self.peek().clone() {
            Token::Ident(ref name) => name.clone(),
            _ => "_error".to_string(),
        };

        // Check for simple name = expr pattern (variable declaration or assignment)
        if self
            .tokens
            .get(self.pos + 1)
            .map_or(false, |t| *t == Token::Eq)
        {
            self.advance(); // consume ident
            self.advance(); // consume '='
            let value = self.parse_expression();
            let camel_name = snake_to_camel(&raw_name);

            if self.declared_locals.contains(&camel_name) {
                // Already declared: this is an assignment
                return Statement::Assignment {
                    target: Expression::Identifier { name: camel_name },
                    value,
                    source_location: self.loc(),
                };
            } else {
                // First assignment: variable declaration
                self.declared_locals.insert(camel_name.clone());
                return Statement::VariableDecl {
                    name: camel_name,
                    var_type: None,
                    mutable: true,
                    init: value,
                    source_location: self.loc(),
                };
            }
        }

        // Parse as expression first
        let expr = self.parse_expression();

        // Simple assignment (e.g. a.b = expr)
        if self.match_tok(&Token::Eq) {
            let value = self.parse_expression();
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }

        // Compound assignments
        let compound_op = match self.peek() {
            Token::PlusEq => Some(BinaryOp::Add),
            Token::MinusEq => Some(BinaryOp::Sub),
            Token::StarEq => Some(BinaryOp::Mul),
            Token::SlashEq => Some(BinaryOp::Div),
            Token::PercentEq => Some(BinaryOp::Mod),
            _ => None,
        };

        if let Some(bin_op) = compound_op {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: bin_op,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }

        // Expression statement
        Statement::ExpressionStatement {
            expression: expr,
            source_location: self.loc(),
        }
    }

    // -----------------------------------------------------------------------
    // Expressions (precedence climbing)
    // -----------------------------------------------------------------------

    fn parse_expression(&mut self) -> Expression {
        self.parse_ternary()
    }

    /// Ruby ternary: `condition ? consequent : alternate`
    fn parse_ternary(&mut self) -> Expression {
        let expr = self.parse_or();

        if *self.peek() == Token::Question {
            self.advance(); // '?'
            let consequent = self.parse_expression();
            self.expect(&Token::Colon);
            let alternate = self.parse_expression();
            Expression::TernaryExpr {
                condition: Box::new(expr),
                consequent: Box::new(consequent),
                alternate: Box::new(alternate),
            }
        } else {
            expr
        }
    }

    fn parse_or(&mut self) -> Expression {
        let mut left = self.parse_and();
        while *self.peek() == Token::Or || *self.peek() == Token::OrOr {
            self.advance();
            let right = self.parse_and();
            left = Expression::BinaryExpr {
                op: BinaryOp::Or,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        left
    }

    fn parse_and(&mut self) -> Expression {
        let mut left = self.parse_not();
        while *self.peek() == Token::And || *self.peek() == Token::AndAnd {
            self.advance();
            let right = self.parse_not();
            left = Expression::BinaryExpr {
                op: BinaryOp::And,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        left
    }

    fn parse_not(&mut self) -> Expression {
        if *self.peek() == Token::Not || *self.peek() == Token::Bang {
            self.advance();
            let operand = self.parse_not();
            Expression::UnaryExpr {
                op: UnaryOp::Not,
                operand: Box::new(operand),
            }
        } else {
            self.parse_bit_or()
        }
    }

    fn parse_bit_or(&mut self) -> Expression {
        let mut left = self.parse_bit_xor();
        while *self.peek() == Token::BitOr {
            self.advance();
            let right = self.parse_bit_xor();
            left = Expression::BinaryExpr {
                op: BinaryOp::BitOr,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        left
    }

    fn parse_bit_xor(&mut self) -> Expression {
        let mut left = self.parse_bit_and();
        while *self.peek() == Token::BitXor {
            self.advance();
            let right = self.parse_bit_and();
            left = Expression::BinaryExpr {
                op: BinaryOp::BitXor,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        left
    }

    fn parse_bit_and(&mut self) -> Expression {
        let mut left = self.parse_equality();
        while *self.peek() == Token::BitAnd {
            self.advance();
            let right = self.parse_equality();
            left = Expression::BinaryExpr {
                op: BinaryOp::BitAnd,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        left
    }

    fn parse_equality(&mut self) -> Expression {
        let mut left = self.parse_comparison();
        loop {
            match self.peek() {
                Token::EqEq => {
                    self.advance();
                    let right = self.parse_comparison();
                    // == maps to ===
                    left = Expression::BinaryExpr {
                        op: BinaryOp::StrictEq,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::NotEq => {
                    self.advance();
                    let right = self.parse_comparison();
                    // != maps to !==
                    left = Expression::BinaryExpr {
                        op: BinaryOp::StrictNe,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_comparison(&mut self) -> Expression {
        let mut left = self.parse_shift();
        loop {
            match self.peek() {
                Token::Lt => {
                    self.advance();
                    let right = self.parse_shift();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Lt,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::Le => {
                    self.advance();
                    let right = self.parse_shift();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Le,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::Gt => {
                    self.advance();
                    let right = self.parse_shift();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Gt,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::Ge => {
                    self.advance();
                    let right = self.parse_shift();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Ge,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_shift(&mut self) -> Expression {
        let mut left = self.parse_additive();
        loop {
            match self.peek() {
                Token::LShift => {
                    self.advance();
                    let right = self.parse_additive();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Shl,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::RShift => {
                    self.advance();
                    let right = self.parse_additive();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Shr,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_additive(&mut self) -> Expression {
        let mut left = self.parse_multiplicative();
        loop {
            match self.peek() {
                Token::Plus => {
                    self.advance();
                    let right = self.parse_multiplicative();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Add,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::Minus => {
                    self.advance();
                    let right = self.parse_multiplicative();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Sub,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_multiplicative(&mut self) -> Expression {
        let mut left = self.parse_unary();
        loop {
            match self.peek() {
                Token::Star => {
                    self.advance();
                    let right = self.parse_unary();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Mul,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::Slash => {
                    self.advance();
                    let right = self.parse_unary();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Div,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::Percent => {
                    self.advance();
                    let right = self.parse_unary();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Mod,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_unary(&mut self) -> Expression {
        match self.peek() {
            Token::Minus => {
                self.advance();
                let operand = self.parse_unary();
                Expression::UnaryExpr {
                    op: UnaryOp::Neg,
                    operand: Box::new(operand),
                }
            }
            Token::Tilde => {
                self.advance();
                let operand = self.parse_unary();
                Expression::UnaryExpr {
                    op: UnaryOp::BitNot,
                    operand: Box::new(operand),
                }
            }
            Token::Bang => {
                self.advance();
                let operand = self.parse_unary();
                Expression::UnaryExpr {
                    op: UnaryOp::Not,
                    operand: Box::new(operand),
                }
            }
            _ => self.parse_power(),
        }
    }

    /// `**` is right-associative and maps to pow() call.
    fn parse_power(&mut self) -> Expression {
        let base = self.parse_postfix();

        if *self.peek() == Token::DoubleStar {
            self.advance();
            let exp = self.parse_power(); // right-recursive for right-associativity
            Expression::CallExpr {
                callee: Box::new(Expression::Identifier {
                    name: "pow".to_string(),
                }),
                args: vec![base, exp],
            }
        } else {
            base
        }
    }

    fn parse_postfix(&mut self) -> Expression {
        let expr = self.parse_primary();
        self.parse_postfix_from(expr)
    }

    /// Parse postfix operations (method calls, property access, indexing) from a given expression.
    fn parse_postfix_from(&mut self, mut expr: Expression) -> Expression {
        loop {
            match self.peek().clone() {
                Token::Dot => {
                    self.advance(); // '.'
                    let raw_prop = self.expect_ident();
                    let prop = map_builtin_name(&raw_prop);

                    // Check if it's a method call
                    if *self.peek() == Token::LParen {
                        let args = self.parse_call_args();
                        // Handle property_access.method(...)
                        if matches!(&expr, Expression::Identifier { name } if name == "this") {
                            expr = Expression::CallExpr {
                                callee: Box::new(Expression::MemberExpr {
                                    object: Box::new(Expression::Identifier {
                                        name: "this".to_string(),
                                    }),
                                    property: prop,
                                }),
                                args,
                            };
                        } else {
                            expr = Expression::CallExpr {
                                callee: Box::new(Expression::MemberExpr {
                                    object: Box::new(expr),
                                    property: prop,
                                }),
                                args,
                            };
                        }
                    } else {
                        // Property access
                        if matches!(&expr, Expression::Identifier { name } if name == "this") {
                            expr = Expression::PropertyAccess { property: prop };
                        } else {
                            expr = Expression::MemberExpr {
                                object: Box::new(expr),
                                property: prop,
                            };
                        }
                    }
                }
                Token::LParen => {
                    let args = self.parse_call_args();
                    expr = Expression::CallExpr {
                        callee: Box::new(expr),
                        args,
                    };
                }
                Token::LBracket => {
                    self.advance();
                    let index = self.parse_expression();
                    self.expect(&Token::RBracket);
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

    fn parse_primary(&mut self) -> Expression {
        match self.advance() {
            Token::NumberLit(v) => Expression::BigIntLiteral { value: v },
            Token::TrueLit => Expression::BoolLiteral { value: true },
            Token::FalseLit => Expression::BoolLiteral { value: false },
            Token::NilLit => Expression::BigIntLiteral { value: 0 },
            Token::HexStringLit(v) => Expression::ByteStringLiteral { value: v },
            Token::StringLit(v) => Expression::ByteStringLiteral { value: v },
            Token::Ivar(name) => {
                // @var -> property access
                let prop_name = snake_to_camel(&name);
                Expression::PropertyAccess {
                    property: prop_name,
                }
            }
            Token::Ident(name) => {
                let mapped = map_builtin_name(&name);
                Expression::Identifier { name: mapped }
            }
            Token::Assert => {
                // assert used as expression (unusual but handle it)
                Expression::Identifier {
                    name: "assert".to_string(),
                }
            }
            Token::Super => {
                Expression::Identifier {
                    name: "super".to_string(),
                }
            }
            Token::LParen => {
                let expr = self.parse_expression();
                self.expect(&Token::RParen);
                expr
            }
            Token::LBracket => {
                // Array literal: [elem, ...]
                let mut elements = Vec::new();
                while *self.peek() != Token::RBracket && *self.peek() != Token::Eof {
                    elements.push(self.parse_expression());
                    if !self.match_tok(&Token::Comma) {
                        break;
                    }
                }
                self.expect(&Token::RBracket);
                Expression::ArrayLiteral { elements }
            }
            other => {
                self.errors
                    .push(format!("Unexpected token in expression: {:?}", other));
                Expression::BigIntLiteral { value: 0 }
            }
        }
    }

    fn parse_call_args(&mut self) -> Vec<Expression> {
        self.expect(&Token::LParen);
        let mut args = Vec::new();
        while *self.peek() != Token::RParen && *self.peek() != Token::Eof {
            args.push(self.parse_expression());
            if !self.match_tok(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RParen);
        args
    }
}

// ---------------------------------------------------------------------------
// Constructor builder
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
        })
        .collect();
    body.push(Statement::ExpressionStatement {
        expression: Expression::CallExpr {
            callee: Box::new(Expression::Identifier {
                name: "super".to_string(),
            }),
            args: super_args,
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
            },
            value: Expression::Identifier {
                name: p.name.clone(),
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
    }
}

// ---------------------------------------------------------------------------
// Bare method call rewriter
// ---------------------------------------------------------------------------

/// Rewrite bare function calls to declared contract methods as `this.method()` calls.
/// In Ruby, `compute_threshold(a, b)` is equivalent to `self.compute_threshold(a, b)`.
fn rewrite_bare_method_calls(stmts: &mut [Statement], method_names: &std::collections::HashSet<String>) {
    for stmt in stmts.iter_mut() {
        rewrite_stmt(stmt, method_names);
    }
}

fn rewrite_expr(expr: &mut Expression, method_names: &std::collections::HashSet<String>) {
    match expr {
        Expression::CallExpr { callee, args } => {
            for arg in args.iter_mut() {
                rewrite_expr(arg, method_names);
            }
            if let Expression::Identifier { name } = callee.as_ref() {
                if method_names.contains(name) {
                    *callee = Box::new(Expression::PropertyAccess { property: name.clone() });
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
        Expression::TernaryExpr { condition, consequent, alternate } => {
            rewrite_expr(condition.as_mut(), method_names);
            rewrite_expr(consequent.as_mut(), method_names);
            rewrite_expr(alternate.as_mut(), method_names);
        }
        _ => {}
    }
}

fn rewrite_stmt(stmt: &mut Statement, method_names: &std::collections::HashSet<String>) {
    match stmt {
        Statement::ExpressionStatement { expression, .. } => {
            rewrite_expr(expression, method_names);
        }
        Statement::VariableDecl { init, .. } => {
            rewrite_expr(init, method_names);
        }
        Statement::Assignment { value, .. } => {
            rewrite_expr(value, method_names);
        }
        Statement::ReturnStatement { value, .. } => {
            if let Some(v) = value {
                rewrite_expr(v, method_names);
            }
        }
        Statement::IfStatement { condition, then_branch, else_branch, .. } => {
            rewrite_expr(condition, method_names);
            rewrite_bare_method_calls(then_branch, method_names);
            if let Some(else_stmts) = else_branch {
                rewrite_bare_method_calls(else_stmts, method_names);
            }
        }
        Statement::ForStatement { body, .. } => {
            rewrite_bare_method_calls(body, method_names);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snake_to_camel() {
        assert_eq!(snake_to_camel("hello_world"), "helloWorld");
        assert_eq!(snake_to_camel("check_sig"), "checkSig");
        assert_eq!(snake_to_camel("already"), "already");
        assert_eq!(snake_to_camel("a_b_c"), "aBC");
        assert_eq!(snake_to_camel("pub_key_hash"), "pubKeyHash");
    }

    #[test]
    fn test_builtin_name_mapping() {
        assert_eq!(map_builtin_name("check_sig"), "checkSig");
        assert_eq!(map_builtin_name("hash160"), "hash160");
        assert_eq!(map_builtin_name("verify_wots"), "verifyWOTS");
        assert_eq!(
            map_builtin_name("verify_slh_dsa_sha2_128s"),
            "verifySLHDSA_SHA2_128s"
        );
        assert_eq!(map_builtin_name("ec_add"), "ecAdd");
        assert_eq!(map_builtin_name("add_output"), "addOutput");
        assert_eq!(map_builtin_name("abs"), "abs");
        assert_eq!(map_builtin_name("some_func"), "someFunc");
    }

    #[test]
    fn test_parse_simple_ruby_contract() {
        let source = r#"
require 'runar'

class P2PKH < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end
"#;

        let result = parse_ruby(source, Some("P2PKH.runar.rb"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.name, "P2PKH");
        assert_eq!(contract.parent_class, "SmartContract");
        assert_eq!(contract.properties.len(), 1);
        assert_eq!(contract.properties[0].name, "pubKeyHash");
        assert!(contract.properties[0].readonly);
        assert_eq!(contract.methods.len(), 1);
        assert_eq!(contract.methods[0].name, "unlock");
        assert_eq!(contract.methods[0].visibility, Visibility::Public);
        assert_eq!(contract.methods[0].params.len(), 2);
        assert_eq!(contract.methods[0].params[0].name, "sig");
        assert_eq!(contract.methods[0].params[1].name, "pubKey");
    }

    #[test]
    fn test_parse_stateful_ruby_contract() {
        let source = r#"
require 'runar'

class Counter < Runar::StatefulSmartContract
  prop :count, Bigint

  def initialize(count)
    super(count)
    @count = count
  end

  runar_public
  def increment
    @count += 1
  end

  runar_public
  def decrement
    assert @count > 0
    @count -= 1
  end
end
"#;

        let result = parse_ruby(source, Some("Counter.runar.rb"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.name, "Counter");
        assert_eq!(contract.parent_class, "StatefulSmartContract");
        assert_eq!(contract.properties.len(), 1);
        assert_eq!(contract.properties[0].name, "count");
        assert!(!contract.properties[0].readonly);
        assert_eq!(contract.methods.len(), 2);
        assert_eq!(contract.methods[0].name, "increment");
        assert_eq!(contract.methods[0].visibility, Visibility::Public);
        assert_eq!(contract.methods[1].name, "decrement");
        assert_eq!(contract.methods[1].visibility, Visibility::Public);
    }

    #[test]
    fn test_parse_readonly_property() {
        let source = r#"
require 'runar'

class Token < Runar::StatefulSmartContract
  prop :owner, PubKey
  prop :balance, Bigint
  prop :token_id, ByteString, readonly: true

  def initialize(owner, balance, token_id)
    super(owner, balance, token_id)
    @owner = owner
    @balance = balance
    @token_id = token_id
  end

  runar_public sig: Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint
  def transfer(sig, to, amount, output_satoshis)
    assert check_sig(sig, @owner)
    assert amount > 0
    assert amount <= @balance
    add_output(output_satoshis, to, amount)
    add_output(output_satoshis, @owner, @balance - amount)
  end
end
"#;

        let result = parse_ruby(source, Some("Token.runar.rb"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.name, "Token");
        assert_eq!(contract.properties.len(), 3);
        assert!(!contract.properties[0].readonly); // owner
        assert!(!contract.properties[1].readonly); // balance
        assert!(contract.properties[2].readonly);  // token_id
        assert_eq!(contract.methods.len(), 1);
        assert_eq!(contract.methods[0].name, "transfer");
        assert_eq!(contract.methods[0].params.len(), 4);
    }

    #[test]
    fn test_parse_for_loop_exclusive() {
        let source = r#"
require 'runar'

class BoundedLoop < Runar::SmartContract
  prop :expected_sum, Bigint

  runar_public n: Bigint
  def verify(n)
    total = 0
    for i in 0...n do
      total += i
    end
    assert total == @expected_sum
  end
end
"#;

        let result = parse_ruby(source, Some("BoundedLoop.runar.rb"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods.len(), 1);
        // The for loop should be present in the body
        let body = &contract.methods[0].body;
        assert!(body.len() >= 3); // total = 0, for loop, assert
    }

    #[test]
    fn test_parse_for_loop_inclusive() {
        let source = r#"
require 'runar'

class InclusiveLoop < Runar::SmartContract
  prop :expected_sum, Bigint

  runar_public n: Bigint
  def verify(n)
    total = 0
    for i in 0..n
      total += i
    end
    assert total == @expected_sum
  end
end
"#;

        let result = parse_ruby(source, Some("InclusiveLoop.runar.rb"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods.len(), 1);
    }

    #[test]
    fn test_parse_if_elsif_else() {
        let source = r#"
require 'runar'

class Branching < Runar::SmartContract
  prop :value, Bigint

  runar_public x: Bigint
  def check(x)
    if x > 10
      assert @value == 1
    elsif x > 5
      assert @value == 2
    else
      assert @value == 3
    end
  end
end
"#;

        let result = parse_ruby(source, Some("Branching.runar.rb"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods.len(), 1);
    }

    #[test]
    fn test_parse_unless_statement() {
        let source = r#"
require 'runar'

class Checker < Runar::SmartContract
  prop :value, Bigint

  runar_public
  def check
    unless @value == 0
      assert @value > 0
    end
  end
end
"#;

        let result = parse_ruby(source, Some("Checker.runar.rb"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods.len(), 1);
    }

    #[test]
    fn test_parse_power_operator() {
        let source = r#"
require 'runar'

class Power < Runar::SmartContract
  prop :expected, Bigint

  runar_public x: Bigint, y: Bigint
  def verify(x, y)
    assert x ** y == @expected
  end
end
"#;

        let result = parse_ruby(source, Some("Power.runar.rb"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
    }

    #[test]
    fn test_parse_auto_generated_constructor() {
        let source = r#"
require 'runar'

class Simple < Runar::SmartContract
  prop :value, Bigint

  runar_public x: Bigint
  def verify(x)
    assert x == @value
  end
end
"#;

        let result = parse_ruby(source, Some("Simple.runar.rb"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        // Constructor should be auto-generated
        assert_eq!(contract.constructor.name, "constructor");
        assert_eq!(contract.constructor.params.len(), 1);
        assert_eq!(contract.constructor.params[0].name, "value");
    }

    #[test]
    fn test_parse_parent_class_without_runar_prefix() {
        let source = r#"
require 'runar'

class Simple < SmartContract
  prop :value, Bigint

  runar_public x: Bigint
  def verify(x)
    assert x == @value
  end
end
"#;

        let result = parse_ruby(source, Some("Simple.runar.rb"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.parent_class, "SmartContract");
    }

    #[test]
    fn test_parse_hex_string_literal() {
        let source = r#"
require 'runar'

class HexTest < Runar::SmartContract
  prop :data, ByteString

  runar_public
  def verify
    assert @data == 'deadbeef'
  end
end
"#;

        let result = parse_ruby(source, Some("HexTest.runar.rb"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
    }

    #[test]
    fn test_parse_private_method_with_params() {
        let source = r#"
require 'runar'

class WithHelper < Runar::SmartContract
  prop :value, Bigint

  params x: Bigint
  def helper(x)
    return x + 1
  end

  runar_public n: Bigint
  def verify(n)
    result = helper(n)
    assert result == @value
  end
end
"#;

        let result = parse_ruby(source, Some("WithHelper.runar.rb"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods.len(), 2);
        assert_eq!(contract.methods[0].name, "helper");
        assert_eq!(contract.methods[0].visibility, Visibility::Private);
        assert_eq!(contract.methods[1].name, "verify");
        assert_eq!(contract.methods[1].visibility, Visibility::Public);
    }
}
