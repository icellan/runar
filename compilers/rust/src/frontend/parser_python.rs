//! Python parser for Rúnar contracts (.runar.py).
//!
//! Parses Python-style contract definitions using a hand-written tokenizer
//! with INDENT/DEDENT tokens and recursive descent parser.
//! Produces the same AST as the TypeScript parser.
//!
//! ## Expected format
//!
//! ```python
//! from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig
//!
//! class P2PKH(SmartContract):
//!     pub_key_hash: Addr
//!
//!     def __init__(self, pub_key_hash: Addr):
//!         super().__init__(pub_key_hash)
//!         self.pub_key_hash = pub_key_hash
//!
//!     @public
//!     def unlock(self, sig: Sig, pub_key: PubKey):
//!         assert_(hash160(pub_key) == self.pub_key_hash)
//!         assert_(check_sig(sig, pub_key))
//! ```
//!
//! Key mappings:
//! - `class Foo(SmartContract):` -> contract
//! - `@public` decorator -> Visibility::Public
//! - `self.prop` -> PropertyAccess (like `this.prop`)
//! - `assert_(expr)` or `assert expr` -> assert(expr)
//! - `//` integer division -> Div in AST (OP_DIV)
//! - `and`/`or`/`not` -> And/Or/Not operators
//! - `==`/`!=` -> StrictEq/StrictNe
//! - `Readonly[T]` -> readonly property
//! - `for i in range(n):` -> ForStatement
//! - snake_case identifiers -> camelCase in AST

use super::ast::{
    BinaryOp, ContractNode, Expression, MethodNode, ParamNode, PrimitiveTypeName, PropertyNode,
    SourceLocation, Statement, TypeNode, UnaryOp, Visibility,
};
use super::diagnostic::Diagnostic;
use super::parser::ParseResult;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a Python-format Rúnar contract source.
pub fn parse_python(source: &str, file_name: Option<&str>) -> ParseResult {
    let file = file_name.unwrap_or("contract.runar.py");
    let mut errors: Vec<Diagnostic> = Vec::new();

    let tokens = tokenize(source);
    let mut parser = PyParser::new(tokens, file, &mut errors);

    let contract = parser.parse_contract();

    ParseResult { contract, errors }
}

// ---------------------------------------------------------------------------
// Name conversion helpers
// ---------------------------------------------------------------------------

/// Convert snake_case to camelCase. Single words pass through unchanged.
/// Strips trailing underscore (e.g. `sum_` -> `sum`, `assert_` -> `assert`).
fn snake_to_camel(name: &str) -> String {
    // Strip trailing underscore (e.g. assert_ -> assert)
    let n = if name.ends_with('_') && name != "_" {
        &name[..name.len() - 1]
    } else {
        name
    };

    let mut result = String::new();
    let mut capitalize_next = false;

    for ch in n.chars() {
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

/// Map Python builtin function names to Rúnar AST callee names.
fn map_builtin_name(name: &str) -> String {
    // Exact-match special cases (names that don't follow simple snake_case -> camelCase)
    match name {
        "assert_" => return "assert".to_string(),
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
        "add_output" => return "addOutput".to_string(),
        "get_state_script" => return "getStateScript".to_string(),
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

/// Map Python type names to Rúnar AST types.
fn map_py_type(name: &str) -> &str {
    match name {
        "Bigint" | "int" | "Int" => "bigint",
        "bool" => "boolean",
        "ByteString" | "bytes" => "ByteString",
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
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    // Keywords
    Class,
    Def,
    If,
    Elif,
    Else,
    For,
    In,
    Range,
    Return,
    Pass,
    TrueLit,
    FalseLit,
    NoneLit,
    And,
    Or,
    Not,
    SelfKw,
    Super,
    From,
    Import,
    Assert,

    // Identifiers and literals
    Ident(String),
    NumberLit(i64),
    HexStringLit(String),
    StringLit(String),

    // Decorators
    At,

    // Operators
    Plus,
    Minus,
    Star,
    Slash,
    IntDiv,       // //
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
    IntDivEq,     // //=
    PercentEq,    // %=
    Arrow,        // ->

    // Delimiters
    LParen,
    RParen,
    LBracket,
    RBracket,
    Colon,
    Comma,
    Dot,

    // Indentation
    Indent,
    Dedent,
    Newline,

    // Special
    Eof,
}

fn tokenize(source: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let lines: Vec<&str> = source.split('\n').collect();
    let mut indent_stack: Vec<usize> = vec![0];
    let mut paren_depth: usize = 0;

    for raw_line in &lines {
        // Strip trailing \r
        let line = if raw_line.ends_with('\r') {
            &raw_line[..raw_line.len() - 1]
        } else {
            raw_line
        };

        // Skip blank lines and comment-only lines (they don't affect indentation)
        let stripped = line.trim_start();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }

        let chars: Vec<char> = line.chars().collect();

        // Compute indent level (only at paren depth 0)
        if paren_depth == 0 {
            let mut indent = 0usize;
            for &ch in &chars {
                if ch == ' ' {
                    indent += 1;
                } else if ch == '\t' {
                    indent += 4;
                } else {
                    break;
                }
            }

            let current_indent = *indent_stack.last().unwrap();
            if indent > current_indent {
                indent_stack.push(indent);
                tokens.push(Token::Indent);
            } else if indent < current_indent {
                while indent_stack.len() > 1 && *indent_stack.last().unwrap() > indent {
                    indent_stack.pop();
                    tokens.push(Token::Dedent);
                }
            }
        }

        // Tokenize the content of this line
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

            // Decorators
            if ch == '@' {
                pos += 1;
                tokens.push(Token::At);
                continue;
            }

            // Three-char operators: //=
            if ch == '/'
                && pos + 2 < chars.len()
                && chars[pos + 1] == '/'
                && chars[pos + 2] == '='
            {
                tokens.push(Token::IntDivEq);
                pos += 3;
                continue;
            }

            // Two-char operators: ** // == != <= >= << >> += -= *= /= %= ->
            if ch == '*' && pos + 1 < chars.len() && chars[pos + 1] == '*' {
                tokens.push(Token::DoubleStar);
                pos += 2;
                continue;
            }
            if ch == '/' && pos + 1 < chars.len() && chars[pos + 1] == '/' {
                tokens.push(Token::IntDiv);
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
            if ch == '-' && pos + 1 < chars.len() && chars[pos + 1] == '>' {
                tokens.push(Token::Arrow);
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
                _ => {}
            }

            // Hex byte string: b'\xde\xad' or b"\xde\xad"
            if ch == 'b'
                && pos + 1 < chars.len()
                && (chars[pos + 1] == '\'' || chars[pos + 1] == '"')
            {
                let quote = chars[pos + 1];
                pos += 2; // skip b and opening quote
                let mut hex = String::new();
                while pos < chars.len() && chars[pos] != quote {
                    if chars[pos] == '\\'
                        && pos + 1 < chars.len()
                        && chars[pos + 1] == 'x'
                        && pos + 3 < chars.len()
                    {
                        // \xHH
                        hex.push(chars[pos + 2]);
                        hex.push(chars[pos + 3]);
                        pos += 4;
                    } else {
                        // Non-hex byte -- encode as hex
                        let byte = chars[pos] as u32;
                        hex.push_str(&format!("{:02x}", byte));
                        pos += 1;
                    }
                }
                if pos < chars.len() {
                    pos += 1; // skip closing quote
                }
                tokens.push(Token::HexStringLit(hex));
                continue;
            }

            // String literals (single or double quoted)
            if ch == '\'' || ch == '"' {
                let quote = ch;
                pos += 1;
                let mut val = String::new();
                while pos < chars.len() && chars[pos] != quote {
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
                while pos < chars.len() && (chars[pos].is_ascii_alphanumeric() || chars[pos] == '_')
                {
                    pos += 1;
                }
                let word: String = chars[start..pos].iter().collect();
                let tok = match word.as_str() {
                    "class" => Token::Class,
                    "def" => Token::Def,
                    "if" => Token::If,
                    "elif" => Token::Elif,
                    "else" => Token::Else,
                    "for" => Token::For,
                    "in" => Token::In,
                    "range" => Token::Range,
                    "return" => Token::Return,
                    "pass" => Token::Pass,
                    "True" => Token::TrueLit,
                    "False" => Token::FalseLit,
                    "None" => Token::NoneLit,
                    "and" => Token::And,
                    "or" => Token::Or,
                    "not" => Token::Not,
                    "self" => Token::SelfKw,
                    "super" => Token::Super,
                    "from" => Token::From,
                    "import" => Token::Import,
                    "assert" => Token::Assert,
                    _ => Token::Ident(word),
                };
                tokens.push(tok);
                continue;
            }

            // Skip unrecognized characters
            pos += 1;
        }

        // Emit NEWLINE at end of significant line (only if not inside parens)
        if paren_depth == 0 {
            tokens.push(Token::Newline);
        }
    }

    // Emit remaining DEDENTs
    while indent_stack.len() > 1 {
        indent_stack.pop();
        tokens.push(Token::Dedent);
    }

    tokens.push(Token::Eof);
    tokens
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct PyParser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    file: &'a str,
    errors: &'a mut Vec<Diagnostic>,
}

impl<'a> PyParser<'a> {
    fn new(tokens: Vec<Token>, file: &'a str, errors: &'a mut Vec<Diagnostic>) -> Self {
        Self {
            tokens,
            pos: 0,
            file,
            errors,
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
            self.errors.push(Diagnostic::error(format!(
                "Expected {:?}, got {:?}",
                expected,
                self.peek()
            ), None));
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
                    .push(Diagnostic::error(format!("Expected identifier, got {:?}", other), None));
                "_error".to_string()
            }
        }
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

        // Skip `from runar import ...` lines
        while *self.peek() == Token::From || *self.peek() == Token::Import {
            self.parse_import_line();
            self.skip_newlines();
        }

        self.skip_newlines();

        if *self.peek() != Token::Class {
            self.errors
                .push(Diagnostic::error("Expected 'class' declaration", None));
            return None;
        }

        self.advance(); // consume 'class'
        let contract_name = self.expect_ident();
        self.expect(&Token::LParen);
        let parent_class = self.expect_ident();
        self.expect(&Token::RParen);
        self.expect(&Token::Colon);
        self.skip_newlines();
        self.expect(&Token::Indent);
        self.skip_newlines();

        if parent_class != "SmartContract" && parent_class != "StatefulSmartContract" {
            self.errors.push(Diagnostic::error(format!(
                "Unknown parent class: {}",
                parent_class
            ), None));
            return None;
        }

        let mut properties = Vec::new();
        let mut methods = Vec::new();
        let mut constructor: Option<MethodNode> = None;

        while *self.peek() != Token::Dedent && *self.peek() != Token::Eof {
            self.skip_newlines();
            if *self.peek() == Token::Dedent || *self.peek() == Token::Eof {
                break;
            }

            // Decorators
            let mut decorators: Vec<String> = Vec::new();
            while *self.peek() == Token::At {
                self.advance(); // '@'
                let dec_name = match self.advance() {
                    Token::Ident(name) => name,
                    other => {
                        self.errors
                            .push(Diagnostic::error(format!("Expected decorator name, got {:?}", other), None));
                        String::new()
                    }
                };
                decorators.push(dec_name);
                self.skip_newlines();
            }

            // Method definition
            if *self.peek() == Token::Def {
                let method = self.parse_method_def(&decorators);
                if method.name == "constructor" {
                    constructor = Some(method);
                } else {
                    methods.push(method);
                }
                self.skip_newlines();
                continue;
            }

            // Property: name: Type
            if let Token::Ident(_) = self.peek().clone() {
                if let Some(prop) = self.parse_property(&parent_class) {
                    properties.push(prop);
                }
                self.skip_newlines();
                continue;
            }

            // Skip unknown tokens
            self.advance();
        }

        self.match_tok(&Token::Dedent);

        // Auto-generate constructor if not provided
        let constructor = constructor
            .unwrap_or_else(|| build_constructor(&properties, self.file));

        Some(ContractNode {
            name: contract_name,
            parent_class,
            properties,
            constructor,
            methods,
            source_file: self.file.to_string(),
        })
    }

    fn parse_import_line(&mut self) {
        // from X import Y, Z, ...
        // or: import X
        if *self.peek() == Token::From {
            self.advance(); // 'from'
            // consume module path
            while *self.peek() != Token::Import
                && *self.peek() != Token::Newline
                && *self.peek() != Token::Eof
            {
                self.advance();
            }
            if self.match_tok(&Token::Import) {
                // consume imported names
                while *self.peek() != Token::Newline && *self.peek() != Token::Eof {
                    self.advance();
                }
            }
        } else if *self.peek() == Token::Import {
            self.advance();
            while *self.peek() != Token::Newline && *self.peek() != Token::Eof {
                self.advance();
            }
        }
        self.skip_newlines();
    }

    // -----------------------------------------------------------------------
    // Properties
    // -----------------------------------------------------------------------

    fn parse_property(&mut self, parent_class: &str) -> Option<PropertyNode> {
        let raw_name = self.expect_ident();

        if *self.peek() != Token::Colon {
            // Not a property -- might be a stray identifier; skip the line
            while *self.peek() != Token::Newline && *self.peek() != Token::Eof {
                self.advance();
            }
            return None;
        }
        self.advance(); // consume ':'

        // Parse type (possibly Readonly[T])
        let mut is_readonly = false;
        let type_node;

        if let Token::Ident(ref name) = *self.peek() {
            if name == "Readonly" {
                is_readonly = true;
                self.advance(); // consume 'Readonly'
                self.expect(&Token::LBracket);
                type_node = self.parse_type();
                self.expect(&Token::RBracket);
            } else {
                type_node = self.parse_type();
            }
        } else {
            type_node = self.parse_type();
        }

        // In stateless contracts, all properties are readonly
        if parent_class == "SmartContract" {
            is_readonly = true;
        }

        // Parse optional initializer: = value
        let initializer = if *self.peek() == Token::Eq {
            self.advance(); // consume '='
            Some(self.parse_expression())
        } else {
            None
        };

        // Skip rest of line
        while *self.peek() != Token::Newline
            && *self.peek() != Token::Eof
            && *self.peek() != Token::Dedent
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
                        .push(Diagnostic::error("FixedArray requires numeric length", None));
                    0
                }
            };
            self.expect(&Token::RBracket);
            return TypeNode::FixedArray {
                element: Box::new(element),
                length,
            };
        }

        let mapped = map_py_type(&raw_name);
        if let Some(prim) = PrimitiveTypeName::from_str(mapped) {
            TypeNode::Primitive(prim)
        } else {
            TypeNode::Custom(mapped.to_string())
        }
    }

    // -----------------------------------------------------------------------
    // Method definitions
    // -----------------------------------------------------------------------

    fn parse_method_def(&mut self, decorators: &[String]) -> MethodNode {
        self.expect(&Token::Def);

        let raw_name = match self.advance() {
            Token::Ident(name) => name,
            other => {
                self.errors
                    .push(Diagnostic::error(format!("Expected method name, got {:?}", other), None));
                "_error".to_string()
            }
        };

        self.expect(&Token::LParen);
        let params = self.parse_params();
        self.expect(&Token::RParen);

        // Optional return type annotation: -> Type
        if self.match_tok(&Token::Arrow) {
            self.parse_type(); // consume and discard return type
        }

        self.expect(&Token::Colon);
        self.skip_newlines();
        self.expect(&Token::Indent);

        let body = self.parse_statements();

        self.match_tok(&Token::Dedent);

        // Determine if this is the constructor
        if raw_name == "__init__" {
            return MethodNode {
                name: "constructor".to_string(),
                params,
                body,
                visibility: Visibility::Public,
                source_location: self.loc(),
            };
        }

        let is_public = decorators.contains(&"public".to_string());
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

    fn parse_params(&mut self) -> Vec<ParamNode> {
        let mut params = Vec::new();

        while *self.peek() != Token::RParen && *self.peek() != Token::Eof {
            // Skip 'self' parameter
            if *self.peek() == Token::SelfKw {
                self.advance();
                if *self.peek() == Token::Comma {
                    self.advance();
                }
                continue;
            }

            let raw_name = self.expect_ident();

            let param_type = if self.match_tok(&Token::Colon) {
                self.parse_type()
            } else {
                TypeNode::Custom("unknown".to_string())
            };

            params.push(ParamNode {
                name: snake_to_camel(&raw_name),
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

        while *self.peek() != Token::Dedent && *self.peek() != Token::Eof {
            self.skip_newlines();
            if *self.peek() == Token::Dedent || *self.peek() == Token::Eof {
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

            // for statement
            Token::For => Some(self.parse_for_statement()),

            // return statement
            Token::Return => Some(self.parse_return_statement()),

            // pass statement
            Token::Pass => {
                self.advance();
                None
            }

            // super().__init__(...) -- constructor super call
            Token::Super => Some(self.parse_super_call()),

            // self.prop = expr (assignment to property) or self.method(...)
            Token::SelfKw => Some(self.parse_self_statement()),

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
        self.expect(&Token::Colon);
        self.skip_newlines();
        self.expect(&Token::Indent);
        let then_branch = self.parse_statements();
        self.match_tok(&Token::Dedent);
        self.skip_newlines();

        let else_branch = if *self.peek() == Token::Elif {
            // elif -> else { if ... }
            Some(vec![self.parse_elif_statement()])
        } else if *self.peek() == Token::Else {
            self.advance(); // 'else'
            self.expect(&Token::Colon);
            self.skip_newlines();
            self.expect(&Token::Indent);
            let stmts = self.parse_statements();
            self.match_tok(&Token::Dedent);
            Some(stmts)
        } else {
            None
        };

        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            source_location: self.loc(),
        }
    }

    fn parse_elif_statement(&mut self) -> Statement {
        self.advance(); // consume 'elif'
        let condition = self.parse_expression();
        self.expect(&Token::Colon);
        self.skip_newlines();
        self.expect(&Token::Indent);
        let then_branch = self.parse_statements();
        self.match_tok(&Token::Dedent);
        self.skip_newlines();

        let else_branch = if *self.peek() == Token::Elif {
            Some(vec![self.parse_elif_statement()])
        } else if *self.peek() == Token::Else {
            self.advance();
            self.expect(&Token::Colon);
            self.skip_newlines();
            self.expect(&Token::Indent);
            let stmts = self.parse_statements();
            self.match_tok(&Token::Dedent);
            Some(stmts)
        } else {
            None
        };

        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            source_location: self.loc(),
        }
    }

    fn parse_for_statement(&mut self) -> Statement {
        self.advance(); // consume 'for'

        let raw_var = self.expect_ident();
        let var_name = snake_to_camel(&raw_var);

        self.expect(&Token::In);
        self.expect(&Token::Range);
        self.expect(&Token::LParen);

        // range(n) or range(a, b)
        let first_arg = self.parse_expression();
        let (start_expr, end_expr) = if self.match_tok(&Token::Comma) {
            let second_arg = self.parse_expression();
            (first_arg, second_arg)
        } else {
            (Expression::BigIntLiteral { value: 0 }, first_arg)
        };

        self.expect(&Token::RParen);
        self.expect(&Token::Colon);
        self.skip_newlines();
        self.expect(&Token::Indent);
        let body = self.parse_statements();
        self.match_tok(&Token::Dedent);

        // Construct a C-style for loop AST node:
        // for (let varName: bigint = startExpr; varName < endExpr; varName++)
        let init = Statement::VariableDecl {
            name: var_name.clone(),
            var_type: Some(TypeNode::Primitive(PrimitiveTypeName::Bigint)),
            mutable: true,
            init: start_expr,
            source_location: self.loc(),
        };

        let condition = Expression::BinaryExpr {
            op: BinaryOp::Lt,
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
            && *self.peek() != Token::Dedent
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
        // super().__init__(...) -> super(args) in AST
        self.advance(); // 'super'
        self.expect(&Token::LParen);
        self.expect(&Token::RParen);
        self.expect(&Token::Dot);

        // Expect __init__
        let method_name = self.expect_ident();
        if method_name != "__init__" {
            self.errors.push(Diagnostic::error(format!(
                "Expected __init__ after super(), got '{}'",
                method_name
            ), None));
        }

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

    fn parse_self_statement(&mut self) -> Statement {
        // self.prop = expr  or  self.prop += expr  or  self.method(...)
        let expr = self.parse_expression();

        // Simple assignment: self.x = expr
        if self.match_tok(&Token::Eq) {
            let value = self.parse_expression();
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }

        // Compound assignments
        if *self.peek() == Token::PlusEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Add,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }
        if *self.peek() == Token::MinusEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Sub,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }
        if *self.peek() == Token::StarEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Mul,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }
        if *self.peek() == Token::SlashEq || *self.peek() == Token::IntDivEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Div,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }
        if *self.peek() == Token::PercentEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Mod,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }

        // Expression statement (method call)
        Statement::ExpressionStatement {
            expression: expr,
            source_location: self.loc(),
        }
    }

    fn parse_ident_statement(&mut self) -> Statement {
        // Could be:
        // 1. name: Type = expr  (variable declaration with type annotation)
        // 2. name = expr  (variable declaration without type)
        // 3. name(...)  (expression statement / function call)
        // 4. name += expr (compound assignment)

        let raw_name = match self.peek().clone() {
            Token::Ident(ref name) => name.clone(),
            _ => "_error".to_string(),
        };

        // Look ahead: if next token after ident is ':', it's a typed variable decl
        if self.tokens.get(self.pos + 1).map_or(false, |t| *t == Token::Colon) {
            self.advance(); // consume ident
            self.advance(); // consume ':'

            // Check if it's Readonly[T] -- that would be a property, not a var decl,
            // but at statement level it means typed var decl with Readonly as a type name.
            let type_node = self.parse_type();

            let init = if self.match_tok(&Token::Eq) {
                self.parse_expression()
            } else {
                Expression::BigIntLiteral { value: 0 }
            };

            return Statement::VariableDecl {
                name: snake_to_camel(&raw_name),
                var_type: Some(type_node),
                mutable: true,
                init,
                source_location: self.loc(),
            };
        }

        // Check for simple name = expr pattern (no type annotation)
        if self.tokens.get(self.pos + 1).map_or(false, |t| *t == Token::Eq) {
            self.advance(); // consume ident
            self.advance(); // consume '='
            let value = self.parse_expression();
            return Statement::VariableDecl {
                name: snake_to_camel(&raw_name),
                var_type: None,
                mutable: true,
                init: value,
                source_location: self.loc(),
            };
        }

        // Parse as expression first
        let expr = self.parse_expression();

        // Simple assignment (for a.b = expr)
        if self.match_tok(&Token::Eq) {
            let value = self.parse_expression();
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }

        // Compound assignments
        if *self.peek() == Token::PlusEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Add,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }
        if *self.peek() == Token::MinusEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Sub,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }
        if *self.peek() == Token::StarEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Mul,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }
        if *self.peek() == Token::SlashEq || *self.peek() == Token::IntDivEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Div,
                left: Box::new(expr.clone()),
                right: Box::new(rhs),
            };
            return Statement::Assignment {
                target: expr,
                value,
                source_location: self.loc(),
            };
        }
        if *self.peek() == Token::PercentEq {
            self.advance();
            let rhs = self.parse_expression();
            let value = Expression::BinaryExpr {
                op: BinaryOp::Mod,
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

    /// Python conditional expression: `x if cond else y`
    /// Parsed as postfix: parse or-expr first, then check for 'if'.
    fn parse_ternary(&mut self) -> Expression {
        let expr = self.parse_or();

        if *self.peek() == Token::If {
            self.advance(); // 'if'
            let condition = self.parse_or();
            self.expect(&Token::Else);
            let alternate = self.parse_ternary();
            Expression::TernaryExpr {
                condition: Box::new(condition),
                consequent: Box::new(expr),
                alternate: Box::new(alternate),
            }
        } else {
            expr
        }
    }

    fn parse_or(&mut self) -> Expression {
        let mut left = self.parse_and();
        while *self.peek() == Token::Or {
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
        while *self.peek() == Token::And {
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
        if *self.peek() == Token::Not {
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
                Token::IntDiv => {
                    // Python integer division // maps to / in AST (OP_DIV)
                    self.advance();
                    let right = self.parse_unary();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Div,
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
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Expression {
        let mut expr = self.parse_primary();

        loop {
            match self.peek().clone() {
                Token::Dot => {
                    self.advance(); // '.'
                    let raw_prop = self.expect_ident();
                    let prop = snake_to_camel(&raw_prop);

                    // Check if it's a method call
                    if *self.peek() == Token::LParen {
                        let args = self.parse_call_args();
                        // Handle self.method(...) -> this.method(...)
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
            Token::NoneLit => Expression::BigIntLiteral { value: 0 },
            Token::HexStringLit(v) => Expression::ByteStringLiteral { value: v },
            Token::StringLit(v) => Expression::ByteStringLiteral { value: v },
            Token::SelfKw => {
                // self -> this
                Expression::Identifier {
                    name: "this".to_string(),
                }
            }
            Token::Ident(name) => {
                // Check for bytes.fromhex("...")
                if name == "bytes" && *self.peek() == Token::Dot {
                    if let Some(Token::Ident(ref next_name)) = self.tokens.get(self.pos + 1) {
                        if next_name == "fromhex" {
                            self.advance(); // '.'
                            self.advance(); // 'fromhex'
                            self.expect(&Token::LParen);
                            let val = match self.advance() {
                                Token::StringLit(s) => s,
                                _ => {
                                    self.errors
                                        .push(Diagnostic::error("Expected string in bytes.fromhex()", None));
                                    String::new()
                                }
                            };
                            self.expect(&Token::RParen);
                            return Expression::ByteStringLiteral { value: val };
                        }
                    }
                }

                let mapped = map_builtin_name(&name);
                Expression::Identifier { name: mapped }
            }
            Token::Assert => {
                // assert used as expression (unusual but handle it)
                // In Python, `assert_(expr)` is an ident, but `assert expr` uses the keyword.
                // If we get here, it means `assert` keyword was used as an expression callee.
                Expression::Identifier {
                    name: "assert".to_string(),
                }
            }
            Token::LParen => {
                let expr = self.parse_expression();
                self.expect(&Token::RParen);
                expr
            }
            other => {
                self.errors
                    .push(Diagnostic::error(format!("Unexpected token in expression: {:?}", other), None));
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
    // Only include properties without initializers as constructor params
    let uninit_props: Vec<&PropertyNode> = properties
        .iter()
        .filter(|p| p.initializer.is_none())
        .collect();

    let params: Vec<ParamNode> = uninit_props
        .iter()
        .map(|p| ParamNode {
            name: p.name.clone(),
            param_type: p.prop_type.clone(),
        })
        .collect();

    let mut body: Vec<Statement> = Vec::new();

    // super(...) call — only non-initialized property names as args
    let super_args: Vec<Expression> = uninit_props
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

    // this.x = x for each non-initialized property
    for p in &uninit_props {
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
        assert_eq!(snake_to_camel("sum_"), "sum");
        assert_eq!(snake_to_camel("assert_"), "assert");
    }

    #[test]
    fn test_builtin_name_mapping() {
        assert_eq!(map_builtin_name("assert_"), "assert");
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
    fn test_parse_simple_python_contract() {
        let source = r#"
from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig

class P2PKH(SmartContract):
    pub_key_hash: Addr

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
"#;

        let result = parse_python(source, Some("P2PKH.runar.py"));
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
        // self param should be excluded
        assert_eq!(contract.methods[0].params.len(), 2);
        assert_eq!(contract.methods[0].params[0].name, "sig");
        assert_eq!(contract.methods[0].params[1].name, "pubKey");
    }

    #[test]
    fn test_parse_stateful_python_contract() {
        let source = r#"
from runar import StatefulSmartContract, Bigint, Readonly, public, assert_

class Stateful(StatefulSmartContract):
    count: Bigint
    max_count: Readonly[Bigint]

    def __init__(self, count: Bigint, max_count: Bigint):
        super().__init__(count, max_count)
        self.count = count
        self.max_count = max_count

    @public
    def increment(self, amount: Bigint):
        self.count = self.count + amount
        assert_(self.count <= self.max_count)

    @public
    def reset(self):
        self.count = 0
"#;

        let result = parse_python(source, Some("Stateful.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.name, "Stateful");
        assert_eq!(contract.parent_class, "StatefulSmartContract");
        assert_eq!(contract.properties.len(), 2);
        assert_eq!(contract.properties[0].name, "count");
        assert!(!contract.properties[0].readonly);
        assert_eq!(contract.properties[1].name, "maxCount");
        assert!(contract.properties[1].readonly);
        assert_eq!(contract.methods.len(), 2);
    }

    #[test]
    fn test_parse_for_loop() {
        let source = r#"
from runar import SmartContract, Bigint, public, assert_

class BoundedLoop(SmartContract):
    expected_sum: Bigint

    def __init__(self, expected_sum: Bigint):
        super().__init__(expected_sum)
        self.expected_sum = expected_sum

    @public
    def verify(self, start: Bigint):
        sum_: Bigint = 0
        for i in range(5):
            sum_ = sum_ + start + i
        assert_(sum_ == self.expected_sum)
"#;

        let result = parse_python(source, Some("BoundedLoop.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods[0].name, "verify");
        // body: let sum, for, assert
        assert_eq!(contract.methods[0].body.len(), 3);
    }

    #[test]
    fn test_parse_if_else() {
        let source = r#"
from runar import SmartContract, Bigint, public, assert_

class IfElse(SmartContract):
    limit: Bigint

    def __init__(self, limit: Bigint):
        super().__init__(limit)
        self.limit = limit

    @public
    def check(self, value: Bigint, mode: bool):
        result: Bigint = 0
        if mode:
            result = value + self.limit
        else:
            result = value - self.limit
        assert_(result > 0)
"#;

        let result = parse_python(source, Some("IfElse.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods[0].body.len(), 3); // let result, if/else, assert
    }

    #[test]
    fn test_eq_maps_to_strict_eq() {
        let source = r#"
from runar import SmartContract, Bigint, public, assert_

class Test(SmartContract):
    x: Bigint

    @public
    def check(self, y: Bigint):
        assert_(self.x == y)
        assert_(self.x != y)
"#;

        let result = parse_python(source, Some("Test.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;
        assert_eq!(body.len(), 2);

        // First assert: StrictEq
        if let Statement::ExpressionStatement { expression, .. } = &body[0] {
            if let Expression::CallExpr { args, .. } = expression {
                if let Expression::BinaryExpr { op, .. } = &args[0] {
                    assert_eq!(*op, BinaryOp::StrictEq);
                } else {
                    panic!("Expected BinaryExpr inside assert");
                }
            } else {
                panic!("Expected CallExpr for assert");
            }
        }

        // Second assert: StrictNe
        if let Statement::ExpressionStatement { expression, .. } = &body[1] {
            if let Expression::CallExpr { args, .. } = expression {
                if let Expression::BinaryExpr { op, .. } = &args[0] {
                    assert_eq!(*op, BinaryOp::StrictNe);
                } else {
                    panic!("Expected BinaryExpr inside assert");
                }
            }
        }
    }

    #[test]
    fn test_self_to_this_conversion() {
        let source = r#"
from runar import StatefulSmartContract, Bigint, public

class Example(StatefulSmartContract):
    value: Bigint

    @public
    def set_value(self, new_value: Bigint):
        self.value = new_value
"#;

        let result = parse_python(source, Some("Example.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;
        assert_eq!(body.len(), 1);

        // Should be this.value = newValue (with PropertyAccess)
        if let Statement::Assignment { target, .. } = &body[0] {
            match target {
                Expression::PropertyAccess { property } => {
                    assert_eq!(property, "value");
                }
                _ => panic!("Expected PropertyAccess, got {:?}", target),
            }
        }
        // Method name and param should be camelCase
        assert_eq!(contract.methods[0].name, "setValue");
        assert_eq!(contract.methods[0].params[0].name, "newValue");
    }

    #[test]
    fn test_constructor_auto_generated() {
        let source = r#"
from runar import SmartContract, Bigint, PubKey, public, assert_

class Test(SmartContract):
    a: Bigint
    b: PubKey

    @public
    def check(self):
        assert_(self.a > 0)
"#;

        let result = parse_python(source, None);
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        // Constructor should have params for each property
        assert_eq!(contract.constructor.params.len(), 2);
        // Constructor body: super(a, b) + this.a = a + this.b = b
        assert_eq!(contract.constructor.body.len(), 3);
    }

    #[test]
    fn test_python_integer_division() {
        let source = r#"
from runar import SmartContract, Bigint, public, assert_

class DivTest(SmartContract):
    x: Bigint

    @public
    def check(self, y: Bigint):
        result: Bigint = self.x // y
        assert_(result > 0)
"#;

        let result = parse_python(source, Some("DivTest.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;

        // First statement should be a variable decl with init being BinaryExpr Div
        if let Statement::VariableDecl { init, .. } = &body[0] {
            if let Expression::BinaryExpr { op, .. } = init {
                assert_eq!(*op, BinaryOp::Div);
            } else {
                panic!("Expected BinaryExpr Div, got {:?}", init);
            }
        }
    }

    #[test]
    fn test_ternary_expression() {
        let source = r#"
from runar import SmartContract, Bigint, public, assert_

class TernTest(SmartContract):
    x: Bigint

    @public
    def check(self, cond: bool):
        result: Bigint = 1 if cond else 0
        assert_(result == self.x)
"#;

        let result = parse_python(source, Some("TernTest.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;

        // First statement should be variable decl with ternary init
        if let Statement::VariableDecl { init, .. } = &body[0] {
            match init {
                Expression::TernaryExpr { .. } => {} // OK
                _ => panic!("Expected TernaryExpr, got {:?}", init),
            }
        }
    }

    #[test]
    fn test_assert_keyword_as_statement() {
        let source = r#"
from runar import SmartContract, Bigint, public

class AssertTest(SmartContract):
    x: Bigint

    @public
    def check(self, y: Bigint):
        assert self.x == y
"#;

        let result = parse_python(source, Some("AssertTest.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;
        assert_eq!(body.len(), 1);

        if let Statement::ExpressionStatement { expression, .. } = &body[0] {
            if let Expression::CallExpr { callee, .. } = expression {
                if let Expression::Identifier { name } = callee.as_ref() {
                    assert_eq!(name, "assert");
                }
            }
        }
    }

    #[test]
    fn test_hex_byte_string() {
        let source = r#"
from runar import SmartContract, ByteString, public, assert_

class HexTest(SmartContract):
    data: ByteString

    @public
    def check(self):
        val: ByteString = b'\xde\xad'
        assert_(val == self.data)
"#;

        let result = parse_python(source, Some("HexTest.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;

        if let Statement::VariableDecl { init, .. } = &body[0] {
            if let Expression::ByteStringLiteral { value } = init {
                assert_eq!(value, "dead");
            } else {
                panic!("Expected ByteStringLiteral, got {:?}", init);
            }
        }
    }

    #[test]
    fn test_shift_operators() {
        let source = r#"
from runar import SmartContract, Bigint, public, assert_

class ShiftTest(SmartContract):
    x: Bigint

    @public
    def check(self, n: Bigint):
        a: Bigint = self.x << n
        b: Bigint = self.x >> n
        assert_(a + b > 0)
"#;

        let result = parse_python(source, Some("ShiftTest.runar.py"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;

        // First var decl should have Shl
        if let Statement::VariableDecl { init, .. } = &body[0] {
            if let Expression::BinaryExpr { op, .. } = init {
                assert_eq!(*op, BinaryOp::Shl);
            }
        }
        // Second var decl should have Shr
        if let Statement::VariableDecl { init, .. } = &body[1] {
            if let Expression::BinaryExpr { op, .. } = init {
                assert_eq!(*op, BinaryOp::Shr);
            }
        }
    }
}
