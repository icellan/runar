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

use super::ast::{
    BinaryOp, ContractNode, Expression, MethodNode, ParamNode, PrimitiveTypeName, PropertyNode,
    SourceLocation, Statement, TypeNode, UnaryOp, Visibility,
};
use super::parser::ParseResult;
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a Zig-format Rúnar contract source.
pub fn parse_zig(source: &str, file_name: Option<&str>) -> ParseResult {
    use super::diagnostic::Diagnostic;

    let file = file_name.unwrap_or("contract.runar.zig");
    let mut str_errors: Vec<String> = Vec::new();

    let tokens = tokenize(source);
    let mut parser = ZigParser::new(tokens, file, &mut str_errors);

    let contract = parser.parse_contract();

    let errors = str_errors
        .into_iter()
        .map(|msg| Diagnostic::error(msg, None))
        .collect();

    ParseResult { contract, errors }
}

// ---------------------------------------------------------------------------
// Type mapping
// ---------------------------------------------------------------------------

/// Map Zig type names to Rúnar primitive type names.
fn map_zig_type(name: &str) -> &str {
    match name {
        "i8" | "i16" | "i32" | "i64" | "i128" | "isize" => "bigint",
        "u8" | "u16" | "u32" | "u64" | "u128" | "usize" => "bigint",
        "comptime_int" => "bigint",
        "Bigint" => "bigint",
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

    // Identifiers and literals
    Ident(String),
    NumberLit(i128),
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

fn tokenize(source: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = source.chars().collect();
    let mut pos = 0;

    while pos < chars.len() {
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
            if ch == '0' && pos + 1 < chars.len() && (chars[pos + 1] == 'x' || chars[pos + 1] == 'X')
            {
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
                i128::from_str_radix(&num_str[2..], 16).unwrap_or(0)
            } else {
                num_str.parse::<i128>().unwrap_or(0)
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

        // Skip unrecognised characters
        pos += 1;
    }

    tokens.push(Token::Eof);
    tokens
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct ZigParser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    file: &'a str,
    errors: &'a mut Vec<String>,
    contract_name: String,
    /// Names used as `self` receiver (first parameter whose type == contract name).
    self_names: HashSet<String>,
    /// Names of parameters typed as `StatefulContext`.
    stateful_context_names: HashSet<String>,
}

impl<'a> ZigParser<'a> {
    fn new(tokens: Vec<Token>, file: &'a str, errors: &'a mut Vec<String>) -> Self {
        Self {
            tokens,
            pos: 0,
            file,
            errors,
            contract_name: String::new(),
            self_names: HashSet::new(),
            stateful_context_names: HashSet::new(),
        }
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

    fn loc(&self) -> SourceLocation {
        SourceLocation {
            file: self.file.to_string(),
            line: 1,
            column: 0,
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
        // - Strip `initializer` for properties that are also constructor
        //   params (the constructor param overrides the default; the Zig
        //   compiler reference omits `initialValue` in this case).
        let ctor_param_names: HashSet<String> = constructor
            .params
            .iter()
            .map(|p| p.name.clone())
            .collect();
        for prop in &mut properties {
            let had_initializer = prop.initializer.is_some();
            if ctor_param_names.contains(&prop.name) {
                prop.initializer = None;
            }
            if parent_class == "SmartContract" {
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
            let name = self.expect_ident();
            if name == "StatefulSmartContract" {
                parent = "StatefulSmartContract".to_string();
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
        let (type_node, is_readonly) = self.parse_type();
        let mut initializer: Option<Expression> = None;

        // Optional field initializer: `= value`
        if *self.peek() == Token::Eq {
            self.advance();
            initializer = Some(self.parse_expression());
        }

        // Trailing comma
        self.match_tok(&Token::Comma);

        Some(PropertyNode {
            name,
            prop_type: type_node,
            readonly: is_readonly,
            initializer,
            source_location: self.loc(),
            synthetic_array_chain: None,
        })
    }

    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    /// Parse a type, returning (TypeNode, is_readonly).
    fn parse_type(&mut self) -> (TypeNode, bool) {
        // Array type: [N]T
        if *self.peek() == Token::LBracket {
            self.advance(); // [
            let length = match self.advance() {
                Token::NumberLit(n) => n as usize,
                _ => {
                    self.errors.push("Expected array length".to_string());
                    0
                }
            };
            self.expect(&Token::RBracket);
            let (element, readonly) = self.parse_type();
            return (
                TypeNode::FixedArray {
                    element: Box::new(element),
                    length,
                },
                readonly,
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
                let (inner, _) = self.parse_type();
                self.expect(&Token::RParen);
                return (inner, true);
            }

            let mapped = map_zig_type(&name);
            return (make_type_node(mapped), false);
        }

        // void keyword
        if *self.peek() == Token::Void {
            self.advance();
            return (TypeNode::Primitive(PrimitiveTypeName::Void), false);
        }

        // Plain identifier type
        if matches!(self.peek(), Token::Ident(_)) {
            let name = self.expect_ident();
            let mapped = map_zig_type(&name);
            return (make_type_node(mapped), false);
        }

        // Fallback
        self.advance();
        (TypeNode::Custom("unknown".to_string()), false)
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

        // Skip return type (everything before '{')
        if *self.peek() != Token::LBrace {
            self.parse_type();
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
            });
        }

        let body = self.parse_block_statements();
        self.self_names = prev_self_names;
        self.stateful_context_names = prev_stateful_ctx;

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
                stateful_ctx_names.insert(param_name.clone());
                params.push(ParamNode {
                    name: param_name,
                    param_type: type_node,
                });
            } else {
                params.push(ParamNode {
                    name: param_name,
                    param_type: type_node,
                });
            }

            index += 1;
            self.match_tok(&Token::Comma);
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
            if *self.peek() == Token::Dot {
                self.advance(); // .
            }
            let field = self.expect_ident();
            self.expect(&Token::Eq);
            let value = self.parse_expression();
            assignments.push(Statement::Assignment {
                target: Expression::PropertyAccess {
                    property: field,
                },
                value,
                source_location: self.loc(),
            });
            self.match_tok(&Token::Comma);
        }

        self.expect(&Token::RBrace);
        assignments
    }

    fn create_super_call(&self, params: &[ParamNode]) -> Statement {
        let super_args: Vec<Expression> = params
            .iter()
            .map(|p| Expression::Identifier {
                name: p.name.clone(),
            })
            .collect();
        Statement::ExpressionStatement {
            expression: Expression::CallExpr {
                callee: Box::new(Expression::Identifier {
                    name: "super".to_string(),
                }),
                args: super_args,
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
                        if name == "__while_no_init" {
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

        // _ = expr; (discard expression)
        if matches!(self.peek(), Token::Ident(ref n) if n == "_")
            && *self.peek_at(1) == Token::Eq
        {
            self.advance(); // _
            self.advance(); // =
            self.parse_expression();
            self.match_tok(&Token::Semicolon);
            return None;
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
                Some(vec![self.parse_if_statement()])
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
            source_location: self.loc(),
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
    /// Emits a ForStatement. The init is synthesized as `var __while_no_init = 0`
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
                expression: Expression::BigIntLiteral { value: 0 },
                source_location: self.loc(),
            };
        }

        let body = self.parse_block_statements();

        // Emit a for_statement. The init will be patched by parse_block_statements
        // if the preceding statement was a variable_decl for the loop variable.
        Statement::ForStatement {
            init: Box::new(Statement::VariableDecl {
                name: "__while_no_init".to_string(),
                var_type: None,
                mutable: true,
                init: Expression::BigIntLiteral { value: 0 },
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
        self.parse_ternary()
    }

    /// No ternary operator in Zig, but parse_ternary provides the top level.
    fn parse_ternary(&mut self) -> Expression {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Expression {
        let mut left = self.parse_and();
        while *self.peek() == Token::OrOr {
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
        let mut left = self.parse_bit_or();
        while *self.peek() == Token::AndAnd {
            self.advance();
            let right = self.parse_bit_or();
            left = Expression::BinaryExpr {
                op: BinaryOp::And,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        left
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
            Token::Bang => {
                self.advance();
                let operand = self.parse_unary();
                Expression::UnaryExpr {
                    op: UnaryOp::Not,
                    operand: Box::new(operand),
                }
            }
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
            _ => {
                let expr = self.parse_primary();
                self.parse_postfix(expr)
            }
        }
    }

    fn parse_primary(&mut self) -> Expression {
        // Anonymous struct literal: .{ ... }
        if *self.peek() == Token::Dot && *self.peek_at(1) == Token::LBrace {
            self.advance(); // .
            self.advance(); // {
            let mut elements = Vec::new();
            while *self.peek() != Token::RBrace && *self.peek() != Token::Eof {
                elements.push(self.parse_expression());
                self.match_tok(&Token::Comma);
            }
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
            if let Token::StringLit(v) = self.advance() {
                return Expression::ByteStringLiteral { value: v };
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

        // Array literal: [ ... ]
        if *self.peek() == Token::LBracket {
            self.advance();
            let mut elements = Vec::new();
            while *self.peek() != Token::RBracket && *self.peek() != Token::Eof {
                elements.push(self.parse_expression());
                self.match_tok(&Token::Comma);
            }
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
                        };
                    }

                    return Expression::Identifier { name: builtin };
                }

                return Expression::Identifier { name };
            }
        }

        // Fallback
        self.advance();
        Expression::BigIntLiteral { value: 0 }
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
                        }),
                        args,
                    }
                } else {
                    self.errors
                        .push(format!("Unsupported Zig builtin '@{}'", name));
                    Expression::Identifier {
                        name: name.to_string(),
                    }
                }
            }
        }
    }

    /// Parse postfix operations: `.prop`, `(args)`, `[index]`.
    fn parse_postfix(&mut self, mut expr: Expression) -> Expression {
        loop {
            match self.peek() {
                Token::LParen => {
                    self.advance(); // (
                    let mut args = Vec::new();
                    while *self.peek() != Token::RParen && *self.peek() != Token::Eof {
                        args.push(self.parse_expression());
                        self.match_tok(&Token::Comma);
                    }
                    self.expect(&Token::RParen);
                    expr = Expression::CallExpr {
                        callee: Box::new(expr),
                        args,
                    };
                }
                Token::Dot => {
                    self.advance(); // .
                    let prop = self.expect_ident();

                    // self.property -> PropertyAccess
                    if let Expression::Identifier { ref name } = expr {
                        if self.self_names.contains(name) {
                            expr = Expression::PropertyAccess {
                                property: prop,
                            };
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
                                expr = Expression::PropertyAccess { property: prop };
                                continue;
                            }
                        }
                    }

                    expr = Expression::MemberExpr {
                        object: Box::new(expr),
                        property: prop,
                    };
                }
                Token::LBracket => {
                    self.advance(); // [
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
// Helper: get loop update target name from a ForStatement
// ---------------------------------------------------------------------------

fn get_loop_update_target(stmt: &Statement) -> Option<String> {
    if let Statement::ForStatement { update, .. } = stmt {
        match update.as_ref() {
            Statement::Assignment { target, .. } => {
                if let Expression::Identifier { name } = target {
                    return Some(name.clone());
                }
            }
            Statement::ExpressionStatement { expression, .. } => {
                if let Expression::Identifier { name } = expression {
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
        Expression::CallExpr { callee, args } => {
            for arg in args.iter_mut() {
                rewrite_expr(arg, method_names);
            }
            if let Expression::Identifier { name } = callee.as_ref() {
                if method_names.contains(name) {
                    *callee = Box::new(Expression::PropertyAccess {
                        property: name.clone(),
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
            if let Expression::PropertyAccess { property } = target {
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
        Expression::CallExpr { callee, args } => {
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
            if let Expression::PropertyAccess { property } = operand.as_ref() {
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
        // count is mutated in increment/decrement -> not readonly even after
        // the initializer is stripped below.
        assert!(!contract.properties[0].readonly);
        // `count: i64 = 0` collides with `pub fn init(count: i64)`: the ctor
        // param always overrides the default so the parser strips the
        // initializer to match the Zig compiler reference IR.
        assert!(contract.properties[0].initializer.is_none());
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
                    matches!(callee.as_ref(), Expression::PropertyAccess { property } if property == "computeThreshold"),
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
