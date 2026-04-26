//! Move-style parser for Rúnar contracts.
//!
//! Parses a Move-inspired syntax into the same AST as the TypeScript parser.
//! Hand-written tokenizer + recursive descent parser.
//!
//! ## Expected format
//!
//! ```move
//! module p2pkh {
//!     struct P2PKH has SmartContract {
//!         pub_key_hash: Addr,  // readonly by default in SmartContract
//!     }
//!
//!     public fun unlock(self: &P2PKH, sig: Sig, pub_key: PubKey) {
//!         assert!(hash160(pub_key) == self.pub_key_hash);
//!         assert!(check_sig(sig, pub_key));
//!     }
//! }
//! ```
//!
//! Key mappings:
//! - `module` wraps the contract
//! - `struct Name has SmartContract/StatefulSmartContract` defines the contract
//! - `public fun` / `fun` for method visibility
//! - `assert!(x)` -> assert(x)
//! - `assert_eq!(a, b)` -> assert(a === b)
//! - snake_case identifiers -> camelCase in AST
//! - Move builtins mapped: `check_sig` -> `checkSig`, `hash160` -> `hash160`, etc.

use super::ast::{
    BinaryOp, ContractNode, Expression, MethodNode, ParamNode, PrimitiveTypeName, PropertyNode,
    SourceLocation, Statement, TypeNode, UnaryOp, Visibility,
};
use super::diagnostic::Diagnostic;
use super::parser::ParseResult;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a Move-format Rúnar contract source.
pub fn parse_move(source: &str, file_name: Option<&str>) -> ParseResult {
    let file = file_name.unwrap_or("contract.runar.move");
    let mut errors: Vec<Diagnostic> = Vec::new();

    let tokens = tokenize(source);
    let mut parser = MoveParser::new(tokens, file, &mut errors);

    let contract = parser.parse_module();

    ParseResult {
        contract,
        errors,
    }
}

// ---------------------------------------------------------------------------
// Name conversion helpers
// ---------------------------------------------------------------------------

/// Convert snake_case to camelCase.
fn snake_to_camel(s: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = false;

    for ch in s.chars() {
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

/// Map Move builtin names to Rúnar builtin names.
fn map_builtin_name(name: &str) -> String {
    match name {
        "check_sig" => "checkSig".to_string(),
        "check_multi_sig" => "checkMultiSig".to_string(),
        "check_preimage" => "checkPreimage".to_string(),
        "extract_locktime" => "extractLocktime".to_string(),
        "hash160" => "hash160".to_string(),
        "hash256" => "hash256".to_string(),
        "sha256" => "sha256".to_string(),
        "ripemd160" => "ripemd160".to_string(),
        "num2bin" => "num2bin".to_string(),
        "bin2num" => "bin2num".to_string(),
        "add_output" => "addOutput".to_string(),
        "add_raw_output" => "addRawOutput".to_string(),
        "add_data_output" => "addDataOutput".to_string(),
        "tx_preimage" => "txPreimage".to_string(),
        "bool_cast" => "bool".to_string(),
        "verify_wots" => "verifyWOTS".to_string(),
        "verify_slh_dsa_sha2_128s" | "verifySlhdsaSha2128s" | "verifySlhDsaSha2128s" => "verifySLHDSA_SHA2_128s".to_string(),
        "verify_slh_dsa_sha2_128f" | "verifySlhdsaSha2128f" | "verifySlhDsaSha2128f" => "verifySLHDSA_SHA2_128f".to_string(),
        "verify_slh_dsa_sha2_192s" | "verifySlhdsaSha2192s" | "verifySlhDsaSha2192s" => "verifySLHDSA_SHA2_192s".to_string(),
        "verify_slh_dsa_sha2_192f" | "verifySlhdsaSha2192f" | "verifySlhDsaSha2192f" => "verifySLHDSA_SHA2_192f".to_string(),
        "verify_slh_dsa_sha2_256s" | "verifySlhdsaSha2256s" | "verifySlhDsaSha2256s" => "verifySLHDSA_SHA2_256s".to_string(),
        "verify_slh_dsa_sha2_256f" | "verifySlhdsaSha2256f" | "verifySlhDsaSha2256f" => "verifySLHDSA_SHA2_256f".to_string(),
        "sha256_compress" => "sha256Compress".to_string(),
        "sha256_finalize" => "sha256Finalize".to_string(),
        "to_byte_string" => "toByteString".to_string(),
        "int_2_str" | "int2str" => "int2str".to_string(),
        "reverse_bytes" => "reverseBytes".to_string(),
        "p256_add" => "p256Add".to_string(),
        "p256_mul" => "p256Mul".to_string(),
        "p256_mul_gen" => "p256MulGen".to_string(),
        "p256_negate" => "p256Negate".to_string(),
        "p256_on_curve" => "p256OnCurve".to_string(),
        "p256_encode_compressed" => "p256EncodeCompressed".to_string(),
        "verify_ecdsa_p256" => "verifyECDSA_P256".to_string(),
        "p384_add" => "p384Add".to_string(),
        "p384_mul" => "p384Mul".to_string(),
        "p384_mul_gen" => "p384MulGen".to_string(),
        "p384_negate" => "p384Negate".to_string(),
        "p384_on_curve" => "p384OnCurve".to_string(),
        "p384_encode_compressed" => "p384EncodeCompressed".to_string(),
        "verify_ecdsa_p384" => "verifyECDSA_P384".to_string(),
        // Pre-camelCased forms also accepted (matches the canonical TS Move
        // parser, whose regex preserves the literal `_P` boundary).
        "verifyECDSA_P256" => "verifyECDSA_P256".to_string(),
        "verifyECDSA_P384" => "verifyECDSA_P384".to_string(),
        _ => snake_to_camel(name),
    }
}

/// Map Move type names to Rúnar type names.
fn map_type_name(name: &str) -> &str {
    match name {
        "Int" | "u64" | "u128" | "u256" => "bigint",
        "Bool" | "bool" => "boolean",
        "vector<u8>" | "Bytes" => "ByteString",
        "address" => "Addr",
        _ => name,
    }
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    // Keywords
    Module,
    Use,
    Resource,
    Struct,
    Has,
    Public,
    Fun,
    Let,
    Mut,
    If,
    Else,
    While,
    Loop,
    Return,
    True,
    False,
    Assert,     // assert!
    AssertEq,   // assert_eq!

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
    EqEq,       // ==
    NotEq,      // !=
    Lt,
    Le,
    Gt,
    Ge,
    Shl,        // <<
    Shr,        // >>
    And,        // &&
    Or,         // ||
    Amp,        // &
    Pipe,       // |
    Caret,      // ^
    Bang,       // !
    Tilde,      // ~
    Eq,         // =
    PlusEq,
    MinusEq,
    StarEq,
    SlashEq,
    PercentEq,
    PlusPlus,
    MinusMinus,

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
    ColonColon, // ::
    Question,

    // Special
    Eof,
}

fn tokenize(source: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = source.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let ch = chars[i];

        if ch.is_whitespace() {
            i += 1;
            continue;
        }

        // Line comments
        if ch == '/' && i + 1 < len && chars[i + 1] == '/' {
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }

        // Block comments
        if ch == '/' && i + 1 < len && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < len && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            if i + 1 < len {
                i += 2;
            }
            continue;
        }

        // Multi-char operators
        if ch == '=' && i + 1 < len && chars[i + 1] == '=' {
            tokens.push(Token::EqEq);
            i += 2;
            continue;
        }
        if ch == '!' && i + 1 < len && chars[i + 1] == '=' {
            tokens.push(Token::NotEq);
            i += 2;
            continue;
        }
        if ch == '<' && i + 1 < len && chars[i + 1] == '=' {
            tokens.push(Token::Le);
            i += 2;
            continue;
        }
        if ch == '>' && i + 1 < len && chars[i + 1] == '=' {
            tokens.push(Token::Ge);
            i += 2;
            continue;
        }
        if ch == '<' && i + 1 < len && chars[i + 1] == '<' {
            tokens.push(Token::Shl);
            i += 2;
            continue;
        }
        if ch == '>' && i + 1 < len && chars[i + 1] == '>' {
            tokens.push(Token::Shr);
            i += 2;
            continue;
        }
        if ch == '&' && i + 1 < len && chars[i + 1] == '&' {
            tokens.push(Token::And);
            i += 2;
            continue;
        }
        if ch == '|' && i + 1 < len && chars[i + 1] == '|' {
            tokens.push(Token::Or);
            i += 2;
            continue;
        }
        if ch == '+' && i + 1 < len && chars[i + 1] == '+' {
            tokens.push(Token::PlusPlus);
            i += 2;
            continue;
        }
        if ch == '-' && i + 1 < len && chars[i + 1] == '-' {
            tokens.push(Token::MinusMinus);
            i += 2;
            continue;
        }
        if ch == '+' && i + 1 < len && chars[i + 1] == '=' {
            tokens.push(Token::PlusEq);
            i += 2;
            continue;
        }
        if ch == '-' && i + 1 < len && chars[i + 1] == '=' {
            tokens.push(Token::MinusEq);
            i += 2;
            continue;
        }
        if ch == '*' && i + 1 < len && chars[i + 1] == '=' {
            tokens.push(Token::StarEq);
            i += 2;
            continue;
        }
        if ch == '/' && i + 1 < len && chars[i + 1] == '=' {
            tokens.push(Token::SlashEq);
            i += 2;
            continue;
        }
        if ch == '%' && i + 1 < len && chars[i + 1] == '=' {
            tokens.push(Token::PercentEq);
            i += 2;
            continue;
        }
        if ch == ':' && i + 1 < len && chars[i + 1] == ':' {
            tokens.push(Token::ColonColon);
            i += 2;
            continue;
        }

        // Single-char tokens
        match ch {
            '+' => { tokens.push(Token::Plus); i += 1; continue; }
            '-' => { tokens.push(Token::Minus); i += 1; continue; }
            '*' => { tokens.push(Token::Star); i += 1; continue; }
            '/' => { tokens.push(Token::Slash); i += 1; continue; }
            '%' => { tokens.push(Token::Percent); i += 1; continue; }
            '<' => { tokens.push(Token::Lt); i += 1; continue; }
            '>' => { tokens.push(Token::Gt); i += 1; continue; }
            '!' => { tokens.push(Token::Bang); i += 1; continue; }
            '~' => { tokens.push(Token::Tilde); i += 1; continue; }
            '&' => { tokens.push(Token::Amp); i += 1; continue; }
            '|' => { tokens.push(Token::Pipe); i += 1; continue; }
            '^' => { tokens.push(Token::Caret); i += 1; continue; }
            '=' => { tokens.push(Token::Eq); i += 1; continue; }
            '(' => { tokens.push(Token::LParen); i += 1; continue; }
            ')' => { tokens.push(Token::RParen); i += 1; continue; }
            '{' => { tokens.push(Token::LBrace); i += 1; continue; }
            '}' => { tokens.push(Token::RBrace); i += 1; continue; }
            '[' => { tokens.push(Token::LBracket); i += 1; continue; }
            ']' => { tokens.push(Token::RBracket); i += 1; continue; }
            ';' => { tokens.push(Token::Semicolon); i += 1; continue; }
            ',' => { tokens.push(Token::Comma); i += 1; continue; }
            '.' => { tokens.push(Token::Dot); i += 1; continue; }
            ':' => { tokens.push(Token::Colon); i += 1; continue; }
            '?' => { tokens.push(Token::Question); i += 1; continue; }
            _ => {}
        }

        // String literals
        if ch == '\'' || ch == '"' || ch == 'b' && i + 1 < len && (chars[i + 1] == '\'' || chars[i + 1] == '"') {
            // Skip optional 'b' prefix for byte strings
            if ch == 'b' {
                i += 1;
            }
            let quote = chars[i];
            i += 1;
            let start = i;
            while i < len && chars[i] != quote {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            let val: String = chars[start..i].iter().collect();
            tokens.push(Token::StringLit(val));
            if i < len {
                i += 1;
            }
            continue;
        }

        // Hex literals: 0x...
        if ch == '0' && i + 1 < len && chars[i + 1] == 'x' {
            i += 2; // skip '0x'
            let start = i;
            while i < len && chars[i].is_ascii_hexdigit() {
                i += 1;
            }
            let hex_val: String = chars[start..i].iter().collect();
            tokens.push(Token::StringLit(hex_val));
            continue;
        }

        // Numbers
        if ch.is_ascii_digit() {
            let start = i;
            while i < len && (chars[i].is_ascii_digit() || chars[i] == '_' || chars[i] == 'n') {
                i += 1;
            }
            let num_str: String = chars[start..i]
                .iter()
                .filter(|c| **c != '_' && **c != 'n')
                .collect();
            let val = num_str.parse::<i128>().unwrap_or(0);
            tokens.push(Token::NumberLit(val));
            continue;
        }

        // Identifiers and keywords
        if ch.is_ascii_alphabetic() || ch == '_' {
            let start = i;
            while i < len && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();

            // Check for assert! and assert_eq! (macros)
            if (word == "assert" || word == "assert_eq") && i < len && chars[i] == '!' {
                i += 1; // consume '!'
                if word == "assert" {
                    tokens.push(Token::Assert);
                } else {
                    tokens.push(Token::AssertEq);
                }
                continue;
            }

            let tok = match word.as_str() {
                "module" => Token::Module,
                "use" => Token::Use,
                "resource" => Token::Resource,
                "struct" => Token::Struct,
                "has" => Token::Has,
                "public" => Token::Public,
                "fun" => Token::Fun,
                "let" => Token::Let,
                "mut" => Token::Mut,
                "if" => Token::If,
                "else" => Token::Else,
                "while" => Token::While,
                "loop" => Token::Loop,
                "return" => Token::Return,
                "true" => Token::True,
                "false" => Token::False,
                _ => Token::Ident(word),
            };
            tokens.push(tok);
            continue;
        }

        // Skip unrecognized
        i += 1;
    }

    tokens.push(Token::Eof);
    tokens
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct MoveParser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    file: &'a str,
    errors: &'a mut Vec<Diagnostic>,
    struct_name: String,
}

impl<'a> MoveParser<'a> {
    fn new(tokens: Vec<Token>, file: &'a str, errors: &'a mut Vec<Diagnostic>) -> Self {
        Self {
            tokens,
            pos: 0,
            file,
            errors,
            struct_name: String::new(),
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
        if self.peek() == expected {
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

    // -----------------------------------------------------------------------
    // Module (top level)
    // -----------------------------------------------------------------------

    fn parse_module(&mut self) -> Option<ContractNode> {
        // Skip until 'module'
        while *self.peek() != Token::Module && *self.peek() != Token::Eof {
            // Also allow struct at top level without module wrapper
            if *self.peek() == Token::Struct || *self.peek() == Token::Resource || *self.peek() == Token::Public {
                return self.parse_top_level_without_module();
            }
            self.advance();
        }

        if *self.peek() == Token::Eof {
            self.errors.push(Diagnostic::error("No 'module' declaration found", None));
            return None;
        }

        self.advance(); // consume 'module'
        let _module_name = self.expect_ident();

        // Optional :: address
        if *self.peek() == Token::ColonColon {
            self.advance();
            self.expect_ident();
        }

        self.expect(&Token::LBrace);

        let result = self.parse_module_body();

        self.expect(&Token::RBrace);

        result
    }

    fn parse_top_level_without_module(&mut self) -> Option<ContractNode> {
        self.parse_module_body()
    }

    fn parse_module_body(&mut self) -> Option<ContractNode> {
        let mut contract_name: Option<String> = None;
        let mut parent_class = "SmartContract".to_string();
        let mut properties: Vec<PropertyNode> = Vec::new();
        let mut methods: Vec<MethodNode> = Vec::new();
        let mut is_resource = false;

        // Skip use declarations first
        while *self.peek() == Token::Use {
            while *self.peek() != Token::Semicolon && *self.peek() != Token::Eof {
                self.advance();
            }
            if *self.peek() == Token::Semicolon {
                self.advance();
            }
        }

        while *self.peek() != Token::RBrace && *self.peek() != Token::Eof {
            match self.peek().clone() {
                Token::Use => {
                    // Skip use declarations that appear after other items
                    while *self.peek() != Token::Semicolon && *self.peek() != Token::Eof {
                        self.advance();
                    }
                    if *self.peek() == Token::Semicolon {
                        self.advance();
                    }
                }
                Token::Resource => {
                    // "resource struct Name { ... }"
                    is_resource = true;
                    self.advance(); // consume 'resource'
                    if *self.peek() == Token::Struct {
                        let (name, pc, props) = self.parse_struct();
                        contract_name = Some(name.clone());
                        self.struct_name = name;
                        parent_class = pc;
                        properties = props;
                    } else {
                        self.errors.push(Diagnostic::error(format!(
                            "Expected 'struct' after 'resource', got {:?}",
                            self.peek()
                        ), None));
                    }
                }
                Token::Struct => {
                    let (name, pc, props) = self.parse_struct();
                    contract_name = Some(name.clone());
                    self.struct_name = name;
                    parent_class = pc;
                    properties = props;
                }
                Token::Public => {
                    // public fun name(...)
                    self.advance(); // consume 'public'
                    if *self.peek() == Token::Fun {
                        methods.push(self.parse_fun(Visibility::Public));
                    } else {
                        self.errors.push(Diagnostic::error(format!(
                            "Expected 'fun' after 'public', got {:?}",
                            self.peek()
                        ), None));
                        self.advance();
                    }
                }
                Token::Fun => {
                    methods.push(self.parse_fun(Visibility::Private));
                }
                _ => {
                    self.advance();
                }
            }
        }

        let contract_name = match contract_name {
            Some(n) => n,
            None => {
                self.errors
                    .push(Diagnostic::error("No 'struct' declaration found in module", None));
                return None;
            }
        };

        // If struct was marked as "resource" or has mutable fields, it's stateful
        if is_resource {
            parent_class = "StatefulSmartContract".to_string();
        } else {
            let has_mutable = properties.iter().any(|p| !p.readonly);
            if has_mutable {
                parent_class = "StatefulSmartContract".to_string();
            }
        }

        // Determine readonly based on parent class
        let is_stateless = parent_class == "SmartContract";
        if is_stateless {
            for prop in &mut properties {
                prop.readonly = true;
            }
        }

        // Build constructor from properties
        let constructor = build_constructor(&properties, self.file);

        Some(ContractNode {
            name: contract_name,
            parent_class,
            properties,
            constructor,
            methods,
            source_file: self.file.to_string(),
        })
    }

    // -----------------------------------------------------------------------
    // Struct
    // -----------------------------------------------------------------------

    fn parse_struct(&mut self) -> (String, String, Vec<PropertyNode>) {
        self.advance(); // consume 'struct'
        let name = self.expect_ident();

        // 'has' BaseClass
        let parent_class = if *self.peek() == Token::Has {
            self.advance();
            self.expect_ident()
        } else {
            "SmartContract".to_string()
        };

        self.expect(&Token::LBrace);

        let mut properties = Vec::new();
        while *self.peek() != Token::RBrace && *self.peek() != Token::Eof {
            let prop = self.parse_struct_field();
            properties.push(prop);
            // Optional comma between fields
            if *self.peek() == Token::Comma {
                self.advance();
            }
        }
        self.expect(&Token::RBrace);

        (name, parent_class, properties)
    }

    fn parse_struct_field(&mut self) -> PropertyNode {
        let field_name = self.expect_ident();
        self.expect(&Token::Colon);

        // Check for &mut (mutable reference) before parsing type
        // Default: readonly = true (matching TS parser behavior)
        // Only &mut explicitly makes a property mutable
        let mut readonly = true;
        if *self.peek() == Token::Amp {
            self.advance(); // consume '&'
            if *self.peek() == Token::Mut {
                self.advance(); // consume 'mut'
                readonly = false;
            }
        }

        let type_node = self.parse_type();

        // Parse optional initializer: = value
        let initializer = if *self.peek() == Token::Eq {
            self.advance(); // consume '='
            Some(self.parse_expression())
        } else {
            None
        };

        PropertyNode {
            name: map_builtin_name(&field_name),
            prop_type: type_node,
            readonly,
            initializer,
            source_location: self.loc(),
            synthetic_array_chain: None,
        }
    }

    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    fn parse_type(&mut self) -> TypeNode {
        // Handle &/&mut reference prefix (Move style) - just skip it
        if *self.peek() == Token::Amp {
            self.advance();
            if *self.peek() == Token::Mut {
                self.advance();
            }
        }

        let name = self.expect_ident();
        let mapped = map_type_name(&name);

        // Check for FixedArray<T, N>
        if mapped == "FixedArray" || name == "FixedArray" {
            if *self.peek() == Token::Lt {
                self.advance();
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
                self.expect(&Token::Gt);
                return TypeNode::FixedArray {
                    element: Box::new(element),
                    length,
                };
            }
        }

        if let Some(prim) = PrimitiveTypeName::from_str(mapped) {
            TypeNode::Primitive(prim)
        } else {
            TypeNode::Custom(mapped.to_string())
        }
    }

    // -----------------------------------------------------------------------
    // Functions
    // -----------------------------------------------------------------------

    fn parse_fun(&mut self, visibility: Visibility) -> MethodNode {
        self.advance(); // consume 'fun'
        let raw_name = self.expect_ident();
        let name = map_builtin_name(&raw_name);

        self.expect(&Token::LParen);
        let params = self.parse_param_list();
        self.expect(&Token::RParen);

        // Optional return type
        let mut has_return_type = false;
        if *self.peek() == Token::Colon {
            self.advance();
            let _ret_type = self.parse_type();
            has_return_type = true;
        }

        let mut body = self.parse_block();

        // Move allows an implicit return of the final expression when the
        // function declares a return type. Convert the trailing expression
        // statement into an explicit return statement so the type checker
        // can infer the method's return type.
        if has_return_type {
            if let Some(last) = body.pop() {
                match last {
                    Statement::ExpressionStatement { expression, source_location } => {
                        body.push(Statement::ReturnStatement {
                            value: Some(expression),
                            source_location,
                        });
                    }
                    other => body.push(other),
                }
            }
        }

        MethodNode {
            name,
            params,
            body,
            visibility,
            source_location: self.loc(),
        }
    }

    fn parse_param_list(&mut self) -> Vec<ParamNode> {
        let mut params = Vec::new();
        if *self.peek() == Token::RParen {
            return params;
        }

        // First param might be `self: &StructName` or `contract: &mut StructName` -- skip it
        let first = self.parse_one_param();
        if first.name == "self" || first.name == "contract" {
            // Skip self/contract param -- it's implicit in Rúnar
        } else {
            params.push(first);
        }

        while *self.peek() == Token::Comma {
            self.advance();
            if *self.peek() == Token::RParen {
                break;
            }
            params.push(self.parse_one_param());
        }
        params
    }

    fn parse_one_param(&mut self) -> ParamNode {
        // Move style: name: Type
        let raw_name = self.expect_ident();
        self.expect(&Token::Colon);
        let param_type = self.parse_type();
        let name = map_builtin_name(&raw_name);
        ParamNode { name, param_type }
    }

    // -----------------------------------------------------------------------
    // Blocks and statements
    // -----------------------------------------------------------------------

    fn parse_block(&mut self) -> Vec<Statement> {
        self.expect(&Token::LBrace);
        let mut stmts = Vec::new();
        while *self.peek() != Token::RBrace && *self.peek() != Token::Eof {
            if let Some(stmt) = self.parse_statement() {
                stmts.push(stmt);
            }
        }
        self.expect(&Token::RBrace);
        fold_move_while_as_for(stmts)
    }

    fn parse_statement(&mut self) -> Option<Statement> {
        match self.peek().clone() {
            Token::Let => Some(self.parse_let()),
            Token::If => {
                let stmt = self.parse_if();
                // Optional trailing semicolon after if/else block
                if *self.peek() == Token::Semicolon {
                    self.advance();
                }
                Some(stmt)
            }
            Token::Return => Some(self.parse_return()),
            Token::Assert => Some(self.parse_assert()),
            Token::AssertEq => Some(self.parse_assert_eq()),
            Token::While => {
                let stmt = self.parse_while_as_for();
                // Optional trailing semicolon after while block
                if *self.peek() == Token::Semicolon {
                    self.advance();
                }
                Some(stmt)
            }
            _ => {
                // Expression statement or assignment
                let expr = self.parse_expression();

                match self.peek() {
                    Token::Eq => {
                        self.advance();
                        let value = self.parse_expression();
                        self.expect(&Token::Semicolon);
                        Some(Statement::Assignment {
                            target: self.convert_self_to_this(expr),
                            value: self.convert_self_to_this(value),
                            source_location: self.loc(),
                        })
                    }
                    Token::PlusEq => {
                        self.advance();
                        let rhs = self.parse_expression();
                        let target = self.convert_self_to_this(expr);
                        let value = Expression::BinaryExpr {
                            op: BinaryOp::Add,
                            left: Box::new(target.clone()),
                            right: Box::new(self.convert_self_to_this(rhs)),
                        };
                        self.expect(&Token::Semicolon);
                        Some(Statement::Assignment {
                            target,
                            value,
                            source_location: self.loc(),
                        })
                    }
                    Token::MinusEq => {
                        self.advance();
                        let rhs = self.parse_expression();
                        let target = self.convert_self_to_this(expr);
                        let value = Expression::BinaryExpr {
                            op: BinaryOp::Sub,
                            left: Box::new(target.clone()),
                            right: Box::new(self.convert_self_to_this(rhs)),
                        };
                        self.expect(&Token::Semicolon);
                        Some(Statement::Assignment {
                            target,
                            value,
                            source_location: self.loc(),
                        })
                    }
                    Token::StarEq => {
                        self.advance();
                        let rhs = self.parse_expression();
                        let target = self.convert_self_to_this(expr);
                        let value = Expression::BinaryExpr {
                            op: BinaryOp::Mul,
                            left: Box::new(target.clone()),
                            right: Box::new(self.convert_self_to_this(rhs)),
                        };
                        self.expect(&Token::Semicolon);
                        Some(Statement::Assignment {
                            target,
                            value,
                            source_location: self.loc(),
                        })
                    }
                    _ => {
                        let had_semi = *self.peek() == Token::Semicolon;
                        if had_semi {
                            self.advance(); // consume optional semicolon
                        }
                        let expr = self.convert_self_to_this(expr);
                        // If no semicolon and next token is `}`, treat as implicit return
                        if !had_semi && *self.peek() == Token::RBrace {
                            Some(Statement::ReturnStatement {
                                value: Some(expr),
                                source_location: self.loc(),
                            })
                        } else {
                            Some(Statement::ExpressionStatement {
                                expression: expr,
                                source_location: self.loc(),
                            })
                        }
                    }
                }
            }
        }
    }

    /// Recursively convert `self.x` to `this.x` (PropertyAccess) in expressions.
    fn convert_self_to_this(&self, expr: Expression) -> Expression {
        match expr {
            Expression::MemberExpr { object, property } => {
                if matches!(object.as_ref(), Expression::Identifier { name } if name == "self" || name == "contract") {
                    // self.x or contract.x -> PropertyAccess { property: camelCase(x) }
                    Expression::PropertyAccess {
                        property: map_builtin_name(&property),
                    }
                } else {
                    Expression::MemberExpr {
                        object: Box::new(self.convert_self_to_this(*object)),
                        property,
                    }
                }
            }
            Expression::BinaryExpr { op, left, right } => Expression::BinaryExpr {
                op,
                left: Box::new(self.convert_self_to_this(*left)),
                right: Box::new(self.convert_self_to_this(*right)),
            },
            Expression::UnaryExpr { op, operand } => Expression::UnaryExpr {
                op,
                operand: Box::new(self.convert_self_to_this(*operand)),
            },
            Expression::CallExpr { callee, args } => {
                let new_callee = self.convert_self_to_this(*callee);
                let new_args: Vec<Expression> =
                    args.into_iter().map(|a| self.convert_self_to_this(a)).collect();
                Expression::CallExpr {
                    callee: Box::new(new_callee),
                    args: new_args,
                }
            }
            Expression::TernaryExpr {
                condition,
                consequent,
                alternate,
            } => Expression::TernaryExpr {
                condition: Box::new(self.convert_self_to_this(*condition)),
                consequent: Box::new(self.convert_self_to_this(*consequent)),
                alternate: Box::new(self.convert_self_to_this(*alternate)),
            },
            Expression::IndexAccess { object, index } => Expression::IndexAccess {
                object: Box::new(self.convert_self_to_this(*object)),
                index: Box::new(self.convert_self_to_this(*index)),
            },
            Expression::IncrementExpr { operand, prefix } => Expression::IncrementExpr {
                operand: Box::new(self.convert_self_to_this(*operand)),
                prefix,
            },
            Expression::DecrementExpr { operand, prefix } => Expression::DecrementExpr {
                operand: Box::new(self.convert_self_to_this(*operand)),
                prefix,
            },
            // Rename `self` identifier to `this`
            Expression::Identifier { ref name } if name == "self" => Expression::Identifier {
                name: "this".to_string(),
            },
            other => other,
        }
    }

    fn parse_let(&mut self) -> Statement {
        self.advance(); // consume 'let'
        let mutable = if *self.peek() == Token::Mut {
            self.advance();
            true
        } else {
            false
        };

        let raw_name = self.expect_ident();
        let name = map_builtin_name(&raw_name);

        // Optional type annotation: ": Type"
        let var_type = if *self.peek() == Token::Colon {
            self.advance();
            Some(self.parse_type())
        } else {
            None
        };

        self.expect(&Token::Eq);
        let init = self.parse_expression();
        let init = self.convert_self_to_this(init);
        self.expect(&Token::Semicolon);

        Statement::VariableDecl {
            name,
            var_type,
            mutable,
            init,
            source_location: self.loc(),
        }
    }

    fn parse_assert(&mut self) -> Statement {
        self.advance(); // consume Assert token (assert!)
        self.expect(&Token::LParen);
        let expr = self.parse_expression();
        let expr = self.convert_self_to_this(expr);
        // Skip optional error code: assert!(expr, error_code)
        if *self.peek() == Token::Comma {
            self.advance();
            let _error_code = self.parse_expression();
        }
        self.expect(&Token::RParen);
        self.expect(&Token::Semicolon);

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

    fn parse_assert_eq(&mut self) -> Statement {
        self.advance(); // consume AssertEq token (assert_eq!)
        self.expect(&Token::LParen);
        let left = self.parse_expression();
        let left = self.convert_self_to_this(left);
        self.expect(&Token::Comma);
        let right = self.parse_expression();
        let right = self.convert_self_to_this(right);
        self.expect(&Token::RParen);
        self.expect(&Token::Semicolon);

        // assert_eq!(a, b) -> assert(a === b)
        Statement::ExpressionStatement {
            expression: Expression::CallExpr {
                callee: Box::new(Expression::Identifier {
                    name: "assert".to_string(),
                }),
                args: vec![Expression::BinaryExpr {
                    op: BinaryOp::StrictEq,
                    left: Box::new(left),
                    right: Box::new(right),
                }],
            },
            source_location: self.loc(),
        }
    }

    fn parse_if(&mut self) -> Statement {
        self.advance(); // consume 'if'

        // Move uses `if (cond) { ... }` or `if cond { ... }`
        let has_parens = *self.peek() == Token::LParen;
        if has_parens {
            self.advance();
        }
        let condition = self.parse_expression();
        let condition = self.convert_self_to_this(condition);
        if has_parens {
            self.expect(&Token::RParen);
        }

        let then_branch = self.parse_block_converting_self();

        let else_branch = if *self.peek() == Token::Else {
            self.advance();
            if *self.peek() == Token::If {
                let nested = self.parse_if();
                Some(vec![nested])
            } else {
                Some(self.parse_block_converting_self())
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

    fn parse_block_converting_self(&mut self) -> Vec<Statement> {
        self.parse_block()
    }

    /// Parse `while` loop as a for loop (for compatibility with Rúnar AST which only has ForStatement).
    fn parse_while_as_for(&mut self) -> Statement {
        self.advance(); // consume 'while'

        let has_parens = *self.peek() == Token::LParen;
        if has_parens {
            self.advance();
        }
        let condition = self.parse_expression();
        let condition = self.convert_self_to_this(condition);
        if has_parens {
            self.expect(&Token::RParen);
        }

        let body = self.parse_block_converting_self();

        // Represent while as: for (let _w = 0; condition; _w = 0)
        Statement::ForStatement {
            init: Box::new(Statement::VariableDecl {
                name: "_w".to_string(),
                var_type: None,
                mutable: true,
                init: Expression::BigIntLiteral { value: 0 },
                source_location: self.loc(),
            }),
            condition,
            update: Box::new(Statement::ExpressionStatement {
                expression: Expression::BigIntLiteral { value: 0 },
                source_location: self.loc(),
            }),
            body,
            source_location: self.loc(),
        }
    }

    fn parse_return(&mut self) -> Statement {
        self.advance(); // consume 'return'
        if *self.peek() == Token::Semicolon {
            self.advance();
            return Statement::ReturnStatement {
                value: None,
                source_location: self.loc(),
            };
        }
        let value = self.parse_expression();
        let value = self.convert_self_to_this(value);
        self.expect(&Token::Semicolon);
        Statement::ReturnStatement {
            value: Some(value),
            source_location: self.loc(),
        }
    }

    // -----------------------------------------------------------------------
    // Expressions (precedence climbing)
    // -----------------------------------------------------------------------

    fn parse_expression(&mut self) -> Expression {
        self.parse_ternary()
    }

    fn parse_ternary(&mut self) -> Expression {
        let cond = self.parse_or();
        if *self.peek() == Token::Question {
            self.advance();
            let cons = self.parse_ternary();
            self.expect(&Token::Colon);
            let alt = self.parse_ternary();
            Expression::TernaryExpr {
                condition: Box::new(cond),
                consequent: Box::new(cons),
                alternate: Box::new(alt),
            }
        } else {
            cond
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
        let mut left = self.parse_bit_or();
        while *self.peek() == Token::And {
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
        while *self.peek() == Token::Pipe {
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
        while *self.peek() == Token::Caret {
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
        while *self.peek() == Token::Amp {
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
                Token::Shl => {
                    self.advance();
                    let right = self.parse_additive();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Shl,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::Shr => {
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
            Token::PlusPlus => {
                self.advance();
                let operand = self.parse_postfix();
                Expression::IncrementExpr {
                    operand: Box::new(operand),
                    prefix: true,
                }
            }
            Token::MinusMinus => {
                self.advance();
                let operand = self.parse_postfix();
                Expression::DecrementExpr {
                    operand: Box::new(operand),
                    prefix: true,
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
                    self.advance();
                    let raw_prop = self.expect_ident();
                    let prop = map_builtin_name(&raw_prop);
                    // Note: self.x conversion happens in convert_self_to_this
                    expr = Expression::MemberExpr {
                        object: Box::new(expr),
                        property: prop,
                    };
                }
                Token::ColonColon => {
                    // Module::function -- treat as just the function name
                    self.advance();
                    let raw_name = self.expect_ident();
                    let name = map_builtin_name(&raw_name);
                    expr = Expression::Identifier { name };
                }
                Token::LParen => {
                    self.advance();
                    let mut args = Vec::new();
                    if *self.peek() != Token::RParen {
                        args.push(self.parse_expression());
                        while *self.peek() == Token::Comma {
                            self.advance();
                            args.push(self.parse_expression());
                        }
                    }
                    self.expect(&Token::RParen);

                    // Free helper functions in Move take `contract: &Self` as
                    // the first argument. The parser drops `contract` from
                    // parameter lists on the definition side, so strip a
                    // matching `contract`/`self` identifier as the first
                    // argument at call sites too.
                    if let Expression::Identifier { .. } = &expr {
                        if let Some(Expression::Identifier { name }) = args.first() {
                            if name == "contract" || name == "self" {
                                args.remove(0);
                            }
                        }
                    }

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
                Token::PlusPlus => {
                    self.advance();
                    expr = Expression::IncrementExpr {
                        operand: Box::new(expr),
                        prefix: false,
                    };
                }
                Token::MinusMinus => {
                    self.advance();
                    expr = Expression::DecrementExpr {
                        operand: Box::new(expr),
                        prefix: false,
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
            Token::True => Expression::BoolLiteral { value: true },
            Token::False => Expression::BoolLiteral { value: false },
            Token::StringLit(v) => Expression::ByteStringLiteral { value: v },
            Token::Ident(name) => Expression::Identifier { name: map_builtin_name(&name) },
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
// Pattern folding: `let i = K; while (i < N) { ...; i = i + S; }` → ForStatement
// ---------------------------------------------------------------------------

/// Fold the canonical Move bounded-loop pattern
/// ```ignore
/// let i: Int = K;
/// while (i < N) { ...; i = i + S; }
/// ```
/// into a single ForStatement whose init/condition/update match TypeScript's
/// native `for (let i = 0n; i < N; i++)`, so downstream ANF lowering produces
/// identical bounded-loop IR across all formats.
fn fold_move_while_as_for(stmts: Vec<Statement>) -> Vec<Statement> {
    let mut out: Vec<Statement> = Vec::with_capacity(stmts.len());
    let mut i = 0;
    while i < stmts.len() {
        if i + 1 < stmts.len() {
            if let (Statement::VariableDecl { name: decl_name, var_type, init: decl_init, source_location: decl_loc, .. },
                    Statement::ForStatement { init, condition, body, source_location: for_loc, .. }) =
                (&stmts[i], &stmts[i + 1])
            {
                // The while→for stub uses `_w` as init name.
                let is_while_stub = matches!(
                    init.as_ref(),
                    Statement::VariableDecl { name, .. } if name == "_w"
                );
                if is_while_stub {
                    let iter_name = decl_name.clone();
                    // Condition: iter_name <cmp> bound
                    if let Expression::BinaryExpr { left, .. } = condition {
                        if let Expression::Identifier { name: left_name } = left.as_ref() {
                            if left_name == &iter_name && !body.is_empty() {
                                // Last body stmt: iter_name = iter_name + K
                                if let Statement::Assignment { target, value, .. } = &body[body.len() - 1] {
                                    if let Expression::Identifier { name: tgt_name } = target {
                                        if let Expression::BinaryExpr { op: BinaryOp::Add, left: bl, .. } = value {
                                            if let Expression::Identifier { name: bl_name } = bl.as_ref() {
                                                if tgt_name == &iter_name && bl_name == &iter_name {
                                                    let trimmed: Vec<Statement> = body[..body.len() - 1].to_vec();
                                                    let new_for = Statement::ForStatement {
                                                        init: Box::new(Statement::VariableDecl {
                                                            name: iter_name.clone(),
                                                            var_type: var_type.clone(),
                                                            mutable: true,
                                                            init: decl_init.clone(),
                                                            source_location: decl_loc.clone(),
                                                        }),
                                                        condition: condition.clone(),
                                                        update: Box::new(Statement::ExpressionStatement {
                                                            expression: Expression::IncrementExpr {
                                                                operand: Box::new(Expression::Identifier {
                                                                    name: iter_name.clone(),
                                                                }),
                                                                prefix: false,
                                                            },
                                                            source_location: for_loc.clone(),
                                                        }),
                                                        body: trimmed,
                                                        source_location: for_loc.clone(),
                                                    };
                                                    out.push(new_for);
                                                    i += 2;
                                                    continue;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        out.push(stmts[i].clone());
        i += 1;
    }
    out
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
    }

    #[test]
    fn test_parse_simple_move_contract() {
        let source = r#"
module p2pkh {
    struct P2PKH has SmartContract {
        pub_key_hash: Addr,
    }

    public fun unlock(self: &P2PKH, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}
"#;

        let result = parse_move(source, Some("P2PKH.runar.move"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.name, "P2PKH");
        assert_eq!(contract.parent_class, "SmartContract");
        assert_eq!(contract.properties.len(), 1);
        assert_eq!(contract.properties[0].name, "pubKeyHash"); // snake_case -> camelCase
        assert!(contract.properties[0].readonly); // SmartContract -> all readonly
        assert_eq!(contract.methods.len(), 1);
        assert_eq!(contract.methods[0].name, "unlock");
        assert_eq!(contract.methods[0].visibility, Visibility::Public);
        // self param should be excluded
        assert_eq!(contract.methods[0].params.len(), 2);
        assert_eq!(contract.methods[0].params[0].name, "sig");
        assert_eq!(contract.methods[0].params[1].name, "pubKey"); // snake_case -> camelCase
    }

    #[test]
    fn test_parse_stateful_move_contract() {
        let source = r#"
module counter {
    struct Counter has StatefulSmartContract {
        count: &mut bigint,
    }

    public fun increment(self: &Counter) {
        self.count++;
    }

    public fun decrement(self: &Counter) {
        assert!(self.count > 0);
        self.count--;
    }
}
"#;

        let result = parse_move(source, Some("Counter.runar.move"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.name, "Counter");
        assert_eq!(contract.parent_class, "StatefulSmartContract");
        assert!(!contract.properties[0].readonly); // &mut marks property as mutable
        assert_eq!(contract.methods.len(), 2);
    }

    #[test]
    fn test_assert_eq_mapping() {
        let source = r#"
module test {
    struct Test has SmartContract {
        x: bigint,
    }

    public fun check(self: &Test, y: bigint) {
        assert_eq!(self.x, y);
    }
}
"#;

        let result = parse_move(source, Some("Test.runar.move"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;
        assert_eq!(body.len(), 1);

        // Should be assert(self.x === y)
        if let Statement::ExpressionStatement { expression, .. } = &body[0] {
            if let Expression::CallExpr { callee, args } = expression {
                if let Expression::Identifier { name } = callee.as_ref() {
                    assert_eq!(name, "assert");
                }
                if let Expression::BinaryExpr { op, .. } = &args[0] {
                    assert_eq!(*op, BinaryOp::StrictEq);
                } else {
                    panic!("Expected BinaryExpr, got {:?}", args[0]);
                }
            }
        }
    }

    #[test]
    fn test_self_to_this_conversion() {
        let source = r#"
module example {
    struct Example has StatefulSmartContract {
        value: bigint,
    }

    public fun set_value(self: &Example, new_value: bigint) {
        self.value = new_value;
    }
}
"#;

        let result = parse_move(source, Some("Example.runar.move"));
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
        // Param name should be camelCase
        assert_eq!(contract.methods[0].params[0].name, "newValue");
    }

    #[test]
    fn test_constructor_auto_generated() {
        let source = r#"
module test {
    struct Test has SmartContract {
        a: bigint,
        b: PubKey,
    }

    public fun check(self: &Test) {
        assert!(self.a > 0);
    }
}
"#;

        let result = parse_move(source, None);
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.constructor.params.len(), 2);
        // Constructor body: super(a, b) + this.a = a + this.b = b
        assert_eq!(contract.constructor.body.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Test: malformed Move produces an error
    // -----------------------------------------------------------------------

    #[test]
    fn test_invalid_syntax_error() {
        // Missing module name
        let source = r#"
module {
    // missing name
}
"#;

        let result = parse_move(source, Some("bad.runar.move"));
        // Should either produce errors or fail to produce a valid contract
        let is_bad = !result.errors.is_empty() || result.contract.is_none();
        assert!(
            is_bad,
            "expected errors or no contract for invalid Move syntax"
        );
    }

    // -----------------------------------------------------------------------
    // Test: contract with multiple public functions all parsed
    // -----------------------------------------------------------------------

    #[test]
    fn test_multiple_methods() {
        let source = r#"
module multi {
    struct Multi has SmartContract {
        x: bigint,
    }

    public fun method1(self: &Multi, a: bigint) {
        assert!(a == self.x);
    }

    public fun method2(self: &Multi, b: bigint) {
        assert!(b == self.x);
    }
}
"#;

        let result = parse_move(source, Some("Multi.runar.move"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(
            contract.methods.len(),
            2,
            "expected 2 methods, got {}",
            contract.methods.len()
        );
    }

    // -----------------------------------------------------------------------
    // Test: property types and method visibility are parsed correctly
    // -----------------------------------------------------------------------

    #[test]
    fn test_properties_and_methods() {
        let source = r#"
module adder {
    struct Adder has SmartContract {
        target: bigint,
    }

    public fun verify(self: &Adder, a: bigint, b: bigint) {
        assert!(a + b == self.target);
    }
}
"#;

        let result = parse_move(source, Some("Adder.runar.move"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();

        assert!(contract.properties.len() >= 1, "expected at least 1 property");
        assert_eq!(contract.properties[0].name, "target");

        assert_eq!(contract.methods.len(), 1, "expected 1 method");
        assert_eq!(contract.methods[0].name, "verify");
        assert_eq!(
            contract.methods[0].visibility,
            Visibility::Public,
            "expected method to be public"
        );
    }
}
