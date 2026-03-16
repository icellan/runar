//! Go contract parser for Rúnar contracts (.runar.go).
//!
//! Parses Go struct-based contract definitions using a hand-written tokenizer
//! and recursive descent parser. Produces the same AST as the TypeScript parser.
//!
//! ## Expected format
//!
//! ```go
//! package contract
//!
//! import runar "github.com/icellan/runar/packages/runar-go"
//!
//! type P2PKH struct {
//!     runar.SmartContract
//!     PubKeyHash runar.Addr `runar:"readonly"`
//! }
//!
//! func (c *P2PKH) Unlock(sig runar.Sig, pubKey runar.PubKey) {
//!     runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
//!     runar.Assert(runar.CheckSig(sig, pubKey))
//! }
//! ```
//!
//! Key mappings:
//! - `runar.SmartContract` embed -> parentClass = "SmartContract"
//! - `runar.StatefulSmartContract` embed -> parentClass = "StatefulSmartContract"
//! - `runar:"readonly"` struct tag -> readonly = true
//! - Exported methods (capital first letter) -> public
//! - Unexported methods -> private
//! - `runar.Assert(x)` -> assert(x)
//! - `==` -> StrictEq (===), `!=` -> StrictNe (!==)
//! - Go type names mapped: `runar.Bigint` -> bigint, `runar.PubKey` -> PubKey, etc.
//! - Exported Go identifiers lowercased (camelCase): `PubKeyHash` -> `pubKeyHash`
//! - `init()` method -> property initializers (extracted, not emitted as a method)
//! - `++` / `--` -> IncrementExpr / DecrementExpr
//! - `:=` -> VariableDecl (mutable)
//! - standalone functions (no receiver) -> private helper methods

use super::ast::{
    BinaryOp, ContractNode, Expression, MethodNode, ParamNode, PrimitiveTypeName, PropertyNode,
    SourceLocation, Statement, TypeNode, UnaryOp, Visibility,
};
use super::parser::ParseResult;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a Go-format Rúnar contract source.
pub fn parse_go_contract(source: &str, file_name: Option<&str>) -> ParseResult {
    let file = file_name.unwrap_or("contract.runar.go");
    let mut errors: Vec<String> = Vec::new();

    let tokens = tokenize(source);
    let mut parser = GoParser::new(tokens, file, &mut errors);

    let contract = parser.parse();

    ParseResult { contract, errors }
}

// ---------------------------------------------------------------------------
// Name conversion helpers
// ---------------------------------------------------------------------------

/// Convert a Go exported identifier to camelCase.
/// e.g., "PubKeyHash" -> "pubKeyHash", "Unlock" -> "unlock"
/// Lowercase identifiers pass through unchanged.
fn go_to_camel(name: &str) -> String {
    if name.is_empty() {
        return name.to_string();
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if first.is_uppercase() {
        let rest: String = chars.collect();
        format!("{}{}", first.to_lowercase(), rest)
    } else {
        name.to_string()
    }
}

/// Map Go/runar type names to Rúnar AST type nodes.
fn map_go_type(name: &str) -> TypeNode {
    match name {
        "Int" | "Bigint" | "int64" | "uint64" | "int" | "uint" => {
            TypeNode::Primitive(PrimitiveTypeName::Bigint)
        }
        "Bool" | "bool" => TypeNode::Primitive(PrimitiveTypeName::Boolean),
        "ByteString" | "[]byte" | "string" => TypeNode::Primitive(PrimitiveTypeName::ByteString),
        "PubKey" => TypeNode::Primitive(PrimitiveTypeName::PubKey),
        "Sig" => TypeNode::Primitive(PrimitiveTypeName::Sig),
        "Sha256" => TypeNode::Primitive(PrimitiveTypeName::Sha256),
        "Ripemd160" => TypeNode::Primitive(PrimitiveTypeName::Ripemd160),
        "Addr" => TypeNode::Primitive(PrimitiveTypeName::Addr),
        "SigHashPreimage" => TypeNode::Primitive(PrimitiveTypeName::SigHashPreimage),
        "RabinSig" => TypeNode::Primitive(PrimitiveTypeName::RabinSig),
        "RabinPubKey" => TypeNode::Primitive(PrimitiveTypeName::RabinPubKey),
        "Point" => TypeNode::Primitive(PrimitiveTypeName::Point),
        _ => TypeNode::Custom(name.to_string()),
    }
}

/// Map a runar.* builtin name (the part after "runar.") to the Rúnar AST callee name.
fn map_go_builtin(name: &str) -> String {
    match name {
        "Assert" => "assert".to_string(),
        "Hash160" => "hash160".to_string(),
        "Hash256" => "hash256".to_string(),
        "Sha256" => "sha256".to_string(),
        "Ripemd160" => "ripemd160".to_string(),
        "CheckSig" => "checkSig".to_string(),
        "CheckMultiSig" => "checkMultiSig".to_string(),
        "CheckPreimage" => "checkPreimage".to_string(),
        "VerifyRabinSig" => "verifyRabinSig".to_string(),
        "VerifyWOTS" => "verifyWOTS".to_string(),
        "VerifySLHDSA_SHA2_128s" => "verifySLHDSA_SHA2_128s".to_string(),
        "VerifySLHDSA_SHA2_128f" => "verifySLHDSA_SHA2_128f".to_string(),
        "VerifySLHDSA_SHA2_192s" => "verifySLHDSA_SHA2_192s".to_string(),
        "VerifySLHDSA_SHA2_192f" => "verifySLHDSA_SHA2_192f".to_string(),
        "VerifySLHDSA_SHA2_256s" => "verifySLHDSA_SHA2_256s".to_string(),
        "VerifySLHDSA_SHA2_256f" => "verifySLHDSA_SHA2_256f".to_string(),
        "Num2Bin" => "num2bin".to_string(),
        "Bin2Num" => "bin2num".to_string(),
        "Cat" => "cat".to_string(),
        "Substr" => "substr".to_string(),
        "Len" => "len".to_string(),
        "ReverseBytes" => "reverseBytes".to_string(),
        "ExtractLocktime" => "extractLocktime".to_string(),
        "ExtractOutputHash" => "extractOutputHash".to_string(),
        "AddOutput" => "addOutput".to_string(),
        "GetStateScript" => "getStateScript".to_string(),
        "Safediv" => "safediv".to_string(),
        "Safemod" => "safemod".to_string(),
        "Clamp" => "clamp".to_string(),
        "Sign" => "sign".to_string(),
        "Pow" => "pow".to_string(),
        "MulDiv" => "mulDiv".to_string(),
        "PercentOf" => "percentOf".to_string(),
        "Sqrt" => "sqrt".to_string(),
        "Gcd" => "gcd".to_string(),
        "Divmod" => "divmod".to_string(),
        "Log2" => "log2".to_string(),
        "ToBool" => "bool".to_string(),
        "Abs" => "abs".to_string(),
        "Min" => "min".to_string(),
        "Max" => "max".to_string(),
        "Within" => "within".to_string(),
        "EcAdd" => "ecAdd".to_string(),
        "EcMul" => "ecMul".to_string(),
        "EcMulGen" => "ecMulGen".to_string(),
        "EcNegate" => "ecNegate".to_string(),
        "EcOnCurve" => "ecOnCurve".to_string(),
        "EcModReduce" => "ecModReduce".to_string(),
        "EcEncodeCompressed" => "ecEncodeCompressed".to_string(),
        "EcMakePoint" => "ecMakePoint".to_string(),
        "EcPointX" => "ecPointX".to_string(),
        "EcPointY" => "ecPointY".to_string(),
        "Sha256Compress" => "sha256Compress".to_string(),
        "Sha256Finalize" => "sha256Finalize".to_string(),
        _ => go_to_camel(name),
    }
}

// ---------------------------------------------------------------------------
// Token types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum TokenType {
    // Keywords
    Package,
    Import,
    Type,
    Struct,
    Func,
    If,
    Else,
    For,
    Return,
    Var,
    Const,
    True,
    False,
    // Punctuation
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Semi,
    Comma,
    Dot,
    Colon,
    Star,
    // Operators
    Plus,
    Minus,
    Slash,
    Percent,
    EqEq,   // ==
    BangEq, // !=
    Lt,
    LtEq,
    Gt,
    GtEq,
    AmpAmp, // &&
    PipePipe, // ||
    Amp,
    Pipe,
    Caret,
    Tilde,
    Bang,
    Eq,       // =
    ColonEq,  // :=
    PlusEq,   // +=
    MinusEq,  // -=
    PlusPlus, // ++
    MinusMinus, // --
    // Literals
    Ident(String),
    Number(i64),
    StringLit(String), // backtick or double-quoted
    // End
    Eof,
}

#[derive(Debug, Clone)]
struct Token {
    typ: TokenType,
    line: usize,
    col: usize,
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

fn tokenize(source: &str) -> Vec<Token> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut pos = 0usize;
    let mut line = 1usize;
    let mut col = 1usize;

    while pos < chars.len() {
        let ch = chars[pos];
        let l = line;
        let c = col;

        // Whitespace (skip semicolons that Go inserts — we handle real `;` and newlines)
        if ch.is_whitespace() {
            if ch == '\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
            pos += 1;
            continue;
        }

        // Line comments
        if ch == '/' && pos + 1 < chars.len() && chars[pos + 1] == '/' {
            while pos < chars.len() && chars[pos] != '\n' {
                pos += 1;
            }
            continue;
        }

        // Block comments
        if ch == '/' && pos + 1 < chars.len() && chars[pos + 1] == '*' {
            pos += 2;
            col += 2;
            while pos + 1 < chars.len() {
                if chars[pos] == '\n' {
                    line += 1;
                    col = 1;
                }
                if chars[pos] == '*' && chars[pos + 1] == '/' {
                    pos += 2;
                    col += 2;
                    break;
                }
                pos += 1;
                col += 1;
            }
            continue;
        }

        // Backtick string (struct tags like `runar:"readonly"`)
        if ch == '`' {
            let mut val = String::new();
            pos += 1;
            col += 1;
            while pos < chars.len() && chars[pos] != '`' {
                val.push(chars[pos]);
                pos += 1;
                col += 1;
            }
            if pos < chars.len() {
                pos += 1;
                col += 1;
            }
            tokens.push(Token { typ: TokenType::StringLit(val), line: l, col: c });
            continue;
        }

        // Double-quoted string
        if ch == '"' {
            let mut val = String::new();
            pos += 1;
            col += 1;
            while pos < chars.len() && chars[pos] != '"' {
                if chars[pos] == '\\' && pos + 1 < chars.len() {
                    pos += 1;
                    col += 1;
                    match chars[pos] {
                        'n' => val.push('\n'),
                        't' => val.push('\t'),
                        '\\' => val.push('\\'),
                        '"' => val.push('"'),
                        c => { val.push('\\'); val.push(c); }
                    }
                } else {
                    val.push(chars[pos]);
                }
                pos += 1;
                col += 1;
            }
            if pos < chars.len() {
                pos += 1;
                col += 1;
            }
            tokens.push(Token { typ: TokenType::StringLit(val), line: l, col: c });
            continue;
        }

        // Three-char operators first
        if pos + 2 < chars.len() {
            let three = format!("{}{}{}", ch, chars[pos + 1], chars[pos + 2]);
            // none currently needed, placeholder
            let _ = three;
        }

        // Two-char operators
        if pos + 1 < chars.len() {
            let two = (ch, chars[pos + 1]);
            let tok = match two {
                (':', '=') => Some(TokenType::ColonEq),
                ('=', '=') => Some(TokenType::EqEq),
                ('!', '=') => Some(TokenType::BangEq),
                ('<', '=') => Some(TokenType::LtEq),
                ('>', '=') => Some(TokenType::GtEq),
                ('&', '&') => Some(TokenType::AmpAmp),
                ('|', '|') => Some(TokenType::PipePipe),
                ('+', '=') => Some(TokenType::PlusEq),
                ('-', '=') => Some(TokenType::MinusEq),
                ('+', '+') => Some(TokenType::PlusPlus),
                ('-', '-') => Some(TokenType::MinusMinus),
                _ => None,
            };
            if let Some(t) = tok {
                tokens.push(Token { typ: t, line: l, col: c });
                pos += 2;
                col += 2;
                continue;
            }
        }

        // Single-char tokens
        let single = match ch {
            '(' => Some(TokenType::LParen),
            ')' => Some(TokenType::RParen),
            '{' => Some(TokenType::LBrace),
            '}' => Some(TokenType::RBrace),
            '[' => Some(TokenType::LBracket),
            ']' => Some(TokenType::RBracket),
            ';' => Some(TokenType::Semi),
            ',' => Some(TokenType::Comma),
            '.' => Some(TokenType::Dot),
            ':' => Some(TokenType::Colon),
            '*' => Some(TokenType::Star),
            '+' => Some(TokenType::Plus),
            '-' => Some(TokenType::Minus),
            '/' => Some(TokenType::Slash),
            '%' => Some(TokenType::Percent),
            '<' => Some(TokenType::Lt),
            '>' => Some(TokenType::Gt),
            '&' => Some(TokenType::Amp),
            '|' => Some(TokenType::Pipe),
            '^' => Some(TokenType::Caret),
            '~' => Some(TokenType::Tilde),
            '!' => Some(TokenType::Bang),
            '=' => Some(TokenType::Eq),
            _ => None,
        };
        if let Some(t) = single {
            tokens.push(Token { typ: t, line: l, col: c });
            pos += 1;
            col += 1;
            continue;
        }

        // Number literal
        if ch.is_ascii_digit() {
            let mut val = String::new();
            while pos < chars.len() && (chars[pos].is_ascii_digit() || chars[pos] == '_') {
                if chars[pos] != '_' {
                    val.push(chars[pos]);
                }
                pos += 1;
                col += 1;
            }
            let n: i64 = val.parse().unwrap_or(0);
            tokens.push(Token { typ: TokenType::Number(n), line: l, col: c });
            continue;
        }

        // Identifier / keyword
        if ch.is_alphabetic() || ch == '_' {
            let mut val = String::new();
            while pos < chars.len() && (chars[pos].is_alphanumeric() || chars[pos] == '_') {
                val.push(chars[pos]);
                pos += 1;
                col += 1;
            }
            let tok = match val.as_str() {
                "package" => TokenType::Package,
                "import" => TokenType::Import,
                "type" => TokenType::Type,
                "struct" => TokenType::Struct,
                "func" => TokenType::Func,
                "if" => TokenType::If,
                "else" => TokenType::Else,
                "for" => TokenType::For,
                "return" => TokenType::Return,
                "var" => TokenType::Var,
                "const" => TokenType::Const,
                "true" => TokenType::True,
                "false" => TokenType::False,
                _ => TokenType::Ident(val),
            };
            tokens.push(Token { typ: tok, line: l, col: c });
            continue;
        }

        // Skip unknown characters silently
        pos += 1;
        col += 1;
    }

    tokens.push(Token { typ: TokenType::Eof, line, col });
    tokens
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct GoParser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    file: String,
    errors: &'a mut Vec<String>,
    /// The current method's receiver name (e.g. "c", "self", "m")
    receiver_name: String,
}

impl<'a> GoParser<'a> {
    fn new(tokens: Vec<Token>, file: &str, errors: &'a mut Vec<String>) -> Self {
        Self {
            tokens,
            pos: 0,
            file: file.to_string(),
            errors,
            receiver_name: "c".to_string(),
        }
    }

    fn current(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(self.tokens.last().unwrap())
    }

    fn advance(&mut self) -> Token {
        let t = self.current().clone();
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        t
    }

    fn skip_semis(&mut self) {
        while matches!(self.current().typ, TokenType::Semi) {
            self.advance();
        }
    }

    fn loc(&self) -> SourceLocation {
        SourceLocation {
            file: self.file.clone(),
            line: self.current().line,
            column: self.current().col,
        }
    }

    fn loc_at(file: &str, line: usize, col: usize) -> SourceLocation {
        SourceLocation { file: file.to_string(), line, column: col }
    }

    /// Expect an identifier, returning its value.
    fn expect_ident(&mut self) -> String {
        if let TokenType::Ident(name) = self.current().typ.clone() {
            self.advance();
            name
        } else {
            self.errors.push(format!(
                "Expected identifier, got {:?} at {}:{}",
                self.current().typ,
                self.current().line,
                self.current().col
            ));
            String::new()
        }
    }

    fn expect_tok(&mut self, expected: &TokenType) {
        if std::mem::discriminant(&self.current().typ) != std::mem::discriminant(expected) {
            self.errors.push(format!(
                "Expected {:?}, got {:?} at {}:{}:{}",
                expected,
                self.current().typ,
                self.file,
                self.current().line,
                self.current().col
            ));
        }
        self.advance();
    }

    fn match_tok(&mut self, expected: &TokenType) -> bool {
        if std::mem::discriminant(&self.current().typ) == std::mem::discriminant(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    // ---------------------------------------------------------------------------
    // Top-level parse
    // ---------------------------------------------------------------------------

    fn parse(&mut self) -> Option<ContractNode> {
        // Skip `package <name>`
        if matches!(self.current().typ, TokenType::Package) {
            self.advance();
            self.expect_ident();
            self.skip_semis();
        }

        // Skip `import ...` statements
        while matches!(self.current().typ, TokenType::Import) {
            self.advance();
            self.skip_import_block();
            self.skip_semis();
        }

        let mut contract_name = String::new();
        let mut parent_class = "SmartContract".to_string();
        let mut properties: Vec<PropertyNode> = Vec::new();

        // Find `type <Name> struct { ... }`
        while !matches!(self.current().typ, TokenType::Eof) {
            self.skip_semis();
            if matches!(self.current().typ, TokenType::Type) {
                let saved_pos = self.pos;
                self.advance(); // consume 'type'
                if let TokenType::Ident(name) = self.current().typ.clone() {
                    self.advance(); // consume name
                    if matches!(self.current().typ, TokenType::Struct) {
                        self.advance(); // consume 'struct'
                        if matches!(self.current().typ, TokenType::LBrace) {
                            // Try to find runar.SmartContract or runar.StatefulSmartContract
                            let (found_parent, props) = self.parse_struct_body();
                            if found_parent.is_some() {
                                contract_name = name;
                                parent_class = found_parent.unwrap();
                                properties = props;
                                break;
                            }
                        }
                        // Not a Rúnar contract struct, restore position
                        self.pos = saved_pos;
                        self.advance(); // skip 'type'
                    } else {
                        self.pos = saved_pos;
                        self.advance();
                    }
                } else {
                    self.pos = saved_pos;
                    self.advance();
                }
            } else {
                self.advance();
            }
        }

        if contract_name.is_empty() {
            self.errors.push("no Rúnar contract struct found in Go source".to_string());
            return None;
        }

        // Collect all methods/functions
        let mut raw_methods: Vec<MethodNode> = Vec::new();

        // Continue scanning for func declarations
        while !matches!(self.current().typ, TokenType::Eof) {
            self.skip_semis();
            if !matches!(self.current().typ, TokenType::Func) {
                self.advance();
                continue;
            }
            self.advance(); // consume 'func'

            // Check if it's a method (with receiver) or a standalone function
            if matches!(self.current().typ, TokenType::LParen) {
                // Method: func (recv *ContractName) MethodName(...)
                if let Some(method) = self.parse_method(&contract_name) {
                    raw_methods.push(method);
                }
            } else {
                // Standalone function (no receiver)
                if let Some(func) = self.parse_standalone_func() {
                    raw_methods.push(func);
                }
            }
        }

        // Separate init() method (property initializers) from regular methods
        let mut final_methods: Vec<MethodNode> = Vec::new();
        for m in raw_methods {
            if m.name == "init" && m.params.is_empty() {
                // Extract property assignments as initializers
                for stmt in &m.body {
                    if let Statement::Assignment { target, value, .. } = stmt {
                        if let Expression::PropertyAccess { property } = target {
                            for prop in properties.iter_mut() {
                                if &prop.name == property {
                                    prop.initializer = Some(value.clone());
                                    break;
                                }
                            }
                        }
                    }
                }
            } else {
                final_methods.push(m);
            }
        }

        // Build constructor from non-initialized properties
        let uninit_props: Vec<&PropertyNode> =
            properties.iter().filter(|p| p.initializer.is_none()).collect();

        let constructor_params: Vec<ParamNode> = uninit_props
            .iter()
            .map(|p| ParamNode { name: p.name.clone(), param_type: p.prop_type.clone() })
            .collect();

        // super(...) call
        let super_args: Vec<Expression> = uninit_props
            .iter()
            .map(|p| Expression::Identifier { name: p.name.clone() })
            .collect();

        let super_loc = Self::loc_at(&self.file, 1, 1);
        let mut constructor_body: Vec<Statement> = Vec::new();
        constructor_body.push(Statement::ExpressionStatement {
            expression: Expression::CallExpr {
                callee: Box::new(Expression::Identifier { name: "super".to_string() }),
                args: super_args,
            },
            source_location: super_loc.clone(),
        });

        for prop in uninit_props.iter() {
            constructor_body.push(Statement::Assignment {
                target: Expression::PropertyAccess { property: prop.name.clone() },
                value: Expression::Identifier { name: prop.name.clone() },
                source_location: super_loc.clone(),
            });
        }

        let constructor = MethodNode {
            name: "constructor".to_string(),
            params: constructor_params,
            body: constructor_body,
            visibility: Visibility::Public,
            source_location: Self::loc_at(&self.file, 1, 1),
        };

        Some(ContractNode {
            name: contract_name,
            parent_class,
            properties,
            constructor,
            methods: final_methods,
            source_file: self.file.clone(),
        })
    }

    // ---------------------------------------------------------------------------
    // Import skipping
    // ---------------------------------------------------------------------------

    fn skip_import_block(&mut self) {
        if matches!(self.current().typ, TokenType::LParen) {
            // import ( ... )
            self.advance();
            let mut depth = 1usize;
            while !matches!(self.current().typ, TokenType::Eof) {
                match self.current().typ {
                    TokenType::LParen => { depth += 1; self.advance(); }
                    TokenType::RParen => {
                        depth -= 1;
                        self.advance();
                        if depth == 0 { break; }
                    }
                    _ => { self.advance(); }
                }
            }
        } else {
            // import "..." or import alias "path"
            // Since we don't emit implicit semicolons, skip tokens until we hit
            // a StringLit (the path), then stop. This handles both forms:
            //   import "path"
            //   import alias "path"
            while !matches!(self.current().typ, TokenType::Eof) {
                if let TokenType::StringLit(_) = self.current().typ.clone() {
                    self.advance(); // consume the path string
                    break;
                }
                // Also stop if we hit a top-level keyword (defensive)
                if matches!(self.current().typ,
                    TokenType::Type | TokenType::Func | TokenType::Package) {
                    break;
                }
                self.advance();
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Struct body parsing
    // ---------------------------------------------------------------------------

    /// Parse `{ ... }` struct body. Returns (Option<parentClass>, Vec<PropertyNode>).
    /// Returns (None, _) if no runar.SmartContract embed is found.
    fn parse_struct_body(&mut self) -> (Option<String>, Vec<PropertyNode>) {
        self.expect_tok(&TokenType::LBrace);

        let mut parent_class: Option<String> = None;
        let mut properties: Vec<PropertyNode> = Vec::new();

        while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
            self.skip_semis();
            if matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
                break;
            }

            // Could be:
            // - runar.SmartContract (embed, no name)
            // - FieldName runar.Type `tag`
            // - FieldName runar.Type
            // We need to look ahead to determine what we have.

            let line = self.current().line;
            let col_start = self.current().col;

            // Try to read the first identifier
            let first_name = if let TokenType::Ident(n) = self.current().typ.clone() {
                self.advance();
                n
            } else {
                self.advance();
                continue;
            };

            // If followed by '.', it could be `runar.SmartContract` (embedded type)
            if matches!(self.current().typ, TokenType::Dot) {
                self.advance(); // consume '.'
                let second = if let TokenType::Ident(n) = self.current().typ.clone() {
                    self.advance();
                    n
                } else {
                    continue;
                };

                if first_name == "runar" {
                    match second.as_str() {
                        "SmartContract" => {
                            parent_class = Some("SmartContract".to_string());
                        }
                        "StatefulSmartContract" => {
                            parent_class = Some("StatefulSmartContract".to_string());
                        }
                        _ => {
                            // Might be a field of type runar.Type — but we need a field name first
                            // This is unlikely in embedded form, skip
                        }
                    }
                    // Skip optional struct tag on this line
                    if matches!(self.current().typ, TokenType::StringLit(_)) {
                        self.advance();
                    }
                    self.skip_semis();
                    continue;
                }

                // Otherwise: first_name is the field name and first_name.second is the type
                // e.g., "Balance runar.Bigint" (but we already consumed "Balance" and "runar.Bigint")
                // Actually first_name here is NOT the field name — it's like "runar" but not equal
                // Could be another package reference. Skip.
                if matches!(self.current().typ, TokenType::StringLit(_)) {
                    self.advance();
                }
                self.skip_semis();
                continue;
            }

            // Otherwise first_name is a field name, next is the type
            // e.g. `PubKeyHash runar.Addr `runar:"readonly"``
            let prop_type = self.parse_type();
            let prop_name = go_to_camel(&first_name);

            // Check for struct tag
            let mut readonly = false;
            if let TokenType::StringLit(tag) = self.current().typ.clone() {
                self.advance();
                if tag.contains(r#"runar:"readonly""#) {
                    readonly = true;
                }
            }

            let loc = SourceLocation { file: self.file.clone(), line, column: col_start };
            properties.push(PropertyNode {
                name: prop_name,
                prop_type,
                readonly,
                initializer: None,
                source_location: loc,
            });

            self.skip_semis();
        }

        self.match_tok(&TokenType::RBrace);

        (parent_class, properties)
    }

    // ---------------------------------------------------------------------------
    // Type parsing
    // ---------------------------------------------------------------------------

    fn parse_type(&mut self) -> TypeNode {
        // `[]byte` — slice type
        if matches!(self.current().typ, TokenType::LBracket) {
            self.advance(); // '['
            if matches!(self.current().typ, TokenType::RBracket) {
                self.advance(); // ']'
                let inner = self.parse_type();
                // []byte -> ByteString
                if let TypeNode::Primitive(PrimitiveTypeName::Bigint) = &inner {
                    // byte is not bigint, but we mapped it via map_go_type; for []byte just return ByteString
                }
                return TypeNode::Primitive(PrimitiveTypeName::ByteString);
            }
            // Fixed-size array [N]T
            let size = if let TokenType::Number(n) = self.current().typ.clone() {
                self.advance();
                n as usize
            } else {
                0
            };
            self.match_tok(&TokenType::RBracket);
            let inner = self.parse_type();
            return TypeNode::FixedArray { element: Box::new(inner), length: size };
        }

        // `runar.TypeName` or plain ident
        if let TokenType::Ident(first) = self.current().typ.clone() {
            self.advance();
            if matches!(self.current().typ, TokenType::Dot) {
                self.advance();
                if let TokenType::Ident(second) = self.current().typ.clone() {
                    self.advance();
                    if first == "runar" {
                        return map_go_type(&second);
                    }
                    return TypeNode::Custom(format!("{}.{}", first, second));
                }
            }
            // Plain identifier like `bool`, `int64`, `string`
            return map_go_type(&first);
        }

        TypeNode::Custom("unknown".to_string())
    }

    // ---------------------------------------------------------------------------
    // Method parsing
    // ---------------------------------------------------------------------------

    /// Parse a method: `(recv *ContractName) MethodName(params) ReturnType { body }`
    /// The `func` keyword has already been consumed.
    fn parse_method(&mut self, contract_name: &str) -> Option<MethodNode> {
        // (recv *ContractName)
        self.expect_tok(&TokenType::LParen);

        let recv_name = if let TokenType::Ident(n) = self.current().typ.clone() {
            let n_clone = n.clone();
            self.advance();
            n_clone
        } else {
            "c".to_string()
        };

        // *ContractName or ContractName
        self.match_tok(&TokenType::Star);

        let recv_type = if let TokenType::Ident(n) = self.current().typ.clone() {
            self.advance();
            n
        } else {
            String::new()
        };

        self.expect_tok(&TokenType::RParen);

        if recv_type != contract_name {
            // Not a method on our contract — skip to end of block
            self.skip_to_matching_brace();
            return None;
        }

        self.receiver_name = recv_name;

        let method_name_raw = self.expect_ident();
        let method_name = go_to_camel(&method_name_raw);

        // Exported = public, unexported = private
        let visibility = if method_name_raw.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
            Visibility::Public
        } else {
            Visibility::Private
        };

        let loc = SourceLocation {
            file: self.file.clone(),
            line: self.current().line,
            column: self.current().col,
        };

        // Parameters
        let params = self.parse_params();

        // Optional return type (skip it — Rúnar doesn't use it structurally)
        self.skip_return_type();

        // Body
        let body = self.parse_block();

        Some(MethodNode {
            name: method_name,
            params,
            body,
            visibility,
            source_location: loc,
        })
    }

    /// Parse a standalone function (no receiver): `FuncName(params) ReturnType { body }`
    /// The `func` keyword has already been consumed.
    fn parse_standalone_func(&mut self) -> Option<MethodNode> {
        let func_name_raw = self.expect_ident();

        // Skip init() and main()
        if func_name_raw == "init" || func_name_raw == "main" {
            self.skip_to_matching_brace();
            return None;
        }

        // Exported standalone functions are skipped (only unexported helpers)
        // (But we parse all, callers can filter)

        let func_name = go_to_camel(&func_name_raw);
        // Standalone functions with receiver = "" → private
        let saved_recv = self.receiver_name.clone();
        self.receiver_name = String::new(); // no receiver

        let loc = SourceLocation {
            file: self.file.clone(),
            line: self.current().line,
            column: self.current().col,
        };

        let params = self.parse_params();
        self.skip_return_type();
        let body = self.parse_block();

        self.receiver_name = saved_recv;

        // Exported standalone functions: skip them (Go compiler also skips them)
        if func_name_raw.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
            return None;
        }

        Some(MethodNode {
            name: func_name,
            params,
            body,
            visibility: Visibility::Private,
            source_location: loc,
        })
    }

    /// Parse parameter list: `(a runar.Type, b runar.Type, ...)`
    fn parse_params(&mut self) -> Vec<ParamNode> {
        self.expect_tok(&TokenType::LParen);
        let mut params = Vec::new();

        while !matches!(self.current().typ, TokenType::RParen | TokenType::Eof) {
            // Could be `name runar.Type` or just `,`
            if matches!(self.current().typ, TokenType::Comma) {
                self.advance();
                continue;
            }

            let name_raw = if let TokenType::Ident(n) = self.current().typ.clone() {
                self.advance();
                n
            } else {
                break;
            };

            let param_type = self.parse_type();
            let param_name = go_to_camel(&name_raw);

            params.push(ParamNode { name: param_name, param_type });

            self.match_tok(&TokenType::Comma);
        }

        self.expect_tok(&TokenType::RParen);
        params
    }

    /// Skip an optional return type declaration (everything up to `{` or EOF).
    fn skip_return_type(&mut self) {
        // If next token is `{`, no return type
        if matches!(self.current().typ, TokenType::LBrace | TokenType::Eof) {
            return;
        }
        // Otherwise skip until we find `{` (possibly a parenthesized multi-return)
        let mut depth = 0usize;
        while !matches!(self.current().typ, TokenType::Eof) {
            match self.current().typ {
                TokenType::LParen => { depth += 1; self.advance(); }
                TokenType::RParen => {
                    if depth > 0 { depth -= 1; }
                    self.advance();
                }
                TokenType::LBrace => break,
                _ => { self.advance(); }
            }
        }
    }

    /// Parse a block `{ ... }` and return the statements.
    fn parse_block(&mut self) -> Vec<Statement> {
        self.expect_tok(&TokenType::LBrace);
        let mut stmts = Vec::new();

        while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
            self.skip_semis();
            if matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
                break;
            }
            if let Some(s) = self.parse_statement() {
                stmts.push(s);
            } else {
                // Skip unknown tokens to avoid infinite loop
                self.advance();
            }
            self.skip_semis();
        }

        self.match_tok(&TokenType::RBrace);
        stmts
    }

    // ---------------------------------------------------------------------------
    // Statement parsing
    // ---------------------------------------------------------------------------

    fn parse_statement(&mut self) -> Option<Statement> {
        let loc = self.loc();

        match self.current().typ.clone() {
            TokenType::If => {
                self.advance();
                let cond = self.parse_expr()?;
                let then_branch = self.parse_block();
                let else_branch = if matches!(self.current().typ, TokenType::Else) {
                    self.advance();
                    if matches!(self.current().typ, TokenType::If) {
                        // else if → wrap in a single-statement else branch
                        if let Some(s) = self.parse_statement() {
                            Some(vec![s])
                        } else {
                            None
                        }
                    } else {
                        Some(self.parse_block())
                    }
                } else {
                    None
                };
                Some(Statement::IfStatement { condition: cond, then_branch, else_branch, source_location: loc })
            }

            TokenType::For => {
                self.advance();
                self.parse_for_statement(loc)
            }

            TokenType::Return => {
                self.advance();
                let value = if matches!(self.current().typ, TokenType::Semi | TokenType::RBrace | TokenType::Eof) {
                    None
                } else {
                    self.parse_expr()
                };
                Some(Statement::ReturnStatement { value, source_location: loc })
            }

            TokenType::Var | TokenType::Const => {
                // var/const Name Type = Expr
                let is_var = matches!(self.current().typ, TokenType::Var);
                self.advance();
                let name_raw = self.expect_ident();
                let name = go_to_camel(&name_raw);

                // Optional type
                let var_type = if !matches!(self.current().typ, TokenType::Eq | TokenType::Semi | TokenType::Eof) {
                    Some(self.parse_type())
                } else {
                    None
                };

                let init = if matches!(self.current().typ, TokenType::Eq) {
                    self.advance();
                    self.parse_expr()?
                } else {
                    return None;
                };

                Some(Statement::VariableDecl {
                    name,
                    var_type,
                    mutable: is_var,
                    init,
                    source_location: loc,
                })
            }

            TokenType::Ident(_) => {
                // Could be:
                // - `name := expr`  (short variable decl)
                // - `name = expr`   (assignment)
                // - `name.field = expr`
                // - `name++` / `name--`
                // - expression statement (function call, etc.)
                self.parse_ident_statement(loc)
            }

            // Standalone increment/decrement is unlikely at statement start but handle anyway
            TokenType::PlusPlus | TokenType::MinusMinus => {
                let is_inc = matches!(self.current().typ, TokenType::PlusPlus);
                self.advance();
                let operand = self.parse_primary()?;
                if is_inc {
                    Some(Statement::ExpressionStatement {
                        expression: Expression::IncrementExpr { operand: Box::new(operand), prefix: true },
                        source_location: loc,
                    })
                } else {
                    Some(Statement::ExpressionStatement {
                        expression: Expression::DecrementExpr { operand: Box::new(operand), prefix: true },
                        source_location: loc,
                    })
                }
            }

            _ => {
                // Try as expression statement
                if let Some(expr) = self.parse_expr() {
                    Some(Statement::ExpressionStatement { expression: expr, source_location: loc })
                } else {
                    None
                }
            }
        }
    }

    fn parse_ident_statement(&mut self, loc: SourceLocation) -> Option<Statement> {
        // Parse the left-hand side expression
        let lhs = self.parse_expr()?;

        match self.current().typ.clone() {
            TokenType::ColonEq => {
                // name := expr
                self.advance();
                let rhs = self.parse_expr()?;
                let name = if let Expression::Identifier { name } = &lhs {
                    name.clone()
                } else {
                    String::new()
                };
                Some(Statement::VariableDecl {
                    name,
                    var_type: None,
                    mutable: true,
                    init: rhs,
                    source_location: loc,
                })
            }

            TokenType::Eq => {
                // target = expr
                self.advance();
                let rhs = self.parse_expr()?;
                Some(Statement::Assignment { target: lhs, value: rhs, source_location: loc })
            }

            TokenType::PlusEq => {
                // target += expr  ->  target = target + expr
                self.advance();
                let rhs = self.parse_expr()?;
                let new_val = Expression::BinaryExpr {
                    op: BinaryOp::Add,
                    left: Box::new(lhs.clone()),
                    right: Box::new(rhs),
                };
                Some(Statement::Assignment { target: lhs, value: new_val, source_location: loc })
            }

            TokenType::MinusEq => {
                // target -= expr  ->  target = target - expr
                self.advance();
                let rhs = self.parse_expr()?;
                let new_val = Expression::BinaryExpr {
                    op: BinaryOp::Sub,
                    left: Box::new(lhs.clone()),
                    right: Box::new(rhs),
                };
                Some(Statement::Assignment { target: lhs, value: new_val, source_location: loc })
            }

            TokenType::PlusPlus => {
                // x++ -> ExpressionStatement(IncrementExpr)
                self.advance();
                Some(Statement::ExpressionStatement {
                    expression: Expression::IncrementExpr { operand: Box::new(lhs), prefix: false },
                    source_location: loc,
                })
            }

            TokenType::MinusMinus => {
                // x-- -> ExpressionStatement(DecrementExpr)
                self.advance();
                Some(Statement::ExpressionStatement {
                    expression: Expression::DecrementExpr { operand: Box::new(lhs), prefix: false },
                    source_location: loc,
                })
            }

            _ => {
                // Expression statement (e.g., function call)
                Some(Statement::ExpressionStatement { expression: lhs, source_location: loc })
            }
        }
    }

    fn parse_for_statement(&mut self, loc: SourceLocation) -> Option<Statement> {
        // for { body }  — infinite loop (not valid Rúnar but handle gracefully)
        // for i := 0; i < n; i++ { body }
        // for i < n { body }  — Go while-equivalent

        // Check if it's a simple condition for (no init/post)
        // We peek ahead: if next token starts a block immediately or is a simple expr
        // A three-part for has `:=` or `=` followed by `;`
        // Heuristic: look for `;` before `{`
        let is_three_part = self.has_semi_before_brace();

        if is_three_part {
            // Parse init statement
            let init = self.parse_for_init_statement()?;
            self.skip_semis();

            // Parse condition
            let condition = if matches!(self.current().typ, TokenType::Semi) {
                // No condition (always true), use BoolLiteral true
                Expression::BoolLiteral { value: true }
            } else {
                self.parse_expr()?
            };
            self.skip_semis();

            // Parse post statement
            let update = self.parse_for_post_statement()?;

            let body = self.parse_block();

            Some(Statement::ForStatement {
                init: Box::new(init),
                condition,
                update: Box::new(update),
                body,
                source_location: loc,
            })
        } else {
            // `for condition { body }` — simple while-like loop
            // We need a dummy init
            let condition = self.parse_expr()?;
            let body = self.parse_block();

            let dummy_init = Statement::VariableDecl {
                name: "_i".to_string(),
                var_type: None,
                mutable: true,
                init: Expression::BigIntLiteral { value: 0 },
                source_location: loc.clone(),
            };
            let dummy_update = Statement::ExpressionStatement {
                expression: Expression::Identifier { name: "_i".to_string() },
                source_location: loc.clone(),
            };

            Some(Statement::ForStatement {
                init: Box::new(dummy_init),
                condition,
                update: Box::new(dummy_update),
                body,
                source_location: loc,
            })
        }
    }

    fn has_semi_before_brace(&self) -> bool {
        let mut i = self.pos;
        while i < self.tokens.len() {
            match self.tokens[i].typ {
                TokenType::Semi => return true,
                TokenType::LBrace => return false,
                TokenType::Eof => return false,
                _ => {}
            }
            i += 1;
        }
        false
    }

    fn parse_for_init_statement(&mut self) -> Option<Statement> {
        let loc = self.loc();
        // `i := 0` or `var i int = 0`
        if let TokenType::Ident(name_raw) = self.current().typ.clone() {
            let name = go_to_camel(&name_raw);
            self.advance();
            if matches!(self.current().typ, TokenType::ColonEq) {
                self.advance();
                let init = self.parse_expr()?;
                return Some(Statement::VariableDecl {
                    name,
                    var_type: None,
                    mutable: true,
                    init,
                    source_location: loc,
                });
            }
        }
        // Fallback: parse as expression
        let expr = self.parse_expr()?;
        Some(Statement::ExpressionStatement { expression: expr, source_location: loc })
    }

    fn parse_for_post_statement(&mut self) -> Option<Statement> {
        let loc = self.loc();
        // `i++`, `i--`, `i += 1`, etc.
        let lhs = self.parse_expr()?;
        match self.current().typ.clone() {
            TokenType::PlusPlus => {
                self.advance();
                Some(Statement::ExpressionStatement {
                    expression: Expression::IncrementExpr { operand: Box::new(lhs), prefix: false },
                    source_location: loc,
                })
            }
            TokenType::MinusMinus => {
                self.advance();
                Some(Statement::ExpressionStatement {
                    expression: Expression::DecrementExpr { operand: Box::new(lhs), prefix: false },
                    source_location: loc,
                })
            }
            TokenType::PlusEq => {
                self.advance();
                let rhs = self.parse_expr()?;
                let new_val = Expression::BinaryExpr {
                    op: BinaryOp::Add,
                    left: Box::new(lhs.clone()),
                    right: Box::new(rhs),
                };
                Some(Statement::Assignment { target: lhs, value: new_val, source_location: loc })
            }
            TokenType::MinusEq => {
                self.advance();
                let rhs = self.parse_expr()?;
                let new_val = Expression::BinaryExpr {
                    op: BinaryOp::Sub,
                    left: Box::new(lhs.clone()),
                    right: Box::new(rhs),
                };
                Some(Statement::Assignment { target: lhs, value: new_val, source_location: loc })
            }
            _ => Some(Statement::ExpressionStatement { expression: lhs, source_location: loc }),
        }
    }

    // ---------------------------------------------------------------------------
    // Expression parsing (Pratt-style precedence climbing)
    // ---------------------------------------------------------------------------

    fn parse_expr(&mut self) -> Option<Expression> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Option<Expression> {
        let mut left = self.parse_and()?;
        while matches!(self.current().typ, TokenType::PipePipe) {
            self.advance();
            let right = self.parse_and()?;
            left = Expression::BinaryExpr { op: BinaryOp::Or, left: Box::new(left), right: Box::new(right) };
        }
        Some(left)
    }

    fn parse_and(&mut self) -> Option<Expression> {
        let mut left = self.parse_bitor()?;
        while matches!(self.current().typ, TokenType::AmpAmp) {
            self.advance();
            let right = self.parse_bitor()?;
            left = Expression::BinaryExpr { op: BinaryOp::And, left: Box::new(left), right: Box::new(right) };
        }
        Some(left)
    }

    fn parse_bitor(&mut self) -> Option<Expression> {
        let mut left = self.parse_bitxor()?;
        while matches!(self.current().typ, TokenType::Pipe) {
            self.advance();
            let right = self.parse_bitxor()?;
            left = Expression::BinaryExpr { op: BinaryOp::BitOr, left: Box::new(left), right: Box::new(right) };
        }
        Some(left)
    }

    fn parse_bitxor(&mut self) -> Option<Expression> {
        let mut left = self.parse_bitand()?;
        while matches!(self.current().typ, TokenType::Caret) {
            self.advance();
            let right = self.parse_bitand()?;
            left = Expression::BinaryExpr { op: BinaryOp::BitXor, left: Box::new(left), right: Box::new(right) };
        }
        Some(left)
    }

    fn parse_bitand(&mut self) -> Option<Expression> {
        let mut left = self.parse_equality()?;
        while matches!(self.current().typ, TokenType::Amp) {
            self.advance();
            let right = self.parse_equality()?;
            left = Expression::BinaryExpr { op: BinaryOp::BitAnd, left: Box::new(left), right: Box::new(right) };
        }
        Some(left)
    }

    fn parse_equality(&mut self) -> Option<Expression> {
        let mut left = self.parse_relational()?;
        loop {
            let op = match self.current().typ {
                TokenType::EqEq => BinaryOp::StrictEq,
                TokenType::BangEq => BinaryOp::StrictNe,
                _ => break,
            };
            self.advance();
            let right = self.parse_relational()?;
            left = Expression::BinaryExpr { op, left: Box::new(left), right: Box::new(right) };
        }
        Some(left)
    }

    fn parse_relational(&mut self) -> Option<Expression> {
        let mut left = self.parse_additive()?;
        loop {
            let op = match self.current().typ {
                TokenType::Lt => BinaryOp::Lt,
                TokenType::LtEq => BinaryOp::Le,
                TokenType::Gt => BinaryOp::Gt,
                TokenType::GtEq => BinaryOp::Ge,
                _ => break,
            };
            self.advance();
            let right = self.parse_additive()?;
            left = Expression::BinaryExpr { op, left: Box::new(left), right: Box::new(right) };
        }
        Some(left)
    }

    fn parse_additive(&mut self) -> Option<Expression> {
        let mut left = self.parse_multiplicative()?;
        loop {
            let op = match self.current().typ {
                TokenType::Plus => BinaryOp::Add,
                TokenType::Minus => BinaryOp::Sub,
                _ => break,
            };
            self.advance();
            let right = self.parse_multiplicative()?;
            left = Expression::BinaryExpr { op, left: Box::new(left), right: Box::new(right) };
        }
        Some(left)
    }

    fn parse_multiplicative(&mut self) -> Option<Expression> {
        let mut left = self.parse_unary()?;
        loop {
            let op = match self.current().typ {
                TokenType::Star => BinaryOp::Mul,
                TokenType::Slash => BinaryOp::Div,
                TokenType::Percent => BinaryOp::Mod,
                _ => break,
            };
            self.advance();
            let right = self.parse_unary()?;
            left = Expression::BinaryExpr { op, left: Box::new(left), right: Box::new(right) };
        }
        Some(left)
    }

    fn parse_unary(&mut self) -> Option<Expression> {
        match self.current().typ.clone() {
            TokenType::Bang => {
                self.advance();
                let operand = self.parse_unary()?;
                Some(Expression::UnaryExpr { op: UnaryOp::Not, operand: Box::new(operand) })
            }
            TokenType::Minus => {
                self.advance();
                let operand = self.parse_unary()?;
                Some(Expression::UnaryExpr { op: UnaryOp::Neg, operand: Box::new(operand) })
            }
            TokenType::Tilde | TokenType::Caret => {
                self.advance();
                let operand = self.parse_unary()?;
                Some(Expression::UnaryExpr { op: UnaryOp::BitNot, operand: Box::new(operand) })
            }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Option<Expression> {
        let mut expr = self.parse_primary()?;

        loop {
            match self.current().typ.clone() {
                TokenType::Dot => {
                    self.advance();
                    let prop_raw = self.expect_ident();
                    let prop = go_to_camel(&prop_raw);

                    // Check if it's a call: expr.method(...)
                    if matches!(self.current().typ, TokenType::LParen) {
                        let args = self.parse_call_args();
                        expr = Expression::CallExpr {
                            callee: Box::new(Expression::MemberExpr {
                                object: Box::new(expr),
                                property: prop,
                            }),
                            args,
                        };
                    } else {
                        // field access
                        expr = Expression::MemberExpr { object: Box::new(expr), property: prop };
                    }
                }

                TokenType::LBracket => {
                    self.advance();
                    let index = self.parse_expr()?;
                    self.expect_tok(&TokenType::RBracket);
                    expr = Expression::IndexAccess { object: Box::new(expr), index: Box::new(index) };
                }

                TokenType::LParen => {
                    // Direct call: func(...)
                    let args = self.parse_call_args();
                    expr = Expression::CallExpr { callee: Box::new(expr), args };
                }

                _ => break,
            }
        }

        Some(expr)
    }

    fn parse_primary(&mut self) -> Option<Expression> {
        match self.current().typ.clone() {
            TokenType::Number(n) => {
                self.advance();
                Some(Expression::BigIntLiteral { value: n })
            }

            TokenType::True => {
                self.advance();
                Some(Expression::BoolLiteral { value: true })
            }

            TokenType::False => {
                self.advance();
                Some(Expression::BoolLiteral { value: false })
            }

            TokenType::StringLit(s) => {
                self.advance();
                Some(Expression::ByteStringLiteral { value: s })
            }

            TokenType::LParen => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect_tok(&TokenType::RParen);
                Some(expr)
            }

            TokenType::Ident(name) => {
                self.advance();

                // `runar.Something` — could be type conversion or builtin call
                if name == "runar" && matches!(self.current().typ, TokenType::Dot) {
                    self.advance(); // consume '.'
                    let member_raw = self.expect_ident();

                    // Type conversion: runar.Int(x), runar.Bigint(x), runar.Bool(x)
                    if matches!(member_raw.as_str(), "Int" | "Bigint" | "Bool") {
                        if matches!(self.current().typ, TokenType::LParen) {
                            let args = self.parse_call_args();
                            // Unwrap: runar.Int(x) -> x
                            if args.len() == 1 {
                                return Some(args.into_iter().next().unwrap());
                            }
                        }
                    }

                    let callee_name = map_go_builtin(&member_raw);

                    if matches!(self.current().typ, TokenType::LParen) {
                        let args = self.parse_call_args();
                        return Some(Expression::CallExpr {
                            callee: Box::new(Expression::Identifier { name: callee_name }),
                            args,
                        });
                    }

                    return Some(Expression::Identifier { name: callee_name });
                }

                // Receiver access: c.Field or self.Field
                if (name == self.receiver_name && !self.receiver_name.is_empty())
                    || name == "c"
                    || name == "self"
                {
                    if matches!(self.current().typ, TokenType::Dot) {
                        self.advance(); // consume '.'
                        let prop_raw = self.expect_ident();
                        let prop = go_to_camel(&prop_raw);

                        // Check for method call on receiver: c.privateMethod(...)
                        if matches!(self.current().typ, TokenType::LParen) {
                            let args = self.parse_call_args();
                            return Some(Expression::CallExpr {
                                callee: Box::new(Expression::MemberExpr {
                                    object: Box::new(Expression::Identifier { name: "this".to_string() }),
                                    property: prop,
                                }),
                                args,
                            });
                        }

                        return Some(Expression::PropertyAccess { property: prop });
                    }
                    // Receiver as value without field access — skip returning Identifier
                }

                // Regular identifier
                let camel = go_to_camel(&name);
                Some(Expression::Identifier { name: camel })
            }

            _ => None,
        }
    }

    fn parse_call_args(&mut self) -> Vec<Expression> {
        self.expect_tok(&TokenType::LParen);
        let mut args = Vec::new();

        while !matches!(self.current().typ, TokenType::RParen | TokenType::Eof) {
            if matches!(self.current().typ, TokenType::Comma) {
                self.advance();
                continue;
            }
            if let Some(arg) = self.parse_expr() {
                args.push(arg);
            } else {
                break;
            }
            self.match_tok(&TokenType::Comma);
        }

        self.expect_tok(&TokenType::RParen);
        args
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    /// Skip to the matching `}` brace (used when skipping non-contract methods).
    fn skip_to_matching_brace(&mut self) {
        // Find the next `{` first
        while !matches!(self.current().typ, TokenType::LBrace | TokenType::Eof) {
            self.advance();
        }
        if matches!(self.current().typ, TokenType::Eof) {
            return;
        }
        let mut depth = 0usize;
        while !matches!(self.current().typ, TokenType::Eof) {
            match self.current().typ {
                TokenType::LBrace => { depth += 1; self.advance(); }
                TokenType::RBrace => {
                    if depth > 0 { depth -= 1; }
                    self.advance();
                    if depth == 0 { break; }
                }
                _ => { self.advance(); }
            }
        }
    }
}
