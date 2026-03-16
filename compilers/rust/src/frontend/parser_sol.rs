//! Solidity-like parser for Rúnar contracts.
//!
//! Parses a Solidity-style syntax into the same AST as the TypeScript parser.
//! Hand-written tokenizer + recursive descent parser.
//!
//! ## Expected format
//!
//! ```solidity
//! // SPDX-License-Identifier: MIT
//! contract P2PKH is SmartContract {
//!     immutable Addr pubKeyHash;
//!
//!     constructor(Addr pubKeyHash) {
//!         super(pubKeyHash);
//!         this.pubKeyHash = pubKeyHash;
//!     }
//!
//!     function unlock(Sig sig, PubKey pubKey) public {
//!         require(hash160(pubKey) == this.pubKeyHash);
//!         require(checkSig(sig, pubKey));
//!     }
//! }
//! ```
//!
//! Key mappings:
//! - `require(x)` -> `assert(x)`
//! - `immutable` -> readonly
//! - `==` -> StrictEq (===)
//! - `!=` -> StrictNe (!==)
//! - Types before names (Solidity convention)

use super::ast::{
    BinaryOp, ContractNode, Expression, MethodNode, ParamNode, PrimitiveTypeName, PropertyNode,
    SourceLocation, Statement, TypeNode, UnaryOp, Visibility,
};
use super::parser::ParseResult;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a Solidity-format Rúnar contract source.
pub fn parse_solidity(source: &str, file_name: Option<&str>) -> ParseResult {
    let file = file_name.unwrap_or("contract.runar.sol");
    let mut errors: Vec<String> = Vec::new();

    let tokens = tokenize(source);
    let mut parser = SolParser::new(tokens, file, &mut errors);

    let contract = parser.parse_contract();

    ParseResult {
        contract,
        errors,
    }
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    // Keywords
    Contract,
    Is,
    Immutable,
    Constructor,
    Function,
    Public,
    Private,
    If,
    Else,
    For,
    Return,
    Require,
    Let,
    Const,
    True,
    False,

    // Identifiers and literals
    Ident(String),
    NumberLit(i64),
    StringLit(String),

    // Operators
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    EqEq,       // == (maps to ===)
    NotEq,      // != (maps to !==)
    EqEqEq,     // ===
    NotEqEq,    // !==
    Lt,
    Le,
    Gt,
    Ge,
    And,        // &&
    Or,         // ||
    BitAnd,     // &
    BitOr,      // |
    BitXor,     // ^
    Not,        // !
    Tilde,      // ~
    Eq,         // =
    PlusEq,     // +=
    MinusEq,    // -=
    StarEq,     // *=
    SlashEq,    // /=
    PercentEq,  // %=
    PlusPlus,   // ++
    MinusMinus, // --

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

        // Whitespace
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

        // Multi-character operators (order matters: longest match first)
        if ch == '=' && i + 2 < len && chars[i + 1] == '=' && chars[i + 2] == '=' {
            tokens.push(Token::EqEqEq);
            i += 3;
            continue;
        }
        if ch == '!' && i + 2 < len && chars[i + 1] == '=' && chars[i + 2] == '=' {
            tokens.push(Token::NotEqEq);
            i += 3;
            continue;
        }
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

        // Single-character tokens
        match ch {
            '+' => { tokens.push(Token::Plus); i += 1; continue; }
            '-' => { tokens.push(Token::Minus); i += 1; continue; }
            '*' => { tokens.push(Token::Star); i += 1; continue; }
            '/' => { tokens.push(Token::Slash); i += 1; continue; }
            '%' => { tokens.push(Token::Percent); i += 1; continue; }
            '<' => { tokens.push(Token::Lt); i += 1; continue; }
            '>' => { tokens.push(Token::Gt); i += 1; continue; }
            '!' => { tokens.push(Token::Not); i += 1; continue; }
            '~' => { tokens.push(Token::Tilde); i += 1; continue; }
            '&' => { tokens.push(Token::BitAnd); i += 1; continue; }
            '|' => { tokens.push(Token::BitOr); i += 1; continue; }
            '^' => { tokens.push(Token::BitXor); i += 1; continue; }
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
        if ch == '\'' || ch == '"' {
            let quote = ch;
            i += 1;
            let start = i;
            while i < len && chars[i] != quote {
                if chars[i] == '\\' {
                    i += 1; // skip escaped char
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

        // Numbers
        if ch.is_ascii_digit() {
            let start = i;
            while i < len && (chars[i].is_ascii_digit() || chars[i] == 'n') {
                i += 1;
            }
            let num_str: String = chars[start..i].iter().collect();
            let num_str = num_str.trim_end_matches('n');
            let val = num_str.parse::<i64>().unwrap_or(0);
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
            let tok = match word.as_str() {
                "contract" => Token::Contract,
                "is" => Token::Is,
                "immutable" => Token::Immutable,
                "constructor" => Token::Constructor,
                "function" => Token::Function,
                "public" => Token::Public,
                "private" => Token::Private,
                "if" => Token::If,
                "else" => Token::Else,
                "for" => Token::For,
                "return" => Token::Return,
                "require" => Token::Require,
                "let" => Token::Let,
                "const" => Token::Const,
                "true" => Token::True,
                "false" => Token::False,
                _ => Token::Ident(word),
            };
            tokens.push(tok);
            continue;
        }

        // Skip unrecognized characters
        i += 1;
    }

    tokens.push(Token::Eof);
    tokens
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct SolParser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    file: &'a str,
    errors: &'a mut Vec<String>,
}

impl<'a> SolParser<'a> {
    fn new(tokens: Vec<Token>, file: &'a str, errors: &'a mut Vec<String>) -> Self {
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
        if self.peek() == expected {
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
    // Top-level contract
    // -----------------------------------------------------------------------

    fn parse_contract(&mut self) -> Option<ContractNode> {
        // Skip any top-level pragmas, imports, or comments until we see 'contract'
        while *self.peek() != Token::Contract && *self.peek() != Token::Eof {
            self.advance();
        }

        if *self.peek() == Token::Eof {
            self.errors
                .push("No 'contract' declaration found".to_string());
            return None;
        }

        self.expect(&Token::Contract);
        let name = self.expect_ident();

        // 'is' BaseClass
        let parent_class = if *self.peek() == Token::Is {
            self.advance();
            self.expect_ident()
        } else {
            "SmartContract".to_string()
        };

        self.expect(&Token::LBrace);

        let mut properties = Vec::new();
        let mut constructor: Option<MethodNode> = None;
        let mut methods = Vec::new();

        while *self.peek() != Token::RBrace && *self.peek() != Token::Eof {
            match self.peek().clone() {
                Token::Constructor => {
                    constructor = Some(self.parse_constructor());
                }
                Token::Function => {
                    methods.push(self.parse_function());
                }
                Token::Immutable => {
                    properties.push(self.parse_property(true));
                }
                Token::Ident(_) => {
                    // Non-immutable property: "Type name;"
                    properties.push(self.parse_property(false));
                }
                _ => {
                    self.errors.push(format!(
                        "Unexpected token in contract body: {:?}",
                        self.peek()
                    ));
                    self.advance();
                }
            }
        }

        self.expect(&Token::RBrace);

        let constructor = constructor.unwrap_or_else(|| {
            self.errors
                .push("Contract must have a constructor".to_string());
            MethodNode {
                name: "constructor".to_string(),
                params: Vec::new(),
                body: Vec::new(),
                visibility: Visibility::Public,
                source_location: self.loc(),
            }
        });

        Some(ContractNode {
            name,
            parent_class,
            properties,
            constructor,
            methods,
            source_file: self.file.to_string(),
        })
    }

    // -----------------------------------------------------------------------
    // Properties
    // -----------------------------------------------------------------------

    fn parse_property(&mut self, is_immutable: bool) -> PropertyNode {
        if is_immutable {
            self.advance(); // consume 'immutable'
        }

        let type_node = self.parse_type();
        let name = self.expect_ident();

        // Parse optional initializer: = value
        let initializer = if *self.peek() == Token::Eq {
            self.advance(); // consume '='
            Some(self.parse_expression())
        } else {
            None
        };

        self.expect(&Token::Semicolon);

        PropertyNode {
            name,
            prop_type: type_node,
            readonly: is_immutable,
            initializer,
            source_location: self.loc(),
        }
    }

    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    fn parse_type(&mut self) -> TypeNode {
        let name = self.expect_ident();

        // Check for FixedArray<T, N>
        if name == "FixedArray" {
            if *self.peek() == Token::Lt {
                self.advance(); // <
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
                self.expect(&Token::Gt);
                return TypeNode::FixedArray {
                    element: Box::new(element),
                    length,
                };
            }
        }

        // Map Solidity-like type names to Rúnar types
        let mapped = match name.as_str() {
            "uint256" | "int256" | "uint" | "int" => "bigint",
            "bool" => "boolean",
            "bytes" => "ByteString",
            "address" => "Addr",
            _ => &name,
        };

        if let Some(prim) = PrimitiveTypeName::from_str(mapped) {
            TypeNode::Primitive(prim)
        } else {
            TypeNode::Custom(mapped.to_string())
        }
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    fn parse_constructor(&mut self) -> MethodNode {
        self.advance(); // consume 'constructor'
        self.expect(&Token::LParen);
        let params = self.parse_param_list();
        self.expect(&Token::RParen);

        // Optional visibility
        if *self.peek() == Token::Public || *self.peek() == Token::Private {
            self.advance();
        }

        let body = self.parse_block();

        MethodNode {
            name: "constructor".to_string(),
            params,
            body,
            visibility: Visibility::Public,
            source_location: self.loc(),
        }
    }

    // -----------------------------------------------------------------------
    // Functions/methods
    // -----------------------------------------------------------------------

    fn parse_function(&mut self) -> MethodNode {
        self.advance(); // consume 'function'
        let name = self.expect_ident();
        self.expect(&Token::LParen);
        let params = self.parse_param_list();
        self.expect(&Token::RParen);

        // Parse visibility modifier (Solidity puts it after params)
        let visibility = match self.peek() {
            Token::Public => {
                self.advance();
                Visibility::Public
            }
            Token::Private => {
                self.advance();
                Visibility::Private
            }
            _ => Visibility::Public,
        };

        let body = self.parse_block();

        MethodNode {
            name,
            params,
            body,
            visibility,
            source_location: self.loc(),
        }
    }

    // -----------------------------------------------------------------------
    // Parameters (Solidity-style: Type name, Type name)
    // -----------------------------------------------------------------------

    fn parse_param_list(&mut self) -> Vec<ParamNode> {
        let mut params = Vec::new();
        if *self.peek() == Token::RParen {
            return params;
        }

        params.push(self.parse_param());
        while *self.peek() == Token::Comma {
            self.advance();
            params.push(self.parse_param());
        }
        params
    }

    fn parse_param(&mut self) -> ParamNode {
        let param_type = self.parse_type();
        let name = self.expect_ident();
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
        stmts
    }

    fn parse_statement(&mut self) -> Option<Statement> {
        match self.peek().clone() {
            Token::Let | Token::Const => Some(self.parse_var_decl()),
            Token::If => Some(self.parse_if()),
            Token::For => Some(self.parse_for()),
            Token::Return => Some(self.parse_return()),
            Token::Require => Some(self.parse_require()),
            _ => {
                // Expression statement or assignment
                let expr = self.parse_expression();

                // Check for assignment
                match self.peek() {
                    Token::Eq => {
                        self.advance();
                        let value = self.parse_expression();
                        self.expect(&Token::Semicolon);
                        Some(Statement::Assignment {
                            target: expr,
                            value,
                            source_location: self.loc(),
                        })
                    }
                    Token::PlusEq => {
                        self.advance();
                        let rhs = self.parse_expression();
                        let value = Expression::BinaryExpr {
                            op: BinaryOp::Add,
                            left: Box::new(expr.clone()),
                            right: Box::new(rhs),
                        };
                        self.expect(&Token::Semicolon);
                        Some(Statement::Assignment {
                            target: expr,
                            value,
                            source_location: self.loc(),
                        })
                    }
                    Token::MinusEq => {
                        self.advance();
                        let rhs = self.parse_expression();
                        let value = Expression::BinaryExpr {
                            op: BinaryOp::Sub,
                            left: Box::new(expr.clone()),
                            right: Box::new(rhs),
                        };
                        self.expect(&Token::Semicolon);
                        Some(Statement::Assignment {
                            target: expr,
                            value,
                            source_location: self.loc(),
                        })
                    }
                    Token::StarEq => {
                        self.advance();
                        let rhs = self.parse_expression();
                        let value = Expression::BinaryExpr {
                            op: BinaryOp::Mul,
                            left: Box::new(expr.clone()),
                            right: Box::new(rhs),
                        };
                        self.expect(&Token::Semicolon);
                        Some(Statement::Assignment {
                            target: expr,
                            value,
                            source_location: self.loc(),
                        })
                    }
                    Token::SlashEq => {
                        self.advance();
                        let rhs = self.parse_expression();
                        let value = Expression::BinaryExpr {
                            op: BinaryOp::Div,
                            left: Box::new(expr.clone()),
                            right: Box::new(rhs),
                        };
                        self.expect(&Token::Semicolon);
                        Some(Statement::Assignment {
                            target: expr,
                            value,
                            source_location: self.loc(),
                        })
                    }
                    Token::PercentEq => {
                        self.advance();
                        let rhs = self.parse_expression();
                        let value = Expression::BinaryExpr {
                            op: BinaryOp::Mod,
                            left: Box::new(expr.clone()),
                            right: Box::new(rhs),
                        };
                        self.expect(&Token::Semicolon);
                        Some(Statement::Assignment {
                            target: expr,
                            value,
                            source_location: self.loc(),
                        })
                    }
                    _ => {
                        self.expect(&Token::Semicolon);
                        Some(Statement::ExpressionStatement {
                            expression: expr,
                            source_location: self.loc(),
                        })
                    }
                }
            }
        }
    }

    fn parse_var_decl(&mut self) -> Statement {
        let is_const = *self.peek() == Token::Const;
        self.advance(); // consume let/const

        // Solidity style: might be "Type name = expr;" or "name = expr;"
        // We support both: "let name = expr;" and "let Type name = expr;" and "let name: Type = expr;"

        // Look ahead: if the next-next token is also an ident (before = or ;), it's "Type name"
        let (name, var_type) = if self.is_type_then_name() {
            let type_node = self.parse_type();
            let name = self.expect_ident();
            (name, Some(type_node))
        } else {
            let name = self.expect_ident();
            // Check for ": Type"
            let var_type = if *self.peek() == Token::Colon {
                self.advance();
                Some(self.parse_type())
            } else {
                None
            };
            (name, var_type)
        };

        self.expect(&Token::Eq);
        let init = self.parse_expression();
        self.expect(&Token::Semicolon);

        Statement::VariableDecl {
            name,
            var_type,
            mutable: !is_const,
            init,
            source_location: self.loc(),
        }
    }

    /// Heuristic: check if the next two tokens are Ident Ident (i.e. Type Name).
    fn is_type_then_name(&self) -> bool {
        matches!(
            (self.tokens.get(self.pos), self.tokens.get(self.pos + 1)),
            (Some(Token::Ident(_)), Some(Token::Ident(_)))
        )
    }

    fn parse_require(&mut self) -> Statement {
        self.advance(); // consume 'require'
        self.expect(&Token::LParen);
        let expr = self.parse_expression();
        self.expect(&Token::RParen);
        self.expect(&Token::Semicolon);

        // require(x) -> assert(x)
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

    fn parse_if(&mut self) -> Statement {
        self.advance(); // consume 'if'
        self.expect(&Token::LParen);
        let condition = self.parse_expression();
        self.expect(&Token::RParen);

        let then_branch = self.parse_block();

        let else_branch = if *self.peek() == Token::Else {
            self.advance();
            if *self.peek() == Token::If {
                // else if -> wrapped in a single-element branch
                let nested = self.parse_if();
                Some(vec![nested])
            } else {
                Some(self.parse_block())
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

    fn parse_for(&mut self) -> Statement {
        self.advance(); // consume 'for'
        self.expect(&Token::LParen);

        // Init
        let init = if *self.peek() == Token::Let || *self.peek() == Token::Const {
            self.parse_var_decl()
        } else {
            self.errors
                .push("For loop init must be a variable declaration".to_string());
            self.expect(&Token::Semicolon);
            Statement::VariableDecl {
                name: "_i".to_string(),
                var_type: None,
                mutable: true,
                init: Expression::BigIntLiteral { value: 0 },
                source_location: self.loc(),
            }
        };

        // Condition
        let condition = self.parse_expression();
        self.expect(&Token::Semicolon);

        // Update
        let update = self.parse_for_update();
        self.expect(&Token::RParen);

        let body = self.parse_block();

        Statement::ForStatement {
            init: Box::new(init),
            condition,
            update: Box::new(update),
            body,
            source_location: self.loc(),
        }
    }

    fn parse_for_update(&mut self) -> Statement {
        let expr = self.parse_expression();

        // Check for assignment
        match self.peek() {
            Token::Eq => {
                self.advance();
                let value = self.parse_expression();
                Statement::Assignment {
                    target: expr,
                    value,
                    source_location: self.loc(),
                }
            }
            Token::PlusEq => {
                self.advance();
                let rhs = self.parse_expression();
                Statement::Assignment {
                    target: expr.clone(),
                    value: Expression::BinaryExpr {
                        op: BinaryOp::Add,
                        left: Box::new(expr),
                        right: Box::new(rhs),
                    },
                    source_location: self.loc(),
                }
            }
            Token::MinusEq => {
                self.advance();
                let rhs = self.parse_expression();
                Statement::Assignment {
                    target: expr.clone(),
                    value: Expression::BinaryExpr {
                        op: BinaryOp::Sub,
                        left: Box::new(expr),
                        right: Box::new(rhs),
                    },
                    source_location: self.loc(),
                }
            }
            _ => Statement::ExpressionStatement {
                expression: expr,
                source_location: self.loc(),
            },
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
                Token::EqEq | Token::EqEqEq => {
                    self.advance();
                    let right = self.parse_comparison();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::StrictEq,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::NotEq | Token::NotEqEq => {
                    self.advance();
                    let right = self.parse_comparison();
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
        let mut left = self.parse_additive();
        loop {
            match self.peek() {
                Token::Lt => {
                    self.advance();
                    let right = self.parse_additive();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Lt,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::Le => {
                    self.advance();
                    let right = self.parse_additive();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Le,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::Gt => {
                    self.advance();
                    let right = self.parse_additive();
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Gt,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                Token::Ge => {
                    self.advance();
                    let right = self.parse_additive();
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
            Token::Not => {
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
                    let prop = self.expect_ident();
                    if matches!(&expr, Expression::Identifier { name } if name == "this") {
                        expr = Expression::PropertyAccess { property: prop };
                    } else {
                        expr = Expression::MemberExpr {
                            object: Box::new(expr),
                            property: prop,
                        };
                    }
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
            Token::Ident(name) => {
                if name == "this" {
                    Expression::Identifier {
                        name: "this".to_string(),
                    }
                } else if name == "super" {
                    Expression::Identifier {
                        name: "super".to_string(),
                    }
                } else {
                    Expression::Identifier { name }
                }
            }
            Token::Require => {
                // require used as expression (unusual but handle it)
                self.expect(&Token::LParen);
                let arg = self.parse_expression();
                self.expect(&Token::RParen);
                Expression::CallExpr {
                    callee: Box::new(Expression::Identifier {
                        name: "assert".to_string(),
                    }),
                    args: vec![arg],
                }
            }
            Token::LParen => {
                let expr = self.parse_expression();
                self.expect(&Token::RParen);
                expr
            }
            other => {
                self.errors
                    .push(format!("Unexpected token in expression: {:?}", other));
                Expression::BigIntLiteral { value: 0 }
            }
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
    fn test_parse_simple_solidity_contract() {
        let source = r#"
contract P2PKH is SmartContract {
    immutable Addr pubKeyHash;

    constructor(Addr pubKeyHash) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    function unlock(Sig sig, PubKey pubKey) public {
        require(hash160(pubKey) == this.pubKeyHash);
        require(checkSig(sig, pubKey));
    }
}
"#;

        let result = parse_solidity(source, Some("P2PKH.runar.sol"));
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
    }

    #[test]
    fn test_parse_stateful_solidity_contract() {
        let source = r#"
contract Counter is StatefulSmartContract {
    bigint count;

    constructor(bigint count) {
        super(count);
        this.count = count;
    }

    function increment() public {
        this.count++;
    }

    function decrement() public {
        require(this.count > 0);
        this.count--;
    }
}
"#;

        let result = parse_solidity(source, Some("Counter.runar.sol"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.name, "Counter");
        assert_eq!(contract.parent_class, "StatefulSmartContract");
        assert_eq!(contract.properties.len(), 1);
        assert!(!contract.properties[0].readonly);
        assert_eq!(contract.methods.len(), 2);
    }

    #[test]
    fn test_eq_maps_to_strict_eq() {
        let source = r#"
contract Test is SmartContract {
    immutable bigint x;

    constructor(bigint x) {
        super(x);
        this.x = x;
    }

    function check(bigint y) public {
        require(this.x == y);
        require(this.x != y);
    }
}
"#;

        let result = parse_solidity(source, Some("Test.runar.sol"));
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
    }

    #[test]
    fn test_for_loop() {
        let source = r#"
contract Loop is SmartContract {
    immutable bigint n;

    constructor(bigint n) {
        super(n);
        this.n = n;
    }

    function run() public {
        let bigint sum = 0;
        for (let bigint i = 0; i < this.n; i++) {
            sum += i;
        }
        require(sum > 0);
    }
}
"#;

        let result = parse_solidity(source, Some("Loop.runar.sol"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods[0].body.len(), 3); // let sum, for, require
    }

    // -----------------------------------------------------------------------
    // Test: method name, visibility, and parameter names/types are parsed
    // -----------------------------------------------------------------------

    #[test]
    fn test_methods_and_params() {
        let source = r#"
contract Adder is SmartContract {
    immutable bigint target;

    constructor(bigint target) {
        super(target);
        this.target = target;
    }

    function verify(bigint a, bigint b) public {
        require(a + b == this.target);
    }
}
"#;

        let result = parse_solidity(source, Some("Adder.runar.sol"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();

        assert_eq!(contract.methods.len(), 1, "expected 1 method");
        let method = &contract.methods[0];
        assert_eq!(method.name, "verify");
        assert_eq!(
            method.visibility,
            Visibility::Public,
            "expected public visibility"
        );
        assert_eq!(method.params.len(), 2, "expected 2 params");
        assert_eq!(method.params[0].name, "a");
        assert_eq!(method.params[1].name, "b");
    }

    // -----------------------------------------------------------------------
    // Test: malformed Solidity produces an error
    // -----------------------------------------------------------------------

    #[test]
    fn test_invalid_syntax_error() {
        // Missing contract name and parent
        let source = r#"
contract {
    // missing name and parent
}
"#;

        let result = parse_solidity(source, Some("bad.runar.sol"));
        // Should either produce errors or fail to produce a valid contract
        let is_bad = !result.errors.is_empty() || result.contract.is_none();
        assert!(
            is_bad,
            "expected errors or no contract for invalid Solidity syntax"
        );
    }

    // -----------------------------------------------------------------------
    // Test: contract with multiple properties all parsed correctly
    // -----------------------------------------------------------------------

    #[test]
    fn test_multiple_properties() {
        let source = r#"
contract TwoProps is SmartContract {
    immutable Addr addr;
    immutable PubKey key;

    constructor(Addr addr, PubKey key) {
        super(addr, key);
        this.addr = addr;
        this.key = key;
    }

    function check(bigint x) public {
        require(x == 1);
    }
}
"#;

        let result = parse_solidity(source, Some("TwoProps.runar.sol"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(
            contract.properties.len(),
            2,
            "expected 2 properties, got {}",
            contract.properties.len()
        );
        assert_eq!(contract.properties[0].name, "addr");
        assert_eq!(contract.properties[1].name, "key");
    }
}
