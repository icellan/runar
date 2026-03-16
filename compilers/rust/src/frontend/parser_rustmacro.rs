//! Rust DSL parser for Rúnar contracts (.runar.rs).
//!
//! Parses Rust-style contract definitions using a hand-written tokenizer
//! and recursive descent parser. Produces the same AST as the TypeScript parser.

use super::ast::{
    BinaryOp, ContractNode, Expression, MethodNode, ParamNode, PrimitiveTypeName,
    PropertyNode, SourceLocation, Statement, TypeNode, UnaryOp, Visibility,
};
use super::parser::ParseResult;

// ---------------------------------------------------------------------------
// Token types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum TokenType {
    Use, Struct, Impl, Fn, Pub, Let, Mut, If, Else, For, Return, In,
    True, False, Self_,
    AssertMacro, AssertEqMacro,
    Ident(String), Number(String), HexString(String),
    // Attributes
    HashBracket, // #[
    // Punctuation
    LParen, RParen, LBrace, RBrace, LBracket, RBracket,
    Semi, Comma, Dot, Colon, ColonColon, Arrow,
    // Operators
    Plus, Minus, Star, Slash, Percent,
    EqEq, BangEq, Lt, LtEq, Gt, GtEq,
    AmpAmp, PipePipe,
    Amp, Pipe, Caret, Tilde, Bang,
    Eq, PlusEq, MinusEq,
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
    let mut pos = 0;
    let mut line = 1usize;
    let mut col = 1usize;

    while pos < chars.len() {
        let ch = chars[pos];
        let l = line;
        let c = col;

        // Whitespace
        if ch.is_whitespace() {
            if ch == '\n' { line += 1; col = 1; } else { col += 1; }
            pos += 1;
            continue;
        }

        // Line comments
        if ch == '/' && pos + 1 < chars.len() && chars[pos + 1] == '/' {
            while pos < chars.len() && chars[pos] != '\n' { pos += 1; }
            continue;
        }

        // Block comments
        if ch == '/' && pos + 1 < chars.len() && chars[pos + 1] == '*' {
            pos += 2; col += 2;
            while pos + 1 < chars.len() {
                if chars[pos] == '\n' { line += 1; col = 1; }
                if chars[pos] == '*' && chars[pos + 1] == '/' { pos += 2; col += 2; break; }
                pos += 1; col += 1;
            }
            continue;
        }

        // #[ attribute
        if ch == '#' && pos + 1 < chars.len() && chars[pos + 1] == '[' {
            tokens.push(Token { typ: TokenType::HashBracket, line: l, col: c });
            pos += 2; col += 2;
            continue;
        }

        // Two-char operators
        if pos + 1 < chars.len() {
            let two = format!("{}{}", ch, chars[pos + 1]);
            let tok = match two.as_str() {
                "::" => Some(TokenType::ColonColon),
                "->" => Some(TokenType::Arrow),
                "==" => Some(TokenType::EqEq),
                "!=" => Some(TokenType::BangEq),
                "<=" => Some(TokenType::LtEq),
                ">=" => Some(TokenType::GtEq),
                "&&" => Some(TokenType::AmpAmp),
                "||" => Some(TokenType::PipePipe),
                "+=" => Some(TokenType::PlusEq),
                "-=" => Some(TokenType::MinusEq),
                _ => None,
            };
            if let Some(t) = tok {
                tokens.push(Token { typ: t, line: l, col: c });
                pos += 2; col += 2;
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
            '+' => Some(TokenType::Plus),
            '-' => Some(TokenType::Minus),
            '*' => Some(TokenType::Star),
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
            pos += 1; col += 1;
            continue;
        }

        // Hex literal
        if ch == '0' && pos + 1 < chars.len() && chars[pos + 1] == 'x' {
            let mut val = String::new();
            pos += 2; col += 2;
            while pos < chars.len() && chars[pos].is_ascii_hexdigit() {
                val.push(chars[pos]);
                pos += 1; col += 1;
            }
            tokens.push(Token { typ: TokenType::HexString(val), line: l, col: c });
            continue;
        }

        // Number
        if ch.is_ascii_digit() {
            let mut val = String::new();
            while pos < chars.len() && (chars[pos].is_ascii_digit() || chars[pos] == '_') {
                if chars[pos] != '_' { val.push(chars[pos]); }
                pos += 1; col += 1;
            }
            tokens.push(Token { typ: TokenType::Number(val), line: l, col: c });
            continue;
        }

        // Identifier / keyword
        if ch.is_alphabetic() || ch == '_' {
            let mut val = String::new();
            while pos < chars.len() && (chars[pos].is_alphanumeric() || chars[pos] == '_') {
                val.push(chars[pos]);
                pos += 1; col += 1;
            }
            // Check for assert!/assert_eq!
            if (val == "assert" || val == "assert_eq") && pos < chars.len() && chars[pos] == '!' {
                pos += 1; col += 1;
                let tok = if val == "assert" { TokenType::AssertMacro } else { TokenType::AssertEqMacro };
                tokens.push(Token { typ: tok, line: l, col: c });
                continue;
            }
            let tok = match val.as_str() {
                "use" => TokenType::Use,
                "struct" => TokenType::Struct,
                "impl" => TokenType::Impl,
                "fn" => TokenType::Fn,
                "pub" => TokenType::Pub,
                "let" => TokenType::Let,
                "mut" => TokenType::Mut,
                "if" => TokenType::If,
                "else" => TokenType::Else,
                "for" => TokenType::For,
                "return" => TokenType::Return,
                "in" => TokenType::In,
                "true" => TokenType::True,
                "false" => TokenType::False,
                "self" => TokenType::Self_,
                _ => TokenType::Ident(val),
            };
            tokens.push(Token { typ: tok, line: l, col: c });
            continue;
        }

        // String literal (double-quoted) — treated as hex ByteString like in TS/Sol/Move
        if ch == '"' {
            let mut val = String::new();
            pos += 1; col += 1;
            while pos < chars.len() && chars[pos] != '"' {
                val.push(chars[pos]);
                pos += 1; col += 1;
            }
            if pos < chars.len() { pos += 1; col += 1; } // skip closing quote
            tokens.push(Token { typ: TokenType::HexString(val), line: l, col: c });
            continue;
        }

        pos += 1; col += 1;
    }

    tokens.push(Token { typ: TokenType::Eof, line, col });
    tokens
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct RustDslParser {
    tokens: Vec<Token>,
    pos: usize,
    file: String,
    errors: Vec<String>,
}

impl RustDslParser {
    fn new(tokens: Vec<Token>, file: String) -> Self {
        Self { tokens, pos: 0, file, errors: Vec::new() }
    }

    fn current(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(self.tokens.last().unwrap())
    }

    fn advance_clone(&mut self) -> Token {
        let t = self.current().clone();
        if self.pos < self.tokens.len() - 1 { self.pos += 1; }
        t
    }

    fn expect(&mut self, expected: &TokenType) {
        if std::mem::discriminant(&self.current().typ) != std::mem::discriminant(expected) {
            self.errors.push(format!("Expected {:?}, got {:?} at {}:{}", expected, self.current().typ, self.current().line, self.current().col));
        }
        self.advance_clone();
    }

    fn match_tok(&mut self, expected: &TokenType) -> bool {
        if std::mem::discriminant(&self.current().typ) == std::mem::discriminant(expected) {
            self.advance_clone();
            true
        } else {
            false
        }
    }

    fn loc(&self) -> SourceLocation {
        SourceLocation { file: self.file.clone(), line: self.current().line, column: self.current().col }
    }

    fn parse(mut self) -> ParseResult {
        // Skip use declarations
        while matches!(self.current().typ, TokenType::Use) {
            while !matches!(self.current().typ, TokenType::Semi | TokenType::Eof) { self.advance_clone(); }
            if matches!(self.current().typ, TokenType::Semi) { self.advance_clone(); }
        }

        // Look for #[runar::contract] struct
        let mut properties: Vec<PropertyNode> = Vec::new();
        let mut contract_name = String::new();
        let mut parent_class = "SmartContract".to_string();
        let mut methods: Vec<MethodNode> = Vec::new();

        while !matches!(self.current().typ, TokenType::Eof) {
            // Attribute: #[...]
            if matches!(self.current().typ, TokenType::HashBracket) {
                let attr = self.parse_attribute();

                if attr == "runar::contract" || attr == "runar::stateful_contract" {
                    if attr == "runar::stateful_contract" {
                        parent_class = "StatefulSmartContract".to_string();
                    }
                    // Parse struct
                    if matches!(self.current().typ, TokenType::Pub) { self.advance_clone(); }
                    self.expect(&TokenType::Struct);
                    if let TokenType::Ident(name) = self.current().typ.clone() {
                        contract_name = name;
                        self.advance_clone();
                    }
                    self.expect(&TokenType::LBrace);

                    while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
                        // Check for #[readonly] attribute
                        let mut readonly = false;
                        if matches!(self.current().typ, TokenType::HashBracket) {
                            let field_attr = self.parse_attribute();
                            if field_attr == "readonly" { readonly = true; }
                        }

                        let loc = self.loc();
                        if let TokenType::Ident(field_name) = self.current().typ.clone() {
                            self.advance_clone();
                            self.expect(&TokenType::Colon);
                            let field_type = self.parse_rust_type();
                            self.match_tok(&TokenType::Comma);

                            if !readonly {
                                // Check later if any field is mutable
                            }

                            // Skip txPreimage — it's an implicit stateful param, not a contract property
                            let camel_name = snake_to_camel(&field_name);
                            if camel_name != "txPreimage" {
                                properties.push(PropertyNode {
                                    name: camel_name,
                                    prop_type: field_type,
                                    readonly,
                                    initializer: None,
                                    source_location: loc,
                                });
                            }
                        } else {
                            self.advance_clone();
                        }
                    }
                    self.expect(&TokenType::RBrace);
                } else if attr.starts_with("runar::methods") {
                    // Parse impl block
                    if matches!(self.current().typ, TokenType::Impl) { self.advance_clone(); }
                    // Skip type name
                    if let TokenType::Ident(_) = self.current().typ { self.advance_clone(); }
                    self.expect(&TokenType::LBrace);

                    while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
                        // Check for #[public] attribute
                        let mut visibility = Visibility::Private;
                        if matches!(self.current().typ, TokenType::HashBracket) {
                            let method_attr = self.parse_attribute();
                            if method_attr == "public" { visibility = Visibility::Public; }
                        }
                        if matches!(self.current().typ, TokenType::Pub) {
                            self.advance_clone();
                            visibility = Visibility::Public;
                        }
                        methods.push(self.parse_function(visibility));
                    }
                    self.expect(&TokenType::RBrace);
                } else {
                    // Unknown attribute, skip
                    continue;
                }
            } else {
                self.advance_clone();
            }
        }

        // Determine parent class from property mutability
        if properties.iter().any(|p| !p.readonly) {
            parent_class = "StatefulSmartContract".to_string();
        }

        if contract_name.is_empty() {
            self.errors.push("No Rúnar contract struct found".to_string());
            return ParseResult { contract: None, errors: self.errors };
        }

        // Extract init() method as property initializers, if present.
        // init() is a special private method that sets default values on properties.
        let mut final_methods = Vec::new();
        for m in methods {
            if m.name == "init" && m.params.is_empty() {
                for stmt in &m.body {
                    if let Statement::Assignment { target, value, .. } = stmt {
                        if let Expression::PropertyAccess { property } = target {
                            for p in properties.iter_mut() {
                                if p.name == *property {
                                    p.initializer = Some(value.clone());
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
        let methods = final_methods;

        // Build constructor (only non-initialized properties)
        let uninit_props: Vec<&PropertyNode> = properties.iter()
            .filter(|p| p.initializer.is_none())
            .collect();

        let loc = SourceLocation { file: self.file.clone(), line: 1, column: 1 };

        // super(...) call as first statement
        let super_args: Vec<Expression> = uninit_props.iter()
            .map(|p| Expression::Identifier { name: p.name.clone() })
            .collect();
        let super_call = Statement::ExpressionStatement {
            expression: Expression::CallExpr {
                callee: Box::new(Expression::Identifier { name: "super".to_string() }),
                args: super_args,
            },
            source_location: loc.clone(),
        };

        // Property assignments
        let mut ctor_body = vec![super_call];
        for p in &uninit_props {
            ctor_body.push(Statement::Assignment {
                target: Expression::PropertyAccess { property: p.name.clone() },
                value: Expression::Identifier { name: p.name.clone() },
                source_location: loc.clone(),
            });
        }

        let constructor = MethodNode {
            name: "constructor".to_string(),
            params: uninit_props.iter().map(|p| ParamNode {
                name: p.name.clone(),
                param_type: p.prop_type.clone(),
            }).collect(),
            body: ctor_body,
            visibility: Visibility::Public,
            source_location: loc,
        };

        let contract = ContractNode {
            name: contract_name,
            parent_class,
            properties,
            constructor,
            methods,
            source_file: self.file.clone(),
        };

        ParseResult { contract: Some(contract), errors: self.errors }
    }

    fn parse_attribute(&mut self) -> String {
        // Already consumed #[
        self.advance_clone(); // skip #[
        let mut attr = String::new();
        let mut depth = 1;
        while depth > 0 && !matches!(self.current().typ, TokenType::Eof) {
            match &self.current().typ {
                TokenType::LBracket => { depth += 1; self.advance_clone(); }
                TokenType::RBracket => {
                    depth -= 1;
                    if depth == 0 { self.advance_clone(); break; }
                    self.advance_clone();
                }
                TokenType::Ident(name) => { attr.push_str(name); self.advance_clone(); }
                TokenType::ColonColon => { attr.push_str("::"); self.advance_clone(); }
                TokenType::LParen => { attr.push('('); self.advance_clone(); }
                TokenType::RParen => { attr.push(')'); self.advance_clone(); }
                _ => { self.advance_clone(); }
            }
        }
        attr
    }

    fn parse_rust_type(&mut self) -> TypeNode {
        if let TokenType::Ident(name) = self.current().typ.clone() {
            self.advance_clone();
            let mapped = map_rust_type(&name);
            if let Some(prim) = PrimitiveTypeName::from_str(&mapped) {
                TypeNode::Primitive(prim)
            } else {
                TypeNode::Custom(mapped)
            }
        } else {
            self.advance_clone();
            TypeNode::Custom("unknown".to_string())
        }
    }

    fn parse_function(&mut self, visibility: Visibility) -> MethodNode {
        let loc = self.loc();
        self.expect(&TokenType::Fn);

        let raw_name = if let TokenType::Ident(name) = self.current().typ.clone() {
            self.advance_clone();
            name
        } else {
            self.advance_clone();
            "unknown".to_string()
        };
        let name = snake_to_camel(&raw_name);

        self.expect(&TokenType::LParen);
        let mut params: Vec<ParamNode> = Vec::new();

        while !matches!(self.current().typ, TokenType::RParen | TokenType::Eof) {
            // Skip &self, &mut self
            if matches!(self.current().typ, TokenType::Amp) {
                self.advance_clone();
                if matches!(self.current().typ, TokenType::Mut) { self.advance_clone(); }
                if matches!(self.current().typ, TokenType::Self_) {
                    self.advance_clone();
                    if matches!(self.current().typ, TokenType::Comma) { self.advance_clone(); }
                    continue;
                }
            }
            if matches!(self.current().typ, TokenType::Self_) {
                self.advance_clone();
                if matches!(self.current().typ, TokenType::Comma) { self.advance_clone(); }
                continue;
            }

            if let TokenType::Ident(param_name) = self.current().typ.clone() {
                self.advance_clone();
                self.expect(&TokenType::Colon);
                // Skip & and &mut before type
                if matches!(self.current().typ, TokenType::Amp) {
                    self.advance_clone();
                    if matches!(self.current().typ, TokenType::Mut) { self.advance_clone(); }
                }
                let param_type = self.parse_rust_type();
                params.push(ParamNode {
                    name: snake_to_camel(&param_name),
                    param_type,
                });
            } else {
                self.advance_clone();
            }
            if matches!(self.current().typ, TokenType::Comma) { self.advance_clone(); }
        }
        self.expect(&TokenType::RParen);

        // Optional return type
        if matches!(self.current().typ, TokenType::Arrow) {
            self.advance_clone();
            self.parse_rust_type();
        }

        self.expect(&TokenType::LBrace);
        let mut body: Vec<Statement> = Vec::new();
        while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
            if let Some(stmt) = self.parse_statement() {
                body.push(stmt);
            }
        }
        self.expect(&TokenType::RBrace);

        MethodNode { name, params, body, visibility, source_location: loc }
    }

    fn parse_statement(&mut self) -> Option<Statement> {
        let loc = self.loc();

        // assert!(expr)
        if matches!(self.current().typ, TokenType::AssertMacro) {
            self.advance_clone();
            self.expect(&TokenType::LParen);
            let expr = self.parse_expression();
            self.expect(&TokenType::RParen);
            self.match_tok(&TokenType::Semi);
            return Some(Statement::ExpressionStatement {
                expression: Expression::CallExpr {
                    callee: Box::new(Expression::Identifier { name: "assert".to_string() }),
                    args: vec![expr],
                },
                source_location: loc,
            });
        }

        // assert_eq!(a, b)
        if matches!(self.current().typ, TokenType::AssertEqMacro) {
            self.advance_clone();
            self.expect(&TokenType::LParen);
            let left = self.parse_expression();
            self.expect(&TokenType::Comma);
            let right = self.parse_expression();
            self.expect(&TokenType::RParen);
            self.match_tok(&TokenType::Semi);
            return Some(Statement::ExpressionStatement {
                expression: Expression::CallExpr {
                    callee: Box::new(Expression::Identifier { name: "assert".to_string() }),
                    args: vec![Expression::BinaryExpr {
                        op: BinaryOp::StrictEq,
                        left: Box::new(left),
                        right: Box::new(right),
                    }],
                },
                source_location: loc,
            });
        }

        // let [mut] name [: type] = expr;
        if matches!(self.current().typ, TokenType::Let) {
            self.advance_clone();
            let mutable = self.match_tok(&TokenType::Mut);
            let var_name = if let TokenType::Ident(name) = self.current().typ.clone() {
                self.advance_clone();
                snake_to_camel(&name)
            } else {
                self.advance_clone();
                "unknown".to_string()
            };
            let var_type = if matches!(self.current().typ, TokenType::Colon) {
                self.advance_clone();
                if matches!(self.current().typ, TokenType::Amp) { self.advance_clone(); }
                if matches!(self.current().typ, TokenType::Mut) { self.advance_clone(); }
                Some(self.parse_rust_type())
            } else {
                None
            };
            self.expect(&TokenType::Eq);
            let init = self.parse_expression();
            self.match_tok(&TokenType::Semi);
            return Some(Statement::VariableDecl {
                name: var_name, var_type, mutable, init, source_location: loc,
            });
        }

        // if
        if matches!(self.current().typ, TokenType::If) {
            self.advance_clone();
            let condition = self.parse_expression();
            self.expect(&TokenType::LBrace);
            let mut then_branch = Vec::new();
            while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
                if let Some(s) = self.parse_statement() { then_branch.push(s); }
            }
            self.expect(&TokenType::RBrace);
            let else_branch = if matches!(self.current().typ, TokenType::Else) {
                self.advance_clone();
                self.expect(&TokenType::LBrace);
                let mut eb = Vec::new();
                while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
                    if let Some(s) = self.parse_statement() { eb.push(s); }
                }
                self.expect(&TokenType::RBrace);
                Some(eb)
            } else {
                None
            };
            return Some(Statement::IfStatement { condition, then_branch, else_branch, source_location: loc });
        }

        // return
        if matches!(self.current().typ, TokenType::Return) {
            self.advance_clone();
            let value = if !matches!(self.current().typ, TokenType::Semi | TokenType::RBrace) {
                Some(self.parse_expression())
            } else {
                None
            };
            self.match_tok(&TokenType::Semi);
            return Some(Statement::ReturnStatement { value, source_location: loc });
        }

        // Expression statement
        let expr = self.parse_expression();

        // Assignment
        if matches!(self.current().typ, TokenType::Eq) {
            self.advance_clone();
            let value = self.parse_expression();
            self.match_tok(&TokenType::Semi);
            return Some(Statement::Assignment {
                target: self.convert_self_access(expr),
                value,
                source_location: loc,
            });
        }

        // Compound assignments
        if matches!(self.current().typ, TokenType::PlusEq) {
            self.advance_clone();
            let rhs = self.parse_expression();
            self.match_tok(&TokenType::Semi);
            let target = self.convert_self_access(expr.clone());
            return Some(Statement::Assignment {
                target: target.clone(),
                value: Expression::BinaryExpr { op: BinaryOp::Add, left: Box::new(target), right: Box::new(rhs) },
                source_location: loc,
            });
        }
        if matches!(self.current().typ, TokenType::MinusEq) {
            self.advance_clone();
            let rhs = self.parse_expression();
            self.match_tok(&TokenType::Semi);
            let target = self.convert_self_access(expr.clone());
            return Some(Statement::Assignment {
                target: target.clone(),
                value: Expression::BinaryExpr { op: BinaryOp::Sub, left: Box::new(target), right: Box::new(rhs) },
                source_location: loc,
            });
        }

        let had_semi = self.match_tok(&TokenType::Semi);
        // Implicit return: expression without semicolon followed immediately by `}`
        if !had_semi && matches!(self.current().typ, TokenType::RBrace) {
            return Some(Statement::ReturnStatement { value: Some(expr), source_location: loc });
        }
        Some(Statement::ExpressionStatement { expression: expr, source_location: loc })
    }

    fn convert_self_access(&self, expr: Expression) -> Expression {
        if let Expression::MemberExpr { ref object, ref property } = expr {
            if let Expression::Identifier { ref name } = **object {
                if name == "self" {
                    return Expression::PropertyAccess { property: snake_to_camel(property) };
                }
            }
        }
        expr
    }

    // Expression parsing with precedence climbing
    fn parse_expression(&mut self) -> Expression { self.parse_or() }

    fn parse_or(&mut self) -> Expression {
        let mut left = self.parse_and();
        while matches!(self.current().typ, TokenType::PipePipe) {
            self.advance_clone();
            let right = self.parse_and();
            left = Expression::BinaryExpr { op: BinaryOp::Or, left: Box::new(left), right: Box::new(right) };
        }
        left
    }

    fn parse_and(&mut self) -> Expression {
        let mut left = self.parse_bit_or();
        while matches!(self.current().typ, TokenType::AmpAmp) {
            self.advance_clone();
            let right = self.parse_bit_or();
            left = Expression::BinaryExpr { op: BinaryOp::And, left: Box::new(left), right: Box::new(right) };
        }
        left
    }

    fn parse_bit_or(&mut self) -> Expression {
        let mut left = self.parse_bit_xor();
        while matches!(self.current().typ, TokenType::Pipe) {
            self.advance_clone();
            left = Expression::BinaryExpr { op: BinaryOp::BitOr, left: Box::new(left), right: Box::new(self.parse_bit_xor()) };
        }
        left
    }

    fn parse_bit_xor(&mut self) -> Expression {
        let mut left = self.parse_bit_and();
        while matches!(self.current().typ, TokenType::Caret) {
            self.advance_clone();
            left = Expression::BinaryExpr { op: BinaryOp::BitXor, left: Box::new(left), right: Box::new(self.parse_bit_and()) };
        }
        left
    }

    fn parse_bit_and(&mut self) -> Expression {
        let mut left = self.parse_equality();
        while matches!(self.current().typ, TokenType::Amp) {
            self.advance_clone();
            left = Expression::BinaryExpr { op: BinaryOp::BitAnd, left: Box::new(left), right: Box::new(self.parse_equality()) };
        }
        left
    }

    fn parse_equality(&mut self) -> Expression {
        let mut left = self.parse_comparison();
        loop {
            let op = match self.current().typ {
                TokenType::EqEq => BinaryOp::StrictEq,
                TokenType::BangEq => BinaryOp::StrictNe,
                _ => break,
            };
            self.advance_clone();
            left = Expression::BinaryExpr { op, left: Box::new(left), right: Box::new(self.parse_comparison()) };
        }
        left
    }

    fn parse_comparison(&mut self) -> Expression {
        let mut left = self.parse_add_sub();
        loop {
            let op = match self.current().typ {
                TokenType::Lt => BinaryOp::Lt,
                TokenType::LtEq => BinaryOp::Le,
                TokenType::Gt => BinaryOp::Gt,
                TokenType::GtEq => BinaryOp::Ge,
                _ => break,
            };
            self.advance_clone();
            left = Expression::BinaryExpr { op, left: Box::new(left), right: Box::new(self.parse_add_sub()) };
        }
        left
    }

    fn parse_add_sub(&mut self) -> Expression {
        let mut left = self.parse_mul_div();
        loop {
            let op = match self.current().typ {
                TokenType::Plus => BinaryOp::Add,
                TokenType::Minus => BinaryOp::Sub,
                _ => break,
            };
            self.advance_clone();
            left = Expression::BinaryExpr { op, left: Box::new(left), right: Box::new(self.parse_mul_div()) };
        }
        left
    }

    fn parse_mul_div(&mut self) -> Expression {
        let mut left = self.parse_unary();
        loop {
            let op = match self.current().typ {
                TokenType::Star => BinaryOp::Mul,
                TokenType::Slash => BinaryOp::Div,
                TokenType::Percent => BinaryOp::Mod,
                _ => break,
            };
            self.advance_clone();
            left = Expression::BinaryExpr { op, left: Box::new(left), right: Box::new(self.parse_unary()) };
        }
        left
    }

    fn parse_unary(&mut self) -> Expression {
        match self.current().typ {
            TokenType::Bang => { self.advance_clone(); Expression::UnaryExpr { op: UnaryOp::Not, operand: Box::new(self.parse_unary()) } }
            TokenType::Minus => { self.advance_clone(); Expression::UnaryExpr { op: UnaryOp::Neg, operand: Box::new(self.parse_unary()) } }
            TokenType::Tilde => { self.advance_clone(); Expression::UnaryExpr { op: UnaryOp::BitNot, operand: Box::new(self.parse_unary()) } }
            TokenType::Amp => {
                self.advance_clone();
                if matches!(self.current().typ, TokenType::Mut) { self.advance_clone(); }
                self.parse_postfix()
            }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Expression {
        let mut expr = self.parse_primary();
        loop {
            if matches!(self.current().typ, TokenType::LParen) {
                self.advance_clone();
                let mut args = Vec::new();
                while !matches!(self.current().typ, TokenType::RParen | TokenType::Eof) {
                    args.push(self.parse_expression());
                    if matches!(self.current().typ, TokenType::Comma) { self.advance_clone(); }
                }
                self.expect(&TokenType::RParen);
                expr = Expression::CallExpr { callee: Box::new(expr), args };
            } else if matches!(self.current().typ, TokenType::Dot) {
                self.advance_clone();
                let prop = if let TokenType::Ident(name) = self.current().typ.clone() {
                    self.advance_clone();
                    snake_to_camel(&name)
                } else {
                    self.advance_clone();
                    "unknown".to_string()
                };
                // self.field -> PropertyAccess
                if let Expression::Identifier { ref name } = expr {
                    if name == "self" {
                        expr = Expression::PropertyAccess { property: prop };
                        continue;
                    }
                }
                expr = Expression::MemberExpr { object: Box::new(expr), property: prop };
            } else if matches!(self.current().typ, TokenType::ColonColon) {
                self.advance_clone();
                if let TokenType::Ident(name) = self.current().typ.clone() {
                    self.advance_clone();
                    expr = Expression::Identifier { name: snake_to_camel(&name) };
                }
            } else if matches!(self.current().typ, TokenType::LBracket) {
                self.advance_clone();
                let index = self.parse_expression();
                self.expect(&TokenType::RBracket);
                expr = Expression::IndexAccess { object: Box::new(expr), index: Box::new(index) };
            } else {
                break;
            }
        }
        expr
    }

    fn parse_primary(&mut self) -> Expression {
        match self.current().typ.clone() {
            TokenType::Number(val) => {
                self.advance_clone();
                let n: i64 = val.parse().unwrap_or(0);
                Expression::BigIntLiteral { value: n }
            }
            TokenType::HexString(val) => {
                self.advance_clone();
                Expression::ByteStringLiteral { value: val }
            }
            TokenType::True => { self.advance_clone(); Expression::BoolLiteral { value: true } }
            TokenType::False => { self.advance_clone(); Expression::BoolLiteral { value: false } }
            TokenType::Self_ => {
                self.advance_clone();
                Expression::Identifier { name: "self".to_string() }
            }
            TokenType::LParen => {
                self.advance_clone();
                let expr = self.parse_expression();
                self.expect(&TokenType::RParen);
                expr
            }
            TokenType::Ident(name) => {
                self.advance_clone();
                let mapped = map_rust_builtin(&name);
                Expression::Identifier { name: mapped }
            }
            _ => {
                let tok = self.current().clone();
                self.advance_clone();
                self.errors.push(format!(
                    "unsupported token '{:?}' at {}:{} — not valid in Rúnar contract",
                    tok.typ, tok.line, tok.col));
                Expression::Identifier { name: "unknown".to_string() }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn snake_to_camel(name: &str) -> String {
    let parts: Vec<&str> = name.split('_').collect();
    if parts.len() <= 1 {
        return name.to_string();
    }
    let mut result = parts[0].to_string();
    for part in &parts[1..] {
        if !part.is_empty() {
            let mut chars = part.chars();
            if let Some(first) = chars.next() {
                result.push(first.to_uppercase().next().unwrap());
                result.extend(chars);
            }
        }
    }
    result
}

fn map_rust_type(name: &str) -> String {
    match name {
        "Bigint" | "Int" | "i64" | "u64" | "i128" | "u128" => "bigint".to_string(),
        "Bool" | "bool" => "boolean".to_string(),
        _ => name.to_string(),
    }
}

fn map_rust_builtin(name: &str) -> String {
    // Handle names that snake_to_camel can't produce correctly BEFORE conversion.
    // These have acronyms, digit boundaries, or non-standard mappings.
    match name {
        "bool_cast" => return "bool".to_string(),
        "verify_wots" => return "verifyWOTS".to_string(),
        "verify_slh_dsa_sha2_128s" => return "verifySLHDSA_SHA2_128s".to_string(),
        "verify_slh_dsa_sha2_128f" => return "verifySLHDSA_SHA2_128f".to_string(),
        "verify_slh_dsa_sha2_192s" => return "verifySLHDSA_SHA2_192s".to_string(),
        "verify_slh_dsa_sha2_192f" => return "verifySLHDSA_SHA2_192f".to_string(),
        "verify_slh_dsa_sha2_256s" => return "verifySLHDSA_SHA2_256s".to_string(),
        "verify_slh_dsa_sha2_256f" => return "verifySLHDSA_SHA2_256f".to_string(),
        "bin_2_num" => return "bin2num".to_string(),
        "int_2_str" => return "int2str".to_string(),
        "to_byte_string" => return "toByteString".to_string(),
        _ => {}
    }

    let camel = snake_to_camel(name);
    // Map specific Rust builtins that snake_to_camel handles correctly
    // but we list explicitly for clarity and stability
    match camel.as_str() {
        "hash160" => "hash160".to_string(),
        "hash256" => "hash256".to_string(),
        "sha256" => "sha256".to_string(),
        "ripemd160" => "ripemd160".to_string(),
        "checkSig" => "checkSig".to_string(),
        "checkMultiSig" => "checkMultiSig".to_string(),
        "checkPreimage" => "checkPreimage".to_string(),
        "verifyRabinSig" => "verifyRabinSig".to_string(),
        "num2bin" => "num2bin".to_string(),
        "bin2num" => "bin2num".to_string(),
        "int2str" => "int2str".to_string(),
        "extractLocktime" => "extractLocktime".to_string(),
        "extractOutputHash" => "extractOutputHash".to_string(),
        "extractVersion" => "extractVersion".to_string(),
        "extractHashPrevouts" => "extractHashPrevouts".to_string(),
        "extractHashSequence" => "extractHashSequence".to_string(),
        "extractOutpoint" => "extractOutpoint".to_string(),
        "extractInputIndex" => "extractInputIndex".to_string(),
        "extractScriptCode" => "extractScriptCode".to_string(),
        "extractAmount" => "extractAmount".to_string(),
        "extractSequence" => "extractSequence".to_string(),
        "extractOutputs" => "extractOutputs".to_string(),
        "extractSigHashType" => "extractSigHashType".to_string(),
        "addOutput" => "addOutput".to_string(),
        "reverseBytes" => "reverseBytes".to_string(),
        "toByteString" => "toByteString".to_string(),
        _ => camel,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn parse_rust_dsl(source: &str, file_name: Option<&str>) -> ParseResult {
    let file = file_name.unwrap_or("contract.runar.rs").to_string();
    let tokens = tokenize(source);
    let parser = RustDslParser::new(tokens, file);
    parser.parse()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_rust_contract() {
        let source = r#"
use runar::prelude::*;

#[runar::contract]
pub struct P2PKH {
    pub_key_hash: Addr,
}

#[runar::methods]
impl P2PKH {
    #[public]
    fn unlock(&self, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}
"#;

        let result = parse_rust_dsl(source, Some("P2PKH.runar.rs"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.name, "P2PKH");
        assert_eq!(contract.properties.len(), 1);
        assert_eq!(contract.methods.len(), 1);
        assert_eq!(contract.methods[0].name, "unlock");
        assert_eq!(contract.methods[0].visibility, Visibility::Public);
        // self param should be excluded
        assert_eq!(contract.methods[0].params.len(), 2);
    }

    #[test]
    fn test_snake_to_camel_conversion() {
        assert_eq!(snake_to_camel("pub_key_hash"), "pubKeyHash");
        assert_eq!(snake_to_camel("check_sig"), "checkSig");
        assert_eq!(snake_to_camel("already"), "already");
        assert_eq!(snake_to_camel("a_b_c"), "aBC");
        assert_eq!(snake_to_camel("hello_world"), "helloWorld");
    }

    #[test]
    fn test_type_mapping_works() {
        // i64 -> bigint
        assert_eq!(map_rust_type("i64"), "bigint");
        assert_eq!(map_rust_type("u64"), "bigint");
        assert_eq!(map_rust_type("i128"), "bigint");
        assert_eq!(map_rust_type("u128"), "bigint");
        assert_eq!(map_rust_type("Bigint"), "bigint");
        // bool -> boolean
        assert_eq!(map_rust_type("bool"), "boolean");
        assert_eq!(map_rust_type("Bool"), "boolean");
        // Pass-through
        assert_eq!(map_rust_type("PubKey"), "PubKey");
        assert_eq!(map_rust_type("Sig"), "Sig");
        assert_eq!(map_rust_type("Addr"), "Addr");
    }

    #[test]
    fn test_public_attribute_makes_method_public() {
        let source = r#"
use runar::prelude::*;

#[runar::contract]
pub struct Test {
    #[readonly]
    x: bigint,
}

#[runar::methods]
impl Test {
    #[public]
    fn public_method(&self, v: i64) {
        assert!(v == self.x);
    }

    fn private_method(&self, v: i64) -> i64 {
        return v + 1;
    }
}
"#;

        let result = parse_rust_dsl(source, Some("Test.runar.rs"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods.len(), 2);

        // First method should be public (has #[public])
        assert_eq!(contract.methods[0].name, "publicMethod");
        assert_eq!(contract.methods[0].visibility, Visibility::Public);

        // Second method should be private (no #[public])
        assert_eq!(contract.methods[1].name, "privateMethod");
        assert_eq!(contract.methods[1].visibility, Visibility::Private);
    }

    #[test]
    fn test_contract_name_extracted_correctly() {
        let source = r#"
use runar::prelude::*;

#[runar::contract]
pub struct MyFancyContract {
    value: bigint,
}

#[runar::methods]
impl MyFancyContract {
    #[public]
    fn check(&self, v: i64) {
        assert!(v == self.value);
    }
}
"#;

        let result = parse_rust_dsl(source, Some("MyFancyContract.runar.rs"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.name, "MyFancyContract");
    }

    #[test]
    fn test_property_names_are_camel_cased() {
        let source = r#"
use runar::prelude::*;

#[runar::contract]
pub struct Test {
    pub_key_hash: Addr,
    my_value: bigint,
}

#[runar::methods]
impl Test {
    #[public]
    fn check(&self, v: i64) {
        assert!(v == self.my_value);
    }
}
"#;

        let result = parse_rust_dsl(source, Some("Test.runar.rs"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.properties[0].name, "pubKeyHash");
        assert_eq!(contract.properties[1].name, "myValue");
    }

    #[test]
    fn test_stateful_contract_attribute() {
        let source = r#"
use runar::prelude::*;

#[runar::stateful_contract]
pub struct Counter {
    count: bigint,
}

#[runar::methods]
impl Counter {
    #[public]
    fn increment(&mut self) {
        self.count = self.count + 1;
    }
}
"#;

        let result = parse_rust_dsl(source, Some("Counter.runar.rs"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.name, "Counter");
        assert_eq!(contract.parent_class, "StatefulSmartContract");
    }

    #[test]
    fn test_constructor_auto_generated() {
        let source = r#"
use runar::prelude::*;

#[runar::contract]
pub struct Test {
    a: bigint,
    b: PubKey,
}

#[runar::methods]
impl Test {
    #[public]
    fn check(&self) {
        assert!(self.a > 0);
    }
}
"#;

        let result = parse_rust_dsl(source, None);
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        // Constructor should have params for each property
        assert_eq!(contract.constructor.params.len(), 2);
        // Constructor body: super(a, b) + this.a = a + this.b = b
        assert_eq!(contract.constructor.body.len(), 3);
    }

    #[test]
    fn test_assert_eq_macro_maps_to_assert_strict_eq() {
        let source = r#"
use runar::prelude::*;

#[runar::contract]
pub struct Test {
    #[readonly]
    x: bigint,
}

#[runar::methods]
impl Test {
    #[public]
    fn check(&self, v: i64) {
        assert_eq!(self.x, v);
    }
}
"#;

        let result = parse_rust_dsl(source, Some("Test.runar.rs"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let body = &contract.methods[0].body;
        assert_eq!(body.len(), 1);

        // Should be assert(self.x === v)
        if let Statement::ExpressionStatement { expression, .. } = &body[0] {
            if let Expression::CallExpr { callee, args } = expression {
                if let Expression::Identifier { name } = callee.as_ref() {
                    assert_eq!(name, "assert");
                }
                if let Expression::BinaryExpr { op, .. } = &args[0] {
                    assert_eq!(*op, BinaryOp::StrictEq);
                } else {
                    panic!("Expected BinaryExpr inside assert_eq!, got {:?}", args[0]);
                }
            }
        }
    }

    #[test]
    fn test_int_type_maps_to_bigint() {
        assert_eq!(map_rust_type("Int"), "bigint");
    }

    #[test]
    fn test_bool_cast_maps_to_bool() {
        assert_eq!(map_rust_builtin("bool_cast"), "bool");
    }

    #[test]
    fn test_verify_wots_mapping() {
        assert_eq!(map_rust_builtin("verify_wots"), "verifyWOTS");
    }

    #[test]
    fn test_verify_slh_dsa_mappings() {
        assert_eq!(map_rust_builtin("verify_slh_dsa_sha2_128s"), "verifySLHDSA_SHA2_128s");
        assert_eq!(map_rust_builtin("verify_slh_dsa_sha2_128f"), "verifySLHDSA_SHA2_128f");
        assert_eq!(map_rust_builtin("verify_slh_dsa_sha2_192s"), "verifySLHDSA_SHA2_192s");
        assert_eq!(map_rust_builtin("verify_slh_dsa_sha2_192f"), "verifySLHDSA_SHA2_192f");
        assert_eq!(map_rust_builtin("verify_slh_dsa_sha2_256s"), "verifySLHDSA_SHA2_256s");
        assert_eq!(map_rust_builtin("verify_slh_dsa_sha2_256f"), "verifySLHDSA_SHA2_256f");
    }

    #[test]
    fn test_extract_builtin_mappings() {
        assert_eq!(map_rust_builtin("extract_version"), "extractVersion");
        assert_eq!(map_rust_builtin("extract_hash_prevouts"), "extractHashPrevouts");
        assert_eq!(map_rust_builtin("extract_hash_sequence"), "extractHashSequence");
        assert_eq!(map_rust_builtin("extract_outpoint"), "extractOutpoint");
        assert_eq!(map_rust_builtin("extract_input_index"), "extractInputIndex");
        assert_eq!(map_rust_builtin("extract_script_code"), "extractScriptCode");
        assert_eq!(map_rust_builtin("extract_amount"), "extractAmount");
        assert_eq!(map_rust_builtin("extract_sequence"), "extractSequence");
        assert_eq!(map_rust_builtin("extract_output_hash"), "extractOutputHash");
        assert_eq!(map_rust_builtin("extract_outputs"), "extractOutputs");
        assert_eq!(map_rust_builtin("extract_locktime"), "extractLocktime");
        assert_eq!(map_rust_builtin("extract_sig_hash_type"), "extractSigHashType");
    }

    #[test]
    fn test_byte_operation_builtin_mappings() {
        assert_eq!(map_rust_builtin("reverse_bytes"), "reverseBytes");
        assert_eq!(map_rust_builtin("bin2num"), "bin2num");
        assert_eq!(map_rust_builtin("bin_2_num"), "bin2num");
        assert_eq!(map_rust_builtin("int2str"), "int2str");
        assert_eq!(map_rust_builtin("int_2_str"), "int2str");
        assert_eq!(map_rust_builtin("to_byte_string"), "toByteString");
        assert_eq!(map_rust_builtin("add_output"), "addOutput");
    }

    #[test]
    fn test_implicit_return_in_method() {
        let source = r#"
use runar::prelude::*;
#[runar::contract]
pub struct Foo { #[readonly] pub x: Bigint }
#[runar::methods(Foo)]
impl Foo {
    fn compute(&self, a: Bigint, b: Bigint) -> Bigint {
        let sum = a + b;
        sum
    }
    #[public]
    pub fn check(&self) {
        assert!(self.x > 0);
    }
}
"#;
        let result = parse_rust_dsl(source, Some("Foo.runar.rs"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        let compute = contract.methods.iter().find(|m| m.name == "compute").unwrap();
        assert_eq!(compute.body.len(), 2, "expected 2 statements (let + return)");
        // Last statement should be a ReturnStatement
        match &compute.body[1] {
            Statement::ReturnStatement { value: Some(_), .. } => {}
            other => panic!("expected ReturnStatement, got {:?}", other),
        }
    }
}
