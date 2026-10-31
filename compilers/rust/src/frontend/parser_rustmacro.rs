//! Rust DSL parser for Rúnar contracts (.runar.rs).
//!
//! Parses Rust-style contract definitions using a hand-written tokenizer
//! and recursive descent parser. Produces the same AST as the TypeScript parser.

use num_bigint::BigInt;
use num_traits::Num;
use super::ast::{
    BinaryOp, ContractNode, Expression, MethodNode, ParamNode, PrimitiveTypeName,
    PropertyNode, SourceLocation, Statement, TypeNode, UnaryOp, Visibility,
};
use super::diagnostic::{lex_error, static_method_message, unknown_return_type_message, Diagnostic, UNTERMINATED_STRING_LITERAL};
use super::sighash_directive::{lost_directive_message, resolve_native_sighash};
use super::int_literal::{invalid_integer_literal, parse_int_literal, scan_number_end};
use super::identifier_collision::DeclaredIdents;
use super::input_limits::{enforce_ast_nesting, nesting_refusal, DepthTracker, NestingCounter};
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
    /// F-026: a signed-suffix minimum such as `128i8` (value, text as
    /// written): legal only under a unary minus.
    NegOnlyNumber(String, String),
    // Attributes
    HashBracket, // #[
    // Punctuation
    LParen, RParen, LBrace, RBrace, LBracket, RBracket,
    Semi, Comma, Dot, DotDot, Colon, ColonColon, Arrow,
    // Operators
    Plus, Minus, Star, Slash, Percent,
    EqEq, BangEq, Lt, LtEq, Gt, GtEq, Shl, Shr,
    AmpAmp, PipePipe,
    Amp, Pipe, Caret, Tilde, Bang,
    Eq, PlusEq, MinusEq,
    // End
    Eof,
}

/// N-093: one field/method attribute, classified by `parse_directive_attribute`.
enum DirectiveAttr {
    EmbedAlways { loc: SourceLocation },
    Sighash { flags: Option<String>, loc: SourceLocation },
    Other(String),
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

fn tokenize(source: &str, file: &str, errors: &mut Vec<Diagnostic>) -> Vec<Token> {
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
        // N-407: exactly the TS reference's whitespace (' ', '\t', '\r', '\n'); a
        // non-ASCII space such as U+00A0 is refused as an unexpected character.
        if matches!(ch, ' ' | '\t' | '\r' | '\n') {
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
                // N-406: a newline resets the column; it is not counted again.
                if chars[pos] == '\n' { line += 1; col = 1; pos += 1; continue; }
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
                "<<" => Some(TokenType::Shl),
                ">>" => Some(TokenType::Shr),
                "&&" => Some(TokenType::AmpAmp),
                "||" => Some(TokenType::PipePipe),
                "+=" => Some(TokenType::PlusEq),
                "-=" => Some(TokenType::MinusEq),
                ".." => Some(TokenType::DotDot),
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

        // Number (F-026): the whole glued [0-9A-Za-z_] run is one Rust
        // integer literal (a lowercase `0x` was taken above as a ByteString).
        if ch.is_ascii_digit() {
            let end = scan_number_end(&chars, pos);
            let text: String = chars[pos..end].iter().collect();
            col += end - pos;
            pos = end;
            let typ = match parse_int_literal("rs", &text) {
                Some(lit) if lit.neg_only => TokenType::NegOnlyNumber(lit.value.to_string(), text),
                Some(lit) => TokenType::Number(lit.value.to_string()),
                None => {
                    errors.push(lex_error(&invalid_integer_literal("rs", &text), file, l, c - 1));
                    TokenType::Number("0".to_string())
                }
            };
            tokens.push(Token { typ, line: l, col: c });
            continue;
        }

        // Identifier / keyword
        // N-407: ASCII only, as the TS reference; a non-ASCII letter is refused
        // as an unexpected character.
        if ch.is_ascii_alphabetic() || ch == '_' {
            let mut val = String::new();
            while pos < chars.len() && (chars[pos].is_ascii_alphanumeric() || chars[pos] == '_') {
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
                // A backslash escapes the next character (as in the TS
                // reference), so `\"` does not close the literal.
                if chars[pos] == '\\' && pos + 1 < chars.len() {
                    val.push(chars[pos]);
                    pos += 1; col += 1;
                }
                val.push(chars[pos]);
                // N-406: a newline inside the literal advances the line, as TS.
                if chars[pos] == '\n' { line += 1; col = 1; } else { col += 1; }
                pos += 1;
            }
            // F-011: Rust strings may span lines, so only end of file leaves
            // one unterminated.
            if pos < chars.len() { pos += 1; col += 1; } // skip closing quote
            else { errors.push(lex_error(UNTERMINATED_STRING_LITERAL, file, l, c - 1)); }
            tokens.push(Token { typ: TokenType::HexString(val), line: l, col: c });
            continue;
        }

        // N-020: an unrecognised character is refused, as the TS reference
        // does, rather than skipped: skipping compiled `a + § b` as `a + b`.
        errors.push(lex_error(&format!("Unexpected character '{}'", ch), file, l, c - 1));
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
    errors: Vec<Diagnostic>,
    /// F-017: declared (spelling, Rúnar name) pairs.
    idents: DeclaredIdents,
    /// F-213 measure (A): parse nesting.
    nest: NestingCounter,
}

impl RustDslParser {
    fn new(tokens: Vec<Token>, file: String) -> Self {
        Self { tokens, pos: 0, file, errors: Vec::new(), idents: DeclaredIdents::default(), nest: NestingCounter::new() }
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
            self.errors.push(Diagnostic::error(format!("Expected {:?}, got {:?} at {}:{}", expected, self.current().typ, self.current().line, self.current().col.saturating_sub(1)), None));
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

                if attr == "runar::contract"
                    || attr == "runar::stateful_contract"
                    || attr == "runar::unsafe_contract"
                {
                    if attr == "runar::stateful_contract" {
                        parent_class = "StatefulSmartContract".to_string();
                    } else if attr == "runar::unsafe_contract" {
                        parent_class = "UnsafeSmartContract".to_string();
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
                        // Field attributes, any number and order: #[readonly],
                        // and N-093's #[embed_always] (the native spelling of
                        // `@embedAlways`). A #[sighash(...)] here annotates
                        // nothing and is refused.
                        let mut readonly = false;
                        let mut embed_always = false;
                        while matches!(self.current().typ, TokenType::HashBracket) {
                            match self.parse_directive_attribute() {
                                DirectiveAttr::EmbedAlways { .. } => embed_always = true,
                                DirectiveAttr::Sighash { loc, .. } => self.errors.push(Diagnostic::error(
                                    lost_directive_message("@sighash"),
                                    Some(loc),
                                )),
                                DirectiveAttr::Other(field_attr) => {
                                    if field_attr == "readonly" { readonly = true; }
                                }
                            }
                        }

                        // Skip optional `pub` visibility modifier
                        if matches!(self.current().typ, TokenType::Pub) {
                            self.advance_clone();
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
                            let camel_name = self.idents.declare(&field_name, snake_to_camel(&field_name));
                            if camel_name != "txPreimage" {
                                properties.push(PropertyNode {
                                    name: camel_name,
                                    prop_type: field_type,
                                    readonly,
                                    initializer: None,
                                    source_location: loc,
                                    synthetic_array_chain: None,
                                    embed_always,
                                });
                            }
                        } else {
                            self.advance_clone();
                        }
                    }
                    self.expect(&TokenType::RBrace);
                } else if attr.starts_with("runar::methods") {
                    // #[runar::methods] is no longer supported — bare `impl` blocks
                    // are discovered directly. Emit a migration diagnostic; the
                    // `impl` branch below still parses the block on the next pass.
                    self.errors.push(Diagnostic::error(
                        "#[runar::methods] is no longer supported — write a bare 'impl ContractName { ... }' block instead",
                        None,
                    ));
                    continue;
                } else {
                    // Unknown attribute, skip
                    continue;
                }
            } else if matches!(self.current().typ, TokenType::Impl) {
                let impl_methods = self.parse_impl_block();
                methods.extend(impl_methods);
            } else {
                self.advance_clone();
            }
        }

        // Determine parent class from property mutability. The explicit
        // `#[runar::unsafe_contract]` attribute is authoritative and must
        // not be silently overridden by this structural inference (F-204).
        if parent_class != "UnsafeSmartContract" && properties.iter().any(|p| !p.readonly) {
            parent_class = "StatefulSmartContract".to_string();
        }

        if self.nest.exceeded() {
            return nesting_refusal(None);
        }
        if contract_name.is_empty() {
            self.errors.push(Diagnostic::error("no Rúnar contract struct found in Rust source", None));
            return ParseResult { contract: None, errors: self.errors, source_size_err: None };
        }

        // Extract init() method as property initializers, if present.
        // init() is a special private method that sets default values on properties.
        let mut final_methods = Vec::new();
        for m in methods {
            if m.name == "init" && m.params.is_empty() {
                // N-093: init() is not a spending entry point, so a #[sighash]
                // on it would be dropped with the method.
                if m.sighash_type.is_some() {
                    self.errors.push(Diagnostic::error(
                        lost_directive_message("@sighash"),
                        Some(m.source_location.clone()),
                    ));
                }
                for stmt in &m.body {
                    if let Statement::Assignment { target, value, .. } = stmt {
                        if let Expression::PropertyAccess { property, .. } = target {
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
            .map(|p| Expression::Identifier { name: p.name.clone(), source_location: None })
            .collect();
        let super_call = Statement::ExpressionStatement {
            expression: Expression::CallExpr {
                callee: Box::new(Expression::Identifier { name: "super".to_string(), source_location: None }),
                args: super_args,
                asm_return_type: None,
            },
            source_location: loc.clone(),
        };

        // Property assignments
        let mut ctor_body = vec![super_call];
        for p in &uninit_props {
            ctor_body.push(Statement::Assignment {
                target: Expression::PropertyAccess { property: p.name.clone(), source_location: None },
                value: Expression::Identifier { name: p.name.clone(), source_location: None },
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
            sighash_type: None,
        };

        let contract = ContractNode {
            name: contract_name,
            parent_class,
            properties,
            constructor,
            methods,
            source_file: self.file.clone(),
        };

        // F-213 measure (A), then measure (B) on the finished tree.
        if self.nest.exceeded() {
            return nesting_refusal(None);
        }
        self.errors.extend(self.idents.collision_diagnostic());
        enforce_ast_nesting(ParseResult { contract: Some(contract), errors: self.errors, source_size_err: None })
    }

    /// Parse a bare `impl ContractName { ... }` block and return its methods.
    /// The type name is consumed and discarded (unrelated `impl` blocks merge
    /// the same way they did under the old `#[runar::methods]` gate). `pub fn`
    /// marks a public spending entry point; bare `fn` is a private helper.
    fn parse_impl_block(&mut self) -> Vec<MethodNode> {
        let mut methods: Vec<MethodNode> = Vec::new();
        self.expect(&TokenType::Impl);
        // Skip the type name.
        if let TokenType::Ident(_) = self.current().typ { self.advance_clone(); }
        self.expect(&TokenType::LBrace);

        while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
            // #[public] is no longer supported — `pub fn` marks public methods.
            // N-093: #[sighash(FLAGS)] is the native spelling of `@sighash`;
            // #[embed_always] on a method annotates nothing and is refused.
            let mut sighash_specs: Vec<Option<String>> = Vec::new();
            while matches!(self.current().typ, TokenType::HashBracket) {
                match self.parse_directive_attribute() {
                    DirectiveAttr::Sighash { flags, .. } => sighash_specs.push(flags),
                    DirectiveAttr::EmbedAlways { loc } => {
                        self.errors.push(Diagnostic::error(lost_directive_message("@embedAlways"), Some(loc)));
                    }
                    DirectiveAttr::Other(method_attr) => {
                        if method_attr == "public" {
                            self.errors.push(Diagnostic::error(
                                "#[public] is no longer supported — use 'pub fn' for public methods",
                                None,
                            ));
                        }
                    }
                }
            }

            let mut visibility = Visibility::Private;
            if matches!(self.current().typ, TokenType::Pub) {
                self.advance_clone();
                visibility = Visibility::Public;
            }
            if !matches!(self.current().typ, TokenType::Fn) {
                // N-093: a #[sighash] not followed by a fn annotates nothing.
                for _ in &sighash_specs {
                    let loc = self.loc();
                    self.errors.push(Diagnostic::error(lost_directive_message("@sighash"), Some(loc)));
                }
                methods.push(self.parse_function(visibility));
                continue;
            }
            let mut method = self.parse_function(visibility);
            match resolve_native_sighash(&method.name, method.visibility == Visibility::Public, &sighash_specs) {
                Some(Ok(v)) => method.sighash_type = Some(v),
                Some(Err(msg)) => {
                    self.errors.push(Diagnostic::error(msg, Some(method.source_location.clone())))
                }
                None => {}
            }
            methods.push(method);
        }
        self.expect(&TokenType::RBrace);
        methods
    }

    /// N-093: classify a field/method attribute as one of the two directives.
    /// `#[embed_always]` and `#[sighash(FLAGS)]` (optionally `runar::`-qualified)
    /// are the native spellings of `@embedAlways` / `@sighash`. For `sighash`,
    /// `flags` is the `|`-joined identifier list, or `None` when the
    /// parentheses are missing or hold any other token. Every other attribute
    /// is returned as `Other` with its compact text, exactly as before.
    /// Mirrors `parseDirectiveAttribute` in the TS reference (01-parse-rust.ts).
    fn parse_directive_attribute(&mut self) -> DirectiveAttr {
        let loc = self.loc();
        let start = self.pos;
        let content = self.parse_attribute();
        // Inside `#[` ... `]`. `parse_attribute` stops at the final token
        // without advancing past it, so guard the end index.
        let end = if matches!(self.tokens.get(self.pos.wrapping_sub(1)).map(|t| &t.typ), Some(TokenType::RBracket)) {
            self.pos - 1
        } else {
            self.pos
        };
        let toks: Vec<TokenType> = self.tokens[(start + 1).min(end)..end].iter().map(|t| t.typ.clone()).collect();
        let mut i = 0;
        if matches!(toks.first(), Some(TokenType::Ident(n)) if n == "runar") && matches!(toks.get(1), Some(TokenType::ColonColon)) {
            i = 2;
        }
        let name = match toks.get(i) {
            Some(TokenType::Ident(n)) => n.clone(),
            _ => String::new(),
        };
        let rest = toks.get(i + 1..).unwrap_or(&[]);
        if name == "embed_always" && rest.is_empty() {
            return DirectiveAttr::EmbedAlways { loc };
        }
        if name == "sighash" {
            let ok = rest.len() >= 2
                && matches!(rest[0], TokenType::LParen)
                && matches!(rest[rest.len() - 1], TokenType::RParen)
                && rest[1..rest.len() - 1].iter().all(|t| matches!(t, TokenType::Ident(_) | TokenType::Pipe));
            let flags = ok.then(|| {
                rest[1..rest.len() - 1]
                    .iter()
                    .map(|t| match t {
                        TokenType::Ident(n) => n.as_str(),
                        _ => "|",
                    })
                    .collect::<String>()
            });
            return DirectiveAttr::Sighash { flags, loc };
        }
        DirectiveAttr::Other(content)
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
        // Fixed-size array: `[T; N]` — maps to TypeNode::FixedArray.
        if matches!(self.current().typ, TokenType::LBracket) {
            self.advance_clone(); // consume [
            // F-213: `[T; N]` element type is one level deeper (+1).
            let element = self.nested(TypeNode::Custom("_error".to_string()), |p| p.parse_rust_type());
            // Expect `;`
            self.match_tok(&TokenType::Semi);
            // Length must be a numeric literal.
            let length = if let TokenType::Number(val) = self.current().typ.clone() {
                self.advance_clone();
                val.parse::<usize>().unwrap_or(0)
            } else {
                0
            };
            self.match_tok(&TokenType::RBracket);
            return TypeNode::FixedArray {
                element: Box::new(element),
                length,
            };
        }
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
        let name = self.idents.declare(&raw_name, snake_to_camel(&raw_name));

        self.expect(&TokenType::LParen);
        let mut params: Vec<ParamNode> = Vec::new();
        let mut has_self = false;

        while !matches!(self.current().typ, TokenType::RParen | TokenType::Eof) {
            // Skip &self, &mut self
            if matches!(self.current().typ, TokenType::Amp) {
                self.advance_clone();
                if matches!(self.current().typ, TokenType::Mut) { self.advance_clone(); }
                if matches!(self.current().typ, TokenType::Self_) {
                    has_self = true;
                    self.advance_clone();
                    if matches!(self.current().typ, TokenType::Comma) { self.advance_clone(); }
                    continue;
                }
            }
            if matches!(self.current().typ, TokenType::Self_) {
                has_self = true;
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
                    name: self.idents.declare(&param_name, snake_to_camel(&param_name)),
                    param_type,
                });
            } else {
                self.advance_clone();
            }
            if matches!(self.current().typ, TokenType::Comma) { self.advance_clone(); }
        }
        self.expect(&TokenType::RParen);

        // N-050: a `pub fn` without a self receiver is an associated (static)
        // function, not a contract method. A private one stays a helper (R9).
        if visibility == Visibility::Public && !has_self {
            self.errors.push(Diagnostic::error(static_method_message(&raw_name), Some(loc.clone())));
        }

        // Optional return type
        if matches!(self.current().typ, TokenType::Arrow) {
            self.advance_clone();
            // The AST keeps no return type; N-331 refuses an unknown name.
            let ret_type = self.parse_rust_type();
            if let Some(msg) = unknown_return_type_message(&ret_type, &raw_name, visibility == Visibility::Public) {
                self.errors.push(Diagnostic::error(msg, Some(loc.clone())));
            }
        }

        self.expect(&TokenType::LBrace);
        let mut body: Vec<Statement> = Vec::new();
        while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
            if let Some(stmt) = self.parse_statement() {
                body.push(stmt);
            }
        }
        self.expect(&TokenType::RBrace);

        MethodNode { name, params, body, visibility, sighash_type: None, source_location: loc }
    }

    fn parse_statement(&mut self) -> Option<Statement> {
        self.nested(None, |p| p.parse_statement_inner())
    }

    fn parse_statement_inner(&mut self) -> Option<Statement> {
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
                    callee: Box::new(Expression::Identifier { name: "assert".to_string(), source_location: None }),
                    args: vec![expr],
                    asm_return_type: None,
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
                    callee: Box::new(Expression::Identifier { name: "assert".to_string(), source_location: None }),
                    args: vec![Expression::BinaryExpr {
                        op: BinaryOp::StrictEq,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: None,
                    }],
                    asm_return_type: None,
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
                self.idents.declare(&name, snake_to_camel(&name))
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
                // `else if <cond> { ... }` -> treat the `if` as a nested
                // statement so else chains compose correctly.
                if matches!(self.current().typ, TokenType::If) {
                    if let Some(nested) = self.parse_statement() {
                        Some(vec![nested])
                    } else {
                        Some(Vec::new())
                    }
                } else {
                    self.expect(&TokenType::LBrace);
                    let mut eb = Vec::new();
                    while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
                        if let Some(s) = self.parse_statement() { eb.push(s); }
                    }
                    self.expect(&TokenType::RBrace);
                    Some(eb)
                }
            } else {
                None
            };
            return Some(Statement::IfStatement { condition, then_branch, else_branch, source_location: loc });
        }

        // for i in start..end { body }
        if matches!(self.current().typ, TokenType::For) {
            self.advance_clone();
            let var_name = if let TokenType::Ident(name) = self.current().typ.clone() {
                self.advance_clone();
                self.idents.declare(&name, snake_to_camel(&name))
            } else {
                self.advance_clone();
                "i".to_string()
            };
            self.expect(&TokenType::In);
            // Two loop headers, both of them real Rust that iterates exactly
            // these values:
            //
            //   for i in a..b         -> a, a+1, … b-1  (ascending)
            //   for i in (a..b).rev() -> b-1, b-2, … a  (DESCENDING)
            //
            // `.rev()` is what lets the Rust surface spell a countdown. A Rust
            // range only ever ascends — `(5..2)` is empty — so `step = -1` was
            // unreachable from this surface and no fixture could exercise it
            // across all nine. `Iterator::rev` reverses the half-open range:
            // the descending loop starts at `b - 1` and ends at `a` INCLUSIVE,
            // which is why the guard below is `>=` against `a`.
            let has_paren = matches!(self.current().typ, TokenType::LParen);
            if has_paren {
                self.advance_clone();
            }
            let range_start = self.parse_expression();
            self.expect(&TokenType::DotDot);
            let range_end = self.parse_expression();

            let mut descending = false;
            if has_paren {
                self.expect(&TokenType::RParen);
                self.expect(&TokenType::Dot);
                let method = match self.current().typ.clone() {
                    TokenType::Ident(name) => {
                        self.advance_clone();
                        name
                    }
                    _ => String::new(),
                };
                if method != "rev" {
                    self.errors.push(Diagnostic::error(
                        format!(
                            "Unsupported range method '.{}()' in for loop — only '.rev()' is supported",
                            method
                        ),
                        Some(loc.clone()),
                    ));
                }
                self.expect(&TokenType::LParen);
                self.expect(&TokenType::RParen);
                descending = true;
            }

            // `(a..b).rev()` starts at `b - 1`. The unrolled loop model needs
            // that start as a compile-time literal — it synthesizes iteration
            // k as `start + k*step` — so fold the subtraction here when `b` is
            // one, and otherwise hand the un-foldable expression straight
            // through so ANF lowering raises its own "Cannot determine loop
            // start" diagnostic rather than this parser inventing a second
            // wording for the same rule.
            let (start_expr, end_expr) = if descending {
                let start = match literal_int_value(&range_end) {
                    Some(upper) => Expression::BigIntLiteral { value: upper - BigInt::from(1) },
                    None => range_end,
                };
                (start, range_start)
            } else {
                (range_start, range_end)
            };

            self.expect(&TokenType::LBrace);
            let mut body = Vec::new();
            while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
                if let Some(s) = self.parse_statement() { body.push(s); }
            }
            self.expect(&TokenType::RBrace);

            let init = Statement::VariableDecl {
                name: var_name.clone(),
                var_type: Some(TypeNode::Primitive(PrimitiveTypeName::Bigint)),
                mutable: true,
                init: start_expr,
                source_location: loc.clone(),
            };
            let condition = Expression::BinaryExpr {
                op: if descending { BinaryOp::Ge } else { BinaryOp::Lt },
                left: Box::new(Expression::Identifier { name: var_name.clone(), source_location: None }),
                right: Box::new(end_expr),
                source_location: None,
            };
            let update_operand = Box::new(Expression::Identifier { name: var_name, source_location: None });
            let update = Statement::ExpressionStatement {
                expression: if descending {
                    Expression::DecrementExpr { operand: update_operand, prefix: false }
                } else {
                    Expression::IncrementExpr { operand: update_operand, prefix: false }
                },
                source_location: loc.clone(),
            };
            return Some(Statement::ForStatement {
                init: Box::new(init),
                condition,
                update: Box::new(update),
                body,
                source_location: loc,
            });
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
                value: Expression::BinaryExpr { op: BinaryOp::Add, left: Box::new(target), right: Box::new(rhs), source_location: None },
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
                value: Expression::BinaryExpr { op: BinaryOp::Sub, left: Box::new(target), right: Box::new(rhs), source_location: None },
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
            if let Expression::Identifier { ref name, .. } = **object {
                if name == "self" {
                    return Expression::PropertyAccess { property: snake_to_camel(property), source_location: None };
                }
            }
        }
        // Recurse into `self.board[idx]` so the inner MemberExpr becomes a
        // PropertyAccess. The expand-fixed-arrays pass matches on
        // `PropertyAccess` inside `IndexAccess.object`.
        if let Expression::IndexAccess { object, index } = expr {
            let new_obj = self.convert_self_access(*object);
            return Expression::IndexAccess {
                object: Box::new(new_obj),
                index,
            };
        }
        expr
    }

    // Expression parsing with precedence climbing
    fn parse_expression(&mut self) -> Expression { self.nested(zero(), |p| p.parse_or()) }

    fn parse_or(&mut self) -> Expression {
        let mut left = self.parse_and();
        let mut dt = DepthTracker::new();
        while matches!(self.current().typ, TokenType::PipePipe) {
            self.advance_clone();
            let right = self.parse_and();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr { op: BinaryOp::Or, left: Box::new(left), right: Box::new(right), source_location: None };
        }
        left
    }

    fn parse_and(&mut self) -> Expression {
        let mut left = self.parse_bit_or();
        let mut dt = DepthTracker::new();
        while matches!(self.current().typ, TokenType::AmpAmp) {
            self.advance_clone();
            let right = self.parse_bit_or();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr { op: BinaryOp::And, left: Box::new(left), right: Box::new(right), source_location: None };
        }
        left
    }

    fn parse_bit_or(&mut self) -> Expression {
        let mut left = self.parse_bit_xor();
        let mut dt = DepthTracker::new();
        while matches!(self.current().typ, TokenType::Pipe) {
            self.advance_clone();
            let right = self.parse_bit_xor();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr { op: BinaryOp::BitOr, left: Box::new(left), right: Box::new(right), source_location: None };
        }
        left
    }

    fn parse_bit_xor(&mut self) -> Expression {
        let mut left = self.parse_bit_and();
        let mut dt = DepthTracker::new();
        while matches!(self.current().typ, TokenType::Caret) {
            self.advance_clone();
            let right = self.parse_bit_and();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr { op: BinaryOp::BitXor, left: Box::new(left), right: Box::new(right), source_location: None };
        }
        left
    }

    fn parse_bit_and(&mut self) -> Expression {
        let mut left = self.parse_equality();
        let mut dt = DepthTracker::new();
        while matches!(self.current().typ, TokenType::Amp) {
            self.advance_clone();
            let right = self.parse_equality();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr { op: BinaryOp::BitAnd, left: Box::new(left), right: Box::new(right), source_location: None };
        }
        left
    }

    fn parse_equality(&mut self) -> Expression {
        let mut left = self.parse_comparison();
        let mut dt = DepthTracker::new();
        loop {
            let op = match self.current().typ {
                TokenType::EqEq => BinaryOp::StrictEq,
                TokenType::BangEq => BinaryOp::StrictNe,
                _ => break,
            };
            self.advance_clone();
            let right = self.parse_comparison();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr { op, left: Box::new(left), right: Box::new(right), source_location: None };
        }
        left
    }

    fn parse_comparison(&mut self) -> Expression {
        let mut left = self.parse_shift();
        let mut dt = DepthTracker::new();
        loop {
            let op = match self.current().typ {
                TokenType::Lt => BinaryOp::Lt,
                TokenType::LtEq => BinaryOp::Le,
                TokenType::Gt => BinaryOp::Gt,
                TokenType::GtEq => BinaryOp::Ge,
                _ => break,
            };
            self.advance_clone();
            let right = self.parse_shift();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr { op, left: Box::new(left), right: Box::new(right), source_location: None };
        }
        left
    }

    fn parse_shift(&mut self) -> Expression {
        let mut left = self.parse_add_sub();
        let mut dt = DepthTracker::new();
        loop {
            let op = match self.current().typ {
                TokenType::Shl => BinaryOp::Shl,
                TokenType::Shr => BinaryOp::Shr,
                _ => break,
            };
            self.advance_clone();
            let right = self.parse_add_sub();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr { op, left: Box::new(left), right: Box::new(right), source_location: None };
        }
        left
    }

    fn parse_add_sub(&mut self) -> Expression {
        let mut left = self.parse_mul_div();
        let mut dt = DepthTracker::new();
        loop {
            let op = match self.current().typ {
                TokenType::Plus => BinaryOp::Add,
                TokenType::Minus => BinaryOp::Sub,
                _ => break,
            };
            self.advance_clone();
            let right = self.parse_mul_div();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr { op, left: Box::new(left), right: Box::new(right), source_location: None };
        }
        left
    }

    fn parse_mul_div(&mut self) -> Expression {
        let mut left = self.parse_unary();
        let mut dt = DepthTracker::new();
        loop {
            let op = match self.current().typ {
                TokenType::Star => BinaryOp::Mul,
                TokenType::Slash => BinaryOp::Div,
                TokenType::Percent => BinaryOp::Mod,
                _ => break,
            };
            self.advance_clone();
            let right = self.parse_unary();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr { op, left: Box::new(left), right: Box::new(right), source_location: None };
        }
        left
    }

    fn parse_unary(&mut self) -> Expression {
        match self.current().typ {
            TokenType::Bang => { self.advance_clone(); Expression::UnaryExpr { op: UnaryOp::Not, operand: Box::new(self.nested(zero(), |p| p.parse_unary())), source_location: None } }
            TokenType::Minus => {
                self.advance_clone();
                // F-026: a signed-suffix minimum (`128i8`) is legal under this
                // minus, through parentheses, as rustc's overflowing_literals lint.
                let mut k = self.pos;
                let mut opens = 0;
                while k < self.tokens.len() && matches!(self.tokens[k].typ, TokenType::LParen) {
                    k += 1;
                    opens += 1;
                }
                if let Some(TokenType::NegOnlyNumber(v, _)) = self.tokens.get(k).map(|t| t.typ.clone()) {
                    let closed = (1..=opens).all(|j| matches!(self.tokens.get(k + j).map(|t| &t.typ), Some(TokenType::RParen)));
                    if closed {
                        self.tokens[k].typ = TokenType::Number(v);
                    }
                }
                Expression::UnaryExpr { op: UnaryOp::Neg, operand: Box::new(self.nested(zero(), |p| p.parse_unary())), source_location: None }
            }
            TokenType::Tilde => { self.advance_clone(); Expression::UnaryExpr { op: UnaryOp::BitNot, operand: Box::new(self.nested(zero(), |p| p.parse_unary())), source_location: None } }
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
        let mut dt = DepthTracker::new();
        loop {
            if matches!(self.current().typ, TokenType::LParen) {
                self.advance_clone();
                let mut args = Vec::new();
                while !matches!(self.current().typ, TokenType::RParen | TokenType::Eof) {
                    args.push(self.parse_expression());
                    if matches!(self.current().typ, TokenType::Comma) { self.advance_clone(); }
                }
                self.expect(&TokenType::RParen);
                // `.clone()` is a Rust borrow-checker artifact — in Rúnar,
                // values are copied by default, so strip it and keep the
                // receiver. Without this the IR emits a spurious
                // method_call(clone) followed by a general-call fallback,
                // which lowers to OP_DROP OP_0 padding.
                if args.is_empty() {
                    if let Expression::MemberExpr { object, property } = &expr {
                        if property == "clone" {
                            expr = (**object).clone();
                            dt = DepthTracker::new();
                            continue;
                        }
                    }
                }
                let arg_refs: Vec<&Expression> = args.iter().collect();
                if !self.grow(&mut dt, &expr, &arg_refs) { break; }
                expr = Expression::CallExpr { callee: Box::new(expr), args, asm_return_type: None };
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
                if let Expression::Identifier { ref name, .. } = expr {
                    if name == "self" {
                        expr = Expression::PropertyAccess { property: prop, source_location: None };
                        dt = DepthTracker::new();
                        continue;
                    }
                }
                if !self.grow(&mut dt, &expr, &[]) { break; }
                expr = Expression::MemberExpr { object: Box::new(expr), property: prop };
            } else if matches!(self.current().typ, TokenType::ColonColon) {
                self.advance_clone();
                if let TokenType::Ident(name) = self.current().typ.clone() {
                    self.advance_clone();
                    expr = Expression::Identifier { name: snake_to_camel(&name), source_location: None };
                    dt = DepthTracker::new();
                }
            } else if matches!(self.current().typ, TokenType::LBracket) {
                self.advance_clone();
                let index = self.parse_expression();
                self.expect(&TokenType::RBracket);
                if !self.grow(&mut dt, &expr, &[&index]) { break; }
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
                let n = <BigInt as Num>::from_str_radix(&val, 10)
                    .unwrap_or_else(|_| BigInt::from(0));
                Expression::BigIntLiteral { value: n }
            }
            TokenType::NegOnlyNumber(val, text) => {
                let t = self.current().clone();
                self.errors.push(lex_error(&invalid_integer_literal("rs", &text), &self.file.clone(), t.line, t.col.saturating_sub(1)));
                self.advance_clone();
                let n = <BigInt as Num>::from_str_radix(&val, 10)
                    .unwrap_or_else(|_| BigInt::from(0));
                Expression::BigIntLiteral { value: n }
            }
            TokenType::HexString(val) => {
                let lit_loc = self.loc();
                self.advance_clone();
                Expression::ByteStringLiteral { value: val, source_location: Some(lit_loc) }
            }
            TokenType::True => { self.advance_clone(); Expression::BoolLiteral { value: true } }
            TokenType::False => { self.advance_clone(); Expression::BoolLiteral { value: false } }
            TokenType::Self_ => {
                self.advance_clone();
                Expression::Identifier { name: "self".to_string(), source_location: None }
            }
            TokenType::LParen => {
                self.advance_clone();
                let expr = self.parse_expression();
                self.expect(&TokenType::RParen);
                expr
            }
            TokenType::LBracket => {
                // Array literal: `[e0, e1, ...]` — used for FixedArray
                // property initializers in init(). Also supports nested
                // array literals for nested FixedArrays.
                self.advance_clone(); // consume [
                let mut elements: Vec<Expression> = Vec::new();
                while !matches!(self.current().typ, TokenType::RBracket | TokenType::Eof) {
                    let e = self.parse_expression();
                    elements.push(e);
                    if matches!(self.current().typ, TokenType::Comma) {
                        self.advance_clone();
                    } else {
                        break;
                    }
                }
                self.expect(&TokenType::RBracket);
                Expression::ArrayLiteral { elements }
            }
            TokenType::Ident(name) => {
                let ident_loc = self.loc();
                self.advance_clone();
                let mapped = map_rust_builtin(&name);
                Expression::Identifier { name: mapped, source_location: Some(ident_loc) }
            }
            _ => {
                let tok = self.current().clone();
                self.advance_clone();
                self.errors.push(Diagnostic::error(format!(
                    "unsupported token '{:?}' at {}:{} — not valid in Rúnar contract",
                    tok.typ, tok.line, tok.col.saturating_sub(1)), None));
                Expression::Identifier { name: "unknown".to_string(), source_location: None }
            }
        }
    }
}

/// Placeholder expression returned by a parse cut short by the F-213 limit.
fn zero() -> Expression {
    Expression::BigIntLiteral { value: BigInt::from(0) }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The integer value of a literal expression, or `None` when it is not one.
///
/// A negative literal arrives as a unary minus over a positive one, so both
/// shapes have to be walked — the same walk `extract_big_int_value` does in
/// ANF lowering, for the same reason (N-138).
fn literal_int_value(expr: &Expression) -> Option<BigInt> {
    match expr {
        Expression::BigIntLiteral { value } => Some(value.clone()),
        Expression::UnaryExpr { op, operand, .. } if *op == UnaryOp::Neg => {
            literal_int_value(operand).map(|v| -v)
        }
        _ => None,
    }
}

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

/// Map a Rust DSL type name to its Rúnar spelling.
///
/// N-108: `Sha256Digest` is runar-lang's cross-language name for `Sha256`
/// (`packages/runar-lang/src/types.ts`: `export type Sha256Digest = Sha256`)
/// and the Rust DSL surface uses it. Alias resolution is a per-SURFACE rule,
/// so `parser.rs`'s `resolve_type_alias` (the `.runar.ts` surface, N-104b) does
/// not reach this parser. TypeScript, Python, Ruby and Java resolved it here;
/// Go, Rust and Zig did not, and the name reached the validator as an opaque
/// custom type. Every other surface parser in this tier already has the arm
/// (parser_gocontract.rs, parser_java.rs, parser_python.rs, parser_ruby.rs,
/// parser_zig.rs) -- the Rust DSL was the omission.
fn map_rust_type(name: &str) -> String {
    match name {
        // `BigintBig` is packages/runar-rs's num_bigint::BigInt, the wide half
        // of a pair whose narrow half (`Bigint` = i64) REFUSES what it cannot
        // represent. A different Rust runtime type, the same Script primitive:
        // reaching for it must not change one emitted byte. R-RustBigint.
        "Bigint" | "BigintBig" | "Int" | "i64" | "u64" | "i128" | "u128" => "bigint".to_string(),
        "Bool" | "bool" => "boolean".to_string(),
        "Sha256Digest" => "Sha256".to_string(),
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
        // The arbitrary-precision encoder spellings from packages/runar-rs.
        // Mapped here, BEFORE camelisation, so the answer does not depend on
        // this tier's snake_to_camel. Without them the typechecker answers
        // "unknown function" — a TYPECHECK diagnostic, which --parse-only
        // cannot see. R-RustBigint.
        "bin2num_big" => return "bin2num".to_string(),
        "num2bin_big" => return "num2bin".to_string(),
        "int_2_str" => return "int2str".to_string(),
        "to_byte_string" => return "toByteString".to_string(),
        "verify_ecdsa_p256" => return "verifyECDSA_P256".to_string(),
        "verify_ecdsa_p384" => return "verifyECDSA_P384".to_string(),
        // Intent sub-covenant intrinsics (BSVM Phase 13). The P2PKH acronym
        // doesn't survive snake_to_camel (it would lowercase the `P`), so map
        // explicitly. extract_prev_output_script and current_block_height
        // round-trip cleanly but are listed in the post-camel block below.
        "require_output_p2pkh" => return "requireOutputP2PKH".to_string(),
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
        "extractPrevOutputScript" => "extractPrevOutputScript".to_string(),
        "currentBlockHeight" => "currentBlockHeight".to_string(),
        "continuationAmount" => "continuationAmount".to_string(),
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
        "addRawOutput" => "addRawOutput".to_string(),
        "addDataOutput" => "addDataOutput".to_string(),
        "reverseBytes" => "reverseBytes".to_string(),
        "toByteString" => "toByteString".to_string(),
        _ => camel,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn parse_rust_dsl(source: &str, file_name: Option<&str>) -> ParseResult {
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
    super::input_limits::run_on_parse_stack(|| parse_rust_dsl_on_parse_stack(source, file_name))
}

/// The body of [`parse_rust_dsl`], on the parse stack segment.
fn parse_rust_dsl_on_parse_stack(source: &str, file_name: Option<&str>) -> ParseResult {
    let file = file_name.unwrap_or("contract.runar.rs").to_string();
    let mut lex_errors: Vec<Diagnostic> = Vec::new();
    let tokens = tokenize(source, &file, &mut lex_errors);
    let parser = RustDslParser::new(tokens, file);
    let mut result = parser.parse();
    lex_errors.append(&mut result.errors);
    result.errors = lex_errors;
    result
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

impl P2PKH {
    pub fn unlock(&self, sig: Sig, pub_key: PubKey) {
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
    fn test_pub_fn_makes_method_public() {
        let source = r#"
use runar::prelude::*;

#[runar::contract]
pub struct Test {
    #[readonly]
    x: bigint,
}

impl Test {
    pub fn public_method(&self, v: i64) {
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

        // First method should be public (`pub fn`)
        assert_eq!(contract.methods[0].name, "publicMethod");
        assert_eq!(contract.methods[0].visibility, Visibility::Public);

        // Second method should be private (bare `fn`)
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

impl MyFancyContract {
    pub fn check(&self, v: i64) {
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

impl Test {
    pub fn check(&self, v: i64) {
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

impl Counter {
    pub fn increment(&mut self) {
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
    fn test_unsafe_contract_with_mutable_field_stays_unsafe() {
        // F-204: `#[runar::unsafe_contract]` must not be silently downgraded
        // to StatefulSmartContract by the structural mutability inference.
        // The explicit attribute is authoritative (mirrors the TS reference
        // parser's ordering, where the attribute override is applied last).
        let source = r#"
use runar::prelude::*;

#[runar::unsafe_contract]
pub struct Counter {
    count: bigint,
}

impl Counter {
    pub fn increment(&mut self) {
        asm("51", 0, 1);
    }
}
"#;

        let result = parse_rust_dsl(source, Some("Counter.runar.rs"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.name, "Counter");
        assert_eq!(contract.parent_class, "UnsafeSmartContract");
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

impl Test {
    pub fn check(&self) {
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

impl Test {
    pub fn check(&self, v: i64) {
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
            if let Expression::CallExpr { callee, args, .. } = expression {
                if let Expression::Identifier { name, .. } = callee.as_ref() {
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
impl Foo {
    fn compute(&self, a: Bigint, b: Bigint) -> Bigint {
        let sum = a + b;
        sum
    }
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

    // -- New-style bare `impl` parsing -------------------------------------

    #[test]
    fn test_bare_impl_without_methods_attribute() {
        // `impl ContractName` with no `#[runar::methods]` attribute is parsed.
        let source = r#"
use runar::prelude::*;

#[runar::contract]
pub struct Counter {
    count: Bigint,
}

impl Counter {
    pub fn increment(&mut self) {
        self.count = self.count + 1;
    }
}
"#;
        let result = parse_rust_dsl(source, Some("Counter.runar.rs"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods.len(), 1);
        assert_eq!(contract.methods[0].name, "increment");
        assert_eq!(contract.methods[0].visibility, Visibility::Public);
    }

    #[test]
    fn test_multiple_impl_blocks_merge_in_order() {
        let source = r#"
use runar::prelude::*;

#[runar::contract]
pub struct Multi {
    #[readonly]
    x: Bigint,
}

impl Multi {
    pub fn first(&self) {
        assert!(self.x > 0);
    }
}

impl Multi {
    pub fn second(&self) {
        assert!(self.x < 100);
    }
}
"#;
        let result = parse_rust_dsl(source, Some("Multi.runar.rs"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.methods.len(), 2);
        assert_eq!(contract.methods[0].name, "first");
        assert_eq!(contract.methods[1].name, "second");
    }

    #[test]
    fn test_impl_before_struct() {
        // Single-pass parsing tolerates the `impl` block appearing before the
        // contract struct.
        let source = r#"
use runar::prelude::*;

impl Early {
    pub fn check(&self) {
        assert!(self.x > 0);
    }
}

#[runar::contract]
pub struct Early {
    #[readonly]
    x: Bigint,
}
"#;
        let result = parse_rust_dsl(source, Some("Early.runar.rs"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let contract = result.contract.unwrap();
        assert_eq!(contract.name, "Early");
        assert_eq!(contract.methods.len(), 1);
        assert_eq!(contract.methods[0].name, "check");
    }

    #[test]
    fn test_runar_methods_attribute_rejected() {
        let source = r#"
use runar::prelude::*;

#[runar::contract]
pub struct Old {
    #[readonly]
    x: Bigint,
}

#[runar::methods(Old)]
impl Old {
    pub fn check(&self) {
        assert!(self.x > 0);
    }
}
"#;
        let result = parse_rust_dsl(source, Some("Old.runar.rs"));
        assert!(
            result.errors.iter().any(|e| e.message.contains("#[runar::methods]")),
            "expected a migration diagnostic, got: {:?}",
            result.errors,
        );
    }

    #[test]
    fn test_public_attribute_rejected() {
        let source = r#"
use runar::prelude::*;

#[runar::contract]
pub struct Old {
    #[readonly]
    x: Bigint,
}

impl Old {
    #[public]
    pub fn check(&self) {
        assert!(self.x > 0);
    }
}
"#;
        let result = parse_rust_dsl(source, Some("Old.runar.rs"));
        assert!(
            result.errors.iter().any(|e| e.message.contains("#[public]")),
            "expected a migration diagnostic, got: {:?}",
            result.errors,
        );
    }
}
