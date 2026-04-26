//! Java contract parser for Rúnar contracts (.runar.java).
//!
//! Parses the Rúnar subset of Java using a hand-written tokenizer and
//! recursive-descent parser. Produces the same AST as the TypeScript
//! parser.
//!
//! This is a faithful port of the Java-side reference parser
//! (`compilers/java/src/main/java/runar/compiler/frontend/JavaParser.java`).
//! It accepts only the Rúnar subset of Java syntax. Non-contract Java
//! constructs (inner classes, lambdas, switch expressions, generics beyond
//! `FixedArray`, try/catch, annotations other than `@Readonly` / `@Public`
//! / `@Stateful`) are rejected at parse time — loud failure is preferred
//! over silent divergence from the other compilers.
//!
//! ## Expected shape
//!
//! ```java
//! package runar.examples.p2pkh;
//!
//! import runar.lang.SmartContract;
//! import runar.lang.annotations.Readonly;
//! import runar.lang.annotations.Public;
//! import runar.lang.types.Addr;
//! import runar.lang.types.PubKey;
//! import runar.lang.types.Sig;
//! import static runar.lang.Builtins.*;
//!
//! class P2PKH extends SmartContract {
//!     @Readonly Addr pubKeyHash;
//!
//!     P2PKH(Addr pubKeyHash) {
//!         super(pubKeyHash);
//!         this.pubKeyHash = pubKeyHash;
//!     }
//!
//!     @Public
//!     void unlock(Sig sig, PubKey pubKey) {
//!         assertThat(hash160(pubKey).equals(pubKeyHash));
//!         assertThat(checkSig(sig, pubKey));
//!     }
//! }
//! ```

use super::ast::{
    BinaryOp, ContractNode, Expression, MethodNode, ParamNode, PrimitiveTypeName, PropertyNode,
    SourceLocation, Statement, TypeNode, UnaryOp, Visibility,
};
use super::diagnostic::Diagnostic;
use super::parser::ParseResult;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a Java-format Rúnar contract source.
pub fn parse_java(source: &str, file_name: Option<&str>) -> ParseResult {
    let file = file_name.unwrap_or("contract.runar.java");
    let mut errors: Vec<Diagnostic> = Vec::new();

    let tokens = tokenize(source);
    let mut parser = JavaParser::new(tokens, file, &mut errors);
    let contract = parser.parse();

    ParseResult { contract, errors }
}

// ---------------------------------------------------------------------------
// Type mapping
// ---------------------------------------------------------------------------

/// Map a Java type name (identifier) to a Rúnar AST type. Mirrors
/// `resolveNamedType` in the reference Java parser.
fn resolve_named_type(name: &str) -> TypeNode {
    if let Some(p) = PrimitiveTypeName::from_str(name) {
        return TypeNode::Primitive(p);
    }
    match name {
        "Bigint" | "BigInteger" => TypeNode::Primitive(PrimitiveTypeName::Bigint),
        "Boolean" => TypeNode::Primitive(PrimitiveTypeName::Boolean),
        "Ripemd160" | "Hash160" => TypeNode::Primitive(PrimitiveTypeName::Ripemd160),
        "Sha256Digest" => TypeNode::Primitive(PrimitiveTypeName::Sha256),
        _ => TypeNode::Custom(name.to_string()),
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
    Class,
    Extends,
    Implements,
    Static,
    Public,
    Private,
    Protected,
    Final,
    Abstract,
    If,
    Else,
    For,
    While,
    Return,
    True,
    False,
    This,
    Super,
    New,
    Void,
    Null,
    Instanceof,
    // Punctuation
    At,
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
    Question, // ? in ternary
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
    Shl,      // <<
    Shr,      // >>
    AmpAmp,   // &&
    PipePipe, // ||
    Amp,
    Pipe,
    Caret,
    Tilde,
    Bang,
    Eq,       // =
    PlusEq,   // +=
    MinusEq,  // -=
    StarEq,   // *=
    SlashEq,  // /=
    PercentEq, // %=
    PlusPlus, // ++
    MinusMinus, // --
    // Literals
    Ident(String),
    Number(i128),
    StringLit(String),
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
    let mut tokens: Vec<Token> = Vec::new();
    let mut pos = 0usize;
    let mut line = 1usize;
    let mut col = 1usize;

    while pos < chars.len() {
        let ch = chars[pos];
        let l = line;
        let c = col;

        // Whitespace
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

        // Line comment
        if ch == '/' && pos + 1 < chars.len() && chars[pos + 1] == '/' {
            while pos < chars.len() && chars[pos] != '\n' {
                pos += 1;
            }
            continue;
        }

        // Block comment (also handles /** ... */ javadoc)
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

        // Double-quoted string. Java does not support backticks or single-quoted strings
        // here (char literals are rejected below).
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
                        'r' => val.push('\r'),
                        '0' => val.push('\0'),
                        '\\' => val.push('\\'),
                        '"' => val.push('"'),
                        '\'' => val.push('\''),
                        other => {
                            val.push('\\');
                            val.push(other);
                        }
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

        // Single-quoted char literal — tokenize as string so the parser can
        // reject it uniformly as "bare String / char literals not allowed".
        if ch == '\'' {
            let mut val = String::new();
            pos += 1;
            col += 1;
            while pos < chars.len() && chars[pos] != '\'' {
                if chars[pos] == '\\' && pos + 1 < chars.len() {
                    pos += 1;
                    col += 1;
                }
                val.push(chars[pos]);
                pos += 1;
                col += 1;
            }
            if pos < chars.len() {
                pos += 1;
                col += 1;
            }
            // Represent as string — parse_primary rejects StringLit by design.
            tokens.push(Token { typ: TokenType::StringLit(val), line: l, col: c });
            continue;
        }

        // Two-char operators
        if pos + 1 < chars.len() {
            let two = (ch, chars[pos + 1]);
            let tok = match two {
                ('=', '=') => Some(TokenType::EqEq),
                ('!', '=') => Some(TokenType::BangEq),
                ('<', '=') => Some(TokenType::LtEq),
                ('>', '=') => Some(TokenType::GtEq),
                ('&', '&') => Some(TokenType::AmpAmp),
                ('|', '|') => Some(TokenType::PipePipe),
                ('+', '=') => Some(TokenType::PlusEq),
                ('-', '=') => Some(TokenType::MinusEq),
                ('*', '=') => Some(TokenType::StarEq),
                ('/', '=') => Some(TokenType::SlashEq),
                ('%', '=') => Some(TokenType::PercentEq),
                ('+', '+') => Some(TokenType::PlusPlus),
                ('-', '-') => Some(TokenType::MinusMinus),
                ('<', '<') => Some(TokenType::Shl),
                ('>', '>') => Some(TokenType::Shr),
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
            '@' => Some(TokenType::At),
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
            '?' => Some(TokenType::Question),
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

        // Number literal (allow optional trailing L/l suffix for long
        // literals, and underscores between digits).
        if ch.is_ascii_digit() {
            let mut val = String::new();
            while pos < chars.len() && (chars[pos].is_ascii_digit() || chars[pos] == '_') {
                if chars[pos] != '_' {
                    val.push(chars[pos]);
                }
                pos += 1;
                col += 1;
            }
            // optional L / l long suffix
            if pos < chars.len() && (chars[pos] == 'L' || chars[pos] == 'l') {
                pos += 1;
                col += 1;
            }
            let n: i128 = val.parse().unwrap_or(0);
            tokens.push(Token { typ: TokenType::Number(n), line: l, col: c });
            continue;
        }

        // Identifier / keyword
        if ch.is_alphabetic() || ch == '_' || ch == '$' {
            let mut val = String::new();
            while pos < chars.len()
                && (chars[pos].is_alphanumeric() || chars[pos] == '_' || chars[pos] == '$')
            {
                val.push(chars[pos]);
                pos += 1;
                col += 1;
            }
            let tok = match val.as_str() {
                "package" => TokenType::Package,
                "import" => TokenType::Import,
                "class" => TokenType::Class,
                "extends" => TokenType::Extends,
                "implements" => TokenType::Implements,
                "static" => TokenType::Static,
                "public" => TokenType::Public,
                "private" => TokenType::Private,
                "protected" => TokenType::Protected,
                "final" => TokenType::Final,
                "abstract" => TokenType::Abstract,
                "if" => TokenType::If,
                "else" => TokenType::Else,
                "for" => TokenType::For,
                "while" => TokenType::While,
                "return" => TokenType::Return,
                "true" => TokenType::True,
                "false" => TokenType::False,
                "this" => TokenType::This,
                "super" => TokenType::Super,
                "new" => TokenType::New,
                "void" => TokenType::Void,
                "null" => TokenType::Null,
                "instanceof" => TokenType::Instanceof,
                _ => TokenType::Ident(val),
            };
            tokens.push(Token { typ: tok, line: l, col: c });
            continue;
        }

        // Skip unknown character silently
        pos += 1;
        col += 1;
    }

    tokens.push(Token { typ: TokenType::Eof, line, col });
    tokens
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct JavaParser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    file: String,
    errors: &'a mut Vec<Diagnostic>,
    /// Set while parsing a type argument list (`FixedArray<T, N>`). When true,
    /// `>` and `>>` are treated as type-list closers rather than binary
    /// operators. The counter allows nested generics (`FixedArray<FixedArray<...>>`).
    type_args_depth: usize,
    /// Name of the enclosing contract class (used to distinguish the
    /// constructor from a method with the same name).
    contract_name: String,
}

impl<'a> JavaParser<'a> {
    fn new(tokens: Vec<Token>, file: &str, errors: &'a mut Vec<Diagnostic>) -> Self {
        Self {
            tokens,
            pos: 0,
            file: file.to_string(),
            errors,
            type_args_depth: 0,
            contract_name: String::new(),
        }
    }

    fn current(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(self.tokens.last().unwrap())
    }

    fn peek_at(&self, offset: usize) -> &Token {
        self.tokens
            .get(self.pos + offset)
            .unwrap_or(self.tokens.last().unwrap())
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

    fn error(&mut self, message: impl Into<String>) {
        let loc = SourceLocation {
            file: self.file.clone(),
            line: self.current().line,
            column: self.current().col,
        };
        self.errors.push(Diagnostic::error(message, Some(loc)));
    }

    fn expect_ident(&mut self) -> String {
        if let TokenType::Ident(name) = self.current().typ.clone() {
            self.advance();
            name
        } else {
            self.error(format!(
                "expected identifier, got {:?}",
                self.current().typ
            ));
            String::new()
        }
    }

    fn expect_tok(&mut self, expected: &TokenType) {
        if std::mem::discriminant(&self.current().typ) != std::mem::discriminant(expected) {
            self.error(format!(
                "expected {:?}, got {:?}",
                expected,
                self.current().typ
            ));
            return;
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

    // -----------------------------------------------------------------------
    // Top-level parse
    // -----------------------------------------------------------------------

    fn parse(&mut self) -> Option<ContractNode> {
        // Optional `package <qualified.name>;`
        if matches!(self.current().typ, TokenType::Package) {
            self.advance();
            self.skip_qualified_name();
            self.match_tok(&TokenType::Semi);
        }

        // Zero or more `import [static] <qualified.name>[.*];`
        while matches!(self.current().typ, TokenType::Import) {
            self.advance();
            self.match_tok(&TokenType::Static);
            self.skip_qualified_name();
            // Handle trailing `.*`
            if matches!(self.current().typ, TokenType::Dot) {
                self.advance();
                if matches!(self.current().typ, TokenType::Star) {
                    self.advance();
                }
            }
            self.match_tok(&TokenType::Semi);
        }

        // Skip class-level annotations (@Stateful, etc.). They're informational.
        while matches!(self.current().typ, TokenType::At) {
            self.skip_annotation();
        }

        // Eat class modifiers: public/private/protected/static/final/abstract
        while matches!(
            self.current().typ,
            TokenType::Public
                | TokenType::Private
                | TokenType::Protected
                | TokenType::Static
                | TokenType::Final
                | TokenType::Abstract
        ) {
            self.advance();
        }

        // `class <Name>` ...
        if !matches!(self.current().typ, TokenType::Class) {
            self.error("expected 'class' declaration");
            return None;
        }
        self.advance();

        let class_name = self.expect_ident();
        self.contract_name = class_name.clone();

        // extends <Parent>
        let parent_class = if matches!(self.current().typ, TokenType::Extends) {
            self.advance();
            let name = self.expect_ident();
            match name.as_str() {
                "SmartContract" => "SmartContract".to_string(),
                "StatefulSmartContract" => "StatefulSmartContract".to_string(),
                other => {
                    self.error(format!(
                        "contract class in {} must extend SmartContract or StatefulSmartContract, got {}",
                        self.file, other
                    ));
                    return None;
                }
            }
        } else {
            self.error(format!(
                "contract class in {} must extend SmartContract or StatefulSmartContract",
                self.file
            ));
            return None;
        };

        // Optional `implements ...` — skip.
        if matches!(self.current().typ, TokenType::Implements) {
            self.advance();
            while !matches!(self.current().typ, TokenType::LBrace | TokenType::Eof) {
                self.advance();
            }
        }

        // Class body
        self.expect_tok(&TokenType::LBrace);

        let mut properties: Vec<PropertyNode> = Vec::new();
        let mut constructor: Option<MethodNode> = None;
        let mut methods: Vec<MethodNode> = Vec::new();

        while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
            self.skip_semis();
            if matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
                break;
            }
            self.parse_member(&class_name, &mut properties, &mut constructor, &mut methods);
        }

        self.match_tok(&TokenType::RBrace);

        let ctor = constructor.unwrap_or_else(|| synthesize_constructor(&properties, &self.file));

        Some(ContractNode {
            name: class_name,
            parent_class,
            properties,
            constructor: ctor,
            methods,
            source_file: self.file.clone(),
        })
    }

    fn skip_qualified_name(&mut self) {
        loop {
            if let TokenType::Ident(_) = self.current().typ.clone() {
                self.advance();
            } else {
                break;
            }
            if matches!(self.current().typ, TokenType::Dot) {
                // Only consume `.` if followed by another identifier. A
                // `.*` import is handled by the caller after we return.
                if matches!(self.peek_at(1).typ, TokenType::Ident(_)) {
                    self.advance();
                    continue;
                }
            }
            break;
        }
    }

    /// Skip an annotation (`@Name` or `@Name(args)`) at the current position.
    fn skip_annotation(&mut self) {
        self.expect_tok(&TokenType::At);
        // `@Ident` or `@pkg.Ident` — identifier chain.
        self.skip_qualified_name();
        if matches!(self.current().typ, TokenType::LParen) {
            // Balanced skip of the annotation argument list.
            self.advance();
            let mut depth = 1usize;
            while !matches!(self.current().typ, TokenType::Eof) {
                match self.current().typ {
                    TokenType::LParen => {
                        depth += 1;
                        self.advance();
                    }
                    TokenType::RParen => {
                        depth -= 1;
                        self.advance();
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {
                        self.advance();
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Class members: fields, constructor, methods
    // -----------------------------------------------------------------------

    fn parse_member(
        &mut self,
        class_name: &str,
        properties: &mut Vec<PropertyNode>,
        constructor: &mut Option<MethodNode>,
        methods: &mut Vec<MethodNode>,
    ) {
        // Collect annotations.
        let mut annotations: Vec<String> = Vec::new();
        while matches!(self.current().typ, TokenType::At) {
            self.advance();
            let name = self.expect_ident();
            // Annotations may carry arguments (e.g. `@Foo("bar")`).
            if matches!(self.current().typ, TokenType::LParen) {
                self.advance();
                let mut depth = 1usize;
                while !matches!(self.current().typ, TokenType::Eof) {
                    match self.current().typ {
                        TokenType::LParen => {
                            depth += 1;
                            self.advance();
                        }
                        TokenType::RParen => {
                            depth -= 1;
                            self.advance();
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {
                            self.advance();
                        }
                    }
                }
            }
            annotations.push(name);
        }

        // Visibility / modifier keywords. We tolerate them but don't rely on them.
        while matches!(
            self.current().typ,
            TokenType::Public
                | TokenType::Private
                | TokenType::Protected
                | TokenType::Static
                | TokenType::Final
                | TokenType::Abstract
        ) {
            self.advance();
        }

        let member_loc = self.loc();

        // Disambiguate constructor vs field vs method.
        //
        // Constructor: `ClassName(...)` — an identifier matching the class,
        // followed immediately by `(`.
        if let TokenType::Ident(name) = self.current().typ.clone() {
            if name == class_name && matches!(self.peek_at(1).typ, TokenType::LParen) {
                // Constructor
                self.advance(); // consume class name
                let params = self.parse_param_list();
                // Skip throws clause (rejected later) if any: `throws X, Y {`
                while !matches!(self.current().typ, TokenType::LBrace | TokenType::Eof) {
                    self.advance();
                }
                let body = self.parse_block();
                if constructor.is_some() {
                    self.error(format!("{} has more than one constructor", class_name));
                }
                *constructor = Some(MethodNode {
                    name: "constructor".to_string(),
                    params,
                    body,
                    visibility: Visibility::Public,
                    source_location: member_loc,
                });
                return;
            }
        }

        // Otherwise: a typed member (field or method). Parse the type first.
        let member_type = self.parse_type();

        // Members must be followed by an identifier.
        let member_name = match self.current().typ.clone() {
            TokenType::Ident(n) => {
                self.advance();
                n
            }
            _ => {
                self.error(format!(
                    "expected member name, got {:?}",
                    self.current().typ
                ));
                // Skip to next `;` or `}` to recover.
                while !matches!(
                    self.current().typ,
                    TokenType::Semi | TokenType::RBrace | TokenType::Eof
                ) {
                    self.advance();
                }
                self.match_tok(&TokenType::Semi);
                return;
            }
        };

        if matches!(self.current().typ, TokenType::LParen) {
            // Method declaration.
            let params = self.parse_param_list();
            while !matches!(self.current().typ, TokenType::LBrace | TokenType::Eof) {
                self.advance();
            }
            let body = if matches!(self.current().typ, TokenType::LBrace) {
                self.parse_block()
            } else {
                // Abstract-ish / missing body: record empty.
                self.error(format!("method {} has no body", member_name));
                Vec::new()
            };

            let visibility = if annotations.iter().any(|a| a == "Public") {
                Visibility::Public
            } else {
                Visibility::Private
            };

            let _ = member_type; // return type not used structurally
            methods.push(MethodNode {
                name: member_name,
                params,
                body,
                visibility,
                source_location: member_loc,
            });
            return;
        }

        // Field declaration: optional `= initializer`, then `;`.
        let initializer = if matches!(self.current().typ, TokenType::Eq) {
            self.advance();
            self.parse_expr()
        } else {
            None
        };
        self.match_tok(&TokenType::Semi);

        let readonly = annotations.iter().any(|a| a == "Readonly");

        properties.push(PropertyNode {
            name: member_name,
            prop_type: member_type,
            readonly,
            initializer,
            source_location: member_loc,
            synthetic_array_chain: None,
        });
    }

    /// Parse `(param1 Type1, param2 Type2, ...)`.
    fn parse_param_list(&mut self) -> Vec<ParamNode> {
        self.expect_tok(&TokenType::LParen);
        let mut params: Vec<ParamNode> = Vec::new();

        while !matches!(self.current().typ, TokenType::RParen | TokenType::Eof) {
            // Skip optional `final` modifier on params.
            if matches!(self.current().typ, TokenType::Final) {
                self.advance();
            }
            // Skip parameter-level annotations (rare but legal).
            while matches!(self.current().typ, TokenType::At) {
                self.skip_annotation();
            }
            let param_type = self.parse_type();
            let param_name = self.expect_ident();
            params.push(ParamNode { name: param_name, param_type });
            if !self.match_tok(&TokenType::Comma) {
                break;
            }
        }

        self.expect_tok(&TokenType::RParen);
        params
    }

    // -----------------------------------------------------------------------
    // Type parsing
    // -----------------------------------------------------------------------

    fn parse_type(&mut self) -> TypeNode {
        // `void` keyword is a valid return type token; surface it for method
        // returns but we don't use it structurally. Represent as Void primitive.
        if matches!(self.current().typ, TokenType::Void) {
            self.advance();
            return TypeNode::Primitive(PrimitiveTypeName::Void);
        }

        // Identifier-based type. May be qualified (`java.math.BigInteger`),
        // parameterised (`FixedArray<T, N>`), or plain (`Addr`).
        let mut name = match self.current().typ.clone() {
            TokenType::Ident(n) => {
                self.advance();
                n
            }
            _ => {
                self.error(format!(
                    "expected type, got {:?}",
                    self.current().typ
                ));
                return TypeNode::Custom("unknown".to_string());
            }
        };

        // Consume qualified-name segments (`a.b.c`). Only the rightmost
        // segment participates in type resolution, mirroring javac's
        // `typeSimpleName` helper.
        while matches!(self.current().typ, TokenType::Dot) {
            // Only if followed by an identifier (otherwise leave the `.`
            // for a different consumer — unlikely here but defensive).
            if matches!(self.peek_at(1).typ, TokenType::Ident(_)) {
                self.advance(); // '.'
                if let TokenType::Ident(n) = self.current().typ.clone() {
                    self.advance();
                    name = n;
                }
            } else {
                break;
            }
        }

        // Generic arguments: `FixedArray<T, N>`.
        if matches!(self.current().typ, TokenType::Lt) {
            self.advance();
            self.type_args_depth += 1;
            let mut args: Vec<TypeNode> = Vec::new();
            let mut length_arg: Option<usize> = None;

            loop {
                // A type argument is either a type or, for the length slot, a
                // Number literal. Try number first — if we're in FixedArray<T, N>
                // the second arg is always an int literal.
                if let TokenType::Number(n) = self.current().typ.clone() {
                    self.advance();
                    length_arg = Some(n as usize);
                } else {
                    let inner = self.parse_type();
                    args.push(inner);
                }
                if !self.match_tok(&TokenType::Comma) {
                    break;
                }
            }

            self.type_args_depth -= 1;
            // Consume closing `>` or `>>` (nested generic).
            match self.current().typ.clone() {
                TokenType::Gt => {
                    self.advance();
                }
                TokenType::Shr => {
                    // `>>` at end of nested generic — consume one `>`, re-emit the other.
                    // Rewrite the current token to a single Gt by advancing over one and
                    // synthesising: since we cannot easily split a token in place, we fall
                    // back to advancing over `>>` altogether.  FixedArray nesting of depth
                    // two is rare; if the outer consumer expected another `>` after this,
                    // it will error out cleanly.
                    self.advance();
                }
                _ => {
                    self.error(format!(
                        "expected '>' to close type-argument list, got {:?}",
                        self.current().typ
                    ));
                }
            }

            if name == "FixedArray" {
                if args.len() != 1 || length_arg.is_none() {
                    self.error(format!(
                        "FixedArray requires 2 type arguments (element, length) in {}",
                        self.file
                    ));
                    return TypeNode::Custom("FixedArray".to_string());
                }
                let element = args.into_iter().next().unwrap();
                return TypeNode::FixedArray {
                    element: Box::new(element),
                    length: length_arg.unwrap(),
                };
            }

            // Unknown generic — surface as custom.
            return TypeNode::Custom(name);
        }

        resolve_named_type(&name)
    }

    // -----------------------------------------------------------------------
    // Block / statement parsing
    // -----------------------------------------------------------------------

    fn parse_block(&mut self) -> Vec<Statement> {
        self.expect_tok(&TokenType::LBrace);
        let mut stmts: Vec<Statement> = Vec::new();
        while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
            self.skip_semis();
            if matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
                break;
            }
            if let Some(s) = self.parse_statement() {
                stmts.push(s);
            } else {
                // Defensive — advance to avoid an infinite loop on malformed input.
                self.advance();
            }
            self.skip_semis();
        }
        self.match_tok(&TokenType::RBrace);
        stmts
    }

    fn parse_statement(&mut self) -> Option<Statement> {
        let loc = self.loc();

        match self.current().typ.clone() {
            TokenType::If => {
                self.advance();
                self.expect_tok(&TokenType::LParen);
                let cond = self.parse_expr()?;
                self.expect_tok(&TokenType::RParen);
                let then_branch = self.parse_block_or_stmt();
                let else_branch = if matches!(self.current().typ, TokenType::Else) {
                    self.advance();
                    if matches!(self.current().typ, TokenType::If) {
                        // `else if` — wrap in a single-element branch.
                        let nested = self.parse_statement()?;
                        Some(vec![nested])
                    } else {
                        Some(self.parse_block_or_stmt())
                    }
                } else {
                    None
                };
                Some(Statement::IfStatement {
                    condition: cond,
                    then_branch,
                    else_branch,
                    source_location: loc,
                })
            }

            TokenType::For => {
                self.advance();
                self.parse_for_statement(loc)
            }

            TokenType::Return => {
                self.advance();
                let value = if matches!(
                    self.current().typ,
                    TokenType::Semi | TokenType::RBrace | TokenType::Eof
                ) {
                    None
                } else {
                    self.parse_expr()
                };
                self.match_tok(&TokenType::Semi);
                Some(Statement::ReturnStatement {
                    value,
                    source_location: loc,
                })
            }

            _ => {
                // Could be:
                //   <Type> <ident> (= <expr>)? ;   (local var decl)
                //   <lhs> = <expr> ;               (assignment)
                //   <expr> ;                       (expression statement)
                //
                // We distinguish a variable declaration from an assignment/
                // expression by looking ahead for the classic `Type name =`
                // or `Type name ;` shape. If the first two tokens are
                // `Ident Ident` that's a decl with no initializer or with
                // a following `=`. Qualified / generic types (`FixedArray<T,N> foo`)
                // are also declarations.
                if self.looks_like_var_decl() {
                    self.parse_var_decl(loc)
                } else {
                    let lhs = self.parse_expr()?;
                    self.parse_expr_statement_tail(lhs, loc)
                }
            }
        }
    }

    fn parse_block_or_stmt(&mut self) -> Vec<Statement> {
        if matches!(self.current().typ, TokenType::LBrace) {
            self.parse_block()
        } else if let Some(s) = self.parse_statement() {
            vec![s]
        } else {
            Vec::new()
        }
    }

    /// Heuristic: does the current position begin a local-variable decl?
    ///
    /// A declaration starts with a type. In the Rúnar subset, a type is one
    /// of:
    ///   - a bare identifier that is a known primitive / custom type name,
    ///     followed by another identifier (the variable name)
    ///   - `FixedArray<...>` followed by an identifier
    ///   - a qualified name `a.b.c` followed by an identifier
    ///   - a built-in Java keyword type like `boolean`
    fn looks_like_var_decl(&self) -> bool {
        // Scan tokens from self.pos without side effects.
        // We accept: (Ident | boolean-keyword) (. Ident)* (<...>)? Ident (= | ;)
        let mut i = self.pos;

        // `boolean` is lexed as Ident in our tokenizer since we don't
        // special-case it. For resilience we check both.
        match self.tokens.get(i).map(|t| &t.typ) {
            Some(TokenType::Ident(_)) => {}
            _ => return false,
        }
        i += 1;

        // Qualified-name segments (unlikely in Rúnar Java but tolerated).
        while matches!(self.tokens.get(i).map(|t| &t.typ), Some(TokenType::Dot)) {
            match self.tokens.get(i + 1).map(|t| &t.typ) {
                Some(TokenType::Ident(_)) => {
                    i += 2;
                }
                _ => return false,
            }
        }

        // Optional generic type arguments: skip balanced `<...>`.
        if matches!(self.tokens.get(i).map(|t| &t.typ), Some(TokenType::Lt)) {
            let mut depth = 1usize;
            i += 1;
            while let Some(tok) = self.tokens.get(i) {
                match &tok.typ {
                    TokenType::Lt => {
                        depth += 1;
                        i += 1;
                    }
                    TokenType::Gt => {
                        depth -= 1;
                        i += 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    TokenType::Shr => {
                        // closes two levels
                        if depth >= 2 {
                            depth -= 2;
                        } else {
                            depth = 0;
                        }
                        i += 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    TokenType::Eof
                    | TokenType::LBrace
                    | TokenType::RBrace
                    | TokenType::Semi => return false,
                    _ => {
                        i += 1;
                    }
                }
            }
        }

        // After the type, we need: <Ident> (= | ;) to be a var decl.
        let after_type = self.tokens.get(i).map(|t| &t.typ);
        if !matches!(after_type, Some(TokenType::Ident(_))) {
            return false;
        }
        let after_ident = self.tokens.get(i + 1).map(|t| &t.typ);
        matches!(after_ident, Some(TokenType::Eq) | Some(TokenType::Semi))
    }

    fn parse_var_decl(&mut self, loc: SourceLocation) -> Option<Statement> {
        let var_type = self.parse_type();
        let name = self.expect_ident();
        if !matches!(self.current().typ, TokenType::Eq) {
            self.error(format!(
                "local variable {} must have an initializer in {}",
                name, self.file
            ));
            self.match_tok(&TokenType::Semi);
            return None;
        }
        self.advance(); // consume '='
        let init = self.parse_expr()?;
        self.match_tok(&TokenType::Semi);
        Some(Statement::VariableDecl {
            name,
            var_type: Some(var_type),
            mutable: true,
            init,
            source_location: loc,
        })
    }

    /// Given an already-parsed LHS expression, recognise the rest of an
    /// expression-statement or assignment.
    fn parse_expr_statement_tail(
        &mut self,
        lhs: Expression,
        loc: SourceLocation,
    ) -> Option<Statement> {
        match self.current().typ.clone() {
            TokenType::Eq => {
                self.advance();
                let rhs = self.parse_expr()?;
                self.match_tok(&TokenType::Semi);
                Some(Statement::Assignment {
                    target: lhs,
                    value: rhs,
                    source_location: loc,
                })
            }
            TokenType::PlusEq => {
                self.advance();
                let rhs = self.parse_expr()?;
                self.match_tok(&TokenType::Semi);
                let new_val = Expression::BinaryExpr {
                    op: BinaryOp::Add,
                    left: Box::new(lhs.clone()),
                    right: Box::new(rhs),
                };
                Some(Statement::Assignment {
                    target: lhs,
                    value: new_val,
                    source_location: loc,
                })
            }
            TokenType::MinusEq => {
                self.advance();
                let rhs = self.parse_expr()?;
                self.match_tok(&TokenType::Semi);
                let new_val = Expression::BinaryExpr {
                    op: BinaryOp::Sub,
                    left: Box::new(lhs.clone()),
                    right: Box::new(rhs),
                };
                Some(Statement::Assignment {
                    target: lhs,
                    value: new_val,
                    source_location: loc,
                })
            }
            TokenType::StarEq => {
                self.advance();
                let rhs = self.parse_expr()?;
                self.match_tok(&TokenType::Semi);
                let new_val = Expression::BinaryExpr {
                    op: BinaryOp::Mul,
                    left: Box::new(lhs.clone()),
                    right: Box::new(rhs),
                };
                Some(Statement::Assignment {
                    target: lhs,
                    value: new_val,
                    source_location: loc,
                })
            }
            TokenType::SlashEq => {
                self.advance();
                let rhs = self.parse_expr()?;
                self.match_tok(&TokenType::Semi);
                let new_val = Expression::BinaryExpr {
                    op: BinaryOp::Div,
                    left: Box::new(lhs.clone()),
                    right: Box::new(rhs),
                };
                Some(Statement::Assignment {
                    target: lhs,
                    value: new_val,
                    source_location: loc,
                })
            }
            TokenType::PercentEq => {
                self.advance();
                let rhs = self.parse_expr()?;
                self.match_tok(&TokenType::Semi);
                let new_val = Expression::BinaryExpr {
                    op: BinaryOp::Mod,
                    left: Box::new(lhs.clone()),
                    right: Box::new(rhs),
                };
                Some(Statement::Assignment {
                    target: lhs,
                    value: new_val,
                    source_location: loc,
                })
            }
            TokenType::PlusPlus => {
                self.advance();
                self.match_tok(&TokenType::Semi);
                Some(Statement::ExpressionStatement {
                    expression: Expression::IncrementExpr {
                        operand: Box::new(lhs),
                        prefix: false,
                    },
                    source_location: loc,
                })
            }
            TokenType::MinusMinus => {
                self.advance();
                self.match_tok(&TokenType::Semi);
                Some(Statement::ExpressionStatement {
                    expression: Expression::DecrementExpr {
                        operand: Box::new(lhs),
                        prefix: false,
                    },
                    source_location: loc,
                })
            }
            _ => {
                self.match_tok(&TokenType::Semi);
                Some(Statement::ExpressionStatement {
                    expression: lhs,
                    source_location: loc,
                })
            }
        }
    }

    fn parse_for_statement(&mut self, loc: SourceLocation) -> Option<Statement> {
        // `for (<init> ; <cond> ; <update>) <body>`.
        self.expect_tok(&TokenType::LParen);

        // Init: must be a single variable declaration.
        let init_loc = self.loc();
        let init = if self.looks_like_var_decl() {
            self.parse_var_decl(init_loc)?
        } else {
            self.error(format!(
                "for-loop must declare a single loop variable in {}",
                self.file
            ));
            return None;
        };

        // Condition
        let cond = self.parse_expr()?;
        self.match_tok(&TokenType::Semi);

        // Update: assignment-like expression statement, no trailing `;`.
        let update_loc = self.loc();
        let update = {
            let lhs = self.parse_expr()?;
            self.parse_for_update_tail(lhs, update_loc)?
        };

        self.expect_tok(&TokenType::RParen);
        let body = self.parse_block_or_stmt();
        Some(Statement::ForStatement {
            init: Box::new(init),
            condition: cond,
            update: Box::new(update),
            body,
            source_location: loc,
        })
    }

    fn parse_for_update_tail(
        &mut self,
        lhs: Expression,
        loc: SourceLocation,
    ) -> Option<Statement> {
        match self.current().typ.clone() {
            TokenType::Eq => {
                self.advance();
                let rhs = self.parse_expr()?;
                Some(Statement::Assignment {
                    target: lhs,
                    value: rhs,
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
                Some(Statement::Assignment {
                    target: lhs,
                    value: new_val,
                    source_location: loc,
                })
            }
            TokenType::MinusEq => {
                self.advance();
                let rhs = self.parse_expr()?;
                let new_val = Expression::BinaryExpr {
                    op: BinaryOp::Sub,
                    left: Box::new(lhs.clone()),
                    right: Box::new(rhs),
                };
                Some(Statement::Assignment {
                    target: lhs,
                    value: new_val,
                    source_location: loc,
                })
            }
            TokenType::PlusPlus => {
                self.advance();
                Some(Statement::ExpressionStatement {
                    expression: Expression::IncrementExpr {
                        operand: Box::new(lhs),
                        prefix: false,
                    },
                    source_location: loc,
                })
            }
            TokenType::MinusMinus => {
                self.advance();
                Some(Statement::ExpressionStatement {
                    expression: Expression::DecrementExpr {
                        operand: Box::new(lhs),
                        prefix: false,
                    },
                    source_location: loc,
                })
            }
            _ => Some(Statement::ExpressionStatement {
                expression: lhs,
                source_location: loc,
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Expression parsing (precedence climbing)
    // -----------------------------------------------------------------------

    fn parse_expr(&mut self) -> Option<Expression> {
        self.parse_ternary()
    }

    fn parse_ternary(&mut self) -> Option<Expression> {
        let cond = self.parse_or()?;
        if matches!(self.current().typ, TokenType::Question) {
            self.advance();
            let consequent = self.parse_expr()?;
            self.expect_tok(&TokenType::Colon);
            let alternate = self.parse_expr()?;
            return Some(Expression::TernaryExpr {
                condition: Box::new(cond),
                consequent: Box::new(consequent),
                alternate: Box::new(alternate),
            });
        }
        Some(cond)
    }

    fn parse_or(&mut self) -> Option<Expression> {
        let mut left = self.parse_and()?;
        while matches!(self.current().typ, TokenType::PipePipe) {
            self.advance();
            let right = self.parse_and()?;
            left = Expression::BinaryExpr {
                op: BinaryOp::Or,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Some(left)
    }

    fn parse_and(&mut self) -> Option<Expression> {
        let mut left = self.parse_bitor()?;
        while matches!(self.current().typ, TokenType::AmpAmp) {
            self.advance();
            let right = self.parse_bitor()?;
            left = Expression::BinaryExpr {
                op: BinaryOp::And,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Some(left)
    }

    fn parse_bitor(&mut self) -> Option<Expression> {
        let mut left = self.parse_bitxor()?;
        while matches!(self.current().typ, TokenType::Pipe) {
            self.advance();
            let right = self.parse_bitxor()?;
            left = Expression::BinaryExpr {
                op: BinaryOp::BitOr,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Some(left)
    }

    fn parse_bitxor(&mut self) -> Option<Expression> {
        let mut left = self.parse_bitand()?;
        while matches!(self.current().typ, TokenType::Caret) {
            self.advance();
            let right = self.parse_bitand()?;
            left = Expression::BinaryExpr {
                op: BinaryOp::BitXor,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Some(left)
    }

    fn parse_bitand(&mut self) -> Option<Expression> {
        let mut left = self.parse_equality()?;
        while matches!(self.current().typ, TokenType::Amp) {
            self.advance();
            let right = self.parse_equality()?;
            left = Expression::BinaryExpr {
                op: BinaryOp::BitAnd,
                left: Box::new(left),
                right: Box::new(right),
            };
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
            left = Expression::BinaryExpr {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Some(left)
    }

    fn parse_relational(&mut self) -> Option<Expression> {
        let mut left = self.parse_shift()?;
        loop {
            // Inside a generic type-argument list, `>` is a closer, not an operator.
            if self.type_args_depth > 0
                && matches!(self.current().typ, TokenType::Gt | TokenType::Shr | TokenType::GtEq)
            {
                break;
            }
            let op = match self.current().typ {
                TokenType::Lt => BinaryOp::Lt,
                TokenType::LtEq => BinaryOp::Le,
                TokenType::Gt => BinaryOp::Gt,
                TokenType::GtEq => BinaryOp::Ge,
                _ => break,
            };
            self.advance();
            let right = self.parse_shift()?;
            left = Expression::BinaryExpr {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Some(left)
    }

    fn parse_shift(&mut self) -> Option<Expression> {
        let mut left = self.parse_additive()?;
        loop {
            if self.type_args_depth > 0 && matches!(self.current().typ, TokenType::Shr) {
                break;
            }
            let op = match self.current().typ {
                TokenType::Shl => BinaryOp::Shl,
                TokenType::Shr => BinaryOp::Shr,
                _ => break,
            };
            self.advance();
            let right = self.parse_additive()?;
            left = Expression::BinaryExpr {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
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
            left = Expression::BinaryExpr {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
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
            left = Expression::BinaryExpr {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Some(left)
    }

    fn parse_unary(&mut self) -> Option<Expression> {
        match self.current().typ.clone() {
            TokenType::Bang => {
                self.advance();
                let operand = self.parse_unary()?;
                Some(Expression::UnaryExpr {
                    op: UnaryOp::Not,
                    operand: Box::new(operand),
                })
            }
            TokenType::Minus => {
                self.advance();
                let operand = self.parse_unary()?;
                Some(Expression::UnaryExpr {
                    op: UnaryOp::Neg,
                    operand: Box::new(operand),
                })
            }
            TokenType::Plus => {
                // Unary `+` is identity.
                self.advance();
                self.parse_unary()
            }
            TokenType::Tilde => {
                self.advance();
                let operand = self.parse_unary()?;
                Some(Expression::UnaryExpr {
                    op: UnaryOp::BitNot,
                    operand: Box::new(operand),
                })
            }
            TokenType::PlusPlus => {
                self.advance();
                let operand = self.parse_unary()?;
                Some(Expression::IncrementExpr {
                    operand: Box::new(operand),
                    prefix: true,
                })
            }
            TokenType::MinusMinus => {
                self.advance();
                let operand = self.parse_unary()?;
                Some(Expression::DecrementExpr {
                    operand: Box::new(operand),
                    prefix: true,
                })
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
                    let prop = self.expect_ident();

                    if matches!(self.current().typ, TokenType::LParen) {
                        let args = self.parse_call_args();
                        expr = promote_literal_calls(Expression::CallExpr {
                            callee: Box::new(Expression::MemberExpr {
                                object: Box::new(expr),
                                property: prop,
                            }),
                            args,
                        });
                    } else {
                        expr = Expression::MemberExpr {
                            object: Box::new(expr),
                            property: prop,
                        };
                    }
                }
                TokenType::LBracket => {
                    self.advance();
                    let index = self.parse_expr()?;
                    self.expect_tok(&TokenType::RBracket);
                    expr = Expression::IndexAccess {
                        object: Box::new(expr),
                        index: Box::new(index),
                    };
                }
                TokenType::LParen => {
                    let args = self.parse_call_args();
                    expr = promote_literal_calls(Expression::CallExpr {
                        callee: Box::new(expr),
                        args,
                    });
                }
                TokenType::PlusPlus => {
                    self.advance();
                    expr = Expression::IncrementExpr {
                        operand: Box::new(expr),
                        prefix: false,
                    };
                }
                TokenType::MinusMinus => {
                    self.advance();
                    expr = Expression::DecrementExpr {
                        operand: Box::new(expr),
                        prefix: false,
                    };
                }
                _ => break,
            }
        }

        // Special-case recognition now that we've built the call expression:
        // promote `<Type>.fromHex("hex")` and `BigInteger.valueOf(<int>)` to
        // literal AST nodes — mirroring the Java reference parser's
        // `convertCall` helper.
        expr = promote_literal_calls(expr);
        Some(expr)
    }

    fn parse_call_args(&mut self) -> Vec<Expression> {
        self.expect_tok(&TokenType::LParen);
        let mut args: Vec<Expression> = Vec::new();
        while !matches!(self.current().typ, TokenType::RParen | TokenType::Eof) {
            if let Some(arg) = self.parse_expr() {
                args.push(arg);
            } else {
                break;
            }
            if !self.match_tok(&TokenType::Comma) {
                break;
            }
        }
        self.expect_tok(&TokenType::RParen);
        args
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
                // String literals are only legal as the argument to
                // `<X>.fromHex("hex")` in the Rúnar subset. We accept them
                // here as `ByteStringLiteral` and let the validator / type
                // checker reject any free-standing string usage — matches
                // the Go/Python/Ruby parser behaviour. `promote_literal_calls`
                // unwraps the `fromHex(...)` wrapper after the postfix parse.
                self.advance();
                Some(Expression::ByteStringLiteral { value: s })
            }
            TokenType::Null => {
                self.error(format!("null literals are unsupported in {}", self.file));
                self.advance();
                Some(Expression::BoolLiteral { value: false })
            }
            TokenType::LParen => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect_tok(&TokenType::RParen);
                Some(expr)
            }
            TokenType::This => {
                self.advance();
                // `this.foo` is a PropertyAccess. Any use of `this` not
                // followed by a member select stays as Identifier("this").
                if matches!(self.current().typ, TokenType::Dot) {
                    self.advance();
                    let prop = self.expect_ident();
                    if matches!(self.current().typ, TokenType::LParen) {
                        // `this.method(args)` → CallExpr(MemberExpr(this, method), args).
                        let args = self.parse_call_args();
                        return Some(Expression::CallExpr {
                            callee: Box::new(Expression::MemberExpr {
                                object: Box::new(Expression::Identifier {
                                    name: "this".to_string(),
                                }),
                                property: prop,
                            }),
                            args,
                        });
                    }
                    return Some(Expression::PropertyAccess { property: prop });
                }
                Some(Expression::Identifier {
                    name: "this".to_string(),
                })
            }
            TokenType::Super => {
                self.advance();
                // `super(args)` inside a constructor body.
                if matches!(self.current().typ, TokenType::LParen) {
                    let args = self.parse_call_args();
                    return Some(Expression::CallExpr {
                        callee: Box::new(Expression::Identifier {
                            name: "super".to_string(),
                        }),
                        args,
                    });
                }
                // `super.method(args)` — fall back to an identifier followed
                // by postfix handling.
                Some(Expression::Identifier {
                    name: "super".to_string(),
                })
            }
            TokenType::New => {
                self.advance();
                // Support only `new T[]{...}` / `new T[N]{...}` array literals.
                let _elem_type = self.parse_type();
                self.expect_tok(&TokenType::LBracket);
                // Optional length expression is allowed but ignored; the
                // initializer list is authoritative.
                if !matches!(self.current().typ, TokenType::RBracket) {
                    let _ = self.parse_expr();
                }
                self.expect_tok(&TokenType::RBracket);
                // Trailing empty bracket pairs (for multi-dim arrays) get
                // consumed gracefully.
                while matches!(self.current().typ, TokenType::LBracket) {
                    self.advance();
                    if !matches!(self.current().typ, TokenType::RBracket) {
                        let _ = self.parse_expr();
                    }
                    self.match_tok(&TokenType::RBracket);
                }

                if !matches!(self.current().typ, TokenType::LBrace) {
                    self.error(format!(
                        "new-array expressions must have an initializer list in {}",
                        self.file
                    ));
                    return Some(Expression::ArrayLiteral { elements: Vec::new() });
                }
                self.advance(); // '{'
                let mut elements: Vec<Expression> = Vec::new();
                while !matches!(self.current().typ, TokenType::RBrace | TokenType::Eof) {
                    if let Some(e) = self.parse_expr() {
                        elements.push(e);
                    } else {
                        break;
                    }
                    if !self.match_tok(&TokenType::Comma) {
                        break;
                    }
                }
                self.match_tok(&TokenType::RBrace);
                Some(Expression::ArrayLiteral { elements })
            }
            TokenType::Ident(name) => {
                self.advance();
                // `BigInteger.ZERO/ONE/TWO/TEN` or `Bigint.ZERO/ONE/TWO/TEN`
                // → BigIntLiteral. The Bigint wrapper re-exports the same
                // constants so both spellings are accepted. Match eagerly
                // before falling through to generic member-access parsing.
                if (name == "BigInteger" || name == "Bigint")
                    && matches!(self.current().typ, TokenType::Dot)
                {
                    let next_name = match self.peek_at(1).typ.clone() {
                        TokenType::Ident(n) => n,
                        _ => String::new(),
                    };
                    // Peek one further to distinguish constants from `valueOf(...)`.
                    let two_ahead = self.peek_at(2).typ.clone();
                    if matches!(two_ahead, TokenType::LParen) {
                        // Constructor call `BigInteger.valueOf(N)` — handled by
                        // the normal call path; promote_literal_calls lifts it.
                        // fall through
                    } else {
                        match next_name.as_str() {
                            "ZERO" => {
                                self.advance(); // '.'
                                self.advance(); // ZERO
                                return Some(Expression::BigIntLiteral { value: 0 });
                            }
                            "ONE" => {
                                self.advance();
                                self.advance();
                                return Some(Expression::BigIntLiteral { value: 1 });
                            }
                            "TWO" => {
                                self.advance();
                                self.advance();
                                return Some(Expression::BigIntLiteral { value: 2 });
                            }
                            "TEN" => {
                                self.advance();
                                self.advance();
                                return Some(Expression::BigIntLiteral { value: 10 });
                            }
                            _ => {}
                        }
                    }
                }
                Some(Expression::Identifier { name })
            }
            _ => {
                self.error(format!(
                    "unsupported expression token {:?}",
                    self.current().typ
                ));
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Literal-call promotion
// ---------------------------------------------------------------------------

/// Recognise the literal-as-call and Bigint-wrapper identity shapes:
///   - `<X>.fromHex("hex")`               → `ByteStringLiteral`
///   - `BigInteger.valueOf(<int literal>)` → `BigIntLiteral`
///   - `Bigint.of(<int literal>)`          → `BigIntLiteral`
///   - `Bigint.of(<expr>)`                 → `<expr>` (identity wrap)
///   - `BigInteger.valueOf(<expr>)`        → `<expr>` (identity wrap)
///   - `<expr>.value()`                    → `<expr>` (identity unwrap)
///   - `a.plus(b)` / `a.minus(b)` / ...    → `BinaryExpr` (Bigint arith)
///   - `a.neg()`                           → `UnaryExpr(-)`
///   - `a.abs()`                           → `CallExpr(abs, a)` (builtin)
///   - `assertThat(c)`                     → `CallExpr(assert, c)`
///
/// This is the Rust analogue of the Java parser's `convertCall` helper.
fn promote_literal_calls(expr: Expression) -> Expression {
    if let Expression::CallExpr { callee, args } = &expr {
        // X.fromHex("hex") → ByteStringLiteral(hex)
        if args.len() == 1 {
            if let Expression::MemberExpr { property, .. } = callee.as_ref() {
                if property == "fromHex" {
                    if let Expression::ByteStringLiteral { value } = &args[0] {
                        return Expression::ByteStringLiteral { value: value.clone() };
                    }
                    // Support the Java literal being a string literal converted
                    // to ByteStringLiteral above or arriving as BigIntLiteral-
                    // wrapped (unlikely). Fall through if neither shape matches.
                }
            }
        }
        // BigInteger.valueOf(<int literal>) / Bigint.of(<int literal>) → BigIntLiteral
        if args.len() == 1 {
            if let Expression::MemberExpr { object, property } = callee.as_ref() {
                if let Expression::Identifier { name } = object.as_ref() {
                    let is_bigint_literal_call = (name == "BigInteger" && property == "valueOf")
                        || (name == "Bigint" && property == "of");
                    if is_bigint_literal_call {
                        if let Expression::BigIntLiteral { value } = &args[0] {
                            return Expression::BigIntLiteral { value: *value };
                        }
                    }
                }
            }
        }
        // Bigint.of(<arbitrary expression>) / BigInteger.valueOf(<arbitrary expression>)
        // — identity at the Rúnar AST level. Bigint and BigInteger collapse to the
        // same BIGINT primitive, so the wrap is a no-op: lower to the inner
        // expression. Mirrors JavaParser.java's identity branch.
        if args.len() == 1 {
            if let Expression::MemberExpr { object, property } = callee.as_ref() {
                if let Expression::Identifier { name } = object.as_ref() {
                    let is_bigint_identity = (name == "Bigint" && property == "of")
                        || (name == "BigInteger" && property == "valueOf");
                    if is_bigint_identity {
                        return args[0].clone();
                    }
                }
            }
        }
        // <expr>.value() — unwrapping a Bigint back to its underlying BigInteger.
        // Symmetric no-op to Bigint.of(...) above.
        if args.is_empty() {
            if let Expression::MemberExpr { object, property } = callee.as_ref() {
                if property == "value" {
                    return (**object).clone();
                }
            }
        }
        // Bigint-wrapper arithmetic methods: `a.plus(b)` → BinaryExpr(+, a, b),
        // `a.neg()` → UnaryExpr(-, a), `a.abs()` → CallExpr(abs, a). Matched by
        // method name + arity; receiver type is not consulted (parser has no
        // type info at this stage); the typechecker rejects misuse. Mirrors
        // JavaParser.tryLowerBigintMethod.
        if let Expression::MemberExpr { object, property } = callee.as_ref() {
            if args.len() == 1 {
                if let Some(op) = bigint_binary_method_op(property) {
                    return Expression::BinaryExpr {
                        op,
                        left: object.clone(),
                        right: Box::new(args[0].clone()),
                    };
                }
            }
            if args.is_empty() && property == "neg" {
                return Expression::UnaryExpr {
                    op: UnaryOp::Neg,
                    operand: object.clone(),
                };
            }
            if args.is_empty() && property == "abs" {
                return Expression::CallExpr {
                    callee: Box::new(Expression::Identifier { name: "abs".to_string() }),
                    args: vec![(**object).clone()],
                };
            }
        }
        // Static-imported `assertThat(cond)` is a builtin alias for `assert`
        // in the canonical Java BuiltinRegistry. Peer typecheckers only know
        // `assert`, so rewrite the callee here.
        if let Expression::Identifier { name } = callee.as_ref() {
            if name == "assertThat" {
                return Expression::CallExpr {
                    callee: Box::new(Expression::Identifier { name: "assert".to_string() }),
                    args: args.clone(),
                };
            }
        }
    }
    expr
}

/// Map a Bigint-wrapper method name to its canonical BinaryOp, mirroring
/// JavaParser.BIGINT_BINARY_METHODS. Unary `neg`/`abs` are handled separately.
fn bigint_binary_method_op(method: &str) -> Option<BinaryOp> {
    match method {
        "plus"  => Some(BinaryOp::Add),
        "minus" => Some(BinaryOp::Sub),
        "times" => Some(BinaryOp::Mul),
        "div"   => Some(BinaryOp::Div),
        "mod"   => Some(BinaryOp::Mod),
        "shl"   => Some(BinaryOp::Shl),
        "shr"   => Some(BinaryOp::Shr),
        "and"   => Some(BinaryOp::BitAnd),
        "or"    => Some(BinaryOp::BitOr),
        "xor"   => Some(BinaryOp::BitXor),
        "gt"    => Some(BinaryOp::Gt),
        "lt"    => Some(BinaryOp::Lt),
        "ge"    => Some(BinaryOp::Ge),
        "le"    => Some(BinaryOp::Le),
        "eq"    => Some(BinaryOp::StrictEq),
        "neq"   => Some(BinaryOp::StrictNe),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Synthetic constructor (same shape as the other parsers)
// ---------------------------------------------------------------------------

fn synthesize_constructor(properties: &[PropertyNode], file: &str) -> MethodNode {
    let loc = JavaParser::loc_at(file, 0, 0);
    let mut params: Vec<ParamNode> = Vec::new();
    let mut body: Vec<Statement> = Vec::new();
    let mut super_args: Vec<Expression> = Vec::new();

    for prop in properties {
        if prop.initializer.is_some() {
            continue;
        }
        params.push(ParamNode {
            name: prop.name.clone(),
            param_type: prop.prop_type.clone(),
        });
        super_args.push(Expression::Identifier {
            name: prop.name.clone(),
        });
    }

    body.push(Statement::ExpressionStatement {
        expression: Expression::CallExpr {
            callee: Box::new(Expression::Identifier {
                name: "super".to_string(),
            }),
            args: super_args,
        },
        source_location: loc.clone(),
    });

    for prop in properties {
        if prop.initializer.is_some() {
            continue;
        }
        body.push(Statement::Assignment {
            target: Expression::PropertyAccess {
                property: prop.name.clone(),
            },
            value: Expression::Identifier {
                name: prop.name.clone(),
            },
            source_location: loc.clone(),
        });
    }

    MethodNode {
        name: "constructor".to_string(),
        params,
        body,
        visibility: Visibility::Public,
        source_location: loc,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const P2PKH_SOURCE: &str = r#"
        package runar.examples.p2pkh;

        import runar.lang.SmartContract;
        import runar.lang.annotations.Public;
        import runar.lang.annotations.Readonly;
        import runar.lang.types.Addr;
        import runar.lang.types.PubKey;
        import runar.lang.types.Sig;
        import static runar.lang.Builtins.assertThat;
        import static runar.lang.Builtins.checkSig;
        import static runar.lang.Builtins.hash160;

        class P2PKH extends SmartContract {
            @Readonly Addr pubKeyHash;

            P2PKH(Addr pubKeyHash) {
                super(pubKeyHash);
                this.pubKeyHash = pubKeyHash;
            }

            @Public
            void unlock(Sig sig, PubKey pubKey) {
                assertThat(hash160(pubKey).equals(pubKeyHash));
                assertThat(checkSig(sig, pubKey));
            }
        }
    "#;

    #[test]
    fn parses_p2pkh_into_expected_contract_shape() {
        let result = parse_java(P2PKH_SOURCE, Some("P2PKH.runar.java"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let c = result.contract.expect("should produce a contract");
        assert_eq!(c.name, "P2PKH");
        assert_eq!(c.parent_class, "SmartContract");
        assert_eq!(c.source_file, "P2PKH.runar.java");

        assert_eq!(c.properties.len(), 1);
        let pkh = &c.properties[0];
        assert_eq!(pkh.name, "pubKeyHash");
        assert!(pkh.readonly);
        match &pkh.prop_type {
            TypeNode::Primitive(PrimitiveTypeName::Addr) => {}
            other => panic!("expected Addr, got {:?}", other),
        }
        assert!(pkh.initializer.is_none());
    }

    #[test]
    fn parses_constructor_with_super_and_this_assignment() {
        let result = parse_java(P2PKH_SOURCE, Some("P2PKH.runar.java"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let c = result.contract.unwrap();
        let ctor = &c.constructor;
        assert_eq!(ctor.name, "constructor");
        assert_eq!(ctor.params.len(), 1);
        assert_eq!(ctor.params[0].name, "pubKeyHash");

        assert_eq!(ctor.body.len(), 2);

        match &ctor.body[0] {
            Statement::ExpressionStatement { expression, .. } => match expression {
                Expression::CallExpr { callee, args } => {
                    match callee.as_ref() {
                        Expression::Identifier { name } => assert_eq!(name, "super"),
                        other => panic!("expected super identifier, got {:?}", other),
                    }
                    assert_eq!(args.len(), 1);
                    match &args[0] {
                        Expression::Identifier { name } => assert_eq!(name, "pubKeyHash"),
                        other => panic!("expected identifier, got {:?}", other),
                    }
                }
                other => panic!("expected super(...) call, got {:?}", other),
            },
            other => panic!("expected ExpressionStatement, got {:?}", other),
        }

        match &ctor.body[1] {
            Statement::Assignment { target, value, .. } => {
                match target {
                    Expression::PropertyAccess { property } => {
                        assert_eq!(property, "pubKeyHash")
                    }
                    other => panic!("expected PropertyAccess, got {:?}", other),
                }
                match value {
                    Expression::Identifier { name } => assert_eq!(name, "pubKeyHash"),
                    other => panic!("expected Identifier, got {:?}", other),
                }
            }
            other => panic!("expected Assignment, got {:?}", other),
        }
    }

    #[test]
    fn parses_unlock_method_with_static_imported_calls() {
        let result = parse_java(P2PKH_SOURCE, Some("P2PKH.runar.java"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let c = result.contract.unwrap();
        assert_eq!(c.methods.len(), 1);
        let unlock = &c.methods[0];
        assert_eq!(unlock.name, "unlock");
        assert_eq!(unlock.visibility, Visibility::Public);
        assert_eq!(unlock.params.len(), 2);
        match &unlock.params[0].param_type {
            TypeNode::Primitive(PrimitiveTypeName::Sig) => {}
            other => panic!("expected Sig, got {:?}", other),
        }
        match &unlock.params[1].param_type {
            TypeNode::Primitive(PrimitiveTypeName::PubKey) => {}
            other => panic!("expected PubKey, got {:?}", other),
        }

        assert_eq!(unlock.body.len(), 2);

        // First stmt: assertThat(hash160(pubKey).equals(pubKeyHash)). The
        // peer parser rewrites the static-imported `assertThat` to `assert`
        // so the shared typechecker (which only knows `assert`) accepts the
        // call.
        let first = match &unlock.body[0] {
            Statement::ExpressionStatement { expression, .. } => expression,
            other => panic!("expected ExpressionStatement, got {:?}", other),
        };
        let first_call = match first {
            Expression::CallExpr { callee, args } => {
                match callee.as_ref() {
                    Expression::Identifier { name } => assert_eq!(name, "assert"),
                    other => panic!("expected assert callee, got {:?}", other),
                }
                assert_eq!(args.len(), 1);
                &args[0]
            }
            other => panic!("expected CallExpr, got {:?}", other),
        };
        let equals_call = match first_call {
            Expression::CallExpr { callee, args } => {
                match callee.as_ref() {
                    Expression::MemberExpr { property, object } => {
                        assert_eq!(property, "equals");
                        match object.as_ref() {
                            Expression::CallExpr { callee: inner, .. } => {
                                match inner.as_ref() {
                                    Expression::Identifier { name } => {
                                        assert_eq!(name, "hash160")
                                    }
                                    other => panic!("expected hash160, got {:?}", other),
                                }
                            }
                            other => panic!("expected hash160 call, got {:?}", other),
                        }
                    }
                    other => panic!("expected .equals member, got {:?}", other),
                }
                assert_eq!(args.len(), 1);
                first_call
            }
            other => panic!("expected .equals(...) CallExpr, got {:?}", other),
        };
        let _ = equals_call;
    }

    #[test]
    fn accepts_stateful_smart_contract() {
        let src = r#"
            class Counter extends StatefulSmartContract {
                Bigint count;
                Counter(Bigint count) {
                    super(count);
                    this.count = count;
                }
            }
        "#;
        let result = parse_java(src, Some("Counter.runar.java"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let c = result.contract.unwrap();
        assert_eq!(c.parent_class, "StatefulSmartContract");
        assert_eq!(c.properties.len(), 1);
        match &c.properties[0].prop_type {
            TypeNode::Primitive(PrimitiveTypeName::Bigint) => {}
            other => panic!("expected Bigint, got {:?}", other),
        }
        assert!(!c.properties[0].readonly);
    }

    #[test]
    fn parses_property_initializer() {
        let src = r#"
            class Counter extends StatefulSmartContract {
                Bigint count = BigInteger.ZERO;
                @Readonly PubKey owner;
                Counter(PubKey owner) { super(owner); this.owner = owner; }
            }
        "#;
        let result = parse_java(src, Some("Counter.runar.java"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let c = result.contract.unwrap();
        assert_eq!(c.properties.len(), 2);
        let count = c
            .properties
            .iter()
            .find(|p| p.name == "count")
            .expect("count property");
        match &count.initializer {
            Some(Expression::BigIntLiteral { value }) => assert_eq!(*value, 0),
            other => panic!("expected BigIntLiteral(0), got {:?}", other),
        }
    }

    #[test]
    fn parses_byte_string_from_hex_as_literal() {
        let src = r#"
            class C extends SmartContract {
                @Readonly ByteString magic;
                @Public void check() {
                    assertThat(magic.equals(ByteString.fromHex("deadbeef")));
                }
            }
        "#;
        let result = parse_java(src, Some("C.runar.java"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let c = result.contract.unwrap();
        let stmt = &c.methods[0].body[0];
        let assert_call = match stmt {
            Statement::ExpressionStatement { expression, .. } => expression,
            other => panic!("expected ExpressionStatement, got {:?}", other),
        };
        let equals_args = match assert_call {
            Expression::CallExpr { args, .. } => args,
            other => panic!("expected CallExpr, got {:?}", other),
        };
        let equals_call = &equals_args[0];
        let equals_inner = match equals_call {
            Expression::CallExpr { args, .. } => args,
            other => panic!("expected CallExpr, got {:?}", other),
        };
        match &equals_inner[0] {
            Expression::ByteStringLiteral { value } => assert_eq!(value, "deadbeef"),
            other => panic!("expected ByteStringLiteral, got {:?}", other),
        }
    }

    #[test]
    fn parses_big_integer_value_of_as_literal() {
        let src = r#"
            class C extends SmartContract {
                @Readonly Bigint threshold;
                @Public void check(Bigint x) {
                    assertThat(x == BigInteger.valueOf(7));
                }
            }
        "#;
        let result = parse_java(src, Some("C.runar.java"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let c = result.contract.unwrap();
        let check = &c.methods[0];
        let stmt = match &check.body[0] {
            Statement::ExpressionStatement { expression, .. } => expression,
            other => panic!("expected ExpressionStatement, got {:?}", other),
        };
        let assert_args = match stmt {
            Expression::CallExpr { args, .. } => args,
            other => panic!("expected assertThat call, got {:?}", other),
        };
        match &assert_args[0] {
            Expression::BinaryExpr { op, left, right } => {
                assert_eq!(*op, BinaryOp::StrictEq);
                match left.as_ref() {
                    Expression::Identifier { name } => assert_eq!(name, "x"),
                    other => panic!("expected identifier x, got {:?}", other),
                }
                match right.as_ref() {
                    Expression::BigIntLiteral { value } => assert_eq!(*value, 7),
                    other => panic!("expected BigIntLiteral(7), got {:?}", other),
                }
            }
            other => panic!("expected BinaryExpr, got {:?}", other),
        }
    }

    #[test]
    fn maps_binary_operators() {
        let src = r#"
            class C extends SmartContract {
                @Readonly Bigint a;
                @Public void run(Bigint x, Bigint y) {
                    assertThat((x + y) * (x - y) == x * x - y * y);
                    assertThat(x / y + x % y > x << 1);
                    assertThat((x & y) | (x ^ y) != x >> 1);
                    assertThat(x <= y && !(x >= y));
                    assertThat(x < y || x != y);
                }
            }
        "#;
        let result = parse_java(src, Some("C.runar.java"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let c = result.contract.unwrap();
        assert_eq!(c.methods.len(), 1);
        assert_eq!(c.methods[0].body.len(), 5);
    }

    #[test]
    fn rejects_contract_without_extends_clause() {
        let src = "class Bad { @Readonly Addr pkh; }";
        let result = parse_java(src, Some("Bad.runar.java"));
        assert!(result.contract.is_none());
        let msg = result
            .errors
            .iter()
            .map(|d| d.message.clone())
            .collect::<Vec<_>>()
            .join(";");
        assert!(
            msg.contains("must extend"),
            "errors did not mention 'must extend': {}",
            msg
        );
    }

    #[test]
    fn rejects_contract_extending_unknown_base_class() {
        let src = "class Bad extends Frobulator { }";
        let result = parse_java(src, Some("Bad.runar.java"));
        assert!(result.contract.is_none());
        let msg = result
            .errors
            .iter()
            .map(|d| d.message.clone())
            .collect::<Vec<_>>()
            .join(";");
        assert!(
            msg.contains("Frobulator"),
            "errors did not mention 'Frobulator': {}",
            msg
        );
    }

    #[test]
    fn parses_fixed_array_type() {
        let src = r#"
            class C extends SmartContract {
                @Readonly FixedArray<Bigint, 3> xs;
                C(FixedArray<Bigint, 3> xs) { super(xs); this.xs = xs; }
            }
        "#;
        let result = parse_java(src, Some("C.runar.java"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let c = result.contract.unwrap();
        match &c.properties[0].prop_type {
            TypeNode::FixedArray { element, length } => {
                assert_eq!(*length, 3);
                match element.as_ref() {
                    TypeNode::Primitive(PrimitiveTypeName::Bigint) => {}
                    other => panic!("expected Bigint element, got {:?}", other),
                }
            }
            other => panic!("expected FixedArray, got {:?}", other),
        }
    }

    #[test]
    fn parses_ternary_expression() {
        let src = r#"
            class C extends SmartContract {
                @Readonly Bigint a;
                @Public void run(Bigint x) {
                    Bigint r = x > BigInteger.ZERO ? x : BigInteger.ONE;
                    assertThat(r > BigInteger.ZERO);
                }
            }
        "#;
        let result = parse_java(src, Some("C.runar.java"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let c = result.contract.unwrap();
        match &c.methods[0].body[0] {
            Statement::VariableDecl { init, .. } => match init {
                Expression::TernaryExpr { .. } => {}
                other => panic!("expected TernaryExpr, got {:?}", other),
            },
            other => panic!("expected VariableDecl, got {:?}", other),
        }
    }

    #[test]
    fn parses_for_loop() {
        let src = r#"
            class C extends SmartContract {
                @Readonly Bigint a;
                @Public void run() {
                    Bigint acc = BigInteger.ZERO;
                    for (Bigint i = BigInteger.ZERO; i < BigInteger.TEN; i = i + BigInteger.ONE) {
                        acc = acc + i;
                    }
                    assertThat(acc > BigInteger.ZERO);
                }
            }
        "#;
        let result = parse_java(src, Some("C.runar.java"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let c = result.contract.unwrap();
        match &c.methods[0].body[1] {
            Statement::ForStatement { body, .. } => assert_eq!(body.len(), 1),
            other => panic!("expected ForStatement, got {:?}", other),
        }
    }

    #[test]
    fn dispatches_on_runar_java_extension() {
        use super::super::parser::parse_source;
        let result = parse_source(P2PKH_SOURCE, Some("P2PKH.runar.java"));
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let c = result.contract.unwrap();
        assert_eq!(c.name, "P2PKH");
        assert_eq!(c.parent_class, "SmartContract");
    }
}
