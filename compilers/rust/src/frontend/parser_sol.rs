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

use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use super::ast::{
    BinaryOp, ContractNode, Expression, MethodNode, ParamNode, PrimitiveTypeName, PropertyNode,
    SourceLocation, Statement, TypeNode, UnaryOp, Visibility,
};
use super::diagnostic::{char_index_positions, lex_error_at_index, unknown_return_type_message, Diagnostic, UNTERMINATED_STRING_LITERAL};
use super::sighash_directive::resolve_native_sighash;
use super::int_literal::{invalid_integer_literal, parse_int_literal, scan_number_end};
use super::input_limits::{enforce_ast_nesting, nesting_refusal, type_too_deep, DepthTracker, NestingCounter};
use super::parser::ParseResult;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a Solidity-format Rúnar contract source.
pub fn parse_solidity(source: &str, file_name: Option<&str>) -> ParseResult {
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
    super::input_limits::run_on_parse_stack(|| parse_solidity_on_parse_stack(source, file_name))
}

/// The body of [`parse_solidity`], on the parse stack segment.
fn parse_solidity_on_parse_stack(source: &str, file_name: Option<&str>) -> ParseResult {
    let file = file_name.unwrap_or("contract.runar.sol");
    let mut errors: Vec<Diagnostic> = Vec::new();

    let (tokens, positions) = tokenize(source, file, &mut errors);
    let mut parser = SolParser::new(tokens, positions, file, &mut errors);

    let contract = parser.parse_contract();
    // F-213 measure (A), then measure (B) on the finished tree.
    if parser.nest.exceeded() {
        return nesting_refusal(None);
    }

    enforce_ast_nesting(ParseResult {
        contract,
        errors,
        source_size_err: None,
    })
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
    NumberLit(BigInt),
    HexLit(String),
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
    Shl,        // <<
    Shr,        // >>
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

/// Returns the tokens and, index for index, the (1-based line, 1-based
/// column — the AST convention; codegen/emit.rs converts) where each one
/// starts (F-337).
fn tokenize(
    source: &str,
    file: &str,
    errors: &mut Vec<Diagnostic>,
) -> (Vec<Token>, Vec<(usize, usize)>) {
    let mut tokens = Vec::new();
    // F-337: char index where each token starts.
    let mut starts: Vec<usize> = Vec::new();
    let mut at = 0usize;
    let chars: Vec<char> = source.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Tokens pushed by the previous iteration started at `at`.
        starts.resize(tokens.len(), at);
        at = i;
        let ch = chars[i];

        // Whitespace
        // N-407: exactly the TS reference's whitespace (' ', '\t', '\r', '\n'); a
        // non-ASCII space such as U+00A0 is refused as an unexpected character.
        if matches!(ch, ' ' | '\t' | '\r' | '\n') {
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
            let open = i;
            i += 1;
            let start = i;
            // F-011: a literal that reaches a line break (escaped or not) or
            // end of file is unterminated; it must never run on into the
            // following lines.
            while i < len && chars[i] != quote && chars[i] != '\n' && chars[i] != '\r' {
                if chars[i] == '\\' {
                    if i + 1 >= len || chars[i + 1] == '\n' || chars[i + 1] == '\r' {
                        break;
                    }
                    i += 1;
                }
                i += 1;
            }
            let val: String = chars[start..i].iter().collect();
            tokens.push(Token::StringLit(val));
            if i < len && chars[i] == quote {
                i += 1;
                // N-019: this surface has no quoted literal; a terminated one
                // is refused as an unexpected character (as the TS reference).
                errors.push(lex_error_at_index(&format!("Unexpected character '{}'", quote), file, &chars, open));
            } else {
                errors.push(lex_error_at_index(UNTERMINATED_STRING_LITERAL, file, &chars, open));
            }
            continue;
        }

        // Numbers (and hex byte string literals: 0x...)
        if ch.is_ascii_digit() {
            // Hex byte string literal -> ByteString (lowercase x only, as the
            // TS reference; `0X` is an invalid integer literal).
            if ch == '0' && i + 1 < len && chars[i + 1] == 'x' {
                i += 2;
                let hex_start = i;
                while i < len && chars[i].is_ascii_hexdigit() {
                    i += 1;
                }
                let hex_str: String = chars[hex_start..i].iter().collect();
                tokens.push(Token::HexLit(hex_str));
                continue;
            }
            // F-026: the whole glued [0-9A-Za-z_] run is one Solidity literal.
            let start = i;
            i = scan_number_end(&chars, i);
            let text: String = chars[start..i].iter().collect();
            let val = match parse_int_literal("sol", &text) {
                Some(lit) => lit.value,
                None => {
                    errors.push(lex_error_at_index(&invalid_integer_literal("sol", &text), file, &chars, start));
                    BigInt::from(0)
                }
            };
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

        // N-214: an unrecognised character is refused, as the TS reference
        // does, rather than skipped: skipping compiled `a + § b` as `a + b`.
        errors.push(lex_error_at_index(&format!("Unexpected character '{}'", ch), file, &chars, i));
        i += 1;
    }

    tokens.push(Token::Eof);
    starts.resize(tokens.len(), at);
    let positions = char_index_positions(&chars, &starts);
    (tokens, positions)
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct SolParser<'a> {
    tokens: Vec<Token>,
    /// F-337: start (line, column) of each token in `tokens`.
    positions: Vec<(usize, usize)>,
    pos: usize,
    file: &'a str,
    errors: &'a mut Vec<Diagnostic>,
    /// F-213 measure (A): parse nesting.
    nest: NestingCounter,
}

impl<'a> SolParser<'a> {
    fn new(
        tokens: Vec<Token>,
        positions: Vec<(usize, usize)>,
        file: &'a str,
        errors: &'a mut Vec<Diagnostic>,
    ) -> Self {
        Self {
            tokens,
            positions,
            pos: 0,
            file,
            errors,
            nest: NestingCounter::new(),
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
    // Top-level contract
    // -----------------------------------------------------------------------

    fn parse_contract(&mut self) -> Option<ContractNode> {
        // Skip any top-level pragmas, imports, or comments until we see 'contract'
        while *self.peek() != Token::Contract && *self.peek() != Token::Eof {
            self.advance();
        }

        if *self.peek() == Token::Eof {
            self.errors
                .push(Diagnostic::error("No 'contract' declaration found", None));
            return None;
        }

        // N-490: a synthesized constructor is anchored at the `contract` keyword.
        let contract_loc = self.loc();
        self.expect(&Token::Contract);
        let name = self.expect_ident();

        // 'is' BaseClass. Only the three real bases are honoured; any other
        // name is refused at parse (N-014, formerly folded to SmartContract by
        // F-022), in every tier, with one shared diagnostic.
        let parent_class = if *self.peek() == Token::Is {
            self.advance();
            let parent_loc = self.loc();
            let parent = self.expect_ident();
            match parent.as_str() {
                "SmartContract" | "StatefulSmartContract" | "UnsafeSmartContract" => parent,
                _ => {
                    // N-014: an unknown base is refused, never folded to SmartContract.
                    self.errors.push(Diagnostic::error(
                        format!(
                            "unknown parent class: '{}', expected SmartContract, StatefulSmartContract, or UnsafeSmartContract",
                            parent
                        ),
                        Some(parent_loc),
                    ));
                    "SmartContract".to_string()
                }
            }
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
                    constructor = Some(self.parse_constructor(&properties));
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
                    self.errors.push(Diagnostic::error(format!(
                        "Unexpected token in contract body: {:?}",
                        self.peek()
                    ), None));
                    self.advance();
                }
            }
        }

        self.expect(&Token::RBrace);

        // R-114: a `.runar.sol` with no constructor is VALID — synthesise one
        // from the declared properties, with super() first (CLAUDE.md,
        // "Auto-generated constructors MUST include super() as the first
        // statement"). This used to be a parse ERROR here, while ts/go/zig/ruby
        // accepted the same file and python/java synthesised an empty
        // constructor they then rejected themselves. Four tiers accepted, three
        // refused — an accept/reject split is a frontend-parity breach.
        // Mirrors compilers/go/frontend/parser_sol.go:495-530.
        let constructor = constructor.unwrap_or_else(|| {
            let loc = contract_loc;
            let uninit: Vec<&PropertyNode> =
                properties.iter().filter(|p| p.initializer.is_none()).collect();
            let params: Vec<ParamNode> = uninit
                .iter()
                .map(|p| ParamNode {
                    name: p.name.clone(),
                    param_type: p.prop_type.clone(),
                })
                .collect();
            let mut body: Vec<Statement> = vec![Statement::ExpressionStatement {
                expression: Expression::CallExpr {
                    callee: Box::new(Expression::Identifier {
                        name: "super".to_string(),
                        source_location: None,
                    }),
                    args: uninit
                        .iter()
                        .map(|p| Expression::Identifier { name: p.name.clone(), source_location: None })
                        .collect(),
                    asm_return_type: None,
                },
                source_location: loc.clone(),
            }];
            for p in &uninit {
                body.push(Statement::Assignment {
                    target: Expression::PropertyAccess {
                        property: p.name.clone(),
                        source_location: None,
                    },
                    value: Expression::Identifier { name: p.name.clone(), source_location: None },
                    source_location: loc.clone(),
                });
            }
            MethodNode {
                name: "constructor".to_string(),
                params,
                body,
                visibility: Visibility::Public,
                source_location: loc,
                sighash_type: None,
                binding_variant: None,
            }
        });

        // Resolve bare property references and bare contract-method calls in
        // method bodies (Solidity allows referencing state variables and other
        // contract methods without a `this.` prefix).
        let prop_names: std::collections::HashSet<String> =
            properties.iter().map(|p| p.name.clone()).collect();
        let method_names: std::collections::HashSet<String> =
            methods.iter().map(|m| m.name.clone()).collect();
        let methods: Vec<MethodNode> = methods
            .into_iter()
            .map(|mut m| {
                let mut locals: std::collections::HashSet<String> =
                    m.params.iter().map(|p| p.name.clone()).collect();
                m.body = m
                    .body
                    .into_iter()
                    .map(|s| sol_rewrite_stmt_bare_props(s, &prop_names, &mut locals, &method_names))
                    .collect();
                m
            })
            .collect();

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

        // Modifiers after the type, any order: `immutable` (readonly) and
        // N-093's `embedAlways` (the native spelling of the `@embedAlways`
        // directive). An `embedAlways` directly followed by `;` or `=` is the
        // property NAME, not a modifier.
        let mut is_immutable = is_immutable;
        let mut embed_always = false;
        loop {
            if *self.peek() == Token::Immutable {
                self.advance(); // consume 'immutable'
                is_immutable = true;
                continue;
            }
            if matches!(self.peek(), Token::Ident(w) if w == "embedAlways")
                && !matches!(self.tokens.get(self.pos + 1), Some(Token::Semicolon) | Some(Token::Eq))
            {
                self.advance();
                embed_always = true;
                continue;
            }
            break;
        }

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
            synthetic_array_chain: None,
            embed_always,
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
                let element = self.nested(TypeNode::Custom("_error".to_string()), |p| p.parse_type());
                self.expect(&Token::Comma);
                let length = match self.advance() {
                    Token::NumberLit(n) => n.to_usize().unwrap_or(0),
                    _ => {
                        self.errors
                            .push(Diagnostic::error("FixedArray requires numeric length", None));
                        0
                    }
                };
                self.expect(&Token::Gt);
                let base = TypeNode::FixedArray {
                    element: Box::new(element),
                    length,
                };
                return self.parse_sol_fixed_array_suffix(base);
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

        let base = if let Some(prim) = PrimitiveTypeName::from_str(mapped) {
            TypeNode::Primitive(prim)
        } else {
            TypeNode::Custom(mapped.to_string())
        };

        self.parse_sol_fixed_array_suffix(base)
    }

    // Consume any number of trailing `[N]` bracket suffixes, wrapping the
    // type as `FixedArray<previous, N>` per Solidity's left-to-right
    // outer-to-inner declaration order. `T[A][B]` ⇒ outer B of inner A of T.
    fn parse_sol_fixed_array_suffix(&mut self, base: TypeNode) -> TypeNode {
        let mut result = base;
        while *self.peek() == Token::LBracket {
            self.advance(); // [
            let length = match self.advance() {
                Token::NumberLit(n) if n.sign() != Sign::Minus => n.to_usize().unwrap_or(0),
                other => {
                    self.errors.push(Diagnostic::error(
                        &format!("FixedArray length must be a non-negative integer literal, got {:?}", other),
                        None,
                    ));
                    0
                }
            };
            self.expect(&Token::RBracket);
            result = TypeNode::FixedArray {
                element: Box::new(result),
                length,
            };
            // F-213: this loop builds the type; stop once it is too deep.
            if type_too_deep(&result) {
                self.bail();
                break;
            }
        }
        result
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    fn parse_constructor(&mut self, properties: &[PropertyNode]) -> MethodNode {
        let loc = self.loc();
        self.advance(); // consume 'constructor'
        self.expect(&Token::LParen);
        let mut params = self.parse_param_list();
        self.expect(&Token::RParen);

        // Optional visibility
        if *self.peek() == Token::Public || *self.peek() == Token::Private {
            self.advance();
        }

        let raw_body = self.parse_block();

        // Strip _ prefix from param names and build rename map
        let mut rename_map = std::collections::HashMap::new();
        for param in &mut params {
            if param.name.starts_with('_') {
                let original = param.name.clone();
                param.name = param.name[1..].to_string();
                rename_map.insert(original, param.name.clone());
            }
        }

        // Build set of property names
        let prop_names: std::collections::HashSet<String> =
            properties.iter().map(|p| p.name.clone()).collect();

        // Inject super(...) as first statement
        let super_call = Statement::ExpressionStatement {
            expression: Expression::CallExpr {
                callee: Box::new(Expression::Identifier {
                    name: "super".to_string(),
                    source_location: None,
                }),
                args: params.iter().map(|p| Expression::Identifier {
                    name: p.name.clone(),
                    source_location: None,
                }).collect(),
                asm_return_type: None,
            },
            source_location: loc.clone(),
        };

        // Process body: rename _-prefixed identifiers and convert bare
        // property assignments to this.property assignments
        let mut fixed_body = Vec::new();
        for stmt in raw_body {
            let renamed = sol_rename_identifiers_in_stmt(stmt, &rename_map);
            let fixed = sol_fix_property_assignment(renamed, &prop_names);
            fixed_body.push(fixed);
        }

        MethodNode {
            name: "constructor".to_string(),
            params,
            body: std::iter::once(super_call).chain(fixed_body).collect(),
            visibility: Visibility::Public,
            source_location: loc,
            sighash_type: None,
            binding_variant: None,
        }
    }

    // -----------------------------------------------------------------------
    // Functions/methods
    // -----------------------------------------------------------------------

    fn parse_function(&mut self) -> MethodNode {
        let location = self.loc();
        self.advance(); // consume 'function'
        let name = self.expect_ident();
        self.expect(&Token::LParen);
        let params = self.parse_param_list();
        self.expect(&Token::RParen);

        // Parse Solidity-style modifiers in any order: visibility (public/private/
        // external/internal), state mutability (view/pure/payable), returns,
        // and N-093's `sighash(FLAGS)` (the native spelling of the `@sighash`
        // directive). FLAGS must be identifiers separated by `|`; any other
        // token makes the spelling malformed.
        let mut visibility = Visibility::Private;
        let mut sighash_specs: Vec<Option<String>> = Vec::new();
        let mut pending_ret: Option<TypeNode> = None;
        loop {
            match self.peek().clone() {
                Token::Public => {
                    self.advance();
                    visibility = Visibility::Public;
                }
                Token::Private => {
                    self.advance();
                    visibility = Visibility::Private;
                }
                Token::Ident(word) => {
                    match word.as_str() {
                        "external" => {
                            self.advance();
                            visibility = Visibility::Public;
                        }
                        "internal" | "view" | "pure" | "payable" => {
                            self.advance();
                        }
                        "sighash" if matches!(self.tokens.get(self.pos + 1), Some(Token::LParen)) => {
                            self.advance();
                            let spec = self.parse_sighash_flag_tokens();
                            sighash_specs.push(spec);
                        }
                        "returns" => {
                            self.advance();
                            // Skip the parenthesised return type list
                            if *self.peek() == Token::LParen {
                                self.advance();
                                // N-331: the AST keeps no return type; an unknown name is refused.
                                // N-332: checked after the modifier loop, because
                                // `public` may follow `returns (...)`.
                                if matches!(self.peek(), Token::Ident(_)) {
                                    pending_ret = Some(self.parse_type());
                                }
                                let mut depth: i32 = 1;
                                while depth > 0 && *self.peek() != Token::Eof {
                                    if *self.peek() == Token::LParen {
                                        depth += 1;
                                    } else if *self.peek() == Token::RParen {
                                        depth -= 1;
                                        if depth == 0 {
                                            self.advance();
                                            break;
                                        }
                                    }
                                    self.advance();
                                }
                            }
                        }
                        _ => break,
                    }
                }
                _ => break,
            }
        }

        if let Some(ret) = pending_ret {
            if let Some(msg) = unknown_return_type_message(&ret, &name, visibility == Visibility::Public) {
                self.errors.push(Diagnostic::error(msg, Some(location.clone())));
            }
        }

        let body = self.parse_block();

        let sighash_type = match resolve_native_sighash(&name, visibility == Visibility::Public, &sighash_specs) {
            Some(Ok(v)) => Some(v),
            Some(Err(msg)) => {
                self.errors.push(Diagnostic::error(msg, Some(location.clone())));
                None
            }
            None => None,
        };

        MethodNode {
            name,
            params,
            body,
            visibility,
            source_location: location,
            sighash_type,
            binding_variant: None,
        }
    }

    /// N-093: `( IDENT ( '|' IDENT )* )` after `sighash` → the flag text, or
    /// `None` when anything else appears inside the parentheses. Always
    /// consumes through the matching `)` so a malformed spelling does not
    /// derail parsing. Mirrors `parseSighashFlagTokens` (01-parse-sol.ts).
    fn parse_sighash_flag_tokens(&mut self) -> Option<String> {
        self.expect(&Token::LParen);
        let mut text = String::new();
        let mut ok = true;
        let mut depth = 1;
        while *self.peek() != Token::Eof {
            match self.peek().clone() {
                Token::LParen => {
                    depth += 1;
                    ok = false;
                }
                Token::RParen => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    ok = false;
                }
                Token::Ident(n) => text.push_str(&n),
                Token::BitOr => text.push('|'),
                _ => ok = false,
            }
            self.advance();
        }
        self.expect(&Token::RParen);
        if ok { Some(text) } else { None }
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
        // Check for Solidity-style local variable declaration: Type name = expr; or Type name;
        if self.is_type_then_name() {
            return Some(self.parse_typed_var_decl());
        }

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
                            source_location: None,
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
                            source_location: None,
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
                            source_location: None,
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
                            source_location: None,
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
                            source_location: None,
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

    /// Parse Solidity-style typed variable declaration: `Type name = expr;` or `Type name;`
    fn parse_typed_var_decl(&mut self) -> Statement {
        let type_node = self.parse_type();
        let name = self.expect_ident();

        let init = if *self.peek() == Token::Eq {
            self.advance();
            self.parse_expression()
        } else {
            // Type name; — declaration without initializer, default to 0
            Expression::BigIntLiteral { value: BigInt::from(0) }
        };

        self.expect(&Token::Semicolon);

        Statement::VariableDecl {
            name,
            var_type: Some(type_node),
            mutable: false,
            init,
            source_location: self.loc(),
        }
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
                    source_location: None,
                }),
                args: vec![expr],
                asm_return_type: None,
            },
            source_location: self.loc(),
        }
    }

    fn parse_if(&mut self) -> Statement {
        // F-337: located at the `if` token (an `else if` never passes
        // through parse_statement).
        let loc = self.loc();
        self.advance(); // consume 'if'
        self.expect(&Token::LParen);
        let condition = self.parse_expression();
        self.expect(&Token::RParen);

        let then_branch = self.parse_block();

        let else_branch = if *self.peek() == Token::Else {
            self.advance();
            if *self.peek() == Token::If {
                // else if -> wrapped in a single-element branch. F-213: the
                // nested `if` is a statement of the else branch (+1).
                self.nested(Some(Vec::new()), |p| Some(vec![p.parse_if()]))
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
            source_location: loc,
        }
    }

    fn parse_for(&mut self) -> Statement {
        self.advance(); // consume 'for'
        self.expect(&Token::LParen);

        // Init: accept `let Type name = expr;`, `const ... = expr;`, or
        // Solidity-style `Type name = expr;` (no leading keyword).
        let init = if *self.peek() == Token::Let || *self.peek() == Token::Const {
            self.parse_var_decl()
        } else if self.is_type_then_name() {
            self.parse_typed_var_decl()
        } else {
            self.errors
                .push(Diagnostic::error("For loop init must be a variable declaration", None));
            self.expect(&Token::Semicolon);
            Statement::VariableDecl {
                name: "_i".to_string(),
                var_type: None,
                mutable: true,
                init: Expression::BigIntLiteral { value: BigInt::from(0) },
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
        // N-133: the TS reference's Solidity parser takes one expression
        // here (with an optional postfix `++`/`--`) and then expects `)`, so
        // `i += 1`, `i -= 1` and `i = i + 1` are refused at the `)`. Leave the
        // assignment token unconsumed so the caller's `expect(RParen)` refuses
        // them the same way instead of desugaring them into an Assignment.
        let expr = self.parse_expression();
        Statement::ExpressionStatement {
            expression: expr,
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
        self.nested(zero(), |p| p.parse_ternary())
    }

    fn parse_ternary(&mut self) -> Expression {
        let cond = self.parse_or();
        if *self.peek() == Token::Question {
            self.advance();
            // F-213: the arms recurse into the ternary parser directly; the
            // TS reference parses them with parseExpression, +1 each.
            let cons = self.nested(zero(), |p| p.parse_ternary());
            self.expect(&Token::Colon);
            let alt = self.nested(zero(), |p| p.parse_ternary());
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
        let start = self.loc();
        let mut left = self.parse_and();
        let mut dt = DepthTracker::new();
        while *self.peek() == Token::Or {
            self.advance();
            let right = self.parse_and();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr {
                op: BinaryOp::Or,
                left: Box::new(left),
                right: Box::new(right),
                source_location: Some(start.clone()),
            };
        }
        left
    }

    fn parse_and(&mut self) -> Expression {
        let start = self.loc();
        let mut left = self.parse_bit_or();
        let mut dt = DepthTracker::new();
        while *self.peek() == Token::And {
            self.advance();
            let right = self.parse_bit_or();
            if !self.grow(&mut dt, &left, &[&right]) { break; }
            left = Expression::BinaryExpr {
                op: BinaryOp::And,
                left: Box::new(left),
                right: Box::new(right),
                source_location: Some(start.clone()),
            };
        }
        left
    }

    fn parse_bit_or(&mut self) -> Expression {
        let start = self.loc();
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
                source_location: Some(start.clone()),
            };
        }
        left
    }

    fn parse_bit_xor(&mut self) -> Expression {
        let start = self.loc();
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
                source_location: Some(start.clone()),
            };
        }
        left
    }

    fn parse_bit_and(&mut self) -> Expression {
        let start = self.loc();
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
                source_location: Some(start.clone()),
            };
        }
        left
    }

    fn parse_equality(&mut self) -> Expression {
        let start = self.loc();
        let mut left = self.parse_comparison();
        let mut dt = DepthTracker::new();
        loop {
            match self.peek() {
                Token::EqEq | Token::EqEqEq => {
                    self.advance();
                    let right = self.parse_comparison();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::StrictEq,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: Some(start.clone()),
                    };
                }
                Token::NotEq | Token::NotEqEq => {
                    self.advance();
                    let right = self.parse_comparison();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::StrictNe,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: Some(start.clone()),
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_comparison(&mut self) -> Expression {
        let start = self.loc();
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
                        source_location: Some(start.clone()),
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
                        source_location: Some(start.clone()),
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
                        source_location: Some(start.clone()),
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
                        source_location: Some(start.clone()),
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_shift(&mut self) -> Expression {
        let start = self.loc();
        let mut left = self.parse_additive();
        let mut dt = DepthTracker::new();
        loop {
            match self.peek() {
                Token::Shl => {
                    self.advance();
                    let right = self.parse_additive();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Shl,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: Some(start.clone()),
                    };
                }
                Token::Shr => {
                    self.advance();
                    let right = self.parse_additive();
                    if !self.grow(&mut dt, &left, &[&right]) { break; }
                    left = Expression::BinaryExpr {
                        op: BinaryOp::Shr,
                        left: Box::new(left),
                        right: Box::new(right),
                        source_location: Some(start.clone()),
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_additive(&mut self) -> Expression {
        let start = self.loc();
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
                        source_location: Some(start.clone()),
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
                        source_location: Some(start.clone()),
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_multiplicative(&mut self) -> Expression {
        let start = self.loc();
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
                        source_location: Some(start.clone()),
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
                        source_location: Some(start.clone()),
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
                        source_location: Some(start.clone()),
                    };
                }
                _ => break,
            }
        }
        left
    }

    fn parse_unary(&mut self) -> Expression {
        let op_loc = self.loc();
        match self.peek() {
            Token::Not => {
                self.advance();
                let operand = self.nested(zero(), |p| p.parse_unary());
                Expression::UnaryExpr {
                    op: UnaryOp::Not,
                    operand: Box::new(operand),
                    source_location: Some(op_loc.clone()),
                }
            }
            Token::Minus => {
                self.advance();
                let operand = self.nested(zero(), |p| p.parse_unary());
                Expression::UnaryExpr {
                    op: UnaryOp::Neg,
                    operand: Box::new(operand),
                    source_location: Some(op_loc.clone()),
                }
            }
            Token::Tilde => {
                self.advance();
                let operand = self.nested(zero(), |p| p.parse_unary());
                Expression::UnaryExpr {
                    op: UnaryOp::BitNot,
                    operand: Box::new(operand),
                    source_location: Some(op_loc.clone()),
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
        let mut dt = DepthTracker::new();

        loop {
            match self.peek().clone() {
                Token::Dot => {
                    self.advance();
                    let prop = self.expect_ident();
                    if matches!(&expr, Expression::Identifier { name, .. } if name == "this") {
                        expr = Expression::PropertyAccess { property: prop, source_location: None };
                        dt = DepthTracker::new();
                    } else {
                        if !self.grow(&mut dt, &expr, &[]) { break; }
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
                    let arg_refs: Vec<&Expression> = args.iter().collect();
                    if !self.grow(&mut dt, &expr, &arg_refs) { break; }
                    expr = Expression::CallExpr {
                        callee: Box::new(expr),
                        args,
                        asm_return_type: None,
                    };
                }
                Token::LBracket => {
                    self.advance();
                    let index = self.parse_expression();
                    self.expect(&Token::RBracket);
                    if !self.grow(&mut dt, &expr, &[&index]) { break; }
                    expr = Expression::IndexAccess {
                        object: Box::new(expr),
                        index: Box::new(index),
                    };
                }
                Token::PlusPlus => {
                    self.advance();
                    if !self.grow(&mut dt, &expr, &[]) { break; }
                    expr = Expression::IncrementExpr {
                        operand: Box::new(expr),
                        prefix: false,
                    };
                }
                Token::MinusMinus => {
                    self.advance();
                    if !self.grow(&mut dt, &expr, &[]) { break; }
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
        let lit_loc = self.loc(); // N-449: the literal's position, before it is consumed
        match self.advance() {
            Token::NumberLit(v) => Expression::BigIntLiteral { value: v },
            Token::HexLit(v) => Expression::ByteStringLiteral { value: v, source_location: Some(lit_loc) },
            Token::True => Expression::BoolLiteral { value: true },
            Token::False => Expression::BoolLiteral { value: false },
            Token::StringLit(v) => Expression::ByteStringLiteral { value: v, source_location: Some(lit_loc) },
            Token::Ident(name) => {
                if name == "this" {
                    Expression::Identifier {
                        name: "this".to_string(),
                        source_location: None,
                    }
                } else if name == "super" {
                    Expression::Identifier {
                        name: "super".to_string(),
                        source_location: None,
                    }
                } else {
                    Expression::Identifier { name, source_location: Some(lit_loc) }
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
                        source_location: None,
                    }),
                    args: vec![arg],
                    asm_return_type: None,
                }
            }
            Token::LParen => {
                let expr = self.parse_expression();
                self.expect(&Token::RParen);
                expr
            }
            Token::LBracket => {
                // Array literal: [a, b, c]
                let mut elements: Vec<Expression> = Vec::new();
                while !matches!(self.peek(), Token::RBracket | Token::Eof) {
                    elements.push(self.parse_expression());
                    if !matches!(self.peek(), Token::Comma) {
                        break;
                    }
                    self.advance();
                }
                self.expect(&Token::RBracket);
                Expression::ArrayLiteral { elements }
            }
            other => {
                self.errors
                    .push(Diagnostic::error(format!("Unexpected token in expression: {:?}", other), None));
                Expression::BigIntLiteral { value: BigInt::from(0) }
            }
        }
    }
}

/// Placeholder expression returned by a parse cut short by the F-213 limit.
fn zero() -> Expression {
    Expression::BigIntLiteral { value: BigInt::from(0) }
}

// ---------------------------------------------------------------------------
// Constructor helper functions
// ---------------------------------------------------------------------------

/// Recursively rename identifiers in a statement using the provided rename map.
/// Used to fix _-prefixed constructor param references in the body.
fn sol_rename_identifiers_in_stmt(
    stmt: Statement,
    rename_map: &std::collections::HashMap<String, String>,
) -> Statement {
    if rename_map.is_empty() {
        return stmt;
    }
    match stmt {
        Statement::Assignment {
            target,
            value,
            source_location,
        } => Statement::Assignment {
            target: sol_rename_identifiers_in_expr(target, rename_map),
            value: sol_rename_identifiers_in_expr(value, rename_map),
            source_location,
        },
        Statement::ExpressionStatement {
            expression,
            source_location,
        } => Statement::ExpressionStatement {
            expression: sol_rename_identifiers_in_expr(expression, rename_map),
            source_location,
        },
        Statement::VariableDecl {
            name,
            var_type,
            mutable,
            init,
            source_location,
        } => Statement::VariableDecl {
            name,
            var_type,
            mutable,
            init: sol_rename_identifiers_in_expr(init, rename_map),
            source_location,
        },
        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            source_location,
        } => Statement::IfStatement {
            condition: sol_rename_identifiers_in_expr(condition, rename_map),
            then_branch: then_branch
                .into_iter()
                .map(|s| sol_rename_identifiers_in_stmt(s, rename_map))
                .collect(),
            else_branch: else_branch.map(|stmts| {
                stmts
                    .into_iter()
                    .map(|s| sol_rename_identifiers_in_stmt(s, rename_map))
                    .collect()
            }),
            source_location,
        },
        Statement::ReturnStatement {
            value,
            source_location,
        } => Statement::ReturnStatement {
            value: value.map(|v| sol_rename_identifiers_in_expr(v, rename_map)),
            source_location,
        },
        other => other,
    }
}

/// Recursively rename identifiers in an expression using the provided rename map.
fn sol_rename_identifiers_in_expr(
    expr: Expression,
    rename_map: &std::collections::HashMap<String, String>,
) -> Expression {
    match expr {
        Expression::Identifier { name, source_location } => {
            if let Some(new_name) = rename_map.get(&name) {
                Expression::Identifier {
                    name: new_name.clone(),
                    source_location: None,
                }
            } else {
                Expression::Identifier { name, source_location }
            }
        }
        Expression::CallExpr { callee, args, .. } => Expression::CallExpr {
            callee: Box::new(sol_rename_identifiers_in_expr(*callee, rename_map)),
            args: args
                .into_iter()
                .map(|a| sol_rename_identifiers_in_expr(a, rename_map))
                .collect(),
            asm_return_type: None,
        },
        Expression::BinaryExpr { op, left, right, source_location  } => Expression::BinaryExpr {
            op,
            left: Box::new(sol_rename_identifiers_in_expr(*left, rename_map)),
            right: Box::new(sol_rename_identifiers_in_expr(*right, rename_map)),
            source_location: source_location,
        },
        Expression::UnaryExpr { op, operand, source_location  } => Expression::UnaryExpr {
            op,
            operand: Box::new(sol_rename_identifiers_in_expr(*operand, rename_map)),
            source_location: source_location,
        },
        Expression::MemberExpr { object, property } => Expression::MemberExpr {
            object: Box::new(sol_rename_identifiers_in_expr(*object, rename_map)),
            property,
        },
        Expression::IndexAccess { object, index } => Expression::IndexAccess {
            object: Box::new(sol_rename_identifiers_in_expr(*object, rename_map)),
            index: Box::new(sol_rename_identifiers_in_expr(*index, rename_map)),
        },
        Expression::TernaryExpr {
            condition,
            consequent,
            alternate,
        } => Expression::TernaryExpr {
            condition: Box::new(sol_rename_identifiers_in_expr(*condition, rename_map)),
            consequent: Box::new(sol_rename_identifiers_in_expr(*consequent, rename_map)),
            alternate: Box::new(sol_rename_identifiers_in_expr(*alternate, rename_map)),
        },
        other => other,
    }
}

/// Convert bare identifier assignments to property access assignments when the
/// target is a known property name.
/// e.g., `pubKeyHash = x` -> `this.pubKeyHash = x`
fn sol_fix_property_assignment(
    stmt: Statement,
    prop_names: &std::collections::HashSet<String>,
) -> Statement {
    if let Statement::Assignment {
        target,
        value,
        source_location,
    } = stmt
    {
        if let Expression::Identifier { ref name, .. } = target {
            if prop_names.contains(name) {
                return Statement::Assignment {
                    target: Expression::PropertyAccess {
                        property: name.clone(),
                        source_location: None,
                    },
                    value,
                    source_location,
                };
            }
        }
        Statement::Assignment {
            target,
            value,
            source_location,
        }
    } else {
        stmt
    }
}

/// Recursively rewrite bare `Identifier(name)` references to
/// `PropertyAccess { property: name }` when `name` matches a contract property
/// (and is not shadowed by a local variable). Bare calls `foo(args)` to a
/// contract method are rewritten to `this.foo(args)`.
fn sol_rewrite_expr_bare_props(
    expr: Expression,
    prop_names: &std::collections::HashSet<String>,
    locals: &std::collections::HashSet<String>,
    method_names: &std::collections::HashSet<String>,
) -> Expression {
    match expr {
        Expression::Identifier { name, source_location } => {
            if prop_names.contains(&name) && !locals.contains(&name) {
                Expression::PropertyAccess { property: name, source_location: None }
            } else {
                Expression::Identifier { name, source_location }
            }
        }
        Expression::CallExpr { callee, args, .. } => {
            if let Expression::Identifier { ref name, .. } = *callee {
                if method_names.contains(name) && !locals.contains(name) && !prop_names.contains(name) {
                    let new_args: Vec<Expression> = args
                        .into_iter()
                        .map(|a| sol_rewrite_expr_bare_props(a, prop_names, locals, method_names))
                        .collect();
                    return Expression::CallExpr {
                        callee: Box::new(Expression::MemberExpr {
                            object: Box::new(Expression::Identifier {
                                name: "this".to_string(),
                                source_location: None,
                            }),
                            property: name.clone(),
                        }),
                        args: new_args,
                        asm_return_type: None,
                    };
                }
            }
            Expression::CallExpr {
                callee: Box::new(sol_rewrite_expr_bare_props(*callee, prop_names, locals, method_names)),
                args: args
                    .into_iter()
                    .map(|a| sol_rewrite_expr_bare_props(a, prop_names, locals, method_names))
                    .collect(),
                asm_return_type: None,
            }
        }
        Expression::BinaryExpr { op, left, right, source_location  } => Expression::BinaryExpr {
            op,
            left: Box::new(sol_rewrite_expr_bare_props(*left, prop_names, locals, method_names)),
            right: Box::new(sol_rewrite_expr_bare_props(*right, prop_names, locals, method_names)),
            source_location: source_location,
        },
        Expression::UnaryExpr { op, operand, source_location  } => Expression::UnaryExpr {
            op,
            operand: Box::new(sol_rewrite_expr_bare_props(*operand, prop_names, locals, method_names)),
            source_location: source_location,
        },
        Expression::MemberExpr { object, property } => Expression::MemberExpr {
            object: Box::new(sol_rewrite_expr_bare_props(*object, prop_names, locals, method_names)),
            property,
        },
        Expression::TernaryExpr {
            condition,
            consequent,
            alternate,
        } => Expression::TernaryExpr {
            condition: Box::new(sol_rewrite_expr_bare_props(*condition, prop_names, locals, method_names)),
            consequent: Box::new(sol_rewrite_expr_bare_props(*consequent, prop_names, locals, method_names)),
            alternate: Box::new(sol_rewrite_expr_bare_props(*alternate, prop_names, locals, method_names)),
        },
        Expression::IndexAccess { object, index } => Expression::IndexAccess {
            object: Box::new(sol_rewrite_expr_bare_props(*object, prop_names, locals, method_names)),
            index: Box::new(sol_rewrite_expr_bare_props(*index, prop_names, locals, method_names)),
        },
        Expression::IncrementExpr { operand, prefix } => Expression::IncrementExpr {
            operand: Box::new(sol_rewrite_expr_bare_props(*operand, prop_names, locals, method_names)),
            prefix,
        },
        Expression::DecrementExpr { operand, prefix } => Expression::DecrementExpr {
            operand: Box::new(sol_rewrite_expr_bare_props(*operand, prop_names, locals, method_names)),
            prefix,
        },
        Expression::ArrayLiteral { elements } => Expression::ArrayLiteral {
            elements: elements
                .into_iter()
                .map(|e| sol_rewrite_expr_bare_props(e, prop_names, locals, method_names))
                .collect(),
        },
        other => other,
    }
}

/// Recursively rewrite bare property references and method calls in a
/// statement, threading newly-declared local variables through the local set
/// so they shadow same-named properties.
fn sol_rewrite_stmt_bare_props(
    stmt: Statement,
    prop_names: &std::collections::HashSet<String>,
    locals: &mut std::collections::HashSet<String>,
    method_names: &std::collections::HashSet<String>,
) -> Statement {
    match stmt {
        Statement::ExpressionStatement {
            expression,
            source_location,
        } => Statement::ExpressionStatement {
            expression: sol_rewrite_expr_bare_props(expression, prop_names, locals, method_names),
            source_location,
        },
        Statement::Assignment {
            target,
            value,
            source_location,
        } => Statement::Assignment {
            target: sol_rewrite_expr_bare_props(target, prop_names, locals, method_names),
            value: sol_rewrite_expr_bare_props(value, prop_names, locals, method_names),
            source_location,
        },
        Statement::VariableDecl {
            name,
            var_type,
            mutable,
            init,
            source_location,
        } => {
            let new_init = sol_rewrite_expr_bare_props(init, prop_names, locals, method_names);
            locals.insert(name.clone());
            Statement::VariableDecl {
                name,
                var_type,
                mutable,
                init: new_init,
                source_location,
            }
        }
        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            source_location,
        } => {
            let new_cond = sol_rewrite_expr_bare_props(condition, prop_names, locals, method_names);
            let mut then_locals = locals.clone();
            let new_then: Vec<Statement> = then_branch
                .into_iter()
                .map(|s| sol_rewrite_stmt_bare_props(s, prop_names, &mut then_locals, method_names))
                .collect();
            let new_else = else_branch.map(|stmts| {
                let mut else_locals = locals.clone();
                stmts
                    .into_iter()
                    .map(|s| sol_rewrite_stmt_bare_props(s, prop_names, &mut else_locals, method_names))
                    .collect()
            });
            Statement::IfStatement {
                condition: new_cond,
                then_branch: new_then,
                else_branch: new_else,
                source_location,
            }
        }
        Statement::ForStatement {
            init,
            condition,
            update,
            body,
            source_location,
        } => {
            let mut for_locals = locals.clone();
            let new_init = sol_rewrite_stmt_bare_props(*init, prop_names, &mut for_locals, method_names);
            let new_cond = sol_rewrite_expr_bare_props(condition, prop_names, &for_locals, method_names);
            let new_update = sol_rewrite_stmt_bare_props(*update, prop_names, &mut for_locals, method_names);
            let new_body: Vec<Statement> = body
                .into_iter()
                .map(|s| sol_rewrite_stmt_bare_props(s, prop_names, &mut for_locals, method_names))
                .collect();
            Statement::ForStatement {
                init: Box::new(new_init),
                condition: new_cond,
                update: Box::new(new_update),
                body: new_body,
                source_location,
            }
        }
        Statement::ReturnStatement {
            value,
            source_location,
        } => Statement::ReturnStatement {
            value: value.map(|v| sol_rewrite_expr_bare_props(v, prop_names, locals, method_names)),
            source_location,
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

    // -----------------------------------------------------------------------
    // F-022 / CL-BUG-247, N-014: unknown base class after `is`
    //
    // Proves: the Rust `.runar.sol` frontend REFUSES `is <UnknownName>` at
    // parse with the shared diagnostic (as every other tier does), instead of
    // folding it to SmartContract (the F-022 behaviour, which let a read-only
    // contract compile under a base the author never wrote). Also pins that
    // the three real bases are preserved verbatim.
    // Does NOT prove: parity of the other six tiers (see
    // conformance/negatives/n014-unknown-base-class-parity.test.ts), nor
    // anything about on-chain behaviour of the accepted programs.
    // -----------------------------------------------------------------------

    const BOGUS_MUTABLE_SOL: &str = r#"
contract Bogus is TotallyMadeUp {
    bigint total;

    constructor(bigint _total) {
        total = _total;
    }

    function bump() public {
        this.total = this.total + 1;
    }
}
"#;

    #[test]
    fn test_unknown_base_class_is_refused_at_parse() {
        let result = parse_solidity(BOGUS_MUTABLE_SOL, Some("Bogus.runar.sol"));
        assert!(
            result.errors.iter().any(|e| e.message.contains(
                "unknown parent class: 'TotallyMadeUp', expected SmartContract, StatefulSmartContract, or UnsafeSmartContract"
            )),
            "errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_known_base_classes_preserved() {
        for base in ["SmartContract", "StatefulSmartContract", "UnsafeSmartContract"] {
            let src = BOGUS_MUTABLE_SOL.replace("TotallyMadeUp", base);
            let result = parse_solidity(&src, Some("Bogus.runar.sol"));
            assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
            assert_eq!(result.contract.unwrap().parent_class, base);
        }
    }

    #[test]
    fn test_unknown_base_with_mutable_property_is_refused() {
        let err = crate::compile_from_source_str(BOGUS_MUTABLE_SOL, Some("Bogus.runar.sol"))
            .expect_err("an unknown base must not compile");
        assert!(
            err.contains("unknown parent class: 'TotallyMadeUp'"),
            "expected the unknown-parent-class diagnostic, got: {}",
            err
        );
    }
}
