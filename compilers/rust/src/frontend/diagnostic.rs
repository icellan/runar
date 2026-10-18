//! Structured compiler diagnostics.
//!
//! Provides a `Diagnostic` type that mirrors the TypeScript compiler's
//! `CompilerDiagnostic` type: `{ message, loc?, severity }`.

use super::ast::{SourceLocation, TypeNode};
use std::fmt;

/// Severity levels for compiler diagnostics.
#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Error,
    Warning,
}

/// A single compiler diagnostic (error or warning).
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub message: String,
    pub loc: Option<SourceLocation>,
    pub severity: Severity,
}

impl Diagnostic {
    /// Create a new diagnostic.
    pub fn new(message: impl Into<String>, severity: Severity, loc: Option<SourceLocation>) -> Self {
        Self {
            message: message.into(),
            loc,
            severity,
        }
    }

    /// Create an error diagnostic.
    pub fn error(message: impl Into<String>, loc: Option<SourceLocation>) -> Self {
        Self::new(message, Severity::Error, loc)
    }

    /// Create a warning diagnostic.
    pub fn warning(message: impl Into<String>, loc: Option<SourceLocation>) -> Self {
        Self::new(message, Severity::Warning, loc)
    }

    /// Format the diagnostic with optional file:line:column prefix.
    ///
    /// `loc.column` follows the AST's SourceLocation convention (1-based,
    /// F-337 / F-341; 0 = untracked), but the PRINTED column is 0-based
    /// (N-078, R88a), the same conversion codegen/emit.rs makes for source
    /// maps. A position in the first column (internal 1) prints `:0`.
    pub fn format_message(&self) -> String {
        if let Some(ref loc) = self.loc {
            if !loc.file.is_empty() {
                if loc.column > 0 {
                    return format!("{}:{}:{}: {}", loc.file, loc.line, loc.column - 1, self.message);
                }
                return format!("{}:{}: {}", loc.file, loc.line, self.message);
            }
        }
        self.message.clone()
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_message())
    }
}

/// F-011's shared diagnostic (the TS reference's `UNTERMINATED_STRING_LITERAL`):
/// every hand-written tokenizer emits it, at the opening quote, for a quoted
/// literal that reaches a line break or end of file before its closing quote.
/// On `.runar.rs`, for Python triple-quoted strings and for `.runar.go`
/// backtick raw strings, which may span lines, only end of file counts.
pub const UNTERMINATED_STRING_LITERAL: &str = "unterminated string literal";

/// N-121's refusal (user decision R85; the TS reference's `OPTIONAL_CHAINING`)
/// of a `.runar.ts` `?.`, located at the `?`. Only the first `?.` in a file is
/// reported.
pub const OPTIONAL_CHAINING: &str = "optional chaining '?.' is not supported";

/// F-203: a .runar.py string or bytes escape CPython does not define for that
/// literal kind, a `\x` without two hex digits, an octal escape above 0o377,
/// or a str `\N` / `\u` / `\U` escape the surface does not support (the TS
/// reference's `invalidEscapeSequenceMessage`). `escape` is the backslash plus
/// the escape letter, or the whole octal escape.
pub fn invalid_escape_sequence_message(escape: &str) -> String {
    format!("invalid escape sequence '{}'", escape)
}

/// F-203: CPython's refusal of a non-ASCII character inside b'..' / b"..".
pub const PY_BYTES_NON_ASCII: &str = "bytes can only contain ASCII literal characters";

/// F-026: a .runar.zig call argument list or array literal whose elements are
/// not separated by commas (the TS reference's `ZIG_LIST_COMMA`).
pub const ZIG_LIST_COMMA: &str = "expected ',' between list elements";

/// F-026: a second .runar.py statement on the same line (the TS reference's
/// `PY_STATEMENT_LINE_BREAK`).
pub const PY_STATEMENT_LINE_BREAK: &str = "expected a line break between statements";

/// The TS reference's refusal of a Java char literal.
pub const JAVA_CHAR_LITERAL: &str = "char literals are unsupported in Rúnar Java contracts";

/// N-053's refusal of a .runar.rb / .runar.py statement whose first token can
/// begin neither a statement nor an expression (the TS reference's
/// `unsupportedStatementMessage`). `token` is the token's source text.
pub fn unsupported_statement_message(token: &str) -> String {
    format!("Unsupported statement starting with '{}'", token)
}

/// N-004's refusal of a .runar.rb class-body token that is not `prop`,
/// `runar_public`, `params`, `def` or a bare `private` / `public` marker (the
/// TS reference's `unexpectedClassBodyTokenMessage`). It used to be skipped,
/// so an indented `=begin` (lexed as `=`, `begin`) let a "commented-out"
/// method become the only spend path.
pub fn unexpected_class_body_token_message(token: &str) -> String {
    format!("Unexpected token in class body: '{}'", token)
}

/// N-004's refusal of the first token after a .runar.rb class's `end` (the TS
/// reference's `unexpectedTokenAfterClassMessage`).
pub fn unexpected_token_after_class_message(token: &str) -> String {
    format!("Unexpected token after class end: '{}'", token)
}

/// N-050's refusal of a static or class-level method (the TS reference's
/// `staticMethodMessage`): `static` on .runar.ts / .runar.java,
/// `@staticmethod` / `@classmethod` on .runar.py, `def self.m` on .runar.rb,
/// and a `pub fn` without a self receiver on .runar.rs / .runar.zig. `name` is
/// the method name as written in the source.
pub fn static_method_message(name: &str) -> String {
    format!("static methods are not allowed in Rúnar contracts; method '{}' is declared static", name)
}

/// N-331's refusal of a method whose RETURN-type annotation names a type that
/// is not a Rúnar type (the TS reference's `checkReturnType`). The AST keeps no
/// return type, so every surface parser calls this where the annotation is
/// spelled. `None` for any other type; `unknown` is the missing-annotation
/// placeholder, diagnosed elsewhere.
///
/// N-332: when `is_public`, any non-void return type is also refused -- public
/// methods are spending entry points and return void (spec/grammar.md:161).
pub fn unknown_return_type_message(t: &TypeNode, method: &str, is_public: bool) -> Option<String> {
    match t {
        TypeNode::Custom(name) if name == "unknown" => None,
        TypeNode::Custom(name) => Some(format!(
            "Type '{}' of the return value of method '{}' is not a Rúnar type",
            name, method
        )),
        TypeNode::Primitive(super::ast::PrimitiveTypeName::Void) => None,
        _ if is_public => Some(public_return_type_message(method)),
        _ => None,
    }
}

/// N-332's refusal of a PUBLIC method that declares a non-void return type (the
/// TS reference's `publicReturnTypeMessage`).
pub fn public_return_type_message(method: &str) -> String {
    format!(
        "Public method '{}' must not declare a return type: public methods are spending entry points and return void (spec/grammar.md:161)",
        method
    )
}

/// N-023's (R49) refusal, on the .runar.java surface, of an assignment (=,
/// op=, ++, --) to a bare property name that no local or parameter shadows
/// (the TS reference's `bareJavaPropertyAssignmentMessage`). In Java that bare
/// name IS the field.
pub fn bare_java_property_assignment_message(name: &str) -> String {
    format!("bare assignment to property '{name}' is not allowed; write `this.{name} = ...`")
}

/// A tokenizer diagnostic at 1-based `line` / 0-based `column` of `file`.
/// The location is stored in the AST's 1-based column convention, which
/// `format_message` prints back 0-based (N-078).
pub fn lex_error(message: &str, file: &str, line: usize, column: usize) -> Diagnostic {
    Diagnostic::error(
        message,
        Some(SourceLocation { file: file.to_string(), line, column: column + 1 }),
    )
}

/// Like [`lex_error`], for a tokenizer that tracks only a char index.
pub fn lex_error_at_index(message: &str, file: &str, chars: &[char], idx: usize) -> Diagnostic {
    let before = &chars[..idx.min(chars.len())];
    let line = 1 + before.iter().filter(|&&c| c == '\n').count();
    let column = before.iter().rev().take_while(|&&c| c != '\n').count();
    lex_error(message, file, line, column)
}

/// F-337: the (1-based line, 1-based column) of each char index in `starts`
/// — the AST's SourceLocation convention (codegen/emit.rs converts to the
/// source map's 0-based column). `starts` must be non-decreasing.
pub fn char_index_positions(chars: &[char], starts: &[usize]) -> Vec<(usize, usize)> {
    let (mut line, mut line_start, mut scanned) = (1usize, 0usize, 0usize);
    starts
        .iter()
        .map(|&idx| {
            let idx = idx.min(chars.len());
            while scanned < idx {
                if chars[scanned] == '\n' {
                    line += 1;
                    line_start = scanned + 1;
                }
                scanned += 1;
            }
            (line, idx - line_start + 1)
        })
        .collect()
}
