//! Structured compiler diagnostics.
//!
//! Provides a `Diagnostic` type that mirrors the TypeScript compiler's
//! `CompilerDiagnostic` type: `{ message, loc?, severity }`.

use super::ast::SourceLocation;
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
    pub fn format_message(&self) -> String {
        if let Some(ref loc) = self.loc {
            if !loc.file.is_empty() {
                if loc.column > 0 {
                    return format!("{}:{}:{}: {}", loc.file, loc.line, loc.column, self.message);
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

/// F-026: a .runar.zig call argument list or array literal whose elements are
/// not separated by commas (the TS reference's `ZIG_LIST_COMMA`).
pub const ZIG_LIST_COMMA: &str = "expected ',' between list elements";

/// F-026: a second .runar.py statement on the same line (the TS reference's
/// `PY_STATEMENT_LINE_BREAK`).
pub const PY_STATEMENT_LINE_BREAK: &str = "expected a line break between statements";

/// The TS reference's refusal of a Java char literal.
pub const JAVA_CHAR_LITERAL: &str = "char literals are unsupported in Rúnar Java contracts";

/// A tokenizer diagnostic at 1-based `line` / 0-based `column` of `file`.
pub fn lex_error(message: &str, file: &str, line: usize, column: usize) -> Diagnostic {
    Diagnostic::error(
        message,
        Some(SourceLocation { file: file.to_string(), line, column }),
    )
}

/// Like [`lex_error`], for a tokenizer that tracks only a char index.
pub fn lex_error_at_index(message: &str, file: &str, chars: &[char], idx: usize) -> Diagnostic {
    let before = &chars[..idx.min(chars.len())];
    let line = 1 + before.iter().filter(|&&c| c == '\n').count();
    let column = before.iter().rev().take_while(|&&c| c != '\n').count();
    lex_error(message, file, line, column)
}
