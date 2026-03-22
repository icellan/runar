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
