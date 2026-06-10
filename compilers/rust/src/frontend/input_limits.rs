//! DoS-bound input limits + typed errors for the Rust frontend.
//!
//! Mirrors `InputLimits` from `packages/runar-ir-schema/src/input-limits.ts`.
//! See `compilers/go/frontend/input_limits.go` for the reference shape.

use std::fmt;

/// Mirrors `InputLimits.MAX_SOURCE_BYTES` (4 MiB) from the TS schema package.
/// Rúnar source files larger than this are rejected at the parser entry
/// point (`parse_source` / `parse`) BEFORE the tokenizer touches the
/// input. BUG-008 follow-up.
pub const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;

/// Returned when a source payload exceeds [`MAX_SOURCE_BYTES`] at a public
/// parser entry point. Distinct typed error so callers can distinguish
/// DoS-bound rejection from generic syntax errors.
#[derive(Debug, Clone)]
pub struct SourceSizeExceededError {
    pub limit: usize,
    pub actual: usize,
}

impl fmt::Display for SourceSizeExceededError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source exceeds MAX_SOURCE_BYTES (limit={}, actual={})",
            self.limit, self.actual
        )
    }
}

impl std::error::Error for SourceSizeExceededError {}

/// Returns `Some(SourceSizeExceededError)` if `source.len() > MAX_SOURCE_BYTES`,
/// `None` otherwise.
pub fn assert_source_bytes_under_limit(source: &str) -> Option<SourceSizeExceededError> {
    let n = source.len();
    if n > MAX_SOURCE_BYTES {
        Some(SourceSizeExceededError {
            limit: MAX_SOURCE_BYTES,
            actual: n,
        })
    } else {
        None
    }
}
