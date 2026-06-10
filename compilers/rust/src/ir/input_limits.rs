//! DoS-bound input limits + typed errors for the Rust ANF IR loader.
//!
//! Mirrors `InputLimits` from `packages/runar-ir-schema/src/input-limits.ts`
//! and the Go reference at `compilers/go/ir/input_limits.go`.
//!
//! BUG-008 follow-up.

use std::fmt;

/// Mirrors `InputLimits.MAX_IR_BYTES` (16 MiB) from the TS schema package.
/// Any ANF IR JSON larger than this is rejected at the loader entry points
/// (`load_ir` / `load_ir_from_str`) BEFORE `serde_json::from_str` runs so
/// a malicious caller cannot exhaust memory / CPU with a giant payload.
pub const MAX_IR_BYTES: usize = 16 * 1024 * 1024;

/// Mirrors `InputLimits.MAX_NESTING` (512) from the TS schema package.
/// ANF IR JSON whose structural nesting (objects + arrays) exceeds this
/// is rejected. Prevents stack-exhaustion DoS via deeply nested JSON.
pub const MAX_IR_NESTING: usize = 512;

/// Returned when an IR JSON payload exceeds [`MAX_IR_BYTES`] at a public
/// loader entry point. Distinct typed error so callers can distinguish
/// DoS-bound rejection from generic deserialisation failures.
#[derive(Debug, Clone)]
pub struct IRSizeExceededError {
    pub limit: usize,
    pub actual: usize,
}

impl fmt::Display for IRSizeExceededError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IR JSON exceeds MAX_IR_BYTES (limit={}, actual={})",
            self.limit, self.actual
        )
    }
}

impl std::error::Error for IRSizeExceededError {}

/// Returned when an IR JSON payload's structural nesting (objects +
/// arrays) exceeds [`MAX_IR_NESTING`].
#[derive(Debug, Clone)]
pub struct IRNestingExceededError {
    pub limit: usize,
}

impl fmt::Display for IRNestingExceededError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IR JSON nesting exceeds MAX_NESTING (limit={})",
            self.limit
        )
    }
}

impl std::error::Error for IRNestingExceededError {}

/// Returns `Some(IRSizeExceededError)` if `data.len() > MAX_IR_BYTES`.
pub fn assert_ir_bytes_under_limit(data: &[u8]) -> Option<IRSizeExceededError> {
    if data.len() > MAX_IR_BYTES {
        Some(IRSizeExceededError {
            limit: MAX_IR_BYTES,
            actual: data.len(),
        })
    } else {
        None
    }
}

/// Iteratively walks the raw JSON bytes and returns
/// `Some(IRNestingExceededError)` the first time the nesting depth
/// (objects + arrays) exceeds [`MAX_IR_NESTING`]. Runs BEFORE
/// `serde_json::from_str` so a deeply-nested payload cannot exhaust the
/// thread stack inside the deserializer.
///
/// Skips strings (respecting backslash-escapes) so a `{` inside a JSON
/// string doesn't count toward depth.
pub fn assert_ir_nesting_under_limit(data: &[u8]) -> Option<IRNestingExceededError> {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in data {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            if b == b'\\' {
                escaped = true;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_IR_NESTING {
                    return Some(IRNestingExceededError {
                        limit: MAX_IR_NESTING,
                    });
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    None
}
