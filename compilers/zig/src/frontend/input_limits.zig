// DoS-bound input limits + typed errors for the Zig frontend.
//
// Mirrors InputLimits from packages/runar-ir-schema/src/input-limits.ts.
// See compilers/go/frontend/input_limits.go for the reference shape.

const std = @import("std");

/// Mirrors `InputLimits.MAX_SOURCE_BYTES` (4 MiB) from the TS schema package.
/// Rúnar source files larger than this are rejected at the public entry
/// point (compileSource) BEFORE the tokenizer touches the input.
/// BUG-008 follow-up.
pub const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;

/// Typed error set for source-size rejection. Distinct from generic
/// ParseFailed so callers can distinguish DoS-bound rejection.
pub const SourceSizeError = error{SourceSizeExceeded};

/// Returns SourceSizeError.SourceSizeExceeded if source.len > MAX_SOURCE_BYTES,
/// void otherwise.
pub fn assertSourceBytesUnderLimit(source: []const u8) SourceSizeError!void {
    if (source.len > MAX_SOURCE_BYTES) {
        return SourceSizeError.SourceSizeExceeded;
    }
}
