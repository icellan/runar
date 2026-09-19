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

// ---------------------------------------------------------------------------
// Fail-closed guard for author-facing comment directives that the Zig frontend
// honours ONLY on the `.runar.ts` surface (matching the TS reference compiler,
// which implements them only there): `@sighash <FLAGS>` (#123, per-method
// sighash type), `@embedAlways` (#109, readonly-field DCE opt-out), and
// `@bindingVariant <lowS|all>` (per-method Any-S binding construction). The
// eight non-TS surface parsers ignore comments, so silently dropping a
// directive would change signing / DCE semantics — those formats reject rather
// than diverge. The `.runar.ts` parse path is exempt (it implements the
// directives) — the guard callers narrow accordingly.
// ---------------------------------------------------------------------------

pub const SIGHASH_DIRECTIVE_ERROR = "@sighash directive (issue #123) is only honoured on the TypeScript (.runar.ts) surface; write the contract in .runar.ts where @sighash is implemented";
pub const EMBED_ALWAYS_DIRECTIVE_ERROR = "@embedAlways directive (issue #109) is only honoured on the TypeScript (.runar.ts) surface; write the contract in .runar.ts where @embedAlways is implemented";
pub const BINDING_VARIANT_DIRECTIVE_ERROR = "@bindingVariant directive is only honoured on the TypeScript (.runar.ts) surface; write the contract in .runar.ts where @bindingVariant is implemented";

fn isWordByte(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or c == '_';
}

/// True when `marker` (which begins with a non-word `@`) appears in `source`
/// followed by a word boundary — i.e. the next byte is not `[A-Za-z0-9_]`.
/// Mirrors the TypeScript compiler's `/@sighash\b/` / `/@embedAlways\b/` scans
/// so an identifier like `sighashType` does not trip the guard.
pub fn containsDirectiveToken(source: []const u8, marker: []const u8) bool {
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, source, i, marker)) |pos| {
        const after = pos + marker.len;
        if (after >= source.len or !isWordByte(source[after])) return true;
        i = pos + 1;
    }
    return false;
}

/// Returns the fail-closed diagnostic message for the first unsupported
/// directive in `source`, or null when the source is clean.
pub fn unsupportedDirectiveError(source: []const u8) ?[]const u8 {
    if (containsDirectiveToken(source, "@sighash")) return SIGHASH_DIRECTIVE_ERROR;
    if (containsDirectiveToken(source, "@embedAlways")) return EMBED_ALWAYS_DIRECTIVE_ERROR;
    if (containsDirectiveToken(source, "@bindingVariant")) return BINDING_VARIANT_DIRECTIVE_ERROR;
    return null;
}
