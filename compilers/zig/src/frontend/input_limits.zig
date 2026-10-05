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
// sighash type) and `@embedAlways` (#109, readonly-field DCE opt-out). The
// eight non-TS surface parsers ignore comments, so silently dropping a
// directive would change signing / DCE semantics — those formats reject rather
// than diverge. The `.runar.ts` parse path is exempt (it implements the
// directives) — the guard callers narrow accordingly.
// ---------------------------------------------------------------------------

pub const SIGHASH_DIRECTIVE_ERROR = "@sighash directive (issue #123) is only honoured on the TypeScript (.runar.ts) surface; write the contract in .runar.ts where @sighash is implemented";
pub const EMBED_ALWAYS_DIRECTIVE_ERROR = "@embedAlways directive (issue #109) is only honoured on the TypeScript (.runar.ts) surface; write the contract in .runar.ts where @embedAlways is implemented";

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
    return null;
}

// ---------------------------------------------------------------------------
// N-136: the size guard above (`assertSourceBytesUnderLimit`) was reachable
// only through `runPipeline`'s Pass 0. `compiler_api.parseSource` (the
// format-dispatching entry) and every one of the nine per-format
// `passes/parse_*.zig` functions it dispatches to are `pub fn` and
// re-exported (directly, for `parseZig`; via `parseSource`, for the rest) by
// `frontend_api.zig` for the Zig SDK's direct use — so a caller reaching any
// of those ten entries without going through `runPipeline` got no DoS-bound
// rejection at all. Each entry now calls `sourceSizeGuardErrors` first.
// ---------------------------------------------------------------------------

var source_size_exceeded_fallback = [_][]const u8{"source exceeds MAX_SOURCE_BYTES"};

/// Returns an allocated one-element `[][]const u8` carrying the DoS-bound
/// size-exceeded diagnostic when `source` exceeds `MAX_SOURCE_BYTES`, or
/// `null` when it is within bounds (strictly: `source.len <=
/// MAX_SOURCE_BYTES` is accepted, matching `assertSourceBytesUnderLimit`).
pub fn sourceSizeGuardErrors(allocator: std.mem.Allocator, source: []const u8) ?[][]const u8 {
    if (source.len <= MAX_SOURCE_BYTES) return null;
    const text = std.fmt.allocPrint(
        allocator,
        "source exceeds MAX_SOURCE_BYTES (limit={d}, actual={d})",
        .{ MAX_SOURCE_BYTES, source.len },
    ) catch return source_size_exceeded_fallback[0..];
    const out = allocator.alloc([]const u8, 1) catch return source_size_exceeded_fallback[0..];
    out[0] = text;
    return out;
}
