//! Typed error raised by ANF / Stack-IR / constant-fold dispatch sites when
//! they encounter an ANF value kind they don't recognize.
//!
//! Historically these dispatchers used silent default branches that returned
//! a no-op value (the original ANFValue, an empty refs list, `false` for
//! side-effect checks). Adding a new ANFValue variant and forgetting to wire
//! it into every dispatch site (see CLAUDE.md § Adding a New ANF Value Kind)
//! would then silently corrupt output instead of failing loudly.
//!
//! Mirrors the TypeScript reference compiler's `UnknownANFKindError`
//! (packages/runar-ir-schema/src/unknown-anf-kind-error.ts).

const std = @import("std");

pub const UnknownAnfKindError = error{UnknownAnfKind};

/// Format and log an UnknownAnfKind diagnostic before returning the error.
/// Callers propagate the returned error up the call chain — Zig requires the
/// error to be declared in the function's error union for the propagation to
/// type-check.
///
/// The diagnostic is emitted at `warn` level (not `err`) so that negative-path
/// tests that intentionally exercise this code path do not trip Zig 0.16's
/// `log_err_count` test-failure mechanism. Production callers still see the
/// message — Zig's default log level prints `warn` to stderr, and the typed
/// `error.UnknownAnfKind` is the authoritative signal for the failure.
pub fn unknownAnfKind(kind: []const u8, location: []const u8) UnknownAnfKindError {
    std.log.warn(
        "unknown ANF kind '{s}' encountered in {s} — if you added a new ANFValue variant, update all dispatch sites (see CLAUDE.md § Adding a New ANF Value Kind for the recipe)",
        .{ kind, location },
    );
    return error.UnknownAnfKind;
}

// ============================================================================
// Tests
// ============================================================================

test "unknownAnfKind returns UnknownAnfKind error" {
    const err = unknownAnfKind("totally_made_up_kind", "test.location");
    try std.testing.expectError(error.UnknownAnfKind, @as(UnknownAnfKindError!void, err));
}

test "unknownAnfKind error union round-trips" {
    const Wrapper = struct {
        fn call() UnknownAnfKindError!u32 {
            return unknownAnfKind("foo", "test.wrapper");
        }
    };
    try std.testing.expectError(error.UnknownAnfKind, Wrapper.call());
}
