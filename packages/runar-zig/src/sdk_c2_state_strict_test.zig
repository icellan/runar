//! C2 — `deserializeState` failed OPEN.
//!
//! The state blob is read back out of a deployed locking script's OP_RETURN
//! tail (`RunarContract.fromUtxo` -> `extractStateFromScript` ->
//! `deserializeState`). That script is something any third party can
//! construct, so the blob is untrusted input — and the caller then builds and
//! SIGNS a continuation output committing to whatever state came back.
//!
//! Every arm of the Zig decoder (`sdk_state.zig:510+`) bounds-checked, returned
//! a DEFAULT and then advanced the NOMINAL width anyway, desynchronising every
//! later field, and `deserializeState` had no trailing-byte check at all.
//! Measured before the fix, `zig build test` exit 0, 367 passed:
//!
//!     2a00000000000000            a,b bigint    -> int(42) int(0)
//!     2a.. + 01.. + deadbeef      a,b bigint    -> int(42) int(1)
//!     4b aaaaaa                   m ByteString  -> bytes("")
//!     aa x10                      k PubKey      -> bytes("")
//!     55                          m ByteString  -> bytes("")
//!
//! The semantics here are TypeScript's (C28, packages/runar-sdk/src/state.ts,
//! test c28-state-strict.test.ts): refuse rather than default, and refuse
//! trailing bytes. All seven SDKs read the SAME wire format, so the triggering
//! conditions must be identical even though each tier uses its own error type.

const std = @import("std");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");

/// Decode and free, returning only whether it was accepted.
fn refuses(fields: []const types.StateField, blob: []const u8) !void {
    const a = std.testing.allocator;
    if (state_mod.deserializeState(a, fields, blob)) |vals| {
        defer {
            for (vals) |*v| v.deinit(a);
            a.free(vals);
        }
        std.debug.print("accepted a hostile blob \"{s}\"\n", .{blob});
        return error.TestUnexpectedResult;
    } else |_| {
        // Refused, as required.
    }
}

const TWO_INTS = [_]types.StateField{
    .{ .name = "a", .type_name = "bigint", .index = 0 },
    .{ .name = "b", .type_name = "bigint", .index = 1 },
};
const BYTESTR = [_]types.StateField{.{ .name = "blob", .type_name = "ByteString", .index = 0 }};
const PUBKEY = [_]types.StateField{.{ .name = "k", .type_name = "PubKey", .index = 0 }};

/// Every fixed-width type and its declared width in bytes.
const FIXED_WIDTHS = [_]struct { name: []const u8, width: usize }{
    .{ .name = "boolean", .width = 1 },
    .{ .name = "bool", .width = 1 },
    .{ .name = "bigint", .width = 8 },
    .{ .name = "int", .width = 8 },
    .{ .name = "PubKey", .width = 33 },
    .{ .name = "Addr", .width = 20 },
    .{ .name = "Ripemd160", .width = 20 },
    .{ .name = "Sha256", .width = 32 },
    .{ .name = "Point", .width = 64 },
    .{ .name = "P256Point", .width = 64 },
    .{ .name = "P384Point", .width = 96 },
};

fn rep(allocator: std.mem.Allocator, unit: []const u8, n: usize) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    for (0..n) |_| try out.appendSlice(allocator, unit);
    return out.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// The five hostile blobs from the finding, verbatim.
// ---------------------------------------------------------------------------

test "C2: a truncated trailing bigint is refused" {
    try std.testing.expectError(
        error.TruncatedStateSection,
        state_mod.deserializeState(std.testing.allocator, &TWO_INTS, "2a00000000000000"),
    );
}

test "C2: trailing bytes are refused" {
    try std.testing.expectError(
        error.TrailingStateBytes,
        state_mod.deserializeState(
            std.testing.allocator,
            &TWO_INTS,
            "2a000000000000000100000000000000deadbeef",
        ),
    );
}

test "C2: a push payload running past the end is refused" {
    try std.testing.expectError(
        error.TruncatedStateSection,
        state_mod.deserializeState(std.testing.allocator, &BYTESTR, "4baaaaaa"),
    );
}

test "C2: a short PubKey is refused" {
    try std.testing.expectError(
        error.TruncatedStateSection,
        state_mod.deserializeState(std.testing.allocator, &PUBKEY, "aaaaaaaaaaaaaaaaaaaa"),
    );
}

test "C2: a byte that is not a push opcode is refused" {
    try std.testing.expectError(
        error.MalformedStateSection,
        state_mod.deserializeState(std.testing.allocator, &BYTESTR, "55"),
    );
}

// ---------------------------------------------------------------------------
// Truncation, exhaustively
// ---------------------------------------------------------------------------

test "C2: every fixed-width arm refuses a blob one byte short" {
    const a = std.testing.allocator;
    for (FIXED_WIDTHS) |ty| {
        const fields = [_]types.StateField{.{ .name = "v", .type_name = ty.name, .index = 0 }};
        const short = try rep(a, "aa", ty.width - 1);
        defer a.free(short);
        try refuses(&fields, short);
    }
}

test "C2: push framing is bounds-checked" {
    const blobs = [_][]const u8{
        "4c", // OP_PUSHDATA1, no length byte
        "4c05aabb", // declares 5 bytes, 2 supplied
        "4d", // OP_PUSHDATA2, no length bytes
        "4d00", // half a length
        "4d0500aabb", // declares 5, 2 supplied
        "4e", // OP_PUSHDATA4, no length bytes
        "4e05000000", // declares 5, none supplied
        "05aabb", // direct push declares 5, 2 supplied
    };
    for (blobs) |blob| try refuses(&BYTESTR, blob);
}

test "C2: a missing push opcode byte entirely is refused" {
    const fields = [_]types.StateField{
        .{ .name = "n", .type_name = "bigint", .index = 0 },
        .{ .name = "blob", .type_name = "ByteString", .index = 1 },
    };
    // 8 bytes of bigint and nothing else — the ByteString has no opcode byte.
    try refuses(&fields, "0100000000000000");
}

test "C2: a truncated fixed-array element is refused" {
    var synth = [_][]const u8{ "board__0", "board__1", "board__2" };
    const fields = [_]types.StateField{.{
        .name = "board",
        .type_name = "FixedArray<bigint, 3>",
        .index = 0,
        .fixed_array = .{ .length = 3, .element_type = "bigint", .synthetic_names = &synth },
    }};
    // 3 bigints = 24 bytes; supply 20.
    try refuses(&fields, "01000000000000000200000000000000" ++ "03000000");
}

test "C2: a blob that is not a whole number of bytes is refused" {
    const fields = [_]types.StateField{.{ .name = "count", .type_name = "bigint", .index = 0 }};
    try refuses(&fields, "00112233445566778");
}

// ---------------------------------------------------------------------------
// Overlong tails
// ---------------------------------------------------------------------------

test "C2: one unexpected trailing byte is refused" {
    const fields = [_]types.StateField{.{ .name = "a", .type_name = "bigint", .index = 0 }};
    try std.testing.expectError(
        error.TrailingStateBytes,
        state_mod.deserializeState(std.testing.allocator, &fields, "2a00000000000000ff"),
    );
}

test "C2: a trailing byte after a variable-length field is refused" {
    try std.testing.expectError(
        error.TrailingStateBytes,
        state_mod.deserializeState(std.testing.allocator, &BYTESTR, "03aabbcc00"),
    );
}

test "C2: a whole extra field is refused" {
    const one = [_]types.StateField{.{ .name = "a", .type_name = "bigint", .index = 0 }};
    try std.testing.expectError(
        error.TrailingStateBytes,
        state_mod.deserializeState(
            std.testing.allocator,
            &one,
            "01000000000000000200000000000000",
        ),
    );
}

test "C2: extractStateFromScript surfaces a corrupted continuation" {
    const a = std.testing.allocator;
    var fields = [_]types.StateField{.{ .name = "count", .type_name = "bigint", .index = 0 }};
    var artifact = types.RunarArtifact{ .allocator = a };
    artifact.state_fields = &fields;
    // OP_1 OP_RETURN <8-byte bigint> <one junk byte>
    try std.testing.expectError(
        error.TrailingStateBytes,
        state_mod.extractStateFromScript(a, &artifact, "516a0500000000000000ff"),
    );
}

// ---------------------------------------------------------------------------
// CONTROLS — a guard that rejects legitimate state is just as broken.
// ---------------------------------------------------------------------------

test "C2 control: a well-formed mixed-type record still round-trips" {
    const a = std.testing.allocator;
    const fields = [_]types.StateField{
        .{ .name = "count", .type_name = "bigint", .index = 0 },
        .{ .name = "active", .type_name = "boolean", .index = 1 },
        .{ .name = "owner", .type_name = "PubKey", .index = 2 },
        .{ .name = "blob", .type_name = "ByteString", .index = 3 },
    };
    const owner = try rep(a, "cd", 33);
    defer a.free(owner);
    const values = [_]types.StateValue{
        .{ .int = -9 },
        .{ .boolean = true },
        .{ .bytes = owner },
        .{ .bytes = "deadbeef" },
    };

    const hex = try state_mod.serializeState(a, &fields, &values);
    defer a.free(hex);

    const back = try state_mod.deserializeState(a, &fields, hex);
    defer {
        for (back) |*v| v.deinit(a);
        a.free(back);
    }
    try std.testing.expectEqual(@as(i64, -9), back[0].int);
    try std.testing.expect(back[1].boolean);
    try std.testing.expectEqualStrings(owner, back[2].bytes);
    try std.testing.expectEqualStrings("deadbeef", back[3].bytes);
}

test "C2 control: edge-shaped but legitimate blobs still round-trip" {
    const a = std.testing.allocator;

    // A 1-byte ByteString in the OP_1..OP_16 value range: <len><data>, the
    // compiler's on-chain state codec — NOT the MINIMALDATA opcode form ("55"),
    // which the contract's own script cannot read.
    {
        const values = [_]types.StateValue{.{ .bytes = "05" }};
        const hex = try state_mod.serializeState(a, &BYTESTR, &values);
        defer a.free(hex);
        try std.testing.expectEqualStrings("0105", hex);
        const back = try state_mod.deserializeState(a, &BYTESTR, hex);
        defer {
            for (back) |*v| v.deinit(a);
            a.free(back);
        }
        try std.testing.expectEqualStrings("05", back[0].bytes);
    }

    // An empty ByteString.
    {
        const values = [_]types.StateValue{.{ .bytes = "" }};
        const hex = try state_mod.serializeState(a, &BYTESTR, &values);
        defer a.free(hex);
        const back = try state_mod.deserializeState(a, &BYTESTR, hex);
        defer {
            for (back) |*v| v.deinit(a);
            a.free(back);
        }
        try std.testing.expectEqualStrings("", back[0].bytes);
    }

    // The empty record.
    {
        const back = try state_mod.deserializeState(a, &[_]types.StateField{}, "");
        defer a.free(back);
        try std.testing.expectEqual(@as(usize, 0), back.len);
    }

    // A maximal direct push (75 bytes) and an OP_PUSHDATA1 payload (76 bytes).
    for ([_]usize{ 75, 76, 300 }) |n| {
        const payload = try rep(a, "ab", n);
        defer a.free(payload);
        const values = [_]types.StateValue{.{ .bytes = payload }};
        const hex = try state_mod.serializeState(a, &BYTESTR, &values);
        defer a.free(hex);
        const back = try state_mod.deserializeState(a, &BYTESTR, hex);
        defer {
            for (back) |*v| v.deinit(a);
            a.free(back);
        }
        try std.testing.expectEqualStrings(payload, back[0].bytes);
    }

    // Every raw fixed-width type at its exact width.
    for (FIXED_WIDTHS[4..]) |ty| {
        const fields = [_]types.StateField{.{ .name = "v", .type_name = ty.name, .index = 0 }};
        const payload = try rep(a, "7e", ty.width);
        defer a.free(payload);
        const back = try state_mod.deserializeState(a, &fields, payload);
        defer {
            for (back) |*v| v.deinit(a);
            a.free(back);
        }
        try std.testing.expectEqualStrings(payload, back[0].bytes);
    }
}

test "C2 control: a legitimate continuation still restores" {
    const a = std.testing.allocator;
    var fields = [_]types.StateField{.{ .name = "count", .type_name = "bigint", .index = 0 }};
    var artifact = types.RunarArtifact{ .allocator = a };
    artifact.state_fields = &fields;
    const got = (try state_mod.extractStateFromScript(a, &artifact, "516a0500000000000000")).?;
    defer {
        for (got) |*v| v.deinit(a);
        a.free(got);
    }
    try std.testing.expectEqual(@as(i64, 5), got[0].int);
}

// ---------------------------------------------------------------------------
// Missing value for a raw fixed-width field — the byte divergence.
//
// Zig wrote "" (zero bytes for a field the artifact declares N bytes wide) for
// any non-.bytes value, Python/Ruby the same, Go "<nil>", Java "null", TS
// "undefined". None deploys a state section the contract can read; they just
// corrupt it differently. Refusing is the only answer that is the same in every
// tier.
// ---------------------------------------------------------------------------

test "C2: serializing a missing raw fixed-width value is refused" {
    const a = std.testing.allocator;
    for (FIXED_WIDTHS[4..]) |ty| {
        const fields = [_]types.StateField{.{ .name = "v", .type_name = ty.name, .index = 0 }};
        // An .int where the artifact declares N raw bytes: no value the encoder
        // can write.
        const values = [_]types.StateValue{.{ .int = 0 }};
        try std.testing.expectError(
            error.MissingStateValue,
            state_mod.serializeState(a, &fields, &values),
        );
    }
}
