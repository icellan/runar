//! `fixedArray.syntheticNames` is a trust boundary, and it was parsed as if it
//! could not be malformed.
//!
//! `StateField.fromJsonValue` allocated `synthetic_names` at
//! `sn.array.items.len` but only wrote the entries that happened to be JSON
//! strings, then published the FULL-length slice. A non-string entry therefore
//! left uninitialised slice members that `FixedArrayInfo.deinit` later passed
//! to `allocator.free`. Measured on this exact input before the fix: the parse
//! reported success with `synthetic_names.len == 4` (3 real names + 1 garbage),
//! and `artifact.deinit()` died with
//!
//!     Segmentation fault at address 0xaaaaaaaaaaaaaaaa
//!       std/mem/Allocator.zig:448 in free
//!       sdk_types.zig:544 in FixedArrayInfo.deinit
//!
//! 0xaaaa… being Zig's Debug fill for `undefined`. Unreachable with a
//! compiler-produced artifact; reachable with a hand-written one — and a
//! hand-written artifact is exactly what this boundary has to survive.
//!
//! Truncating to the entries that did parse is not a fix either. These names
//! are POSITIONAL: entry k names state slot k, and `serializeState` writes one
//! word per entry. A short list writes a short state section, which the
//! contract's own on-chain reader cannot satisfy — the unspendable case
//! `7baf01dd` was about.
//!
//! So refuse, the way `8c989dda` refused a JSON float on the `--ir` boundary,
//! and for the same reason: `packages/runar-ir-schema/src/artifact.ts` already
//! types this field as a required `syntheticNames: string[]`, so anything else
//! is outside the format the artifact claims to be in and there is no correct
//! value to guess.

const std = @import("std");
const types = @import("sdk_types.zig");

/// Assert the parser REFUSES `src` with `expected`.
///
/// On a parser that accepts it we deliberately leak the artifact rather than
/// deinit it: pre-fix, freeing the corrupt `synthetic_names` slice segfaults
/// and takes the whole test binary with it, which would hide every other
/// result. The leak is reported by the testing allocator alongside this
/// test's own failure, and cannot happen once the parse is refused.
fn expectRefused(src: []const u8, expected: anyerror) !void {
    const allocator = std.testing.allocator;
    if (types.RunarArtifact.fromJson(allocator, src)) |_| {
        return error.MalformedArtifactWasAccepted;
    } else |err| {
        try std.testing.expectEqual(expected, err);
    }
}

const NON_STRING_ENTRY =
    \\{"contractName":"X","script":"00","stateFields":[
    \\ {"name":"table","type":"FixedArray<bigint, 4>","index":0,
    \\  "fixedArray":{"elementType":"bigint","length":4,
    \\   "syntheticNames":["table__0", 7, "table__2", "table__3"]}}]}
;

const NULL_ENTRY =
    \\{"contractName":"X","script":"00","stateFields":[
    \\ {"name":"table","type":"FixedArray<bigint, 4>","index":0,
    \\  "fixedArray":{"elementType":"bigint","length":4,
    \\   "syntheticNames":["table__0", null, "table__2", "table__3"]}}]}
;

const NOT_AN_ARRAY =
    \\{"contractName":"X","script":"00","stateFields":[
    \\ {"name":"table","type":"FixedArray<bigint, 4>","index":0,
    \\  "fixedArray":{"elementType":"bigint","length":4,
    \\   "syntheticNames":"table__0"}}]}
;

const MISSING =
    \\{"contractName":"X","script":"00","stateFields":[
    \\ {"name":"table","type":"FixedArray<bigint, 4>","index":0,
    \\  "fixedArray":{"elementType":"bigint","length":4}}]}
;

const WELL_FORMED =
    \\{"contractName":"X","script":"00","stateFields":[
    \\ {"name":"table","type":"FixedArray<bigint, 4>","index":0,
    \\  "initialValue":["0n","0n","0n","0n"],
    \\  "fixedArray":{"elementType":"bigint","length":4,
    \\   "syntheticNames":["table__0","table__1","table__2","table__3"]}}]}
;

test "artifact trust boundary: a non-string syntheticNames entry is refused" {
    try expectRefused(NON_STRING_ENTRY, error.MalformedSyntheticNames);
}

test "artifact trust boundary: a null syntheticNames entry is refused" {
    try expectRefused(NULL_ENTRY, error.MalformedSyntheticNames);
}

test "artifact trust boundary: a syntheticNames that is not an array is refused" {
    // Tolerating this left `synthetic_names` empty while `length` still said 4,
    // so `serializeState` wrote a ZERO-word state section for a field the
    // contract reads as four — silent truncation, not a parse detail.
    try expectRefused(NOT_AN_ARRAY, error.MalformedSyntheticNames);
}

test "artifact trust boundary: a fixedArray with no syntheticNames at all is refused" {
    // Required by packages/runar-ir-schema/src/artifact.ts.
    try expectRefused(MISSING, error.MalformedSyntheticNames);
}

test "artifact trust boundary: the well-formed shape still parses and frees cleanly" {
    // The guard must reject the malformed shapes and nothing else. This is the
    // shape every compiler actually emits (and what
    // conformance/sdk-output/tests/fixed-array-write carries); it must survive
    // parse, expose all four names in order, and deinit without leaking — the
    // testing allocator fails this test if it does.
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, WELL_FORMED);
    defer artifact.deinit();

    try std.testing.expectEqual(@as(usize, 1), artifact.state_fields.len);
    const fa = artifact.state_fields[0].fixed_array orelse return error.MissingFixedArrayInfo;
    try std.testing.expectEqual(@as(u32, 4), fa.length);
    try std.testing.expectEqual(@as(usize, 4), fa.synthetic_names.len);
    try std.testing.expectEqualStrings("table__0", fa.synthetic_names[0]);
    try std.testing.expectEqualStrings("table__1", fa.synthetic_names[1]);
    try std.testing.expectEqualStrings("table__2", fa.synthetic_names[2]);
    try std.testing.expectEqualStrings("table__3", fa.synthetic_names[3]);
}

test "artifact trust boundary: refusing a field frees everything parsed before it" {
    // A refusal aborts the stateFields loop before `artifact.state_fields` is
    // assigned, so the artifact-level `errdefer artifact.deinit()` cannot see
    // the fields already built — they need their own errdefer.
    //
    // This uses a LOCAL leak-checking allocator rather than
    // `std.testing.allocator` because the success branch leaks ON PURPOSE (see
    // `expectRefused`), which the runner's per-test leak check would now fail
    // the test for. Originally it was a workaround: the runner never called
    // `std.testing.allocator_instance.deinit()`, so a leak through the shared
    // testing allocator was silent. It no longer is.
    const src =
        \\{"contractName":"X","script":"00","stateFields":[
        \\ {"name":"count","type":"bigint","index":0,"initialValue":"7n"},
        \\ {"name":"table","type":"FixedArray<bigint, 2>","index":1,
        \\  "fixedArray":{"elementType":"bigint","length":2,
        \\   "syntheticNames":["table__0", 7]}}]}
    ;
    var dbg: std.heap.DebugAllocator(.{}) = .init;
    const refused = blk: {
        if (types.RunarArtifact.fromJson(dbg.allocator(), src)) |_| {
            break :blk false; // leaked on purpose — see expectRefused
        } else |err| {
            try std.testing.expectEqual(error.MalformedSyntheticNames, err);
            break :blk true;
        }
    };
    const check = dbg.deinit();
    try std.testing.expect(refused);
    try std.testing.expectEqual(std.heap.Check.ok, check);
}

test "artifact trust boundary: a state field with no fixedArray is untouched by the guard" {
    const allocator = std.testing.allocator;
    const src =
        \\{"contractName":"X","script":"00","stateFields":[
        \\ {"name":"count","type":"bigint","index":0}]}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, src);
    defer artifact.deinit();
    try std.testing.expectEqual(@as(usize, 1), artifact.state_fields.len);
    try std.testing.expect(artifact.state_fields[0].fixed_array == null);
}
