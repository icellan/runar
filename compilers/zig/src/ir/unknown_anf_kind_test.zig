//! Regression tests for F-003 — the JSON loader and the
//! UnknownAnfKindError helper must surface unknown ANF kinds loudly instead
//! of silently returning a no-op or generic error.
//!
//! The JSON-loader tests use an ArenaAllocator because `parseProgram` does
//! not currently install `errdefer` cleanup across its method loop — when
//! `parseANFValue` raises an error mid-program, any allocations made earlier
//! in the same call would otherwise leak. An arena cleanly reclaims them in
//! `defer arena.deinit()`. This is intentional: the test exercises the
//! error path, not the happy-path allocator hygiene that other tests cover.

const std = @import("std");
const json = @import("json.zig");
const unknown_anf_kind = @import("unknown_anf_kind.zig");

test "unknownAnfKind helper returns UnknownAnfKind" {
    try std.testing.expectError(
        error.UnknownAnfKind,
        @as(unknown_anf_kind.UnknownAnfKindError!void, unknown_anf_kind.unknownAnfKind("ghost_kind", "test.helper")),
    );
}

test "json loader: unknown ANF kind surfaces as UnknownAnfKind" {
    // Synthetic program with one binding whose `value.kind` is not a real
    // ANFValue variant. Prior to F-003 this returned a generic
    // ParseError.InvalidKind, hiding the missed dispatch from the caller.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\{
        \\  "contractName": "Bogus",
        \\  "properties": [],
        \\  "methods": [
        \\    {
        \\      "name": "m",
        \\      "isPublic": true,
        \\      "params": [],
        \\      "body": [
        \\        { "name": "t0", "value": { "kind": "totally_made_up_variant" } }
        \\      ]
        \\    }
        \\  ]
        \\}
    ;
    try std.testing.expectError(
        error.UnknownAnfKind,
        json.parseANFProgram(arena.allocator(), src),
    );
}

test "json loader: nested unknown kind inside if-branch also surfaces UnknownAnfKind" {
    // Confirms the error propagates through `parseIf` (which recursively
    // parses then/else branches via BindingError). Without the propagation
    // wiring the recursive call would coerce to `ParseError.InvalidKind` and
    // the diagnostic would be lost.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\{
        \\  "contractName": "Bogus",
        \\  "properties": [],
        \\  "methods": [
        \\    {
        \\      "name": "m",
        \\      "isPublic": true,
        \\      "params": [],
        \\      "body": [
        \\        {
        \\          "name": "t0",
        \\          "value": {
        \\            "kind": "if",
        \\            "cond": "c",
        \\            "then": [
        \\              { "name": "t1", "value": { "kind": "made_up_inner_variant" } }
        \\            ],
        \\            "else": []
        \\          }
        \\        }
        \\      ]
        \\    }
        \\  ]
        \\}
    ;
    try std.testing.expectError(
        error.UnknownAnfKind,
        json.parseANFProgram(arena.allocator(), src),
    );
}
