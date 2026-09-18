//! A `FixedArray<T, N>` state field occupies N scalar slots in the state
//! section, not one.
//!
//! `serializeState` / `deserializeState` dispatched purely on
//! `StateField.type_name` and never looked at `StateField.fixed_array`. For a
//! FixedArray field the type name is the whole string `"FixedArray<bigint, 4>"`,
//! which matches none of the scalar cases, so the field fell through to the
//! variable-length push-data branch and a non-`.bytes` value serialised as the
//! single byte `00`.
//!
//! That is a fund-loss defect, not a cosmetic one: the contract's own on-chain
//! state reader rebuilds 4 x OP_NUM2BIN 8 = 32 bytes for `table`, so a deploy
//! carrying a 1-byte state section can never satisfy the continuation covenant
//! and the UTXO is unspendable forever. Measured on
//! `conformance/sdk-output/tests/fixed-array-write`: six tiers agreed on 884
//! bytes, Zig alone emitted 853.
//!
//! Contract (matches packages/runar-sdk/src/state.ts `serializeState`):
//!  - the leaf scalar type comes from peeling EVERY `FixedArray<...>` layer off
//!    `field.type`, not from `fixedArray.elementType` — for a nested array that
//!    is itself another `FixedArray<...>`;
//!  - the slot count is `fixedArray.syntheticNames.length`;
//!  - a value that is not an array (or is short) leaves the remaining slots at
//!    their scalar default rather than truncating the section;
//!  - on decode the flat leaves are regrouped into the nested shape parsed from
//!    `field.type`.

const std = @import("std");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");

const ZERO8 = "0000000000000000";

fn expectZeroWords(hex: []const u8, n: usize) !void {
    try std.testing.expectEqual(n * ZERO8.len, hex.len);
    for (hex) |c| try std.testing.expectEqual(@as(u8, '0'), c);
}

test "state FixedArray: a flat FixedArray<bigint,4> of zeros is 32 bytes, not 1" {
    const allocator = std.testing.allocator;
    var names = [_][]const u8{ "table__0", "table__1", "table__2", "table__3" };
    const fields = [_]types.StateField{.{
        .name = "table",
        .type_name = "FixedArray<bigint, 4>",
        .index = 0,
        .fixed_array = .{ .element_type = "bigint", .length = 4, .synthetic_names = &names },
    }};
    const items = [_]types.StateValue{.{ .int = 0 }} ** 4;
    const values = [_]types.StateValue{.{ .array_value = &items }};

    const got = try state_mod.serializeState(allocator, &fields, &values);
    defer allocator.free(got);
    try std.testing.expectEqualStrings(ZERO8 ** 4, got);
    try expectZeroWords(got, 4);
}

test "state FixedArray: a non-array value still fills every slot" {
    // The conformance fixture's exact path: `ArrayWrite.table` has an array
    // initializer the Zig artifact loader does not turn into an `.array_value`,
    // so the field reaches the serializer as a bare scalar. The TS SDK writes
    // one default-encoded word per synthetic name in that case; anything
    // shorter is an unspendable state section.
    const allocator = std.testing.allocator;
    var names = [_][]const u8{ "table__0", "table__1", "table__2", "table__3" };
    const fields = [_]types.StateField{.{
        .name = "table",
        .type_name = "FixedArray<bigint, 4>",
        .index = 0,
        .fixed_array = .{ .element_type = "bigint", .length = 4, .synthetic_names = &names },
    }};
    const values = [_]types.StateValue{.{ .int = 0 }};

    const got = try state_mod.serializeState(allocator, &fields, &values);
    defer allocator.free(got);
    try expectZeroWords(got, 4);
}

test "state FixedArray: elements encode num2bin-le8 in declaration order" {
    const allocator = std.testing.allocator;
    var names = [_][]const u8{ "table__0", "table__1", "table__2", "table__3" };
    const fields = [_]types.StateField{.{
        .name = "table",
        .type_name = "FixedArray<bigint, 4>",
        .index = 0,
        .fixed_array = .{ .element_type = "bigint", .length = 4, .synthetic_names = &names },
    }};
    const items = [_]types.StateValue{
        .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 }, .{ .int = -4 },
    };
    const values = [_]types.StateValue{.{ .array_value = &items }};

    const got = try state_mod.serializeState(allocator, &fields, &values);
    defer allocator.free(got);
    try std.testing.expectEqualStrings(
        "0100000000000000" ++ "0200000000000000" ++ "0300000000000000" ++ "0400000000000080",
        got,
    );
}

test "state FixedArray: a FixedArray field round-trips through deserializeState" {
    const allocator = std.testing.allocator;
    var names = [_][]const u8{ "table__0", "table__1", "table__2", "table__3" };
    const fields = [_]types.StateField{.{
        .name = "table",
        .type_name = "FixedArray<bigint, 4>",
        .index = 0,
        .fixed_array = .{ .element_type = "bigint", .length = 4, .synthetic_names = &names },
    }};
    const items = [_]types.StateValue{
        .{ .int = 7 }, .{ .int = 0 }, .{ .int = 99 }, .{ .int = -1 },
    };
    const values = [_]types.StateValue{.{ .array_value = &items }};

    const hex = try state_mod.serializeState(allocator, &fields, &values);
    defer allocator.free(hex);

    const back = try state_mod.deserializeState(allocator, &fields, hex);
    defer {
        for (back) |*v| v.deinit(allocator);
        allocator.free(back);
    }
    try std.testing.expectEqual(@as(usize, 1), back.len);
    try std.testing.expect(back[0] == .array_value);
    const row = back[0].array_value;
    try std.testing.expectEqual(@as(usize, 4), row.len);
    try std.testing.expectEqual(@as(i64, 7), row[0].int);
    try std.testing.expectEqual(@as(i64, 0), row[1].int);
    try std.testing.expectEqual(@as(i64, 99), row[2].int);
    try std.testing.expectEqual(@as(i64, -1), row[3].int);
}

test "state FixedArray: a nested 2x2 field is 4 leaf words and regroups on read" {
    // `elementType` here is "FixedArray<bigint, 2>", NOT a scalar — encoding
    // against it would take the push-data branch. The leaf type must come from
    // peeling every layer off `type`.
    const allocator = std.testing.allocator;
    var names = [_][]const u8{ "grid__0__0", "grid__0__1", "grid__1__0", "grid__1__1" };
    const fields = [_]types.StateField{.{
        .name = "grid",
        .type_name = "FixedArray<FixedArray<bigint, 2>, 2>",
        .index = 0,
        .fixed_array = .{
            .element_type = "FixedArray<bigint, 2>",
            .length = 2,
            .synthetic_names = &names,
        },
    }};
    const row0 = [_]types.StateValue{ .{ .int = 10 }, .{ .int = 20 } };
    const row1 = [_]types.StateValue{ .{ .int = 30 }, .{ .int = 40 } };
    const outer = [_]types.StateValue{
        .{ .array_value = &row0 },
        .{ .array_value = &row1 },
    };
    const values = [_]types.StateValue{.{ .array_value = &outer }};

    const hex = try state_mod.serializeState(allocator, &fields, &values);
    defer allocator.free(hex);
    try std.testing.expectEqualStrings(
        "0a00000000000000" ++ "1400000000000000" ++ "1e00000000000000" ++ "2800000000000000",
        hex,
    );

    const back = try state_mod.deserializeState(allocator, &fields, hex);
    defer {
        for (back) |*v| v.deinit(allocator);
        allocator.free(back);
    }
    try std.testing.expect(back[0] == .array_value);
    try std.testing.expectEqual(@as(usize, 2), back[0].array_value.len);
    try std.testing.expectEqual(@as(i64, 10), back[0].array_value[0].array_value[0].int);
    try std.testing.expectEqual(@as(i64, 20), back[0].array_value[0].array_value[1].int);
    try std.testing.expectEqual(@as(i64, 30), back[0].array_value[1].array_value[0].int);
    try std.testing.expectEqual(@as(i64, 40), back[0].array_value[1].array_value[1].int);
}

test "state FixedArray: a FixedArray field does not desynchronise the fields after it" {
    const allocator = std.testing.allocator;
    var names = [_][]const u8{ "table__0", "table__1" };
    const fields = [_]types.StateField{
        .{
            .name = "table",
            .type_name = "FixedArray<bigint, 2>",
            .index = 0,
            .fixed_array = .{ .element_type = "bigint", .length = 2, .synthetic_names = &names },
        },
        .{ .name = "flag", .type_name = "boolean", .index = 1 },
    };
    const items = [_]types.StateValue{ .{ .int = 5 }, .{ .int = 6 } };
    const values = [_]types.StateValue{
        .{ .array_value = &items },
        .{ .boolean = true },
    };

    const hex = try state_mod.serializeState(allocator, &fields, &values);
    defer allocator.free(hex);
    try std.testing.expectEqualStrings(
        "0500000000000000" ++ "0600000000000000" ++ "01",
        hex,
    );

    const back = try state_mod.deserializeState(allocator, &fields, hex);
    defer {
        for (back) |*v| v.deinit(allocator);
        allocator.free(back);
    }
    try std.testing.expectEqual(@as(i64, 5), back[0].array_value[0].int);
    try std.testing.expectEqual(@as(i64, 6), back[0].array_value[1].int);
    try std.testing.expect(back[1].boolean);
}

// ---------------------------------------------------------------------------
// The SECOND half of the same defect: an array `initialValue` never reached
// the state at all.
//
// `StateField.fromJsonValue` stored `initialValue` as a STRING and handled only
// `.string` / `.integer` / `.bool`; a JSON array fell through to `else => {}`,
// leaving `initial_value` null. `RunarContract.init` then took the "no default,
// no constructor arg" branch and seeded the field with the scalar `.int = 0`.
//
// With the serializer fixed, that scalar pads out to N ZERO words — the right
// LENGTH with the wrong CONTENTS. Measured on the sdk-output fixture with its
// initializer changed to [1n,2n,3n,4n]: the TS tier ends
// `...6a 0100000000000000 0200000000000000 0300000000000000 0400000000000000`
// while Zig ended `...6a` + 32 zero bytes. A contract deployed that way commits
// to a state its own constructor semantics never chose, and every later spend
// rebuilds the continuation from the declared defaults — so the covenant check
// fails and the funds are stuck.
// ---------------------------------------------------------------------------

const contract_mod = @import("sdk_contract.zig");

fn expectInitialState(json: []const u8, want_hex: []const u8) !void {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try contract_mod.RunarContract.init(allocator, &artifact, &[_]types.StateValue{});
    defer contract.deinit();

    const hex = try state_mod.serializeState(allocator, artifact.state_fields, contract.state);
    defer allocator.free(hex);
    try std.testing.expectEqualStrings(want_hex, hex);
}

test "state FixedArray: a flat array initialValue seeds every element" {
    try expectInitialState(
        \\{"contractName":"T","parentClass":"StatefulSmartContract","script":"51",
        \\ "abi":{"constructor":{"params":[]},"methods":[]},
        \\ "stateFields":[{"name":"table","type":"FixedArray<bigint, 4>","index":0,
        \\   "initialValue":["1n","2n","3n","4n"],
        \\   "fixedArray":{"elementType":"bigint","length":4,
        \\     "syntheticNames":["table__0","table__1","table__2","table__3"]}}]}
    ,
        "0100000000000000" ++ "0200000000000000" ++ "0300000000000000" ++ "0400000000000000",
    );
}

test "state FixedArray: a nested array initialValue seeds leaves depth-first" {
    try expectInitialState(
        \\{"contractName":"T","parentClass":"StatefulSmartContract","script":"51",
        \\ "abi":{"constructor":{"params":[]},"methods":[]},
        \\ "stateFields":[{"name":"grid","type":"FixedArray<FixedArray<bigint, 2>, 2>","index":0,
        \\   "initialValue":[["10n","20n"],["30n","40n"]],
        \\   "fixedArray":{"elementType":"FixedArray<bigint, 2>","length":2,
        \\     "syntheticNames":["grid__0__0","grid__0__1","grid__1__0","grid__1__1"]}}]}
    ,
        "0a00000000000000" ++ "1400000000000000" ++ "1e00000000000000" ++ "2800000000000000",
    );
}

test "state FixedArray: an all-zero array initialValue still writes N words" {
    try expectInitialState(
        \\{"contractName":"T","parentClass":"StatefulSmartContract","script":"51",
        \\ "abi":{"constructor":{"params":[]},"methods":[]},
        \\ "stateFields":[{"name":"table","type":"FixedArray<bigint, 4>","index":0,
        \\   "initialValue":["0n","0n","0n","0n"],
        \\   "fixedArray":{"elementType":"bigint","length":4,
        \\     "syntheticNames":["table__0","table__1","table__2","table__3"]}}]}
    ,
        "0000000000000000" ** 4,
    );
}
