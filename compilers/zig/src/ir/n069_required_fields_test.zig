//! N-069 — `parseANFProgram` checks every required ANF field for presence and
//! JSON type and names the field path (diagnostic shared verbatim by all seven
//! tiers; the full corpus is conformance/negatives/ir-required-fields-cases.json,
//! driven through this tier's CLI by ir-required-fields.test.ts).
//!
//! Before: an omitted method `body` loaded as an empty method and `compile-ir`
//! exited 0 printing `51` (bare OP_TRUE) for a P2PK contract; `body: "x"` and
//! `params: {}` aborted the process on a union-field access.
//!
//! Proves: the control loads; the three F-084 probe shapes plus a missing name,
//! a missing binding value and a nested binding field are refused with the
//! exact shared message. Does not prove: full schema conformance.

const std = @import("std");
const testing = std.testing;
const json = @import("json.zig");
const required_fields = @import("required_fields.zig");

const control =
    \\{"contractName":"X","properties":[{"name":"pk","type":"PubKey","readonly":true}],"methods":[{"name":"unlock","isPublic":true,"params":[{"name":"sig","type":"Sig"}],"body":[{"name":"t0","value":{"kind":"load_param","name":"sig"}},{"name":"t1","value":{"kind":"load_prop","name":"pk"}},{"name":"t2","value":{"kind":"call","func":"checkSig","args":["t0","t1"]}},{"name":"t3","value":{"kind":"assert","value":"t2"}}]}]}
;

fn expectRefused(src: []const u8, want_err: anyerror, want_msg: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(want_err, json.parseANFProgram(arena.allocator(), src));
    try testing.expectEqualStrings(want_msg, required_fields.lastDiagnostic() orelse "<none>");
}

/// `control` with the first `from` replaced by `to`. Call as `comptime mutate(...)`.
fn mutate(comptime from: []const u8, comptime to: []const u8) []const u8 {
    @setEvalBranchQuota(100_000);
    const i = std.mem.indexOf(u8, control, from) orelse @compileError("pattern not in control: " ++ from);
    return control[0..i] ++ to ++ control[i + from.len ..];
}

/// `,"body":[...]` — the last key of the only method (the control ends `]}]}`).
const body_field = control[std.mem.indexOf(u8, control, ",\"body\":").? .. control.len - 3];

test "N-069 control loads" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const program = try json.parseANFProgram(arena.allocator(), control);
    try testing.expectEqual(@as(usize, 4), program.methods[0].body.len);
}

test "N-069 body omitted" {
    try expectRefused(
        comptime mutate(body_field, ""),
        error.IRRequiredFieldMissing,
        "IR validation: required field methods[0].body is missing",
    );
}

test "N-069 body is a string" {
    try expectRefused(
        comptime mutate(body_field, ",\"body\":\"not-an-array\""),
        error.IRFieldWrongType,
        "IR validation: methods[0].body must be an array, got string",
    );
}

test "N-069 params is an object" {
    try expectRefused(
        comptime mutate("\"params\":[{\"name\":\"sig\",\"type\":\"Sig\"}]", "\"params\":{\"name\":\"sig\",\"type\":\"Sig\"}"),
        error.IRFieldWrongType,
        "IR validation: methods[0].params must be an array, got object",
    );
}

test "N-069 method name missing" {
    try expectRefused(
        comptime mutate("\"name\":\"unlock\",", ""),
        error.IRRequiredFieldMissing,
        "IR validation: required field methods[0].name is missing",
    );
}

test "N-069 binding value missing" {
    try expectRefused(
        comptime mutate("\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"sig\"}", "\"name\":\"t0\""),
        error.IRFieldWrongType,
        "IR validation: methods[0].body[0].value must be an object, got null",
    );
}

test "N-069 nested if-arm binding field" {
    try expectRefused(
        comptime mutate("{\"kind\":\"assert\",\"value\":\"t2\"}", "{\"kind\":\"if\",\"cond\":\"t2\",\"then\":[{\"name\":\"u0\",\"value\":{\"kind\":\"load_param\"}}],\"else\":[]}"),
        error.IRRequiredFieldMissing,
        "IR validation: required field methods[0].body[3].value.then[0].value.name is missing",
    );
}
