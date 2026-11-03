//! N-071 — `parseANFProgram` refuses a public method that does not END with an
//! assert, with the diagnostic shared verbatim by all seven tiers (the full
//! corpus is conformance/negatives/ir-terminal-assert-cases.json, driven
//! through this tier's CLI by ir-terminal-assert.test.ts).
//!
//! Before: `"body": []` or a body with no assert made `compile-ir` exit 0
//! printing `51` (bare OP_TRUE), and an `if` whose else arm ended in
//! `load_const true` compiled to a script an empty signature spends.
//!
//! Proves: the control and a both-arm `if` load; each corpus shape is refused
//! with the exact shared message. Does not prove: that an accepted program is
//! secure — ending in an assert is necessary, not sufficient.

const std = @import("std");
const testing = std.testing;
const json = @import("json.zig");
const required_fields = @import("required_fields.zig");

const control =
    \\{"contractName":"X","properties":[{"name":"pk","type":"PubKey","readonly":true}],"methods":[{"name":"unlock","isPublic":true,"params":[{"name":"sig","type":"Sig"}],"body":[{"name":"t0","value":{"kind":"load_param","name":"sig"}},{"name":"t1","value":{"kind":"load_prop","name":"pk"}},{"name":"t2","value":{"kind":"call","func":"checkSig","args":["t0","t1"]}},{"name":"t3","value":{"kind":"assert","value":"t2"}}]}]}
;

const shared_error = "IR validation: public method 'unlock' must end with an assert() call (or an if/else whose arms both do, or a terminal raw_script with out_arity 1); otherwise the value its last binding leaves on the stack decides the spend";

const assert_t3 = "{\"name\":\"t3\",\"value\":{\"kind\":\"assert\",\"value\":\"t2\"}}";

/// `control` with the first `from` replaced by `to`. Call as `comptime mutate(...)`.
fn mutate(comptime from: []const u8, comptime to: []const u8) []const u8 {
    @setEvalBranchQuota(100_000);
    const i = std.mem.indexOf(u8, control, from) orelse @compileError("pattern not in control: " ++ from);
    return control[0..i] ++ to ++ control[i + from.len ..];
}

/// The whole body array of the only method (the control ends `]}]}`).
const body_array = control[std.mem.indexOf(u8, control, "\"body\":").? + 7 .. control.len - 3];

fn expectLoads(src: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    _ = try json.parseANFProgram(arena.allocator(), src);
}

fn expectRefused(src: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.PublicMethodMissingTerminalAssert, json.parseANFProgram(arena.allocator(), src));
    try testing.expectEqualStrings(shared_error, required_fields.lastDiagnostic() orelse "<none>");
}

test "N-071 control loads" {
    try expectLoads(control);
}

test "N-071 if whose arms both end with an assert loads" {
    try expectLoads(comptime mutate(assert_t3, "{\"name\":\"t3\",\"value\":{\"kind\":\"if\",\"cond\":\"t2\",\"then\":[{\"name\":\"t4\",\"value\":{\"kind\":\"assert\",\"value\":\"t2\"}}],\"else\":[{\"name\":\"t5\",\"value\":{\"kind\":\"assert\",\"value\":\"t2\"}}]}}"));
}

test "N-071 body empty" {
    try expectRefused(comptime mutate(body_array, "[]"));
}

test "N-071 body without assert" {
    try expectRefused(comptime mutate(body_array, "[{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"sig\"}}]"));
}

test "N-071 binding after last assert" {
    try expectRefused(comptime mutate(assert_t3, assert_t3 ++ ",{\"name\":\"t4\",\"value\":{\"kind\":\"load_const\",\"value\":true}}"));
}

test "N-071 if else arm without assert" {
    try expectRefused(comptime mutate(assert_t3, "{\"name\":\"t3\",\"value\":{\"kind\":\"if\",\"cond\":\"t2\",\"then\":[{\"name\":\"t4\",\"value\":{\"kind\":\"assert\",\"value\":\"t2\"}}],\"else\":[{\"name\":\"t5\",\"value\":{\"kind\":\"load_const\",\"value\":true}}]}}"));
}

test "N-071 if empty else arm" {
    try expectRefused(comptime mutate(assert_t3, "{\"name\":\"t3\",\"value\":{\"kind\":\"if\",\"cond\":\"t2\",\"then\":[{\"name\":\"t4\",\"value\":{\"kind\":\"assert\",\"value\":\"t2\"}}],\"else\":[]}}"));
}

test "N-071 terminal raw_script with out_arity 0" {
    try expectRefused(comptime mutate(assert_t3, assert_t3 ++ ",{\"name\":\"t4\",\"value\":{\"kind\":\"raw_script\",\"bytes\":\"61\",\"in_arity\":0,\"out_arity\":0}}"));
}
