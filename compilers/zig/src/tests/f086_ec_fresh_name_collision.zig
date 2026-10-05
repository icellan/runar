//! F-086 — a name minted by the EC optimizer must never collide with a name
//! the method already uses.
//!
//! The scalar-fusing rules (9, 10, 11) bind the folded scalar under a
//! generated name (`<binding>_k` since N-112, as in TS; `__ec_opt_N` before) just before
//! the rewritten binding. `freshConstName` never checked whether that name was
//! taken. ANF is single-assignment and stack lowering resolves a name to its
//! shallowest slot, so when `__ec_opt_N` is already a body binding or a method
//! param the two values alias. Reachable from `compile-ir`, where names are
//! attacker-chosen. Pre-fix, `__ec_opt_1 = 999; s = ecAdd(ecMulGen(2),
//! ecMulGen(3)); assert(k == __ec_opt_1)` compiled to a script that accepts
//! k = 5 and rejects the honest k = 999 (@bsv/sdk Spend.validate, strict v1 —
//! F-086 remediation log).
//!
//! Proves: the minted name is fresh w.r.t. every binding (at any depth), param
//! and property; colliding programs compile to exactly the script of their
//! renamed twins; the no-collision name is unchanged.
//! Does not prove: anything about names minted by stack lowering
//! (`_codePart`, `__param_*`, `__merge$*`).

const std = @import("std");
const types = @import("../ir/types.zig");
const json_parser = @import("../ir/json.zig");
const ec_optimizer = @import("../passes/ec_optimizer.zig");
const stack_lower = @import("../passes/stack_lower.zig");
const peephole = @import("../passes/peephole.zig");
const emit = @import("../codegen/emit.zig");
const compiler_api = @import("../compiler_api.zig");

/// `body_name` == "" means no pre-existing body binding (the k check then
/// compares against a fresh `t9c = 999`).
fn programJson(alloc: std.mem.Allocator, body_name: []const u8, k_param: []const u8) ![]u8 {
    const pre = if (body_name.len > 0)
        try std.fmt.allocPrint(alloc, "{{\"name\":\"{s}\",\"value\":{{\"kind\":\"load_const\",\"value\":999}}}},", .{body_name})
    else
        "";
    const rhs_bind = if (body_name.len > 0) "" else "{\"name\":\"t9c\",\"value\":{\"kind\":\"load_const\",\"value\":999}},";
    const rhs = if (body_name.len > 0) body_name else "t9c";
    return std.fmt.allocPrint(alloc,
        \\{{"contractName":"EcOptCollide","properties":[],"methods":[
        \\{{"name":"constructor","isPublic":false,"params":[],"body":[{{"name":"t0","value":{{"kind":"call","func":"super","args":[]}}}}]}},
        \\{{"name":"unlock","isPublic":true,"params":[{{"name":"p","type":"Point"}},{{"name":"{s}","type":"bigint"}}],"body":[
        \\{s}
        \\{{"name":"t1","value":{{"kind":"load_const","value":2}}}},
        \\{{"name":"t2","value":{{"kind":"call","func":"ecMulGen","args":["t1"]}}}},
        \\{{"name":"t3","value":{{"kind":"load_const","value":3}}}},
        \\{{"name":"t4","value":{{"kind":"call","func":"ecMulGen","args":["t3"]}}}},
        \\{{"name":"s","value":{{"kind":"call","func":"ecAdd","args":["t2","t4"]}}}},
        \\{{"name":"t5","value":{{"kind":"load_param","name":"p"}}}},
        \\{{"name":"t6","value":{{"kind":"bin_op","op":"===","left":"s","right":"t5"}}}},
        \\{{"name":"t7","value":{{"kind":"assert","value":"t6"}}}},
        \\{{"name":"t8","value":{{"kind":"load_param","name":"{s}"}}}},
        \\{s}
        \\{{"name":"t9","value":{{"kind":"bin_op","op":"===","left":"t8","right":"{s}"}}}},
        \\{{"name":"t10","value":{{"kind":"assert","value":"t9"}}}}
        \\]}}]}}
    , .{ k_param, pre, k_param, rhs_bind, rhs });
}

fn optimizedUnlock(alloc: std.mem.Allocator, src: []const u8) !types.ANFMethod {
    const program = try ec_optimizer.optimize(alloc, try json_parser.parseANFProgram(alloc, src));
    for (program.methods) |m| {
        if (std.mem.eql(u8, m.name, "unlock")) return m;
    }
    return error.NoUnlock;
}

/// The constant the fused `s` consumes: the unique prior binding of its arg.
fn fusedScalar(m: types.ANFMethod) !i128 {
    var idx: usize = 0;
    for (m.body, 0..) |b, i| {
        if (std.mem.eql(u8, b.name, "s")) idx = i;
    }
    const call = switch (m.body[idx].value) {
        .call => |c| c,
        else => return error.NotRewritten,
    };
    try std.testing.expectEqualStrings("ecMulGen", call.func);
    const arg = call.args[0];
    for (m.params) |p| {
        if (std.mem.eql(u8, p.name, arg)) return error.FusedScalarIsAParam;
    }
    var count: usize = 0;
    var value: ?i128 = null;
    for (m.body[0..idx]) |b| {
        if (!std.mem.eql(u8, b.name, arg)) continue;
        count += 1;
        switch (b.value) {
            .load_const => |lc| switch (lc.value) {
                .integer => |n| value = n,
                else => {},
            },
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 1), count);
    return value orelse error.NotAnIntConst;
}

fn expectSingleAssignment(m: types.ANFMethod) !void {
    for (m.body, 0..) |b, i| {
        for (m.params) |p| {
            if (std.mem.eql(u8, p.name, b.name)) return error.BindingShadowsParam;
        }
        for (m.body[0..i]) |prev| {
            if (std.mem.eql(u8, prev.name, b.name)) return error.BindingAssignedTwice;
        }
    }
}

fn scriptHex(alloc: std.mem.Allocator, src: []const u8) ![]const u8 {
    const program = try ec_optimizer.optimize(alloc, try json_parser.parseANFProgram(alloc, src));
    const stack_program = try stack_lower.lower(alloc, program);
    const methods = try peephole.optimize(alloc, stack_program.methods);
    const optimized = types.StackProgram{
        .methods = methods,
        .contract_name = stack_program.contract_name,
        .properties = stack_program.properties,
        .constructor_params = stack_program.constructor_params,
    };
    return compiler_api.extractArtifactScript(try emit.emitArtifact(alloc, optimized, program));
}

test "F-086 control: no collision keeps the historical s_k name" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const m = try optimizedUnlock(alloc, try programJson(alloc, "", "k"));
    var found = false;
    for (m.body) |b| found = found or std.mem.eql(u8, b.name, "s_k");
    try std.testing.expect(found);
    try std.testing.expectEqual(@as(i128, 5), try fusedScalar(m));
}

test "F-086: a pre-existing body binding s_k is not shadowed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const m = try optimizedUnlock(alloc, try programJson(alloc, "s_k", "k"));
    try expectSingleAssignment(m);
    try std.testing.expectEqual(@as(i128, 5), try fusedScalar(m));
}

test "F-086: a method param named s_k is not shadowed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const m = try optimizedUnlock(alloc, try programJson(alloc, "", "s_k"));
    try expectSingleAssignment(m);
    try std.testing.expectEqual(@as(i128, 5), try fusedScalar(m));
}

test "F-086: colliding programs compile like their renamed twins" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    // std.mem.eql, not expectEqualStrings: the scripts are ~1.3 MB each.
    try std.testing.expect(std.mem.eql(
        u8,
        try scriptHex(alloc, try programJson(alloc, "zz_unused", "k")),
        try scriptHex(alloc, try programJson(alloc, "s_k", "k")),
    ));
    try std.testing.expect(std.mem.eql(
        u8,
        try scriptHex(alloc, try programJson(alloc, "", "zz")),
        try scriptHex(alloc, try programJson(alloc, "", "s_k")),
    ));
}
