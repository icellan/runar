//! N-265 — `parseANFProgram` refuses a cycle, or an acyclic chain past
//! N-180's MAX_CALL_DEPTH, in the IR method_call graph. This tier had no
//! such check anywhere on the `--ir` path (`compile-ir`) before this —
//! stack lowering inlined every method_call with no cycle or depth guard.
//!
//! Proves: a chain right at MAX_CALL_DEPTH loads; one past it is refused
//! naming the first offending method in declaration order with the shared
//! diagnostic; a 20000-link chain is refused promptly (no overflow, no
//! multi-second hang); and a direct/mutual cycle is refused with the shared
//! recursion wording. Does not prove that the other six tiers' --ir loaders
//! agree (conformance/negatives/n265-ir-call-depth-parity.test.ts does).

const std = @import("std");
const testing = std.testing;
const json = @import("json.zig");
const required_fields = @import("required_fields.zig");
const input_limits = @import("../frontend/input_limits.zig");

/// verify(a) calls m0(a); m_i calls m_{i+1} for i < n; m_{n-1} returns its
/// argument unchanged. Declaration order is m0..m(n-1) THEN verify, matching
/// N-180's own chain fixture: at n=MAX_CALL_DEPTH only `verify` exceeds the
/// bound, but at n=20000 `m0` is declared first and already exceeds it.
fn chainIR(allocator: std.mem.Allocator, n: usize) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    try buf.appendSlice(allocator, "{\"contractName\":\"Chain\",\"properties\":[],\"methods\":[");
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (i > 0) try buf.appendSlice(allocator, ",");
        if (i == n - 1) {
            const seg = try std.fmt.allocPrint(allocator,
                "{{\"name\":\"m{d}\",\"isPublic\":false,\"params\":[{{\"name\":\"x\",\"type\":\"bigint\"}}],\"body\":[{{\"name\":\"t0\",\"value\":{{\"kind\":\"load_param\",\"name\":\"x\"}}}}]}}",
                .{i},
            );
            try buf.appendSlice(allocator, seg);
        } else {
            const seg = try std.fmt.allocPrint(allocator,
                "{{\"name\":\"m{d}\",\"isPublic\":false,\"params\":[{{\"name\":\"x\",\"type\":\"bigint\"}}],\"body\":[{{\"name\":\"t0\",\"value\":{{\"kind\":\"load_const\",\"value\":\"@this\"}}}},{{\"name\":\"t1\",\"value\":{{\"kind\":\"load_param\",\"name\":\"x\"}}}},{{\"name\":\"t2\",\"value\":{{\"kind\":\"method_call\",\"object\":\"t0\",\"method\":\"m{d}\",\"args\":[\"t1\"]}}}}]}}",
                .{ i, i + 1 },
            );
            try buf.appendSlice(allocator, seg);
        }
    }
    if (n > 0) try buf.appendSlice(allocator, ",");
    try buf.appendSlice(allocator,
        "{\"name\":\"verify\",\"isPublic\":true,\"params\":[{\"name\":\"a\",\"type\":\"bigint\"}],\"body\":[" ++
        "{\"name\":\"t0\",\"value\":{\"kind\":\"load_const\",\"value\":\"@this\"}}," ++
        "{\"name\":\"t1\",\"value\":{\"kind\":\"load_param\",\"name\":\"a\"}}," ++
        "{\"name\":\"t2\",\"value\":{\"kind\":\"method_call\",\"object\":\"t0\",\"method\":\"m0\",\"args\":[\"t1\"]}}," ++
        "{\"name\":\"t3\",\"value\":{\"kind\":\"load_const\",\"value\":0}}," ++
        "{\"name\":\"t4\",\"value\":{\"kind\":\"bin_op\",\"op\":\">=\",\"left\":\"t2\",\"right\":\"t3\"}}," ++
        "{\"name\":\"t5\",\"value\":{\"kind\":\"assert\",\"value\":\"t4\"}}" ++
        "]}");
    try buf.appendSlice(allocator, "]}");
    return buf.toOwnedSlice(allocator);
}

test "N-265 chain at MAX_CALL_DEPTH loads" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const src = try chainIR(arena.allocator(), input_limits.MAX_CALL_DEPTH);
    _ = try json.parseANFProgram(arena.allocator(), src);
}

test "N-265 chain one past MAX_CALL_DEPTH refused naming verify" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const src = try chainIR(arena.allocator(), input_limits.MAX_CALL_DEPTH + 1);
    if (json.parseANFProgram(arena.allocator(), src)) |_| {
        return error.TestUnexpectedlyAccepted;
    } else |_| {}
    const got = required_fields.lastDiagnostic() orelse "<none>";
    try testing.expect(std.mem.indexOf(u8, got, "call depth of method 'verify' exceeds MAX_CALL_DEPTH") != null);
}

test "N-265 20000-link chain refused promptly naming m0" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const src = try chainIR(arena.allocator(), 20000);
    // "Promptly": this is an iterative walk (see call_depth.zig), so a
    // 20000-link chain is O(n) -- no host recursion, no quadratic restart.
    // The surrounding cross-tier harness's timeout is the wall-clock check;
    // this test's job is just to confirm the diagnostic, not a budget.
    if (json.parseANFProgram(arena.allocator(), src)) |_| {
        return error.TestUnexpectedlyAccepted;
    } else |_| {}
    const got = required_fields.lastDiagnostic() orelse "<none>";
    try testing.expect(std.mem.indexOf(u8, got, "call depth of method 'm0' exceeds MAX_CALL_DEPTH") != null);
}

fn recursionIR(allocator: std.mem.Allocator, private_methods: []const [2][]const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    try buf.appendSlice(allocator,
        "{\"contractName\":\"Rec\",\"properties\":[],\"methods\":[" ++
        "{\"name\":\"unlock\",\"isPublic\":true,\"params\":[{\"name\":\"x\",\"type\":\"bigint\"}],\"body\":[" ++
        "{\"name\":\"t0\",\"value\":{\"kind\":\"load_const\",\"value\":\"@this\"}}," ++
        "{\"name\":\"t1\",\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}}," ++
        "{\"name\":\"t2\",\"value\":{\"kind\":\"method_call\",\"object\":\"t0\",\"method\":\"p\",\"args\":[\"t1\"]}}," ++
        "{\"name\":\"t3\",\"value\":{\"kind\":\"load_const\",\"value\":0}}," ++
        "{\"name\":\"t4\",\"value\":{\"kind\":\"bin_op\",\"op\":\">=\",\"left\":\"t2\",\"right\":\"t3\"}}," ++
        "{\"name\":\"t5\",\"value\":{\"kind\":\"assert\",\"value\":\"t4\"}}" ++
        "]}");
    for (private_methods) |pm| {
        const name = pm[0];
        const callee = pm[1];
        try buf.appendSlice(allocator, ",");
        if (callee.len == 0) {
            const seg = try std.fmt.allocPrint(allocator,
                "{{\"name\":\"{s}\",\"isPublic\":false,\"params\":[{{\"name\":\"x\",\"type\":\"bigint\"}}],\"body\":[{{\"name\":\"t0\",\"value\":{{\"kind\":\"load_param\",\"name\":\"x\"}}}}]}}",
                .{name},
            );
            try buf.appendSlice(allocator, seg);
        } else {
            const seg = try std.fmt.allocPrint(allocator,
                "{{\"name\":\"{s}\",\"isPublic\":false,\"params\":[{{\"name\":\"x\",\"type\":\"bigint\"}}],\"body\":[{{\"name\":\"t0\",\"value\":{{\"kind\":\"load_const\",\"value\":\"@this\"}}}},{{\"name\":\"t1\",\"value\":{{\"kind\":\"load_param\",\"name\":\"x\"}}}},{{\"name\":\"t2\",\"value\":{{\"kind\":\"method_call\",\"object\":\"t0\",\"method\":\"{s}\",\"args\":[\"t1\"]}}}}]}}",
                .{ name, callee },
            );
            try buf.appendSlice(allocator, seg);
        }
    }
    try buf.appendSlice(allocator, "]}");
    return buf.toOwnedSlice(allocator);
}

test "N-265 direct self-recursion refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const src = try recursionIR(arena.allocator(), &.{.{ "p", "p" }});
    if (json.parseANFProgram(arena.allocator(), src)) |_| {
        return error.TestUnexpectedlyAccepted;
    } else |_| {}
    const got = required_fields.lastDiagnostic() orelse "<none>";
    try testing.expect(std.mem.indexOf(u8, got, "recursion detected") != null);
    try testing.expect(std.mem.indexOf(u8, got, "calls itself directly or indirectly") != null);
    try testing.expect(std.mem.indexOf(u8, got, "method 'p'") != null);
}

test "N-265 mutual recursion refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const src = try recursionIR(arena.allocator(), &.{ .{ "p", "q" }, .{ "q", "p" } });
    if (json.parseANFProgram(arena.allocator(), src)) |_| {
        return error.TestUnexpectedlyAccepted;
    } else |_| {}
    const got = required_fields.lastDiagnostic() orelse "<none>";
    try testing.expect(std.mem.indexOf(u8, got, "recursion detected") != null);
    try testing.expect(std.mem.indexOf(u8, got, "method 'p'") != null or std.mem.indexOf(u8, got, "method 'q'") != null);
}

test "N-265 non-recursive chain still loads" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const src = try recursionIR(arena.allocator(), &.{ .{ "p", "q" }, .{ "q", "r" }, .{ "r", "" } });
    _ = try json.parseANFProgram(arena.allocator(), src);
}
