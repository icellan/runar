//! F-024 (CL-BUG-079, user decision R14) — Zig-tier port of
//! packages/runar-compiler/src/__tests__/f024-continuation-amount.test.ts.
//!
//! Proves (Zig tier, TS surface): every default single-output continuation
//! carries the injected `assert(_newAmount >= extractAmount(txPreimage))` ANF
//! (load_param txPreimage; call extractAmount; load_param _newAmount;
//! bin_op >=; assert) after the body; addOutput and terminal methods do not;
//! `continuationAmount()` lowers to load_param _newAmount where that witness
//! exists and is refused everywhere else; a write to it is refused.
//! Does NOT prove on-chain rejection of a drain (the TS Spend test does) or
//! cross-tier byte parity (conformance).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const types = @import("../ir/types.zig");

const COUNTER =
    \\class Counter extends StatefulSmartContract {
    \\  count: bigint;
    \\  constructor(count: bigint) { super(count); this.count = count; }
    \\  public increment() { this.count = this.count + 1n; }
    \\  public addTo(amount: bigint) { this.addOutput(1000n, this.count + amount); }
    \\  public close() { assert(this.count > 0n); }
    \\  public log(payload: ByteString) { this.addDataOutput(0n, payload); }
    \\}
;

const POT_HEAD =
    \\class Pot extends StatefulSmartContract {
    \\  count: bigint;
    \\  constructor(count: bigint) { super(count); this.count = count; }
    \\
;

const READ_ONLY = "continuationAmount() is read-only and cannot be assigned";
const UNAVAILABLE = "continuationAmount() is only available in a public StatefulSmartContract method whose state continues through the default single-output continuation";

fn lower(a: std.mem.Allocator, src: []const u8, diag: *compiler_api.Diagnostics) !types.ANFProgram {
    const p = try compiler_api.runPipeline(a, src, "C.runar.ts", .{ .disable_constant_folding = true, .stop_after = .anf }, diag);
    return p.program.?;
}

fn publicMethod(p: types.ANFProgram, name: []const u8) !types.ANFMethod {
    for (p.methods) |m| {
        if (m.is_public and std.mem.eql(u8, m.name, name)) return m;
    }
    return error.MethodNotFound;
}

fn isLoadParam(v: types.ANFValue, name: []const u8) bool {
    return switch (v) {
        .load_param => |lp| std.mem.eql(u8, lp.name, name),
        else => false,
    };
}

fn isCall(v: types.ANFValue, func: []const u8) bool {
    return switch (v) {
        .call => |c| std.mem.eql(u8, c.func, func),
        else => false,
    };
}

/// Start indexes of the injected 5-binding check in `body`.
fn injectedCheckCount(body: []const types.ANFBinding, first: *usize) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i + 4 < body.len) : (i += 1) {
        const w = body[i .. i + 5];
        if (!isLoadParam(w[0].value, "txPreimage")) continue;
        const call = switch (w[1].value) {
            .call => |c| c,
            else => continue,
        };
        if (!std.mem.eql(u8, call.func, "extractAmount") or call.args.len != 1 or !std.mem.eql(u8, call.args[0], w[0].name)) continue;
        if (!isLoadParam(w[2].value, "_newAmount")) continue;
        const bo = switch (w[3].value) {
            .bin_op => |b| b,
            else => continue,
        };
        if (!std.mem.eql(u8, bo.op, ">=") or !std.mem.eql(u8, bo.left, w[2].name) or !std.mem.eql(u8, bo.right, w[1].name)) continue;
        const as = switch (w[4].value) {
            .assert => |x| x,
            else => continue,
        };
        if (!std.mem.eql(u8, as.value, w[3].name) or as.is_auto_injected_state_check) continue;
        if (n == 0) first.* = i;
        n += 1;
    }
    return n;
}

fn hasKind(body: []const types.ANFBinding, tag: std.meta.Tag(types.ANFValue)) bool {
    for (body) |b| if (std.meta.activeTag(b.value) == tag) return true;
    return false;
}

fn hasCall(body: []const types.ANFBinding, func: []const u8) bool {
    for (body) |b| if (isCall(b.value, func)) return true;
    return false;
}

fn hasParam(m: types.ANFMethod, name: []const u8) bool {
    for (m.params) |p| if (std.mem.eql(u8, p.name, name)) return true;
    return false;
}

test "F-024: the default continuation carries exactly one value check, after the body" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var diag: compiler_api.Diagnostics = .{};
    const p = try lower(a, COUNTER, &diag);

    const inc = try publicMethod(p, "increment");
    var at: usize = 0;
    try std.testing.expectEqual(@as(usize, 1), injectedCheckCount(inc.body, &at));
    try std.testing.expect(hasKind(inc.body[0..at], .update_prop));
    const after = inc.body[at + 5 ..];
    try std.testing.expect(hasKind(after, .@"if"));
    try std.testing.expect(hasKind(after, .get_state_script));
    try std.testing.expect(hasCall(after, "computeStateOutput"));

    const log = try publicMethod(p, "log");
    try std.testing.expectEqual(@as(usize, 1), injectedCheckCount(log.body, &at));

    for ([_][]const u8{ "addTo", "close" }) |name| {
        const m = try publicMethod(p, name);
        try std.testing.expect(!hasParam(m, "_newAmount"));
        try std.testing.expect(!hasCall(m.body, "extractAmount"));
    }
}

test "F-024: a continuationAmount() read lowers to its own load_param _newAmount" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var diag: compiler_api.Diagnostics = .{};
    const src = POT_HEAD ++
        \\  public join(bet: bigint) {
        \\    assert(continuationAmount() == extractAmount(this.txPreimage) + bet);
        \\    this.count = this.count + 1n;
        \\  }
        \\}
    ;
    const p = lower(a, src, &diag) catch |err| {
        for (diag.errors.items) |line| std.debug.print("    {s}\n", .{line});
        return err;
    };
    const m = try publicMethod(p, "join");
    var at: usize = 0;
    try std.testing.expectEqual(@as(usize, 1), injectedCheckCount(m.body, &at));
    var first: ?usize = null;
    for (m.body, 0..) |b, i| {
        if (isLoadParam(b.value, "_newAmount")) {
            first = i;
            break;
        }
    }
    try std.testing.expect(first != null and first.? < at);
}

const Refusal = struct { name: []const u8, src: []const u8, want: ?[]const u8 };

test "F-024: continuationAmount() is refused where there is no _newAmount, and cannot be written" {
    const cases = [_]Refusal{
        .{ .name = "write", .src = POT_HEAD ++ "  public join() { continuationAmount() = 5n; this.count = this.count + 1n; }\n}\n", .want = READ_ONLY },
        .{ .name = "increment", .src = POT_HEAD ++ "  public join() { continuationAmount()++; this.count = this.count + 1n; }\n}\n", .want = READ_ONLY },
        .{ .name = "stateless", .src = 
        \\class P extends SmartContract {
        \\  readonly x: bigint;
        \\  constructor(x: bigint) { super(x); this.x = x; }
        \\  public unlock() { assert(continuationAmount() > this.x); }
        \\}
        , .want = "continuationAmount() is only available in StatefulSmartContract methods" },
        .{ .name = "terminal", .src = POT_HEAD ++ "  public close() { assert(continuationAmount() > 0n); }\n}\n", .want = UNAVAILABLE },
        .{ .name = "addOutput", .src = POT_HEAD ++ "  public split() { this.addOutput(continuationAmount(), this.count); }\n}\n", .want = UNAVAILABLE },
        .{ .name = "private", .src = POT_HEAD ++ "  private amt(): bigint { return continuationAmount(); }\n  public bump() { this.count = this.count + this.amt(); }\n}\n", .want = UNAVAILABLE },
    };
    for (cases) |c| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var diag: compiler_api.Diagnostics = .{};
        if (lower(a, c.src, &diag)) |_| {
            std.debug.print("F-024 {s}: expected a refusal, it compiled\n", .{c.name});
            return error.ExpectedRefusal;
        } else |_| {}
        const want = c.want orelse continue;
        var found = false;
        for (diag.errors.items) |line| {
            if (std.mem.indexOf(u8, line, want) != null) found = true;
        }
        if (!found) {
            std.debug.print("F-024 {s}: expected \"{s}\", got:\n", .{ c.name, want });
            for (diag.errors.items) |line| std.debug.print("    {s}\n", .{line});
            return error.WrongDiagnostic;
        }
    }
}
