//! #199 (release-trap warning) and D18 (dropped-continuation refusal), Zig
//! tier. Port of packages/runar-compiler/src/passes/continuation-rules.ts.
//! Corpora: conformance/negatives/release-trap-cases.json and
//! conformance/negatives/dropped-continuation-cases.json (read relative to
//! compilers/zig, the test cwd).
//!
//! Proves: validate carries the #199 warning on every warn shape (which still
//! compiles) and on no nowarn shape; typecheck refuses every D18 refuse shape
//! with the shared text; every D18 accept shape compiles; and the IR loader
//! refuses the TS-lowered, typecheck-skipped ANF of the issue #180 Lock
//! contract. Does not prove: the CLI's stderr / exit code (the conformance
//! gates drive the binary), or the other six tiers.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const typecheck = @import("../passes/typecheck.zig");
const json = @import("../ir/json.zig");
const required_fields = @import("../ir/required_fields.zig");

fn corpus(a: std.mem.Allocator, name: []const u8) !std.json.Value {
    const path = try std.fmt.allocPrint(a, "../../conformance/negatives/{s}", .{name});
    const raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, a, .limited(4 * 1024 * 1024));
    return (try std.json.parseFromSlice(std.json.Value, a, raw, .{})).value;
}

fn str(v: std.json.Value, key: []const u8) []const u8 {
    return v.object.get(key).?.string;
}

const Frontend = struct { errors: []const []const u8, warnings: []const []const u8 };

/// Parse + validate + (when validate is clean) typecheck.
fn frontend(a: std.mem.Allocator, src: []const u8, file: []const u8) !Frontend {
    const parsed = compiler_api.parseSource(a, src, file);
    if (parsed.errors.len != 0) return .{ .errors = parsed.errors, .warnings = &.{} };
    const contract = parsed.contract.?;
    const val = try compiler_api.validateForFile(a, contract, file);
    var warns: std.ArrayListUnmanaged([]const u8) = .empty;
    for (val.warnings) |w| try warns.append(a, w.message);
    var errs: std.ArrayListUnmanaged([]const u8) = .empty;
    for (val.errors) |e| try errs.append(a, e.message);
    if (errs.items.len == 0) {
        for ((try typecheck.typeCheck(a, contract)).errors) |e| try errs.append(a, e);
    }
    return .{ .errors = errs.items, .warnings = warns.items };
}

fn contains(list: []const []const u8, want: []const u8) bool {
    for (list) |s| if (std.mem.indexOf(u8, s, want) != null) return true;
    return false;
}

fn compiles(src: []const u8, file: []const u8) !void {
    const hex = try compiler_api.compileSourceToHex(std.testing.allocator, src, file);
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hex.len > 0);
}

test "#199: every warn shape warns and still compiles" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try corpus(a, "release-trap-cases.json");
    const cases = c.object.get("warn").?.array.items;
    try std.testing.expect(cases.len > 0);
    for (cases) |case| {
        const fe = try frontend(a, str(case, "src"), str(case, "file"));
        if (fe.errors.len != 0 or !contains(fe.warnings, str(case, "warning"))) {
            std.debug.print("{s}: errors={d}, warning missing\n", .{ str(case, "name"), fe.errors.len });
            return error.TestExpectedWarning;
        }
        try compiles(str(case, "src"), str(case, "file"));
    }
}

test "#199: no nowarn shape warns" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try corpus(a, "release-trap-cases.json");
    for (c.object.get("nowarn").?.array.items) |case| {
        const fe = try frontend(a, str(case, "src"), str(case, "file"));
        if (fe.errors.len != 0 or contains(fe.warnings, str(case, "warning_absent"))) {
            std.debug.print("{s}: errors={d} or unexpected warning\n", .{ str(case, "name"), fe.errors.len });
            return error.TestUnexpectedWarning;
        }
    }
}

test "D18: every refuse shape is refused with the shared text" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try corpus(a, "dropped-continuation-cases.json");
    const cases = c.object.get("refuse").?.array.items;
    try std.testing.expect(cases.len > 0);
    var failed: usize = 0;
    for (cases) |case| {
        const fe = try frontend(a, str(case, "src"), str(case, "file"));
        if (!contains(fe.errors, str(case, "error"))) {
            std.debug.print("{s}: not refused\n", .{str(case, "name")});
            failed += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failed);
}

test "D18: every accept shape compiles" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try corpus(a, "dropped-continuation-cases.json");
    for (c.object.get("accept").?.array.items) |case| {
        const fe = try frontend(a, str(case, "src"), str(case, "file"));
        if (fe.errors.len != 0) {
            std.debug.print("{s}: refused: {s}\n", .{ str(case, "name"), fe.errors[0] });
            return error.TestUnexpectedRefusal;
        }
        try compiles(str(case, "src"), str(case, "file"));
    }
}

fn refusedIr(fixture: []const u8, case_name: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try corpus(a, "dropped-continuation-cases.json");
    var want: []const u8 = "";
    for (c.object.get("refuse").?.array.items) |case| {
        if (std.mem.eql(u8, str(case, "name"), case_name)) want = str(case, "error");
    }
    try std.testing.expect(want.len > 0);
    const ir = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, fixture, a, .limited(1 << 20));
    if (json.parseANFProgram(a, ir)) |_| {
        return error.TestUnexpectedlyAccepted;
    } else |_| {}
    const diag = required_fields.lastDiagnostic() orelse "<none>";
    if (std.mem.indexOf(u8, diag, want) == null) {
        std.debug.print("diag: {s}\n", .{diag});
        return error.TestWrongDiagnostic;
    }
}

// Per path: the TS ANF of terminal-branch-writes-nothing with an update_prop
// added to its raw-output `if` arm (the IR ir-release-trap.test.ts hand-builds).
test "D18: the IR loader refuses a write on the raw-output branch" {
    try refusedIr("src/tests/d18_write_on_raw_branch.ir.json", "write-on-raw-branch-sibling-add-output");
}

test "D18: the IR loader accepts terminal-branch-writes-nothing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ir = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "src/tests/d18_terminal_branch_writes_nothing.ir.json", a, .limited(1 << 20));
    _ = try json.parseANFProgram(a, ir);
}

test "D18: the IR loader refuses the issue #180 Lock ANF" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try corpus(a, "dropped-continuation-cases.json");
    var want: []const u8 = "";
    for (c.object.get("refuse").?.array.items) |case| {
        if (std.mem.eql(u8, str(case, "name"), "issue-180-lock")) want = str(case, "error");
    }
    try std.testing.expect(want.len > 0);
    const ir = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "src/tests/d18_issue180_lock.ir.json", a, .limited(1 << 20));
    if (json.parseANFProgram(a, ir)) |_| {
        return error.TestUnexpectedlyAccepted;
    } else |_| {}
    const diag = required_fields.lastDiagnostic() orelse "<none>";
    if (std.mem.indexOf(u8, diag, want) == null) {
        std.debug.print("diag: {s}\n", .{diag});
        return error.TestWrongDiagnostic;
    }
}

// ---------------------------------------------------------------------------
// D27 (dead state write) and D26 (locktime domain). Ports of
// packages/runar-compiler/src/passes/continuation-rules.ts (D27) and
// locktime-domain.ts (D26). Corpora: dropped-continuation-cases.json
// (`refuse_after_last`) and locktime-domain-cases.json.
// ---------------------------------------------------------------------------

fn corpusText(a: std.mem.Allocator, file: []const u8, key: []const u8, case_name: []const u8) ![]const u8 {
    const c = try corpus(a, file);
    for (c.object.get(key).?.array.items) |case| {
        if (std.mem.eql(u8, str(case, "name"), case_name)) return str(case, "error");
    }
    return error.TestCaseMissing;
}

fn irRefusedWith(fixture: []const u8, want: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ir = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, fixture, a, .limited(1 << 20));
    // Clear the channel first: a stale diagnostic from an earlier test must not pass for this one.
    required_fields.setDiag("", .{});
    if (json.parseANFProgram(a, ir)) |_| {
        return error.TestUnexpectedlyAccepted;
    } else |err| {
        if (err != error.LocktimeDomain and err != error.DroppedContinuation) {
            std.debug.print("{s}: refused for the wrong reason: {s}\n", .{ fixture, @errorName(err) });
            return error.TestWrongDiagnostic;
        }
    }
    const diag = required_fields.lastDiagnostic() orelse "<none>";
    if (std.mem.indexOf(u8, diag, want) == null) {
        std.debug.print("diag: {s}\n", .{diag});
        return error.TestWrongDiagnostic;
    }
}

test "D27: every refuse_after_last shape is refused with the shared text" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try corpus(a, "dropped-continuation-cases.json");
    const cases = c.object.get("refuse_after_last").?.array.items;
    try std.testing.expect(cases.len > 0);
    var failed: usize = 0;
    for (cases) |case| {
        const fe = try frontend(a, str(case, "src"), str(case, "file"));
        if (!contains(fe.errors, str(case, "error"))) {
            std.debug.print("{s}: not refused\n", .{str(case, "name")});
            failed += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failed);
}

test "D27: the IR loader refuses a write after the last add_output" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const want = try corpusText(arena.allocator(), "dropped-continuation-cases.json", "refuse_after_last", "write-after-add-output");
    try irRefusedWith("src/tests/d27_write_after_add_output.ir.json", want);
}

test "D26: every locktime refuse shape is refused with the shared text" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try corpus(a, "locktime-domain-cases.json");
    const cases = c.object.get("refuse").?.array.items;
    try std.testing.expect(cases.len > 0);
    var failed: usize = 0;
    for (cases) |case| {
        const fe = try frontend(a, str(case, "src"), str(case, "file"));
        if (!contains(fe.errors, str(case, "error"))) {
            std.debug.print("{s}: not refused\n", .{str(case, "name")});
            failed += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failed);
}

test "D26: every locktime accept shape compiles" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try corpus(a, "locktime-domain-cases.json");
    for (c.object.get("accept").?.array.items) |case| {
        const fe = try frontend(a, str(case, "src"), str(case, "file"));
        if (fe.errors.len != 0) {
            std.debug.print("{s}: refused: {s}\n", .{ str(case, "name"), fe.errors[0] });
            return error.TestUnexpectedRefusal;
        }
        try compiles(str(case, "src"), str(case, "file"));
    }
}

test "D26: the IR loader refuses an unpinned height gate" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const want = try corpusText(arena.allocator(), "locktime-domain-cases.json", "refuse", "height-gate-literal");
    try irRefusedWith("src/tests/d26_height_gate.ir.json", want);
}

test "D26: the IR loader refuses a gate on a helper parameter" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const want = try corpusText(arena.allocator(), "locktime-domain-cases.json", "refuse", "gate-on-helper-param");
    try irRefusedWith("src/tests/d26_gate_on_helper_param.ir.json", want);
}

test "D26: the IR loader accepts a helper-parameter gate the caller pins" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ir = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "src/tests/d26_helper_param_pinned_by_caller.ir.json", a, .limited(1 << 20));
    _ = try json.parseANFProgram(a, ir);
}

// N534: D26 must not mask the D14 extractor refusal typecheck reports.
test "D26: N534 still carries the D14 diagnostic beside D26" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "../../conformance/negatives/N534-ts-extractor-bytestring-property.runar.ts", a, .limited(1 << 20));
    var diag: compiler_api.Diagnostics = .{};
    if (compiler_api.runPipeline(a, src, "N534.runar.ts", .{}, &diag)) |_| {
        return error.TestUnexpectedlyAccepted;
    } else |_| {}
    try std.testing.expect(contains(diag.errors.items, "extractLocktime() needs a checked SigHashPreimage"));
    try std.testing.expect(contains(diag.errors.items, "compares extractLocktime against a lower bound without pinning the locktime domain"));
}

// SPEC UPDATE 3: only `>= 0` is vacuous; an IR literal -1 bound is a gate.
test "D26: the IR loader refuses a negative lower bound" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const want = try corpusText(arena.allocator(), "locktime-domain-cases.json", "refuse", "height-gate-literal");
    try irRefusedWith("src/tests/d26_negative_bound.ir.json", want);
}
