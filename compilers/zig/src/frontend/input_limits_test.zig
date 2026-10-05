// BUG-008 follow-up: source-parser size-guard regression tests.

const std = @import("std");
const testing = std.testing;
const input_limits = @import("input_limits.zig");
const compiler_api = @import("../compiler_api.zig");
const parse_sol = @import("../passes/parse_sol.zig");
const parse_move = @import("../passes/parse_move.zig");
const parse_go = @import("../passes/parse_go.zig");
const parse_rust = @import("../passes/parse_rust.zig");
const parse_python = @import("../passes/parse_python.zig");
const parse_ruby = @import("../passes/parse_ruby.zig");
const parse_java = @import("../passes/parse_java.zig");
const parse_ts = @import("../passes/parse_ts.zig");
const parse_zig = @import("../passes/parse_zig.zig");

test "assertSourceBytesUnderLimit rejects oversized input" {
    const allocator = testing.allocator;
    const oversized = try allocator.alloc(u8, input_limits.MAX_SOURCE_BYTES + 1);
    defer allocator.free(oversized);
    @memset(oversized, ' ');

    const result = input_limits.assertSourceBytesUnderLimit(oversized);
    try testing.expectError(error.SourceSizeExceeded, result);
}

test "assertSourceBytesUnderLimit accepts at-limit input" {
    const allocator = testing.allocator;
    // At-limit (== MAX_SOURCE_BYTES) is accepted; cap is strict > only.
    const sized = try allocator.alloc(u8, input_limits.MAX_SOURCE_BYTES);
    defer allocator.free(sized);
    @memset(sized, ' ');

    try input_limits.assertSourceBytesUnderLimit(sized);
}

test "compileSource returns SourceSizeExceeded on oversized input" {
    const allocator = testing.allocator;
    const oversized = try allocator.alloc(u8, input_limits.MAX_SOURCE_BYTES + 1);
    defer allocator.free(oversized);
    @memset(oversized, ' ');

    const result = compiler_api.compileSource(allocator, oversized, "Counter.runar.zig");
    try testing.expectError(error.SourceSizeExceeded, result);
}

// N-136: compiler_api.parseSource (the format-dispatching entry) and the
// nine per-format passes/parse_*.zig functions it dispatches to are all
// `pub fn` and reachable directly by a caller that bypasses runPipeline
// (frontend_api.zig re-exports both parseSource and parseZig for exactly
// this direct use by the Zig SDK). Only runPipeline's Pass 0 called
// assertSourceBytesUnderLimit; every one of these 10 entries went straight
// to its own tokenizer, so a caller reaching any of them directly got no
// DoS-bound rejection at all. This proves each entry refuses a
// MAX_SOURCE_BYTES+1 input (contract == null, errors mention
// MAX_SOURCE_BYTES); it does not prove the guard runs before tokenization
// (code inspection only).
test "parseSource (dispatcher) rejects oversized input directly" {
    const allocator = testing.allocator;
    const oversized = try allocator.alloc(u8, input_limits.MAX_SOURCE_BYTES + 1);
    defer allocator.free(oversized);
    @memset(oversized, ' ');

    // The guard allocates its diagnostic via the allocator it is given; use
    // an arena so this test does not have to hand-track that allocation.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const result = compiler_api.parseSource(arena.allocator(), oversized, "Counter.runar.ts");
    try testing.expect(result.contract == null);
    try testing.expect(result.errors.len > 0);
    try testing.expect(std.mem.indexOf(u8, result.errors[0], "MAX_SOURCE_BYTES") != null);
}

test "every exported per-format parser rejects oversized input directly" {
    const allocator = testing.allocator;
    const oversized = try allocator.alloc(u8, input_limits.MAX_SOURCE_BYTES + 1);
    defer allocator.free(oversized);
    @memset(oversized, ' ');

    // Same as above: the guard's diagnostic allocation is real parser
    // output, not what this test is proving, so it goes on an arena.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const work = arena.allocator();

    const sol = parse_sol.parseSol(work, oversized, "Counter.runar.sol");
    try testing.expect(sol.contract == null);
    try testing.expect(std.mem.indexOf(u8, sol.errors[0], "MAX_SOURCE_BYTES") != null);

    const move = parse_move.parseMove(work, oversized, "Counter.runar.move");
    try testing.expect(move.contract == null);
    try testing.expect(std.mem.indexOf(u8, move.errors[0], "MAX_SOURCE_BYTES") != null);

    const go = parse_go.parseGo(work, oversized, "Counter.runar.go");
    try testing.expect(go.contract == null);
    try testing.expect(std.mem.indexOf(u8, go.errors[0], "MAX_SOURCE_BYTES") != null);

    const rust = parse_rust.parseRust(work, oversized, "Counter.runar.rs");
    try testing.expect(rust.contract == null);
    try testing.expect(std.mem.indexOf(u8, rust.errors[0], "MAX_SOURCE_BYTES") != null);

    const python = parse_python.parsePython(work, oversized, "Counter.runar.py");
    try testing.expect(python.contract == null);
    try testing.expect(std.mem.indexOf(u8, python.errors[0], "MAX_SOURCE_BYTES") != null);

    const ruby = parse_ruby.parseRuby(work, oversized, "Counter.runar.rb");
    try testing.expect(ruby.contract == null);
    try testing.expect(std.mem.indexOf(u8, ruby.errors[0], "MAX_SOURCE_BYTES") != null);

    const java = parse_java.parseJava(work, oversized, "Counter.runar.java");
    try testing.expect(java.contract == null);
    try testing.expect(std.mem.indexOf(u8, java.errors[0], "MAX_SOURCE_BYTES") != null);

    const ts = parse_ts.parseTs(work, oversized, "Counter.runar.ts");
    try testing.expect(ts.contract == null);
    try testing.expect(std.mem.indexOf(u8, ts.errors[0], "MAX_SOURCE_BYTES") != null);

    const zig_r = parse_zig.parseZig(work, oversized, "Counter.runar.zig");
    try testing.expect(zig_r.contract == null);
    try testing.expect(std.mem.indexOf(u8, zig_r.errors[0], "MAX_SOURCE_BYTES") != null);
}

// Control: an at-limit input (== MAX_SOURCE_BYTES, strictly not over) must
// not trip the guard on any of the 10 entries above. Each parser is free to
// fail afterwards for its own syntactic reasons -- this only asserts the
// size guard itself did not fire a MAX_SOURCE_BYTES diagnostic.
test "every exported per-format parser accepts at-limit input at the guard" {
    const allocator = testing.allocator;
    const sized = try allocator.alloc(u8, input_limits.MAX_SOURCE_BYTES);
    defer allocator.free(sized);
    @memset(sized, ' ');

    // An all-whitespace source is well under the cap but not valid syntax
    // for any surface, so the parsers below allocate diagnostic strings for
    // their own (non-size) complaints. Those allocations are real parser
    // output, not part of what this test is proving, so they are handed an
    // arena rather than `testing.allocator` to avoid flagging them as leaks.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const work = arena.allocator();

    const checks = .{
        parse_sol.parseSol(work, sized, "Counter.runar.sol"),
        parse_move.parseMove(work, sized, "Counter.runar.move"),
        parse_go.parseGo(work, sized, "Counter.runar.go"),
        parse_rust.parseRust(work, sized, "Counter.runar.rs"),
        parse_python.parsePython(work, sized, "Counter.runar.py"),
        parse_ruby.parseRuby(work, sized, "Counter.runar.rb"),
        parse_java.parseJava(work, sized, "Counter.runar.java"),
        parse_ts.parseTs(work, sized, "Counter.runar.ts"),
        parse_zig.parseZig(work, sized, "Counter.runar.zig"),
    };
    inline for (checks) |r| {
        for (r.errors) |e| {
            try testing.expect(std.mem.indexOf(u8, e, "MAX_SOURCE_BYTES") == null);
        }
    }

    const dispatched = compiler_api.parseSource(work, sized, "Counter.runar.ts");
    for (dispatched.errors) |e| {
        try testing.expect(std.mem.indexOf(u8, e, "MAX_SOURCE_BYTES") == null);
    }
}

test "compileSource accepts small but invalid input without tripping size guard" {
    const allocator = testing.allocator;
    // A short snippet — too short to be a valid contract but well below the
    // size cap. We expect *some* downstream error (ParseFailed etc.) but
    // NOT SourceSizeExceeded.
    const src = "// empty\n";
    const result = compiler_api.compileSource(allocator, src, "Counter.runar.zig");
    if (result) |r| {
        // Unexpected success path; clean up.
        r.deinit(allocator);
        try testing.expect(false);
    } else |err| {
        try testing.expect(err != error.SourceSizeExceeded);
    }
}
