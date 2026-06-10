// Conformance test — runs the Zig analyzer on each canonical fixture
// and asserts the emitted JSON is byte-identical with the golden at
// conformance/analyzer/<fixture>/expected-analyzer-report.json.

const std = @import("std");
const analyzer = @import("analyzer.zig");

const FIXTURES = [_][]const u8{
    "basic-p2pkh",
    "escrow",
    "stateful-counter",
    "auction",
    "covenant-vault",
    "ec-demo",
    "schnorr-zkp",
    "if-else",
};

fn repoRoot(allocator: std.mem.Allocator) ![]u8 {
    // packages/runar-zig is two levels below the repo root.
    const z = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, "../..", allocator);
    // Convert sentinel-terminated to plain slice via dupe.
    defer allocator.free(z);
    return try allocator.dupe(u8, z);
}

fn runFixture(allocator: std.mem.Allocator, fixture: []const u8) !void {
    const root = try repoRoot(allocator);
    defer allocator.free(root);

    const hex_path = try std.fs.path.join(allocator, &.{ root, "conformance", "tests", fixture, "expected-script.hex" });
    defer allocator.free(hex_path);
    const golden_path = try std.fs.path.join(allocator, &.{ root, "conformance", "analyzer", fixture, "expected-analyzer-report.json" });
    defer allocator.free(golden_path);

    const hex_raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, hex_path, allocator, .limited(64 * 1024 * 1024));
    defer allocator.free(hex_raw);
    var end = hex_raw.len;
    while (end > 0) : (end -= 1) {
        const c = hex_raw[end - 1];
        if (c != ' ' and c != '\t' and c != '\n' and c != '\r') break;
    }
    const hex = hex_raw[0..end];

    const golden = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, golden_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(golden);

    const result = try analyzer.analyzeScript(allocator, hex, .{});
    defer result.deinit(allocator);

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(allocator);
    try analyzer.writeReportJson(allocator, &buf, result);

    if (!std.mem.eql(u8, buf.items, golden)) {
        // Locate first divergence for a nicer message.
        const n = @min(buf.items.len, golden.len);
        var i: usize = 0;
        while (i < n and buf.items[i] == golden[i]) : (i += 1) {}
        const ctx_start = if (i > 80) i - 80 else 0;
        const ctx_end_actual = @min(i + 80, buf.items.len);
        const ctx_end_golden = @min(i + 80, golden.len);
        std.debug.print(
            "fixture {s}: divergence at byte {d} (actual.len={d}, golden.len={d})\n",
            .{ fixture, i, buf.items.len, golden.len },
        );
        std.debug.print("actual context: {s}\n", .{buf.items[ctx_start..ctx_end_actual]});
        std.debug.print("golden context: {s}\n", .{golden[ctx_start..ctx_end_golden]});
        return error.JsonMismatch;
    }
}

test "conformance: basic-p2pkh" {
    try runFixture(std.testing.allocator, "basic-p2pkh");
}

test "conformance: escrow" {
    try runFixture(std.testing.allocator, "escrow");
}

test "conformance: stateful-counter" {
    try runFixture(std.testing.allocator, "stateful-counter");
}

test "conformance: auction" {
    try runFixture(std.testing.allocator, "auction");
}

test "conformance: covenant-vault" {
    try runFixture(std.testing.allocator, "covenant-vault");
}

test "conformance: if-else" {
    try runFixture(std.testing.allocator, "if-else");
}

test "conformance: ec-demo" {
    try runFixture(std.testing.allocator, "ec-demo");
}

test "conformance: schnorr-zkp" {
    try runFixture(std.testing.allocator, "schnorr-zkp");
}
