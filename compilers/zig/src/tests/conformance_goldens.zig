//! Byte-identical golden diff harness for the Zig compiler.
//!
//! For every directory under `conformance/tests/`, this test:
//!   1. Locates the Zig-format source file (`*.runar.zig`)
//!   2. Invokes the Zig compiler binary (`zig-out/bin/runar-zig`) via subprocess
//!      with `--emit-ir --disable-constant-folding` and `--hex --disable-constant-folding`
//!   3. Canonicalizes the ANF IR JSON (sort keys, strip `sourceLoc`, 2-space indent)
//!   4. Asserts byte-for-byte equality against `expected-ir.json` and `expected-script.hex`
//!
//! The canonicalization strategy mirrors
//! `conformance/runner/runner.ts::canonicalizeJson`.
//!
//! The binary is resolved via the `RUNAR_ZIG_BIN` environment variable, and
//! falls back to `zig-out/bin/runar-zig` relative to CWD if unset. Run via:
//!   zig build          # builds zig-out/bin/runar-zig
//!   zig build conformance-goldens   # runs this test suite

const std = @import("std");

const conformance_base = "../../conformance/tests/";

/// Resolve a path to the built runar-zig binary.
/// Preference: RUNAR_ZIG_BIN env var, then zig-out/bin/runar-zig, then PATH.
fn resolveZigBinary(allocator: std.mem.Allocator) ![]const u8 {
    if (std.testing.environ.getPosix("RUNAR_ZIG_BIN")) |bin| {
        return try allocator.dupe(u8, bin);
    }
    return try allocator.dupe(u8, "zig-out/bin/runar-zig");
}

/// Resolve the Zig-format source file for a conformance fixture.
///
/// Mirrors the TS runner (`conformance/runner/runner.ts`):
///   1. If `source.json` exists and has a `.runar.zig` entry in `sources`,
///      resolve it relative to the fixture directory. Use it if it exists.
///   2. Otherwise fall back to the first `*.runar.zig` file in the fixture dir.
///
/// Returned slice is allocated with `allocator`.
fn findZigSource(allocator: std.mem.Allocator, io: std.Io, test_dir: []const u8) !?[]u8 {
    // (1) source.json lookup
    const config_path = try std.fmt.allocPrint(allocator, "{s}/source.json", .{test_dir});
    defer allocator.free(config_path);
    if (std.Io.Dir.cwd().readFileAlloc(io, config_path, allocator, .limited(1 * 1024 * 1024))) |raw| {
        defer allocator.free(raw);
        if (std.json.parseFromSlice(std.json.Value, allocator, raw, .{})) |parsed| {
            defer parsed.deinit();
            switch (parsed.value) {
                .object => |root| {
                    if (root.get("sources")) |sources_val| {
                        switch (sources_val) {
                            .object => |sources| {
                                if (sources.get(".runar.zig")) |v| {
                                    switch (v) {
                                        .string => |rel| {
                                            const resolved = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ test_dir, rel });
                                            // Confirm existence via stat; fall through on failure.
                                            if (std.Io.Dir.cwd().statFile(io, resolved, .{})) |_| {
                                                return resolved;
                                            } else |_| {
                                                allocator.free(resolved);
                                            }
                                        },
                                        else => {},
                                    }
                                }
                            },
                            else => {},
                        }
                    }
                },
                else => {},
            }
        } else |_| {}
    } else |_| {}

    // (2) glob fallback in fixture directory
    var dir = std.Io.Dir.cwd().openDir(io, test_dir, .{ .iterate = true }) catch return null;
    defer dir.close(io);

    var iter = dir.iterate();
    var names: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (names.items) |n| allocator.free(n);
        names.deinit(allocator);
    }

    while (try iter.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.endsWith(u8, entry.name, ".runar.zig")) {
            try names.append(allocator, try allocator.dupe(u8, entry.name));
        }
    }
    if (names.items.len == 0) return null;

    // Sort for deterministic selection
    std.mem.sort([]u8, names.items, {}, struct {
        fn lessThan(_: void, a: []u8, b: []u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);

    return try std.fmt.allocPrint(allocator, "{s}/{s}", .{ test_dir, names.items[0] });
}

/// Run the Zig compiler binary with the given flags.
/// Returns stdout on success (caller frees); returns error + prints stderr on failure.
fn runCompiler(
    allocator: std.mem.Allocator,
    io: std.Io,
    binary: []const u8,
    source_path: []const u8,
    flags: []const []const u8,
) ![]u8 {
    var argv: std.ArrayListUnmanaged([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.append(allocator, binary);
    try argv.append(allocator, "--source");
    try argv.append(allocator, source_path);
    for (flags) |f| try argv.append(allocator, f);

    const result = try std.process.run(allocator, io, .{
        .argv = argv.items,
        .stdout_limit = .limited(10 * 1024 * 1024),
    });
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code != 0) {
            defer allocator.free(result.stdout);
            std.debug.print("  runar-zig exit code {d}: {s}\n", .{ code, result.stderr });
            return error.CompilerExitNonZero;
        },
        else => {
            defer allocator.free(result.stdout);
            std.debug.print("  runar-zig abnormal termination\n", .{});
            return error.CompilerAbnormalExit;
        },
    }
    return result.stdout;
}

/// Recursively canonicalize a std.json.Value: strip `sourceLoc`, sort keys,
/// re-serialize with 2-space indent.
fn canonicalizeJson(allocator: std.mem.Allocator, json_str: []const u8) ![]u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    try writeValue(allocator, &buf, parsed.value, 0);
    return buf.toOwnedSlice(allocator);
}

fn writeIndent(allocator: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8), depth: usize) !void {
    var i: usize = 0;
    while (i < depth) : (i += 1) {
        try buf.appendSlice(allocator, "  ");
    }
}

fn writeValue(
    allocator: std.mem.Allocator,
    buf: *std.ArrayListUnmanaged(u8),
    v: std.json.Value,
    depth: usize,
) !void {
    switch (v) {
        .null => try buf.appendSlice(allocator, "null"),
        .bool => |b| try buf.appendSlice(allocator, if (b) "true" else "false"),
        .integer => |i| {
            var tmp: [32]u8 = undefined;
            const s = try std.fmt.bufPrint(&tmp, "{d}", .{i});
            try buf.appendSlice(allocator, s);
        },
        .float => |f| {
            var tmp: [64]u8 = undefined;
            const s = try std.fmt.bufPrint(&tmp, "{d}", .{f});
            try buf.appendSlice(allocator, s);
        },
        .number_string => |s| try buf.appendSlice(allocator, s),
        .string => |s| {
            try buf.append(allocator, '"');
            try writeJsonEscapedString(allocator, buf, s);
            try buf.append(allocator, '"');
        },
        .array => |arr| {
            if (arr.items.len == 0) {
                try buf.appendSlice(allocator, "[]");
                return;
            }
            try buf.append(allocator, '[');
            for (arr.items, 0..) |item, i| {
                try buf.append(allocator, '\n');
                try writeIndent(allocator, buf, depth + 1);
                try writeValue(allocator, buf, item, depth + 1);
                if (i + 1 < arr.items.len) try buf.append(allocator, ',');
            }
            try buf.append(allocator, '\n');
            try writeIndent(allocator, buf, depth);
            try buf.append(allocator, ']');
        },
        .object => |obj| {
            // Collect non-sourceLoc keys, sort them
            var keys: std.ArrayListUnmanaged([]const u8) = .empty;
            defer keys.deinit(allocator);
            var it = obj.iterator();
            while (it.next()) |kv| {
                if (std.mem.eql(u8, kv.key_ptr.*, "sourceLoc")) continue;
                try keys.append(allocator, kv.key_ptr.*);
            }
            std.mem.sort([]const u8, keys.items, {}, struct {
                fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                    return std.mem.lessThan(u8, a, b);
                }
            }.lessThan);

            if (keys.items.len == 0) {
                try buf.appendSlice(allocator, "{}");
                return;
            }
            try buf.append(allocator, '{');
            for (keys.items, 0..) |k, i| {
                try buf.append(allocator, '\n');
                try writeIndent(allocator, buf, depth + 1);
                try buf.append(allocator, '"');
                try writeJsonEscapedString(allocator, buf, k);
                try buf.appendSlice(allocator, "\": ");
                try writeValue(allocator, buf, obj.get(k).?, depth + 1);
                if (i + 1 < keys.items.len) try buf.append(allocator, ',');
            }
            try buf.append(allocator, '\n');
            try writeIndent(allocator, buf, depth);
            try buf.append(allocator, '}');
        },
    }
}

fn writeJsonEscapedString(
    allocator: std.mem.Allocator,
    buf: *std.ArrayListUnmanaged(u8),
    s: []const u8,
) !void {
    for (s) |c| {
        switch (c) {
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            0x08 => try buf.appendSlice(allocator, "\\b"),
            0x0c => try buf.appendSlice(allocator, "\\f"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '\r' => try buf.appendSlice(allocator, "\\r"),
            '\t' => try buf.appendSlice(allocator, "\\t"),
            else => {
                if (c < 0x20) {
                    var tmp: [8]u8 = undefined;
                    const esc = try std.fmt.bufPrint(&tmp, "\\u{x:0>4}", .{c});
                    try buf.appendSlice(allocator, esc);
                } else {
                    try buf.append(allocator, c);
                }
            },
        }
    }
}

/// Strip ASCII whitespace from `input`, lowercase hex digits, return new slice.
fn normalizeHex(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.ensureTotalCapacity(allocator, input.len);
    for (input) |c| {
        if (c == ' ' or c == '\t' or c == '\n' or c == '\r') continue;
        const lc = if (c >= 'A' and c <= 'Z') c + 32 else c;
        try out.append(allocator, lc);
    }
    return out.toOwnedSlice(allocator);
}

// ============================================================================
// Shared state for the aggregate summary test
// ============================================================================

const FailureKind = enum { compile_ir, compile_hex, canon_ir, ir_mismatch, script_mismatch };

const Failure = struct {
    name: []const u8,
    kind: FailureKind,
    detail: []const u8,
    expected: ?[]const u8 = null,
    actual: ?[]const u8 = null,
};

fn printShortDiff(expected: []const u8, actual: []const u8) void {
    var exp_lines_iter = std.mem.splitScalar(u8, expected, '\n');
    var act_lines_iter = std.mem.splitScalar(u8, actual, '\n');
    var shown: usize = 0;
    var line: usize = 1;
    while (true) : (line += 1) {
        const e = exp_lines_iter.next();
        const a = act_lines_iter.next();
        if (e == null and a == null) break;
        const el = e orelse "<EOF>";
        const al = a orelse "<EOF>";
        if (!std.mem.eql(u8, el, al)) {
            std.debug.print("    line {d}:\n      - expected: {s}\n      + actual:   {s}\n", .{ line, el, al });
            shown += 1;
            if (shown >= 12) {
                std.debug.print("    ... (truncated)\n", .{});
                return;
            }
        }
    }
}

fn printScriptDiff(expected: []const u8, actual: []const u8) void {
    const min_len = @min(expected.len, actual.len);
    var first_diff: usize = min_len;
    var i: usize = 0;
    while (i < min_len) : (i += 1) {
        if (expected[i] != actual[i]) {
            first_diff = i;
            break;
        }
    }
    const lo = if (first_diff >= 20) first_diff - 20 else 0;
    const exp_hi = @min(first_diff + 20, expected.len);
    const act_hi = @min(first_diff + 20, actual.len);
    std.debug.print(
        "  expected {d} hex chars, actual {d} hex chars\n  first diff at hex offset {d} (byte {d})\n  expected: ...{s}...\n  actual:   ...{s}...\n",
        .{ expected.len, actual.len, first_diff, first_diff / 2, expected[lo..exp_hi], actual[lo..act_hi] },
    );
}

// ============================================================================
// The single conformance test — iterates all 40 fixture directories
// ============================================================================

test "conformance-goldens: zig compiler produces byte-identical output for all fixtures" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const binary = try resolveZigBinary(allocator);
    defer allocator.free(binary);

    var dir = std.Io.Dir.cwd().openDir(io, conformance_base, .{ .iterate = true }) catch |err| {
        std.debug.print("cannot open {s}: {s}\n", .{ conformance_base, @errorName(err) });
        return err;
    };
    defer dir.close(io);

    // Gather fixture dirs
    var fixture_names: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (fixture_names.items) |n| allocator.free(n);
        fixture_names.deinit(allocator);
    }
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        try fixture_names.append(allocator, try allocator.dupe(u8, entry.name));
    }
    std.mem.sort([]u8, fixture_names.items, {}, struct {
        fn lessThan(_: void, a: []u8, b: []u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);

    var passed: std.ArrayListUnmanaged([]const u8) = .empty;
    defer passed.deinit(allocator);
    var missing: std.ArrayListUnmanaged([]const u8) = .empty;
    defer missing.deinit(allocator);
    var failures: std.ArrayListUnmanaged(Failure) = .empty;
    defer {
        for (failures.items) |f| {
            allocator.free(f.detail);
            if (f.expected) |e| allocator.free(e);
            if (f.actual) |a| allocator.free(a);
        }
        failures.deinit(allocator);
    }

    for (fixture_names.items) |name| {
        const test_dir = try std.fmt.allocPrint(allocator, "{s}{s}", .{ conformance_base, name });
        defer allocator.free(test_dir);

        const source_opt = try findZigSource(allocator, io, test_dir);
        if (source_opt == null) {
            try missing.append(allocator, name);
            continue;
        }
        const source_path = source_opt.?;
        defer allocator.free(source_path);

        // Step 1: emit IR
        const ir_flags = [_][]const u8{ "--emit-ir", "--disable-constant-folding" };
        const ir_raw = runCompiler(allocator, io, binary, source_path, &ir_flags) catch |err| {
            const detail = try std.fmt.allocPrint(allocator, "emit-ir failed: {s}", .{@errorName(err)});
            try failures.append(allocator, .{ .name = name, .kind = .compile_ir, .detail = detail });
            continue;
        };
        defer allocator.free(ir_raw);

        // Step 2: emit hex
        const hex_flags = [_][]const u8{ "--hex", "--disable-constant-folding" };
        const hex_raw = runCompiler(allocator, io, binary, source_path, &hex_flags) catch |err| {
            const detail = try std.fmt.allocPrint(allocator, "emit-hex failed: {s}", .{@errorName(err)});
            try failures.append(allocator, .{ .name = name, .kind = .compile_hex, .detail = detail });
            continue;
        };
        defer allocator.free(hex_raw);

        // Canonicalize actual IR
        const actual_ir = canonicalizeJson(allocator, ir_raw) catch |err| {
            const detail = try std.fmt.allocPrint(allocator, "canonicalize actual IR: {s}", .{@errorName(err)});
            try failures.append(allocator, .{ .name = name, .kind = .canon_ir, .detail = detail });
            continue;
        };

        // Compare IR
        const ir_path = try std.fmt.allocPrint(allocator, "{s}/expected-ir.json", .{test_dir});
        defer allocator.free(ir_path);
        const expected_ir_raw = std.Io.Dir.cwd().readFileAlloc(io, ir_path, allocator, .limited(16 * 1024 * 1024)) catch null;
        if (expected_ir_raw) |raw| {
            defer allocator.free(raw);
            const expected_ir = canonicalizeJson(allocator, raw) catch |err| {
                allocator.free(actual_ir);
                const detail = try std.fmt.allocPrint(allocator, "canonicalize expected IR: {s}", .{@errorName(err)});
                try failures.append(allocator, .{ .name = name, .kind = .canon_ir, .detail = detail });
                continue;
            };
            if (!std.mem.eql(u8, actual_ir, expected_ir)) {
                const detail = try std.fmt.allocPrint(allocator, "IR differs (exp {d} / act {d} chars)", .{ expected_ir.len, actual_ir.len });
                try failures.append(allocator, .{
                    .name = name,
                    .kind = .ir_mismatch,
                    .detail = detail,
                    .expected = expected_ir,
                    .actual = actual_ir,
                });
                continue;
            }
            allocator.free(expected_ir);
        }
        allocator.free(actual_ir);

        // Compare hex
        const actual_hex = try normalizeHex(allocator, hex_raw);

        const hex_path = try std.fmt.allocPrint(allocator, "{s}/expected-script.hex", .{test_dir});
        defer allocator.free(hex_path);
        const expected_hex_raw = std.Io.Dir.cwd().readFileAlloc(io, hex_path, allocator, .limited(4 * 1024 * 1024)) catch null;
        if (expected_hex_raw) |raw| {
            defer allocator.free(raw);
            const expected_hex = try normalizeHex(allocator, raw);
            if (!std.mem.eql(u8, actual_hex, expected_hex)) {
                const detail = try std.fmt.allocPrint(allocator, "script differs (exp {d} / act {d})", .{ expected_hex.len, actual_hex.len });
                try failures.append(allocator, .{
                    .name = name,
                    .kind = .script_mismatch,
                    .detail = detail,
                    .expected = expected_hex,
                    .actual = actual_hex,
                });
                continue;
            }
            allocator.free(expected_hex);
        }
        allocator.free(actual_hex);

        try passed.append(allocator, name);
    }

    const total = fixture_names.items.len;
    std.debug.print(
        "\n=== Zig conformance-goldens summary: {d} pass / {d} fail / {d} missing-source (of {d} fixtures) ===\n",
        .{ passed.items.len, failures.items.len, missing.items.len, total },
    );
    if (missing.items.len > 0) {
        std.debug.print("Missing .runar.zig source files:\n", .{});
        for (missing.items) |n| std.debug.print("  - {s}\n", .{n});
    }
    const shown = @min(failures.items.len, 5);
    var i: usize = 0;
    while (i < shown) : (i += 1) {
        const f = failures.items[i];
        std.debug.print("\n--- FAIL: {s} ({s}) ---\n", .{ f.name, @tagName(f.kind) });
        switch (f.kind) {
            .ir_mismatch => {
                std.debug.print("  {s}\n", .{f.detail});
                if (f.expected != null and f.actual != null) {
                    printShortDiff(f.expected.?, f.actual.?);
                }
            },
            .script_mismatch => {
                if (f.expected != null and f.actual != null) {
                    printScriptDiff(f.expected.?, f.actual.?);
                }
            },
            else => {
                std.debug.print("  {s}\n", .{f.detail});
            },
        }
    }
    if (failures.items.len > shown) {
        std.debug.print("\n... and {d} more failures:\n", .{failures.items.len - shown});
        var j: usize = shown;
        while (j < failures.items.len) : (j += 1) {
            std.debug.print("  - {s}\n", .{failures.items[j].name});
        }
    }

    if (failures.items.len > 0) {
        std.debug.print("\n{d} of {d} fixtures failed conformance-goldens\n", .{ failures.items.len, total });
        return error.ConformanceGoldensFailed;
    }
}
