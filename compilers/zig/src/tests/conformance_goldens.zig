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

// N-389 (R145, "named set, keep coverage"): fixtures Zig is EXPECTED to
// refuse. Zig refuses the BN254 pairing family (bn254MultiPairing4) by
// policy. A fixture is skipped only when it is named here AND its
// source.json allowlist excludes zig. Every other fixture, including the
// Go-only ones Zig compiles byte-identically today (babybear,
// babybear-ext4, merkle-proof, state-covenant), is compiled and
// byte-checked, and a refusal there is a failure. Mirrors the Python
// harness's EXPECTED_NOT_PYTHON_COMPILABLE (N-387).
const EXPECTED_NOT_ZIG_COMPILABLE = [_][]const u8{"bn254-pairing"};

/// Resolve a path to the built runar-zig binary.
/// Preference: RUNAR_ZIG_BIN env var, then zig-out/bin/runar-zig, then PATH.
fn resolveZigBinary(allocator: std.mem.Allocator) ![]const u8 {
    if (std.testing.environ.getPosix("RUNAR_ZIG_BIN")) |bin| {
        return try allocator.dupe(u8, bin);
    }
    return try allocator.dupe(u8, "zig-out/bin/runar-zig");
}

/// N-392: read and parse a fixture's `source.json`, failing closed.
/// Returns null only when the file is absent (the glob fallback / "no
/// allowlist" cases). An unreadable file is `error.UnreadableSourceJson` and
/// invalid JSON is `error.MalformedSourceJson`; both print the fixture dir.
/// Mirrors Python F-323 and the Ruby harness.
fn parseSourceJson(allocator: std.mem.Allocator, io: std.Io, test_dir: []const u8) !?std.json.Parsed(std.json.Value) {
    const config_path = try std.fmt.allocPrint(allocator, "{s}/source.json", .{test_dir});
    defer allocator.free(config_path);
    const raw = std.Io.Dir.cwd().readFileAlloc(io, config_path, allocator, .limited(1 * 1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => {
            std.debug.print("unreadable source.json in fixture '{s}': {s}\n", .{ test_dir, @errorName(err) });
            return error.UnreadableSourceJson;
        },
    };
    defer allocator.free(raw);
    return std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch |err| {
        std.debug.print("malformed source.json in fixture '{s}': {s}\n", .{ test_dir, @errorName(err) });
        return error.MalformedSourceJson;
    };
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
    if (try parseSourceJson(allocator, io, test_dir)) |parsed| {
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
    }

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

/// Honor the per-fixture compiler allowlist in `source.json`. If
/// `compilers` is present and does not include "zig", the fixture is
/// intentionally opted out of Zig Stack-IR / hex parity (parser coverage is
/// universal and enforced elsewhere). Mirrors the Rust harness's
/// `fixture_allowlisted_for_rust` (F-285) and the Ruby harness's
/// `read_compiler_allowlist` (F-151). See `conformance/README.md` ⇒
/// "Per-fixture compiler allowlist".
///
/// Returns true (allowed) when `source.json` is absent (N-392: an unreadable
/// or malformed one is an error), when it has no `compilers` field, or when that field includes "zig".
/// N-389: a `compilers` value that is not a list of strings fails closed
/// (`error.InvalidCompilersAllowlist`) instead of counting as "no allowlist".
fn fixtureAllowlistedForZig(allocator: std.mem.Allocator, io: std.Io, test_dir: []const u8) !bool {
    const parsed = (try parseSourceJson(allocator, io, test_dir)) orelse return true;
    defer parsed.deinit();

    switch (parsed.value) {
        .object => |root| {
            const compilers_val = root.get("compilers") orelse return true;
            switch (compilers_val) {
                .array => |arr| {
                    var found = false;
                    for (arr.items) |item| {
                        switch (item) {
                            .string => |s| if (std.mem.eql(u8, s, "zig")) {
                                found = true;
                            },
                            else => return error.InvalidCompilersAllowlist,
                        }
                    }
                    return found;
                },
                else => return error.InvalidCompilersAllowlist,
            }
        },
        else => return true,
    }
}

/// Independent (raw source.json) check that the allowlist excludes zig.
/// Deliberately does not go through `fixtureAllowlistedForZig`.
fn excludesZigRaw(allocator: std.mem.Allocator, io: std.Io, test_dir: []const u8) !bool {
    const config_path = try std.fmt.allocPrint(allocator, "{s}/source.json", .{test_dir});
    defer allocator.free(config_path);
    const raw = try std.Io.Dir.cwd().readFileAlloc(io, config_path, allocator, .limited(1 * 1024 * 1024));
    defer allocator.free(raw);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const list = parsed.value.object.get("compilers") orelse return false;
    for (list.array.items) |item| {
        if (std.mem.eql(u8, item.string, "zig")) return false;
    }
    return true;
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

const FailureKind = enum {
    missing_source,
    compile_ir,
    compile_hex,
    canon_ir,
    ir_mismatch,
    script_mismatch,
    missing_golden_ir,
    missing_golden_hex,
    // N-389: a fixture named in EXPECTED_NOT_ZIG_COMPILABLE whose
    // source.json allowlist does not exclude zig.
    stale_expected_not_compilable,
};

const Failure = struct {
    name: []const u8,
    kind: FailureKind,
    detail: []const u8,
    expected: ?[]const u8 = null,
    actual: ?[]const u8 = null,
};

/// Outcome of classifying and (if required) compiling a single fixture.
/// Exactly one of `skipped`, `passed`, or `failure` applies.
const ClassifyOutcome = struct {
    skipped: bool = false,
    passed: bool = false,
    failure: ?Failure = null,
};

/// Classify (and, unless skipped/missing-source, compile and compare) a
/// single conformance fixture. Extracted from the aggregate test below so
/// the classification logic (N-124: allowlist skip, missing-source =
/// failure, missing-golden = failure) is directly unit-testable against
/// synthetic, throwaway fixture directories, without depending on or
/// risking the real conformance corpus.
///
/// N-124 fix (porting F-151's scan semantics):
///   - N-389 (R145): a fixture is SKIPPED only when it is named in
///     `not_compilable` AND its source.json `compilers` allowlist excludes
///     "zig". A named fixture whose allowlist does not exclude zig is a
///     `.stale_expected_not_compilable` FAILURE. An unnamed fixture is
///     always compiled and byte-checked, even when its allowlist excludes
///     zig.
///   - Any other fixture with no resolvable `.runar.zig` source is a
///     FAILURE (kind `.missing_source`). Before this fix, such fixtures
///     were appended only to a `missing` list that the aggregate test
///     printed but never failed on.
///   - A fixture whose source compiles but ships no `expected-ir.json` or
///     no `expected-script.hex` is a FAILURE (kind `.missing_golden_ir` /
///     `.missing_golden_hex`). Before this fix, `readFileAlloc(...) catch
///     null` followed by `if (expected_raw) |raw| { ...compare... }`
///     skipped the comparison entirely when the golden was absent, and the
///     fixture fell through to `passed` with zero bytes actually checked.
fn classifyFixture(
    allocator: std.mem.Allocator,
    io: std.Io,
    binary: []const u8,
    test_dir: []const u8,
    name: []const u8,
    not_compilable: []const []const u8,
) !ClassifyOutcome {
    const allowlisted = try fixtureAllowlistedForZig(allocator, io, test_dir);
    for (not_compilable) |n| {
        if (!std.mem.eql(u8, n, name)) continue;
        if (!allowlisted) return .{ .skipped = true };
        const detail = try std.fmt.allocPrint(
            allocator,
            "fixture '{s}' is named in EXPECTED_NOT_ZIG_COMPILABLE but its source.json allowlist does not exclude zig",
            .{name},
        );
        return .{ .failure = .{ .name = name, .kind = .stale_expected_not_compilable, .detail = detail } };
    }

    const source_opt = try findZigSource(allocator, io, test_dir);
    if (source_opt == null) {
        const detail = try std.fmt.allocPrint(allocator, "no .runar.zig source found for fixture '{s}'", .{name});
        return .{ .failure = .{ .name = name, .kind = .missing_source, .detail = detail } };
    }
    const source_path = source_opt.?;
    defer allocator.free(source_path);

    // Step 1: emit IR
    const ir_flags = [_][]const u8{ "--emit-ir", "--disable-constant-folding" };
    const ir_raw = runCompiler(allocator, io, binary, source_path, &ir_flags) catch |err| {
        const detail = try std.fmt.allocPrint(allocator, "emit-ir failed: {s}", .{@errorName(err)});
        return .{ .failure = .{ .name = name, .kind = .compile_ir, .detail = detail } };
    };
    defer allocator.free(ir_raw);

    // Step 2: emit hex
    const hex_flags = [_][]const u8{ "--hex", "--disable-constant-folding" };
    const hex_raw = runCompiler(allocator, io, binary, source_path, &hex_flags) catch |err| {
        const detail = try std.fmt.allocPrint(allocator, "emit-hex failed: {s}", .{@errorName(err)});
        return .{ .failure = .{ .name = name, .kind = .compile_hex, .detail = detail } };
    };
    defer allocator.free(hex_raw);

    // Canonicalize actual IR
    const actual_ir = canonicalizeJson(allocator, ir_raw) catch |err| {
        const detail = try std.fmt.allocPrint(allocator, "canonicalize actual IR: {s}", .{@errorName(err)});
        return .{ .failure = .{ .name = name, .kind = .canon_ir, .detail = detail } };
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
            return .{ .failure = .{ .name = name, .kind = .canon_ir, .detail = detail } };
        };
        if (!std.mem.eql(u8, actual_ir, expected_ir)) {
            const detail = try std.fmt.allocPrint(allocator, "IR differs (exp {d} / act {d} chars)", .{ expected_ir.len, actual_ir.len });
            return .{ .failure = .{
                .name = name,
                .kind = .ir_mismatch,
                .detail = detail,
                .expected = expected_ir,
                .actual = actual_ir,
            } };
        }
        allocator.free(expected_ir);
        allocator.free(actual_ir);
    } else {
        allocator.free(actual_ir);
        const detail = try std.fmt.allocPrint(allocator, "expected-ir.json not found for fixture '{s}'", .{name});
        return .{ .failure = .{ .name = name, .kind = .missing_golden_ir, .detail = detail } };
    }

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
            return .{ .failure = .{
                .name = name,
                .kind = .script_mismatch,
                .detail = detail,
                .expected = expected_hex,
                .actual = actual_hex,
            } };
        }
        allocator.free(expected_hex);
        allocator.free(actual_hex);
    } else {
        allocator.free(actual_hex);
        const detail = try std.fmt.allocPrint(allocator, "expected-script.hex not found for fixture '{s}'", .{name});
        return .{ .failure = .{ .name = name, .kind = .missing_golden_hex, .detail = detail } };
    }

    return .{ .passed = true };
}

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

// N-392. What this proves: a malformed (invalid JSON) source.json is a
// harness failure (error.MalformedSourceJson) from classifyFixture, not a
// silent fall-through to "no allowlist" / the *.runar.zig glob, and a
// source.json that exists but cannot be read as a file is
// error.UnreadableSourceJson. Mirrors Python F-323 and the Ruby harness.
//
// What this does not prove: that the real corpus has a malformed
// source.json (it does not), or the exact stderr wording.
test "conformance-goldens: a malformed source.json fails closed" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const binary = try resolveZigBinary(allocator);
    defer allocator.free(binary);

    const dir = try n124ScratchDir(allocator, io, "n392-malformed");
    defer allocator.free(dir);
    try n124WriteFile(io, dir, "source.json", "{not valid json");
    defer n124DeleteFile(io, dir, "source.json");

    try std.testing.expectError(
        error.MalformedSourceJson,
        classifyFixture(allocator, io, binary, dir, "n392-malformed", &.{}),
    );
}

test "conformance-goldens: an unreadable source.json fails closed" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const binary = try resolveZigBinary(allocator);
    defer allocator.free(binary);

    // A directory named source.json exists but cannot be read as a file.
    const dir = try n124ScratchDir(allocator, io, "n392-unreadable");
    defer allocator.free(dir);
    const sub = try std.fmt.allocPrint(allocator, "{s}/source.json", .{dir});
    defer allocator.free(sub);
    try std.Io.Dir.cwd().createDirPath(io, sub);
    defer std.Io.Dir.cwd().deleteDir(io, sub) catch {};

    try std.testing.expectError(
        error.UnreadableSourceJson,
        classifyFixture(allocator, io, binary, dir, "n392-unreadable", &.{}),
    );
}

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
    var skipped: std.ArrayListUnmanaged([]const u8) = .empty;
    defer skipped.deinit(allocator);
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

        const outcome = try classifyFixture(allocator, io, binary, test_dir, name, &EXPECTED_NOT_ZIG_COMPILABLE);
        if (outcome.skipped) {
            try skipped.append(allocator, name);
        } else if (outcome.failure) |f| {
            try failures.append(allocator, f);
        } else {
            try passed.append(allocator, name);
        }
    }

    const total = fixture_names.items.len;
    std.debug.print(
        "\n=== Zig conformance-goldens summary: {d} pass / {d} fail / {d} skipped (compilers allowlist excludes zig) (of {d} fixtures) ===\n",
        .{ passed.items.len, failures.items.len, skipped.items.len, total },
    );
    if (skipped.items.len > 0) {
        std.debug.print("Skipped (source.json \"compilers\" allowlist excludes zig):\n", .{});
        for (skipped.items) |n| std.debug.print("  - {s}\n", .{n});
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

    // N-389: the skipped set must be exactly the named set (names are in
    // sorted order on both sides), and passed + skipped must account for
    // every fixture.
    try std.testing.expectEqual(EXPECTED_NOT_ZIG_COMPILABLE.len, skipped.items.len);
    for (EXPECTED_NOT_ZIG_COMPILABLE, 0..) |n, k| {
        try std.testing.expectEqualStrings(n, skipped.items[k]);
    }
    try std.testing.expectEqual(total, passed.items.len + skipped.items.len);
    for (EXPECTED_NOT_ZIG_COMPILABLE) |n| {
        var known = false;
        for (fixture_names.items) |f| {
            if (std.mem.eql(u8, f, n)) known = true;
        }
        if (!known) {
            std.debug.print("EXPECTED_NOT_ZIG_COMPILABLE names unknown fixture '{s}'\n", .{n});
            return error.UnknownExpectedNotCompilableFixture;
        }
        const named_dir = try std.fmt.allocPrint(allocator, "{s}{s}", .{ conformance_base, n });
        defer allocator.free(named_dir);
        if (!try excludesZigRaw(allocator, io, named_dir)) {
            std.debug.print("'{s}' allowlist does not exclude zig\n", .{n});
            return error.StaleExpectedNotCompilableEntry;
        }
    }
}

// ============================================================================
// N-124: the Zig golden harness shared F-151's defects (fixed in Ruby) and
// F-280/F-285/F-323's defects (fixed in Go/Rust/Python):
//   (1) a fixture with no resolvable .runar.zig source was appended only to
//       the `missing` list, which the aggregate test above printed but
//       never failed on -- "every fixture's .runar.zig entry repointed at a
//       nonexistent file" reported 0 fail;
//   (2) a missing expected-ir.json / expected-script.hex was read with
//       `catch null`, and the comparison block (`if (raw) |..| {...}`) was
//       simply skipped when the result was null, falling through to
//       `passed` with zero bytes actually checked.
// Both are reproduced below against synthetic, throwaway fixture
// directories under zig-out/ (never against the real conformance corpus)
// and proven fixed. classifyFixture is what makes this directly testable
// without re-running the full fixture sweep.
// ============================================================================

/// Create (and clear a stale copy of) a scratch directory for one of the
/// tests below, under zig-out/ so it is never mistaken for a real fixture
/// under conformance/tests/. Mirrors the dir_path idiom in
/// cli_source_read_cap.zig; unlike that file this directory can hold more
/// than one file, so callers delete their own files but the directory
/// itself is left for the build system to clean up (zig-out is a build
/// artifact directory, not tracked).
fn n124ScratchDir(allocator: std.mem.Allocator, io: std.Io, label: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(allocator, "zig-out/n124-tmp-{s}", .{label});
    try std.Io.Dir.cwd().createDirPath(io, path);
    return path;
}

fn n124WriteFile(io: std.Io, dir: []const u8, name: []const u8, contents: []const u8) !void {
    var buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&buf, "{s}/{s}", .{ dir, name });
    var file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    var wbuf: [65536]u8 = undefined;
    var w = file.writer(io, &wbuf);
    try w.interface.writeAll(contents);
    try w.interface.flush();
}

fn n124DeleteFile(io: std.Io, dir: []const u8, name: []const u8) void {
    var buf: [512]u8 = undefined;
    const path = std.fmt.bufPrint(&buf, "{s}/{s}", .{ dir, name }) catch return;
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
}

fn freeOutcome(allocator: std.mem.Allocator, outcome: ClassifyOutcome) void {
    if (outcome.failure) |f| {
        allocator.free(f.detail);
        if (f.expected) |e| allocator.free(e);
        if (f.actual) |a| allocator.free(a);
    }
}

// What this proves: classifyFixture reports a fixture with no resolvable
// .runar.zig source as a FAILURE (kind .missing_source), not as a
// silently-unasserted "missing" bucket the caller can ignore.
//
// What this does not prove: that the real conformance corpus contains such
// a fixture today -- it does not (every fixture ships a .runar.zig
// source); this is a synthetic, throwaway fixture directory.
test "conformance-goldens: classifyFixture fails on a fixture with no .runar.zig source" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const binary = try resolveZigBinary(allocator);
    defer allocator.free(binary);

    const dir = try n124ScratchDir(allocator, io, "missing-source");
    defer allocator.free(dir);
    // No source.json, no *.runar.zig file written into `dir`.

    const outcome = try classifyFixture(allocator, io, binary, dir, "n124-missing-source", &.{});
    defer freeOutcome(allocator, outcome);

    if (outcome.failure == null) {
        std.debug.print("classifyFixture returned {any} (treated a missing source as a pass/skip); want a failure with kind=missing_source\n", .{outcome});
        return error.MissingSourceNotReportedAsFailure;
    }
    if (outcome.failure.?.kind != .missing_source) {
        std.debug.print("got failure kind {s}, want missing_source\n", .{@tagName(outcome.failure.?.kind)});
        return error.WrongFailureKind;
    }
}

// What this proves: classifyFixture SKIPS (not fails) a fixture whose
// source.json `compilers` allowlist excludes "zig" AND which is named as
// expected-not-compilable (N-389) -- mirroring the Rust
// harness's fixture_allowlisted_for_rust (F-285) and the Ruby harness's
// read_compiler_allowlist (F-151). Without this, treating every
// missing-source fixture as a failure (the fix above) would wrongly fail a
// fixture that legitimately ships no .runar.zig source because zig is not
// a required conformance target for it.
//
// What this does not prove: that the real conformance corpus contains such
// a fixture today for zig specifically -- it does not; the four existing
// "compilers": ["go"] fixtures all exclude zig today, but they do ship
// .runar.zig sources anyway (frontend parity requires it), so this
// specific no-source-plus-excluded combination is synthetic.
test "conformance-goldens: classifyFixture skips an allowlist-excluded fixture with no source" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const binary = try resolveZigBinary(allocator);
    defer allocator.free(binary);

    const dir = try n124ScratchDir(allocator, io, "allowlist-excluded");
    defer allocator.free(dir);
    try n124WriteFile(io, dir, "source.json", "{\"compilers\":[\"go\"]}");
    defer n124DeleteFile(io, dir, "source.json");
    // No *.runar.zig file -- legitimate, since the allowlist excludes zig.

    const outcome = try classifyFixture(allocator, io, binary, dir, "n124-allowlist-excluded", &[_][]const u8{"n124-allowlist-excluded"});
    defer freeOutcome(allocator, outcome);

    if (outcome.failure != null) {
        std.debug.print("an allowlist-excluded fixture must not be reported as a failure (got: {any})\n", .{outcome});
        return error.AllowlistExcludedFixtureReportedAsFailure;
    }
    if (!outcome.skipped) {
        std.debug.print("expected outcome.skipped=true, got {any}\n", .{outcome});
        return error.AllowlistExcludedFixtureNotSkipped;
    }
}

// What this proves: classifyFixture reports a missing expected-ir.json as
// a FAILURE (kind .missing_golden_ir), not as "nothing to compare against,
// mark it passed" -- the behavior the old `if (expected_ir_raw) |raw| {
// ...compare... }` guard produced when the golden was absent (the block
// was simply skipped, falling through to `passed`).
//
// What this does not prove: that the real conformance corpus contains a
// fixture missing this golden today -- it does not; every fixture ships
// both goldens. This test uses the real P2PKH contract source (copied
// inline) so the fixture actually compiles, isolating the missing-golden
// path from compile failures.
test "conformance-goldens: classifyFixture fails on a fixture with no expected-ir.json" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const binary = try resolveZigBinary(allocator);
    defer allocator.free(binary);

    const dir = try n124ScratchDir(allocator, io, "missing-golden-ir");
    defer allocator.free(dir);
    try n124WriteFile(io, dir, "P2PKH.runar.zig", N124_P2PKH_SOURCE);
    defer n124DeleteFile(io, dir, "P2PKH.runar.zig");
    // expected-ir.json and expected-script.hex deliberately absent.

    const outcome = try classifyFixture(allocator, io, binary, dir, "n124-missing-golden-ir", &.{});
    defer freeOutcome(allocator, outcome);

    if (outcome.failure == null) {
        std.debug.print("classifyFixture returned {any} (treated a missing expected-ir.json as a pass); want a failure with kind=missing_golden_ir\n", .{outcome});
        return error.MissingGoldenIrNotReportedAsFailure;
    }
    if (outcome.failure.?.kind != .missing_golden_ir) {
        std.debug.print("got failure kind {s}, want missing_golden_ir\n", .{@tagName(outcome.failure.?.kind)});
        return error.WrongFailureKind;
    }
}

// What this proves: classifyFixture reports a missing expected-script.hex
// as a FAILURE (kind .missing_golden_hex), isolated from the IR-missing
// case above by giving it a matching expected-ir.json (the actual compiled
// IR, written verbatim) so the IR comparison passes first and the hex path
// is what's actually exercised.
//
// What this does not prove: the hex comparison logic itself when the
// golden IS present (covered by the real-corpus run in the aggregate test
// above).
test "conformance-goldens: classifyFixture fails on a fixture with no expected-script.hex" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const binary = try resolveZigBinary(allocator);
    defer allocator.free(binary);

    const dir = try n124ScratchDir(allocator, io, "missing-golden-hex");
    defer allocator.free(dir);
    try n124WriteFile(io, dir, "P2PKH.runar.zig", N124_P2PKH_SOURCE);
    defer n124DeleteFile(io, dir, "P2PKH.runar.zig");

    // Compile once to get the actual IR, then write it back as the golden
    // so the IR comparison passes and only the missing-hex path fires.
    const source_path = try std.fmt.allocPrint(allocator, "{s}/P2PKH.runar.zig", .{dir});
    defer allocator.free(source_path);
    const ir_flags = [_][]const u8{ "--emit-ir", "--disable-constant-folding" };
    const ir_raw = try runCompiler(allocator, io, binary, source_path, &ir_flags);
    defer allocator.free(ir_raw);
    try n124WriteFile(io, dir, "expected-ir.json", ir_raw);
    defer n124DeleteFile(io, dir, "expected-ir.json");
    // expected-script.hex deliberately absent.

    const outcome = try classifyFixture(allocator, io, binary, dir, "n124-missing-golden-hex", &.{});
    defer freeOutcome(allocator, outcome);

    if (outcome.failure == null) {
        std.debug.print("classifyFixture returned {any} (treated a missing expected-script.hex as a pass); want a failure with kind=missing_golden_hex\n", .{outcome});
        return error.MissingGoldenHexNotReportedAsFailure;
    }
    if (outcome.failure.?.kind != .missing_golden_hex) {
        std.debug.print("got failure kind {s}, want missing_golden_hex\n", .{@tagName(outcome.failure.?.kind)});
        return error.WrongFailureKind;
    }
}

const N124_P2PKH_SOURCE =
    \\const runar = @import("runar");
    \\
    \\pub const P2PKH = struct {
    \\    pub const Contract = runar.SmartContract;
    \\
    \\    pubKeyHash: runar.Addr,
    \\
    \\    pub fn init(pubKeyHash: runar.Addr) P2PKH {
    \\        return .{ .pubKeyHash = pubKeyHash };
    \\    }
    \\
    \\    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
    \\        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.pubKeyHash));
    \\        runar.assert(runar.checkSig(sig, pubKey));
    \\    }
    \\};
    \\
;

// ============================================================================
// N-389 (R145): the sweep used to skip EVERY allowlist-excluded fixture,
// dropping the byte check on Go-only fixtures Zig compiles in agreement
// with Go, and treated a non-list `compilers` value as "no allowlist".
// Exercised against synthetic, throwaway fixture directories only.
// ============================================================================

// What this proves: an allowlist-excluded fixture that is NOT named in the
// not-compilable set is attempted, not skipped (here it has no source, so it
// surfaces as .missing_source).
//
// What this does not prove: the byte comparison for such a fixture (the
// real-corpus sweep covers babybear, babybear-ext4, merkle-proof and
// state-covenant).
test "conformance-goldens: classifyFixture compiles an excluded but unnamed fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const binary = try resolveZigBinary(allocator);
    defer allocator.free(binary);

    const dir = try n124ScratchDir(allocator, io, "n389-unnamed");
    defer allocator.free(dir);
    try n124WriteFile(io, dir, "source.json", "{\"compilers\":[\"go\"]}");
    defer n124DeleteFile(io, dir, "source.json");

    const outcome = try classifyFixture(allocator, io, binary, dir, "n389-unnamed", &.{});
    defer freeOutcome(allocator, outcome);

    if (outcome.skipped) return error.UnnamedExcludedFixtureWasSkipped;
    if (outcome.failure == null or outcome.failure.?.kind != .missing_source) {
        std.debug.print("want failure kind missing_source, got {any}\n", .{outcome});
        return error.WrongOutcome;
    }
}

// What this proves: a named fixture whose allowlist does NOT exclude zig is
// a .stale_expected_not_compilable failure, not a skip.
//
// What this does not prove: that the named set matches what zig refuses
// today (the real-corpus sweep asserts that).
test "conformance-goldens: classifyFixture flags a stale named entry" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const binary = try resolveZigBinary(allocator);
    defer allocator.free(binary);

    const dir = try n124ScratchDir(allocator, io, "n389-stale");
    defer allocator.free(dir);
    try n124WriteFile(io, dir, "source.json", "{\"compilers\":[\"go\",\"zig\"]}");
    defer n124DeleteFile(io, dir, "source.json");

    const outcome = try classifyFixture(allocator, io, binary, dir, "n389-stale", &[_][]const u8{"n389-stale"});
    defer freeOutcome(allocator, outcome);

    if (outcome.skipped) return error.StaleNamedEntryWasSkipped;
    if (outcome.failure == null or outcome.failure.?.kind != .stale_expected_not_compilable) {
        std.debug.print("want failure kind stale_expected_not_compilable, got {any}\n", .{outcome});
        return error.WrongOutcome;
    }
}

// What this proves: a non-list `compilers` value fails closed
// (error.InvalidCompilersAllowlist) instead of being treated as "no
// allowlist".
//
// What this does not prove: that the real corpus has such a value (it does
// not).
test "conformance-goldens: a non-list compilers value fails closed" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const binary = try resolveZigBinary(allocator);
    defer allocator.free(binary);

    const dir = try n124ScratchDir(allocator, io, "n389-non-list");
    defer allocator.free(dir);
    try n124WriteFile(io, dir, "source.json", "{\"compilers\":\"go\"}");
    defer n124DeleteFile(io, dir, "source.json");

    try std.testing.expectError(
        error.InvalidCompilersAllowlist,
        classifyFixture(allocator, io, binary, dir, "n389-non-list", &.{}),
    );
}
