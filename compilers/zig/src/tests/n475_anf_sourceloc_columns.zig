//! N-475 -- the artifact `anf` section's sourceLoc values equal the TS ones.
//!
//! Zig's parser carries 1-based columns in `types.SourceLocation`; the TS
//! reference artifact (and the Zig source map, since N-467) is 0-based. The
//! stateful-contract artifact embeds the ANF program, so every binding's
//! `sourceLoc.column` must be 0-based too. For each stateful examples/ts
//! contract below the source is compiled with constant folding off and the
//! sourceLoc (line, column) of every ANF binding, walked depth-first in method
//! order through `if` then/else and `loop` bodies, is compared with the TS
//! compiler's, pinned in n475_ts_anf_sourceloc_reference.json (null = the
//! binding carries no sourceLoc).
//!
//! N-481 extends it to the synthetic `constructor` method (TS gives its
//! `super(...)` call bindings the super statement's sourceLoc) and to the
//! `file` field.
//!
//! What this proves: for these 5 contracts the Zig artifact's anf sourceLoc
//! line/column equals TS for every binding of every method (constructor
//! included), including which bindings have none, and every sourceLoc `file`
//! equals the file name the source was compiled under (which is what TS
//! emits).
//!
//! What this does not prove: fold-on artifacts; surfaces other than
//! .runar.ts (the other parsers record the super location by the same
//! mechanism but are not pinned here); the TS values are pinned, not
//! recomputed, so a TS-side change needs a re-pin.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const REFERENCE = @embedFile("n475_ts_anf_sourceloc_reference.json");
const REFERENCE_N487 = @embedFile("n487_ts_anf_sourceloc_reference.json");

fn walk(a: std.mem.Allocator, want_file: []const u8, bindings: []const std.json.Value, acc: *std.ArrayListUnmanaged(?[2]i64)) !void {
    for (bindings) |b| {
        if (b.object.get("sourceLoc")) |sl| {
            if (!std.mem.eql(u8, sl.object.get("file").?.string, want_file)) return error.WrongFile;
            try acc.append(a, .{ sl.object.get("line").?.integer, sl.object.get("column").?.integer });
        } else {
            try acc.append(a, null);
        }
        const v = b.object.get("value").?.object;
        inline for (.{ "then", "else", "body" }) |k| {
            if (v.get(k)) |arr| {
                if (arr == .array) try walk(a, want_file, arr.array.items, acc);
            }
        }
    }
}

test "N-475: Zig artifact anf sourceLoc equals the pinned TS reference per binding" {
    try checkAgainstReference(REFERENCE);
}

// N-487: the same comparison for the .runar.sol/.move/.go/.rs/.zig surfaces of
// the same five contracts, whose Zig parsers synthesize the constructor's
// super(...) call (and, with no constructor body, its property writes) with no
// source statement. TS locates them at the constructor token (.sol with an
// explicit constructor) or at the 1:0 placeholder every tier uses for a
// synthesized constructor (.sol without one, .move, .go, .rs, .zig; the Go
// tier agrees with TS on this, so it is a cross-tier convention rather than a
// TS-only quirk).
//
// What this proves: for those 25 files every ANF binding's sourceLoc
// line/column equals the pinned TS value, constructor bindings included.
// What this does not prove: fold-on artifacts, or that 1:0 is a meaningful
// location (it is a placeholder); the TS values are pinned, not recomputed.
test "N-487: Zig artifact anf sourceLoc equals TS for the non-TS surfaces" {
    try checkAgainstReference(REFERENCE_N487);
}

fn checkAgainstReference(reference: []const u8) !void {
    const a = std.testing.allocator;
    const ref = try std.json.parseFromSlice(std.json.Value, a, reference, .{});
    defer ref.deinit();

    var failures: usize = 0;
    var it = ref.value.object.iterator();
    while (it.next()) |entry| {
        const rel = entry.key_ptr.*;
        const want = entry.value_ptr.array.items;
        const path = try std.fmt.allocPrint(a, "../../{s}", .{rel});
        defer a.free(path);
        const src = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, a, .limited(1024 * 1024));
        defer a.free(src);

        const result = try compiler_api.compileSourceWithOptions(a, src, std.fs.path.basename(rel), true);
        defer result.deinit(a);
        const artifact = result.artifact_json orelse return error.MissingArtifact;
        const parsed = try std.json.parseFromSlice(std.json.Value, a, artifact, .{});
        defer parsed.deinit();
        const anf = parsed.value.object.get("anf") orelse return error.MissingAnf;

        var got: std.ArrayListUnmanaged(?[2]i64) = .empty;
        defer got.deinit(a);
        for (anf.object.get("methods").?.array.items) |m| {
            try walk(a, std.fs.path.basename(rel), m.object.get("body").?.array.items, &got);
        }

        var first_bad: ?usize = null;
        const n = @min(want.len, got.items.len);
        for (0..n) |i| {
            const g = got.items[i];
            if (want[i] == .null) {
                if (g != null) {
                    first_bad = i;
                    break;
                }
            } else {
                const w = want[i].array.items;
                if (g == null or g.?[0] != w[0].integer or g.?[1] != w[1].integer) {
                    first_bad = i;
                    break;
                }
            }
        }
        if (first_bad == null and want.len != got.items.len) first_bad = n;
        if (first_bad) |i| {
            failures += 1;
            std.debug.print("{s}: binding {d} differs (TS {d}, Zig {d} bindings)", .{ rel, i, want.len, got.items.len });
            if (i < want.len and want[i] != .null) std.debug.print(" TS {d}:{d}", .{ want[i].array.items[0].integer, want[i].array.items[1].integer });
            if (i < got.items.len) {
                if (got.items[i]) |g| std.debug.print(" Zig {d}:{d}", .{ g[0], g[1] });
            }
            std.debug.print("\n", .{});
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
}
