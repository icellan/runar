//! N-467 -- the Zig source map equals the TS reference map, opcode by opcode.
//!
//! For each examples/ts contract below, the .runar.ts source is compiled with
//! constant folding off and every opcode's (line, column) is compared with the
//! TS compiler's map for the same source, pinned in n467_ts_reference_map.json
//! as runs `[first opcodeIndex, count, line, column]` (unmapped opcodes have no
//! run). The examples cover each way the two maps used to differ:
//!   - an if-arm's first op inherits the if's location, and OP_ELSE / OP_ENDIF
//!     go out under whatever the last arm op left (boolean-logic,
//!     fixed-array-index, nested-if-multi-reassign, companion-verifier);
//!   - every opcode a multi-opcode instruction emits is mapped;
//!   - the arms of builtin if-ops are unmapped (merkle-proof, state-covenant,
//!     byte-builtins / reverseBytes, math-demo / sign+pow+sqrt+gcd, WOTS,
//!     P-256, ecEncodeCompressed in ec-unit);
//!   - statements the FixedArray expansion generates carry the source
//!     statement's location (fixed-array-write, tic-tac-toe v2);
//!   - an early-return if keeps its location, and a return statement maps to
//!     its own line (multi-method, function-patterns, tic-tac-toe v2).
//!
//! What this proves: for these 15 examples the Zig map, fold off, equals the
//! TS map per opcode, including which opcodes are unmapped.
//!
//! What this does not prove: fold-on maps; any surface other than .runar.ts
//! (only the .runar.ts parser records a return statement's location); the TS
//! map is pinned, not recomputed, so a TS-side change needs a re-pin.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const REFERENCE = @embedFile("n467_ts_reference_map.json");

const Run = [4]i64;

fn runsFromArtifact(a: std.mem.Allocator, artifact: []const u8) !std.ArrayListUnmanaged(Run) {
    const parsed = try std.json.parseFromSlice(std.json.Value, a, artifact, .{});
    defer parsed.deinit();
    var runs: std.ArrayListUnmanaged(Run) = .empty;
    errdefer runs.deinit(a);
    const sm = parsed.value.object.get("sourceMap") orelse return runs;
    var last_idx: i64 = -1;
    for (sm.object.get("mappings").?.array.items) |m| {
        const idx = m.object.get("opcodeIndex").?.integer;
        const line = m.object.get("line").?.integer;
        const col = m.object.get("column").?.integer;
        // The map is emitted in opcode order, one entry per opcode.
        if (idx <= last_idx) return error.MapNotStrictlyIncreasing;
        last_idx = idx;
        if (runs.items.len > 0) {
            const r = &runs.items[runs.items.len - 1];
            if (r[0] + r[1] == idx and r[2] == line and r[3] == col) {
                r[1] += 1;
                continue;
            }
        }
        try runs.append(a, .{ idx, 1, line, col });
    }
    return runs;
}

test "N-467: Zig source maps equal the pinned TS reference per opcode" {
    const a = std.testing.allocator;
    const ref = try std.json.parseFromSlice(std.json.Value, a, REFERENCE, .{});
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
        const file_name = std.fs.path.basename(rel);

        const result = try compiler_api.compileSourceWithOptions(a, src, file_name, true);
        defer result.deinit(a);
        const artifact = result.artifact_json orelse return error.MissingArtifact;
        var got = try runsFromArtifact(a, artifact);
        defer got.deinit(a);

        const n = @min(want.len, got.items.len);
        var first_bad: ?usize = null;
        for (0..n) |i| {
            const w = want[i].array.items;
            const g = got.items[i];
            if (w[0].integer != g[0] or w[1].integer != g[1] or w[2].integer != g[2] or w[3].integer != g[3]) {
                first_bad = i;
                break;
            }
        }
        if (first_bad == null and want.len != got.items.len) first_bad = n;
        if (first_bad) |i| {
            failures += 1;
            std.debug.print("{s}: run {d} differs (TS {d} runs, Zig {d} runs)", .{ rel, i, want.len, got.items.len });
            if (i < want.len) {
                const w = want[i].array.items;
                std.debug.print(" TS [{d},{d},{d}:{d}]", .{ w[0].integer, w[1].integer, w[2].integer, w[3].integer });
            }
            if (i < got.items.len) {
                const g = got.items[i];
                std.debug.print(" Zig [{d},{d},{d}:{d}]", .{ g[0], g[1], g[2], g[3] });
            }
            std.debug.print("\n", .{});
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
}
