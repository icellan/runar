//! N-320: the state-reading paths must refuse a hostile script with
//! `error.MalformedScript`, never panic, hang or fabricate state.
//!
//! Replays `conformance/sdk-matches-artifact/hostile-state.json` — the N-317
//! hostile scripts of `hostile.json` with expected outcomes for
//! `extractStateFromScript` and `RunarContract.fromUtxo` (replayed by all 7
//! SDKs; this tier has no `fromTxId` on `RunarContract`).
//!
//! Proves: for each of the 30 scripts, `extractStateFromScript` on the
//! stateful artifact returns exactly the expected state / null /
//! `error.MalformedScript`, and `fromUtxo` either reconnects or returns
//! `error.MalformedScript` (any other error fails it) — an odd-length, non-hex
//! or non-ASCII script is refused before any reader runs, and a stateful
//! artifact over a script with no state section is refused (C10, as in TS)
//! instead of carrying constructor-initial state; nothing leaks on either path
//! (std.testing.allocator); the replay used less than a process-CPU budget.
//! N-324: no case is excluded — fromUtxo on stateful-large-genuine decodes its
//! 1 MiB bigint constructor arg (2.5M decimal digits) inside that same budget,
//! because the magnitude-to-decimal conversion is now subquadratic; it used to
//! be quadratic (~100 min) and was skipped here.
//! Does NOT prove: that a hang would be cut off -- Zig cannot stop a running
//! thread, so a non-terminating reader stalls this test rather than failing it
//! at the budget; a panic aborts the test binary rather than being reported
//! per case. Nor on-chain spendability or artifact shapes beyond the two.

const std = @import("std");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");
const contract_mod = @import("sdk_contract.zig");

const DIR = "../../conformance/sdk-matches-artifact/";
// The other tiers use 20 s. This tier's tests run as an unoptimised Debug
// build: the replay takes ~12.5 s on an M-series Mac and went past 20 s on
// CI's x86_64 runner. 60 s still fails the quadratic decoder (~100 min).
const CPU_BUDGET_US: i64 = 60 * std.time.us_per_s;

fn cpuMicros() i64 {
    const ru = std.posix.getrusage(std.posix.rusage.SELF);
    return @as(i64, ru.utime.sec) * std.time.us_per_s + ru.utime.usec + @as(i64, ru.stime.sec) * std.time.us_per_s + ru.stime.usec;
}

fn scriptOf(allocator: std.mem.Allocator, c: std.json.ObjectMap) ![]u8 {
    const prefix = c.get("prefix").?.string;
    const repeat = if (c.get("repeat")) |v| v.string else "";
    const count: usize = if (c.get("count")) |v| @intCast(v.integer) else 0;
    const suffix = if (c.get("suffix")) |v| v.string else "";
    var out = try allocator.alloc(u8, prefix.len + repeat.len * count + suffix.len);
    @memcpy(out[0..prefix.len], prefix);
    var pos = prefix.len;
    for (0..count) |_| {
        @memcpy(out[pos .. pos + repeat.len], repeat);
        pos += repeat.len;
    }
    @memcpy(out[pos..], suffix);
    return out;
}

fn readJson(allocator: std.mem.Allocator, name: []const u8) !std.json.Parsed(std.json.Value) {
    const path = try std.mem.concat(allocator, u8, &.{ DIR, name });
    defer allocator.free(path);
    const raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(1024 * 1024));
    defer allocator.free(raw);
    return std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
}

/// "name=value;" per field — the expected object and the decoded state are
/// both rendered this way. bigint values are decimal.
fn renderState(allocator: std.mem.Allocator, artifact: *const types.RunarArtifact, vals: []const types.StateValue) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    for (artifact.state_fields, vals) |f, v| {
        const s = switch (v) {
            .int => |n| try std.fmt.allocPrint(allocator, "{s}={d};", .{ f.name, n }),
            .big_int => |d| try std.fmt.allocPrint(allocator, "{s}={s};", .{ f.name, d }),
            else => try std.fmt.allocPrint(allocator, "{s}=?;", .{f.name}),
        };
        defer allocator.free(s);
        try out.appendSlice(allocator, s);
    }
    return out.toOwnedSlice(allocator);
}

test "N-320: hostile scripts on the state-reading paths" {
    const allocator = std.testing.allocator;
    const fx = try readJson(allocator, "hostile.json");
    defer fx.deinit();
    const sfx = try readJson(allocator, "hostile-state.json");
    defer sfx.deinit();
    const artifacts_json = fx.value.object.get("artifacts").?.object;
    const cases = fx.value.object.get("cases").?.array.items;
    const want = sfx.value.object.get("cases").?.array.items;
    try std.testing.expect(cases.len > 0 and cases.len == want.len);

    const stateful_json = try std.json.Stringify.valueAlloc(allocator, artifacts_json.get("stateful").?, .{});
    defer allocator.free(stateful_json);
    var stateful = try types.RunarArtifact.fromJson(allocator, stateful_json);
    defer stateful.deinit();

    var failures: usize = 0;
    const start = cpuMicros();

    for (cases, want) |cv, wv| {
        const c = cv.object;
        const w = wv.object;
        const name = c.get("name").?.string;
        try std.testing.expectEqualStrings(name, w.get("name").?.string);
        const script = try scriptOf(allocator, c);
        defer allocator.free(script);

        // extractStateFromScript on the stateful artifact
        const want_state: []u8 = switch (w.get("state").?) {
            .null => try allocator.dupe(u8, "null"),
            .string => |s| try allocator.dupe(u8, s),
            .object => |o| blk: {
                var buf: std.ArrayListUnmanaged(u8) = .empty;
                var it = o.iterator();
                while (it.next()) |e| {
                    const s = try std.fmt.allocPrint(allocator, "{s}={s};", .{ e.key_ptr.*, e.value_ptr.*.string });
                    defer allocator.free(s);
                    try buf.appendSlice(allocator, s);
                }
                break :blk try buf.toOwnedSlice(allocator);
            },
            else => unreachable,
        };
        defer allocator.free(want_state);
        const got_state: []u8 = if (state_mod.extractStateFromScript(allocator, &stateful, script)) |maybe| blk: {
            const vals = maybe orelse break :blk try allocator.dupe(u8, "null");
            defer {
                for (vals) |*v| v.deinit(allocator);
                allocator.free(vals);
            }
            break :blk try renderState(allocator, &stateful, vals);
        } else |err| if (std.mem.eql(u8, @errorName(err), "MalformedScript"))
            try allocator.dupe(u8, "malformed")
        else
            try std.fmt.allocPrint(allocator, "error:{s}", .{@errorName(err)});
        defer allocator.free(got_state);
        if (!std.mem.eql(u8, want_state, got_state)) {
            std.debug.print("N-320 extractStateFromScript {s}: want {s}, got {s}\n", .{ name, want_state, got_state });
            failures += 1;
        }

        // fromUtxo on the case's artifact — every case, stateful-large-genuine
        // (1 MiB bigint ctor arg) included (N-324).
        const artifact_json = try std.json.Stringify.valueAlloc(allocator, artifacts_json.get(c.get("artifact").?.string).?, .{});
        defer allocator.free(artifact_json);
        var artifact = try types.RunarArtifact.fromJson(allocator, artifact_json);
        defer artifact.deinit();
        const utxo = types.UTXO{ .txid = "00" ** 32, .output_index = 0, .satoshis = 1000, .script = script };
        var got_utxo_buf: [64]u8 = undefined;
        const got_utxo: []const u8 = if (contract_mod.RunarContract.fromUtxo(allocator, &artifact, utxo)) |rc| blk: {
            var mrc = rc;
            mrc.deinit();
            break :blk "ok";
        } else |err| if (std.mem.eql(u8, @errorName(err), "MalformedScript"))
            "malformed"
        else
            try std.fmt.bufPrint(&got_utxo_buf, "error:{s}", .{@errorName(err)});
        if (!std.mem.eql(u8, got_utxo, w.get("fromUtxo").?.string)) {
            std.debug.print("N-320 fromUtxo {s}: want {s}, got {s}\n", .{ name, w.get("fromUtxo").?.string, got_utxo });
            failures += 1;
        }
    }

    const used = cpuMicros() - start;
    try std.testing.expect(used < CPU_BUDGET_US);
    try std.testing.expectEqual(@as(usize, 0), failures);
}
