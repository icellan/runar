//! N-317: one hostile UTXO script must not take `TokenWallet.getUtxos` down,
//! and `matchesArtifact` must agree with the TS SDK on every malformed shape.
//!
//! Replays the shared cross-tier vector
//! `conformance/sdk-matches-artifact/hostile.json` (also replayed by the TS,
//! Go, Rust, Python, Ruby and Java SDKs): odd-length and non-hex scripts,
//! truncated OP_PUSHDATA1/2/4, OP_PUSHDATA4 lengths with the high bit set, a
//! push running past the slot, empty and short scripts and ~1 MiB scripts,
//! beside SDK-built genuine instances.
//!
//! Proves: matchesArtifact gives exactly the fixture's outcome per vector
//! (true / false / error.MalformedScript); getUtxos keeps exactly the genuine
//! instances for a stateful and a stateless artifact and returns no error;
//! the replay used less than a process-CPU budget (getrusage before/after).
//! Does NOT prove: that a hang would be cut off -- Zig has no way to stop a
//! running thread, so a non-terminating matcher would stall this test rather
//! than fail it at the budget; a panic (ReleaseSafe overflow / bounds) aborts
//! the test binary rather than being reported per case. Nor on-chain
//! spendability, artifact shapes beyond the fixture's two, or anything about a
//! forged codeSepIndex element (N-318).

const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const script_utils = @import("sdk_script_utils.zig");
const token_wallet = @import("sdk_token_wallet.zig");

const FIXTURE_PATH = "../../conformance/sdk-matches-artifact/hostile.json";

/// Measured: well under a second of CPU after the fix.
const CPU_BUDGET_US: i64 = 20 * std.time.us_per_s;

const Signer = struct {
    fn getPublicKeyImpl(_: *anyopaque, allocator: std.mem.Allocator) signer_mod.SignerError![]u8 {
        return allocator.dupe(u8, "02" ++ ("00" ** 32)) catch return error.OutOfMemory;
    }
    fn getAddressImpl(_: *anyopaque, allocator: std.mem.Allocator) signer_mod.SignerError![]u8 {
        return allocator.dupe(u8, "hostileAddr") catch return error.OutOfMemory;
    }
    fn signImpl(_: *anyopaque, allocator: std.mem.Allocator, _: []const u8, _: usize, _: []const u8, _: i64, _: ?u32) signer_mod.SignerError![]u8 {
        return allocator.dupe(u8, "00" ** 72) catch return error.OutOfMemory;
    }
    const vtable = signer_mod.Signer.VTable{ .getPublicKey = getPublicKeyImpl, .getAddress = getAddressImpl, .sign = signImpl };
};

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

test "N-317: hostile UTXO scripts are rejected without aborting the listing" {
    const allocator = std.testing.allocator;
    const raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, FIXTURE_PATH, allocator, .limited(1024 * 1024));
    defer allocator.free(raw);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const artifacts_json = parsed.value.object.get("artifacts").?.object;
    const cases = parsed.value.object.get("cases").?.array.items;
    try std.testing.expect(cases.len > 0);

    var failures: usize = 0;
    const start = cpuMicros();

    for (cases) |cv| {
        const c = cv.object;
        const artifact_json = try std.json.Stringify.valueAlloc(allocator, artifacts_json.get(c.get("artifact").?.string).?, .{});
        defer allocator.free(artifact_json);
        var artifact = try types.RunarArtifact.fromJson(allocator, artifact_json);
        defer artifact.deinit();
        const script = try scriptOf(allocator, c);
        defer allocator.free(script);
        const got: []const u8 = if (script_utils.matchesArtifact(&artifact, script)) |ok|
            (if (ok) "match" else "no_match")
        else |err| switch (err) {
            error.MalformedScript => "malformed",
        };
        if (!std.mem.eql(u8, got, c.get("matches").?.string)) {
            std.debug.print("N-317 {s}: want {s}, got {s}\n", .{ c.get("name").?.string, c.get("matches").?.string, got });
            failures += 1;
        }
    }

    var it = artifacts_json.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        const artifact_json = try std.json.Stringify.valueAlloc(allocator, entry.value_ptr.*, .{});
        defer allocator.free(artifact_json);
        var artifact = try types.RunarArtifact.fromJson(allocator, artifact_json);
        defer artifact.deinit();

        var prov = provider_mod.MockProvider.init(allocator, "testnet");
        defer prov.deinit();
        var want: std.ArrayListUnmanaged([]u8) = .empty;
        defer {
            for (want.items) |w| allocator.free(w);
            want.deinit(allocator);
        }
        for (cases, 0..) |cv, i| {
            const c = cv.object;
            if (!std.mem.eql(u8, c.get("artifact").?.string, name) or c.get("wallet").? == .null) continue;
            var byte_hex: [2]u8 = undefined;
            _ = try std.fmt.bufPrint(&byte_hex, "{x:0>2}", .{@as(u8, @intCast(i))});
            const txid = try allocator.alloc(u8, 64);
            for (0..32) |k| @memcpy(txid[k * 2 .. k * 2 + 2], &byte_hex);
            const script = try scriptOf(allocator, c);
            defer allocator.free(script);
            prov.addUtxo("hostileAddr", .{ .txid = txid, .output_index = 0, .satoshis = 1000, .script = script }) catch |e| {
                allocator.free(txid);
                return e;
            };
            if (c.get("wallet").?.bool) try want.append(allocator, txid) else allocator.free(txid);
        }
        var dummy: u8 = 0;
        const signer = signer_mod.Signer{ .ptr = @ptrCast(&dummy), .vtable = &Signer.vtable };
        var tw = token_wallet.TokenWallet.init(allocator, &artifact, prov.provider(), signer);
        const kept = tw.getUtxos(allocator) catch |err| {
            std.debug.print("N-317 getUtxos ({s}) failed: {s}\n", .{ name, @errorName(err) });
            failures += 1;
            continue;
        };
        defer {
            for (kept) |*u| {
                var mu = u.*;
                mu.deinit(allocator);
            }
            allocator.free(kept);
        }
        var same = kept.len == want.items.len;
        if (same) for (kept, want.items) |k, w| {
            if (!std.mem.eql(u8, k.txid, w)) same = false;
        };
        if (!same) {
            std.debug.print("N-317 getUtxos ({s}): want {d} UTXOs, got {d}:", .{ name, want.items.len, kept.len });
            for (kept) |k| std.debug.print(" {s}", .{k.txid[0..2]});
            std.debug.print("\n", .{});
            failures += 1;
        }
    }

    const used = cpuMicros() - start;
    try std.testing.expect(used < CPU_BUDGET_US);
    try std.testing.expectEqual(@as(usize, 0), failures);
}
