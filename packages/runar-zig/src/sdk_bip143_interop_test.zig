//! Cross-tier BIP-143 sighash interop test (GAP-003).
//!
//! Loads `conformance/sdk-bip143/fixtures.json` (TS reference, generated via
//! @bsv/sdk TransactionSignature.format) and asserts, for every scenario, that
//! this tier:
//!
//!   1. recomputes the full BIP-143 preimage byte-identically from
//!      (unsignedTxHex, inputIndex, prevScriptHex, prevValueSats) — the core
//!      node-free cross-tier correctness check;
//!   2. produces sha256d(preimage) == the fixture digestHex; and
//!   3. verifies the TS-produced sigHex against pubkeyHex over that digest.
//!
//! Any failure here is a cross-tier BIP-143 protocol divergence (a real
//! consensus bug). See CLAUDE.md §"Seven SDKs Must Stay in Sync".

const std = @import("std");
const oppushtx = @import("sdk_oppushtx.zig");
const envelope = @import("sdk_envelope.zig");

const FIXTURE_REL_PATH = "../../conformance/sdk-bip143/fixtures.json";

fn loadFixtureBytes(allocator: std.mem.Allocator) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, FIXTURE_REL_PATH, allocator, .limited(1024 * 1024));
}

fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    return envelope.hexToBytes(allocator, hex);
}

fn sha256d(data: []const u8) [32]u8 {
    var first: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &first, .{});
    var second: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&first, &second, .{});
    return second;
}

test "interop: BIP-143 preimage + signature for every scenario" {
    const allocator = std.testing.allocator;
    const bytes = try loadFixtureBytes(allocator);
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();

    const scenarios = parsed.value.object.get("scenarios").?.array;
    try std.testing.expect(scenarios.items.len > 0);

    for (scenarios.items) |sv| {
        const s = sv.object;
        const name = s.get("scenario").?.string;
        const tx_hex = s.get("unsignedTxHex").?.string;
        const input_index: usize = @intCast(s.get("inputIndex").?.integer);
        const subscript = s.get("prevScriptHex").?.string;
        const sats: i64 = s.get("prevValueSats").?.integer;
        const want_preimage = s.get("preimageHex").?.string;
        const want_digest = s.get("digestHex").?.string;
        const sig_hex = s.get("sigHex").?.string;
        const pubkey_hex = s.get("pubkeyHex").?.string;
        const sighash_flags: u32 = @intCast(s.get("sighashFlags").?.integer);

        // 1. Independently recompute the BIP-143 preimage under the scenario's
        //    OWN sighash flags.
        //
        //    R-206: this used to reject anything but 0x41, and every scenario
        //    in the fixture was ALL|FORKID — so the per-mode zeroing rules were
        //    implemented seven times and compared zero times.
        var result = try oppushtx.computeOpPushTxWithSigHash(
            allocator, tx_hex, input_index, subscript, sats, -1, sighash_flags);
        defer result.deinit(allocator);
        std.testing.expectEqualStrings(want_preimage, result.preimage_hex) catch |err| {
            std.debug.print("\n{s}: BIP-143 PREIMAGE DIVERGENCE from TS reference\n", .{name});
            return err;
        };

        // 2. sha256d(preimage) must equal the published digest.
        const preimage_bytes = try hexToBytes(allocator, result.preimage_hex);
        defer allocator.free(preimage_bytes);
        const digest = sha256d(preimage_bytes);
        const digest_hex = try envelope.bytesToHex(allocator, &digest);
        defer allocator.free(digest_hex);
        std.testing.expectEqualStrings(want_digest, digest_hex) catch |err| {
            std.debug.print("\n{s}: sighash digest divergence\n", .{name});
            return err;
        };

        // 3. The TS-produced signature must verify over this tier's digest.
        const sig_full = try hexToBytes(allocator, sig_hex);
        defer allocator.free(sig_full);
        const der = sig_full[0 .. sig_full.len - 1]; // strip sighash byte
        const pubkey = try hexToBytes(allocator, pubkey_hex);
        defer allocator.free(pubkey);
        const ok = envelope.verifyDigestDer(digest, der, pubkey);
        if (!ok) {
            std.debug.print("\n{s}: TS reference signature does not verify under this tier's digest\n", .{name});
            return error.SignatureVerifyFailed;
        }
    }
}
