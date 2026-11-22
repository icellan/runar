//! Testing-gap remediation Phase A5 (Zig tier).
//!
//! The Zig tier ships NO Bitcoin Script VM — the `bsvz` library's
//! `script/engine.zig` does not compile under the repo's Zig 0.16 toolchain
//! (`unreachable else prong` at engine.zig:1172), `zig-pkg/` is a gitignored
//! fetch cache rather than an in-repo source tree, and project policy forbids
//! hand-rolling an interpreter (root CLAUDE.md, "Off-chain Script VM").
//!
//! So these tests do NOT claim script-level validation. They pin the checks
//! that ARE genuinely available at the broadcast boundary and that a real node
//! would also apply:
//!
//!   1. STRUCTURAL      — the payload must actually parse as a transaction.
//!   2. NON-VACUITY     — at least one spent outpoint must be known to the
//!                        provider, so the gate can never pass by checking
//!                        nothing.
//!   3. VALUE CONSERVE  — when every input's outpoint is known, the outputs
//!                        must not exceed the inputs.
//!   4. SCRIPT-SIZE     — output scripts stay under MAX_SCRIPT_BYTES.
//!
//! Signature/covenant validity in this tier is proven VERTICALLY instead:
//! absolute-hex pins against the other tiers' goldens, plus the on-chain
//! integration spends in integration/zig. See README, "How fund-path tests
//! fail closed in the Zig tier".

const std = @import("std");
const provider_mod = @import("sdk_provider.zig");

const MockProvider = provider_mod.MockProvider;
const ProviderError = provider_mod.ProviderError;

const PREV_A = "aa" ** 32;
const PREV_B = "bb" ** 32;

/// Serialize a one-input transaction spending `prev_txid:0` with one OP_TRUE
/// output worth `out_sats`. `prev_txid` is a DISPLAY-order (big-endian) txid;
/// the wire format carries it byte-reversed.
fn oneInputTx(allocator: std.mem.Allocator, prev_txid: []const u8, out_sats: u64) ![]u8 {
    std.debug.assert(prev_txid.len == 64);
    var wire_txid: [64]u8 = undefined;
    var b: usize = 0;
    while (b < 32) : (b += 1) {
        const src = prev_txid[(31 - b) * 2 ..][0..2];
        @memcpy(wire_txid[b * 2 ..][0..2], src);
    }

    var sats_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &sats_le, out_sats, .little);
    var sats_hex: [16]u8 = undefined;
    for (sats_le, 0..) |sb, i| {
        _ = std.fmt.bufPrint(sats_hex[i * 2 ..][0..2], "{x:0>2}", .{sb}) catch unreachable;
    }
    return std.fmt.allocPrint(
        allocator,
        "01000000" ++ "01" ++ "{s}" ++ "00000000" ++ "00" ++ "ffffffff" ++ "01" ++ "{s}" ++ "0151" ++ "00000000",
        .{ wire_txid, sats_hex },
    );
}

test "default MockProvider accepts a well-formed, value-conserving spend of a known outpoint" {
    const allocator = std.testing.allocator;
    var mock = MockProvider.init(allocator, "testnet");
    defer mock.deinit();
    try mock.addKnownOutpoint(PREV_A, 0, "51", 10_000);

    const raw = try oneInputTx(allocator, PREV_A, 9_000);
    defer allocator.free(raw);

    var prov = mock.provider();
    const txid = try prov.broadcast(allocator, raw);
    defer allocator.free(txid);

    try std.testing.expectEqual(@as(usize, 64), txid.len);
    try std.testing.expectEqual(@as(usize, 1), mock.lastValidatedInputCount());

    const report = mock.lastValidationReport();
    // The tier makes NO script-validity claim. If a Zig ScriptVM ever lands,
    // this expectation should change deliberately, not by accident.
    try std.testing.expectEqual(@as(usize, 0), report.scripts_executed);
    try std.testing.expectEqual(@as(usize, 1), report.total_inputs);
    try std.testing.expect(report.value_conserved);
}

test "default MockProvider REJECTS a payload that is not a parseable transaction" {
    const allocator = std.testing.allocator;
    var mock = MockProvider.init(allocator, "testnet");
    defer mock.deinit();

    var prov = mock.provider();
    try std.testing.expectError(ProviderError.BroadcastRejected, prov.broadcast(allocator, "0100000000"));
    try std.testing.expectEqual(provider_mod.RejectionReason.not_a_transaction, mock.lastRejection());
}

test "default MockProvider REJECTS a transaction whose outputs exceed its known inputs" {
    const allocator = std.testing.allocator;
    var mock = MockProvider.init(allocator, "testnet");
    defer mock.deinit();
    try mock.addKnownOutpoint(PREV_A, 0, "51", 1_000);

    const raw = try oneInputTx(allocator, PREV_A, 5_000);
    defer allocator.free(raw);

    var prov = mock.provider();
    try std.testing.expectError(ProviderError.BroadcastRejected, prov.broadcast(allocator, raw));
    try std.testing.expectEqual(provider_mod.RejectionReason.underfunded, mock.lastRejection());
}

test "default MockProvider REJECTS a transaction none of whose inputs it knows (no vacuous pass)" {
    const allocator = std.testing.allocator;
    var mock = MockProvider.init(allocator, "testnet");
    defer mock.deinit();

    const raw = try oneInputTx(allocator, PREV_B, 1_000);
    defer allocator.free(raw);

    var prov = mock.provider();
    try std.testing.expectError(ProviderError.BroadcastRejected, prov.broadcast(allocator, raw));
    try std.testing.expectEqual(provider_mod.RejectionReason.nothing_checked, mock.lastRejection());
    // And the report proves the gate really had nothing to check.
    try std.testing.expectEqual(@as(usize, 0), mock.lastValidationReport().known_inputs);
    try std.testing.expectEqual(@as(usize, 1), mock.lastValidationReport().total_inputs);
}

test "a broadcast registers its own outputs so a chained spend is checkable" {
    const allocator = std.testing.allocator;
    var mock = MockProvider.init(allocator, "testnet");
    defer mock.deinit();
    try mock.addKnownOutpoint(PREV_A, 0, "51", 10_000);

    const raw1 = try oneInputTx(allocator, PREV_A, 9_000);
    defer allocator.free(raw1);
    var prov = mock.provider();
    const txid1 = try prov.broadcast(allocator, raw1);
    defer allocator.free(txid1);

    const raw2 = try oneInputTx(allocator, txid1, 8_000);
    defer allocator.free(raw2);
    const txid2 = try prov.broadcast(allocator, raw2);
    defer allocator.free(txid2);

    try std.testing.expectEqual(@as(usize, 64), txid2.len);
    try std.testing.expectEqual(@as(usize, 1), mock.lastValidatedInputCount());
}

test "always-ack MockProvider skips every check" {
    const allocator = std.testing.allocator;
    var mock = MockProvider.initAlwaysAck(allocator, "testnet");
    defer mock.deinit();

    var prov = mock.provider();
    const txid = try prov.broadcast(allocator, "0100000000");
    defer allocator.free(txid);
    try std.testing.expectEqual(@as(usize, 64), txid.len);
}

test "disable/enableBroadcastValidation toggles the gate" {
    const allocator = std.testing.allocator;
    var mock = MockProvider.init(allocator, "testnet");
    defer mock.deinit();
    var prov = mock.provider();

    try std.testing.expectError(ProviderError.BroadcastRejected, prov.broadcast(allocator, "0100000000"));

    mock.disableBroadcastValidation();
    const txid = try prov.broadcast(allocator, "0100000000");
    defer allocator.free(txid);
    try std.testing.expectEqual(@as(usize, 64), txid.len);

    mock.enableBroadcastValidation(true);
    try std.testing.expectError(ProviderError.BroadcastRejected, prov.broadcast(allocator, "0100000000"));
}

// ---------------------------------------------------------------------------
// Double spends. A second, DIFFERENT transaction spending an outpoint an
// earlier accepted broadcast already spent was acked; a node refuses it, so
// acking it lets a test "succeed" at a spend the network rejects.
// ---------------------------------------------------------------------------

/// Deploy: broadcast a tx creating an OP_TRUE output; returns its txid.
fn deployForDoubleSpend(allocator: std.mem.Allocator, mock: *MockProvider) ![]u8 {
    try mock.addKnownOutpoint(PREV_A, 0, "51", 10_000);
    const raw = try oneInputTx(allocator, PREV_A, 9_000);
    defer allocator.free(raw);
    var prov = mock.provider();
    return prov.broadcast(allocator, raw);
}

test "MockProvider REFUSES a different transaction spending an already-spent outpoint" {
    const allocator = std.testing.allocator;
    var mock = MockProvider.init(allocator, "testnet");
    defer mock.deinit();
    const d = try deployForDoubleSpend(allocator, &mock);
    defer allocator.free(d);
    var prov = mock.provider();

    const first = try oneInputTx(allocator, d, 8_000);
    defer allocator.free(first);
    const t1 = try prov.broadcast(allocator, first);
    defer allocator.free(t1);

    const conflicting = try oneInputTx(allocator, d, 7_000);
    defer allocator.free(conflicting);
    const before = mock.broadcasted_txs.items.len;
    try std.testing.expectError(ProviderError.BroadcastRejected, prov.broadcast(allocator, conflicting));
    try std.testing.expectEqual(provider_mod.RejectionReason.double_spend, mock.lastRejection());
    try std.testing.expectEqual(before, mock.broadcasted_txs.items.len);
}

test "MockProvider REFUSES a transaction spending one outpoint twice" {
    const allocator = std.testing.allocator;
    var mock = MockProvider.init(allocator, "testnet");
    defer mock.deinit();
    try mock.addKnownOutpoint(PREV_A, 0, "51", 10_000);
    const in = PREV_A ++ "00000000" ++ "00" ++ "ffffffff";
    const raw = "01000000" ++ "02" ++ in ++ in ++ "01" ++ "2823000000000000" ++ "0151" ++ "00000000";
    var prov = mock.provider();
    try std.testing.expectError(ProviderError.BroadcastRejected, prov.broadcast(allocator, raw));
    try std.testing.expectEqual(provider_mod.RejectionReason.double_spend, mock.lastRejection());
}

test "a refused broadcast does not mark its inputs spent" {
    const allocator = std.testing.allocator;
    var mock = MockProvider.init(allocator, "testnet");
    defer mock.deinit();
    const d = try deployForDoubleSpend(allocator, &mock);
    defer allocator.free(d);
    var prov = mock.provider();

    const over = try oneInputTx(allocator, d, 50_000);
    defer allocator.free(over);
    try std.testing.expectError(ProviderError.BroadcastRejected, prov.broadcast(allocator, over));
    const ok = try oneInputTx(allocator, d, 8_000);
    defer allocator.free(ok);
    const t = try prov.broadcast(allocator, ok);
    allocator.free(t);
}

test "re-broadcasting the identical transaction is not a double spend" {
    const allocator = std.testing.allocator;
    var mock = MockProvider.init(allocator, "testnet");
    defer mock.deinit();
    const d = try deployForDoubleSpend(allocator, &mock);
    defer allocator.free(d);
    var prov = mock.provider();

    const tx = try oneInputTx(allocator, d, 8_000);
    defer allocator.free(tx);
    const a = try prov.broadcast(allocator, tx);
    defer allocator.free(a);
    const before = mock.broadcasted_txs.items.len;
    const b = try prov.broadcast(allocator, tx);
    defer allocator.free(b);
    try std.testing.expectEqualStrings(a, b);
    try std.testing.expectEqual(before, mock.broadcasted_txs.items.len);
}

test "getUtxos no longer lists an outpoint an accepted broadcast spent" {
    const allocator = std.testing.allocator;
    var mock = MockProvider.init(allocator, "testnet");
    defer mock.deinit();
    try mock.addUtxo("funder", .{ .txid = PREV_A, .output_index = 0, .satoshis = 10_000, .script = "51" });
    try mock.addUtxo("funder", .{ .txid = PREV_A, .output_index = 1, .satoshis = 5_000, .script = "51" });
    const d = try deployForDoubleSpend(allocator, &mock);
    allocator.free(d);

    var prov = mock.provider();
    const utxos = try prov.getUtxos(allocator, "funder");
    defer {
        for (utxos) |*u| {
            var mu = u.*;
            mu.deinit(allocator);
        }
        allocator.free(utxos);
    }
    try std.testing.expectEqual(@as(usize, 1), utxos.len);
    try std.testing.expectEqual(@as(i32, 1), utxos[0].output_index);
}
