const std = @import("std");
const bsvz = @import("bsvz");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const state_mod = @import("sdk_state.zig");

// ---------------------------------------------------------------------------
// Transaction construction for contract deployment
// ---------------------------------------------------------------------------

// P2PKH sizes for fee estimation
const p2pkh_input_size: usize = 148; // prevTxid(32) + index(4) + scriptSig(~107) + sequence(4) + varint(1)
const p2pkh_output_size: usize = 34; // satoshis(8) + varint(1) + P2PKH script(25)
const tx_overhead: usize = 10; // version(4) + input varint(1) + output varint(1) + locktime(4)

pub const DeployError = error{
    InsufficientFunds,
    NoUtxos,
    InvalidScript,
    OutOfMemory,
    BuildFailed,
};

/// Result of building a deploy transaction.
pub const DeployResult = struct {
    tx_hex: []u8,
    input_count: usize,

    pub fn deinit(self: *DeployResult, allocator: std.mem.Allocator) void {
        allocator.free(self.tx_hex);
        self.* = .{ .tx_hex = &.{}, .input_count = 0 };
    }
};

/// BuildDeployTransaction builds an unsigned Transaction that creates an output
/// with the given locking script. Returns the serialized tx hex and input count.
pub fn buildDeployTransaction(
    allocator: std.mem.Allocator,
    locking_script_hex: []const u8,
    utxos: []const types.UTXO,
    satoshis: i64,
    change_address: ?[]const u8,
    fee_rate: i64,
) !DeployResult {
    if (utxos.len == 0) return DeployError.NoUtxos;

    var total_input: i64 = 0;
    for (utxos) |u| total_input += u.satoshis;

    const fee = estimateDeployFee(utxos.len, locking_script_hex.len / 2, fee_rate, 0, 0);
    const change = total_input - satoshis - fee;

    if (change < 0) return DeployError.InsufficientFunds;

    // Decode locking script
    const ls_bytes = bsvz.primitives.hex.decode(allocator, locking_script_hex) catch return DeployError.InvalidScript;
    defer allocator.free(ls_bytes);

    var builder = bsvz.transaction.Builder.init(allocator);
    defer builder.deinit();

    // Add inputs (unsigned — empty unlocking script)
    for (utxos) |utxo| {
        // txid from RPC is in display order (reversed); Hash.fromHex reverses to internal order
        const txid_chain = bsvz.primitives.chainhash.Hash.fromHex(utxo.txid) catch return DeployError.InvalidScript;
        const txid_hash = bsvz.crypto.Hash256{ .bytes = txid_chain.bytes };

        // Decode the UTXO locking script for source_output
        const utxo_script_bytes = bsvz.primitives.hex.decode(allocator, utxo.script) catch return DeployError.InvalidScript;
        defer allocator.free(utxo_script_bytes);

        try builder.addInput(.{
            .previous_outpoint = .{
                .txid = txid_hash,
                .index = @intCast(utxo.output_index),
            },
            .unlocking_script = .empty(),
            .sequence = 0xffffffff,
            .source_output = .{
                .satoshis = utxo.satoshis,
                .locking_script = bsvz.script.Script.init(utxo_script_bytes),
            },
        });
    }

    // Output 0: contract locking script
    try builder.addOutput(.{
        .satoshis = satoshis,
        .locking_script = bsvz.script.Script.init(ls_bytes),
    });

    // Output 1: change (if any)
    if (change > 0) {
        if (change_address) |addr| {
            // `payToAddress` only accepts Base58Check. The SDK also uses a bare
            // 40-hex pubkey hash as an "address" internally — WalletSigner's
            // getAddress returns exactly that — and handing one to payToAddress
            // fails with InvalidCharacter, which is why every wallet-funded
            // deploy with a change output died before broadcast. buildP2PKHScript
            // already accepts both spellings; route the hex form through it.
            if (addr.len == 40 and isHex(addr)) {
                const change_script_hex = try buildP2PKHScript(allocator, addr);
                defer allocator.free(change_script_hex);
                const change_script = bsvz.primitives.hex.decode(allocator, change_script_hex) catch return DeployError.InvalidScript;
                defer allocator.free(change_script);
                try builder.addOutput(.{
                    .satoshis = change,
                    .locking_script = bsvz.script.Script.init(change_script),
                });
            } else {
                try builder.payToAddress(addr, change);
            }
        }
    }

    // Build and serialize
    var tx = try builder.build();
    defer tx.deinit(allocator);

    const serialized = try tx.serialize(allocator);
    defer allocator.free(serialized);

    // Encode to hex
    const hex_buf = try allocator.alloc(u8, serialized.len * 2);
    _ = bsvz.primitives.hex.encodeLower(serialized, hex_buf) catch {
        allocator.free(hex_buf);
        return DeployError.BuildFailed;
    };

    return .{
        .tx_hex = hex_buf,
        .input_count = utxos.len,
    };
}

/// SelectUtxos selects the minimum set of UTXOs needed to fund a deployment,
/// using a largest-first strategy.
pub fn selectUtxos(
    allocator: std.mem.Allocator,
    utxos: []const types.UTXO,
    target_satoshis: i64,
    locking_script_byte_len: usize,
    fee_rate: i64,
    extra_input_bytes: i64,
    extra_output_bytes: i64,
) ![]types.UTXO {
    // Sort by satoshis descending
    const indices = try allocator.alloc(usize, utxos.len);
    defer allocator.free(indices);
    for (0..utxos.len) |i| indices[i] = i;
    std.mem.sort(usize, indices, utxos, struct {
        fn lessThan(ctx: []const types.UTXO, a: usize, b: usize) bool {
            return ctx[a].satoshis > ctx[b].satoshis;
        }
    }.lessThan);

    var selected: std.ArrayListUnmanaged(types.UTXO) = .empty;
    errdefer {
        for (selected.items) |*u| u.deinit(allocator);
        selected.deinit(allocator);
    }

    var total: i64 = 0;
    for (indices) |idx| {
        try selected.append(allocator, try utxos[idx].clone(allocator));
        total += utxos[idx].satoshis;

        const fee = estimateDeployFee(selected.items.len, locking_script_byte_len, fee_rate, extra_input_bytes, extra_output_bytes);
        if (total >= target_satoshis + fee) {
            return selected.toOwnedSlice(allocator);
        }
    }

    return selected.toOwnedSlice(allocator);
}

/// EstimateDeployFee estimates the fee for a deploy transaction.
/// Fee rate is in satoshis per KB (0 defaults to 100).
///
/// `extra_input_bytes` (finding C2) is the serialized byte size of any NON-P2PKH
/// inputs this fee must also cover — e.g. a contract/covenant input spent in the
/// same tx (tens of KB for a MERGE that embeds both parent txs). `extra_output_bytes`
/// (finding C15) is the framing (8 + varint + scriptLen) of every output BEYOND the
/// single `locking_script_byte_len` one counted here — additional multi-outputs, raw
/// outputs (finding G1), and data outputs. Both default to 0, so deploy and
/// funding-only selection are byte-for-byte unchanged; `prepareCall` passes real
/// values so funding coin-selection is not under-provisioned on the call path.
pub fn estimateDeployFee(
    num_inputs: usize,
    locking_script_byte_len: usize,
    fee_rate_in: i64,
    extra_input_bytes: i64,
    extra_output_bytes: i64,
) i64 {
    const rate: i64 = if (fee_rate_in > 0) fee_rate_in else 100;
    const inputs_size: i64 = @as(i64, @intCast(num_inputs * p2pkh_input_size)) + extra_input_bytes;
    const contract_output_size: i64 = @intCast(8 + varIntByteSize(locking_script_byte_len) + locking_script_byte_len);
    const change_output_size: i64 = @intCast(p2pkh_output_size);
    const tx_size: i64 = @intCast(tx_overhead);
    const total = tx_size + inputs_size + contract_output_size + extra_output_bytes + change_output_size;
    return @divTrunc(total * rate + 999, 1000);
}

/// Build a standard P2PKH locking script from a hex pubkey hash or address.
pub fn buildP2PKHScript(allocator: std.mem.Allocator, address: []const u8) ![]u8 {
    // If 40-char hex, treat as raw pubkey hash
    if (address.len == 40 and isHex(address)) {
        var result = try allocator.alloc(u8, 50); // "76a914" + 40 + "88ac"
        @memcpy(result[0..6], "76a914");
        @memcpy(result[6..46], address);
        @memcpy(result[46..50], "88ac");
        return result;
    }

    // Decode Base58Check address
    const decoded = bsvz.compat.address.decodeP2pkh(allocator, address) catch return error.OutOfMemory;
    const ls = decoded.lockingScript();
    const hex_buf = try allocator.alloc(u8, ls.len * 2);
    _ = bsvz.primitives.hex.encodeLower(&ls, hex_buf) catch {
        allocator.free(hex_buf);
        return error.OutOfMemory;
    };
    return hex_buf;
}

fn isHex(s: []const u8) bool {
    for (s) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F')))
            return false;
    }
    return true;
}

fn varIntByteSize(n: usize) usize {
    if (n < 0xfd) return 1;
    if (n <= 0xffff) return 3;
    if (n <= 0xffffffff) return 5;
    return 9;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "estimateDeployFee basic calculation" {
    const fee = estimateDeployFee(1, 50, 100, 0, 0);
    // 10 + 148 + (8+1+50) + 34 = 251 bytes; 251 * 100 / 1000 = 26 (rounded up)
    try std.testing.expect(fee > 0);
    try std.testing.expect(fee < 100);
}

test "buildP2PKHScript from hex pubkey hash" {
    const allocator = std.testing.allocator;
    const result = try buildP2PKHScript(allocator, "0000000000000000000000000000000000000000");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("76a914000000000000000000000000000000000000000088ac", result);
}

test "selectUtxos selects largest first" {
    const allocator = std.testing.allocator;
    const utxos = &[_]types.UTXO{
        .{ .txid = "aa" ** 32, .output_index = 0, .satoshis = 100, .script = "5100" },
        .{ .txid = "bb" ** 32, .output_index = 0, .satoshis = 500, .script = "5100" },
        .{ .txid = "cc" ** 32, .output_index = 0, .satoshis = 200, .script = "5100" },
    };

    const selected = try selectUtxos(allocator, utxos, 400, 25, 100, 0, 0);
    defer {
        for (selected) |*u| u.deinit(allocator);
        allocator.free(selected);
    }

    // 500 sat UTXO should be selected first; check we get at least the big one
    try std.testing.expect(selected.len >= 1);
    try std.testing.expectEqual(@as(i64, 500), selected[0].satoshis);
}

// Findings C2 + C15: the call-path funding estimator must size against the
// contract/covenant INPUT unlock bytes (C2, extra_input_bytes) and against ALL
// outputs beyond the single continuation the deploy estimator counts (C15,
// extra_output_bytes). Both are trailing params defaulting to 0 for deploy.
// Mirrors packages/runar-sdk/src/__tests__/c15-funding-output-sizing.test.ts.
test "estimateDeployFee adds extra input/output bytes to the fee (C2/C15)" {
    // 1000 sat/KB makes each extra byte cost exactly 1 sat, so the delta is
    // the extra byte count with no rounding slack.
    const base = estimateDeployFee(1, 100, 1000, 0, 0);
    const with_out = estimateDeployFee(1, 100, 1000, 0, 5000); // +5000 output bytes
    const with_in = estimateDeployFee(1, 100, 1000, 5000, 0); // +5000 input bytes
    try std.testing.expect(with_out > base);
    try std.testing.expect(with_in > base);
    try std.testing.expectEqual(@as(i64, 5000), with_out - base);
    try std.testing.expectEqual(@as(i64, 5000), with_in - base);
}

test "selectUtxos picks more coins when extra output bytes tip the fee (C15)" {
    const allocator = std.testing.allocator;
    const utxos = &[_]types.UTXO{
        .{ .txid = "aa" ** 32, .output_index = 0, .satoshis = 10_000, .script = "5100" },
        .{ .txid = "bb" ** 32, .output_index = 0, .satoshis = 10_000, .script = "5100" },
    };

    // Target 9_000 at 1000 sat/KB. With no extra output bytes a single 10_000
    // coin covers 9_000 + a ~226-sat fee → 1 coin. Adding 2_000 output bytes
    // (2_000 sats of fee) pushes the requirement past 10_000 → 2 coins needed.
    const few = try selectUtxos(allocator, utxos, 9_000, 25, 1000, 0, 0);
    defer {
        for (few) |*u| u.deinit(allocator);
        allocator.free(few);
    }
    const more = try selectUtxos(allocator, utxos, 9_000, 25, 1000, 0, 2_000);
    defer {
        for (more) |*u| u.deinit(allocator);
        allocator.free(more);
    }
    try std.testing.expectEqual(@as(usize, 1), few.len);
    try std.testing.expectEqual(@as(usize, 2), more.len);
}
