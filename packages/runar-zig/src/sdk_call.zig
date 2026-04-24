const std = @import("std");
const bsvz = @import("bsvz");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");
const deploy_mod = @import("sdk_deploy.zig");
const provider_mod = @import("sdk_provider.zig");

// ---------------------------------------------------------------------------
// Transaction construction for method invocation
// ---------------------------------------------------------------------------

pub const CallBuildOptions = struct {
    contract_outputs: []const types.ContractOutput = &.{},
};

pub const CallResult = struct {
    tx_hex: []u8,
    input_count: usize,
    change_amount: i64,

    pub fn deinit(self: *CallResult, allocator: std.mem.Allocator) void {
        allocator.free(self.tx_hex);
        self.* = .{ .tx_hex = &.{}, .input_count = 0, .change_amount = 0 };
    }
};

/// BuildCallTransaction builds a Transaction that spends a contract UTXO.
///
/// Input 0: the current contract UTXO with the given unlocking script.
/// Additional inputs: funding UTXOs if provided.
/// Output 0 (optional): new contract UTXO with updated locking script.
/// Last output (optional): change.
pub fn buildCallTransaction(
    allocator: std.mem.Allocator,
    current_utxo: types.UTXO,
    unlocking_script_hex: []const u8,
    new_locking_script_hex: []const u8,
    new_satoshis: i64,
    change_address: ?[]const u8,
    additional_utxos: []const types.UTXO,
    fee_rate_in: i64,
    opts: ?*const CallBuildOptions,
) !CallResult {
    // Determine contract outputs
    var contract_outputs: std.ArrayListUnmanaged(types.ContractOutput) = .empty;
    defer contract_outputs.deinit(allocator);

    if (opts != null and opts.?.contract_outputs.len > 0) {
        try contract_outputs.appendSlice(allocator, opts.?.contract_outputs);
    } else if (new_locking_script_hex.len > 0) {
        const sats = if (new_satoshis > 0) new_satoshis else current_utxo.satoshis;
        try contract_outputs.append(allocator, .{ .script = new_locking_script_hex, .satoshis = sats });
    }

    // Calculate total inputs
    var total_input: i64 = current_utxo.satoshis;
    for (additional_utxos) |u| total_input += u.satoshis;

    var contract_output_sats: i64 = 0;
    for (contract_outputs.items) |co| contract_output_sats += co.satoshis;

    // Estimate fee
    const input0_script_len = unlocking_script_hex.len / 2;
    const input0_size = 32 + 4 + varIntByteSize(input0_script_len) + input0_script_len + 4;
    const p2pkh_inputs_size = additional_utxos.len * 148;
    const inputs_size = input0_size + p2pkh_inputs_size;

    var outputs_size: usize = 0;
    for (contract_outputs.items) |co| {
        const script_len = co.script.len / 2;
        outputs_size += 8 + varIntByteSize(script_len) + script_len;
    }
    if (change_address != null) {
        outputs_size += 34; // P2PKH change
    }
    const estimated_size: i64 = @intCast(10 + inputs_size + outputs_size);
    const rate: i64 = if (fee_rate_in > 0) fee_rate_in else 100;
    const fee = @divTrunc(estimated_size * rate + 999, 1000);

    const change = total_input - contract_output_sats - fee;

    // Build transaction using bsvz Builder
    var builder = bsvz.transaction.Builder.init(allocator);
    defer builder.deinit();

    // Input 0: contract UTXO with unlocking script
    {
        const txid_chain = bsvz.primitives.chainhash.Hash.fromHex(current_utxo.txid) catch return error.OutOfMemory;
        const txid_hash = bsvz.crypto.Hash256{ .bytes = txid_chain.bytes };
        const unlock_bytes = try bsvz.primitives.hex.decode(allocator, unlocking_script_hex);
        defer allocator.free(unlock_bytes);
        const utxo_script_bytes = try bsvz.primitives.hex.decode(allocator, current_utxo.script);
        defer allocator.free(utxo_script_bytes);

        try builder.addInput(.{
            .previous_outpoint = .{
                .txid = txid_hash,
                .index = @intCast(current_utxo.output_index),
            },
            .unlocking_script = bsvz.script.Script.init(unlock_bytes),
            .sequence = 0xffffffff,
            .source_output = .{
                .satoshis = current_utxo.satoshis,
                .locking_script = bsvz.script.Script.init(utxo_script_bytes),
            },
        });
    }

    // P2PKH funding inputs (unsigned — empty script)
    for (additional_utxos) |utxo| {
        const txid_chain = bsvz.primitives.chainhash.Hash.fromHex(utxo.txid) catch return error.OutOfMemory;
        const txid_hash = bsvz.crypto.Hash256{ .bytes = txid_chain.bytes };
        const utxo_script_bytes = try bsvz.primitives.hex.decode(allocator, utxo.script);
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

    // Contract outputs
    for (contract_outputs.items) |co| {
        const co_bytes = try bsvz.primitives.hex.decode(allocator, co.script);
        defer allocator.free(co_bytes);
        try builder.addOutput(.{
            .satoshis = co.satoshis,
            .locking_script = bsvz.script.Script.init(co_bytes),
        });
    }

    // Change output
    if (change > 0) {
        if (change_address) |addr| {
            try builder.payToAddress(addr, change);
        }
    }

    // Build and serialize
    var tx = try builder.build();
    defer tx.deinit(allocator);

    const serialized = try tx.serialize(allocator);
    defer allocator.free(serialized);

    const hex_buf = try allocator.alloc(u8, serialized.len * 2);
    _ = try bsvz.primitives.hex.encodeLower(serialized, hex_buf);

    return .{
        .tx_hex = hex_buf,
        .input_count = 1 + additional_utxos.len,
        .change_amount = if (change > 0) change else 0,
    };
}

fn varIntByteSize(n: usize) usize {
    if (n < 0xfd) return 1;
    if (n <= 0xffff) return 3;
    if (n <= 0xffffffff) return 5;
    return 9;
}

/// EstimateCallFee estimates the fee for a call transaction. Mirrors the TS
/// `estimateCallFee` semantics: accounts for the contract spending input
/// (including its unlocking script), any P2PKH funding inputs (148 bytes each),
/// each contract continuation output, and an optional P2PKH change output.
/// `fee_rate_in` is satoshis per KB (0 defaults to 100).
pub fn estimateCallFee(
    unlocking_script_byte_len: usize,
    continuation_script_byte_lens: []const usize,
    num_additional_utxos: usize,
    has_change: bool,
    fee_rate_in: i64,
) i64 {
    const tx_overhead: usize = 10;
    const input0_size: usize = 32 + 4 + varIntByteSize(unlocking_script_byte_len) + unlocking_script_byte_len + 4;
    const p2pkh_inputs_size: usize = num_additional_utxos * 148;
    var outputs_size: usize = 0;
    for (continuation_script_byte_lens) |n| {
        outputs_size += 8 + varIntByteSize(n) + n;
    }
    if (has_change) outputs_size += 34;
    const total: i64 = @intCast(tx_overhead + input0_size + p2pkh_inputs_size + outputs_size);
    const rate: i64 = if (fee_rate_in > 0) fee_rate_in else 100;
    return @divTrunc(total * rate + 999, 1000);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "buildCallTransaction with stateless contract" {
    const allocator = std.testing.allocator;

    const contract_utxo = types.UTXO{
        .txid = "aa" ** 32,
        .output_index = 0,
        .satoshis = 1000,
        .script = "5100", // OP_1 OP_0
    };

    // Simple unlocking script: OP_1
    var result = try buildCallTransaction(
        allocator,
        contract_utxo,
        "51", // unlocking script: OP_1
        "", // no new locking script (stateless)
        0,
        null,
        &.{}, // no additional utxos
        100,
        null,
    );
    defer result.deinit(allocator);

    try std.testing.expect(result.tx_hex.len > 0);
    try std.testing.expectEqual(@as(usize, 1), result.input_count);
}

test "estimateCallFee mirrors TS semantics" {
    // No continuation outputs, no change, no extra inputs
    const fee0 = estimateCallFee(1, &.{}, 0, false, 100);
    try std.testing.expect(fee0 > 0);

    // Adding an extra P2PKH input raises the fee
    const fee1 = estimateCallFee(1, &.{}, 1, false, 100);
    try std.testing.expect(fee1 > fee0);

    // Adding a continuation output raises the fee
    const fee2 = estimateCallFee(1, &.{100}, 0, false, 100);
    try std.testing.expect(fee2 > fee0);

    // Adding change output raises the fee
    const fee3 = estimateCallFee(1, &.{}, 0, true, 100);
    try std.testing.expect(fee3 > fee0);

    // Default fee rate (0 → 100)
    const fee4 = estimateCallFee(1, &.{}, 0, false, 0);
    try std.testing.expectEqual(fee0, fee4);
}

// E2E: deploy → broadcast via MockProvider → consume deploy output in a call tx.
// Uses a trivial stateful-like locking script (OP_1) and a trivial unlock (OP_1)
// to exercise the plumbing end-to-end without needing full compiler output here.
test "deploy->broadcast->call lifecycle via MockProvider" {
    const allocator = std.testing.allocator;

    // Set up MockProvider with a funding UTXO for "deployer" address.
    var mock = provider_mod.MockProvider.init(allocator, "testnet");
    defer mock.deinit();

    const fund_utxo = types.UTXO{
        .txid = "bb" ** 32,
        .output_index = 0,
        .satoshis = 100_000,
        .script = "76a914" ++ ("11" ** 20) ++ "88ac",
    };
    try mock.addUtxo("deployer", fund_utxo);

    var prov = mock.provider();
    const utxos = try prov.getUtxos(allocator, "deployer");
    defer {
        for (utxos) |*u| {
            var mu = u.*;
            mu.deinit(allocator);
        }
        allocator.free(utxos);
    }
    try std.testing.expect(utxos.len >= 1);

    // Build deploy tx that creates a contract output with locking script "51" (OP_1).
    const contract_script_hex = "51";
    var deploy_res = try deploy_mod.buildDeployTransaction(
        allocator,
        contract_script_hex,
        utxos,
        1000,
        "1BitcoinEaterAddressDontSendf59kuE",
        100,
    );
    defer deploy_res.deinit(allocator);

    try std.testing.expect(deploy_res.tx_hex.len > 0);
    try std.testing.expectEqual(@as(usize, 1), deploy_res.input_count);

    // "Broadcast" via MockProvider — returns a fake txid and stores the raw tx.
    const deploy_txid = try prov.broadcast(allocator, deploy_res.tx_hex);
    defer allocator.free(deploy_txid);
    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);

    // Provider should recall the raw tx by txid.
    const recalled = try prov.getRawTransaction(allocator, deploy_txid);
    defer allocator.free(recalled);
    try std.testing.expectEqualStrings(deploy_res.tx_hex, recalled);

    // Build a call tx that consumes the deploy output (index 0).
    const deploy_outpoint = types.UTXO{
        .txid = deploy_txid,
        .output_index = 0,
        .satoshis = 1000,
        .script = contract_script_hex,
    };

    var call_res = try buildCallTransaction(
        allocator,
        deploy_outpoint,
        "51", // unlocking: OP_1
        "", // stateless call — no continuation
        0,
        null,
        &.{},
        100,
        null,
    );
    defer call_res.deinit(allocator);

    try std.testing.expect(call_res.tx_hex.len > 0);
    try std.testing.expectEqual(@as(usize, 1), call_res.input_count);

    // The call tx must reference the deploy txid in its first input.
    // Raw tx layout: version(4) | input_count varint | input0{ prev_txid(32 LE) prev_idx(4) script_varint script sequence(4) } ...
    // We check the hex string contains the prev txid bytes in little-endian.
    // deploy_txid is display order (big-endian); the serialized tx has it LE-reversed.
    var le_txid_buf: [64]u8 = undefined;
    for (0..32) |i| {
        le_txid_buf[i * 2] = deploy_txid[(31 - i) * 2];
        le_txid_buf[i * 2 + 1] = deploy_txid[(31 - i) * 2 + 1];
    }
    const le_txid: []const u8 = le_txid_buf[0..];
    try std.testing.expect(std.mem.indexOf(u8, call_res.tx_hex, le_txid) != null);

    // And it should contain the OP_1 unlocking script push (after the script-len varint 0x01).
    try std.testing.expect(std.mem.indexOf(u8, call_res.tx_hex, "0151") != null);
}
