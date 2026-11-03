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
    /// An address string that is not a decodable Base58Check P2PKH address (N-043).
    InvalidAddress,
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

/// Build a standard P2PKH locking script from a 40-char hex pubkey hash, a
/// 66-/130-char hex public key (hashed with HASH160), or a Base58Check P2PKH
/// address (checksum and version verified by bsvz).
pub fn buildP2PKHScript(allocator: std.mem.Allocator, address: []const u8) ![]u8 {
    // If 40-char hex, treat as raw pubkey hash
    if (address.len == 40 and isHex(address)) {
        var result = try allocator.alloc(u8, 50); // "76a914" + 40 + "88ac"
        @memcpy(result[0..6], "76a914");
        @memcpy(result[6..46], address);
        @memcpy(result[46..50], "88ac");
        return result;
    }

    // Compressed (33 bytes) or uncompressed (65 bytes) public key — hash it
    if ((address.len == 66 or address.len == 130) and isHex(address)) {
        var pub_key_buf: [65]u8 = undefined;
        const pub_key = std.fmt.hexToBytes(pub_key_buf[0 .. address.len / 2], address) catch unreachable; // isHex + even length
        const pkh = bsvz.crypto.hash.hash160(pub_key);
        var result = try allocator.alloc(u8, 50);
        @memcpy(result[0..6], "76a914");
        _ = bsvz.primitives.hex.encodeLower(&pkh.bytes, result[6..46]) catch unreachable; // 20 bytes -> 40 chars
        @memcpy(result[46..50], "88ac");
        return result;
    }

    // Decode Base58Check address
    // N-043: only a real allocation failure is OutOfMemory; every decode
    // failure (bad Base58, checksum, payload length, network prefix) is
    // InvalidAddress.
    const decoded = bsvz.compat.address.decodeP2pkh(allocator, address) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidAddress,
    };
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

// F-043: every SDK must accept the same inputs with the same result, using a
// real key (the secp256k1 generator G). buildP2PKHScript had no 66/130-char
// pubkey branch, so a pubkey fell through to the Base58 decoder and failed.
// PROVES: compressed / uncompressed pubkeys are hashed with HASH160 and the
// mainnet / testnet addresses of G decode to HASH160(G) (values match Go
// BuildP2PKHScript and TS buildP2PKHScript); the Genesis address with its last
// character flipped (bad checksum), a P2SH address and a non-Base58 character
// are rejected.
// DOES NOT PROVE: that a pubkey is a valid curve point (no SDK checks it), or
// the specific error name (the address branch maps every failure to one error).
test "buildP2PKHScript accepts G as pubkey, hash and address; rejects bad addresses (F-043)" {
    const allocator = std.testing.allocator;
    const want_g = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac";
    const inputs = [_][]const u8{
        "751e76e8199196d454941c45d1b3a323f1433bd6",
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r",
    };
    for (inputs) |in| {
        const got = try buildP2PKHScript(allocator, in);
        defer allocator.free(got);
        try std.testing.expectEqualStrings(want_g, got);
    }

    const unc = try buildP2PKHScript(allocator, "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" ++
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    defer allocator.free(unc);
    try std.testing.expectEqualStrings("76a91491b24bf9f5288532960ac687abb035127b1d28a588ac", unc);

    const genesis = try buildP2PKHScript(allocator, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    defer allocator.free(genesis);
    try std.testing.expectEqualStrings("76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac", genesis);

    const bad = [_][]const u8{
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf0a",
        "1Badx",
    };
    for (bad) |in| {
        if (buildP2PKHScript(allocator, in)) |script| {
            allocator.free(script);
            std.debug.print("buildP2PKHScript accepted {s}\n", .{in});
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

// N-043: an address that fails to decode used to surface as error.OutOfMemory
// (every decode failure was mapped to it). Proves: a bad checksum, a P2SH
// payload and a non-Base58 string each yield the distinct error.InvalidAddress.
// Does not prove: which underlying bsvz decode error occurred (all collapse to
// InvalidAddress); real allocation failure still reports OutOfMemory (not
// exercised here).
test "N-043 buildP2PKHScript reports a distinct InvalidAddress error" {
    const allocator = std.testing.allocator;
    const bad = [_][]const u8{
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", // bad checksum
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", // P2SH
        "1Badx", // not Base58Check
    };
    for (bad) |in| {
        try std.testing.expectError(error.InvalidAddress, buildP2PKHScript(allocator, in));
    }
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
