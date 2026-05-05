const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

// ---------------------------------------------------------------------------
// BSV-21 token integration tests — port of integration/ts/bsv21-token.test.ts.
//
// BSV-21 (v2) tokens use deploy+mint as a single operation. The token ID is
// the txid_vout of the inscription output. The locking script is identical
// to P2PKH; the inscription envelope encodes the protocol-level metadata.
//
// Mirrors integration/go/bsv21_token_test.go.
//
// NOTE: The Zig SDK's `RunarContract` does not currently expose a `fromTxId`
// reconnection helper directly (only the generated SDK module emits one),
// so the round-trip-via-fromTxId case from the TS reference is omitted here.
// ---------------------------------------------------------------------------

const SOURCE_PATH = "examples/zig/bsv21-token/BSV21Token.runar.zig";

/// Hex-decode a string into UTF-8 bytes (caller frees).
fn hexDecode(allocator: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    if (hex_str.len % 2 != 0) return error.InvalidHex;
    const out = try allocator.alloc(u8, hex_str.len / 2);
    errdefer allocator.free(out);
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        const hi = std.fmt.charToDigit(hex_str[i * 2], 16) catch return error.InvalidHex;
        const lo = std.fmt.charToDigit(hex_str[i * 2 + 1], 16) catch return error.InvalidHex;
        out[i] = (hi << 4) | lo;
    }
    return out;
}

test "BSV21Token_Compile" {
    const allocator = std.testing.allocator;

    var artifact = try compile.compileContract(allocator, SOURCE_PATH);
    defer artifact.deinit();

    try std.testing.expectEqualStrings("BSV21Token", artifact.contract_name);
    try std.testing.expect(artifact.script.len > 0);
    std.log.info("BSV21Token compiled: {d} bytes", .{artifact.script.len / 2});
}

test "BSV21Token_DeployMintInscription" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = try compile.compileContract(allocator, SOURCE_PATH);
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();

    const pkh_hex = try owner.pubKeyHashHex(allocator);
    defer allocator.free(pkh_hex);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pkh_hex },
    });
    defer contract.deinit();

    var insc = try runar.bsv21DeployMint(allocator, "1000000", "18", "RNR", null);
    defer insc.deinit(allocator);
    try contract.withInscription(insc);

    const fund_txid = try helpers.fundWallet(allocator, &owner, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try owner.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 1 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("BSV21Token deploy+mint TX: {s}", .{deploy_txid});

    // Token ID is txid_vout (vout = 0 for the inscription output).
    var rpc_for_tx = helpers.RPCProvider.init(allocator);
    const tx = try rpc_for_tx.provider().getTransaction(allocator, deploy_txid);
    defer {
        for (tx.outputs) |*o| {
            if (o.script.len > 0) allocator.free(o.script);
        }
        if (tx.outputs.len > 0) allocator.free(tx.outputs);
        if (tx.txid.len > 0) allocator.free(tx.txid);
        if (tx.raw.len > 0) allocator.free(tx.raw);
    }

    try std.testing.expect(tx.outputs.len > 0);
    const maybe_parsed = try runar.parseInscriptionEnvelope(allocator, tx.outputs[0].script);
    try std.testing.expect(maybe_parsed != null);
    var parsed = maybe_parsed.?;
    defer parsed.deinit(allocator);

    try std.testing.expectEqualStrings("application/bsv-20", parsed.content_type);

    const json_bytes = try hexDecode(allocator, parsed.data);
    defer allocator.free(json_bytes);

    var json_parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{});
    defer json_parsed.deinit();
    try std.testing.expect(json_parsed.value == .object);

    const op = json_parsed.value.object.get("op").?.string;
    try std.testing.expectEqualStrings("deploy+mint", op);

    const amt = json_parsed.value.object.get("amt").?.string;
    try std.testing.expectEqualStrings("1000000", amt);

    const dec = json_parsed.value.object.get("dec").?.string;
    try std.testing.expectEqualStrings("18", dec);

    const sym = json_parsed.value.object.get("sym").?.string;
    try std.testing.expectEqualStrings("RNR", sym);
}

test "BSV21Token_TransferInscription" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = try compile.compileContract(allocator, SOURCE_PATH);
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();

    const pkh_hex = try owner.pubKeyHashHex(allocator);
    defer allocator.free(pkh_hex);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pkh_hex },
    });
    defer contract.deinit();

    // Use a synthetic token-id matching `txid_vout` shape.
    const token_id = "0000000000000000000000000000000000000000000000000000000000000001_0";
    var insc = try runar.bsv21Transfer(allocator, token_id, "50");
    defer insc.deinit(allocator);
    try contract.withInscription(insc);

    const fund_txid = try helpers.fundWallet(allocator, &owner, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try owner.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 1 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("BSV21Token transfer TX: {s}", .{deploy_txid});

    const tx = try rpc_provider.provider().getTransaction(allocator, deploy_txid);
    defer {
        for (tx.outputs) |*o| {
            if (o.script.len > 0) allocator.free(o.script);
        }
        if (tx.outputs.len > 0) allocator.free(tx.outputs);
        if (tx.txid.len > 0) allocator.free(tx.txid);
        if (tx.raw.len > 0) allocator.free(tx.raw);
    }

    try std.testing.expect(tx.outputs.len > 0);
    const maybe_parsed = try runar.parseInscriptionEnvelope(allocator, tx.outputs[0].script);
    try std.testing.expect(maybe_parsed != null);
    var parsed = maybe_parsed.?;
    defer parsed.deinit(allocator);

    const json_bytes = try hexDecode(allocator, parsed.data);
    defer allocator.free(json_bytes);

    var json_parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{});
    defer json_parsed.deinit();
    try std.testing.expect(json_parsed.value == .object);

    const op = json_parsed.value.object.get("op").?.string;
    try std.testing.expectEqualStrings("transfer", op);

    const id = json_parsed.value.object.get("id").?.string;
    try std.testing.expectEqualStrings(token_id, id);

    const amt = json_parsed.value.object.get("amt").?.string;
    try std.testing.expectEqualStrings("50", amt);
}
