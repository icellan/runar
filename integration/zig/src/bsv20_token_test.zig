const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

// ---------------------------------------------------------------------------
// BSV-20 token integration tests — port of integration/ts/bsv20-token.test.ts.
//
// BSV-20 fungible tokens live as inscriptions on top of P2PKH UTXOs. The
// contract logic is just standard P2PKH; the token semantics (deploy, mint,
// transfer) are encoded in the inscription envelope and interpreted by
// indexers, not the script. These tests verify deploy/mint/transfer JSON
// payloads survive a full round-trip on a regtest node and that the
// underlying P2PKH spend is still accepted.
//
// Mirrors integration/go/bsv20_token_test.go.
//
// NOTE: The Zig SDK's `RunarContract` does not currently expose a `fromTxId`
// reconnection helper directly (only the generated SDK module emits one),
// so the round-trip-via-fromTxId case from the TS reference is omitted here.
// ---------------------------------------------------------------------------

const SOURCE_PATH = "examples/zig/bsv20-token/BSV20Token.runar.zig";

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

test "BSV20Token_Compile" {
    const allocator = std.testing.allocator;

    var artifact = try compile.compileContract(allocator, SOURCE_PATH);
    defer artifact.deinit();

    try std.testing.expectEqualStrings("BSV20Token", artifact.contract_name);
    try std.testing.expect(artifact.script.len > 0);
    std.log.info("BSV20Token compiled: {d} bytes", .{artifact.script.len / 2});
}

/// Deploy a BSV20Token P2PKH contract with the given inscription attached,
/// confirm the inscription survives the broadcast, and parse out the JSON.
fn deployAndVerifyInscription(
    allocator: std.mem.Allocator,
    insc: runar.Inscription,
    expected_op: []const u8,
) !void {
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

    // Attach inscription before deploy. `withInscription` clones internally,
    // so the caller is responsible for freeing the original `insc`.
    try contract.withInscription(insc);

    const fund_txid = try helpers.fundWallet(allocator, &owner, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try owner.localSigner();

    // 1-sat 1Sat-Ordinals UTXO.
    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 1 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("BSV20Token deployed: {s}", .{deploy_txid});

    // Fetch tx, parse output 0 script, expect a BSV-20 inscription envelope.
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
    const script_hex = tx.outputs[0].script;

    const maybe_parsed = try runar.parseInscriptionEnvelope(allocator, script_hex);
    try std.testing.expect(maybe_parsed != null);
    var parsed = maybe_parsed.?;
    defer parsed.deinit(allocator);

    try std.testing.expectEqualStrings("application/bsv-20", parsed.content_type);

    // The inscription `data` is hex-encoded UTF-8 JSON.
    const json_bytes = try hexDecode(allocator, parsed.data);
    defer allocator.free(json_bytes);

    var json_parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{});
    defer json_parsed.deinit();
    try std.testing.expect(json_parsed.value == .object);

    const p_field = json_parsed.value.object.get("p") orelse return error.MissingField;
    try std.testing.expect(p_field == .string);
    try std.testing.expectEqualStrings("bsv-20", p_field.string);

    const op_field = json_parsed.value.object.get("op") orelse return error.MissingField;
    try std.testing.expect(op_field == .string);
    try std.testing.expectEqualStrings(expected_op, op_field.string);
}

test "BSV20Token_DeployTokenInscription" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var insc = try runar.bsv20Deploy(allocator, "RUNAR", "21000000", "1000", null);
    defer insc.deinit(allocator);

    try deployAndVerifyInscription(allocator, insc, "deploy");
}

test "BSV20Token_MintInscription" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var insc = try runar.bsv20Mint(allocator, "RUNAR", "1000");
    defer insc.deinit(allocator);

    try deployAndVerifyInscription(allocator, insc, "mint");
}

test "BSV20Token_TransferInscription" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var insc = try runar.bsv20Transfer(allocator, "RUNAR", "50");
    defer insc.deinit(allocator);

    try deployAndVerifyInscription(allocator, insc, "transfer");
}
