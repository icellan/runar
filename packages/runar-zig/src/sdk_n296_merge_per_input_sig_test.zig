//! N-296 — cross-tier rule for an explicit Sig in a merge's per-input args
//! (`additional_contract_input_args`): a Sig slot the primary call left
//! auto-signed (`.int = 0`) is ALWAYS signed by the connected signer for each
//! additional contract input; a caller-supplied value in that slot is
//! overwritten (TS reference).
//!
//! Proves: on the inputs of `conformance/sdk-call/stateful-merge-prepared.json`,
//! `call()` with (a) no per-input args (offline MockProvider default path) and
//! (b) an explicit garbage Sig in the per-input args broadcasts a tx byte-equal
//! to REFERENCE_TX_HEX (derived by the TS SDK, Spend-validated on all three
//! inputs by its MockProvider).
//! Does NOT prove: the other tiers (own tests, same constant), non-Sig slots,
//! or a live node.

const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");

const VECTOR_PATH = "../../conformance/sdk-call/stateful-merge-prepared.json";

const REFERENCE_TX_HEX = "0100000003aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdcf064ddf0261ab53798201149d757676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781557a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad768b7778820134947f77587f758153797ca269547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f7587774830450221009d3f59f4cd361172b8adcd02f08b6b2293d798aca1a1e93cac0d2d0d3a226a3b022028ea65e754260a5abc40eaeef6afdc01c8abea6e037a123897a86110001222544114751e76e8199196d454941c45d1b3a323f1433bd603ecab010210274d850301000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fde60253798201149d757676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781557a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad768b7778820134947f77587f758153797ca269547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f7587776a00000000000000001027000000000000ffffffff3b946bcc6269e02d76f6aab7aa1d6a7f0c1560ecc40b3eafbcf86633643f9c110000000041000000ffffffffcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fdcf064ddf0261ab53798201149d757676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781557a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad768b7778820134947f77587f758153797ca269547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777483045022100aacf88267e7022606007904cf4a2495b3d1e699c9ca583eb462af2543d70e126022005b6296107935ac6600859fae3c2574a64118c2c77c73bcdf3388904f25ba5914114751e76e8199196d454941c45d1b3a323f1433bd603ecab010210274d850301000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fde60253798201149d757676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781557a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad768b7778820134947f77587f758153797ca269547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f7587776a00000000000000001027000000000000ffffffff3b946bcc6269e02d76f6aab7aa1d6a7f0c1560ecc40b3eafbcf86633643f9c110000000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006a4730440220024c4395537350e6af559fd14011d3a6b7371888dfc82e9f66ef577a88300f4802205cee63d6fdb740bab6bb236b58a573c400100b8daa11c8e49aef89a097816bc441210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffffffff021027000000000000fde80261ab53798201149d757676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781557a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad768b7778820134947f77587f758153797ca269547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f7587776a0100000000000000ecab0100000000001976a914751e76e8199196d454941c45d1b3a323f1433bd688ac00000000";

fn str(obj: std.json.ObjectMap, key: []const u8) []const u8 {
    return obj.get(key).?.string;
}

fn utxoOf(obj: std.json.ObjectMap) types.UTXO {
    return .{
        .txid = str(obj, "txid"),
        .output_index = @intCast(obj.get("outputIndex").?.integer),
        .satoshis = obj.get("satoshis").?.integer,
        .script = str(obj, "script"),
    };
}

fn mergeAndCompare(per_input_args: ?[]const []const types.StateValue) !void {
    const allocator = std.testing.allocator;
    const tx = try mergeTx(allocator, per_input_args, null);
    defer allocator.free(tx);
    try std.testing.expectEqualStrings(REFERENCE_TX_HEX, tx);
}

/// Runs the merge and returns the broadcast tx hex (caller frees). `fee_rate`
/// overrides the MockProvider's sat/kB rate when non-null.
fn mergeTx(allocator: std.mem.Allocator, per_input_args: ?[]const []const types.StateValue, fee_rate: ?i64) ![]u8 {
    const raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, VECTOR_PATH, allocator, .limited(8 * 1024 * 1024));
    defer allocator.free(raw);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const v = parsed.value.object;

    const artifact_json = try std.json.Stringify.valueAlloc(allocator, v.get("artifact").?, .{});
    defer allocator.free(artifact_json);
    var artifact = try types.RunarArtifact.fromJson(allocator, artifact_json);
    defer artifact.deinit();

    const cu = utxoOf(v.get("contractUtxo").?.object);
    const eu = utxoOf(v.get("extraContractUtxo").?.object);
    const fu = utxoOf(v.get("fundingUtxo").?.object);

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    if (fee_rate) |rate| prov.fee_rate = rate;
    var signer = try signer_mod.LocalSigner.fromHex(str(v, "privKeyHex"));
    {
        const addr = try signer.signer().getAddress(allocator);
        defer allocator.free(addr);
        try prov.addUtxo(addr, fu);
    }
    try prov.addKnownOutpoint(cu.txid, cu.output_index, cu.script, cu.satoshis);
    try prov.addKnownOutpoint(eu.txid, eu.output_index, eu.script, eu.satoshis);

    var contract = try contract_mod.RunarContract.fromUtxo(allocator, &artifact, cu);
    defer contract.deinit();

    const args = [_]types.StateValue{.{ .int = 0 }};
    const extra = [_]types.UTXO{eu};
    const txid = try contract.call("increment", &args, prov.provider(), signer.signer(), .{
        .additional_contract_inputs = &extra,
        .additional_contract_input_args = per_input_args,
    });
    defer allocator.free(txid);

    const txs = prov.getBroadcastedTxs();
    try std.testing.expectEqual(@as(usize, 1), txs.len);
    return allocator.dupe(u8, txs[0]);
}

fn readVarint(b: []const u8, i: usize) struct { v: u64, next: usize } {
    const n = b[i];
    if (n < 0xfd) return .{ .v = n, .next = i + 1 };
    const w: usize = switch (n) {
        0xfd => 2,
        0xfe => 4,
        else => 8,
    };
    var v: u64 = 0;
    for (0..w) |k| v |= @as(u64, b[i + 1 + k]) << @intCast(8 * k);
    return .{ .v = v, .next = i + 1 + w };
}

// Fee sizing for a merge: at 1000 sat/kB every byte the fee layout misses is a
// satoshi under-paid. Each additional contract input's unlock carries
// _changeAmount, so it must be sized with the real change, not 0 (the defect
// the Java tier had; ported here as a cross-tier pin).
test "N-296: the merge fee covers every byte of the signed tx at 1 sat/byte" {
    const allocator = std.testing.allocator;
    const tx_hex = try mergeTx(allocator, null, 1000);
    defer allocator.free(tx_hex);
    const raw = try allocator.alloc(u8, tx_hex.len / 2);
    defer allocator.free(raw);
    _ = try std.fmt.hexToBytes(raw, tx_hex);

    var r = readVarint(raw, 4);
    var i = r.next;
    for (0..r.v) |_| {
        const sl = readVarint(raw, i + 36);
        i = sl.next + @as(usize, @intCast(sl.v)) + 4;
    }
    r = readVarint(raw, i);
    i = r.next;
    var out: i64 = 0;
    for (0..r.v) |_| {
        out += @intCast(std.mem.readInt(u64, raw[i..][0..8], .little));
        const sl = readVarint(raw, i + 8);
        i = sl.next + @as(usize, @intCast(sl.v));
    }

    const vec = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, VECTOR_PATH, allocator, .limited(8 * 1024 * 1024));
    defer allocator.free(vec);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, vec, .{});
    defer parsed.deinit();
    const v = parsed.value.object;
    const in = utxoOf(v.get("contractUtxo").?.object).satoshis + utxoOf(v.get("extraContractUtxo").?.object).satoshis +
        utxoOf(v.get("fundingUtxo").?.object).satoshis;
    const paid = in - out;
    if (paid < @as(i64, @intCast(raw.len))) {
        std.debug.print("paid {d} sat for a {d}-byte tx at 1 sat/byte\n", .{ paid, raw.len });
        return error.FeeUnderpaid;
    }
}

test "N-296: default (no per-input args) merge matches the reference tx" {
    try mergeAndCompare(null);
}

test "N-296: an explicit non-zero Sig in the per-input args is overwritten by the signer" {
    const explicit = [_]types.StateValue{.{ .bytes = "ab" ** 71 }};
    const per_input = [_][]const types.StateValue{&explicit};
    try mergeAndCompare(&per_input);
}
