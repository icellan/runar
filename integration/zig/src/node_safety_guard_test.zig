const std = @import("std");
const helpers = @import("helpers.zig");

// ---------------------------------------------------------------------------
// Node-free guards for the integration helpers.
//
// GK-BUG-001: requireNodeAvailable() checked reachability only and the funding
// helper never looked at the chain, so pointing RPC_URL at a mainnet/testnet
// node would spend real coins from its wallet. The Go and Java suites refuse
// anything but chain == "regtest"; these tests hold the Zig helpers to the same.
//
// GK-BUG-004: broadcastAndMine() and fundWallet() discarded a failed mine with
// `catch {}`, so a broadcast whose confirming block never came returned a txid
// as if it had been mined.
//
// All tests drive the helpers through `helpers.NodeOps` against a stub node.
// ---------------------------------------------------------------------------

const Stub = struct {
    chain_json: []const u8 = "{\"chain\":\"regtest\",\"blocks\":200}",
    mine_fails: bool = false,
    /// When set, sendrawtransaction fails with this error; for
    /// error.RpcFailed the node's message is `send_message`.
    send_error: ?anyerror = null,
    send_message: []const u8 = "",
    sent: usize = 0,
    imported: usize = 0,
    mined: usize = 0,

    fn self(ctx: ?*anyopaque) *Stub {
        return @ptrCast(@alignCast(ctx.?));
    }
    fn getBlockchainInfo(ctx: ?*anyopaque, allocator: std.mem.Allocator) anyerror![]u8 {
        return allocator.dupe(u8, self(ctx).chain_json);
    }
    fn importAddress(ctx: ?*anyopaque, _: std.mem.Allocator, _: []const u8) anyerror!void {
        self(ctx).imported += 1;
    }
    fn sendToAddress(ctx: ?*anyopaque, allocator: std.mem.Allocator, _: []const u8, _: f64) anyerror![]u8 {
        self(ctx).sent += 1;
        return allocator.dupe(u8, "aa" ** 32);
    }
    fn sendRawTransaction(ctx: ?*anyopaque, allocator: std.mem.Allocator, _: []const u8) anyerror![]u8 {
        const s = self(ctx);
        s.sent += 1;
        if (s.send_error) |e| {
            if (e == error.RpcFailed) helpers.setLastRpcError(s.send_message);
            return e;
        }
        return allocator.dupe(u8, "bb" ** 32);
    }
    fn mine(ctx: ?*anyopaque, _: std.mem.Allocator, _: i64) anyerror!void {
        const s = self(ctx);
        if (s.mine_fails) return error.RpcFailed;
        s.mined += 1;
    }
    fn ops(s: *Stub) helpers.NodeOps {
        return .{
            .ctx = @ptrCast(s),
            .getBlockchainInfo = getBlockchainInfo,
            .importAddress = importAddress,
            .sendToAddress = sendToAddress,
            .sendRawTransaction = sendRawTransaction,
            .mine = mine,
        };
    }
};

test "GK-BUG-001: checkRegtestChain accepts regtest" {
    try helpers.checkRegtestChain(std.testing.allocator, "{\"chain\":\"regtest\",\"blocks\":101}");
}

test "GK-BUG-001: checkRegtestChain refuses main, test, a missing field and junk" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.NotRegtest, helpers.checkRegtestChain(a, "{\"chain\":\"main\"}"));
    try std.testing.expectError(error.NotRegtest, helpers.checkRegtestChain(a, "{\"chain\":\"test\"}"));
    try std.testing.expectError(error.NotRegtest, helpers.checkRegtestChain(a, "{\"blocks\":5}"));
    try std.testing.expectError(error.NotRegtest, helpers.checkRegtestChain(a, "[]"));
    try std.testing.expectError(error.NotRegtest, helpers.checkRegtestChain(a, "not json"));
}

test "GK-BUG-001: funding refuses a mainnet node before sending anything" {
    var stub: Stub = .{ .chain_json = "{\"chain\":\"main\",\"blocks\":900000}" };
    const result = helpers.fundAddressWith(stub.ops(), std.testing.allocator, "mxyz", 1.0);
    if (result) |txid| {
        std.testing.allocator.free(txid);
        return error.TestUnexpectedResult; // funded a mainnet node
    } else |err| {
        try std.testing.expectEqual(error.NotRegtest, err);
    }
    try std.testing.expectEqual(@as(usize, 0), stub.sent);
    try std.testing.expectEqual(@as(usize, 0), stub.imported);
}

test "GK-BUG-001: funding proceeds on regtest" {
    var stub: Stub = .{};
    const txid = try helpers.fundAddressWith(stub.ops(), std.testing.allocator, "mxyz", 1.0);
    defer std.testing.allocator.free(txid);
    try std.testing.expectEqual(@as(usize, 1), stub.sent);
    try std.testing.expectEqual(@as(usize, 1), stub.mined);
}

test "GK-BUG-004: broadcastAndMine propagates a failed mine" {
    var stub: Stub = .{ .mine_fails = true };
    const result = helpers.broadcastAndMineWith(stub.ops(), std.testing.allocator, "00");
    if (result) |txid| {
        std.testing.allocator.free(txid);
        return error.TestUnexpectedResult; // mine failure swallowed
    } else |err| {
        try std.testing.expectEqual(error.RpcFailed, err);
    }
    try std.testing.expectEqual(@as(usize, 1), stub.sent);
}

test "GK-BUG-004: fundAddress propagates a failed mine" {
    var stub: Stub = .{ .mine_fails = true };
    const result = helpers.fundAddressWith(stub.ops(), std.testing.allocator, "mxyz", 1.0);
    if (result) |txid| {
        std.testing.allocator.free(txid);
        return error.TestUnexpectedResult; // mine failure swallowed
    } else |err| {
        try std.testing.expectEqual(error.RpcFailed, err);
    }
}

test "GK-BUG-004: broadcastAndMine returns the txid when the mine succeeds" {
    var stub: Stub = .{};
    const txid = try helpers.broadcastAndMineWith(stub.ops(), std.testing.allocator, "00");
    defer std.testing.allocator.free(txid);
    try std.testing.expectEqualStrings("bb" ** 32, txid);
    try std.testing.expectEqual(@as(usize, 1), stub.mined);
}

// ---------------------------------------------------------------------------
// R2-NEGATIVES: after GK-BUG-004 an ACCEPTED transaction whose confirming mine
// fails is an error AFTER a broadcast attempt, so the old negative shape --
// `error.CallFailed` plus `broadcast_attempts > broadcasts_before` -- passed on
// an accepted spend. These drive the real RPCProvider.broadcast through a stub
// node and hold `checkNodeRejected` / `assertTxRejectedWith` to the node's
// actual verdict.
// ---------------------------------------------------------------------------

const SCRIPT_FAILURE = "mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)";

fn broadcastThrough(p: *helpers.RPCProvider) void {
    if (p.provider().broadcast(std.testing.allocator, "00")) |txid| {
        std.testing.allocator.free(txid);
    } else |_| {}
}

test "R2-NEGATIVES: an accepted tx whose mine failed passes the old delta but is not a node rejection" {
    var stub: Stub = .{ .mine_fails = true };
    var p = helpers.RPCProvider.init(std.testing.allocator);
    p.ops = stub.ops();
    const before = p.broadcast_attempts;
    const probe = p.rejectionProbe();
    const result = p.provider().broadcast(std.testing.allocator, "00");
    if (result) |txid| {
        std.testing.allocator.free(txid);
        return error.TestUnexpectedResult; // mine failure swallowed
    } else |err| {
        try std.testing.expectEqual(error.BroadcastFailed, err);
    }
    // The old shape is satisfied by an ACCEPTED spend...
    try std.testing.expect(p.broadcast_attempts > before);
    // ...the node-verdict check is not.
    try std.testing.expectError(error.NodeAccepted, p.checkNodeRejected(probe, helpers.SCRIPT_VERIFY_FAILED));
}

test "R2-NEGATIVES: a genuine script-verify rejection passes" {
    var stub: Stub = .{ .send_error = error.RpcFailed, .send_message = SCRIPT_FAILURE };
    var p = helpers.RPCProvider.init(std.testing.allocator);
    p.ops = stub.ops();
    broadcastThrough(&p); // the fixture's deploy, refused here too: irrelevant to the probe below
    const probe = p.rejectionProbe();
    broadcastThrough(&p);
    try p.checkNodeRejected(probe, helpers.SCRIPT_VERIFY_FAILED);
    try std.testing.expectEqualStrings(SCRIPT_FAILURE, p.lastRejection());
}

test "R2-NEGATIVES: a node rejection for another reason is refused" {
    var stub: Stub = .{ .send_error = error.RpcFailed, .send_message = "Missing inputs" };
    var p = helpers.RPCProvider.init(std.testing.allocator);
    p.ops = stub.ops();
    const probe = p.rejectionProbe();
    broadcastThrough(&p);
    try std.testing.expectError(error.WrongReason, p.checkNodeRejected(probe, helpers.SCRIPT_VERIFY_FAILED));
}

test "R2-NEGATIVES: a transport failure is not a node rejection" {
    var stub: Stub = .{ .send_error = error.ConnectionFailed };
    var p = helpers.RPCProvider.init(std.testing.allocator);
    p.ops = stub.ops();
    const probe = p.rejectionProbe();
    broadcastThrough(&p);
    try std.testing.expectError(error.NeverRuled, p.checkNodeRejected(probe, helpers.SCRIPT_VERIFY_FAILED));
}

test "R2-NEGATIVES: no broadcast at all is not a node rejection" {
    var stub: Stub = .{};
    var p = helpers.RPCProvider.init(std.testing.allocator);
    p.ops = stub.ops();
    const probe = p.rejectionProbe();
    try std.testing.expectError(error.NeverBroadcast, p.checkNodeRejected(probe, helpers.SCRIPT_VERIFY_FAILED));
}

test "R2-NEGATIVES: assertTxRejected requires the node's refusal and reason" {
    const a = std.testing.allocator;
    var accepted: Stub = .{};
    try std.testing.expectError(error.NodeAccepted, helpers.assertTxRejectedWith(accepted.ops(), a, "00", helpers.SCRIPT_VERIFY_FAILED));
    var transport: Stub = .{ .send_error = error.ConnectionFailed };
    try std.testing.expectError(error.NeverRuled, helpers.assertTxRejectedWith(transport.ops(), a, "00", helpers.SCRIPT_VERIFY_FAILED));
    var wrong: Stub = .{ .send_error = error.RpcFailed, .send_message = "Missing inputs" };
    try std.testing.expectError(error.WrongReason, helpers.assertTxRejectedWith(wrong.ops(), a, "00", helpers.SCRIPT_VERIFY_FAILED));
    var genuine: Stub = .{ .send_error = error.RpcFailed, .send_message = SCRIPT_FAILURE };
    try helpers.assertTxRejectedWith(genuine.ops(), a, "00", helpers.SCRIPT_VERIFY_FAILED);
}
