//! The call path advances the contract's local state to the post-call state
//! BEFORE the broadcast. When the broadcast was refused nothing put it back, so
//! the next call was built from a state the chain never reached (same bug as
//! the TS SDK, packages/runar-sdk/src/__tests__/pr-b-state-rollback.test.ts).
//!
//! Zig ships no ScriptVM, so MockProvider cannot refuse the failing covenant
//! on its own; the refusal comes from a provider that delegates to a
//! MockProvider but whose broadcast fails while `refuse` is set, like a node
//! rejecting the transaction.
//!
//! Proves: after a refused broadcast — via `call()`, and via `prepareCall()`
//! with an explicit `new_state` + `finalizeCall()` — the state and the tracked
//! UTXO equal their pre-call values, and an honest follow-up call commits
//! n = 1.
//!
//! The embedded artifact (`fixtures/pr-b-gate-artifact.json`) is the output of
//! `runar-zig --source Gate.runar.ts --no-source-map` (sourceLoc stripped) for
//! `bump(k) { assert(k === 7n); this.n = this.n + 1n; }`.

const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");

const RunarContract = contract_mod.RunarContract;
const Provider = provider_mod.Provider;
const ProviderError = provider_mod.ProviderError;

const ARTIFACT_JSON = @embedFile("fixtures/pr-b-gate-artifact.json");
const KEY = "11" ** 32;
const FUND_SCRIPT = "76a914" ++ "00" ** 20 ++ "88ac";

/// Delegates to a MockProvider; broadcast fails while `refuse` is set.
const RefusingProvider = struct {
    inner: *provider_mod.MockProvider,
    refuse: bool = false,

    fn provider(self: *RefusingProvider) Provider {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn get(ctx: *anyopaque) *RefusingProvider {
        return @ptrCast(@alignCast(ctx));
    }

    const vtable = Provider.VTable{
        .getTransaction = getTransaction,
        .broadcast = broadcast,
        .getUtxos = getUtxos,
        .getContractUtxo = getContractUtxo,
        .getNetwork = getNetwork,
        .getFeeRate = getFeeRate,
        .getRawTransaction = getRawTransaction,
    };

    fn getTransaction(ctx: *anyopaque, a: std.mem.Allocator, txid: []const u8) ProviderError!types.TransactionData {
        return get(ctx).inner.provider().getTransaction(a, txid);
    }
    fn broadcast(ctx: *anyopaque, a: std.mem.Allocator, tx_hex: []const u8) ProviderError![]u8 {
        const self = get(ctx);
        if (self.refuse) return ProviderError.BroadcastRejected;
        return self.inner.provider().broadcast(a, tx_hex);
    }
    fn getUtxos(ctx: *anyopaque, a: std.mem.Allocator, address: []const u8) ProviderError![]types.UTXO {
        return get(ctx).inner.provider().getUtxos(a, address);
    }
    fn getContractUtxo(ctx: *anyopaque, a: std.mem.Allocator, script_hash: []const u8) ProviderError!?types.UTXO {
        return get(ctx).inner.provider().getContractUtxo(a, script_hash);
    }
    fn getNetwork(ctx: *anyopaque) []const u8 {
        return get(ctx).inner.provider().getNetwork();
    }
    fn getFeeRate(ctx: *anyopaque) ProviderError!i64 {
        return get(ctx).inner.provider().getFeeRate();
    }
    fn getRawTransaction(ctx: *anyopaque, a: std.mem.Allocator, txid: []const u8) ProviderError![]u8 {
        return get(ctx).inner.provider().getRawTransaction(a, txid);
    }
};

fn expectUtxoEq(want: types.UTXO, got: ?types.UTXO) !void {
    const g = got orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings(want.txid, g.txid);
    try std.testing.expectEqual(want.output_index, g.output_index);
    try std.testing.expectEqual(want.satoshis, g.satoshis);
    try std.testing.expectEqualStrings(want.script, g.script);
}

const Mode = enum { call, prepare_finalize };

fn bump(contract: *RunarContract, k: i64, prov: Provider, signer: signer_mod.Signer, mode: Mode) !void {
    const allocator = std.testing.allocator;
    const args = [_]types.StateValue{.{ .int = k }};
    switch (mode) {
        .call => {
            const txid = try contract.call("bump", &args, prov, signer, null);
            allocator.free(txid);
        },
        .prepare_finalize => {
            // prepareCall does not run the ANF interpreter; the post-call state
            // comes from an explicit new_state, which prepareCall applies to
            // the contract's state before anything is broadcast.
            const new_state = [_]types.StateValue{.{ .int = contract.state[0].int + 1 }};
            var prepared = try contract.prepareCall("bump", &args, prov, signer, .{ .new_state = &new_state });
            defer prepared.deinit(allocator);
            const txid = try contract.finalizeCall(&prepared, &.{}, prov);
            allocator.free(txid);
        },
    }
}

fn refusedThenHonest(mode: Mode) !void {
    const allocator = std.testing.allocator;

    var artifact = try types.RunarArtifact.fromJson(allocator, ARTIFACT_JSON);
    defer artifact.deinit();
    var mock = provider_mod.MockProvider.init(allocator, "testnet");
    defer mock.deinit();
    var refusing = RefusingProvider{ .inner = &mock };
    var signer = try signer_mod.LocalSigner.fromHex(KEY);
    {
        const addr = try signer.signer().getAddress(allocator);
        defer allocator.free(addr);
        try mock.addUtxo(addr, .{ .txid = "aa" ** 32, .output_index = 0, .satoshis = 5_000_000, .script = FUND_SCRIPT });
    }

    const ctor = [_]types.StateValue{.{ .int = 0 }};
    var contract = try RunarContract.init(allocator, &artifact, &ctor);
    defer contract.deinit();
    const deploy_txid = try contract.deploy(refusing.provider(), signer.signer(), .{ .satoshis = 50_000 });
    defer allocator.free(deploy_txid);

    var utxo_before = try contract.getCurrentUtxo().?.clone(allocator);
    defer utxo_before.deinit(allocator);

    refusing.refuse = true;
    if (bump(&contract, 8, refusing.provider(), signer.signer(), mode)) |_| {
        return error.TestUnexpectedSuccess;
    } else |_| {}
    try std.testing.expectEqual(@as(usize, 1), contract.state.len);
    try std.testing.expectEqual(@as(i64, 0), contract.state[0].int);
    try expectUtxoEq(utxo_before, contract.getCurrentUtxo());

    refusing.refuse = false;
    try bump(&contract, 7, refusing.provider(), signer.signer(), mode);
    try std.testing.expectEqual(@as(i64, 1), contract.state[0].int);
}

test "PR B state rollback: a refused call() broadcast leaves state and UTXO untouched" {
    try refusedThenHonest(.call);
}

test "PR B state rollback: a refused finalizeCall() broadcast leaves state and UTXO untouched" {
    try refusedThenHonest(.prepare_finalize);
}

fn finalizeBump(contract: *RunarContract, prov: Provider, prepared: *types.PreparedCall) !void {
    const txid = try contract.finalizeCall(prepared, &.{}, prov);
    std.testing.allocator.free(txid);
}

test "PR B state rollback: a retried finalizeCall commits; a refused repeat of a committed one does not rewind" {
    const allocator = std.testing.allocator;

    var artifact = try types.RunarArtifact.fromJson(allocator, ARTIFACT_JSON);
    defer artifact.deinit();
    var mock = provider_mod.MockProvider.init(allocator, "testnet");
    defer mock.deinit();
    var refusing = RefusingProvider{ .inner = &mock };
    var signer = try signer_mod.LocalSigner.fromHex(KEY);
    {
        const addr = try signer.signer().getAddress(allocator);
        defer allocator.free(addr);
        try mock.addUtxo(addr, .{ .txid = "aa" ** 32, .output_index = 0, .satoshis = 5_000_000, .script = FUND_SCRIPT });
    }
    const ctor = [_]types.StateValue{.{ .int = 0 }};
    var contract = try RunarContract.init(allocator, &artifact, &ctor);
    defer contract.deinit();
    const deploy_txid = try contract.deploy(refusing.provider(), signer.signer(), .{ .satoshis = 50_000 });
    defer allocator.free(deploy_txid);
    const args = [_]types.StateValue{.{ .int = 7 }};

    // Refused, then retried: the retry commits n = 1.
    const one = [_]types.StateValue{.{ .int = 1 }};
    var first = try contract.prepareCall("bump", &args, refusing.provider(), signer.signer(), .{ .new_state = &one });
    defer first.deinit(allocator);
    refusing.refuse = true;
    if (finalizeBump(&contract, refusing.provider(), &first)) |_| return error.TestUnexpectedSuccess else |_| {}
    try std.testing.expectEqual(@as(i64, 0), contract.state[0].int);
    refusing.refuse = false;
    try finalizeBump(&contract, refusing.provider(), &first);
    try std.testing.expectEqual(@as(i64, 1), contract.state[0].int);

    // Committed at the first attempt, then repeated and refused: n stays 2.
    const two = [_]types.StateValue{.{ .int = 2 }};
    var second = try contract.prepareCall("bump", &args, refusing.provider(), signer.signer(), .{ .new_state = &two });
    defer second.deinit(allocator);
    try finalizeBump(&contract, refusing.provider(), &second);
    try std.testing.expectEqual(@as(i64, 2), contract.state[0].int);
    var utxo_after = try contract.getCurrentUtxo().?.clone(allocator);
    defer utxo_after.deinit(allocator);
    refusing.refuse = true;
    if (finalizeBump(&contract, refusing.provider(), &second)) |_| return error.TestUnexpectedSuccess else |_| {}
    try std.testing.expectEqual(@as(i64, 2), contract.state[0].int);
    try expectUtxoEq(utxo_after, contract.getCurrentUtxo());
}
