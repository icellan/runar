const std = @import("std");
const bsvz = @import("bsvz");
const types = @import("sdk_types.zig");
const errors_mod = @import("sdk_errors.zig");

// ---------------------------------------------------------------------------
// Provider interface
// ---------------------------------------------------------------------------

/// Provider abstracts blockchain access for UTXO lookup and broadcast.
pub const Provider = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        getTransaction: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) ProviderError!types.TransactionData,
        broadcast: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, tx_hex: []const u8) ProviderError![]u8,
        getUtxos: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, address: []const u8) ProviderError![]types.UTXO,
        getContractUtxo: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, script_hash: []const u8) ProviderError!?types.UTXO,
        getNetwork: *const fn (ctx: *anyopaque) []const u8,
        getFeeRate: *const fn (ctx: *anyopaque) ProviderError!i64,
        getRawTransaction: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) ProviderError![]u8,
    };

    pub fn getTransaction(self: Provider, allocator: std.mem.Allocator, txid: []const u8) ProviderError!types.TransactionData {
        return self.vtable.getTransaction(self.ptr, allocator, txid);
    }

    pub fn broadcast(self: Provider, allocator: std.mem.Allocator, tx_hex: []const u8) ProviderError![]u8 {
        return self.vtable.broadcast(self.ptr, allocator, tx_hex);
    }

    pub fn getUtxos(self: Provider, allocator: std.mem.Allocator, address: []const u8) ProviderError![]types.UTXO {
        return self.vtable.getUtxos(self.ptr, allocator, address);
    }

    pub fn getContractUtxo(self: Provider, allocator: std.mem.Allocator, script_hash: []const u8) ProviderError!?types.UTXO {
        return self.vtable.getContractUtxo(self.ptr, allocator, script_hash);
    }

    pub fn getNetwork(self: Provider) []const u8 {
        return self.vtable.getNetwork(self.ptr);
    }

    pub fn getFeeRate(self: Provider) ProviderError!i64 {
        return self.vtable.getFeeRate(self.ptr);
    }

    pub fn getRawTransaction(self: Provider, allocator: std.mem.Allocator, txid: []const u8) ProviderError![]u8 {
        return self.vtable.getRawTransaction(self.ptr, allocator, txid);
    }
};

pub const ProviderError = error{
    NotFound,
    BroadcastFailed,
    NetworkError,
    OutOfMemory,
    /// DoS-bound: a UTXO returned by the provider carries a locking script
    /// larger than `errors_mod.MAX_SCRIPT_BYTES`. Inspect
    /// `errors_mod.last_error` for the structured limit/actual/context.
    ScriptSizeExceeded,
};

// ---------------------------------------------------------------------------
// MockProvider — in-memory provider for testing
// ---------------------------------------------------------------------------

/// MockProvider is an in-memory provider for unit tests and local development.
pub const MockProvider = struct {
    allocator: std.mem.Allocator,
    utxos: std.StringHashMap(std.ArrayListUnmanaged(types.UTXO)),
    raw_transactions: std.StringHashMap([]const u8),
    broadcast_count: u32 = 0,
    broadcasted_txs: std.ArrayListUnmanaged([]const u8),
    network: []const u8,
    fee_rate: i64 = 100,

    pub fn init(allocator: std.mem.Allocator, network: []const u8) MockProvider {
        return .{
            .allocator = allocator,
            .utxos = std.StringHashMap(std.ArrayListUnmanaged(types.UTXO)).init(allocator),
            .raw_transactions = std.StringHashMap([]const u8).init(allocator),
            .broadcasted_txs = .empty,
            .network = if (network.len > 0) network else "testnet",
        };
    }

    pub fn deinit(self: *MockProvider) void {
        var utxo_it = self.utxos.iterator();
        while (utxo_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            for (entry.value_ptr.items) |*u| u.deinit(self.allocator);
            entry.value_ptr.deinit(self.allocator);
        }
        self.utxos.deinit();

        var raw_it = self.raw_transactions.iterator();
        while (raw_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.raw_transactions.deinit();

        for (self.broadcasted_txs.items) |tx| {
            self.allocator.free(tx);
        }
        self.broadcasted_txs.deinit(self.allocator);
    }

    /// Add a UTXO for the given address.
    pub fn addUtxo(self: *MockProvider, address: []const u8, utxo: types.UTXO) !void {
        const key = try self.allocator.dupe(u8, address);
        errdefer self.allocator.free(key);
        const gop = try self.utxos.getOrPut(key);
        if (gop.found_existing) {
            self.allocator.free(key);
        } else {
            gop.value_ptr.* = .empty;
        }
        try gop.value_ptr.append(self.allocator, try utxo.clone(self.allocator));
    }

    /// Add a raw transaction hex by txid.
    pub fn addRawTransaction(self: *MockProvider, txid: []const u8, raw_hex: []const u8) !void {
        const key = try self.allocator.dupe(u8, txid);
        errdefer self.allocator.free(key);
        const val = try self.allocator.dupe(u8, raw_hex);
        try self.raw_transactions.put(key, val);
    }

    /// Get the list of broadcasted transaction hex strings.
    pub fn getBroadcastedTxs(self: *const MockProvider) []const []const u8 {
        return self.broadcasted_txs.items;
    }

    /// Return a Provider interface backed by this MockProvider.
    pub fn provider(self: *MockProvider) Provider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = Provider.VTable{
        .getTransaction = getTransactionImpl,
        .broadcast = broadcastImpl,
        .getUtxos = getUtxosImpl,
        .getContractUtxo = getContractUtxoImpl,
        .getNetwork = getNetworkImpl,
        .getFeeRate = getFeeRateImpl,
        .getRawTransaction = getRawTransactionImpl,
    };

    fn getTransactionImpl(_: *anyopaque, _: std.mem.Allocator, _: []const u8) ProviderError!types.TransactionData {
        return ProviderError.NotFound;
    }

    fn broadcastImpl(ctx: *anyopaque, allocator: std.mem.Allocator, tx_hex: []const u8) ProviderError![]u8 {
        const self: *MockProvider = @ptrCast(@alignCast(ctx));
        const stored_hex = allocator.dupe(u8, tx_hex) catch return ProviderError.OutOfMemory;
        self.broadcasted_txs.append(self.allocator, stored_hex) catch {
            allocator.free(stored_hex);
            return ProviderError.OutOfMemory;
        };
        self.broadcast_count += 1;

        // Generate deterministic fake txid
        const prefix = if (tx_hex.len > 16) tx_hex[0..16] else tx_hex;
        const fake_txid = mockHash64(allocator, self.broadcast_count, prefix) catch return ProviderError.OutOfMemory;

        // Store raw hex for later retrieval
        const txid_key = allocator.dupe(u8, fake_txid) catch return ProviderError.OutOfMemory;
        const raw_val = allocator.dupe(u8, tx_hex) catch {
            allocator.free(txid_key);
            return ProviderError.OutOfMemory;
        };
        self.raw_transactions.put(txid_key, raw_val) catch {
            allocator.free(txid_key);
            allocator.free(raw_val);
            return ProviderError.OutOfMemory;
        };

        return fake_txid;
    }

    fn getUtxosImpl(ctx: *anyopaque, allocator: std.mem.Allocator, address: []const u8) ProviderError![]types.UTXO {
        const self: *MockProvider = @ptrCast(@alignCast(ctx));
        const list = self.utxos.get(address) orelse return allocator.alloc(types.UTXO, 0) catch return ProviderError.OutOfMemory;
        // DoS-bound: reject pathological UTXO scripts BEFORE handing to caller.
        for (list.items) |u| {
            if (u.script.len == 0) continue;
            var ctx_buf: [256]u8 = undefined;
            const c = std.fmt.bufPrint(&ctx_buf, "MockProvider.getUtxos({s})", .{address}) catch "MockProvider.getUtxos";
            errors_mod.assertScriptHexUnderLimit(u.script, errors_mod.MAX_SCRIPT_BYTES, c) catch return ProviderError.ScriptSizeExceeded;
        }
        var result = allocator.alloc(types.UTXO, list.items.len) catch return ProviderError.OutOfMemory;
        for (list.items, 0..) |u, i| {
            result[i] = u.clone(allocator) catch return ProviderError.OutOfMemory;
        }
        return result;
    }

    fn getContractUtxoImpl(_: *anyopaque, _: std.mem.Allocator, _: []const u8) ProviderError!?types.UTXO {
        // MockProvider has no contract-utxo map; nothing to guard.
        return null;
    }

    fn getNetworkImpl(ctx: *anyopaque) []const u8 {
        const self: *MockProvider = @ptrCast(@alignCast(ctx));
        return self.network;
    }

    fn getFeeRateImpl(ctx: *anyopaque) ProviderError!i64 {
        const self: *MockProvider = @ptrCast(@alignCast(ctx));
        return self.fee_rate;
    }

    fn getRawTransactionImpl(ctx: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) ProviderError![]u8 {
        const self: *MockProvider = @ptrCast(@alignCast(ctx));
        const raw = self.raw_transactions.get(txid) orelse return ProviderError.NotFound;
        return allocator.dupe(u8, raw) catch return ProviderError.OutOfMemory;
    }
};

// ---------------------------------------------------------------------------
// Deterministic mock hash (produces a 64-char hex string like a txid)
// ---------------------------------------------------------------------------

fn mockHash64(allocator: std.mem.Allocator, count: u32, prefix: []const u8) ![]u8 {
    var h0: u32 = 0x6a09e667;
    var h1: u32 = 0xbb67ae85;
    var h2: u32 = 0x3c6ef372;
    var h3: u32 = 0xa54ff53a;

    // Mix in count
    const count_str_buf = std.fmt.allocPrint(allocator, "mock-broadcast-{d}-", .{count}) catch return error.OutOfMemory;
    defer allocator.free(count_str_buf);
    for (count_str_buf) |c| {
        h0 = imul32(h0 ^ @as(u32, c), 0x01000193);
        h1 = imul32(h1 ^ @as(u32, c), 0x01000193);
        h2 = imul32(h2 ^ @as(u32, c), 0x01000193);
        h3 = imul32(h3 ^ @as(u32, c), 0x01000193);
    }
    for (prefix) |c| {
        h0 = imul32(h0 ^ @as(u32, c), 0x01000193);
        h1 = imul32(h1 ^ @as(u32, c), 0x01000193);
        h2 = imul32(h2 ^ @as(u32, c), 0x01000193);
        h3 = imul32(h3 ^ @as(u32, c), 0x01000193);
    }

    const parts = [8]u32{ h0, h1, h2, h3, h0 ^ h2, h1 ^ h3, h0 ^ h1, h2 ^ h3 };
    var result = try allocator.alloc(u8, 64);
    var pos: usize = 0;
    for (parts) |p| {
        _ = std.fmt.bufPrint(result[pos .. pos + 8], "{x:0>8}", .{p}) catch unreachable;
        pos += 8;
    }
    return result;
}

fn imul32(a: u32, b: u32) u32 {
    return a *% b;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "MockProvider returns UTXOs and broadcasts" {
    const allocator = std.testing.allocator;
    var mock = MockProvider.init(allocator, "testnet");
    defer mock.deinit();

    try mock.addUtxo("addr1", .{
        .txid = "aabb",
        .output_index = 0,
        .satoshis = 1000,
        .script = "76a914",
    });

    var prov = mock.provider();

    const utxos = try prov.getUtxos(allocator, "addr1");
    defer {
        for (utxos) |*u| {
            var mu = u.*;
            mu.deinit(allocator);
        }
        allocator.free(utxos);
    }
    try std.testing.expectEqual(@as(usize, 1), utxos.len);
    try std.testing.expectEqual(@as(i64, 1000), utxos[0].satoshis);

    const txid = try prov.broadcast(allocator, "0100000000");
    defer allocator.free(txid);
    try std.testing.expectEqual(@as(usize, 64), txid.len);

    const fee_rate = try prov.getFeeRate();
    try std.testing.expectEqual(@as(i64, 100), fee_rate);
}
