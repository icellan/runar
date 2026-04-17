const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");

// ---------------------------------------------------------------------------
// GorillaPoolProvider -- HTTP-based 1sat Ordinals provider
// ---------------------------------------------------------------------------
//
// Implements the standard Provider interface using the GorillaPool 1sat
// Ordinals REST API.
//
// Endpoints:
//   Mainnet: https://ordinals.gorillapool.io/api/
//   Testnet: https://testnet.ordinals.gorillapool.io/api/
// ---------------------------------------------------------------------------

pub const GorillaPoolProvider = struct {
    allocator: std.mem.Allocator,
    network: Network,
    base_url: []const u8,

    pub const Network = enum {
        mainnet,
        testnet,

        pub fn toString(self: Network) []const u8 {
            return switch (self) {
                .mainnet => "mainnet",
                .testnet => "testnet",
            };
        }
    };

    const mainnet_base = "https://ordinals.gorillapool.io/api";
    const testnet_base = "https://testnet.ordinals.gorillapool.io/api";

    pub fn init(allocator: std.mem.Allocator, network: Network) GorillaPoolProvider {
        return .{
            .allocator = allocator,
            .network = network,
            .base_url = switch (network) {
                .mainnet => mainnet_base,
                .testnet => testnet_base,
            },
        };
    }

    pub fn deinit(self: *GorillaPoolProvider) void {
        _ = self;
    }

    /// Return a Provider interface backed by this GorillaPoolProvider.
    pub fn provider(self: *GorillaPoolProvider) provider_mod.Provider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = provider_mod.Provider.VTable{
        .getTransaction = getTransactionImpl,
        .broadcast = broadcastImpl,
        .getUtxos = getUtxosImpl,
        .getContractUtxo = getContractUtxoImpl,
        .getNetwork = getNetworkImpl,
        .getFeeRate = getFeeRateImpl,
        .getRawTransaction = getRawTransactionImpl,
    };

    // -----------------------------------------------------------------------
    // HTTP helpers
    // -----------------------------------------------------------------------

    fn httpGet(self: *GorillaPoolProvider, allocator: std.mem.Allocator, path: []const u8) provider_mod.ProviderError![]u8 {
        const url = std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.base_url, path }) catch return provider_mod.ProviderError.OutOfMemory;
        defer self.allocator.free(url);

        var client = std.http.Client{ .allocator = allocator, .io = std.testing.io };
        defer client.deinit();

        var buf: [8192]u8 = undefined;
        const uri = std.Uri.parse(url) catch return provider_mod.ProviderError.NetworkError;
        var req = client.open(.GET, uri, .{ .server_header_buffer = &buf }) catch return provider_mod.ProviderError.NetworkError;
        defer req.deinit();

        req.send() catch return provider_mod.ProviderError.NetworkError;
        req.wait() catch return provider_mod.ProviderError.NetworkError;

        if (req.status != .ok) {
            if (req.status == .not_found) return provider_mod.ProviderError.NotFound;
            return provider_mod.ProviderError.NetworkError;
        }

        const body = req.reader().readAllAlloc(allocator, 10 * 1024 * 1024) catch return provider_mod.ProviderError.OutOfMemory;
        return body;
    }

    fn httpPost(self: *GorillaPoolProvider, allocator: std.mem.Allocator, path: []const u8, json_body: []const u8) provider_mod.ProviderError![]u8 {
        const url = std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.base_url, path }) catch return provider_mod.ProviderError.OutOfMemory;
        defer self.allocator.free(url);

        var client = std.http.Client{ .allocator = allocator, .io = std.testing.io };
        defer client.deinit();

        var buf: [8192]u8 = undefined;
        const uri = std.Uri.parse(url) catch return provider_mod.ProviderError.NetworkError;
        var req = client.open(.POST, uri, .{
            .server_header_buffer = &buf,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
            },
        }) catch return provider_mod.ProviderError.NetworkError;
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = json_body.len };
        req.send() catch return provider_mod.ProviderError.NetworkError;
        req.writeAll(json_body) catch return provider_mod.ProviderError.NetworkError;
        req.finish() catch return provider_mod.ProviderError.NetworkError;
        req.wait() catch return provider_mod.ProviderError.NetworkError;

        if (req.status != .ok) {
            return provider_mod.ProviderError.BroadcastFailed;
        }

        const body = req.reader().readAllAlloc(allocator, 10 * 1024 * 1024) catch return provider_mod.ProviderError.OutOfMemory;
        return body;
    }

    // -----------------------------------------------------------------------
    // VTable implementations
    // -----------------------------------------------------------------------

    fn getTransactionImpl(ctx: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) provider_mod.ProviderError!types.TransactionData {
        const self: *GorillaPoolProvider = @ptrCast(@alignCast(ctx));

        const path = std.fmt.allocPrint(self.allocator, "/tx/{s}", .{txid}) catch return provider_mod.ProviderError.OutOfMemory;
        defer self.allocator.free(path);

        const body = try self.httpGet(allocator, path);
        defer allocator.free(body);

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return provider_mod.ProviderError.NetworkError;
        defer parsed.deinit();

        const root = parsed.value.object;
        const tx_txid = if (root.get("txid")) |v| (if (v == .string) v.string else txid) else txid;
        const version: i32 = if (root.get("version")) |v| (if (v == .integer) @as(i32, @intCast(v.integer)) else 1) else 1;
        const locktime: u32 = if (root.get("locktime")) |v| (if (v == .integer) @as(u32, @intCast(v.integer)) else 0) else 0;

        // Parse inputs
        var inputs: []types.TxInput = &.{};
        if (root.get("vin")) |vin_val| {
            if (vin_val == .array) {
                const items = vin_val.array.items;
                var inp_list = allocator.alloc(types.TxInput, items.len) catch return provider_mod.ProviderError.OutOfMemory;
                for (items, 0..) |item, i| {
                    if (item == .object) {
                        const obj = item.object;
                        const in_txid = if (obj.get("txid")) |v| (if (v == .string) v.string else "") else "";
                        const vout: i32 = if (obj.get("vout")) |v| (if (v == .integer) @as(i32, @intCast(v.integer)) else 0) else 0;
                        var script_hex: []const u8 = "";
                        if (obj.get("scriptSig")) |ss| {
                            if (ss == .object) {
                                if (ss.object.get("hex")) |h| {
                                    if (h == .string) script_hex = h.string;
                                }
                            }
                        }
                        const seq: u32 = if (obj.get("sequence")) |v| (if (v == .integer) @as(u32, @intCast(v.integer)) else 0xffffffff) else 0xffffffff;
                        inp_list[i] = .{
                            .txid = allocator.dupe(u8, in_txid) catch return provider_mod.ProviderError.OutOfMemory,
                            .output_index = vout,
                            .script = allocator.dupe(u8, script_hex) catch return provider_mod.ProviderError.OutOfMemory,
                            .sequence = seq,
                        };
                    } else {
                        inp_list[i] = .{};
                    }
                }
                inputs = inp_list;
            }
        }

        // Parse outputs
        var outputs: []types.TxOutput = &.{};
        if (root.get("vout")) |vout_val| {
            if (vout_val == .array) {
                const items = vout_val.array.items;
                var out_list = allocator.alloc(types.TxOutput, items.len) catch return provider_mod.ProviderError.OutOfMemory;
                for (items, 0..) |item, i| {
                    if (item == .object) {
                        const obj = item.object;
                        var sats: i64 = 0;
                        if (obj.get("value")) |v| {
                            if (v == .float) {
                                sats = @intFromFloat(@round(v.float * 1e8));
                            } else if (v == .integer) {
                                sats = @intCast(v.integer);
                            }
                        }
                        // GorillaPool uses "satoshis" field in some responses
                        if (sats == 0) {
                            if (obj.get("satoshis")) |v| {
                                if (v == .integer) sats = @intCast(v.integer);
                            }
                        }
                        var script_hex: []const u8 = "";
                        if (obj.get("scriptPubKey")) |sp| {
                            if (sp == .object) {
                                if (sp.object.get("hex")) |h| {
                                    if (h == .string) script_hex = h.string;
                                }
                            }
                        }
                        out_list[i] = .{
                            .satoshis = sats,
                            .script = allocator.dupe(u8, script_hex) catch return provider_mod.ProviderError.OutOfMemory,
                        };
                    } else {
                        out_list[i] = .{};
                    }
                }
                outputs = out_list;
            }
        }

        // Raw hex
        var raw: []const u8 = &.{};
        if (root.get("hex")) |v| {
            if (v == .string) raw = allocator.dupe(u8, v.string) catch return provider_mod.ProviderError.OutOfMemory;
        }

        return .{
            .txid = allocator.dupe(u8, tx_txid) catch return provider_mod.ProviderError.OutOfMemory,
            .version = version,
            .inputs = inputs,
            .outputs = outputs,
            .locktime = locktime,
            .raw = raw,
        };
    }

    fn broadcastImpl(ctx: *anyopaque, allocator: std.mem.Allocator, tx_hex: []const u8) provider_mod.ProviderError![]u8 {
        const self: *GorillaPoolProvider = @ptrCast(@alignCast(ctx));

        // GorillaPool expects {"rawTx":"<hex>"}
        const json_body = std.fmt.allocPrint(self.allocator, "{{\"rawTx\":\"{s}\"}}", .{tx_hex}) catch return provider_mod.ProviderError.OutOfMemory;
        defer self.allocator.free(json_body);

        const body = try self.httpPost(allocator, "/tx", json_body);
        defer allocator.free(body);

        // Response may be a plain txid string or JSON {"txid":"..."}
        // Strip surrounding quotes if present
        var result = body;
        if (result.len >= 2 and result[0] == '"' and result[result.len - 1] == '"') {
            result = result[1 .. result.len - 1];
        }

        return allocator.dupe(u8, result) catch return provider_mod.ProviderError.OutOfMemory;
    }

    fn getUtxosImpl(ctx: *anyopaque, allocator: std.mem.Allocator, address: []const u8) provider_mod.ProviderError![]types.UTXO {
        const self: *GorillaPoolProvider = @ptrCast(@alignCast(ctx));

        const path = std.fmt.allocPrint(self.allocator, "/address/{s}/utxos", .{address}) catch return provider_mod.ProviderError.OutOfMemory;
        defer self.allocator.free(path);

        const body = self.httpGet(allocator, path) catch |err| {
            if (err == provider_mod.ProviderError.NotFound) {
                return allocator.alloc(types.UTXO, 0) catch return provider_mod.ProviderError.OutOfMemory;
            }
            return err;
        };
        defer allocator.free(body);

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return provider_mod.ProviderError.NetworkError;
        defer parsed.deinit();

        if (parsed.value != .array) {
            return allocator.alloc(types.UTXO, 0) catch return provider_mod.ProviderError.OutOfMemory;
        }

        const items = parsed.value.array.items;
        var result = allocator.alloc(types.UTXO, items.len) catch return provider_mod.ProviderError.OutOfMemory;
        for (items, 0..) |item, i| {
            if (item == .object) {
                const obj = item.object;
                const tx_hash = if (obj.get("txid")) |v| (if (v == .string) v.string else "") else "";
                const tx_pos: i32 = if (obj.get("vout")) |v| (if (v == .integer) @as(i32, @intCast(v.integer)) else 0) else 0;
                var value: i64 = 0;
                if (obj.get("satoshis")) |v| {
                    if (v == .integer) value = @intCast(v.integer);
                }
                const script: []const u8 = if (obj.get("script")) |v| (if (v == .string) v.string else "") else "";

                result[i] = .{
                    .txid = allocator.dupe(u8, tx_hash) catch return provider_mod.ProviderError.OutOfMemory,
                    .output_index = tx_pos,
                    .satoshis = value,
                    .script = allocator.dupe(u8, script) catch return provider_mod.ProviderError.OutOfMemory,
                };
            } else {
                result[i] = .{
                    .txid = allocator.dupe(u8, "") catch return provider_mod.ProviderError.OutOfMemory,
                    .output_index = 0,
                    .satoshis = 0,
                    .script = allocator.dupe(u8, "") catch return provider_mod.ProviderError.OutOfMemory,
                };
            }
        }

        return result;
    }

    fn getContractUtxoImpl(ctx: *anyopaque, allocator: std.mem.Allocator, script_hash: []const u8) provider_mod.ProviderError!?types.UTXO {
        const self: *GorillaPoolProvider = @ptrCast(@alignCast(ctx));

        const path = std.fmt.allocPrint(self.allocator, "/script/{s}/utxos", .{script_hash}) catch return provider_mod.ProviderError.OutOfMemory;
        defer self.allocator.free(path);

        const body = self.httpGet(allocator, path) catch |err| {
            if (err == provider_mod.ProviderError.NotFound) return null;
            return err;
        };
        defer allocator.free(body);

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return provider_mod.ProviderError.NetworkError;
        defer parsed.deinit();

        if (parsed.value != .array) return null;
        const items = parsed.value.array.items;
        if (items.len == 0) return null;

        const first = items[0];
        if (first != .object) return null;
        const obj = first.object;

        const tx_hash = if (obj.get("txid")) |v| (if (v == .string) v.string else "") else "";
        const tx_pos: i32 = if (obj.get("vout")) |v| (if (v == .integer) @as(i32, @intCast(v.integer)) else 0) else 0;
        var value: i64 = 0;
        if (obj.get("satoshis")) |v| {
            if (v == .integer) value = @intCast(v.integer);
        }
        const script: []const u8 = if (obj.get("script")) |v| (if (v == .string) v.string else "") else "";

        return .{
            .txid = allocator.dupe(u8, tx_hash) catch return provider_mod.ProviderError.OutOfMemory,
            .output_index = tx_pos,
            .satoshis = value,
            .script = allocator.dupe(u8, script) catch return provider_mod.ProviderError.OutOfMemory,
        };
    }

    fn getNetworkImpl(ctx: *anyopaque) []const u8 {
        const self: *GorillaPoolProvider = @ptrCast(@alignCast(ctx));
        return self.network.toString();
    }

    fn getFeeRateImpl(_: *anyopaque) provider_mod.ProviderError!i64 {
        // BSV standard relay fee: 0.1 sat/byte = 100 sat/KB
        return 100;
    }

    fn getRawTransactionImpl(ctx: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) provider_mod.ProviderError![]u8 {
        const self: *GorillaPoolProvider = @ptrCast(@alignCast(ctx));

        const path = std.fmt.allocPrint(self.allocator, "/tx/{s}/hex", .{txid}) catch return provider_mod.ProviderError.OutOfMemory;
        defer self.allocator.free(path);

        const body = try self.httpGet(allocator, path);
        // Trim trailing whitespace/newlines
        var end: usize = body.len;
        while (end > 0 and (body[end - 1] == '\n' or body[end - 1] == '\r' or body[end - 1] == ' ')) {
            end -= 1;
        }
        if (end < body.len) {
            const trimmed = allocator.dupe(u8, body[0..end]) catch {
                allocator.free(body);
                return provider_mod.ProviderError.OutOfMemory;
            };
            allocator.free(body);
            return trimmed;
        }
        return body;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "GorillaPoolProvider initializes correctly" {
    const allocator = std.testing.allocator;
    var gp = GorillaPoolProvider.init(allocator, .mainnet);
    defer gp.deinit();

    const prov = gp.provider();
    try std.testing.expectEqualStrings("mainnet", prov.getNetwork());
}

test "GorillaPoolProvider testnet URL" {
    const allocator = std.testing.allocator;
    var gp = GorillaPoolProvider.init(allocator, .testnet);
    defer gp.deinit();

    const prov = gp.provider();
    try std.testing.expectEqualStrings("testnet", prov.getNetwork());

    const fee_rate = try prov.getFeeRate();
    try std.testing.expectEqual(@as(i64, 100), fee_rate);
}
