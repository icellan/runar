const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");

// ---------------------------------------------------------------------------
// WhatsOnChainProvider — HTTP-based BSV blockchain provider via WoC API
// ---------------------------------------------------------------------------
//
// Mirrors the Go/TS WhatsOnChain provider API. Because std.http.Client in
// zig 0.16 requires a runtime `Io` value that is awkward to construct in a
// synchronous helper, the HTTP transport is abstracted behind a small
// callback (see sdk_rpc_provider.zig for the same pattern). Tests inject a
// MockHttpTransport; production callers either implement an Io-backed
// transport, or pass `null` and accept `TransportNotConfigured` errors when
// a method that needs network access is called.

/// HttpTransport performs one GET or POST request and returns the response
/// body. The implementation owns the returned buffer; the caller frees via
/// the `allocator` passed in.
pub const HttpTransport = struct {
    ctx: *anyopaque,
    get: *const fn (
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        url: []const u8,
    ) provider_mod.ProviderError![]u8,
    post: *const fn (
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        url: []const u8,
        content_type: []const u8,
        body: []const u8,
    ) provider_mod.ProviderError![]u8,
};

/// WhatsOnChainProvider implements Provider by making HTTP requests to the
/// WhatsOnChain API (https://whatsonchain.com). Supports mainnet and testnet.
pub const WhatsOnChainProvider = struct {
    allocator: std.mem.Allocator,
    network: Network,
    base_url: []const u8,
    transport: ?HttpTransport = null,

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

    const mainnet_base = "https://api.whatsonchain.com/v1/bsv/main";
    const testnet_base = "https://api.whatsonchain.com/v1/bsv/test";

    pub fn init(allocator: std.mem.Allocator, network: Network) WhatsOnChainProvider {
        return .{
            .allocator = allocator,
            .network = network,
            .base_url = switch (network) {
                .mainnet => mainnet_base,
                .testnet => testnet_base,
            },
        };
    }

    pub fn deinit(self: *WhatsOnChainProvider) void {
        _ = self;
    }

    /// Inject a concrete HTTP transport. Call before using any network-facing
    /// Provider vtable method. In unit tests this is a MockHttpTransport; in
    /// production callers supply an Io-backed transport.
    pub fn setTransport(self: *WhatsOnChainProvider, transport: HttpTransport) void {
        self.transport = transport;
    }

    /// Return a Provider interface backed by this WhatsOnChainProvider.
    pub fn provider(self: *WhatsOnChainProvider) provider_mod.Provider {
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
    // HTTP helper
    // -----------------------------------------------------------------------

    fn httpGet(self: *WhatsOnChainProvider, allocator: std.mem.Allocator, path: []const u8) provider_mod.ProviderError![]u8 {
        const transport = self.transport orelse return provider_mod.ProviderError.NetworkError;
        const url = std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.base_url, path }) catch return provider_mod.ProviderError.OutOfMemory;
        defer self.allocator.free(url);
        return transport.get(transport.ctx, allocator, url);
    }

    fn httpPost(self: *WhatsOnChainProvider, allocator: std.mem.Allocator, path: []const u8, json_body: []const u8) provider_mod.ProviderError![]u8 {
        const transport = self.transport orelse return provider_mod.ProviderError.NetworkError;
        const url = std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.base_url, path }) catch return provider_mod.ProviderError.OutOfMemory;
        defer self.allocator.free(url);
        return transport.post(transport.ctx, allocator, url, "application/json", json_body);
    }

    // -----------------------------------------------------------------------
    // Path helpers (exposed for testing request shape)
    // -----------------------------------------------------------------------

    pub fn buildTxPath(self: *WhatsOnChainProvider, allocator: std.mem.Allocator, txid: []const u8) provider_mod.ProviderError![]u8 {
        _ = self;
        return std.fmt.allocPrint(allocator, "/tx/hash/{s}", .{txid}) catch return provider_mod.ProviderError.OutOfMemory;
    }

    pub fn buildUtxosPath(self: *WhatsOnChainProvider, allocator: std.mem.Allocator, address: []const u8) provider_mod.ProviderError![]u8 {
        _ = self;
        return std.fmt.allocPrint(allocator, "/address/{s}/unspent", .{address}) catch return provider_mod.ProviderError.OutOfMemory;
    }

    pub fn buildBroadcastBody(self: *WhatsOnChainProvider, allocator: std.mem.Allocator, tx_hex: []const u8) provider_mod.ProviderError![]u8 {
        _ = self;
        return std.fmt.allocPrint(allocator, "{{\"txhex\":\"{s}\"}}", .{tx_hex}) catch return provider_mod.ProviderError.OutOfMemory;
    }

    // -----------------------------------------------------------------------
    // VTable implementations
    // -----------------------------------------------------------------------

    fn getTransactionImpl(ctx: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) provider_mod.ProviderError!types.TransactionData {
        const self: *WhatsOnChainProvider = @ptrCast(@alignCast(ctx));

        const path = std.fmt.allocPrint(self.allocator, "/tx/hash/{s}", .{txid}) catch return provider_mod.ProviderError.OutOfMemory;
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
                        // value is in BTC (float), convert to satoshis
                        var sats: i64 = 0;
                        if (obj.get("value")) |v| {
                            if (v == .float) {
                                sats = @intFromFloat(@round(v.float * 1e8));
                            } else if (v == .integer) {
                                sats = @intCast(v.integer);
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
        const self: *WhatsOnChainProvider = @ptrCast(@alignCast(ctx));

        // Build JSON body: {"txhex":"<raw tx hex>"}
        const json_body = std.fmt.allocPrint(self.allocator, "{{\"txhex\":\"{s}\"}}", .{tx_hex}) catch return provider_mod.ProviderError.OutOfMemory;
        defer self.allocator.free(json_body);

        const body = try self.httpPost(allocator, "/tx/raw", json_body);
        defer allocator.free(body);

        // WoC returns the txid as a JSON-encoded string (with quotes)
        // Strip surrounding quotes if present
        var result = body;
        if (result.len >= 2 and result[0] == '"' and result[result.len - 1] == '"') {
            result = result[1 .. result.len - 1];
        }

        return allocator.dupe(u8, result) catch return provider_mod.ProviderError.OutOfMemory;
    }

    fn getUtxosImpl(ctx: *anyopaque, allocator: std.mem.Allocator, address: []const u8) provider_mod.ProviderError![]types.UTXO {
        const self: *WhatsOnChainProvider = @ptrCast(@alignCast(ctx));

        const path = std.fmt.allocPrint(self.allocator, "/address/{s}/unspent", .{address}) catch return provider_mod.ProviderError.OutOfMemory;
        defer self.allocator.free(path);

        const body = try self.httpGet(allocator, path);
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
                const tx_hash = if (obj.get("tx_hash")) |v| (if (v == .string) v.string else "") else "";
                const tx_pos: i32 = if (obj.get("tx_pos")) |v| (if (v == .integer) @as(i32, @intCast(v.integer)) else 0) else 0;
                const value: i64 = if (obj.get("value")) |v| (if (v == .integer) @as(i64, @intCast(v.integer)) else 0) else 0;

                result[i] = .{
                    .txid = allocator.dupe(u8, tx_hash) catch return provider_mod.ProviderError.OutOfMemory,
                    .output_index = tx_pos,
                    .satoshis = value,
                    .script = allocator.dupe(u8, "") catch return provider_mod.ProviderError.OutOfMemory,
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
        const self: *WhatsOnChainProvider = @ptrCast(@alignCast(ctx));

        const path = std.fmt.allocPrint(self.allocator, "/script/{s}/unspent", .{script_hash}) catch return provider_mod.ProviderError.OutOfMemory;
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

        const tx_hash = if (obj.get("tx_hash")) |v| (if (v == .string) v.string else "") else "";
        const tx_pos: i32 = if (obj.get("tx_pos")) |v| (if (v == .integer) @as(i32, @intCast(v.integer)) else 0) else 0;
        const value: i64 = if (obj.get("value")) |v| (if (v == .integer) @as(i64, @intCast(v.integer)) else 0) else 0;

        return .{
            .txid = allocator.dupe(u8, tx_hash) catch return provider_mod.ProviderError.OutOfMemory,
            .output_index = tx_pos,
            .satoshis = value,
            .script = allocator.dupe(u8, "") catch return provider_mod.ProviderError.OutOfMemory,
        };
    }

    fn getNetworkImpl(ctx: *anyopaque) []const u8 {
        const self: *WhatsOnChainProvider = @ptrCast(@alignCast(ctx));
        return self.network.toString();
    }

    fn getFeeRateImpl(_: *anyopaque) provider_mod.ProviderError!i64 {
        // BSV standard relay fee: 0.1 sat/byte = 100 sat/KB
        return 100;
    }

    fn getRawTransactionImpl(ctx: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) provider_mod.ProviderError![]u8 {
        const self: *WhatsOnChainProvider = @ptrCast(@alignCast(ctx));

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

/// MockHttpTransport captures the last URL/body and returns a canned response.
const MockHttpTransport = struct {
    allocator: std.mem.Allocator,
    response: []const u8,
    last_url: []u8 = &.{},
    last_body: []u8 = &.{},
    last_content_type: []u8 = &.{},
    method: []const u8 = "",

    fn init(allocator: std.mem.Allocator, response: []const u8) MockHttpTransport {
        return .{ .allocator = allocator, .response = response };
    }

    fn deinit(self: *MockHttpTransport) void {
        if (self.last_url.len > 0) self.allocator.free(self.last_url);
        if (self.last_body.len > 0) self.allocator.free(self.last_body);
        if (self.last_content_type.len > 0) self.allocator.free(self.last_content_type);
    }

    fn getFn(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        url: []const u8,
    ) provider_mod.ProviderError![]u8 {
        const self: *MockHttpTransport = @ptrCast(@alignCast(ctx));
        if (self.last_url.len > 0) self.allocator.free(self.last_url);
        self.last_url = self.allocator.dupe(u8, url) catch return provider_mod.ProviderError.OutOfMemory;
        self.method = "GET";
        return allocator.dupe(u8, self.response) catch return provider_mod.ProviderError.OutOfMemory;
    }

    fn postFn(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        url: []const u8,
        content_type: []const u8,
        body: []const u8,
    ) provider_mod.ProviderError![]u8 {
        const self: *MockHttpTransport = @ptrCast(@alignCast(ctx));
        if (self.last_url.len > 0) self.allocator.free(self.last_url);
        if (self.last_body.len > 0) self.allocator.free(self.last_body);
        if (self.last_content_type.len > 0) self.allocator.free(self.last_content_type);
        self.last_url = self.allocator.dupe(u8, url) catch return provider_mod.ProviderError.OutOfMemory;
        self.last_body = self.allocator.dupe(u8, body) catch return provider_mod.ProviderError.OutOfMemory;
        self.last_content_type = self.allocator.dupe(u8, content_type) catch return provider_mod.ProviderError.OutOfMemory;
        self.method = "POST";
        return allocator.dupe(u8, self.response) catch return provider_mod.ProviderError.OutOfMemory;
    }

    fn transport(self: *MockHttpTransport) HttpTransport {
        return .{ .ctx = @ptrCast(self), .get = MockHttpTransport.getFn, .post = MockHttpTransport.postFn };
    }
};

test "WhatsOnChainProvider initializes correctly" {
    const allocator = std.testing.allocator;
    var woc = WhatsOnChainProvider.init(allocator, .mainnet);
    defer woc.deinit();

    const prov = woc.provider();
    try std.testing.expectEqualStrings("mainnet", prov.getNetwork());
}

test "WhatsOnChainProvider testnet URL" {
    const allocator = std.testing.allocator;
    var woc = WhatsOnChainProvider.init(allocator, .testnet);
    defer woc.deinit();

    const prov = woc.provider();
    try std.testing.expectEqualStrings("testnet", prov.getNetwork());

    const fee_rate = try prov.getFeeRate();
    try std.testing.expectEqual(@as(i64, 100), fee_rate);
}

test "WhatsOnChainProvider buildTxPath and buildUtxosPath shape" {
    const allocator = std.testing.allocator;
    var woc = WhatsOnChainProvider.init(allocator, .mainnet);
    defer woc.deinit();

    const p1 = try woc.buildTxPath(allocator, "deadbeef");
    defer allocator.free(p1);
    try std.testing.expectEqualStrings("/tx/hash/deadbeef", p1);

    const p2 = try woc.buildUtxosPath(allocator, "1abc");
    defer allocator.free(p2);
    try std.testing.expectEqualStrings("/address/1abc/unspent", p2);

    const body = try woc.buildBroadcastBody(allocator, "0100deadbeef");
    defer allocator.free(body);
    try std.testing.expectEqualStrings("{\"txhex\":\"0100deadbeef\"}", body);
}

test "WhatsOnChainProvider broadcast via mock transport strips quotes" {
    const allocator = std.testing.allocator;
    var mock = MockHttpTransport.init(allocator, "\"abcd1234\"");
    defer mock.deinit();

    var woc = WhatsOnChainProvider.init(allocator, .mainnet);
    defer woc.deinit();
    woc.setTransport(mock.transport());

    const prov = woc.provider();
    const txid = try prov.broadcast(allocator, "0100deadbeef");
    defer allocator.free(txid);
    try std.testing.expectEqualStrings("abcd1234", txid);

    // Verify request shape
    try std.testing.expect(std.mem.endsWith(u8, mock.last_url, "/tx/raw"));
    try std.testing.expect(std.mem.indexOf(u8, mock.last_body, "\"txhex\":\"0100deadbeef\"") != null);
    try std.testing.expectEqualStrings("application/json", mock.last_content_type);
    try std.testing.expectEqualStrings("POST", mock.method);
}
