const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const errors_mod = @import("sdk_errors.zig");
const bsvz = @import("bsvz");

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

    /// WoC's GET /address/{address}/unspent listing carries outpoints and
    /// values but no locking script. The script is the BIP-143 scriptCode a
    /// signer commits to, so an empty one yields signatures no OP_CHECKSIG
    /// accepts (F-040). Each UTXO's tx is therefore fetched via
    /// GET /tx/{txid}/hex; its double-SHA256 must equal the txid, and tx_pos
    /// must be an output whose value equals the listed value. A malformed
    /// entry, a hash mismatch, a missing output, a value mismatch or an empty
    /// script is NetworkError (the provider's decode-failure error); no UTXO
    /// is returned with an empty script.
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
        var filled: usize = 0;
        errdefer {
            for (result[0..filled]) |*u| u.deinit(allocator);
            allocator.free(result);
        }
        for (items) |item| {
            if (item != .object) return provider_mod.ProviderError.NetworkError;
            const obj = item.object;
            const tx_hash_v = obj.get("tx_hash") orelse return provider_mod.ProviderError.NetworkError;
            const tx_pos_v = obj.get("tx_pos") orelse return provider_mod.ProviderError.NetworkError;
            const value_v = obj.get("value") orelse return provider_mod.ProviderError.NetworkError;
            if (tx_hash_v != .string or tx_pos_v != .integer or value_v != .integer) return provider_mod.ProviderError.NetworkError;
            const tx_hash = tx_hash_v.string;
            if (tx_pos_v.integer < 0 or tx_pos_v.integer > std.math.maxInt(i32)) return provider_mod.ProviderError.NetworkError;
            const tx_pos: usize = @intCast(tx_pos_v.integer);
            const value: i64 = value_v.integer;

            const script = try self.fetchOutputScript(allocator, tx_hash, tx_pos, value);
            errdefer allocator.free(script);
            const c = std.fmt.allocPrint(allocator, "WhatsOnChainProvider.getUtxos({s})", .{address}) catch return provider_mod.ProviderError.OutOfMemory;
            defer allocator.free(c);
            errors_mod.assertScriptHexUnderLimit(script, errors_mod.MAX_SCRIPT_BYTES, c) catch return provider_mod.ProviderError.ScriptSizeExceeded;
            result[filled] = .{
                .txid = allocator.dupe(u8, tx_hash) catch return provider_mod.ProviderError.OutOfMemory,
                .output_index = @intCast(tx_pos),
                .satoshis = value,
                .script = script,
            };
            filled += 1;
        }

        return result;
    }

    /// GET /tx/{txid}/hex, verify it hashes to txid, and return output
    /// `index`'s locking script as owned hex (F-040).
    fn fetchOutputScript(self: *WhatsOnChainProvider, allocator: std.mem.Allocator, txid: []const u8, index: usize, value: i64) provider_mod.ProviderError![]u8 {
        const raw_hex = try getRawTransactionImpl(@ptrCast(self), allocator, txid);
        defer allocator.free(raw_hex);
        const raw = bsvz.primitives.hex.decode(allocator, raw_hex) catch |err| switch (err) {
            error.OutOfMemory => return provider_mod.ProviderError.OutOfMemory,
            else => return provider_mod.ProviderError.NetworkError,
        };
        defer allocator.free(raw);

        var digest = bsvz.crypto.hash.hash256(raw).bytes;
        std.mem.reverse(u8, &digest);
        const body_txid = std.fmt.bytesToHex(digest, .lower);
        if (!std.ascii.eqlIgnoreCase(&body_txid, txid)) return provider_mod.ProviderError.NetworkError;

        const tx = bsvz.transaction.Transaction.parse(allocator, raw) catch |err| switch (err) {
            error.OutOfMemory => return provider_mod.ProviderError.OutOfMemory,
            else => return provider_mod.ProviderError.NetworkError,
        };
        defer tx.deinit(allocator);

        if (index >= tx.outputs.len) return provider_mod.ProviderError.NetworkError;
        const out = tx.outputs[index];
        if (out.satoshis != value) return provider_mod.ProviderError.NetworkError;
        const script_bytes = out.locking_script.bytes;
        if (script_bytes.len == 0) return provider_mod.ProviderError.NetworkError;
        const hex_out = allocator.alloc(u8, script_bytes.len * 2) catch return provider_mod.ProviderError.OutOfMemory;
        _ = bsvz.primitives.hex.encodeLower(script_bytes, hex_out) catch unreachable;
        return hex_out;
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

// ---------------------------------------------------------------------------
// F-040: getUtxos returns the real locking script.
//
// WoC's /address/{a}/unspent listing has no script, and getUtxos used to
// return script "" — which became the BIP-143 scriptCode of every funding
// signature. getUtxos now fetches /tx/{txid}/hex per UTXO.
// Proves: the shared recorded vectors (conformance/sdk-woc) yield the real
// script + value; a body for another txid, a missing output, a value that
// disagrees and an empty output script fail with NetworkError (the provider's
// decode-failure error) and an unavailable tx with NotFound. Does NOT prove
// the live API still serves these shapes (recorded 2026-09-29).
// ---------------------------------------------------------------------------

const WOC_VECTORS_REL_PATH = "../../conformance/sdk-woc/vectors.json";

fn f040LoadVectors(allocator: std.mem.Allocator) !std.json.Parsed(std.json.Value) {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, WOC_VECTORS_REL_PATH, allocator, .limited(4 * 1024 * 1024));
    defer allocator.free(bytes);
    return std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always });
}

/// Serves the listing and each raw tx at /tx/{txid}/hex; NotFound otherwise.
const F040RoutingTransport = struct {
    address: []const u8,
    unspent_body: []const u8,
    raw_tx_hex: std.json.ObjectMap,

    fn getFn(ctx: *anyopaque, allocator: std.mem.Allocator, url: []const u8) provider_mod.ProviderError![]u8 {
        const self: *F040RoutingTransport = @ptrCast(@alignCast(ctx));
        const base = "https://api.whatsonchain.com/v1/bsv/main";
        if (!std.mem.startsWith(u8, url, base)) return provider_mod.ProviderError.NotFound;
        const path = url[base.len..];
        if (std.mem.startsWith(u8, path, "/address/") and std.mem.endsWith(u8, path, "/unspent") and
            std.mem.eql(u8, path["/address/".len .. path.len - "/unspent".len], self.address))
        {
            return allocator.dupe(u8, self.unspent_body) catch provider_mod.ProviderError.OutOfMemory;
        }
        if (std.mem.startsWith(u8, path, "/tx/") and std.mem.endsWith(u8, path, "/hex")) {
            const txid = path["/tx/".len .. path.len - "/hex".len];
            if (self.raw_tx_hex.get(txid)) |v| {
                return allocator.dupe(u8, v.string) catch provider_mod.ProviderError.OutOfMemory;
            }
        }
        return provider_mod.ProviderError.NotFound;
    }

    fn postFn(_: *anyopaque, _: std.mem.Allocator, _: []const u8, _: []const u8, _: []const u8) provider_mod.ProviderError![]u8 {
        return provider_mod.ProviderError.NetworkError;
    }

    fn transport(self: *F040RoutingTransport) HttpTransport {
        return .{ .ctx = @ptrCast(self), .get = F040RoutingTransport.getFn, .post = F040RoutingTransport.postFn };
    }
};

test "F-040 getUtxos returns the recorded locking scripts" {
    const allocator = std.testing.allocator;
    var parsed = try f040LoadVectors(allocator);
    defer parsed.deinit();
    const v = parsed.value.object;
    const address = v.get("address").?.string;

    var routes = F040RoutingTransport{
        .address = address,
        .unspent_body = v.get("unspentBody").?.string,
        .raw_tx_hex = v.get("rawTxHex").?.object,
    };
    var woc = WhatsOnChainProvider.init(allocator, .mainnet);
    defer woc.deinit();
    woc.setTransport(routes.transport());

    const utxos = try woc.provider().getUtxos(allocator, address);
    defer {
        for (utxos) |*u| u.deinit(allocator);
        allocator.free(utxos);
    }
    const expected = v.get("expected").?.array.items;
    try std.testing.expectEqual(expected.len, utxos.len);
    for (expected, utxos) |e, u| {
        try std.testing.expectEqualStrings(e.object.get("txid").?.string, u.txid);
        try std.testing.expectEqual(e.object.get("outputIndex").?.integer, @as(i64, u.output_index));
        try std.testing.expectEqual(e.object.get("satoshis").?.integer, u.satoshis);
        try std.testing.expectEqualStrings(e.object.get("script").?.string, u.script);
    }
}

test "F-040 getUtxos rejection vectors" {
    const allocator = std.testing.allocator;
    var parsed = try f040LoadVectors(allocator);
    defer parsed.deinit();
    const v = parsed.value.object;
    const address = v.get("address").?.string;

    for (v.get("rejection_vectors").?.array.items) |rv| {
        const name = rv.object.get("name").?.string;
        var routes = F040RoutingTransport{
            .address = address,
            .unspent_body = rv.object.get("unspentBody").?.string,
            .raw_tx_hex = rv.object.get("rawTxHex").?.object,
        };
        var woc = WhatsOnChainProvider.init(allocator, .mainnet);
        defer woc.deinit();
        woc.setTransport(routes.transport());

        const want: provider_mod.ProviderError = if (std.mem.eql(u8, name, "raw-tx-unavailable"))
            provider_mod.ProviderError.NotFound
        else
            provider_mod.ProviderError.NetworkError;
        if (woc.provider().getUtxos(allocator, address)) |utxos| {
            for (utxos) |*u| u.deinit(allocator);
            allocator.free(utxos);
            std.debug.print("F-040 {s}: expected {s}, got UTXOs\n", .{ name, @errorName(want) });
            return error.TestExpectedError;
        } else |err| {
            try std.testing.expectEqual(want, err);
        }
    }
}
