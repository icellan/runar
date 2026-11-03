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

    /// N-041: GET /tx/hash/{txid} has no "hex" field and reports values as
    /// float BTC, so raw was always empty. The serialized tx is fetched via
    /// GET /tx/{txid}/hex instead, its double-SHA256 must equal the txid, and
    /// inputs/outputs (with integer satoshis) are parsed from those bytes. A
    /// hash mismatch or an unparseable body is NetworkError.
    fn getTransactionImpl(ctx: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) provider_mod.ProviderError!types.TransactionData {
        const self: *WhatsOnChainProvider = @ptrCast(@alignCast(ctx));

        const raw = try self.fetchVerifiedRaw(allocator, txid);
        defer allocator.free(raw);
        const tx = bsvz.transaction.Transaction.parse(allocator, raw) catch |err| switch (err) {
            error.OutOfMemory => return provider_mod.ProviderError.OutOfMemory,
            else => return provider_mod.ProviderError.NetworkError,
        };
        defer tx.deinit(allocator);

        const inputs = allocator.alloc(types.TxInput, tx.inputs.len) catch return provider_mod.ProviderError.OutOfMemory;
        for (tx.inputs, 0..) |input, i| {
            var prev = input.previous_outpoint.txid.bytes;
            std.mem.reverse(u8, &prev);
            const prev_hex = std.fmt.bytesToHex(prev, .lower);
            inputs[i] = .{
                .txid = allocator.dupe(u8, &prev_hex) catch return provider_mod.ProviderError.OutOfMemory,
                .output_index = @bitCast(input.previous_outpoint.index),
                .script = try hexAlloc(allocator, input.unlocking_script.bytes),
                .sequence = input.sequence,
            };
        }

        const outputs = allocator.alloc(types.TxOutput, tx.outputs.len) catch return provider_mod.ProviderError.OutOfMemory;
        for (tx.outputs, 0..) |output, i| {
            outputs[i] = .{
                .satoshis = output.satoshis,
                .script = try hexAlloc(allocator, output.locking_script.bytes),
            };
        }

        const txid_lower = std.ascii.allocLowerString(allocator, txid) catch return provider_mod.ProviderError.OutOfMemory;
        return .{
            .txid = txid_lower,
            .version = tx.version,
            .inputs = inputs,
            .outputs = outputs,
            .locktime = tx.lock_time,
            .raw = try hexAlloc(allocator, raw),
        };
    }

    fn hexAlloc(allocator: std.mem.Allocator, bytes: []const u8) provider_mod.ProviderError![]u8 {
        const out = allocator.alloc(u8, bytes.len * 2) catch return provider_mod.ProviderError.OutOfMemory;
        _ = bsvz.primitives.hex.encodeLower(bytes, out) catch unreachable;
        return out;
    }

    /// GET /tx/{txid}/hex and require its double-SHA256 (reversed) to equal
    /// txid (F-040 / N-041). Returns the owned raw bytes.
    fn fetchVerifiedRaw(self: *WhatsOnChainProvider, allocator: std.mem.Allocator, txid: []const u8) provider_mod.ProviderError![]u8 {
        const raw_hex = try getRawTransactionImpl(@ptrCast(self), allocator, txid);
        defer allocator.free(raw_hex);
        const raw = bsvz.primitives.hex.decode(allocator, raw_hex) catch |err| switch (err) {
            error.OutOfMemory => return provider_mod.ProviderError.OutOfMemory,
            else => return provider_mod.ProviderError.NetworkError,
        };
        errdefer allocator.free(raw);

        var digest = bsvz.crypto.hash.hash256(raw).bytes;
        std.mem.reverse(u8, &digest);
        const body_txid = std.fmt.bytesToHex(digest, .lower);
        if (!std.ascii.eqlIgnoreCase(&body_txid, txid)) return provider_mod.ProviderError.NetworkError;
        return raw;
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
    ///
    /// Note: WoC caps this legacy listing at about 1000 entries, so an
    /// address holding more UTXOs is returned truncated.
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
        const raw = try self.fetchVerifiedRaw(allocator, txid);
        defer allocator.free(raw);

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

    /// N-041: WoC's GET /script/{scriptHash}/unspent listing (a legacy
    /// array, or a {script, result} object on the /unspent/all family)
    /// carries outpoints and values but no locking script. The first entry's
    /// tx is fetched via GET /tx/{txid}/hex and hash-verified; tx_pos must be
    /// an output whose value equals the listed value, whose script is
    /// non-empty and hashes (sha256, reversed: WoC's scripthash) to
    /// `script_hash`. A malformed listing or any of those failures is
    /// NetworkError; an empty listing or a 404 listing is null.
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

        const items = switch (parsed.value) {
            .array => |a| a.items,
            .object => |o| blk: {
                const r = o.get("result") orelse return provider_mod.ProviderError.NetworkError;
                if (r != .array) return provider_mod.ProviderError.NetworkError;
                break :blk r.array.items;
            },
            else => return provider_mod.ProviderError.NetworkError,
        };
        if (items.len == 0) return null;

        const first = items[0];
        if (first != .object) return provider_mod.ProviderError.NetworkError;
        const obj = first.object;
        const tx_hash_v = obj.get("tx_hash") orelse return provider_mod.ProviderError.NetworkError;
        const tx_pos_v = obj.get("tx_pos") orelse return provider_mod.ProviderError.NetworkError;
        const value_v = obj.get("value") orelse return provider_mod.ProviderError.NetworkError;
        if (tx_hash_v != .string or tx_pos_v != .integer or value_v != .integer) return provider_mod.ProviderError.NetworkError;
        if (tx_pos_v.integer < 0 or tx_pos_v.integer > std.math.maxInt(i32)) return provider_mod.ProviderError.NetworkError;
        const tx_hash = tx_hash_v.string;
        const tx_pos: usize = @intCast(tx_pos_v.integer);
        const value: i64 = value_v.integer;

        const script = try self.fetchOutputScript(allocator, tx_hash, tx_pos, value);
        errdefer allocator.free(script);

        const script_bytes = bsvz.primitives.hex.decode(allocator, script) catch |err| switch (err) {
            error.OutOfMemory => return provider_mod.ProviderError.OutOfMemory,
            else => return provider_mod.ProviderError.NetworkError,
        };
        defer allocator.free(script_bytes);
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(script_bytes, &h, .{});
        std.mem.reverse(u8, &h);
        const got = std.fmt.bytesToHex(h, .lower);
        if (!std.ascii.eqlIgnoreCase(&got, script_hash)) return provider_mod.ProviderError.NetworkError;

        const c = std.fmt.allocPrint(allocator, "WhatsOnChainProvider.getContractUtxo({s})", .{script_hash}) catch return provider_mod.ProviderError.OutOfMemory;
        defer allocator.free(c);
        errors_mod.assertScriptHexUnderLimit(script, errors_mod.MAX_SCRIPT_BYTES, c) catch return provider_mod.ProviderError.ScriptSizeExceeded;

        return .{
            .txid = allocator.dupe(u8, tx_hash) catch return provider_mod.ProviderError.OutOfMemory,
            .output_index = @intCast(tx_pos),
            .satoshis = value,
            .script = script,
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

// ---------------------------------------------------------------------------
// N-041: getContractUtxo returned script "" (WoC's /script/{h}/unspent
// listing has no locking script) and getTransaction read /tx/hash/{txid},
// whose JSON has no "hex" field (raw was always empty) and float values.
// Proves, with conformance/sdk-woc/contract-utxo-tx-vectors.json and a stub
// transport: getContractUtxo returns the real script for the legacy array and
// the {script,result} object listing, null for an empty listing / 404, and a
// txid mismatch, a missing output, a value mismatch, a script hashing to
// another scripthash and an empty script fail with NetworkError (the
// provider's decode-failure error) and an unavailable tx with NotFound;
// getTransaction returns the hash-verified hex as raw, parses inputs/outputs
// from it with exact 21e14-scale satoshis, and refuses a body for another
// txid. Does NOT prove the live API keeps these shapes (recorded 2026-09-29),
// nor which NetworkError cause fired (Zig errors carry no message).
// ---------------------------------------------------------------------------

const N041_VECTORS_REL_PATH = "../../conformance/sdk-woc/contract-utxo-tx-vectors.json";

fn n041LoadVectors(allocator: std.mem.Allocator) !std.json.Parsed(std.json.Value) {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, N041_VECTORS_REL_PATH, allocator, .limited(4 * 1024 * 1024));
    defer allocator.free(bytes);
    return std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always });
}

/// Serves `listing` at /script/{script_hash}/unspent (when non-null), each raw
/// tx at /tx/{txid}/hex, and `hash_body` at /tx/hash/{hash_txid}; NotFound
/// otherwise.
const N041RoutingTransport = struct {
    script_hash: []const u8 = "",
    listing: ?[]const u8 = null,
    raw_tx_hex: ?std.json.ObjectMap = null,
    hex_txid: []const u8 = "",
    hex_body: ?[]const u8 = null,
    hash_body: ?[]const u8 = null,

    fn getFn(ctx: *anyopaque, allocator: std.mem.Allocator, url: []const u8) provider_mod.ProviderError![]u8 {
        const self: *N041RoutingTransport = @ptrCast(@alignCast(ctx));
        const base = "https://api.whatsonchain.com/v1/bsv/main";
        if (!std.mem.startsWith(u8, url, base)) return provider_mod.ProviderError.NotFound;
        const path = url[base.len..];
        if (self.listing) |l| {
            if (std.mem.startsWith(u8, path, "/script/") and std.mem.endsWith(u8, path, "/unspent") and
                std.mem.eql(u8, path["/script/".len .. path.len - "/unspent".len], self.script_hash))
            {
                return allocator.dupe(u8, l) catch provider_mod.ProviderError.OutOfMemory;
            }
        }
        if (std.mem.startsWith(u8, path, "/tx/hash/")) {
            if (self.hash_body) |h| {
                if (std.mem.eql(u8, path["/tx/hash/".len..], self.hex_txid))
                    return allocator.dupe(u8, h) catch provider_mod.ProviderError.OutOfMemory;
            }
            return provider_mod.ProviderError.NotFound;
        }
        if (std.mem.startsWith(u8, path, "/tx/") and std.mem.endsWith(u8, path, "/hex")) {
            const txid = path["/tx/".len .. path.len - "/hex".len];
            if (self.raw_tx_hex) |m| {
                if (m.get(txid)) |v| return allocator.dupe(u8, v.string) catch provider_mod.ProviderError.OutOfMemory;
            }
            if (self.hex_body) |h| {
                if (std.mem.eql(u8, txid, self.hex_txid))
                    return allocator.dupe(u8, h) catch provider_mod.ProviderError.OutOfMemory;
            }
        }
        return provider_mod.ProviderError.NotFound;
    }

    fn postFn(_: *anyopaque, _: std.mem.Allocator, _: []const u8, _: []const u8, _: []const u8) provider_mod.ProviderError![]u8 {
        return provider_mod.ProviderError.NetworkError;
    }

    fn transport(self: *N041RoutingTransport) HttpTransport {
        return .{ .ctx = @ptrCast(self), .get = N041RoutingTransport.getFn, .post = N041RoutingTransport.postFn };
    }
};

fn n041OptString(v: ?std.json.Value) ?[]const u8 {
    const x = v orelse return null;
    return if (x == .string) x.string else null;
}

fn n041FreeTx(allocator: std.mem.Allocator, tx: *types.TransactionData) void {
    for (tx.inputs) |inp| {
        allocator.free(inp.txid);
        allocator.free(inp.script);
    }
    for (tx.outputs) |out| allocator.free(out.script);
    tx.deinit(allocator);
}

test "N-041 getContractUtxo returns the real locking script" {
    const allocator = std.testing.allocator;
    var parsed = try n041LoadVectors(allocator);
    defer parsed.deinit();
    const cu = parsed.value.object.get("contractUtxo").?.object;
    const sh = cu.get("scriptHash").?.string;

    const cases = [_][2][]const u8{
        .{ "legacyBody", "expectedLegacy" },
        .{ "objectBody", "expectedObject" },
    };
    for (cases) |c| {
        var routes = N041RoutingTransport{
            .script_hash = sh,
            .listing = cu.get(c[0]).?.string,
            .raw_tx_hex = cu.get("rawTxHex").?.object,
        };
        var woc = WhatsOnChainProvider.init(allocator, .mainnet);
        defer woc.deinit();
        woc.setTransport(routes.transport());

        var u = (try woc.provider().getContractUtxo(allocator, sh)) orelse return error.TestExpectedUtxo;
        defer u.deinit(allocator);
        const e = cu.get(c[1]).?.object;
        try std.testing.expectEqualStrings(e.get("txid").?.string, u.txid);
        try std.testing.expectEqual(e.get("outputIndex").?.integer, @as(i64, u.output_index));
        try std.testing.expectEqual(e.get("satoshis").?.integer, u.satoshis);
        try std.testing.expectEqualStrings(e.get("script").?.string, u.script);
    }

    for (cu.get("null_vectors").?.array.items) |nv| {
        var routes = N041RoutingTransport{ .script_hash = sh, .listing = n041OptString(nv.object.get("body")) };
        var woc = WhatsOnChainProvider.init(allocator, .mainnet);
        defer woc.deinit();
        woc.setTransport(routes.transport());
        if (try woc.provider().getContractUtxo(allocator, sh)) |got| {
            var g = got;
            g.deinit(allocator);
            std.debug.print("N-041 {s}: expected null\n", .{nv.object.get("name").?.string});
            return error.TestExpectedNull;
        }
    }
}

test "N-041 getContractUtxo rejection vectors" {
    const allocator = std.testing.allocator;
    var parsed = try n041LoadVectors(allocator);
    defer parsed.deinit();
    const cu = parsed.value.object.get("contractUtxo").?.object;

    for (cu.get("rejection_vectors").?.array.items) |rv| {
        const name = rv.object.get("name").?.string;
        const sh = rv.object.get("scriptHash").?.string;
        var routes = N041RoutingTransport{
            .script_hash = sh,
            .listing = rv.object.get("body").?.string,
            .raw_tx_hex = rv.object.get("rawTxHex").?.object,
        };
        var woc = WhatsOnChainProvider.init(allocator, .mainnet);
        defer woc.deinit();
        woc.setTransport(routes.transport());

        const want: provider_mod.ProviderError = if (std.mem.eql(u8, name, "raw-tx-unavailable"))
            provider_mod.ProviderError.NotFound
        else
            provider_mod.ProviderError.NetworkError;
        if (woc.provider().getContractUtxo(allocator, sh)) |got| {
            if (got) |u| {
                var g = u;
                g.deinit(allocator);
            }
            std.debug.print("N-041 {s}: expected {s}, got a result\n", .{ name, @errorName(want) });
            return error.TestExpectedError;
        } else |err| {
            try std.testing.expectEqual(want, err);
        }
    }
}

test "N-041 getTransaction parses the hash-verified raw tx" {
    const allocator = std.testing.allocator;
    var parsed = try n041LoadVectors(allocator);
    defer parsed.deinit();
    const gt = parsed.value.object.get("getTransaction").?.object;

    for (gt.get("cases").?.array.items) |c| {
        const txid = c.object.get("txid").?.string;
        var routes = N041RoutingTransport{
            .hex_txid = txid,
            .hex_body = c.object.get("rawTxHex").?.string,
            .hash_body = c.object.get("hashBody").?.string,
        };
        var woc = WhatsOnChainProvider.init(allocator, .mainnet);
        defer woc.deinit();
        woc.setTransport(routes.transport());

        var tx = try woc.provider().getTransaction(allocator, txid);
        defer n041FreeTx(allocator, &tx);
        const e = c.object.get("expected").?.object;
        try std.testing.expectEqualStrings(e.get("txid").?.string, tx.txid);
        try std.testing.expectEqual(e.get("version").?.integer, @as(i64, tx.version));
        try std.testing.expectEqual(e.get("locktime").?.integer, @as(i64, tx.locktime));
        try std.testing.expectEqualStrings(e.get("raw").?.string, tx.raw);
        const ins = e.get("inputs").?.array.items;
        try std.testing.expectEqual(ins.len, tx.inputs.len);
        for (ins, tx.inputs) |ei, i| {
            try std.testing.expectEqualStrings(ei.object.get("txid").?.string, i.txid);
            try std.testing.expectEqual(ei.object.get("outputIndex").?.integer, @as(i64, i.output_index));
            try std.testing.expectEqualStrings(ei.object.get("script").?.string, i.script);
            try std.testing.expectEqual(ei.object.get("sequence").?.integer, @as(i64, i.sequence));
        }
        const outs = e.get("outputs").?.array.items;
        try std.testing.expectEqual(outs.len, tx.outputs.len);
        for (outs, tx.outputs) |eo, o| {
            try std.testing.expectEqual(eo.object.get("satoshis").?.integer, o.satoshis);
            try std.testing.expectEqualStrings(eo.object.get("script").?.string, o.script);
        }
    }

    for (gt.get("rejection_vectors").?.array.items) |rv| {
        const name = rv.object.get("name").?.string;
        const txid = rv.object.get("txid").?.string;
        var routes = N041RoutingTransport{
            .hex_txid = txid,
            .hex_body = n041OptString(rv.object.get("rawTxHex")),
            .hash_body = n041OptString(rv.object.get("hashBody")),
        };
        var woc = WhatsOnChainProvider.init(allocator, .mainnet);
        defer woc.deinit();
        woc.setTransport(routes.transport());

        const want: provider_mod.ProviderError = if (std.mem.eql(u8, name, "raw-tx-unavailable"))
            provider_mod.ProviderError.NotFound
        else
            provider_mod.ProviderError.NetworkError;
        if (woc.provider().getTransaction(allocator, txid)) |got| {
            var t = got;
            n041FreeTx(allocator, &t);
            std.debug.print("N-041 {s}: expected {s}, got a tx\n", .{ name, @errorName(want) });
            return error.TestExpectedError;
        } else |err| {
            try std.testing.expectEqual(want, err);
        }
    }
}
