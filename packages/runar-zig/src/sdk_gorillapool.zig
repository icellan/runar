const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const errors_mod = @import("sdk_errors.zig");
const bsvz = @import("bsvz");

// ---------------------------------------------------------------------------
// GorillaPoolProvider -- HTTP-based 1sat Ordinals provider
// ---------------------------------------------------------------------------
//
// Implements the standard Provider interface using the GorillaPool 1sat
// Ordinals REST API. HTTP transport is injected (same pattern as
// sdk_rpc_provider / sdk_woc_provider) so tests can exercise the request
// shape without opening sockets — which was the blocker under zig 0.16's
// Io-based std.http.Client.
//
// Endpoints:
//   Mainnet: https://ordinals.gorillapool.io/api/
//   Testnet: https://testnet.ordinals.gorillapool.io/api/
// ---------------------------------------------------------------------------

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

pub const GorillaPoolProvider = struct {
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

    /// Inject a concrete HTTP transport. Tests use MockHttpTransport; production
    /// callers supply an Io-backed transport built against std.http.Client.
    pub fn setTransport(self: *GorillaPoolProvider, transport: HttpTransport) void {
        self.transport = transport;
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
    // HTTP helpers (delegate to injected transport)
    // -----------------------------------------------------------------------

    fn httpGet(self: *GorillaPoolProvider, allocator: std.mem.Allocator, path: []const u8) provider_mod.ProviderError![]u8 {
        const transport = self.transport orelse return provider_mod.ProviderError.NetworkError;
        const url = std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.base_url, path }) catch return provider_mod.ProviderError.OutOfMemory;
        defer self.allocator.free(url);
        return transport.get(transport.ctx, allocator, url);
    }

    fn httpPost(self: *GorillaPoolProvider, allocator: std.mem.Allocator, path: []const u8, json_body: []const u8) provider_mod.ProviderError![]u8 {
        const transport = self.transport orelse return provider_mod.ProviderError.NetworkError;
        const url = std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.base_url, path }) catch return provider_mod.ProviderError.OutOfMemory;
        defer self.allocator.free(url);
        return transport.post(transport.ctx, allocator, url, "application/json", json_body);
    }

    // -----------------------------------------------------------------------
    // Path helpers (exposed for testing request shape)
    // -----------------------------------------------------------------------

    pub fn buildTxPath(self: *GorillaPoolProvider, allocator: std.mem.Allocator, txid: []const u8) provider_mod.ProviderError![]u8 {
        _ = self;
        return std.fmt.allocPrint(allocator, "/tx/{s}", .{txid}) catch return provider_mod.ProviderError.OutOfMemory;
    }

    pub fn buildUtxosPath(self: *GorillaPoolProvider, allocator: std.mem.Allocator, address: []const u8) provider_mod.ProviderError![]u8 {
        _ = self;
        return std.fmt.allocPrint(allocator, "/address/{s}/utxos", .{address}) catch return provider_mod.ProviderError.OutOfMemory;
    }

    pub fn buildBroadcastBody(self: *GorillaPoolProvider, allocator: std.mem.Allocator, tx_hex: []const u8) provider_mod.ProviderError![]u8 {
        _ = self;
        return std.fmt.allocPrint(allocator, "{{\"rawTx\":\"{s}\"}}", .{tx_hex}) catch return provider_mod.ProviderError.OutOfMemory;
    }

    // -----------------------------------------------------------------------
    // VTable implementations
    // -----------------------------------------------------------------------

    /// Fetch a transaction via GET /tx/{txid}/raw (the bare serialized tx).
    /// Each output's satoshis is read from its 8-byte little-endian field, so
    /// values are exact (F-027: the former JSON `vout[].value` decode with its
    /// float→×1e8 rule targeted a field GorillaPool never returns). The body
    /// must hash to the requested txid; a mismatch or an unparseable body is
    /// reported as NetworkError (the provider's decode-failure error).
    fn getTransactionImpl(ctx: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) provider_mod.ProviderError!types.TransactionData {
        const self: *GorillaPoolProvider = @ptrCast(@alignCast(ctx));

        const path = std.fmt.allocPrint(self.allocator, "/tx/{s}/raw", .{txid}) catch return provider_mod.ProviderError.OutOfMemory;
        defer self.allocator.free(path);

        const body = try self.httpGet(allocator, path);
        defer allocator.free(body);

        var digest = bsvz.crypto.hash.hash256(body).bytes;
        std.mem.reverse(u8, &digest);
        const body_txid = std.fmt.bytesToHex(digest, .lower);
        if (!std.ascii.eqlIgnoreCase(&body_txid, txid)) return provider_mod.ProviderError.NetworkError;

        const tx = bsvz.transaction.Transaction.parse(allocator, body) catch |err| switch (err) {
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

        return .{
            .txid = allocator.dupe(u8, &body_txid) catch return provider_mod.ProviderError.OutOfMemory,
            .version = tx.version,
            .inputs = inputs,
            .outputs = outputs,
            .locktime = tx.lock_time,
            .raw = try hexAlloc(allocator, body),
        };
    }

    fn hexAlloc(allocator: std.mem.Allocator, bytes: []const u8) provider_mod.ProviderError![]u8 {
        const out = allocator.alloc(u8, bytes.len * 2) catch return provider_mod.ProviderError.OutOfMemory;
        _ = bsvz.primitives.hex.encodeLower(bytes, out) catch unreachable;
        return out;
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

                // DoS-bound: reject pathological scripts at provider boundary.
                if (script.len > 0) {
                    var ctx_buf: [256]u8 = undefined;
                    const c = std.fmt.bufPrint(&ctx_buf, "GorillaPoolProvider.getUtxos({s})", .{address}) catch "GorillaPoolProvider.getUtxos";
                    errors_mod.assertScriptHexUnderLimit(script, errors_mod.MAX_SCRIPT_BYTES, c) catch return provider_mod.ProviderError.ScriptSizeExceeded;
                }
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

        if (script.len > 0) {
            var ctx_buf: [256]u8 = undefined;
            const c = std.fmt.bufPrint(&ctx_buf, "GorillaPoolProvider.getContractUtxo({s})", .{script_hash}) catch "GorillaPoolProvider.getContractUtxo";
            errors_mod.assertScriptHexUnderLimit(script, errors_mod.MAX_SCRIPT_BYTES, c) catch return provider_mod.ProviderError.ScriptSizeExceeded;
        }

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

test "GorillaPoolProvider buildTxPath and buildUtxosPath shape" {
    const allocator = std.testing.allocator;
    var gp = GorillaPoolProvider.init(allocator, .mainnet);
    defer gp.deinit();

    const p1 = try gp.buildTxPath(allocator, "deadbeef");
    defer allocator.free(p1);
    try std.testing.expectEqualStrings("/tx/deadbeef", p1);

    const p2 = try gp.buildUtxosPath(allocator, "1abc");
    defer allocator.free(p2);
    try std.testing.expectEqualStrings("/address/1abc/utxos", p2);

    const body = try gp.buildBroadcastBody(allocator, "0100deadbeef");
    defer allocator.free(body);
    try std.testing.expectEqualStrings("{\"rawTx\":\"0100deadbeef\"}", body);
}

test "GorillaPoolProvider broadcast via mock transport strips quotes" {
    const allocator = std.testing.allocator;
    var mock = MockHttpTransport.init(allocator, "\"abcd1234\"");
    defer mock.deinit();

    var gp = GorillaPoolProvider.init(allocator, .mainnet);
    defer gp.deinit();
    gp.setTransport(mock.transport());

    const prov = gp.provider();
    const txid = try prov.broadcast(allocator, "0100deadbeef");
    defer allocator.free(txid);
    try std.testing.expectEqualStrings("abcd1234", txid);

    // Verify request shape
    try std.testing.expect(std.mem.endsWith(u8, mock.last_url, "/tx"));
    try std.testing.expect(std.mem.indexOf(u8, mock.last_body, "\"rawTx\":\"0100deadbeef\"") != null);
    try std.testing.expectEqualStrings("application/json", mock.last_content_type);
    try std.testing.expectEqualStrings("POST", mock.method);
}

// ---------------------------------------------------------------------------
// F-027: getTransaction decodes the real GorillaPool response.
//
// GET /tx/{txid} is binary, not the JSON `vout[].value` the old decoder (with
// its float→×1e8 / integer→as-is rule) expected. getTransaction now fetches
// /tx/{txid}/raw and reads each output's 8-byte LE satoshis from the raw tx.
// Proves: the shared recorded vectors (conformance/sdk-gorillapool) decode
// exactly — a real 1-sat inscription output is 1 sat; 999/1000/1e12/2.1e15
// exact — and a body hashing to another txid is rejected (NetworkError, the
// provider's decode-failure error). Does NOT prove the live API still serves
// /tx/{txid}/raw (recorded 2026-09-27).
// ---------------------------------------------------------------------------

const GP_VECTORS_REL_PATH = "../../conformance/sdk-gorillapool/vectors.json";

fn f027LoadVectors(allocator: std.mem.Allocator) !std.json.Parsed(std.json.Value) {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, GP_VECTORS_REL_PATH, allocator, .limited(4 * 1024 * 1024));
    defer allocator.free(bytes);
    return std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always });
}

fn f027Sha256Hex(allocator: std.mem.Allocator, hex_text: []const u8) ![64]u8 {
    const bytes = try allocator.alloc(u8, hex_text.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, hex_text);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn f027FreeTx(allocator: std.mem.Allocator, tx: *types.TransactionData) void {
    for (tx.inputs) |inp| {
        allocator.free(inp.txid);
        allocator.free(inp.script);
    }
    for (tx.outputs) |out| allocator.free(out.script);
    tx.deinit(allocator);
}

test "F-027 getTransaction decodes the recorded raw-tx vectors exactly" {
    const allocator = std.testing.allocator;
    var parsed = try f027LoadVectors(allocator);
    defer parsed.deinit();
    const vectors = parsed.value.object.get("vectors").?.array.items;
    try std.testing.expect(vectors.len >= 3);

    for (vectors) |v| {
        const txid = v.object.get("txid").?.string;
        const resp_hex = v.object.get("responseHex").?.string;
        const exp = v.object.get("expected").?.object;
        const body = try allocator.alloc(u8, resp_hex.len / 2);
        defer allocator.free(body);
        _ = try std.fmt.hexToBytes(body, resp_hex);

        var mock = MockHttpTransport.init(allocator, body);
        defer mock.deinit();
        var gp = GorillaPoolProvider.init(allocator, .mainnet);
        defer gp.deinit();
        gp.setTransport(mock.transport());

        var tx = try gp.provider().getTransaction(allocator, txid);
        defer f027FreeTx(allocator, &tx);

        const want_url = try std.fmt.allocPrint(allocator, "https://ordinals.gorillapool.io/api/tx/{s}/raw", .{txid});
        defer allocator.free(want_url);
        try std.testing.expectEqualStrings(want_url, mock.last_url);

        try std.testing.expectEqualStrings(txid, tx.txid);
        try std.testing.expectEqual(exp.get("version").?.integer, @as(i64, tx.version));
        try std.testing.expectEqual(exp.get("locktime").?.integer, @as(i64, tx.locktime));
        try std.testing.expectEqualStrings(resp_hex, tx.raw);
        try std.testing.expectEqual(@as(usize, @intCast(exp.get("inputCount").?.integer)), tx.inputs.len);

        const fi = exp.get("firstInput").?.object;
        const in0 = tx.inputs[0];
        try std.testing.expectEqualStrings(fi.get("txid").?.string, in0.txid);
        try std.testing.expectEqual(fi.get("outputIndex").?.integer, @as(i64, in0.output_index));
        try std.testing.expectEqual(fi.get("sequence").?.integer, @as(i64, in0.sequence));
        try std.testing.expectEqual(@as(usize, @intCast(2 * fi.get("scriptLen").?.integer)), in0.script.len);
        const in0_sha = try f027Sha256Hex(allocator, in0.script);
        try std.testing.expectEqualStrings(fi.get("scriptSha256").?.string, &in0_sha);

        const outs = exp.get("outputs").?.array.items;
        try std.testing.expectEqual(outs.len, tx.outputs.len);
        for (outs, tx.outputs) |want, got| {
            try std.testing.expectEqual(want.object.get("satoshis").?.integer, got.satoshis);
            try std.testing.expectEqual(@as(usize, @intCast(2 * want.object.get("scriptLen").?.integer)), got.script.len);
            const sha = try f027Sha256Hex(allocator, got.script);
            try std.testing.expectEqualStrings(want.object.get("scriptSha256").?.string, &sha);
        }
    }
}

test "F-027 getTransaction rejects a body that hashes to another txid" {
    const allocator = std.testing.allocator;
    var parsed = try f027LoadVectors(allocator);
    defer parsed.deinit();
    const vectors = parsed.value.object.get("vectors").?.array.items;
    for (parsed.value.object.get("rejection_vectors").?.array.items) |rv| {
        const requested = rv.object.get("requestedTxid").?.string;
        const source_name = rv.object.get("responseOf").?.string;
        var resp_hex: []const u8 = "";
        for (vectors) |v| {
            if (std.mem.eql(u8, v.object.get("name").?.string, source_name)) resp_hex = v.object.get("responseHex").?.string;
        }
        const body = try allocator.alloc(u8, resp_hex.len / 2);
        defer allocator.free(body);
        _ = try std.fmt.hexToBytes(body, resp_hex);

        var mock = MockHttpTransport.init(allocator, body);
        defer mock.deinit();
        var gp = GorillaPoolProvider.init(allocator, .mainnet);
        defer gp.deinit();
        gp.setTransport(mock.transport());
        try std.testing.expectError(provider_mod.ProviderError.NetworkError, gp.provider().getTransaction(allocator, requested));
    }
}
