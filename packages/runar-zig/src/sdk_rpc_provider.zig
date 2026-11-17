const std = @import("std");
const bsvz = @import("bsvz");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const errors_mod = @import("sdk_errors.zig");

// ---------------------------------------------------------------------------
// RPCProvider — JSON-RPC provider for Bitcoin nodes
// ---------------------------------------------------------------------------
//
// Mirrors the Go RPCProvider (packages/runar-go/rpc_provider.go):
//   - getUtxos: listunspent [0, 9999999, [address]]; `amount` is BTC, rounded
//     to satoshis; every script is held to the MAX_SCRIPT_BYTES DoS bound.
//   - broadcast: sendrawtransaction; when auto_mine is set (initRegtest) one
//     block is mined afterwards with Go's fallback (`generate`, else
//     `getnewaddress` + `generatetoaddress`). A failed mine after an ACCEPTED
//     tx is an error (MineFailed), never a silent success: the tx is in the
//     mempool but the confirmation the caller relies on did not happen
//     (GK-BUG-004). TS's RPCProvider has no generatetoaddress fallback; Go's
//     is the one followed here.
//   - getRawTransaction / getTransaction: getrawtransaction (0 / parsed raw).
//   - The node's JSON-RPC `error` object is an error (RPCError), with its
//     code and message kept in lastError(); a reply that is not a JSON-RPC
//     object is InvalidResponse. Nothing is read with a hand-rolled scanner.
//
// R3-ZIG-RPC-STUB: this file used to be a stub. getUtxos always returned an
// empty slice, auto_mine was never read, getTransaction/getRawTransaction
// always said NotFound, and the hand-rolled `"result":` scanner ignored the
// `error` member, so a node refusing sendrawtransaction came back as the
// txid "null".
//
// The HTTP transport is a callback so this file compiles without
// std.http.Client and tests can script the node. A transport must hand back
// the body of a JSON-RPC error reply (SV Node sends it with HTTP 500) rather
// than failing the request; sdk_http_client.zig's transports do.

pub const RPCError = error{
    TransportError,
    ProtocolError,
    RPCError,
    OutOfMemory,
    InvalidResponse,
    /// sendrawtransaction accepted the tx, then the confirming mine failed.
    MineFailed,
    /// A UTXO's locking script exceeds errors_mod.MAX_SCRIPT_BYTES.
    ScriptSizeExceeded,
};

/// HttpTransport performs one POST with basic auth and returns the response body.
/// The implementation owns the returned buffer; the caller frees via `allocator`.
pub const HttpTransport = struct {
    ctx: *anyopaque,
    post: *const fn (
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        url: []const u8,
        user: []const u8,
        pass: []const u8,
        body: []const u8,
    ) RPCError![]u8,
};

/// RPCProvider holds JSON-RPC connection details and a pluggable HTTP transport.
pub const RPCProvider = struct {
    allocator: std.mem.Allocator,
    url: []const u8,
    user: []const u8,
    pass: []const u8,
    network: []const u8,
    auto_mine: bool = false,
    transport: ?HttpTransport = null,
    rpc_id: u64 = 0,
    /// The last JSON-RPC error the node returned (method, code, message), or
    /// the reason for MineFailed. Truncated into a fixed buffer.
    last_error_buf: [512]u8 = undefined,
    last_error_len: usize = 0,
    last_error_code: ?i64 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        url: []const u8,
        user: []const u8,
        pass: []const u8,
    ) RPCProvider {
        return .{
            .allocator = allocator,
            .url = url,
            .user = user,
            .pass = pass,
            .network = "testnet",
        };
    }

    /// Regtest-flavored constructor: auto-mines one block after each broadcast.
    pub fn initRegtest(
        allocator: std.mem.Allocator,
        url: []const u8,
        user: []const u8,
        pass: []const u8,
    ) RPCProvider {
        return .{
            .allocator = allocator,
            .url = url,
            .user = user,
            .pass = pass,
            .network = "regtest",
            .auto_mine = true,
        };
    }

    pub fn setTransport(self: *RPCProvider, transport: HttpTransport) void {
        self.transport = transport;
    }

    pub fn deinit(_: *RPCProvider) void {}

    /// "<method>: <node message>" for the last RPCError, or the MineFailed
    /// reason. Empty when no error has been recorded.
    pub fn lastError(self: *const RPCProvider) []const u8 {
        return self.last_error_buf[0..self.last_error_len];
    }

    fn setLastError(self: *RPCProvider, code: ?i64, comptime fmt: []const u8, args: anytype) void {
        const s = std.fmt.bufPrint(&self.last_error_buf, fmt, args) catch blk: {
            // Truncated: keep what fits.
            break :blk self.last_error_buf[0..];
        };
        self.last_error_len = s.len;
        self.last_error_code = code;
    }

    /// Build a JSON-RPC request body. Exposed for testing.
    pub fn buildRequestBody(
        self: *RPCProvider,
        allocator: std.mem.Allocator,
        method: []const u8,
        params_json: []const u8,
    ) RPCError![]u8 {
        self.rpc_id += 1;
        return std.fmt.allocPrint(
            allocator,
            "{{\"jsonrpc\":\"1.0\",\"id\":\"runar-{d}\",\"method\":\"{s}\",\"params\":{s}}}",
            .{ self.rpc_id, method, params_json },
        ) catch return RPCError.OutOfMemory;
    }

    /// Execute a JSON-RPC call, returning the `result` member re-serialized as
    /// JSON. The caller frees the returned buffer. The node's `error` member is
    /// RPCError (see lastError()); a reply that is not a JSON-RPC object, or
    /// has no `result`, is InvalidResponse.
    pub fn rpcCall(
        self: *RPCProvider,
        allocator: std.mem.Allocator,
        method: []const u8,
        params_json: []const u8,
    ) RPCError![]u8 {
        var parsed = try self.rpcCallParsed(allocator, method, params_json);
        defer parsed.deinit();
        const result = parsed.value.object.get("result") orelse return RPCError.InvalidResponse;
        return std.json.Stringify.valueAlloc(allocator, result, .{}) catch return RPCError.OutOfMemory;
    }

    /// rpcCall without re-serializing: the whole parsed reply, already
    /// checked to be an object whose `error` is null. Caller deinits.
    fn rpcCallParsed(
        self: *RPCProvider,
        allocator: std.mem.Allocator,
        method: []const u8,
        params_json: []const u8,
    ) RPCError!std.json.Parsed(std.json.Value) {
        const transport = self.transport orelse return RPCError.TransportError;
        const body = try self.buildRequestBody(allocator, method, params_json);
        defer allocator.free(body);
        const response = try transport.post(transport.ctx, allocator, self.url, self.user, self.pass, body);
        defer allocator.free(response);

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, response, .{}) catch |err| switch (err) {
            error.OutOfMemory => return RPCError.OutOfMemory,
            else => return RPCError.InvalidResponse,
        };
        errdefer parsed.deinit();
        if (parsed.value != .object) return RPCError.InvalidResponse;
        if (parsed.value.object.get("error")) |e| {
            if (e != .null) {
                var code: ?i64 = null;
                var msg: []const u8 = "";
                if (e == .object) {
                    if (e.object.get("code")) |c| {
                        if (c == .integer) code = c.integer;
                    }
                    if (e.object.get("message")) |m| {
                        if (m == .string) msg = m.string;
                    }
                }
                self.setLastError(code, "{s}: {s}", .{ method, msg });
                return RPCError.RPCError;
            }
        }
        return parsed;
    }

    /// Encode one string as a JSON string literal (escaped). Caller frees.
    fn jsonString(allocator: std.mem.Allocator, s: []const u8) RPCError![]u8 {
        return std.json.Stringify.valueAlloc(allocator, s, .{}) catch return RPCError.OutOfMemory;
    }

    /// Broadcast sends a transaction via sendrawtransaction. With auto_mine,
    /// one block is mined afterwards and a failed mine is MineFailed (the tx
    /// WAS accepted; lastError() names the txid and the mine failure).
    pub fn broadcast(self: *RPCProvider, allocator: std.mem.Allocator, tx_hex: []const u8) RPCError![]u8 {
        const quoted = try jsonString(allocator, tx_hex);
        defer allocator.free(quoted);
        const params = std.fmt.allocPrint(allocator, "[{s}]", .{quoted}) catch return RPCError.OutOfMemory;
        defer allocator.free(params);

        var parsed = try self.rpcCallParsed(allocator, "sendrawtransaction", params);
        defer parsed.deinit();
        const result = parsed.value.object.get("result") orelse return RPCError.InvalidResponse;
        if (result != .string) return RPCError.InvalidResponse;
        const txid = allocator.dupe(u8, result.string) catch return RPCError.OutOfMemory;
        errdefer allocator.free(txid);

        if (self.auto_mine) {
            self.last_error_len = 0;
            self.last_error_code = null;
            self.mine(allocator, 1) catch |err| switch (err) {
                error.OutOfMemory => return RPCError.OutOfMemory,
                else => {
                    var reason_buf: [400]u8 = undefined;
                    const reason = self.lastError();
                    const n = @min(reason.len, reason_buf.len);
                    @memcpy(reason_buf[0..n], reason[0..n]);
                    self.setLastError(self.last_error_code, "broadcast succeeded (txid {s}) but auto-mine failed: {s}", .{ txid, reason_buf[0..n] });
                    return RPCError.MineFailed;
                },
            };
        }
        return txid;
    }

    /// Mine `n` blocks: `generate`, falling back to `getnewaddress` +
    /// `generatetoaddress` (the Go RPCProvider's order).
    pub fn mine(self: *RPCProvider, allocator: std.mem.Allocator, n: u32) RPCError!void {
        const params = std.fmt.allocPrint(allocator, "[{d}]", .{n}) catch return RPCError.OutOfMemory;
        defer allocator.free(params);
        if (self.rpcCall(allocator, "generate", params)) |r| {
            allocator.free(r);
            return;
        } else |err| switch (err) {
            error.OutOfMemory => return RPCError.OutOfMemory,
            else => {},
        }

        var addr_reply = try self.rpcCallParsed(allocator, "getnewaddress", "[]");
        defer addr_reply.deinit();
        const addr_v = addr_reply.value.object.get("result") orelse return RPCError.InvalidResponse;
        if (addr_v != .string) return RPCError.InvalidResponse;
        const addr = try jsonString(allocator, addr_v.string);
        defer allocator.free(addr);
        const gen_params = std.fmt.allocPrint(allocator, "[{d},{s}]", .{ n, addr }) catch return RPCError.OutOfMemory;
        defer allocator.free(gen_params);
        const r = try self.rpcCall(allocator, "generatetoaddress", gen_params);
        allocator.free(r);
    }

    /// GetUtxos returns UTXOs for the given address using listunspent. Each
    /// returned UTXO owns its txid/script (free with UTXO.deinit).
    pub fn getUtxos(self: *RPCProvider, allocator: std.mem.Allocator, address: []const u8) RPCError![]types.UTXO {
        const quoted = try jsonString(allocator, address);
        defer allocator.free(quoted);
        const params = std.fmt.allocPrint(allocator, "[0,9999999,[{s}]]", .{quoted}) catch return RPCError.OutOfMemory;
        defer allocator.free(params);

        var parsed = try self.rpcCallParsed(allocator, "listunspent", params);
        defer parsed.deinit();
        const result = parsed.value.object.get("result") orelse return RPCError.InvalidResponse;
        if (result != .array) return RPCError.InvalidResponse;

        const items = result.array.items;
        var out = allocator.alloc(types.UTXO, items.len) catch return RPCError.OutOfMemory;
        var filled: usize = 0;
        errdefer {
            for (out[0..filled]) |*u| u.deinit(allocator);
            allocator.free(out);
        }
        for (items) |item| {
            if (item != .object) return RPCError.InvalidResponse;
            const obj = item.object;
            const txid_v = obj.get("txid") orelse return RPCError.InvalidResponse;
            const vout_v = obj.get("vout") orelse return RPCError.InvalidResponse;
            const amount_v = obj.get("amount") orelse return RPCError.InvalidResponse;
            const script_v = obj.get("scriptPubKey") orelse return RPCError.InvalidResponse;
            if (txid_v != .string or vout_v != .integer or script_v != .string) return RPCError.InvalidResponse;
            if (vout_v.integer < 0 or vout_v.integer > std.math.maxInt(i32)) return RPCError.InvalidResponse;
            const sats = btcToSatoshis(amount_v) orelse return RPCError.InvalidResponse;

            const ctx = std.fmt.allocPrint(allocator, "RPCProvider.getUtxos({s})", .{address}) catch return RPCError.OutOfMemory;
            defer allocator.free(ctx);
            errors_mod.assertScriptHexUnderLimit(script_v.string, errors_mod.MAX_SCRIPT_BYTES, ctx) catch return RPCError.ScriptSizeExceeded;

            const txid = allocator.dupe(u8, txid_v.string) catch return RPCError.OutOfMemory;
            errdefer allocator.free(txid);
            const script = allocator.dupe(u8, script_v.string) catch return RPCError.OutOfMemory;
            out[filled] = .{
                .txid = txid,
                .output_index = @intCast(vout_v.integer),
                .satoshis = sats,
                .script = script,
            };
            filled += 1;
        }
        return out;
    }

    /// getrawtransaction <txid> 0: the serialized transaction hex. Caller frees.
    pub fn getRawTransaction(self: *RPCProvider, allocator: std.mem.Allocator, txid: []const u8) RPCError![]u8 {
        const quoted = try jsonString(allocator, txid);
        defer allocator.free(quoted);
        const params = std.fmt.allocPrint(allocator, "[{s},0]", .{quoted}) catch return RPCError.OutOfMemory;
        defer allocator.free(params);
        var parsed = try self.rpcCallParsed(allocator, "getrawtransaction", params);
        defer parsed.deinit();
        const result = parsed.value.object.get("result") orelse return RPCError.InvalidResponse;
        if (result != .string) return RPCError.InvalidResponse;
        return allocator.dupe(u8, result.string) catch return RPCError.OutOfMemory;
    }

    /// Provider interface wrapper.
    pub fn provider(self: *RPCProvider) provider_mod.Provider {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
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

    /// RPC_INVALID_ADDRESS_OR_KEY: "No such mempool or blockchain transaction".
    const RPC_NOT_FOUND: i64 = -5;

    fn toProviderError(self: *RPCProvider, e: RPCError, not_found_ok: bool) provider_mod.ProviderError {
        return switch (e) {
            error.OutOfMemory => provider_mod.ProviderError.OutOfMemory,
            error.ScriptSizeExceeded => provider_mod.ProviderError.ScriptSizeExceeded,
            error.RPCError => if (not_found_ok and self.last_error_code != null and self.last_error_code.? == RPC_NOT_FOUND)
                provider_mod.ProviderError.NotFound
            else
                provider_mod.ProviderError.NetworkError,
            error.InvalidResponse, error.ProtocolError, error.TransportError, error.MineFailed => provider_mod.ProviderError.NetworkError,
        };
    }

    /// getrawtransaction, then the serialized bytes parsed (the WhatsOnChain
    /// provider's approach), so satoshis are exact integers rather than a
    /// verbose reply's float BTC. A node's not-found answer is NotFound.
    fn getTransactionImpl(ctx: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) provider_mod.ProviderError!types.TransactionData {
        const self: *RPCProvider = @ptrCast(@alignCast(ctx));
        const raw_hex = self.getRawTransaction(allocator, txid) catch |e| return self.toProviderError(e, true);
        errdefer allocator.free(raw_hex);
        const raw = bsvz.primitives.hex.decode(allocator, raw_hex) catch |err| switch (err) {
            error.OutOfMemory => return provider_mod.ProviderError.OutOfMemory,
            else => return provider_mod.ProviderError.NetworkError,
        };
        defer allocator.free(raw);
        const tx = bsvz.transaction.Transaction.parse(allocator, raw) catch |err| switch (err) {
            error.OutOfMemory => return provider_mod.ProviderError.OutOfMemory,
            else => return provider_mod.ProviderError.NetworkError,
        };
        defer tx.deinit(allocator);

        const outputs = allocator.alloc(types.TxOutput, tx.outputs.len) catch return provider_mod.ProviderError.OutOfMemory;
        for (tx.outputs, 0..) |output, i| {
            const script = allocator.alloc(u8, output.locking_script.bytes.len * 2) catch return provider_mod.ProviderError.OutOfMemory;
            _ = bsvz.primitives.hex.encodeLower(output.locking_script.bytes, script) catch unreachable;
            outputs[i] = .{ .satoshis = output.satoshis, .script = script };
        }
        return .{
            .txid = allocator.dupe(u8, txid) catch return provider_mod.ProviderError.OutOfMemory,
            .version = tx.version,
            .outputs = outputs,
            .locktime = tx.lock_time,
            .raw = raw_hex,
        };
    }

    fn broadcastImpl(ctx: *anyopaque, allocator: std.mem.Allocator, tx_hex: []const u8) provider_mod.ProviderError![]u8 {
        const self: *RPCProvider = @ptrCast(@alignCast(ctx));
        return self.broadcast(allocator, tx_hex) catch |e| switch (e) {
            error.OutOfMemory => provider_mod.ProviderError.OutOfMemory,
            error.RPCError, error.InvalidResponse, error.ProtocolError, error.MineFailed, error.ScriptSizeExceeded => provider_mod.ProviderError.BroadcastFailed,
            error.TransportError => provider_mod.ProviderError.NetworkError,
        };
    }

    fn getUtxosImpl(ctx: *anyopaque, allocator: std.mem.Allocator, address: []const u8) provider_mod.ProviderError![]types.UTXO {
        const self: *RPCProvider = @ptrCast(@alignCast(ctx));
        return self.getUtxos(allocator, address) catch |e| self.toProviderError(e, false);
    }

    fn getContractUtxoImpl(_: *anyopaque, _: std.mem.Allocator, _: []const u8) provider_mod.ProviderError!?types.UTXO {
        // Not implemented for RPCProvider, as in Go (GetContractUtxo) and TS.
        return null;
    }

    fn getNetworkImpl(ctx: *anyopaque) []const u8 {
        const self: *RPCProvider = @ptrCast(@alignCast(ctx));
        return self.network;
    }

    fn getFeeRateImpl(_: *anyopaque) provider_mod.ProviderError!i64 {
        return 100;
    }

    fn getRawTransactionImpl(ctx: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) provider_mod.ProviderError![]u8 {
        const self: *RPCProvider = @ptrCast(@alignCast(ctx));
        return self.getRawTransaction(allocator, txid) catch |e| self.toProviderError(e, true);
    }
};

/// listunspent `amount` is BTC (a float, or an integer for whole coins).
/// Returns satoshis, or null for anything that is not a non-negative amount.
fn btcToSatoshis(v: std.json.Value) ?i64 {
    const btc: f64 = switch (v) {
        .float => |f| f,
        .integer => |i| @floatFromInt(i),
        else => return null,
    };
    if (!std.math.isFinite(btc) or btc < 0 or btc > 21_000_000) return null;
    return @intFromFloat(@round(btc * 1e8));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const MockTransport = struct {
    last_url: []const u8 = &.{},
    last_user: []const u8 = &.{},
    last_pass: []const u8 = &.{},
    last_body: []u8 = &.{},
    allocator: std.mem.Allocator,
    response: []const u8,

    fn init(allocator: std.mem.Allocator, response: []const u8) MockTransport {
        return .{ .allocator = allocator, .response = response };
    }

    fn deinit(self: *MockTransport) void {
        if (self.last_body.len > 0) self.allocator.free(self.last_body);
    }

    fn post(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        url: []const u8,
        user: []const u8,
        pass: []const u8,
        body: []const u8,
    ) RPCError![]u8 {
        const self: *MockTransport = @ptrCast(@alignCast(ctx));
        self.last_url = url;
        self.last_user = user;
        self.last_pass = pass;
        if (self.last_body.len > 0) self.allocator.free(self.last_body);
        self.last_body = self.allocator.dupe(u8, body) catch return RPCError.OutOfMemory;
        return allocator.dupe(u8, self.response) catch return RPCError.OutOfMemory;
    }

    fn transport(self: *MockTransport) HttpTransport {
        return .{ .ctx = @ptrCast(self), .post = MockTransport.post };
    }
};

/// A scripted node: answers each JSON-RPC method from a table and records the
/// methods it was asked for, in order. An unlisted method gets the node's
/// method-not-found error.
const ScriptedNode = struct {
    const Answer = struct { method: []const u8, reply: []const u8 };
    answers: []const Answer,
    calls: [16][]const u8 = undefined,
    n_calls: usize = 0,

    fn post(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        _: []const u8,
        _: []const u8,
        _: []const u8,
        body: []const u8,
    ) RPCError![]u8 {
        const self: *ScriptedNode = @ptrCast(@alignCast(ctx));
        for (self.answers) |a| {
            var needle_buf: [64]u8 = undefined;
            const needle = std.fmt.bufPrint(&needle_buf, "\"method\":\"{s}\"", .{a.method}) catch unreachable;
            if (std.mem.indexOf(u8, body, needle) != null) {
                if (self.n_calls < self.calls.len) self.calls[self.n_calls] = a.method;
                self.n_calls += 1;
                return allocator.dupe(u8, a.reply) catch return RPCError.OutOfMemory;
            }
        }
        if (self.n_calls < self.calls.len) self.calls[self.n_calls] = "?";
        self.n_calls += 1;
        return allocator.dupe(u8, "{\"result\":null,\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":\"x\"}") catch return RPCError.OutOfMemory;
    }

    fn transport(self: *ScriptedNode) HttpTransport {
        return .{ .ctx = @ptrCast(self), .post = ScriptedNode.post };
    }

    fn called(self: *const ScriptedNode) []const []const u8 {
        return self.calls[0..@min(self.n_calls, self.calls.len)];
    }
};

const TXID = "abababababababababababababababababababababababababababababababab";
const P2PKH_SCRIPT = "76a914000000000000000000000000000000000000000088ac";

fn expectCalls(node: *const ScriptedNode, want: []const []const u8) !void {
    const got = node.called();
    if (got.len != want.len) {
        std.debug.print("calls: got {d} {any}, want {d}\n", .{ got.len, got, want.len });
        return error.TestUnexpectedResult;
    }
    for (got, want) |g, w| try std.testing.expectEqualStrings(w, g);
}

test "RPCProvider buildRequestBody produces well-formed JSON" {
    const allocator = std.testing.allocator;
    var rpc = RPCProvider.init(allocator, "http://localhost:18443", "user", "pass");
    defer rpc.deinit();
    const body = try rpc.buildRequestBody(allocator, "getblockcount", "[]");
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"jsonrpc\":\"1.0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"method\":\"getblockcount\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"params\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"id\":\"runar-1\"") != null);
}

test "RPCProvider broadcast via mock transport returns unquoted txid" {
    const allocator = std.testing.allocator;
    const response = "{\"result\":\"abcd1234\",\"error\":null,\"id\":\"runar-1\"}";
    var mock = MockTransport.init(allocator, response);
    defer mock.deinit();

    var rpc = RPCProvider.init(allocator, "http://localhost:18443", "user", "pass");
    defer rpc.deinit();
    rpc.setTransport(mock.transport());

    const txid = try rpc.broadcast(allocator, "0100000000deadbeef");
    defer allocator.free(txid);
    try std.testing.expectEqualStrings("abcd1234", txid);

    // Request shape: the body we sent must contain method + the tx hex as a string param.
    try std.testing.expect(std.mem.indexOf(u8, mock.last_body, "\"method\":\"sendrawtransaction\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mock.last_body, "\"params\":[\"0100000000deadbeef\"]") != null);
    try std.testing.expectEqualStrings("user", mock.last_user);
    try std.testing.expectEqualStrings("pass", mock.last_pass);
    try std.testing.expectEqualStrings("http://localhost:18443", mock.last_url);
}

test "RPCProvider initRegtest sets autoMine and network" {
    const allocator = std.testing.allocator;
    var rpc = RPCProvider.initRegtest(allocator, "http://localhost:18443", "user", "pass");
    defer rpc.deinit();
    try std.testing.expect(rpc.auto_mine);
    try std.testing.expectEqualStrings("regtest", rpc.network);
}

test "RPCProvider provider interface returns network string" {
    const allocator = std.testing.allocator;
    var rpc = RPCProvider.init(allocator, "http://localhost:18443", "user", "pass");
    defer rpc.deinit();
    const prov = rpc.provider();
    try std.testing.expectEqualStrings("testnet", prov.getNetwork());
}

// R3-ZIG-RPC-STUB: getUtxos returned an empty slice whatever listunspent said.
test "RPCProvider getUtxos parses listunspent (amount in BTC)" {
    const allocator = std.testing.allocator;
    var node = ScriptedNode{ .answers = &.{.{ .method = "listunspent", .reply = "{\"result\":[{\"txid\":\"" ++ TXID ++ "\",\"vout\":1,\"amount\":0.0001,\"scriptPubKey\":\"" ++ P2PKH_SCRIPT ++ "\"},{\"txid\":\"" ++ TXID ++ "\",\"vout\":0,\"amount\":2,\"scriptPubKey\":\"" ++ P2PKH_SCRIPT ++ "\"}],\"error\":null,\"id\":\"runar-1\"}" }} };
    var rpc = RPCProvider.init(allocator, "http://n", "u", "p");
    rpc.setTransport(node.transport());

    const utxos = try rpc.provider().getUtxos(allocator, "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r");
    defer {
        for (utxos) |*u| u.deinit(allocator);
        allocator.free(utxos);
    }
    try std.testing.expectEqual(@as(usize, 2), utxos.len);
    try std.testing.expectEqualStrings(TXID, utxos[0].txid);
    try std.testing.expectEqual(@as(i32, 1), utxos[0].output_index);
    try std.testing.expectEqual(@as(i64, 10_000), utxos[0].satoshis);
    try std.testing.expectEqualStrings(P2PKH_SCRIPT, utxos[0].script);
    try std.testing.expectEqual(@as(i64, 200_000_000), utxos[1].satoshis);
}

// R3-ZIG-RPC-STUB: the `error` member was never read, so a refusal came back
// as the "result" scanner's `null`.
test "RPCProvider broadcast surfaces the node's refusal" {
    const allocator = std.testing.allocator;
    var node = ScriptedNode{ .answers = &.{.{ .method = "sendrawtransaction", .reply = "{\"result\":null,\"error\":{\"code\":-26,\"message\":\"mandatory-script-verify-flag-failed (Script failed an OP_VERIFY operation)\"},\"id\":\"runar-1\"}" }} };
    var rpc = RPCProvider.initRegtest(allocator, "http://n", "u", "p");
    rpc.setTransport(node.transport());
    try std.testing.expectError(error.RPCError, rpc.broadcast(allocator, "00"));
    // A refused tx is never followed by a mine.
    try expectCalls(&node, &.{"sendrawtransaction"});
}

test "RPCProvider listunspent error is an error, not an empty wallet" {
    const allocator = std.testing.allocator;
    var node = ScriptedNode{ .answers = &.{.{ .method = "listunspent", .reply = "{\"result\":null,\"error\":{\"code\":-18,\"message\":\"No wallet is loaded\"},\"id\":\"runar-1\"}" }} };
    var rpc = RPCProvider.init(allocator, "http://n", "u", "p");
    rpc.setTransport(node.transport());
    try std.testing.expectError(error.NetworkError, rpc.provider().getUtxos(allocator, "addr"));
}

// R3-ZIG-RPC-STUB: auto_mine was never read.
test "RPCProvider initRegtest mines one block after an accepted broadcast" {
    const allocator = std.testing.allocator;
    var node = ScriptedNode{ .answers = &.{
        .{ .method = "sendrawtransaction", .reply = "{\"result\":\"" ++ TXID ++ "\",\"error\":null,\"id\":\"runar-1\"}" },
        .{ .method = "generate", .reply = "{\"result\":[\"00\"],\"error\":null,\"id\":\"runar-2\"}" },
    } };
    var rpc = RPCProvider.initRegtest(allocator, "http://n", "u", "p");
    rpc.setTransport(node.transport());
    const txid = try rpc.provider().broadcast(allocator, "00");
    defer allocator.free(txid);
    try std.testing.expectEqualStrings(TXID, txid);
    try expectCalls(&node, &.{ "sendrawtransaction", "generate" });
}

test "RPCProvider auto-mine falls back to generatetoaddress (Go's order)" {
    const allocator = std.testing.allocator;
    var node = ScriptedNode{ .answers = &.{
        .{ .method = "sendrawtransaction", .reply = "{\"result\":\"" ++ TXID ++ "\",\"error\":null,\"id\":\"runar-1\"}" },
        .{ .method = "getnewaddress", .reply = "{\"result\":\"mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r\",\"error\":null,\"id\":\"runar-3\"}" },
        .{ .method = "generatetoaddress", .reply = "{\"result\":[\"00\"],\"error\":null,\"id\":\"runar-4\"}" },
    } };
    var rpc = RPCProvider.initRegtest(allocator, "http://n", "u", "p");
    rpc.setTransport(node.transport());
    const txid = try rpc.provider().broadcast(allocator, "00");
    defer allocator.free(txid);
    // "?" is `generate`, answered method-not-found by the scripted node.
    try expectCalls(&node, &.{ "sendrawtransaction", "?", "getnewaddress", "generatetoaddress" });
}

// GK-BUG-004: an accepted tx whose confirming block never came is an error.
test "RPCProvider a failed confirming mine after an accepted broadcast is an error" {
    const allocator = std.testing.allocator;
    var node = ScriptedNode{ .answers = &.{
        .{ .method = "sendrawtransaction", .reply = "{\"result\":\"" ++ TXID ++ "\",\"error\":null,\"id\":\"runar-1\"}" },
        .{ .method = "getnewaddress", .reply = "{\"result\":null,\"error\":{\"code\":-18,\"message\":\"No wallet is loaded\"},\"id\":\"runar-3\"}" },
    } };
    var rpc = RPCProvider.initRegtest(allocator, "http://n", "u", "p");
    rpc.setTransport(node.transport());
    try std.testing.expectError(error.MineFailed, rpc.broadcast(allocator, "00"));
    try std.testing.expect(std.mem.indexOf(u8, rpc.lastError(), "broadcast succeeded (txid " ++ TXID ++ ") but auto-mine failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, rpc.lastError(), "No wallet is loaded") != null);
    try std.testing.expectError(error.BroadcastFailed, rpc.provider().broadcast(allocator, "00"));
}

test "RPCProvider broadcast refusal keeps the node's code and message" {
    const allocator = std.testing.allocator;
    var node = ScriptedNode{ .answers = &.{.{ .method = "sendrawtransaction", .reply = "{\"result\":null,\"error\":{\"code\":-26,\"message\":\"mandatory-script-verify-flag-failed (Script failed an OP_VERIFY operation)\"},\"id\":\"runar-1\"}" }} };
    var rpc = RPCProvider.init(allocator, "http://n", "u", "p");
    rpc.setTransport(node.transport());
    try std.testing.expectError(error.RPCError, rpc.broadcast(allocator, "00"));
    try std.testing.expectEqual(@as(?i64, -26), rpc.last_error_code);
    try std.testing.expectEqualStrings("sendrawtransaction: mandatory-script-verify-flag-failed (Script failed an OP_VERIFY operation)", rpc.lastError());
}

test "RPCProvider a reply that is not JSON-RPC is InvalidResponse" {
    const allocator = std.testing.allocator;
    var node = ScriptedNode{ .answers = &.{.{ .method = "listunspent", .reply = "<html>401 Unauthorized</html>" }} };
    var rpc = RPCProvider.init(allocator, "http://n", "u", "p");
    rpc.setTransport(node.transport());
    try std.testing.expectError(error.InvalidResponse, rpc.getUtxos(allocator, "addr"));
}

test "RPCProvider getRawTransaction / getTransaction read getrawtransaction; -5 is NotFound" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // version 1, one input (null outpoint, empty script), one output of 5000
    // sats paying P2PKH_SCRIPT, locktime 0.
    const raw = "01000000" ++ "01" ++ ("00" ** 32) ++ "ffffffff" ++ "00" ++ "ffffffff" ++ "01" ++ "8813000000000000" ++ "19" ++ P2PKH_SCRIPT ++ "00000000";
    var node = ScriptedNode{ .answers = &.{.{ .method = "getrawtransaction", .reply = "{\"result\":\"" ++ raw ++ "\",\"error\":null,\"id\":\"runar-1\"}" }} };
    var rpc = RPCProvider.init(a, "http://n", "u", "p");
    rpc.setTransport(node.transport());
    const hex = try rpc.provider().getRawTransaction(a, TXID);
    try std.testing.expectEqualStrings(raw, hex);
    const tx = try rpc.provider().getTransaction(a, TXID);
    try std.testing.expectEqual(@as(usize, 1), tx.outputs.len);
    try std.testing.expectEqual(@as(i64, 5000), tx.outputs[0].satoshis);
    try std.testing.expectEqualStrings(P2PKH_SCRIPT, tx.outputs[0].script);

    var missing = ScriptedNode{ .answers = &.{.{ .method = "getrawtransaction", .reply = "{\"result\":null,\"error\":{\"code\":-5,\"message\":\"No such mempool or blockchain transaction\"},\"id\":\"runar-1\"}" }} };
    rpc.setTransport(missing.transport());
    try std.testing.expectError(error.NotFound, rpc.provider().getRawTransaction(a, TXID));
    var down = ScriptedNode{ .answers = &.{.{ .method = "getrawtransaction", .reply = "{\"result\":null,\"error\":{\"code\":-28,\"message\":\"Loading block index\"},\"id\":\"runar-1\"}" }} };
    rpc.setTransport(down.transport());
    try std.testing.expectError(error.NetworkError, rpc.provider().getRawTransaction(a, TXID));
}
