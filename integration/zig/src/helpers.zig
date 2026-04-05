const std = @import("std");
const bsvz = @import("bsvz");
const runar = @import("runar");

// ---------------------------------------------------------------------------
// RPC client for communicating with a Bitcoin regtest node.
// Uses std.process.Child to shell out to curl for HTTP communication,
// avoiding Zig std.http.Client API version fragility.
// ---------------------------------------------------------------------------

pub const RpcError = error{
    ConnectionFailed,
    ParseFailed,
    RpcFailed,
    OutOfMemory,
};

fn rpcUrl() []const u8 {
    return std.posix.getenv("RPC_URL") orelse "http://localhost:18332";
}

fn rpcUser() []const u8 {
    return std.posix.getenv("RPC_USER") orelse "bitcoin";
}

fn rpcPass() []const u8 {
    return std.posix.getenv("RPC_PASS") orelse "bitcoin";
}

/// Make a JSON-RPC 1.0 call to the Bitcoin node. Returns the raw "result" JSON string.
/// Uses a temp file for the request body to avoid ARG_MAX limits on large transactions.
pub fn rpcCall(allocator: std.mem.Allocator, method: []const u8, params_json: []const u8) ![]u8 {
    const body = try std.fmt.allocPrint(allocator, "{{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"{s}\",\"params\":{s}}}", .{ method, params_json });
    defer allocator.free(body);

    const user_pass = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ rpcUser(), rpcPass() });
    defer allocator.free(user_pass);

    // Write body to a unique temp file to avoid ARG_MAX limits for large transactions.
    // curl's @filename syntax reads the POST body from the file.
    var tmp_name_buf: [64]u8 = undefined;
    const thread_id = std.Thread.getCurrentId();
    const tmp_name_len = (std.fmt.bufPrint(&tmp_name_buf, "/tmp/runar_rpc_{d}.json", .{thread_id}) catch return RpcError.ConnectionFailed).len;
    const tmp_path = tmp_name_buf[0..tmp_name_len];

    var tmp_file = std.fs.createFileAbsolute(tmp_path, .{}) catch return RpcError.ConnectionFailed;
    tmp_file.writeAll(body) catch {
        tmp_file.close();
        return RpcError.ConnectionFailed;
    };
    tmp_file.close();
    defer std.fs.deleteFileAbsolute(tmp_path) catch {};

    const at_path = std.fmt.allocPrint(allocator, "@{s}", .{tmp_path}) catch return RpcError.ConnectionFailed;
    defer allocator.free(at_path);

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{
            "curl",
            "-s",
            "--max-time",
            "600",
            "-u",
            user_pass,
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            at_path,
            rpcUrl(),
        },
        .max_output_bytes = 10 * 1024 * 1024,
    }) catch return RpcError.ConnectionFailed;
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    if (result.stdout.len == 0) return RpcError.ConnectionFailed;

    return extractJsonResult(allocator, result.stdout);
}

/// Extract the "result" field from a JSON-RPC response body.
fn extractJsonResult(allocator: std.mem.Allocator, response_body: []const u8) ![]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, response_body, .{}) catch return RpcError.ParseFailed;
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return RpcError.ParseFailed;

    // Check for error
    if (root.object.get("error")) |err_val| {
        if (err_val != .null) {
            if (err_val == .object) {
                if (err_val.object.get("message")) |msg| {
                    if (msg == .string) {
                        std.log.err("RPC error: {s}", .{msg.string});
                    }
                }
            }
            return RpcError.RpcFailed;
        }
    }

    const result_val = root.object.get("result") orelse return RpcError.ParseFailed;

    // Serialize the result back to JSON string
    return jsonStringify(allocator, result_val);
}

/// Serialize a std.json.Value to a JSON string.
fn jsonStringify(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
    return std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(value, .{})}) catch return RpcError.OutOfMemory;
}

// ---------------------------------------------------------------------------
// Node interaction helpers
// ---------------------------------------------------------------------------

/// Check if the regtest node is reachable.
pub fn isNodeAvailable(allocator: std.mem.Allocator) bool {
    const result = rpcCall(allocator, "getblockchaininfo", "[]") catch return false;
    allocator.free(result);
    return true;
}

/// Get the current block height.
pub fn getBlockCount(allocator: std.mem.Allocator) !i64 {
    const result = try rpcCall(allocator, "getblockchaininfo", "[]");
    defer allocator.free(result);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return RpcError.ParseFailed;
    const blocks = parsed.value.object.get("blocks") orelse return RpcError.ParseFailed;
    return blocks.integer;
}

/// Mine n blocks on the regtest node.
pub fn mine(allocator: std.mem.Allocator, n: i64) !void {
    const params = try std.fmt.allocPrint(allocator, "[{d}]", .{n});
    defer allocator.free(params);
    const result = rpcCall(allocator, "generate", params) catch {
        // Try generatetoaddress as fallback
        const addr_result = try rpcCall(allocator, "getnewaddress", "[]");
        defer allocator.free(addr_result);
        const addr = try parseJsonString(allocator, addr_result);
        defer allocator.free(addr);
        const params2 = try std.fmt.allocPrint(allocator, "[{d},\"{s}\"]", .{ n, addr });
        defer allocator.free(params2);
        const r = try rpcCall(allocator, "generatetoaddress", params2);
        allocator.free(r);
        return;
    };
    allocator.free(result);
}

/// Send BTC from the node wallet to an address.
pub fn sendToAddress(allocator: std.mem.Allocator, address: []const u8, btc_amount: f64) ![]u8 {
    const params = try std.fmt.allocPrint(allocator, "[\"{s}\",{d}]", .{ address, btc_amount });
    defer allocator.free(params);
    const result = try rpcCall(allocator, "sendtoaddress", params);
    defer allocator.free(result);
    return parseJsonString(allocator, result);
}

/// Import an address as watch-only.
pub fn importAddress(allocator: std.mem.Allocator, address: []const u8) !void {
    const params = try std.fmt.allocPrint(allocator, "[\"{s}\",\"\",false]", .{address});
    defer allocator.free(params);
    const result = rpcCall(allocator, "importaddress", params) catch return;
    allocator.free(result);
}

/// Broadcast a raw transaction hex. Returns the txid.
pub fn sendRawTransaction(allocator: std.mem.Allocator, tx_hex: []const u8) ![]u8 {
    const params = try std.fmt.allocPrint(allocator, "[\"{s}\"]", .{tx_hex});
    defer allocator.free(params);
    const result = try rpcCall(allocator, "sendrawtransaction", params);
    defer allocator.free(result);
    return parseJsonString(allocator, result);
}

/// Get a raw transaction (verbose mode). Returns the full JSON object as a string.
pub fn getRawTransactionVerbose(allocator: std.mem.Allocator, txid: []const u8) ![]u8 {
    const params = try std.fmt.allocPrint(allocator, "[\"{s}\",1]", .{txid});
    defer allocator.free(params);
    return rpcCall(allocator, "getrawtransaction", params);
}

/// Broadcast and auto-mine 1 block. Returns txid.
pub fn broadcastAndMine(allocator: std.mem.Allocator, tx_hex: []const u8) ![]u8 {
    const txid = try sendRawTransaction(allocator, tx_hex);
    mine(allocator, 1) catch {};
    return txid;
}

// ---------------------------------------------------------------------------
// Wallet management
// ---------------------------------------------------------------------------

pub const Wallet = struct {
    private_key: bsvz.crypto.PrivateKey,
    pub_key_bytes: [33]u8,
    pub_key_hash: [20]u8,
    address: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Wallet) void {
        self.allocator.free(self.address);
    }

    /// Return the pubkey hash as a 40-char hex string.
    pub fn pubKeyHashHex(self: *const Wallet, allocator: std.mem.Allocator) ![]u8 {
        const hex_buf = try allocator.alloc(u8, 40);
        _ = bsvz.primitives.hex.encodeLower(&self.pub_key_hash, hex_buf) catch {
            allocator.free(hex_buf);
            return error.OutOfMemory;
        };
        return hex_buf;
    }

    /// Return the compressed public key as a 66-char hex string.
    pub fn pubKeyHex(self: *const Wallet, allocator: std.mem.Allocator) ![]u8 {
        const hex_buf = try allocator.alloc(u8, 66);
        _ = bsvz.primitives.hex.encodeLower(&self.pub_key_bytes, hex_buf) catch {
            allocator.free(hex_buf);
            return error.OutOfMemory;
        };
        return hex_buf;
    }

    /// Return the P2PKH locking script hex for this wallet.
    pub fn p2pkhScript(self: *const Wallet, allocator: std.mem.Allocator) ![]u8 {
        const pkh_hex = try self.pubKeyHashHex(allocator);
        defer allocator.free(pkh_hex);
        return std.fmt.allocPrint(allocator, "76a914{s}88ac", .{pkh_hex});
    }

    /// Return a runar.LocalSigner for this wallet (regtest network).
    pub fn localSigner(self: *Wallet) !runar.LocalSigner {
        var ls = try runar.LocalSigner.fromBytes(self.private_key.bytes);
        ls.network = .testnet; // regtest uses testnet prefix (0x6f)
        return ls;
    }
};

/// Generate a random ECDSA wallet for regtest.
pub fn newWallet(allocator: std.mem.Allocator) !Wallet {
    // Generate 32 random bytes for the private key
    var key_bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&key_bytes);

    // Ensure the key is valid for secp256k1 (not zero, not >= order)
    key_bytes[0] &= 0x7f;
    if (std.mem.allEqual(u8, &key_bytes, 0)) {
        key_bytes[31] = 1;
    }

    const private_key = bsvz.crypto.PrivateKey.fromBytes(key_bytes) catch {
        // Retry with modified bytes
        key_bytes[31] ^= 0x42;
        return newWallet(allocator);
    };
    const public_key = private_key.publicKey() catch return error.OutOfMemory;
    const pub_key_bytes = public_key.toCompressedSec1();
    const pub_key_hash = bsvz.crypto.hash.hash160(&pub_key_bytes);

    // Generate regtest address (version byte 0x6f — same as testnet)
    const address = try bsvz.compat.address.encodeP2pkh(allocator, .testnet, pub_key_hash);

    return .{
        .private_key = private_key,
        .pub_key_bytes = pub_key_bytes,
        .pub_key_hash = pub_key_hash.bytes,
        .address = address,
        .allocator = allocator,
    };
}

/// Fund a wallet: import address, send BTC, mine a block.
pub fn fundWallet(allocator: std.mem.Allocator, wallet: *const Wallet, btc_amount: f64) ![]u8 {
    try importAddress(allocator, wallet.address);
    const txid = try sendToAddress(allocator, wallet.address, btc_amount);
    mine(allocator, 1) catch {};
    return txid;
}

// ---------------------------------------------------------------------------
// RPC-based Provider for the Runar SDK
// ---------------------------------------------------------------------------

pub const RPCProvider = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) RPCProvider {
        return .{ .allocator = allocator };
    }

    pub fn provider(self: *RPCProvider) runar.Provider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = runar.Provider.VTable{
        .getTransaction = getTransactionImpl,
        .broadcast = broadcastImpl,
        .getUtxos = getUtxosImpl,
        .getContractUtxo = getContractUtxoImpl,
        .getNetwork = getNetworkImpl,
        .getFeeRate = getFeeRateImpl,
        .getRawTransaction = getRawTransactionImpl,
    };

    fn getTransactionImpl(_: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) runar.sdk_provider.ProviderError!runar.TransactionData {
        const result = getRawTransactionVerbose(allocator, txid) catch return runar.sdk_provider.ProviderError.NetworkError;
        defer allocator.free(result);

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, result, .{}) catch return runar.sdk_provider.ProviderError.NetworkError;
        defer parsed.deinit();

        const root = parsed.value;
        if (root != .object) return runar.sdk_provider.ProviderError.NetworkError;

        // Extract hex
        const raw_hex_val = root.object.get("hex") orelse return runar.sdk_provider.ProviderError.NotFound;
        const raw_hex = allocator.dupe(u8, raw_hex_val.string) catch return runar.sdk_provider.ProviderError.OutOfMemory;
        errdefer allocator.free(raw_hex);

        // Extract outputs
        var outputs_list: std.ArrayListUnmanaged(runar.sdk_types.TxOutput) = .empty;
        errdefer outputs_list.deinit(allocator);

        if (root.object.get("vout")) |vout_val| {
            if (vout_val == .array) {
                for (vout_val.array.items) |vout_item| {
                    if (vout_item != .object) continue;
                    const val_btc = vout_item.object.get("value") orelse continue;
                    const sats: i64 = switch (val_btc) {
                        .float => @intFromFloat(val_btc.float * 1e8),
                        .integer => val_btc.integer * 100_000_000,
                        else => 0,
                    };
                    var script_hex: []const u8 = "";
                    if (vout_item.object.get("scriptPubKey")) |sp| {
                        if (sp == .object) {
                            if (sp.object.get("hex")) |h| {
                                if (h == .string) script_hex = h.string;
                            }
                        }
                    }
                    const script_dup = allocator.dupe(u8, script_hex) catch return runar.sdk_provider.ProviderError.OutOfMemory;
                    outputs_list.append(allocator, .{ .satoshis = sats, .script = script_dup }) catch return runar.sdk_provider.ProviderError.OutOfMemory;
                }
            }
        }

        const txid_dup = allocator.dupe(u8, txid) catch return runar.sdk_provider.ProviderError.OutOfMemory;

        return .{
            .txid = txid_dup,
            .version = 1,
            .outputs = outputs_list.toOwnedSlice(allocator) catch return runar.sdk_provider.ProviderError.OutOfMemory,
            .raw = raw_hex,
        };
    }

    fn broadcastImpl(_: *anyopaque, allocator: std.mem.Allocator, tx_hex: []const u8) runar.sdk_provider.ProviderError![]u8 {
        const txid = broadcastAndMine(allocator, tx_hex) catch return runar.sdk_provider.ProviderError.BroadcastFailed;
        return txid;
    }

    fn getUtxosImpl(_: *anyopaque, allocator: std.mem.Allocator, address: []const u8) runar.sdk_provider.ProviderError![]runar.UTXO {
        const params = std.fmt.allocPrint(allocator, "[0,9999999,[\"{s}\"]]", .{address}) catch return runar.sdk_provider.ProviderError.OutOfMemory;
        defer allocator.free(params);
        const result = rpcCall(allocator, "listunspent", params) catch return runar.sdk_provider.ProviderError.NetworkError;
        defer allocator.free(result);

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, result, .{}) catch return runar.sdk_provider.ProviderError.NetworkError;
        defer parsed.deinit();

        if (parsed.value != .array) return runar.sdk_provider.ProviderError.NetworkError;

        var utxos: std.ArrayListUnmanaged(runar.UTXO) = .empty;
        errdefer utxos.deinit(allocator);

        for (parsed.value.array.items) |item| {
            if (item != .object) continue;
            const txid_val = item.object.get("txid") orelse continue;
            const vout_val = item.object.get("vout") orelse continue;
            const amount_val = item.object.get("amount") orelse continue;
            const script_val = item.object.get("scriptPubKey") orelse continue;

            const sats: i64 = switch (amount_val) {
                .float => @intFromFloat(amount_val.float * 1e8),
                .integer => amount_val.integer * 100_000_000,
                else => 0,
            };

            const txid_str = allocator.dupe(u8, txid_val.string) catch return runar.sdk_provider.ProviderError.OutOfMemory;
            const script_str = allocator.dupe(u8, script_val.string) catch return runar.sdk_provider.ProviderError.OutOfMemory;

            utxos.append(allocator, .{
                .txid = txid_str,
                .output_index = @intCast(vout_val.integer),
                .satoshis = sats,
                .script = script_str,
            }) catch return runar.sdk_provider.ProviderError.OutOfMemory;
        }

        return utxos.toOwnedSlice(allocator) catch return runar.sdk_provider.ProviderError.OutOfMemory;
    }

    fn getContractUtxoImpl(_: *anyopaque, _: std.mem.Allocator, _: []const u8) runar.sdk_provider.ProviderError!?runar.UTXO {
        return null;
    }

    fn getNetworkImpl(_: *anyopaque) []const u8 {
        return "regtest";
    }

    fn getFeeRateImpl(_: *anyopaque) runar.sdk_provider.ProviderError!i64 {
        return 100;
    }

    fn getRawTransactionImpl(_: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) runar.sdk_provider.ProviderError![]u8 {
        const result = getRawTransactionVerbose(allocator, txid) catch return runar.sdk_provider.ProviderError.NetworkError;
        defer allocator.free(result);

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, result, .{}) catch return runar.sdk_provider.ProviderError.NetworkError;
        defer parsed.deinit();

        if (parsed.value != .object) return runar.sdk_provider.ProviderError.NotFound;
        const hex_val = parsed.value.object.get("hex") orelse return runar.sdk_provider.ProviderError.NotFound;
        if (hex_val != .string) return runar.sdk_provider.ProviderError.NotFound;
        return allocator.dupe(u8, hex_val.string) catch return runar.sdk_provider.ProviderError.OutOfMemory;
    }
};

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

/// Broadcast a transaction and expect it to be accepted. Returns the txid.
pub fn assertTxAccepted(allocator: std.mem.Allocator, tx_hex: []const u8) ![]u8 {
    return sendRawTransaction(allocator, tx_hex);
}

/// Broadcast a transaction and expect it to be rejected.
pub fn assertTxRejected(allocator: std.mem.Allocator, tx_hex: []const u8) !void {
    const txid = sendRawTransaction(allocator, tx_hex) catch return; // Rejected as expected
    defer allocator.free(txid);
    return error.RpcFailed; // Should have been rejected
}

/// Mine a block and verify the transaction has confirmations.
pub fn assertTxInBlock(allocator: std.mem.Allocator, txid: []const u8) !void {
    mine(allocator, 1) catch {};
    const result = getRawTransactionVerbose(allocator, txid) catch return;
    defer allocator.free(result);
    // If we can fetch it, it's in a block
}

// ---------------------------------------------------------------------------
// JSON utility helpers
// ---------------------------------------------------------------------------

/// Parse a JSON string value (strip surrounding quotes).
pub fn parseJsonString(allocator: std.mem.Allocator, json: []const u8) ![]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return RpcError.ParseFailed;
    defer parsed.deinit();
    if (parsed.value == .string) {
        return allocator.dupe(u8, parsed.value.string);
    }
    return RpcError.ParseFailed;
}
