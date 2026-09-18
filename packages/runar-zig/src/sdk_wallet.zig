const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");
const state_mod = @import("sdk_state.zig");
const deploy_mod = @import("sdk_deploy.zig");

// ---------------------------------------------------------------------------
// BRC-100 Wallet Integration
// ---------------------------------------------------------------------------
//
// Provides a WalletClient interface (vtable pattern), plus WalletProvider
// (implements Provider) and WalletSigner (implements Signer) that delegate
// UTXO management, signing, and action creation to a BRC-100 wallet.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// ProtocolID identifies a BRC-100 derivation protocol, e.g. .{ .level = 2, .name = "my app" }.
pub const ProtocolID = struct {
    level: u8,
    name: []const u8,
};

/// WalletActionOutput describes a single output in a createAction request.
pub const WalletActionOutput = struct {
    locking_script: []const u8, // hex-encoded locking script
    satoshis: i64,
    description: []const u8, // human-readable description
    basket: []const u8, // wallet basket name
    tags: []const []const u8, // tags for the output
};

/// WalletActionResult is returned from createAction.
pub const WalletActionResult = struct {
    txid: []const u8, // 64-char hex txid
    tx_hex: []const u8, // raw transaction hex (may be empty)

    pub fn deinit(self: *WalletActionResult, allocator: std.mem.Allocator) void {
        if (self.txid.len > 0) allocator.free(self.txid);
        if (self.tx_hex.len > 0) allocator.free(self.tx_hex);
        self.* = .{ .txid = &.{}, .tx_hex = &.{} };
    }
};

/// WalletOutput represents an output returned from listOutputs.
pub const WalletOutput = struct {
    outpoint: []const u8, // "txid.vout" format
    satoshis: i64,
    locking_script: []const u8, // hex-encoded locking script
    spendable: bool,

    pub fn deinit(self: *WalletOutput, allocator: std.mem.Allocator) void {
        if (self.outpoint.len > 0) allocator.free(self.outpoint);
        if (self.locking_script.len > 0) allocator.free(self.locking_script);
        self.* = .{ .outpoint = &.{}, .satoshis = 0, .locking_script = &.{}, .spendable = false };
    }

    pub fn clone(self: WalletOutput, allocator: std.mem.Allocator) !WalletOutput {
        return .{
            .outpoint = try allocator.dupe(u8, self.outpoint),
            .satoshis = self.satoshis,
            .locking_script = try allocator.dupe(u8, self.locking_script),
            .spendable = self.spendable,
        };
    }
};

pub const WalletError = error{
    WalletUnavailable,
    ActionFailed,
    SigningFailed,
    KeyDerivationFailed,
    InsufficientFunds,
    OutOfMemory,
    InvalidOutpoint,
};

// ---------------------------------------------------------------------------
// WalletClient interface (vtable pattern)
// ---------------------------------------------------------------------------

/// WalletClient abstracts a BRC-100 compatible wallet. Implementations
/// delegate to a browser-based wallet, a local wallet daemon, or a mock.
pub const WalletClient = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Derive a public key for the given protocol and key ID.
        /// Returns a hex-encoded compressed public key (66 hex chars). Caller owns result.
        getPublicKey: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, protocol_id: ProtocolID, key_id: []const u8) WalletError![]u8,

        /// Sign a pre-hashed digest using the wallet's derived key.
        /// `hash` is a hex-encoded hash to sign directly (no additional hashing).
        /// Returns a DER-encoded signature hex. Caller owns result.
        createSignature: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, hash: []const u8, protocol_id: ProtocolID, key_id: []const u8) WalletError![]u8,

        /// Create a wallet action (transaction) with the given outputs.
        /// The wallet handles input selection, signing, and broadcast internally.
        /// Caller owns the result and must call deinit on it.
        createAction: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, description: []const u8, outputs: []const WalletActionOutput) WalletError!WalletActionResult,

        /// List outputs in a wallet basket, optionally filtered by tags.
        /// Returns a slice of WalletOutput. Caller owns the result and each element.
        listOutputs: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, basket: []const u8, tags: []const []const u8, limit: usize) WalletError![]WalletOutput,
    };

    pub fn getPublicKey(self: WalletClient, allocator: std.mem.Allocator, protocol_id: ProtocolID, key_id: []const u8) WalletError![]u8 {
        return self.vtable.getPublicKey(self.ptr, allocator, protocol_id, key_id);
    }

    pub fn createSignature(self: WalletClient, allocator: std.mem.Allocator, hash: []const u8, protocol_id: ProtocolID, key_id: []const u8) WalletError![]u8 {
        return self.vtable.createSignature(self.ptr, allocator, hash, protocol_id, key_id);
    }

    pub fn createAction(self: WalletClient, allocator: std.mem.Allocator, description: []const u8, outputs: []const WalletActionOutput) WalletError!WalletActionResult {
        return self.vtable.createAction(self.ptr, allocator, description, outputs);
    }

    pub fn listOutputs(self: WalletClient, allocator: std.mem.Allocator, basket: []const u8, tags: []const []const u8, limit: usize) WalletError![]WalletOutput {
        return self.vtable.listOutputs(self.ptr, allocator, basket, tags, limit);
    }
};

// ---------------------------------------------------------------------------
// MockWalletClient — in-memory wallet for testing
// ---------------------------------------------------------------------------

/// MockWalletClient is a deterministic in-memory BRC-100 wallet for unit tests.
pub const MockWalletClient = struct {
    allocator: std.mem.Allocator,
    outputs: std.ArrayListUnmanaged(WalletOutput),
    action_count: u32 = 0,
    last_action_description: []const u8 = &.{},

    pub fn init(allocator: std.mem.Allocator) MockWalletClient {
        return .{
            .allocator = allocator,
            .outputs = .empty,
        };
    }

    pub fn deinit(self: *MockWalletClient) void {
        for (self.outputs.items) |*o| o.deinit(self.allocator);
        self.outputs.deinit(self.allocator);
        if (self.last_action_description.len > 0) self.allocator.free(self.last_action_description);
    }

    /// Add a mock output to the wallet.
    pub fn addOutput(self: *MockWalletClient, output: WalletOutput) !void {
        try self.outputs.append(self.allocator, try output.clone(self.allocator));
    }

    /// Return a WalletClient interface backed by this mock.
    pub fn walletClient(self: *MockWalletClient) WalletClient {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = WalletClient.VTable{
        .getPublicKey = getPublicKeyImpl,
        .createSignature = createSignatureImpl,
        .createAction = createActionImpl,
        .listOutputs = listOutputsImpl,
    };

    fn getPublicKeyImpl(_: *anyopaque, allocator: std.mem.Allocator, _: ProtocolID, _: []const u8) WalletError![]u8 {
        // Return a deterministic compressed public key
        return allocator.dupe(u8, "02" ++ "00" ** 32) catch return WalletError.OutOfMemory;
    }

    fn createSignatureImpl(_: *anyopaque, allocator: std.mem.Allocator, _: []const u8, _: ProtocolID, _: []const u8) WalletError![]u8 {
        // Return a deterministic DER signature
        return allocator.dupe(u8, "30" ++ "44" ++ "02" ++ "20" ++ "00" ** 32 ++ "02" ++ "20" ++ "00" ** 32) catch return WalletError.OutOfMemory;
    }

    fn createActionImpl(ctx: *anyopaque, allocator: std.mem.Allocator, description: []const u8, _: []const WalletActionOutput) WalletError!WalletActionResult {
        const self: *MockWalletClient = @ptrCast(@alignCast(ctx));
        self.action_count += 1;
        if (self.last_action_description.len > 0) self.allocator.free(self.last_action_description);
        self.last_action_description = self.allocator.dupe(u8, description) catch return WalletError.OutOfMemory;

        // Generate a deterministic fake txid
        const txid = std.fmt.allocPrint(allocator, "{x:0>64}", .{self.action_count}) catch return WalletError.OutOfMemory;
        return .{
            .txid = txid,
            .tx_hex = allocator.dupe(u8, "") catch return WalletError.OutOfMemory,
        };
    }

    fn listOutputsImpl(ctx: *anyopaque, allocator: std.mem.Allocator, _: []const u8, _: []const []const u8, limit: usize) WalletError![]WalletOutput {
        const self: *MockWalletClient = @ptrCast(@alignCast(ctx));
        const count = @min(limit, self.outputs.items.len);
        var result = allocator.alloc(WalletOutput, count) catch return WalletError.OutOfMemory;
        for (self.outputs.items[0..count], 0..) |o, i| {
            result[i] = o.clone(allocator) catch return WalletError.OutOfMemory;
        }
        return result;
    }
};

// ---------------------------------------------------------------------------
// WalletProvider — Provider backed by a WalletClient
// ---------------------------------------------------------------------------

/// WalletProvider implements the Provider interface by delegating UTXO
/// management and broadcast to a BRC-100 WalletClient. It uses the wallet's
/// listOutputs for UTXO lookup and createAction for broadcast.
pub const WalletProvider = struct {
    allocator: std.mem.Allocator,
    wallet: WalletClient,
    basket: []const u8,
    funding_tag: []const u8,
    network: []const u8,
    fee_rate: i64,
    /// Expected locking script hex for filtering P2PKH UTXOs.
    /// Set via setExpectedScript or automatically by WalletSigner integration.
    expected_script: ?[]const u8 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        wallet: WalletClient,
        basket: []const u8,
        options: struct {
            funding_tag: ?[]const u8 = null,
            network: ?[]const u8 = null,
            fee_rate: ?i64 = null,
        },
    ) WalletProvider {
        return .{
            .allocator = allocator,
            .wallet = wallet,
            .basket = basket,
            .funding_tag = options.funding_tag orelse "funding",
            .network = options.network orelse "mainnet",
            .fee_rate = options.fee_rate orelse 100,
        };
    }

    pub fn deinit(self: *WalletProvider) void {
        if (self.expected_script) |es| self.allocator.free(es);
        self.expected_script = null;
    }

    /// Set the expected P2PKH locking script hex for UTXO filtering.
    pub fn setExpectedScript(self: *WalletProvider, script_hex: []const u8) !void {
        if (self.expected_script) |es| self.allocator.free(es);
        self.expected_script = try self.allocator.dupe(u8, script_hex);
    }

    /// Return a Provider interface backed by this WalletProvider.
    pub fn provider(self: *WalletProvider) provider_mod.Provider {
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

    fn getTransactionImpl(_: *anyopaque, _: std.mem.Allocator, _: []const u8) provider_mod.ProviderError!types.TransactionData {
        return provider_mod.ProviderError.NotFound;
    }

    fn broadcastImpl(ctx: *anyopaque, allocator: std.mem.Allocator, tx_hex: []const u8) provider_mod.ProviderError![]u8 {
        const self: *WalletProvider = @ptrCast(@alignCast(ctx));

        // Use createAction with no explicit outputs — the tx_hex is the pre-built
        // transaction. For a full implementation this would parse the tx and
        // submit via the wallet. Here we delegate to createAction as a broadcast
        // mechanism, passing the raw hex as the description.
        var result = self.wallet.createAction(allocator, tx_hex, &.{}) catch return provider_mod.ProviderError.BroadcastFailed;

        // Copy txid before deinit
        const txid_copy = if (result.txid.len > 0)
            allocator.dupe(u8, result.txid) catch return provider_mod.ProviderError.OutOfMemory
        else
            null;

        result.deinit(allocator);

        if (txid_copy) |txid| {
            return txid;
        }
        return provider_mod.ProviderError.BroadcastFailed;
    }

    fn getUtxosImpl(ctx: *anyopaque, allocator: std.mem.Allocator, _: []const u8) provider_mod.ProviderError![]types.UTXO {
        const self: *WalletProvider = @ptrCast(@alignCast(ctx));

        const tags = [_][]const u8{self.funding_tag};
        const wallet_outputs = self.wallet.listOutputs(allocator, self.basket, &tags, 100) catch return provider_mod.ProviderError.NetworkError;
        defer {
            for (wallet_outputs) |*o| {
                var mo = o.*;
                mo.deinit(allocator);
            }
            allocator.free(wallet_outputs);
        }

        // Convert WalletOutput to UTXO, filtering by expected script and spendable
        var utxos: std.ArrayListUnmanaged(types.UTXO) = .empty;
        errdefer {
            for (utxos.items) |*u| u.deinit(allocator);
            utxos.deinit(allocator);
        }

        for (wallet_outputs) |wo| {
            if (!wo.spendable) continue;

            // Filter by expected script if set
            if (self.expected_script) |es| {
                if (!std.mem.eql(u8, wo.locking_script, es)) continue;
            }

            // Parse outpoint "txid.vout"
            const dot_pos = std.mem.indexOf(u8, wo.outpoint, ".") orelse continue;
            const txid = wo.outpoint[0..dot_pos];
            const vout_str = wo.outpoint[dot_pos + 1 ..];
            const vout = std.fmt.parseInt(i32, vout_str, 10) catch continue;

            try utxos.append(allocator, .{
                .txid = allocator.dupe(u8, txid) catch return provider_mod.ProviderError.OutOfMemory,
                .output_index = vout,
                .satoshis = wo.satoshis,
                .script = allocator.dupe(u8, wo.locking_script) catch return provider_mod.ProviderError.OutOfMemory,
            });
        }

        return utxos.toOwnedSlice(allocator) catch return provider_mod.ProviderError.OutOfMemory;
    }

    fn getContractUtxoImpl(_: *anyopaque, _: std.mem.Allocator, _: []const u8) provider_mod.ProviderError!?types.UTXO {
        return null;
    }

    fn getNetworkImpl(ctx: *anyopaque) []const u8 {
        const self: *WalletProvider = @ptrCast(@alignCast(ctx));
        return self.network;
    }

    fn getFeeRateImpl(ctx: *anyopaque) provider_mod.ProviderError!i64 {
        const self: *WalletProvider = @ptrCast(@alignCast(ctx));
        return self.fee_rate;
    }

    fn getRawTransactionImpl(_: *anyopaque, _: std.mem.Allocator, _: []const u8) provider_mod.ProviderError![]u8 {
        return provider_mod.ProviderError.NotFound;
    }
};

// ---------------------------------------------------------------------------
// WalletSigner — Signer backed by a WalletClient
// ---------------------------------------------------------------------------

/// WalletSigner implements the Signer interface by delegating key derivation
/// and signing to a BRC-100 WalletClient. It uses protocol ID and key ID for
/// deterministic key derivation.
pub const WalletSigner = struct {
    allocator: std.mem.Allocator,
    wallet: WalletClient,
    protocol_id: ProtocolID,
    key_id: []const u8,
    cached_pub_key: ?[]const u8 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        wallet: WalletClient,
        protocol_id: ProtocolID,
        key_id: []const u8,
    ) WalletSigner {
        return .{
            .allocator = allocator,
            .wallet = wallet,
            .protocol_id = protocol_id,
            .key_id = key_id,
        };
    }

    pub fn deinit(self: *WalletSigner) void {
        if (self.cached_pub_key) |pk| self.allocator.free(pk);
        self.cached_pub_key = null;
    }

    /// Return a Signer interface backed by this WalletSigner.
    pub fn signer(self: *WalletSigner) signer_mod.Signer {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = signer_mod.Signer.VTable{
        .getPublicKey = getPublicKeyImpl,
        .getAddress = getAddressImpl,
        .sign = signImpl,
    };

    fn getPublicKeyImpl(ctx: *anyopaque, allocator: std.mem.Allocator) signer_mod.SignerError![]u8 {
        const self: *WalletSigner = @ptrCast(@alignCast(ctx));

        // Return cached value if available
        if (self.cached_pub_key) |pk| {
            return allocator.dupe(u8, pk) catch return signer_mod.SignerError.OutOfMemory;
        }

        const pub_key = self.wallet.getPublicKey(allocator, self.protocol_id, self.key_id) catch return signer_mod.SignerError.InvalidKey;

        // Cache the result
        self.cached_pub_key = self.allocator.dupe(u8, pub_key) catch {
            allocator.free(pub_key);
            return signer_mod.SignerError.OutOfMemory;
        };

        return pub_key;
    }

    fn getAddressImpl(ctx: *anyopaque, allocator: std.mem.Allocator) signer_mod.SignerError![]u8 {
        const self: *WalletSigner = @ptrCast(@alignCast(ctx));

        // Get public key and compute hash160 to use as address
        const pub_key_hex = try getPublicKeyImpl(@ptrCast(self), allocator);
        defer allocator.free(pub_key_hex);

        // For the wallet signer, the "address" is the hash160 of the public key
        // (20 bytes = 40 hex chars), consistent with how the SDK uses addresses
        // as raw hash160 values internally.
        const pub_key_bytes = state_mod.hexToBytes(allocator, pub_key_hex) catch return signer_mod.SignerError.InvalidEncoding;
        defer allocator.free(pub_key_bytes);

        const bsvz = @import("bsvz");
        const ripe_hash = bsvz.crypto.hash.hash160(pub_key_bytes);
        const hex_buf = allocator.alloc(u8, 40) catch return signer_mod.SignerError.OutOfMemory;
        _ = bsvz.primitives.hex.encodeLower(&ripe_hash.bytes, hex_buf) catch {
            allocator.free(hex_buf);
            return signer_mod.SignerError.InvalidEncoding;
        };
        return hex_buf;
    }

    fn signImpl(ctx: *anyopaque, allocator: std.mem.Allocator, tx_hex: []const u8, input_index: usize, subscript_hex: []const u8, satoshis: i64, sighash_type: ?u32) signer_mod.SignerError![]u8 {
        const self: *WalletSigner = @ptrCast(@alignCast(ctx));
        const bsvz = @import("bsvz");

        const scope = sighash_type orelse (bsvz.transaction.sighash.SigHashType.forkid | bsvz.transaction.sighash.SigHashType.all);

        // 1. Parse the transaction
        const tx_bytes = bsvz.primitives.hex.decode(allocator, tx_hex) catch return signer_mod.SignerError.InvalidTransaction;
        defer allocator.free(tx_bytes);
        var tx = bsvz.transaction.Transaction.parse(allocator, tx_bytes) catch return signer_mod.SignerError.InvalidTransaction;
        defer tx.deinit(allocator);

        if (input_index >= tx.inputs.len) return signer_mod.SignerError.InvalidTransaction;

        // 2. Parse the subscript
        const subscript_bytes = bsvz.primitives.hex.decode(allocator, subscript_hex) catch return signer_mod.SignerError.InvalidEncoding;
        defer allocator.free(subscript_bytes);
        const subscript = bsvz.script.Script.init(subscript_bytes);

        // 3. Compute BIP-143 sighash digest
        const digest = bsvz.transaction.sighash.digest(allocator, &tx, input_index, subscript, satoshis, scope) catch return signer_mod.SignerError.SigningFailed;

        // 4. Encode digest as hex and send to wallet for signing
        var digest_hex: [64]u8 = undefined;
        _ = bsvz.primitives.hex.encodeLower(&digest.bytes, &digest_hex) catch return signer_mod.SignerError.InvalidEncoding;

        const der_hex = self.wallet.createSignature(allocator, &digest_hex, self.protocol_id, self.key_id) catch return signer_mod.SignerError.SigningFailed;
        defer allocator.free(der_hex);

        // 5. Append sighash type byte
        const sighash_byte_hex = std.fmt.allocPrint(allocator, "{x:0>2}", .{@as(u8, @truncate(scope))}) catch return signer_mod.SignerError.OutOfMemory;
        defer allocator.free(sighash_byte_hex);

        return std.mem.concat(allocator, u8, &[_][]const u8{ der_hex, sighash_byte_hex }) catch return signer_mod.SignerError.OutOfMemory;
    }
};

// ---------------------------------------------------------------------------
// deployWithWallet — convenience function
// ---------------------------------------------------------------------------

/// Deploy a RunarContract using a BRC-100 wallet. This is a convenience
/// function that creates a WalletProvider and WalletSigner from the given
/// wallet client, then calls deploy on the contract.
///
/// Returns the broadcast txid (caller owns).
pub fn deployWithWallet(
    contract: *contract_mod.RunarContract,
    wallet: WalletClient,
    options: struct {
        satoshis: i64,
        basket: []const u8,
        protocol_id: ProtocolID,
        key_id: []const u8,
        funding_tag: ?[]const u8 = null,
        network: ?[]const u8 = null,
        fee_rate: ?i64 = null,
        /// Builtins the caller accepts despite the compiler not claiming they
        /// are sound (R-062). Zig already ran the gate on this path — it
        /// delegates to `contract.deploy`, which enforces it — but it had no
        /// way to SUPPLY an acknowledgement, so a legitimate acknowledged
        /// deploy was refused. Same mechanism and same error as
        /// `DeployOptions.acknowledge_unsound`.
        acknowledge_unsound: []const []const u8 = &.{},
    },
) ![]u8 {
    var wallet_provider = WalletProvider.init(
        contract.allocator,
        wallet,
        options.basket,
        .{
            .funding_tag = options.funding_tag,
            .network = options.network,
            .fee_rate = options.fee_rate,
        },
    );
    defer wallet_provider.deinit();

    var wallet_signer = WalletSigner.init(
        contract.allocator,
        wallet,
        options.protocol_id,
        options.key_id,
    );
    defer wallet_signer.deinit();

    // Set expected script on provider for UTXO filtering.
    //
    // buildP2PKHScript takes a 40-hex PUBKEY HASH (or a Base58Check address);
    // it was being handed the 66-hex PUBKEY, which matched neither branch and
    // fell through to the Base58 decoder, so every wallet deploy failed with
    // OutOfMemory before reaching contract.deploy. Hash the key first, the way
    // the call path in sdk_contract.zig does.
    const pub_key_hex = try wallet_signer.signer().getPublicKey(contract.allocator);
    defer contract.allocator.free(pub_key_hex);
    const bsvz = @import("bsvz");
    const pub_key_bytes = try state_mod.hexToBytes(contract.allocator, pub_key_hex);
    defer contract.allocator.free(pub_key_bytes);
    const ripe_hash = bsvz.crypto.hash.hash160(pub_key_bytes);
    var pkh_hex: [40]u8 = undefined;
    _ = bsvz.primitives.hex.encodeLower(&ripe_hash.bytes, &pkh_hex) catch return error.OutOfMemory;
    const expected_script = try deploy_mod.buildP2PKHScript(contract.allocator, &pkh_hex);
    defer contract.allocator.free(expected_script);
    try wallet_provider.setExpectedScript(expected_script);

    return contract.deploy(
        wallet_provider.provider(),
        wallet_signer.signer(),
        .{
            .satoshis = options.satoshis,
            // R-062: carry the caller's acknowledgement into the ONE gate this
            // tier has. Without it the wallet path could only ever refuse an
            // unsound artifact, never fund an acknowledged one.
            .acknowledge_unsound = options.acknowledge_unsound,
        },
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "MockWalletClient getPublicKey returns deterministic key" {
    const allocator = std.testing.allocator;
    var mock = MockWalletClient.init(allocator);
    defer mock.deinit();

    var wc = mock.walletClient();
    const pub_key = try wc.getPublicKey(allocator, .{ .level = 2, .name = "test" }, "1");
    defer allocator.free(pub_key);

    try std.testing.expectEqual(@as(usize, 66), pub_key.len);
    try std.testing.expect(std.mem.startsWith(u8, pub_key, "02"));
}

test "MockWalletClient createSignature returns deterministic signature" {
    const allocator = std.testing.allocator;
    var mock = MockWalletClient.init(allocator);
    defer mock.deinit();

    var wc = mock.walletClient();
    const sig = try wc.createSignature(allocator, "00" ** 32, .{ .level = 2, .name = "test" }, "1");
    defer allocator.free(sig);

    try std.testing.expect(sig.len > 0);
    try std.testing.expect(std.mem.startsWith(u8, sig, "30"));
}

test "MockWalletClient createAction increments count and returns txid" {
    const allocator = std.testing.allocator;
    var mock = MockWalletClient.init(allocator);
    defer mock.deinit();

    var wc = mock.walletClient();
    var result = try wc.createAction(allocator, "deploy contract", &.{});
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 64), result.txid.len);
    try std.testing.expectEqual(@as(u32, 1), mock.action_count);
    try std.testing.expectEqualStrings("deploy contract", mock.last_action_description);
}

test "MockWalletClient listOutputs returns added outputs" {
    const allocator = std.testing.allocator;
    var mock = MockWalletClient.init(allocator);
    defer mock.deinit();

    try mock.addOutput(.{
        .outpoint = "aabb" ++ "00" ** 30 ++ ".0",
        .satoshis = 5000,
        .locking_script = "76a914" ++ "00" ** 20 ++ "88ac",
        .spendable = true,
    });

    var wc = mock.walletClient();
    const outputs = try wc.listOutputs(allocator, "test-basket", &.{}, 100);
    defer {
        for (outputs) |*o| {
            var mo = o.*;
            mo.deinit(allocator);
        }
        allocator.free(outputs);
    }

    try std.testing.expectEqual(@as(usize, 1), outputs.len);
    try std.testing.expectEqual(@as(i64, 5000), outputs[0].satoshis);
    try std.testing.expect(outputs[0].spendable);
}

test "WalletProvider returns UTXOs from wallet outputs" {
    const allocator = std.testing.allocator;
    var mock = MockWalletClient.init(allocator);
    defer mock.deinit();

    try mock.addOutput(.{
        .outpoint = "aabb" ++ "00" ** 30 ++ ".0",
        .satoshis = 5000,
        .locking_script = "76a914" ++ "00" ** 20 ++ "88ac",
        .spendable = true,
    });
    try mock.addOutput(.{
        .outpoint = "ccdd" ++ "00" ** 30 ++ ".1",
        .satoshis = 3000,
        .locking_script = "76a914" ++ "00" ** 20 ++ "88ac",
        .spendable = false, // not spendable, should be filtered
    });

    const wc = mock.walletClient();
    var wp = WalletProvider.init(allocator, wc, "test-basket", .{});
    defer wp.deinit();

    var prov = wp.provider();
    const utxos = try prov.getUtxos(allocator, "any-address");
    defer {
        for (utxos) |*u| {
            var mu = u.*;
            mu.deinit(allocator);
        }
        allocator.free(utxos);
    }

    // Only spendable output returned
    try std.testing.expectEqual(@as(usize, 1), utxos.len);
    try std.testing.expectEqual(@as(i64, 5000), utxos[0].satoshis);
    try std.testing.expectEqual(@as(i32, 0), utxos[0].output_index);
}

test "WalletProvider getNetwork and getFeeRate return configured values" {
    const allocator = std.testing.allocator;
    var mock = MockWalletClient.init(allocator);
    defer mock.deinit();

    const wc = mock.walletClient();
    var wp = WalletProvider.init(allocator, wc, "basket", .{
        .network = "testnet",
        .fee_rate = 50,
    });
    defer wp.deinit();

    var prov = wp.provider();
    try std.testing.expectEqualStrings("testnet", prov.getNetwork());
    try std.testing.expectEqual(@as(i64, 50), try prov.getFeeRate());
}

test "WalletSigner getPublicKey caches result" {
    const allocator = std.testing.allocator;
    var mock = MockWalletClient.init(allocator);
    defer mock.deinit();

    const wc = mock.walletClient();
    var ws = WalletSigner.init(allocator, wc, .{ .level = 2, .name = "test" }, "1");
    defer ws.deinit();

    var s = ws.signer();

    const pk1 = try s.getPublicKey(allocator);
    defer allocator.free(pk1);
    const pk2 = try s.getPublicKey(allocator);
    defer allocator.free(pk2);

    try std.testing.expectEqual(@as(usize, 66), pk1.len);
    try std.testing.expectEqualStrings(pk1, pk2);
}
