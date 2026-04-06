const std = @import("std");
const bsvz = @import("bsvz");
const state = @import("sdk_state.zig");
const der_mod = @import("sdk_der.zig");

// ---------------------------------------------------------------------------
// Signer interface
// ---------------------------------------------------------------------------

/// Signer abstracts private key operations for signing transactions.
pub const Signer = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        getPublicKey: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator) SignerError![]u8,
        getAddress: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator) SignerError![]u8,
        sign: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, tx_hex: []const u8, input_index: usize, subscript_hex: []const u8, satoshis: i64, sighash_type: ?u32) SignerError![]u8,
    };

    /// Returns the hex-encoded compressed public key (66 hex chars). Caller owns result.
    pub fn getPublicKey(self: Signer, allocator: std.mem.Allocator) SignerError![]u8 {
        return self.vtable.getPublicKey(self.ptr, allocator);
    }

    /// Returns the BSV address string. Caller owns result.
    pub fn getAddress(self: Signer, allocator: std.mem.Allocator) SignerError![]u8 {
        return self.vtable.getAddress(self.ptr, allocator);
    }

    /// Sign a transaction input. Returns DER-encoded signature with sighash byte appended, hex-encoded.
    /// Caller owns result.
    pub fn sign(self: Signer, allocator: std.mem.Allocator, tx_hex: []const u8, input_index: usize, subscript_hex: []const u8, satoshis: i64, sighash_type: ?u32) SignerError![]u8 {
        return self.vtable.sign(self.ptr, allocator, tx_hex, input_index, subscript_hex, satoshis, sighash_type);
    }
};

pub const SignerError = error{
    InvalidKey,
    SigningFailed,
    OutOfMemory,
    InvalidEncoding,
    InvalidLength,
    InvalidTransaction,
};

// ---------------------------------------------------------------------------
// LocalSigner — private key in memory
// ---------------------------------------------------------------------------

/// LocalSigner holds a private key in memory for signing transactions.
/// Uses bsvz for ECDSA + BIP-143 sighash computation.
pub const LocalSigner = struct {
    private_key: bsvz.crypto.PrivateKey,
    network: bsvz.primitives.network.Network = .mainnet,

    /// Create a LocalSigner from a 32-byte private key.
    pub fn fromBytes(key_bytes: [32]u8) !LocalSigner {
        const private_key = bsvz.crypto.PrivateKey.fromBytes(key_bytes) catch return error.InvalidKey;
        return .{ .private_key = private_key };
    }

    /// Create a LocalSigner from a 64-char hex string.
    pub fn fromHex(hex_key: []const u8) !LocalSigner {
        if (hex_key.len != 64) return error.InvalidKey;
        var key_bytes: [32]u8 = undefined;
        _ = bsvz.primitives.hex.decodeInto(hex_key, &key_bytes) catch return error.InvalidKey;
        return fromBytes(key_bytes);
    }

    /// Return a Signer interface backed by this LocalSigner.
    pub fn signer(self: *LocalSigner) Signer {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = Signer.VTable{
        .getPublicKey = getPublicKeyImpl,
        .getAddress = getAddressImpl,
        .sign = signImpl,
    };

    fn getPublicKeyImpl(ctx: *anyopaque, allocator: std.mem.Allocator) SignerError![]u8 {
        const self: *LocalSigner = @ptrCast(@alignCast(ctx));
        const public_key = self.private_key.publicKey() catch return error.InvalidKey;
        const compressed = public_key.toCompressedSec1();
        const hex_buf = allocator.alloc(u8, 66) catch return error.OutOfMemory;
        _ = bsvz.primitives.hex.encodeLower(&compressed, hex_buf) catch {
            allocator.free(hex_buf);
            return error.InvalidEncoding;
        };
        return hex_buf;
    }

    fn getAddressImpl(ctx: *anyopaque, allocator: std.mem.Allocator) SignerError![]u8 {
        const self: *LocalSigner = @ptrCast(@alignCast(ctx));
        const public_key = self.private_key.publicKey() catch return error.InvalidKey;
        return bsvz.compat.address.encodeP2pkhFromPublicKey(allocator, self.network, public_key) catch return error.OutOfMemory;
    }

    fn signImpl(ctx: *anyopaque, allocator: std.mem.Allocator, tx_hex: []const u8, input_index: usize, subscript_hex: []const u8, satoshis: i64, sighash_type: ?u32) SignerError![]u8 {
        const self: *LocalSigner = @ptrCast(@alignCast(ctx));
        const scope = sighash_type orelse (bsvz.transaction.sighash.SigHashType.forkid | bsvz.transaction.sighash.SigHashType.all);

        // Decode transaction
        const tx_bytes = bsvz.primitives.hex.decode(allocator, tx_hex) catch return error.InvalidTransaction;
        defer allocator.free(tx_bytes);
        var tx = bsvz.transaction.Transaction.parse(allocator, tx_bytes) catch return error.InvalidTransaction;
        defer tx.deinit(allocator);

        if (input_index >= tx.inputs.len) return error.InvalidTransaction;

        // Decode subscript
        const subscript_bytes = bsvz.primitives.hex.decode(allocator, subscript_hex) catch return error.InvalidEncoding;
        defer allocator.free(subscript_bytes);
        const subscript = bsvz.script.Script.init(subscript_bytes);

        // Compute BIP-143 sighash digest
        const digest = bsvz.transaction.sighash.digest(allocator, &tx, input_index, subscript, satoshis, scope) catch return error.SigningFailed;

        // Sign the digest and enforce low-S (BIP 62)
        var der = self.private_key.signDigest256(digest.bytes) catch return error.SigningFailed;
        der = der_mod.canonicalizeDer(der);

        // Build hex: DER bytes + sighash type byte
        const sig_total_len = der.len + 1;
        const hex_result = allocator.alloc(u8, sig_total_len * 2) catch return error.OutOfMemory;
        errdefer allocator.free(hex_result);

        var sig_bytes: [73]u8 = undefined; // max DER + 1
        @memcpy(sig_bytes[0..der.len], der.asSlice());
        sig_bytes[der.len] = @truncate(scope);

        _ = bsvz.primitives.hex.encodeLower(sig_bytes[0..sig_total_len], hex_result) catch {
            allocator.free(hex_result);
            return error.InvalidEncoding;
        };

        return hex_result;
    }
};

// ---------------------------------------------------------------------------
// MockSigner — deterministic signer for testing
// ---------------------------------------------------------------------------

/// MockSigner returns deterministic values for testing. It does not perform
/// real cryptographic operations.
pub const MockSigner = struct {
    pub_key: []const u8,
    address: []const u8,

    pub fn init(pub_key_hex: ?[]const u8, address: ?[]const u8) MockSigner {
        return .{
            .pub_key = pub_key_hex orelse ("02" ++ "00" ** 32),
            .address = address orelse ("00" ** 20),
        };
    }

    /// Return a Signer interface backed by this MockSigner.
    pub fn signer(self: *MockSigner) Signer {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = Signer.VTable{
        .getPublicKey = getPublicKeyImpl,
        .getAddress = getAddressImpl,
        .sign = signImpl,
    };

    fn getPublicKeyImpl(ctx: *anyopaque, allocator: std.mem.Allocator) SignerError![]u8 {
        const self: *MockSigner = @ptrCast(@alignCast(ctx));
        return allocator.dupe(u8, self.pub_key) catch return error.OutOfMemory;
    }

    fn getAddressImpl(ctx: *anyopaque, allocator: std.mem.Allocator) SignerError![]u8 {
        const self: *MockSigner = @ptrCast(@alignCast(ctx));
        return allocator.dupe(u8, self.address) catch return error.OutOfMemory;
    }

    fn signImpl(_: *anyopaque, allocator: std.mem.Allocator, _: []const u8, _: usize, _: []const u8, _: i64, _: ?u32) SignerError![]u8 {
        // Return deterministic 72-byte mock signature: DER prefix 0x30 + 70 zero bytes + sighash 0x41
        return allocator.dupe(u8, "30" ++ "00" ** 70 ++ "41") catch return error.OutOfMemory;
    }
};

// ---------------------------------------------------------------------------
// ExternalSigner — callback-based signer
// ---------------------------------------------------------------------------

/// ExternalSigner wraps callback functions as a Signer.
pub const ExternalSigner = struct {
    pub_key: []const u8,
    address: []const u8,
    sign_fn: *const fn (allocator: std.mem.Allocator, tx_hex: []const u8, input_index: usize, subscript: []const u8, satoshis: i64, sighash_type: ?u32) SignerError![]u8,

    /// Return a Signer interface backed by this ExternalSigner.
    pub fn signer(self: *ExternalSigner) Signer {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = Signer.VTable{
        .getPublicKey = getPublicKeyImpl,
        .getAddress = getAddressImpl,
        .sign = signImpl,
    };

    fn getPublicKeyImpl(ctx: *anyopaque, allocator: std.mem.Allocator) SignerError![]u8 {
        const self: *ExternalSigner = @ptrCast(@alignCast(ctx));
        return allocator.dupe(u8, self.pub_key) catch return error.OutOfMemory;
    }

    fn getAddressImpl(ctx: *anyopaque, allocator: std.mem.Allocator) SignerError![]u8 {
        const self: *ExternalSigner = @ptrCast(@alignCast(ctx));
        return allocator.dupe(u8, self.address) catch return error.OutOfMemory;
    }

    fn signImpl(ctx: *anyopaque, allocator: std.mem.Allocator, tx_hex: []const u8, input_index: usize, subscript: []const u8, satoshis: i64, sighash_type: ?u32) SignerError![]u8 {
        const self: *ExternalSigner = @ptrCast(@alignCast(ctx));
        return self.sign_fn(allocator, tx_hex, input_index, subscript, satoshis, sighash_type);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "MockSigner returns deterministic values" {
    const allocator = std.testing.allocator;
    var mock = MockSigner.init(null, null);
    var s = mock.signer();

    const pub_key = try s.getPublicKey(allocator);
    defer allocator.free(pub_key);
    try std.testing.expectEqual(@as(usize, 66), pub_key.len);
    try std.testing.expect(std.mem.startsWith(u8, pub_key, "02"));

    const sig = try s.sign(allocator, "0100000000", 0, "76a914", 1000, null);
    defer allocator.free(sig);
    try std.testing.expectEqual(@as(usize, 144), sig.len); // 72 bytes = 144 hex chars
    try std.testing.expect(std.mem.startsWith(u8, sig, "30"));
    try std.testing.expect(std.mem.endsWith(u8, sig, "41"));
}

test "LocalSigner signs and returns hex sig" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    var local = LocalSigner.fromBytes(key_bytes) catch unreachable;
    var s = local.signer();

    const pub_key = try s.getPublicKey(allocator);
    defer allocator.free(pub_key);
    try std.testing.expectEqual(@as(usize, 66), pub_key.len);

    const address = try s.getAddress(allocator);
    defer allocator.free(address);
    try std.testing.expect(address.len > 0);

    // Build a minimal valid transaction hex to sign
    // version(4) + 1 input + txid(32) + vout(4) + scriptSig(0) + seq(4) + 1 output + satoshis(8) + script(1 byte OP_1) + locktime(4)
    const minimal_tx = "01000000" ++ // version
        "01" ++ // input count
        "1111111111111111111111111111111111111111111111111111111111111111" ++ // txid
        "00000000" ++ // vout
        "00" ++ // scriptSig len
        "ffffffff" ++ // sequence
        "01" ++ // output count
        "e803000000000000" ++ // satoshis (1000 LE)
        "01" ++ "51" ++ // script len + OP_1
        "00000000"; // locktime

    const subscript = "76a914" ++ "0000000000000000000000000000000000000000" ++ "88ac";
    const sig = try s.sign(allocator, minimal_tx, 0, subscript, 1000, null);
    defer allocator.free(sig);
    try std.testing.expect(sig.len > 0);
    // Signature ends with sighash byte 0x41 (ALL|FORKID)
    try std.testing.expect(std.mem.endsWith(u8, sig, "41"));
}
