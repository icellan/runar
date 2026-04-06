const std = @import("std");
const bsvz = @import("bsvz");
const state_mod = @import("sdk_state.zig");
const der_mod = @import("sdk_der.zig");

// ---------------------------------------------------------------------------
// OP_PUSH_TX — private key k=1 signing for sighash preimage verification
// ---------------------------------------------------------------------------

/// Result of an OP_PUSH_TX computation.
pub const OpPushTxResult = struct {
    /// DER-encoded ECDSA signature with sighash byte appended, hex-encoded.
    sig_hex: []u8,
    /// Raw BIP-143 preimage, hex-encoded.
    preimage_hex: []u8,

    pub fn deinit(self: *OpPushTxResult, allocator: std.mem.Allocator) void {
        allocator.free(self.sig_hex);
        allocator.free(self.preimage_hex);
        self.* = .{ .sig_hex = &.{}, .preimage_hex = &.{} };
    }
};

/// OP_PUSH_TX private key: k=1 (all zeros except last byte).
fn getOpPushTxPrivateKey() !bsvz.crypto.PrivateKey {
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;
    return bsvz.crypto.PrivateKey.fromBytes(key_bytes) catch return error.InvalidKey;
}

/// Compressed public key hex for the OP_PUSH_TX key (generator point G).
pub fn opPushTxPubKeyHex(allocator: std.mem.Allocator) ![]u8 {
    const priv_key = try getOpPushTxPrivateKey();
    const pub_key = priv_key.publicKey() catch return error.InvalidKey;
    const compressed = pub_key.toCompressedSec1();
    const hex_buf = try allocator.alloc(u8, 66);
    _ = bsvz.primitives.hex.encodeLower(&compressed, hex_buf) catch {
        allocator.free(hex_buf);
        return error.InvalidKey;
    };
    return hex_buf;
}

// DER canonicalization is in sdk_der.zig (shared with sdk_signer.zig)

pub const OpPushTxError = error{
    InvalidKey,
    InvalidTransaction,
    SigningFailed,
    InvalidEncoding,
    OutOfMemory,
};

/// Compute the OP_PUSH_TX DER signature and BIP-143 preimage for a contract
/// input in a raw transaction.
///
/// The OP_PUSH_TX technique uses private key k=1 (public key = generator G).
/// The signature is a standard ECDSA signature with low-S enforcement.
///
/// Parameters:
///   - allocator: memory allocator
///   - tx_hex: the raw transaction hex
///   - input_index: the contract input to sign (usually 0)
///   - subscript_hex: the locking script of the UTXO being spent (hex)
///   - satoshis: the satoshi value of the UTXO being spent
///   - code_separator_index: byte offset of the OP_CODESEPARATOR, or -1 if none
///
/// Returns an OpPushTxResult with the signature and preimage as hex strings.
pub fn computeOpPushTx(
    allocator: std.mem.Allocator,
    tx_hex: []const u8,
    input_index: usize,
    subscript_hex: []const u8,
    satoshis: i64,
    code_separator_index: i32,
) OpPushTxError!OpPushTxResult {
    const priv_key = getOpPushTxPrivateKey() catch return OpPushTxError.InvalidKey;
    const scope: u32 = bsvz.transaction.sighash.SigHashType.forkid | bsvz.transaction.sighash.SigHashType.all;

    // Decode transaction
    const tx_bytes = bsvz.primitives.hex.decode(allocator, tx_hex) catch return OpPushTxError.InvalidTransaction;
    defer allocator.free(tx_bytes);
    var tx = bsvz.transaction.Transaction.parse(allocator, tx_bytes) catch return OpPushTxError.InvalidTransaction;
    defer tx.deinit(allocator);

    if (input_index >= tx.inputs.len) return OpPushTxError.InvalidTransaction;

    // If OP_CODESEPARATOR is present, use only the script after it as scriptCode.
    var script_code_hex = subscript_hex;
    if (code_separator_index >= 0) {
        const hex_offset: usize = @intCast((@as(usize, @intCast(code_separator_index)) + 1) * 2);
        if (hex_offset <= subscript_hex.len) {
            script_code_hex = subscript_hex[hex_offset..];
        }
    }

    // Decode the script code bytes
    const script_bytes = bsvz.primitives.hex.decode(allocator, script_code_hex) catch return OpPushTxError.InvalidEncoding;
    defer allocator.free(script_bytes);
    const subscript = bsvz.script.Script.init(script_bytes);

    // Compute BIP-143 preimage (raw bytes)
    const preimage_bytes = bsvz.transaction.sighash.formatPreimage(allocator, &tx, input_index, subscript, satoshis, scope) catch return OpPushTxError.SigningFailed;
    defer allocator.free(preimage_bytes);

    // Compute sighash digest
    const digest_result = bsvz.transaction.sighash.digest(allocator, &tx, input_index, subscript, satoshis, scope) catch return OpPushTxError.SigningFailed;

    // Sign with k=1 private key and enforce low-S
    var der = priv_key.signDigest256(digest_result.bytes) catch return OpPushTxError.SigningFailed;
    der = der_mod.canonicalizeDer(der);

    // Build sig hex: DER bytes + sighash type byte
    const sig_total_len = der.len + 1;
    var sig_raw: [73]u8 = undefined;
    @memcpy(sig_raw[0..der.len], der.asSlice());
    sig_raw[der.len] = @truncate(scope);

    const sig_hex = allocator.alloc(u8, sig_total_len * 2) catch return OpPushTxError.OutOfMemory;
    errdefer allocator.free(sig_hex);
    _ = bsvz.primitives.hex.encodeLower(sig_raw[0..sig_total_len], sig_hex) catch {
        allocator.free(sig_hex);
        return OpPushTxError.InvalidEncoding;
    };

    // Encode preimage as hex
    const preimage_hex = allocator.alloc(u8, preimage_bytes.len * 2) catch {
        allocator.free(sig_hex);
        return OpPushTxError.OutOfMemory;
    };
    _ = bsvz.primitives.hex.encodeLower(preimage_bytes, preimage_hex) catch {
        allocator.free(sig_hex);
        allocator.free(preimage_hex);
        return OpPushTxError.InvalidEncoding;
    };

    return .{
        .sig_hex = sig_hex,
        .preimage_hex = preimage_hex,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "opPushTxPubKeyHex returns 66-char hex starting with 02 or 03" {
    const allocator = std.testing.allocator;
    const pk_hex = try opPushTxPubKeyHex(allocator);
    defer allocator.free(pk_hex);
    try std.testing.expectEqual(@as(usize, 66), pk_hex.len);
    try std.testing.expect(std.mem.startsWith(u8, pk_hex, "02") or std.mem.startsWith(u8, pk_hex, "03"));
}

test "computeOpPushTx returns valid signature and preimage" {
    const allocator = std.testing.allocator;

    // Minimal valid transaction hex: 1 input, 1 output
    const tx_hex = "01000000" ++ // version
        "01" ++ // 1 input
        "1111111111111111111111111111111111111111111111111111111111111111" ++ // txid
        "00000000" ++ // vout
        "00" ++ // scriptSig len = 0
        "ffffffff" ++ // sequence
        "01" ++ // 1 output
        "e803000000000000" ++ // satoshis (1000 LE)
        "01" ++ "51" ++ // script len + OP_1
        "00000000"; // locktime

    const subscript_hex = "76a914" ++ "0000000000000000000000000000000000000000" ++ "88ac";

    var result = try computeOpPushTx(allocator, tx_hex, 0, subscript_hex, 1000, -1);
    defer result.deinit(allocator);

    // Signature should be hex-encoded and end with sighash byte 0x41
    try std.testing.expect(result.sig_hex.len > 0);
    try std.testing.expect(std.mem.endsWith(u8, result.sig_hex, "41"));

    // Preimage should be non-empty hex
    try std.testing.expect(result.preimage_hex.len > 0);
}

test "computeOpPushTx with code separator" {
    const allocator = std.testing.allocator;

    const tx_hex = "01000000" ++ // version
        "01" ++ // 1 input
        "1111111111111111111111111111111111111111111111111111111111111111" ++ // txid
        "00000000" ++ // vout
        "00" ++ // scriptSig len = 0
        "ffffffff" ++ // sequence
        "01" ++ // 1 output
        "e803000000000000" ++ // satoshis (1000 LE)
        "01" ++ "51" ++ // script len + OP_1
        "00000000"; // locktime

    // Script with OP_CODESEPARATOR (0xab) at offset 2 (byte 2)
    const subscript_hex = "5151ab" ++ "76a914" ++ "0000000000000000000000000000000000000000" ++ "88ac";

    var result = try computeOpPushTx(allocator, tx_hex, 0, subscript_hex, 1000, 2);
    defer result.deinit(allocator);

    try std.testing.expect(result.sig_hex.len > 0);
    try std.testing.expect(result.preimage_hex.len > 0);
}
