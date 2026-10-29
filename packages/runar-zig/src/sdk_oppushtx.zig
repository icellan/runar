const std = @import("std");
const bsvz = @import("bsvz");
const state_mod = @import("sdk_state.zig");
const envelope_sign = @import("sdk_envelope_sign.zig");

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

// N-185: signing is in sdk_envelope_sign.zig (shared with sdk_signer.zig's
// LocalSigner, N-170); see that module's canonical-RFC-6979 doc comment.

pub const OpPushTxError = error{
    InvalidKey,
    InvalidTransaction,
    SigningFailed,
    InvalidEncoding,
    /// R-178: the code-separator offset is past the end of the subscript.
    InvalidCodeSeparatorIndex,
    /// N-041: the subscript is empty; no preimage over it can match the
    /// script the node executes.
    EmptySubscript,
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
    const default_scope: u32 = bsvz.transaction.sighash.SigHashType.forkid | bsvz.transaction.sighash.SigHashType.all;
    return computeOpPushTxWithSigHash(allocator, tx_hex, input_index, subscript_hex, satoshis, code_separator_index, default_scope);
}

/// Mode-aware form (issue #123). `sig_hash_type` is the BIP-143 sighash type the
/// preimage is built under (e.g. 0x43 for SINGLE|FORKID); it drives which
/// preimage fields the bsvz library zeroes (hashPrevouts under ANYONECANPAY,
/// hashSequence unless pure ALL, hashOutputs under NONE / same-index SINGLE) AND
/// the sighash flag byte appended to the DER signature. Must match the method's
/// declared @sighash mode or the on-chain OP_PUSH_TX binding fails to verify.
/// Pass 0 or 0x41 for the default ALL|FORKID.
///
/// NOTE: bsvz's transaction/sighash.zig performs the SINGLE same-index
/// hashOutputs (and NONE / ANYONECANPAY zeroing) natively once the scope is
/// passed — no hand-rolled preimage zeroing is needed (mirrors the Go tier's
/// use of go-sdk's CalcInputPreimage).
pub fn computeOpPushTxWithSigHash(
    allocator: std.mem.Allocator,
    tx_hex: []const u8,
    input_index: usize,
    subscript_hex: []const u8,
    satoshis: i64,
    code_separator_index: i32,
    sig_hash_type: u32,
) OpPushTxError!OpPushTxResult {
    return computeOpPushTxImpl(allocator, tx_hex, input_index, subscript_hex, satoshis, code_separator_index, sig_hash_type, true);
}

/// Number of k=1 OP_PUSH_TX ECDSA signatures computed by this process (N-253).
/// A test observability hook: it lets a test assert that a code path which
/// only needs the preimage does not sign. Tests run single-threaded.
pub var sign_count: usize = 0;

/// N-253: `computeOpPushTxWithSigHash` without the k=1 ECDSA signature -- same
/// arguments, same validation, same preimage bytes. Post-BUG-100 the OP_PUSH_TX
/// signature is derived on-chain from the preimage and the unlocking script has
/// no slot for one, so the stateful prepareCall/call paths use this instead of
/// signing and discarding a signature. The returned `sig_hex` is empty (and
/// still safe to `deinit`).
pub fn computeOpPushTxPreimageWithSigHash(
    allocator: std.mem.Allocator,
    tx_hex: []const u8,
    input_index: usize,
    subscript_hex: []const u8,
    satoshis: i64,
    code_separator_index: i32,
    sig_hash_type: u32,
) OpPushTxError!OpPushTxResult {
    return computeOpPushTxImpl(allocator, tx_hex, input_index, subscript_hex, satoshis, code_separator_index, sig_hash_type, false);
}

fn computeOpPushTxImpl(
    allocator: std.mem.Allocator,
    tx_hex: []const u8,
    input_index: usize,
    subscript_hex: []const u8,
    satoshis: i64,
    code_separator_index: i32,
    sig_hash_type: u32,
    comptime want_sig: bool,
) OpPushTxError!OpPushTxResult {
    const priv_key = getOpPushTxPrivateKey() catch return OpPushTxError.InvalidKey;
    const scope: u32 = if (sig_hash_type == 0)
        (bsvz.transaction.sighash.SigHashType.forkid | bsvz.transaction.sighash.SigHashType.all)
    else
        sig_hash_type;

    // Decode transaction
    const tx_bytes = bsvz.primitives.hex.decode(allocator, tx_hex) catch return OpPushTxError.InvalidTransaction;
    defer allocator.free(tx_bytes);
    var tx = bsvz.transaction.Transaction.parse(allocator, tx_bytes) catch return OpPushTxError.InvalidTransaction;
    defer tx.deinit(allocator);

    if (input_index >= tx.inputs.len) return OpPushTxError.InvalidTransaction;

    // N-041: the subscript is the locking script of the UTXO being spent (e.g.
    // a provider's contract UTXO). An empty one can never match the script the
    // node executes, so refuse it.
    if (subscript_hex.len == 0) return OpPushTxError.EmptySubscript;

    // If OP_CODESEPARATOR is present, use only the script after it as scriptCode.
    var script_code_hex = subscript_hex;
    if (code_separator_index >= 0) {
        // R-178: an out-of-range index used to leave the subscript UNTRIMMED
        // and sign it — a wrong scriptCode, silently, from a fund-moving
        // primitive. There is no correct signature for a separator offset that
        // is not in the script.
        const hex_offset: usize = @intCast((@as(usize, @intCast(code_separator_index)) + 1) * 2);
        if (hex_offset > subscript_hex.len) return OpPushTxError.InvalidCodeSeparatorIndex;
        script_code_hex = subscript_hex[hex_offset..];

        // N-155: a code_separator_index pointing at the LAST byte of the
        // subscript passes the "past the end" check above (hex_offset ==
        // len, not >) but trims script_code_hex down to the empty string --
        // the same unsignable condition the empty-subscript check above
        // exists to catch, just reached a different way. Refuse it too.
        if (script_code_hex.len == 0) return OpPushTxError.EmptySubscript;
    }

    // Decode the script code bytes
    const script_bytes = bsvz.primitives.hex.decode(allocator, script_code_hex) catch return OpPushTxError.InvalidEncoding;
    defer allocator.free(script_bytes);
    const subscript = bsvz.script.Script.init(script_bytes);

    // Compute BIP-143 preimage (raw bytes)
    const preimage_bytes = bsvz.transaction.sighash.formatPreimage(allocator, &tx, input_index, subscript, satoshis, scope) catch return OpPushTxError.SigningFailed;
    defer allocator.free(preimage_bytes);

    const sig_hex: []u8 = if (want_sig) blk: {
        // Compute sighash digest
        const digest_result = bsvz.transaction.sighash.digest(allocator, &tx, input_index, subscript, satoshis, scope) catch return OpPushTxError.SigningFailed;

        // N-185: bsvz's PrivateKey.signDigest256 derives its ECDSA nonce via Zig
        // stdlib's "Deterministic ECDSA with Additional Randomness" draft, not
        // canonical RFC 6979 (see sdk_envelope_sign.zig's GAP-064 doc comment,
        // and sdk_signer.zig's N-170 fix of the same bug in LocalSigner) -- it
        // folds a 32-byte zero "noise" block into the HMAC-DRBG seed. The result
        // is a VALID but non-reproducible signature: it verifies, but never
        // matches the RFC-6979 signature every other tier (and
        // conformance/sdk-bip143's fixture) produces for the same (key, digest).
        // Sign with the same canonical RFC-6979 + low-S implementation the
        // signed-envelope wire protocol and LocalSigner already use.
        var der_buf: [72]u8 = undefined;
        const der = envelope_sign.signDigestLowSDer(priv_key.bytes, digest_result.bytes, &der_buf) catch return OpPushTxError.SigningFailed;

        // Build sig hex: DER bytes + sighash type byte
        const sig_total_len = der.len + 1;
        var sig_raw: [73]u8 = undefined;
        @memcpy(sig_raw[0..der.len], der);
        sig_raw[der.len] = @truncate(scope);

        sign_count += 1;

        const signed_hex = allocator.alloc(u8, sig_total_len * 2) catch return OpPushTxError.OutOfMemory;
        _ = bsvz.primitives.hex.encodeLower(sig_raw[0..sig_total_len], signed_hex) catch {
            allocator.free(signed_hex);
            return OpPushTxError.InvalidEncoding;
        };

        break :blk signed_hex;
    } else allocator.alloc(u8, 0) catch return OpPushTxError.OutOfMemory;
    errdefer allocator.free(sig_hex);

    // Encode preimage as hex
    // N-434: `sig_hex` is owned by the errdefer above; freeing it by hand here
    // too would free it twice on every failure path.
    const preimage_hex = allocator.alloc(u8, preimage_bytes.len * 2) catch return OpPushTxError.OutOfMemory;
    errdefer allocator.free(preimage_hex);
    _ = bsvz.primitives.hex.encodeLower(preimage_bytes, preimage_hex) catch return OpPushTxError.InvalidEncoding;

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

// R-178 (CL-BUG-071): an out-of-range code_separator_index used to leave the
// subscript UNTRIMMED and sign it — a wrong scriptCode, with no error, from a
// fund-moving primitive. All seven SDKs mishandled this in four different ways;
// every tier now refuses and names the input.
test "R-178: an out-of-range code separator index is refused" {
    const allocator = std.testing.allocator;

    const tx_hex = "01000000" ++
        "01" ++
        "1111111111111111111111111111111111111111111111111111111111111111" ++
        "00000000" ++
        "00" ++
        "ffffffff" ++
        "01" ++
        "e803000000000000" ++
        "01" ++ "51" ++
        "00000000";

    // Two bytes: OP_CODESEPARATOR then OP_1. Offset 1 is the last valid index.
    const subscript_hex = "ab51";

    for ([_]i32{ 2, 3, 99 }) |idx| {
        const out = computeOpPushTx(allocator, tx_hex, 0, subscript_hex, 1000, idx);
        try std.testing.expectError(OpPushTxError.InvalidCodeSeparatorIndex, out);
    }
}

test "R-178: an in-range code separator index still trims" {
    const allocator = std.testing.allocator;

    const tx_hex = "01000000" ++
        "01" ++
        "1111111111111111111111111111111111111111111111111111111111111111" ++
        "00000000" ++
        "00" ++
        "ffffffff" ++
        "01" ++
        "e803000000000000" ++
        "01" ++ "51" ++
        "00000000";

    const subscript_hex = "ab51";

    var trimmed = try computeOpPushTx(allocator, tx_hex, 0, subscript_hex, 1000, 0);
    defer trimmed.deinit(allocator);
    var untrimmed = try computeOpPushTx(allocator, tx_hex, 0, subscript_hex, 1000, -1);
    defer untrimmed.deinit(allocator);

    // Trimming the subscript must change the preimage, which is what makes the
    // old silent fallthrough a wrong answer rather than a harmless one.
    try std.testing.expect(!std.mem.eql(u8, trimmed.preimage_hex, untrimmed.preimage_hex));
}

// N-041: an empty subscript can never match the script the node executes, so
// building a preimage over it is refused with EmptySubscript. N-155 (below)
// covers the companion case: a non-empty subscript whose separator is its
// last byte, which trims down to the same empty condition.
test "N-041: an empty subscript is refused" {
    const allocator = std.testing.allocator;

    const tx_hex = "01000000" ++
        "01" ++
        "1111111111111111111111111111111111111111111111111111111111111111" ++
        "00000000" ++
        "00" ++
        "ffffffff" ++
        "01" ++
        "e803000000000000" ++
        "01" ++ "51" ++
        "00000000";

    if (computeOpPushTx(allocator, tx_hex, 0, "", 1000, -1)) |r| {
        var res = r;
        res.deinit(allocator);
        return error.TestExpectedError;
    } else |err| try std.testing.expectEqualStrings("EmptySubscript", @errorName(err));

    var ok = try computeOpPushTx(allocator, tx_hex, 0, "51ab51", 1000, 1);
    defer ok.deinit(allocator);
    try std.testing.expect(ok.preimage_hex.len > 0);
}

// N-155: a code_separator_index pointing at the LAST byte of the subscript
// passes R-178's "past the end" check (hex_offset == len, not >) but trims
// script_code_hex down to the empty string -- the same unsignable condition
// as an empty subscript, reached via the separator offset instead. Proves:
// computeOpPushTx refuses this case (EmptySubscript). Does not prove anything
// about ExternalSigner's signImpl (it already rejects any empty
// subscript it is handed -- see "N-041 ExternalSigner refuses an empty
// subscript" in sdk_signer.zig) or about callers upstream that compute the
// code_separator_index they pass in.
test "N-155: a code separator on the subscript's last byte is refused" {
    const allocator = std.testing.allocator;

    const tx_hex = "01000000" ++
        "01" ++
        "1111111111111111111111111111111111111111111111111111111111111111" ++
        "00000000" ++
        "00" ++
        "ffffffff" ++
        "01" ++
        "e803000000000000" ++
        "01" ++ "51" ++
        "00000000";

    // "51" is one byte (OP_1); code_separator_index 0 is its last (and only)
    // byte, so the trimmed scriptCode is empty.
    if (computeOpPushTx(allocator, tx_hex, 0, "51", 1000, 0)) |r| {
        var res = r;
        res.deinit(allocator);
        return error.TestExpectedError;
    } else |err| try std.testing.expectEqualStrings("EmptySubscript", @errorName(err));
}
