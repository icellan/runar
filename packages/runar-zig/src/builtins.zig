const std = @import("std");
const bsvz = @import("bsvz");
const base = @import("base.zig");
const hex = @import("hex.zig");
const test_keys = @import("test_keys.zig");
const wots = @import("wots_helpers.zig");

const Sha256Hasher = std.crypto.hash.sha2.Sha256;
const test_message = "runar-test-message-v1";
const default_zero_20 = [_]u8{0} ** 20;
const default_zero_32 = [_]u8{0} ** 32;
const default_zero_36 = [_]u8{0} ** 36;
const default_zero_64 = [_]u8{0} ** 64;

const sha256_initial_state = [_]u8{
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
    0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
};

const sha256_k = [_]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

const blake3_iv_words = [_]u32{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

// Little-endian encoding of the 8 IV words (standard BLAKE3 encodes CV/IV words
// as little-endian bytes).
const blake3_iv_bytes = [_]u8{
    0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb,
    0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5,
    0x7f, 0x52, 0x0e, 0x51, 0x8c, 0x68, 0x05, 0x9b,
    0xab, 0xd9, 0x83, 0x1f, 0x19, 0xcd, 0xe0, 0x5b,
};

const blake3_msg_perm = [_]u8{ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 };
const secp256k1_order_be = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
};
const wots_w = wots.wots_w;
const wots_n = wots.wots_n;
const wots_len1 = wots.wots_len1;
const wots_len2 = wots.wots_len2;
const wots_len = wots.wots_len;
const slh_adrs_size = 32;
const slh_adrs_wots_hash: u32 = 0;
const slh_adrs_wots_pk: u32 = 1;
const slh_adrs_tree: u32 = 2;
const slh_adrs_fors_tree: u32 = 3;
const slh_adrs_fors_roots: u32 = 4;
const SlhAdrs = [slh_adrs_size]u8;

const SlhParams = struct {
    n: usize,
    h: usize,
    d: usize,
    hp: usize,
    a: usize,
    k: usize,
    len: usize,
    md_len: usize,
    tree_idx_len: usize,
    leaf_idx_len: usize,
    digest_len: usize,
    fors_sig_len: usize,
    xmss_sig_len: usize,
    sig_len: usize,
    wots_parts_len: usize,
    fors_roots_len: usize,
};

fn slhParams(
    comptime n: usize,
    comptime h: usize,
    comptime d: usize,
    comptime hp: usize,
    comptime a: usize,
    comptime k: usize,
    comptime len: usize,
) SlhParams {
    const md_len = (k * a + 7) / 8;
    const tree_idx_len = (h - hp + 7) / 8;
    const leaf_idx_len = (hp + 7) / 8;
    const digest_len = md_len + tree_idx_len + leaf_idx_len;
    const fors_sig_len = k * (1 + a) * n;
    const xmss_sig_len = (len + hp) * n;
    return .{
        .n = n,
        .h = h,
        .d = d,
        .hp = hp,
        .a = a,
        .k = k,
        .len = len,
        .md_len = md_len,
        .tree_idx_len = tree_idx_len,
        .leaf_idx_len = leaf_idx_len,
        .digest_len = digest_len,
        .fors_sig_len = fors_sig_len,
        .xmss_sig_len = xmss_sig_len,
        .sig_len = n + fors_sig_len + (d * xmss_sig_len),
        .wots_parts_len = len * n,
        .fors_roots_len = k * n,
    };
}

const slh_sha2_128s = slhParams(16, 63, 7, 9, 12, 14, 35);
const slh_sha2_128f = slhParams(16, 66, 22, 3, 6, 33, 35);
const slh_sha2_192s = slhParams(24, 63, 7, 9, 14, 17, 51);
const slh_sha2_192f = slhParams(24, 66, 22, 3, 8, 33, 51);
const slh_sha2_256s = slhParams(32, 64, 8, 8, 14, 22, 67);
const slh_sha2_256f = slhParams(32, 68, 17, 4, 8, 35, 67);
pub const assert_failure_message = "runar assertion failed";

pub const MockPreimageParts = struct {
    hashPrevouts: base.Sha256 = default_zero_32[0..],
    outpoint: base.ByteString = default_zero_36[0..],
    outputHash: base.Sha256 = default_zero_32[0..],
    locktime: base.Bigint = 0,
};

pub fn assert(condition: bool) void {
    // CONTRACT-ABORT: assertion failure IS script-failure semantics.
    if (!condition) @panic(assert_failure_message);
}

pub fn sha256(data: base.ByteString) base.Sha256 {
    const digest = bsvz.crypto.hash.sha256(data);
    return dupeBytes(&digest.bytes);
}

/// Alias for `sha256`. Provides an explicitly-named spelling so cross-format
/// contract sources that reference the `Sha256Hash` identifier (resolved by
/// every parser to the `sha256` builtin) have a matching runtime function on
/// the Zig side too.
pub fn sha256Hash(data: base.ByteString) base.Sha256 {
    return sha256(data);
}

pub fn ripemd160(data: base.ByteString) base.Ripemd160 {
    const digest = bsvz.crypto.hash.ripemd160(data);
    return dupeBytes(&digest.bytes);
}

pub fn hash160(data: base.ByteString) base.Addr {
    const digest = bsvz.crypto.hash.hash160(data);
    return dupeBytes(&digest.bytes);
}

pub fn hash256(data: base.ByteString) base.Sha256 {
    const digest = bsvz.crypto.hash.hash256(data);
    return dupeBytes(&digest.bytes);
}

pub fn bytesEq(left: base.ByteString, right: base.ByteString) bool {
    return std.mem.eql(u8, left, right);
}

pub fn checkSig(sig: base.Sig, pub_key: base.PubKey) bool {
    if (sig.len < 8 or pub_key.len == 0) return false;

    const public_key = bsvz.crypto.PublicKey.fromSec1(pub_key) catch return false;
    const parsed_sig = parseChecksigDer(sig) orelse return false;

    return public_key.verifySha256(test_message, parsed_sig) catch false;
}

pub fn checkMultiSig(sigs: []const base.Sig, pub_keys: []const base.PubKey) bool {
    if (sigs.len > pub_keys.len) return false;

    var pub_key_index: usize = 0;
    for (sigs) |sig| {
        var matched = false;
        while (pub_key_index < pub_keys.len) {
            if (checkSig(sig, pub_keys[pub_key_index])) {
                pub_key_index += 1;
                matched = true;
                break;
            }
            pub_key_index += 1;
        }
        if (!matched) return false;
    }
    return true;
}

pub fn checkPreimage(preimage: base.SigHashPreimage) bool {
    _ = bsvz.transaction.Preimage.parse(preimage) catch return false;
    return true;
}

pub const SignTestMessageError = error{
    InvalidFixturePrivateKey,
    FixtureKeyMismatch,
    SigningFailed,
    OutOfMemory,
};

/// Error-returning variant of `signTestMessage`. Prefer this in SDK / host
/// code. The non-`Checked` variant remains panic-based because it is called
/// from Rúnar contract bodies.
pub fn signTestMessageChecked(allocator: std.mem.Allocator, pair: test_keys.TestKeyPair) SignTestMessageError!base.Sig {
    const private_key = parseFixturePrivateKey(pair.privKey) catch return SignTestMessageError.InvalidFixturePrivateKey;
    const derived_pub_key = private_key.publicKey() catch return SignTestMessageError.InvalidFixturePrivateKey;
    if (!std.mem.eql(u8, &derived_pub_key.bytes, pair.pubKey)) {
        return SignTestMessageError.FixtureKeyMismatch;
    }

    if (lookupCanonicalFixtureSig(pair)) |sig_bytes| {
        return allocator.dupe(u8, sig_bytes) catch return SignTestMessageError.OutOfMemory;
    }

    const sig = private_key.signSha256(test_message) catch return SignTestMessageError.SigningFailed;
    return allocator.dupe(u8, sig.asSlice()) catch return SignTestMessageError.OutOfMemory;
}

pub fn signTestMessage(pair: test_keys.TestKeyPair) base.Sig {
    // INTERNAL-INVARIANT semantics: fixture keys are compile-time constants
    // (test_keys.ALICE/BOB/CHARLIE). Any failure here indicates a malformed
    // fixture, not caller input. Called from test contract bodies with no
    // error channel.
    return signTestMessageChecked(std.heap.page_allocator, pair) catch |err| switch (err) {
        SignTestMessageError.InvalidFixturePrivateKey => @panic("invalid fixture private key"),
        SignTestMessageError.FixtureKeyMismatch => @panic("fixture private/public key mismatch"),
        SignTestMessageError.SigningFailed => @panic("unable to sign fixture test message"),
        SignTestMessageError.OutOfMemory => @panic("OOM"),
    };
}

pub const MockPreimageError = error{
    OutOfMemory,
    LocktimeOutOfRange,
};

/// Error-returning variant of `mockPreimage`. Prefer this in SDK / harness
/// code that can handle allocation failure or invalid caller input. The
/// non-`Checked` variant remains panic-based because it is called directly
/// from Rúnar contract bodies (which cannot propagate errors — contract
/// method signatures compile to Bitcoin Script and have no error channel).
pub fn mockPreimageChecked(allocator: std.mem.Allocator, parts: MockPreimageParts) MockPreimageError!base.SigHashPreimage {
    var encoded = allocator.alloc(u8, 4 + 32 + 32 + 36 + 1 + 8 + 4 + 32 + 4 + 4) catch return MockPreimageError.OutOfMemory;
    std.mem.writeInt(i32, encoded[0..4], 2, .little);
    copyFixed(encoded[4..36], parts.hashPrevouts);
    @memset(encoded[36..68], 0);
    copyFixed(encoded[68..104], parts.outpoint);
    encoded[104] = 0x00;
    @memset(encoded[105..113], 0);
    std.mem.writeInt(u32, encoded[113..117], 0xffff_ffff, .little);
    copyFixed(encoded[117..149], parts.outputHash);
    const locktime: u32 = std.math.cast(u32, parts.locktime) orelse return MockPreimageError.LocktimeOutOfRange;
    std.mem.writeInt(u32, encoded[149..153], locktime, .little);
    std.mem.writeInt(u32, encoded[153..157], 0x41, .little);
    return encoded;
}

pub fn mockPreimage(parts: MockPreimageParts) base.SigHashPreimage {
    // CONTRACT-ABORT semantics: called from test contract bodies which have
    // no error channel. Allocation failure here is treated as script-abort.
    return mockPreimageChecked(std.heap.page_allocator, parts) catch |err| switch (err) {
        MockPreimageError.OutOfMemory => @panic("OOM"),
        MockPreimageError.LocktimeOutOfRange => @panic("mockPreimage: locktime out of range"),
    };
}

pub fn extractHashPrevouts(preimage: base.SigHashPreimage) base.Sha256 {
    const extracted = bsvz.transaction.extractHashPrevouts(preimage) catch return default_zero_32[0..];
    return dupeBytes(&extracted.bytes);
}

pub fn extractOutpoint(preimage: base.SigHashPreimage) base.ByteString {
    const extracted = bsvz.transaction.extractOutpointBytes(preimage) catch return default_zero_36[0..];
    return dupeBytes(&extracted);
}

pub fn extractOutputHash(preimage: base.SigHashPreimage) base.Sha256 {
    const extracted = bsvz.transaction.extractOutputHash(preimage) catch return default_zero_32[0..];
    return dupeBytes(&extracted.bytes);
}

pub fn extractLocktime(preimage: base.SigHashPreimage) base.Bigint {
    const extracted = bsvz.transaction.extractLocktime(preimage) catch return 0;
    return extracted;
}

// ============================================================================
// Intent sub-covenant intrinsics (BSVM Phase 13)
//
// Test-mode stubs for the witness-bridge intrinsics. The compiler frontend
// desugars these into on-chain assertions (hash256 / extractOutputHash /
// substr / extractLocktime) plus auto-injected witness params, so these
// runtime stubs only need to satisfy the off-chain native build of Zig
// contracts. See docs/cross-covenant-pattern.md.
// ============================================================================

/// extractPrevOutputScript is the test-mode stub for the cross-input
/// previous-output script witness-bridge intrinsic. The compiler emits
/// hash256(witness) == expectedScriptHash on-chain; the off-chain mock
/// cannot see other inputs, so this returns an empty ByteString.
pub fn extractPrevOutputScript(input_index: base.Bigint, expected_script_hash: base.ByteString) base.ByteString {
    _ = input_index;
    _ = expected_script_hash;
    return &[_]u8{};
}

/// requireOutputP2PKH is the test-mode stub for the P2PKH-output-binding
/// intrinsic. The compiler emits a hashOutputs reconstruction + substring
/// assertion on-chain; the off-chain mock has no real outputs to inspect,
/// so this is a no-op.
pub fn requireOutputP2PKH(output_index: base.Bigint, pubkey_hash: base.ByteString, amount: base.Bigint) void {
    _ = output_index;
    _ = pubkey_hash;
    _ = amount;
}

/// currentBlockHeight is the test-mode stub for the locktime-as-height
/// shorthand. On-chain the compiler desugars to extractLocktime(txPreimage).
pub fn currentBlockHeight() base.Bigint {
    return 0;
}

pub const BuildChangeOutputError = error{
    OutOfMemory,
    InvalidPubKeyHashLength,
};

/// Error-returning variant of `buildChangeOutput`. Prefer this in SDK / host
/// code where allocation or caller-supplied input validation failures are
/// recoverable. The non-`Checked` variant remains panic-based because it is
/// called directly from Rúnar contract bodies (which cannot propagate errors
/// — contract method signatures compile to Bitcoin Script and have no error
/// channel).
pub fn buildChangeOutputChecked(allocator: std.mem.Allocator, pkh: base.ByteString, amount: base.Bigint) BuildChangeOutputError!base.ByteString {
    if (pkh.len != 20) return BuildChangeOutputError.InvalidPubKeyHashLength;

    var pubkey_hash: bsvz.crypto.Hash160 = undefined;
    @memcpy(&pubkey_hash.bytes, pkh[0..20]);

    const locking_script = bsvz.script.templates.p2pkh.encode(pubkey_hash);
    const output = bsvz.transaction.Output{
        .satoshis = amount,
        .locking_script = .{
            .bytes = &locking_script,
        },
    };
    const out = allocator.alloc(u8, output.serializedLen()) catch return BuildChangeOutputError.OutOfMemory;
    _ = output.writeInto(out);

    return out;
}

pub fn buildChangeOutput(pkh: base.ByteString, amount: base.Bigint) base.ByteString {
    // CONTRACT-ABORT semantics: called from test contract bodies (e.g.
    // CovenantVault.runar.zig) which have no error channel. Length / OOM
    // failures surface as script-abort panics, matching Bitcoin Script
    // verification semantics.
    return buildChangeOutputChecked(std.heap.page_allocator, pkh, amount) catch |err| switch (err) {
        BuildChangeOutputError.OutOfMemory => @panic("OOM"),
        BuildChangeOutputError.InvalidPubKeyHashLength => @panic("buildChangeOutput: pubkey hash must be 20 bytes"),
    };
}

pub fn cat(left: base.ByteString, right: base.ByteString) base.ByteString {
    // CONTRACT-ABORT: in-contract builtin; page_allocator failure is treated
    // as script-abort. Size is bounded by Bitcoin Script max element size.
    return bsvz.script.cat(std.heap.page_allocator, left, right) catch @panic("OOM");
}

pub const bytesConcat = cat;

pub fn hexToBytes(comptime hex_str: []const u8) *const [hex_str.len / 2]u8 {
    return comptime blk: {
        var out: [hex_str.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
        const final = out;
        break :blk &final;
    };
}

pub fn substr(bytes: base.ByteString, start: base.Bigint, len: base.Bigint) base.ByteString {
    if (start < 0 or len <= 0) return &.{};
    const start_usize = std.math.cast(usize, start) orelse return &.{};
    const len_usize = std.math.cast(usize, len) orelse return &.{};
    // CONTRACT-ABORT: in-contract builtin; page_allocator failure = script-abort.
    return bsvz.script.substr(std.heap.page_allocator, bytes, start_usize, len_usize) catch @panic("OOM");
}

pub fn num2bin(value: anytype, size: base.Bigint) base.ByteString {
    if (size < 0) return &.{};
    const size_usize = std.math.cast(usize, size) orelse return &.{};
    // CONTRACT-ABORT: in-contract builtin; OOM = script-abort.
    var script_num = scriptNumFromValue(std.heap.page_allocator, value) catch @panic("OOM");
    defer script_num.deinit();
    return script_num.num2binOwned(std.heap.page_allocator, size_usize) catch |err| switch (err) {
        // CONTRACT-ABORT: Bitcoin Script OP_NUM2BIN semantics — size too
        // small for the value's encoding fails the script.
        error.InvalidEncoding => @panic("num2bin: size too small"),
        error.OutOfMemory => @panic("OOM"),
    };
}

pub fn bin2num(bytes: base.ByteString) SignedBigint {
    // CONTRACT-ABORT: in-contract builtin; malformed encoding = script-abort
    // matching Bitcoin Script OP_BIN2NUM semantics.
    var script_num = bsvz.script.ScriptNum.bin2num(std.heap.page_allocator, bytes) catch @panic("bin2num: invalid encoding");
    defer script_num.deinit();
    return signedBigintFromScriptNum(&script_num);
}

/// Bitcoin Script's OP_WITHIN semantics: `lo <= value < hi` (half-open).
/// Used by the BUG-001 schnorr s-bound malleability gate.
pub fn within(value: base.Bigint, lo: base.Bigint, hi: base.Bigint) bool {
    return value >= lo and value < hi;
}

pub fn clamp(value: base.Bigint, lo: base.Bigint, hi: base.Bigint) base.Bigint {
    return @max(lo, @min(hi, value));
}

pub fn safediv(lhs: base.Bigint, rhs: base.Bigint) base.Bigint {
    if (rhs == 0) return 0;
    return @divTrunc(lhs, rhs);
}

pub fn safemod(lhs: base.Bigint, rhs: base.Bigint) base.Bigint {
    if (rhs == 0) return 0;
    return @rem(lhs, rhs);
}

pub fn sign(value: base.Bigint) base.Bigint {
    return if (value < 0) -1 else if (value > 0) 1 else 0;
}

pub fn pow(base_value: base.Bigint, exponent: base.Bigint) base.Bigint {
    // CONTRACT-ABORT: negative exponent is an in-contract math error.
    if (exponent < 0) @panic("pow: negative exponent");
    if (exponent == 0) return 1;

    var result: i64 = 1;
    var factor = base_value;
    var remaining: u64 = @intCast(exponent);
    while (remaining != 0) : (remaining >>= 1) {
        if ((remaining & 1) != 0) result = checkedMul(result, factor);
        if (remaining > 1) factor = checkedMul(factor, factor);
    }
    return result;
}

pub fn mulDiv(a: base.Bigint, b: base.Bigint, divisor: base.Bigint) base.Bigint {
    if (divisor == 0) return 0;
    return @divTrunc(checkedMul(a, b), divisor);
}

pub fn percentOf(value: base.Bigint, percentage: base.Bigint) base.Bigint {
    return @divTrunc(checkedMul(value, percentage), 100);
}

pub fn sqrt(value: base.Bigint) base.Bigint {
    if (value <= 0) return 0;

    var x = value;
    var y = @divTrunc(value, 2) + 1;
    while (y < x) {
        x = y;
        y = @divTrunc(y + @divTrunc(value, y), 2);
    }
    return x;
}

pub fn gcd(a: base.Bigint, b: base.Bigint) base.Bigint {
    var x = checkedAbs(a);
    var y = checkedAbs(b);
    while (y != 0) {
        const next = @mod(x, y);
        x = y;
        y = next;
    }
    return x;
}

pub fn log2(value: base.Bigint) base.Bigint {
    if (value <= 1) return 0;

    var count: i64 = 0;
    var current = value;
    while (current > 1) : (count += 1) {
        current = @divTrunc(current, 2);
    }
    return count;
}

pub fn sha256Compress(chaining_value: base.ByteString, block: base.ByteString) base.ByteString {
    // CONTRACT-ABORT: length invariants of the in-contract SHA-256 builtin.
    if (chaining_value.len != 32) @panic("sha256Compress: state must be 32 bytes");
    if (block.len != 64) @panic("sha256Compress: block must be 64 bytes");

    var out: [32]u8 = undefined;
    sha256CompressBlock(&out, chaining_value, block);
    return dupeBytes(&out);
}

pub fn sha256Finalize(chaining_value: base.ByteString, remaining: base.ByteString, total_len: base.Bigint) base.ByteString {
    // CONTRACT-ABORT: length / range invariants of the in-contract SHA-256 finalize builtin.
    if (chaining_value.len != 32) @panic("sha256Finalize: state must be 32 bytes");
    if (remaining.len > 119) @panic("sha256Finalize: remaining must be <= 119 bytes");
    if (total_len < 0) @panic("sha256Finalize: total bit length must be non-negative");

    const blocks: usize = if (remaining.len + 1 + 8 <= 64) 1 else 2;
    const total_bytes = blocks * 64;

    var padded = [_]u8{0} ** 128;
    @memcpy(padded[0..remaining.len], remaining);
    padded[remaining.len] = 0x80;
    std.mem.writeInt(u64, padded[total_bytes - 8 .. total_bytes][0..8], @intCast(total_len), .big);

    var out: [32]u8 = undefined;
    if (blocks == 1) {
        sha256CompressBlock(&out, chaining_value, padded[0..64]);
        return dupeBytes(&out);
    }

    var mid: [32]u8 = undefined;
    sha256CompressBlock(&mid, chaining_value, padded[0..64]);
    sha256CompressBlock(&out, &mid, padded[64..128]);
    return dupeBytes(&out);
}

// Single-block BLAKE3 compression. BLAKE3 is little-endian: the chaining value
// and block are parsed as little-endian u32 words and the digest is emitted as
// little-endian bytes. `block_len` is the state word v[14] — the real message
// length for blake3Hash, or the constant 64 for a full-block blake3Compress.
fn blake3CompressBlock(chaining_value: base.ByteString, block: base.ByteString, block_len: u32) base.ByteString {
    var h: [8]u32 = undefined;
    var m: [16]u32 = undefined;
    for (0..8) |index| {
        h[index] = std.mem.readInt(u32, chaining_value[index * 4 ..][0..4], .little);
    }
    for (0..16) |index| {
        m[index] = std.mem.readInt(u32, block[index * 4 ..][0..4], .little);
    }

    var state = [_]u32{
        h[0], h[1], h[2], h[3],
        h[4], h[5], h[6], h[7],
        blake3_iv_words[0], blake3_iv_words[1], blake3_iv_words[2], blake3_iv_words[3],
        0, 0, block_len, 11,
    };
    var msg = m;
    for (0..7) |round_index| {
        blake3Round(&state, &msg);
        if (round_index < 6) msg = blake3Permute(msg);
    }

    var out: [32]u8 = undefined;
    for (0..8) |index| {
        const word = state[index] ^ state[index + 8];
        std.mem.writeInt(u32, out[index * 4 ..][0..4], word, .little);
    }
    return dupeBytes(&out);
}

pub fn blake3Compress(chaining_value: base.ByteString, block: base.ByteString) base.ByteString {
    // CONTRACT-ABORT: length invariants of the in-contract Blake3 builtin.
    if (chaining_value.len != 32) @panic("blake3Compress: chaining value must be 32 bytes");
    if (block.len != 64) @panic("blake3Compress: block must be 64 bytes");

    // Full 64-byte block → block_len = 64.
    return blake3CompressBlock(chaining_value, block, 64);
}

pub fn blake3Hash(message: base.ByteString) base.ByteString {
    // CONTRACT-ABORT: message length invariant of the in-contract Blake3 builtin.
    if (message.len > 64) @panic("blake3Hash: message must be <= 64 bytes");

    var block = [_]u8{0} ** 64;
    @memcpy(block[0..message.len], message);
    // Standard BLAKE3: v[14] = real message length (0..64), IV as LE chaining value.
    return blake3CompressBlock(blake3_iv_bytes[0..], &block, @intCast(message.len));
}

// Mirrors the on-chain Rabin codegen's OP_WITHIN bound (0 <= padding < 65536).
// Without it the off-chain verifier accepts a universal forgery the deployed
// script rejects: sig=0, padding=SHA256(msg) gives (0^2 + SHA256(msg)) mod n
// == SHA256(msg) mod n, validating against any message/modulus.
const RABIN_PADDING_LIMIT: u64 = 65536;

pub fn verifyRabinSig(message: base.ByteString, sig: base.RabinSig, padding: base.ByteString, pub_key: base.RabinPubKey) bool {
    var modulus = BigUint.fromLeBytes(std.heap.page_allocator, pub_key) catch return false;
    defer modulus.deinit();
    if (modulus.isZero()) return false;

    var hash_bytes: [32]u8 = undefined;
    Sha256Hasher.hash(message, &hash_bytes, .{});

    var hash_bn = BigUint.fromLeBytes(std.heap.page_allocator, &hash_bytes) catch return false;
    defer hash_bn.deinit();
    var sig_bn = BigUint.fromLeBytes(std.heap.page_allocator, sig) catch return false;
    defer sig_bn.deinit();
    var pad_bn = BigUint.fromLeBytes(std.heap.page_allocator, padding) catch return false;
    defer pad_bn.deinit();

    // Enforce 0 <= padding < 65536 (padding is unsigned, so the lower bound is free).
    var pad_limit = BigUint.fromU64(std.heap.page_allocator, RABIN_PADDING_LIMIT) catch return false;
    defer pad_limit.deinit();
    if (pad_bn.cmp(&pad_limit) != .lt) return false;

    var sig_sq = sig_bn.mul(&sig_bn) catch return false;
    defer sig_sq.deinit();
    var lhs_sum = sig_sq.add(&pad_bn) catch return false;
    defer lhs_sum.deinit();
    var lhs = lhs_sum.rem(&modulus) catch return false;
    defer lhs.deinit();
    var rhs = hash_bn.rem(&modulus) catch return false;
    defer rhs.deinit();

    return lhs.eql(&rhs);
}

pub fn verifyWOTS(message: base.ByteString, sig: base.ByteString, pub_key: base.ByteString) bool {
    if (sig.len != wots_len * wots_n) return false;
    if (pub_key.len != 2 * wots_n) return false;

    const pub_seed = pub_key[0..wots_n];
    const pk_root = pub_key[wots_n .. 2 * wots_n];
    var msg_hash: [32]u8 = undefined;
    Sha256Hasher.hash(message, &msg_hash, .{});

    const digits = wots.allDigits(&msg_hash);
    // CONTRACT-ABORT: in-contract WOTS+ verifier; OOM = script-abort.
    var endpoints = std.heap.page_allocator.alloc(u8, wots_len * wots_n) catch @panic("OOM");
    defer std.heap.page_allocator.free(endpoints);

    for (0..wots_len) |i| {
        const sig_element = sig[i * wots_n ..][0..wots_n];
        const remaining = (wots_w - 1) - digits[i];
        const endpoint = wots.chain(sig_element, digits[i], remaining, pub_seed, i);
        @memcpy(endpoints[i * wots_n ..][0..wots_n], &endpoint);
    }

    var computed_root: [32]u8 = undefined;
    Sha256Hasher.hash(endpoints, &computed_root, .{});
    return std.mem.eql(u8, &computed_root, pk_root);
}

pub fn verifySLHDSA_SHA2_128s(message: base.ByteString, sig: base.ByteString, pub_key: base.ByteString) bool {
    return slhVerifySha2(slh_sha2_128s, message, sig, pub_key);
}

pub fn verifySLHDSA_SHA2_128f(message: base.ByteString, sig: base.ByteString, pub_key: base.ByteString) bool {
    return slhVerifySha2(slh_sha2_128f, message, sig, pub_key);
}

pub fn verifySLHDSA_SHA2_192s(message: base.ByteString, sig: base.ByteString, pub_key: base.ByteString) bool {
    return slhVerifySha2(slh_sha2_192s, message, sig, pub_key);
}

pub fn verifySLHDSA_SHA2_192f(message: base.ByteString, sig: base.ByteString, pub_key: base.ByteString) bool {
    return slhVerifySha2(slh_sha2_192f, message, sig, pub_key);
}

pub fn verifySLHDSA_SHA2_256s(message: base.ByteString, sig: base.ByteString, pub_key: base.ByteString) bool {
    return slhVerifySha2(slh_sha2_256s, message, sig, pub_key);
}

pub fn verifySLHDSA_SHA2_256f(message: base.ByteString, sig: base.ByteString, pub_key: base.ByteString) bool {
    return slhVerifySha2(slh_sha2_256f, message, sig, pub_key);
}

fn slhVerifySha2(comptime params: SlhParams, message: []const u8, sig: []const u8, pub_key: []const u8) bool {
    if (pub_key.len != 2 * params.n) return false;
    if (sig.len < params.sig_len) return false;

    const pk_seed = pub_key[0..params.n];
    const pk_root = pub_key[params.n .. 2 * params.n];

    var offset: usize = 0;
    const r = sig[offset .. offset + params.n];
    offset += params.n;

    const fors_sig = sig[offset .. offset + params.fors_sig_len];
    offset += params.fors_sig_len;

    const digest = slhHmsg(params, r, pk_seed, pk_root, message);
    const md = digest[0..params.md_len];

    var tree_idx: u64 = 0;
    for (digest[params.md_len .. params.md_len + params.tree_idx_len]) |byte| {
        tree_idx = (tree_idx << 8) | @as(u64, byte);
    }
    const tree_bits = params.h - params.hp;
    if (tree_bits < 64) {
        tree_idx &= (@as(u64, 1) << @intCast(tree_bits)) - 1;
    }

    var leaf_idx: u32 = 0;
    for (digest[params.md_len + params.tree_idx_len ..]) |byte| {
        leaf_idx = (leaf_idx << 8) | @as(u32, byte);
    }
    leaf_idx &= (@as(u32, 1) << @intCast(params.hp)) - 1;

    var fors_adrs = slhNewAdrs();
    slhSetTreeAddress(&fors_adrs, tree_idx);
    slhSetType(&fors_adrs, slh_adrs_fors_tree);
    slhSetKeyPairAddress(&fors_adrs, leaf_idx);
    var current_msg = slhForsPkFromSig(params, fors_sig, md, pk_seed, &fors_adrs);

    var current_tree_idx = tree_idx;
    var current_leaf_idx = leaf_idx;

    for (0..params.d) |layer| {
        if (sig.len < offset + params.xmss_sig_len) return false;
        const xmss_sig = sig[offset .. offset + params.xmss_sig_len];
        offset += params.xmss_sig_len;

        var layer_adrs = slhNewAdrs();
        slhSetLayerAddress(&layer_adrs, @intCast(layer));
        slhSetTreeAddress(&layer_adrs, current_tree_idx);

        current_msg = slhXmssPkFromSig(params, current_leaf_idx, xmss_sig, &current_msg, pk_seed, &layer_adrs);
        current_leaf_idx = @intCast(current_tree_idx & ((@as(u64, 1) << @intCast(params.hp)) - 1));
        current_tree_idx >>= @intCast(params.hp);
    }

    return std.mem.eql(u8, &current_msg, pk_root);
}

fn slhNewAdrs() SlhAdrs {
    return [_]u8{0} ** slh_adrs_size;
}

fn slhSetLayerAddress(adrs: *SlhAdrs, layer: u32) void {
    adrs[0] = @truncate(layer >> 24);
    adrs[1] = @truncate(layer >> 16);
    adrs[2] = @truncate(layer >> 8);
    adrs[3] = @truncate(layer);
}

fn slhSetTreeAddress(adrs: *SlhAdrs, tree: u64) void {
    for (0..12) |i| {
        const shift = 8 * i;
        adrs[4 + 11 - i] = if (shift < 64) @truncate(tree >> @intCast(shift)) else 0;
    }
}

fn slhSetType(adrs: *SlhAdrs, value: u32) void {
    adrs[16] = @truncate(value >> 24);
    adrs[17] = @truncate(value >> 16);
    adrs[18] = @truncate(value >> 8);
    adrs[19] = @truncate(value);
    @memset(adrs[20..32], 0);
}

fn slhSetKeyPairAddress(adrs: *SlhAdrs, value: u32) void {
    adrs[20] = @truncate(value >> 24);
    adrs[21] = @truncate(value >> 16);
    adrs[22] = @truncate(value >> 8);
    adrs[23] = @truncate(value);
}

fn slhSetChainAddress(adrs: *SlhAdrs, value: u32) void {
    adrs[24] = @truncate(value >> 24);
    adrs[25] = @truncate(value >> 16);
    adrs[26] = @truncate(value >> 8);
    adrs[27] = @truncate(value);
}

fn slhSetHashAddress(adrs: *SlhAdrs, value: u32) void {
    adrs[28] = @truncate(value >> 24);
    adrs[29] = @truncate(value >> 16);
    adrs[30] = @truncate(value >> 8);
    adrs[31] = @truncate(value);
}

fn slhSetTreeHeight(adrs: *SlhAdrs, value: u32) void {
    slhSetChainAddress(adrs, value);
}

fn slhSetTreeIndex(adrs: *SlhAdrs, value: u32) void {
    slhSetHashAddress(adrs, value);
}

fn slhGetKeyPairAddress(adrs: *const SlhAdrs) u32 {
    return (@as(u32, adrs[20]) << 24) |
        (@as(u32, adrs[21]) << 16) |
        (@as(u32, adrs[22]) << 8) |
        @as(u32, adrs[23]);
}

fn slhCompressAdrs(adrs: *const SlhAdrs) [22]u8 {
    var compressed: [22]u8 = undefined;
    compressed[0] = adrs[3];
    @memcpy(compressed[1..9], adrs[8..16]);
    compressed[9] = adrs[19];
    @memcpy(compressed[10..22], adrs[20..32]);
    return compressed;
}

fn slhSha256Hash(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256Hasher.hash(data, &out, .{});
    return out;
}

fn slhT(comptime params: SlhParams, pk_seed: []const u8, adrs: *const SlhAdrs, msg: []const u8) [params.n]u8 {
    const compressed_adrs = slhCompressAdrs(adrs);
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(std.heap.page_allocator);

    // CONTRACT-ABORT: in-contract SLH-DSA helper; OOM = script-abort.
    input.appendSlice(std.heap.page_allocator, pk_seed) catch @panic("OOM");
    input.appendNTimes(std.heap.page_allocator, 0, 64 - params.n) catch @panic("OOM");
    input.appendSlice(std.heap.page_allocator, &compressed_adrs) catch @panic("OOM");
    input.appendSlice(std.heap.page_allocator, msg) catch @panic("OOM");

    const hash = slhSha256Hash(input.items);
    var out: [params.n]u8 = undefined;
    @memcpy(&out, hash[0..params.n]);
    return out;
}

fn slhHmsg(comptime params: SlhParams, r: []const u8, pk_seed: []const u8, pk_root: []const u8, msg: []const u8) [params.digest_len]u8 {
    var seed: std.ArrayList(u8) = .empty;
    defer seed.deinit(std.heap.page_allocator);

    // CONTRACT-ABORT: in-contract SLH-DSA helper; OOM = script-abort.
    seed.appendSlice(std.heap.page_allocator, r) catch @panic("OOM");
    seed.appendSlice(std.heap.page_allocator, pk_seed) catch @panic("OOM");
    seed.appendSlice(std.heap.page_allocator, pk_root) catch @panic("OOM");
    seed.appendSlice(std.heap.page_allocator, msg) catch @panic("OOM");

    // FIPS 205 Section 11.2.1: H_msg(R, PK.seed, PK.root, M) =
    //   MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m)
    // The `R || PK.seed` prefix on the MGF1 seed is mandatory -- it mitigates
    // multi-target long-message second-preimage attacks. See issue #137.
    const inner = slhSha256Hash(seed.items);

    var mgf_seed: std.ArrayList(u8) = .empty;
    defer mgf_seed.deinit(std.heap.page_allocator);
    // CONTRACT-ABORT: in-contract SLH-DSA helper; OOM = script-abort.
    mgf_seed.appendSlice(std.heap.page_allocator, r) catch @panic("OOM");
    mgf_seed.appendSlice(std.heap.page_allocator, pk_seed) catch @panic("OOM");
    mgf_seed.appendSlice(std.heap.page_allocator, &inner) catch @panic("OOM");

    var out: [params.digest_len]u8 = undefined;
    var offset: usize = 0;
    var counter: u32 = 0;
    while (offset < params.digest_len) : (counter += 1) {
        var block_input: [2 * params.n + 32 + 4]u8 = undefined;
        @memcpy(block_input[0 .. mgf_seed.items.len], mgf_seed.items);
        std.mem.writeInt(u32, block_input[mgf_seed.items.len..][0..4], counter, .big);
        const block = slhSha256Hash(&block_input);
        const copy_len = @min(32, params.digest_len - offset);
        @memcpy(out[offset..][0..copy_len], block[0..copy_len]);
        offset += copy_len;
    }
    return out;
}

fn slhBase16MsgDigits(comptime params: SlhParams, msg: []const u8) [2 * params.n]u32 {
    var digits = [_]u32{0} ** (2 * params.n);
    var index: usize = 0;
    for (msg) |byte| {
        if (index >= digits.len) break;
        digits[index] = byte >> 4;
        index += 1;
        if (index >= digits.len) break;
        digits[index] = byte & 0x0f;
        index += 1;
    }
    return digits;
}

fn slhBase16ChecksumDigits(comptime params: SlhParams, bytes: [2]u8) [params.len - (2 * params.n)]u32 {
    var digits = [_]u32{0} ** (params.len - (2 * params.n));
    if (digits.len > 0) digits[0] = bytes[0] >> 4;
    if (digits.len > 1) digits[1] = bytes[0] & 0x0f;
    if (digits.len > 2) digits[2] = bytes[1] >> 4;
    return digits;
}

fn slhWotsChain(comptime params: SlhParams, x: []const u8, start: u32, steps: u32, pk_seed: []const u8, adrs: *SlhAdrs) [params.n]u8 {
    var tmp: [params.n]u8 = undefined;
    @memcpy(&tmp, x[0..params.n]);

    var j = start;
    while (j < start + steps) : (j += 1) {
        slhSetHashAddress(adrs, j);
        tmp = slhT(params, pk_seed, adrs, &tmp);
    }
    return tmp;
}

fn slhWotsPkFromSig(comptime params: SlhParams, sig: []const u8, msg: []const u8, pk_seed: []const u8, adrs: *const SlhAdrs) [params.n]u8 {
    const msg_digits = slhBase16MsgDigits(params, msg);

    var csum: u32 = 0;
    for (msg_digits) |digit| csum += 15 - digit;
    const shifted_csum = csum << 4;
    const csum_bytes = [2]u8{
        @truncate(shifted_csum >> 8),
        @truncate(shifted_csum),
    };
    const csum_digits = slhBase16ChecksumDigits(params, csum_bytes);

    var all_digits: [params.len]u32 = undefined;
    @memcpy(all_digits[0 .. 2 * params.n], &msg_digits);
    @memcpy(all_digits[2 * params.n .. params.len], &csum_digits);

    const kp_addr = slhGetKeyPairAddress(adrs);
    var tmp_adrs = adrs.*;
    slhSetType(&tmp_adrs, slh_adrs_wots_hash);
    slhSetKeyPairAddress(&tmp_adrs, kp_addr);

    var parts: [params.wots_parts_len]u8 = undefined;
    for (0..params.len) |i| {
        slhSetChainAddress(&tmp_adrs, @intCast(i));
        const sig_i = sig[i * params.n ..][0..params.n];
        const endpoint = slhWotsChain(params, sig_i, all_digits[i], 15 - all_digits[i], pk_seed, &tmp_adrs);
        @memcpy(parts[i * params.n ..][0..params.n], &endpoint);
    }

    // FIPS 205 Algorithm 8 lines 8-11: setTypeAndClear(WOTS_PK) zeroes bytes
    // 20-31, so the key pair address MUST be restored afterwards. See #137.
    var pk_adrs = adrs.*;
    slhSetType(&pk_adrs, slh_adrs_wots_pk);
    slhSetKeyPairAddress(&pk_adrs, kp_addr);
    return slhT(params, pk_seed, &pk_adrs, &parts);
}

fn slhXmssPkFromSig(comptime params: SlhParams, idx: u32, sig_xmss: []const u8, msg: []const u8, pk_seed: []const u8, adrs: *const SlhAdrs) [params.n]u8 {
    const wots_sig = sig_xmss[0..params.wots_parts_len];
    const auth = sig_xmss[params.wots_parts_len..];

    var w_adrs = adrs.*;
    slhSetType(&w_adrs, slh_adrs_wots_hash);
    slhSetKeyPairAddress(&w_adrs, idx);
    var node = slhWotsPkFromSig(params, wots_sig, msg, pk_seed, &w_adrs);

    var tree_adrs = adrs.*;
    slhSetType(&tree_adrs, slh_adrs_tree);
    for (0..params.hp) |j| {
        const auth_j = auth[j * params.n ..][0..params.n];
        slhSetTreeHeight(&tree_adrs, @intCast(j + 1));
        slhSetTreeIndex(&tree_adrs, idx >> @intCast(j + 1));

        var combined: [2 * params.n]u8 = undefined;
        if (((idx >> @intCast(j)) & 1) == 0) {
            @memcpy(combined[0..params.n], &node);
            @memcpy(combined[params.n .. 2 * params.n], auth_j);
        } else {
            @memcpy(combined[0..params.n], auth_j);
            @memcpy(combined[params.n .. 2 * params.n], &node);
        }
        node = slhT(params, pk_seed, &tree_adrs, &combined);
    }

    return node;
}

fn slhExtractForsIdx(md: []const u8, tree_idx: usize, a: usize) u32 {
    const bit_start = tree_idx * a;
    const byte_start = bit_start / 8;
    const bit_offset = bit_start % 8;

    var value: u32 = 0;
    var bits_read: usize = 0;
    var i = byte_start;
    while (bits_read < a) : (i += 1) {
        const byte = if (i < md.len) md[i] else 0;
        const available_bits = if (i == byte_start) 8 - bit_offset else 8;
        const bits_to_take = @min(available_bits, a - bits_read);
        const shift = if (i == byte_start) available_bits - bits_to_take else 8 - bits_to_take;
        const mask = (@as(u32, 1) << @intCast(bits_to_take)) - 1;
        value = (value << @intCast(bits_to_take)) | ((@as(u32, byte) >> @intCast(shift)) & mask);
        bits_read += bits_to_take;
    }

    return value;
}

fn slhForsPkFromSig(comptime params: SlhParams, fors_sig: []const u8, md: []const u8, pk_seed: []const u8, adrs: *const SlhAdrs) [params.n]u8 {
    var roots: [params.fors_roots_len]u8 = undefined;
    var offset: usize = 0;

    for (0..params.k) |i| {
        const idx = slhExtractForsIdx(md, i, params.a);
        const sk = fors_sig[offset .. offset + params.n];
        offset += params.n;

        var leaf_adrs = adrs.*;
        slhSetType(&leaf_adrs, slh_adrs_fors_tree);
        slhSetKeyPairAddress(&leaf_adrs, slhGetKeyPairAddress(adrs));
        slhSetTreeHeight(&leaf_adrs, 0);
        const tree_span = @as(u32, 1) << @intCast(params.a);
        slhSetTreeIndex(&leaf_adrs, @intCast((@as(u32, @intCast(i)) * tree_span) + idx));
        var node = slhT(params, pk_seed, &leaf_adrs, sk);

        var auth_adrs = adrs.*;
        slhSetType(&auth_adrs, slh_adrs_fors_tree);
        slhSetKeyPairAddress(&auth_adrs, slhGetKeyPairAddress(adrs));

        for (0..params.a) |j| {
            const auth_j = fors_sig[offset .. offset + params.n];
            offset += params.n;

            slhSetTreeHeight(&auth_adrs, @intCast(j + 1));
            const level_span = @as(u32, 1) << @intCast(params.a - j - 1);
            slhSetTreeIndex(&auth_adrs, (@as(u32, @intCast(i)) * level_span) + (idx >> @intCast(j + 1)));

            var combined: [2 * params.n]u8 = undefined;
            if (((idx >> @intCast(j)) & 1) == 0) {
                @memcpy(combined[0..params.n], &node);
                @memcpy(combined[params.n .. 2 * params.n], auth_j);
            } else {
                @memcpy(combined[0..params.n], auth_j);
                @memcpy(combined[params.n .. 2 * params.n], &node);
            }
            node = slhT(params, pk_seed, &auth_adrs, &combined);
        }

        @memcpy(roots[i * params.n ..][0..params.n], &node);
    }

    var fors_pk_adrs = adrs.*;
    slhSetType(&fors_pk_adrs, slh_adrs_fors_roots);
    slhSetKeyPairAddress(&fors_pk_adrs, slhGetKeyPairAddress(adrs));
    return slhT(params, pk_seed, &fors_pk_adrs, &roots);
}

pub fn ecMakePoint(x: base.Bigint, y: base.Bigint) base.Point {
    var point = [_]u8{0} ** 64;
    std.mem.writeInt(u64, point[24..32], @bitCast(x), .big);
    std.mem.writeInt(u64, point[56..64], @bitCast(y), .big);
    return dupeBytes(&point);
}

pub fn ecPointX(point: base.Point) base.Bigint {
    // CONTRACT-ABORT: in-contract EC builtin; malformed Point = script-abort.
    if (point.len != 64) @panic("ecPointX: point must be 64 bytes");
    return @bitCast(std.mem.readInt(u64, point[24..32], .big));
}

pub fn ecPointY(point: base.Point) base.Bigint {
    // CONTRACT-ABORT: in-contract EC builtin; malformed Point = script-abort.
    if (point.len != 64) @panic("ecPointY: point must be 64 bytes");
    return @bitCast(std.mem.readInt(u64, point[56..64], .big));
}

pub fn ecAdd(left: base.Point, right: base.Point) base.Point {
    // CONTRACT-ABORT: in-contract EC builtin; invalid Point = script-abort.
    const lp = parsePoint(left) catch @panic("ecAdd: invalid point");
    const rp = parsePoint(right) catch @panic("ecAdd: invalid point");
    return serializePoint(lp.add(rp));
}

pub fn ecMul(point: base.Point, scalar: anytype) base.Point {
    // CONTRACT-ABORT: in-contract EC builtin; invalid Point/scalar = script-abort.
    const p = parsePoint(point) catch @panic("ecMul: invalid point");
    if (isIdentityPoint(point)) return dupeBytes(&([_]u8{0} ** 64));

    const reduced_scalar = reduceScalarForSecp256k1(scalar);
    if (reduced_scalar.is_zero) return dupeBytes(&([_]u8{0} ** 64));

    var result = p.mul(reduced_scalar.bytes) catch @panic("ecMul: invalid scalar");
    if (reduced_scalar.negative) result = result.negate();
    return serializePoint(result);
}

pub fn ecMulGen(scalar: anytype) base.Point {
    const reduced_scalar = reduceScalarForSecp256k1(scalar);
    if (reduced_scalar.is_zero) return dupeBytes(&([_]u8{0} ** 64));

    // CONTRACT-ABORT: in-contract EC builtin; invalid scalar = script-abort.
    var result = bsvz.crypto.Point.basePointMul(reduced_scalar.bytes) catch @panic("ecMulGen: invalid scalar");
    if (reduced_scalar.negative) result = result.negate();
    return serializePoint(result);
}

pub fn ecNegate(point: base.Point) base.Point {
    // CONTRACT-ABORT: in-contract EC builtin; invalid Point = script-abort.
    const p = parsePoint(point) catch @panic("ecNegate: invalid point");
    return serializePoint(p.negate());
}

pub fn ecOnCurve(point: base.Point) bool {
    // The all-zero blob is this codegen's encoding of the point at infinity,
    // and it is NOT on the curve: the emitted ecOnCurve is exactly
    // x < p AND y < p AND y^2 == x^3 + 7, and 0 != 7. bsvz's Point.identity()
    // reports isOnCurve() = true (the projective convention), which made this
    // mock disagree with the script it stands in for, so `assert(ecOnCurve(r))`
    // passed off-chain and failed on-chain for r = O -- an unspendable output
    // found only after deploy. O is now reachable from ecAdd(P, -P).
    if (isIdentityPoint(point)) return false;
    const p = parsePoint(point) catch return false;
    return p.isOnCurve();
}

pub fn ecModReduce(value: base.Bigint, modulus: base.Bigint) base.Bigint {
    if (modulus == 0) return 0;
    const reduced = @mod(value, modulus);
    return if (reduced < 0) reduced + modulus else reduced;
}

pub fn ecEncodeCompressed(point: base.Point) base.ByteString {
    // CONTRACT-ABORT: in-contract EC builtin; invalid Point = script-abort.
    const p = parsePoint(point) catch @panic("ecEncodeCompressed: invalid point");
    if (isIdentityPoint(point)) return dupeBytes(&[_]u8{0x00});
    const compressed = p.toCompressedSec1();
    return dupeBytes(compressed.slice());
}

// -- Baby Bear field arithmetic (p = 2^31 - 2^27 + 1 = 2013265921) --------

const bb_p: i64 = 2013265921;

pub fn bbFieldAdd(a: base.Bigint, b: base.Bigint) base.Bigint {
    return @mod(a + b, bb_p);
}

pub fn bbFieldSub(a: base.Bigint, b: base.Bigint) base.Bigint {
    return @mod(@mod(a - b, bb_p) + bb_p, bb_p);
}

pub fn bbFieldMul(a: base.Bigint, b: base.Bigint) base.Bigint {
    return @mod(a * b, bb_p);
}

pub fn bbFieldInv(a: base.Bigint) base.Bigint {
    // Fermat's little theorem: a^(p-2) mod p
    const normalized = @mod(@mod(a, bb_p) + bb_p, bb_p);
    var result: i64 = 1;
    var base_val: i64 = normalized;
    var exp: u64 = @intCast(bb_p - 2);
    while (exp != 0) : (exp >>= 1) {
        if ((exp & 1) != 0) result = @mod(result * base_val, bb_p);
        if (exp > 1) base_val = @mod(base_val * base_val, bb_p);
    }
    return result;
}

// -- Baby Bear quartic extension field (x^4 - W, W = 11) ---------------------
//
// Mirrors packages/runar-go/runar.go BbExt4Mul{0..3} / BbExt4Inv{0..3} and
// the compiler codegen used by the `babybear-ext4` conformance fixture.

const bb_ext4_w: i64 = 11;

pub fn bbExt4Mul0(
    a0: base.Bigint, a1: base.Bigint, a2: base.Bigint, a3: base.Bigint,
    b0: base.Bigint, b1: base.Bigint, b2: base.Bigint, b3: base.Bigint,
) base.Bigint {
    const r = bbFieldMul(a0, b0);
    const t = bbFieldAdd(bbFieldMul(a1, b3), bbFieldAdd(bbFieldMul(a2, b2), bbFieldMul(a3, b1)));
    return bbFieldAdd(r, bbFieldMul(bb_ext4_w, t));
}

pub fn bbExt4Mul1(
    a0: base.Bigint, a1: base.Bigint, a2: base.Bigint, a3: base.Bigint,
    b0: base.Bigint, b1: base.Bigint, b2: base.Bigint, b3: base.Bigint,
) base.Bigint {
    const r = bbFieldAdd(bbFieldMul(a0, b1), bbFieldMul(a1, b0));
    const t = bbFieldAdd(bbFieldMul(a2, b3), bbFieldMul(a3, b2));
    return bbFieldAdd(r, bbFieldMul(bb_ext4_w, t));
}

pub fn bbExt4Mul2(
    a0: base.Bigint, a1: base.Bigint, a2: base.Bigint, a3: base.Bigint,
    b0: base.Bigint, b1: base.Bigint, b2: base.Bigint, b3: base.Bigint,
) base.Bigint {
    const r = bbFieldAdd(bbFieldMul(a0, b2), bbFieldAdd(bbFieldMul(a1, b1), bbFieldMul(a2, b0)));
    return bbFieldAdd(r, bbFieldMul(bb_ext4_w, bbFieldMul(a3, b3)));
}

pub fn bbExt4Mul3(
    a0: base.Bigint, a1: base.Bigint, a2: base.Bigint, a3: base.Bigint,
    b0: base.Bigint, b1: base.Bigint, b2: base.Bigint, b3: base.Bigint,
) base.Bigint {
    return bbFieldAdd(bbFieldMul(a0, b3), bbFieldAdd(bbFieldMul(a1, b2), bbFieldAdd(bbFieldMul(a2, b1), bbFieldMul(a3, b0))));
}

fn bbExt4InvAll(a0: base.Bigint, a1: base.Bigint, a2: base.Bigint, a3: base.Bigint) [4]base.Bigint {
    const c0 = a0;
    const c1 = bbFieldSub(0, a1);
    const c2 = a2;
    const c3 = bbFieldSub(0, a3);

    const p0 = bbExt4Mul0(a0, a1, a2, a3, c0, c1, c2, c3);
    const p2 = bbExt4Mul2(a0, a1, a2, a3, c0, c1, c2, c3);

    const norm_sq = bbFieldSub(bbFieldMul(p0, p0), bbFieldMul(bb_ext4_w, bbFieldMul(p2, p2)));
    const norm_inv = bbFieldInv(norm_sq);

    const inv0 = bbFieldMul(p0, norm_inv);
    const inv2 = bbFieldSub(0, bbFieldMul(p2, norm_inv));

    return .{
        bbFieldAdd(bbFieldMul(c0, inv0), bbFieldMul(bb_ext4_w, bbFieldMul(c2, inv2))),
        bbFieldAdd(bbFieldMul(c1, inv0), bbFieldMul(bb_ext4_w, bbFieldMul(c3, inv2))),
        bbFieldAdd(bbFieldMul(c0, inv2), bbFieldMul(c2, inv0)),
        bbFieldAdd(bbFieldMul(c1, inv2), bbFieldMul(c3, inv0)),
    };
}

pub fn bbExt4Inv0(a0: base.Bigint, a1: base.Bigint, a2: base.Bigint, a3: base.Bigint) base.Bigint {
    return bbExt4InvAll(a0, a1, a2, a3)[0];
}

pub fn bbExt4Inv1(a0: base.Bigint, a1: base.Bigint, a2: base.Bigint, a3: base.Bigint) base.Bigint {
    return bbExt4InvAll(a0, a1, a2, a3)[1];
}

pub fn bbExt4Inv2(a0: base.Bigint, a1: base.Bigint, a2: base.Bigint, a3: base.Bigint) base.Bigint {
    return bbExt4InvAll(a0, a1, a2, a3)[2];
}

pub fn bbExt4Inv3(a0: base.Bigint, a1: base.Bigint, a2: base.Bigint, a3: base.Bigint) base.Bigint {
    return bbExt4InvAll(a0, a1, a2, a3)[3];
}

// -- Merkle proof verification ------------------------------------------------

pub fn merkleRootSha256(leaf: base.ByteString, proof: base.ByteString, index: base.Bigint, depth: base.Bigint) base.ByteString {
    return merkleRootImpl(leaf, proof, index, depth, sha256);
}

pub fn merkleRootHash256(leaf: base.ByteString, proof: base.ByteString, index: base.Bigint, depth: base.Bigint) base.ByteString {
    return merkleRootImpl(leaf, proof, index, depth, hash256);
}

fn merkleRootImpl(leaf: base.ByteString, proof: base.ByteString, index: base.Bigint, depth: base.Bigint, hashFn: fn (base.ByteString) base.ByteString) base.ByteString {
    var current: base.ByteString = leaf;
    const depth_u: usize = std.math.cast(usize, depth) orelse return leaf;
    for (0..depth_u) |i| {
        const sibling_start = i * 32;
        const sibling_end = sibling_start + 32;
        // CONTRACT-ABORT: in-contract merkle-proof builtin; short proof = script-abort.
        if (sibling_end > proof.len) @panic("merkleRoot: proof too short");
        const sibling = proof[sibling_start..sibling_end];
        const bit = (index >> @intCast(i)) & 1;
        const preimage = if (bit == 1)
            cat(sibling, current)
        else
            cat(current, sibling);
        current = hashFn(preimage);
    }
    return current;
}

fn lookupCanonicalFixtureSig(pair: test_keys.TestKeyPair) ?[]const u8 {
    if (std.mem.eql(u8, pair.privKey, test_keys.ALICE.privKey)) {
        return &[_]u8{
            0x30, 0x45, 0x02, 0x21, 0x00, 0xe2, 0xaa, 0x12,
            0x65, 0xce, 0x57, 0xf5, 0x4b, 0x98, 0x1f, 0xfc,
            0x6a, 0x5f, 0x3d, 0x22, 0x9e, 0x90, 0x8d, 0x77,
            0x72, 0xfc, 0xeb, 0x75, 0xa5, 0x0c, 0x8c, 0x2d,
            0x60, 0x76, 0x31, 0x3d, 0xf0, 0x02, 0x20, 0x60,
            0x7d, 0xbc, 0xa2, 0xf9, 0xf6, 0x95, 0x43, 0x8b,
            0x49, 0xee, 0xfe, 0xa4, 0xe4, 0x45, 0x66, 0x4c,
            0x74, 0x01, 0x63, 0xaf, 0x8b, 0x62, 0xb1, 0x37,
            0x3f, 0x87, 0xd5, 0x0e, 0xb6, 0x44, 0x17,
        };
    }
    if (std.mem.eql(u8, pair.privKey, test_keys.BOB.privKey)) {
        return &[_]u8{
            0x30, 0x44, 0x02, 0x20, 0x58, 0x32, 0x90, 0x72,
            0xa0, 0xf9, 0xe6, 0x13, 0x3d, 0x93, 0x10, 0x95,
            0x02, 0xdd, 0xea, 0x83, 0x3f, 0x04, 0x3f, 0x00,
            0xb4, 0x60, 0x95, 0x06, 0x83, 0xfa, 0x80, 0xc0,
            0x0c, 0xa4, 0xd9, 0x88, 0x02, 0x20, 0x03, 0x28,
            0xff, 0x8f, 0x8c, 0x1d, 0xa6, 0x73, 0xa4, 0x89,
            0xc9, 0x3e, 0xd0, 0xb8, 0xe8, 0x3b, 0x14, 0x3a,
            0xfb, 0xeb, 0x34, 0x95, 0xae, 0x4a, 0xad, 0x47,
            0x14, 0xc2, 0x56, 0x98, 0x46, 0x08,
        };
    }
    if (std.mem.eql(u8, pair.privKey, test_keys.CHARLIE.privKey)) {
        return &[_]u8{
            0x30, 0x43, 0x02, 0x21, 0x00, 0xaa, 0x67, 0xcf,
            0xa7, 0x25, 0x5b, 0x90, 0x99, 0x2a, 0x8f, 0x5d,
            0x2b, 0xc7, 0xe9, 0xa3, 0x8f, 0x42, 0xb1, 0x2b,
            0x3a, 0x6c, 0x7c, 0xca, 0x7c, 0xb6, 0x54, 0xa1,
            0x71, 0xe3, 0xae, 0xfd, 0x85, 0x02, 0x1e, 0x27,
            0x77, 0x40, 0xc4, 0x40, 0x9c, 0x64, 0x1c, 0xfb,
            0x47, 0x37, 0x0f, 0x51, 0x0b, 0x3e, 0xcf, 0xff,
            0x75, 0x24, 0x88, 0xa8, 0x55, 0xaa, 0xcf, 0xc9,
            0x91, 0x3e, 0x66, 0xd0, 0x38,
        };
    }
    return null;
}

fn parseFixturePrivateKey(priv_key_hex: []const u8) !bsvz.crypto.PrivateKey {
    var secret_key_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret_key_bytes, priv_key_hex);
    return bsvz.crypto.PrivateKey.fromBytes(secret_key_bytes);
}

fn parseChecksigDer(sig: []const u8) ?bsvz.crypto.DerSignature {
    if (sig.len < 2 or sig[0] != 0x30) {
        return bsvz.crypto.DerSignature.fromDer(sig) catch null;
    }

    const pure_der_len = @as(usize, sig[1]) + 2;
    if (sig.len == pure_der_len + 1) {
        const tx_sig = bsvz.crypto.TxSignature.fromChecksigFormat(sig) catch return null;
        return tx_sig.der;
    }
    if (sig.len == pure_der_len) {
        return bsvz.crypto.DerSignature.fromDer(sig) catch null;
    }
    return null;
}

fn dupeBytes(bytes: []const u8) []const u8 {
    // CONTRACT-ABORT: internal helper called throughout in-contract builtins;
    // page_allocator OOM = script-abort.
    return std.heap.page_allocator.dupe(u8, bytes) catch @panic("OOM");
}

pub fn freeIfOwned(bytes: []const u8) void {
    if (bytes.len == 0) return;
    const addr = @intFromPtr(bytes.ptr);
    const static_addrs = [_]usize{
        @intFromPtr(default_zero_20[0..].ptr),
        @intFromPtr(default_zero_32[0..].ptr),
        @intFromPtr(default_zero_36[0..].ptr),
        @intFromPtr(default_zero_64[0..].ptr),
        @intFromPtr(sha256_initial_state[0..].ptr),
        @intFromPtr(blake3_iv_bytes[0..].ptr),
    };
    for (static_addrs) |static_addr| {
        if (addr == static_addr) return;
    }
    std.heap.page_allocator.free(bytes);
}

fn decodeEmbeddedHexAlloc(allocator: std.mem.Allocator, embedded: []const u8) ![]u8 {
    var normalized: std.ArrayList(u8) = .empty;
    defer normalized.deinit(allocator);

    for (embedded) |byte| {
        if (!std.ascii.isWhitespace(byte)) {
            try normalized.append(allocator, byte);
        }
    }

    return hex.decodeAlloc(allocator, normalized.items);
}

fn expectRealSlhVariant(
    comptime message: []const u8,
    comptime pk_fixture_path: []const u8,
    comptime sig_fixture_path: []const u8,
    comptime tamper_index: usize,
    comptime verify_fn: *const fn (base.ByteString, base.ByteString, base.ByteString) bool,
) !void {
    const pk = try decodeEmbeddedHexAlloc(std.testing.allocator, @embedFile(pk_fixture_path));
    defer std.testing.allocator.free(pk);

    const sig = try decodeEmbeddedHexAlloc(std.testing.allocator, @embedFile(sig_fixture_path));
    defer std.testing.allocator.free(sig);

    try std.testing.expect(verify_fn(message, sig, pk));
    try std.testing.expect(!verify_fn("wrong " ++ message, sig, pk));

    var bad_sig = try std.testing.allocator.dupe(u8, sig);
    defer std.testing.allocator.free(bad_sig);
    bad_sig[tamper_index] ^= 0xff;
    try std.testing.expect(!verify_fn(message, bad_sig, pk));
}

fn copyFixed(dest: []u8, source: []const u8) void {
    const count = @min(dest.len, source.len);
    @memset(dest, 0);
    @memcpy(dest[0..count], source[0..count]);
}

fn sliceOrZero(bytes: []const u8, start: usize, len: usize) []const u8 {
    if (start > bytes.len or len > bytes.len - start) {
        // CONTRACT-ABORT: internal helper for in-contract builtins; OOM = script-abort.
        const zeros = std.heap.page_allocator.alloc(u8, len) catch @panic("OOM");
        @memset(zeros, 0);
        return zeros;
    }
    return dupeBytes(bytes[start .. start + len]);
}

fn encodeInt64Le(dest: []u8, value: i64) void {
    const tmp = @as(u64, @bitCast(value));
    for (dest, 0..) |*byte, index| {
        byte.* = @truncate(tmp >> @intCast(index * 8));
    }
}

fn decodeInt64Le(bytes: []const u8) i64 {
    var value: u64 = 0;
    for (bytes, 0..) |byte, index| {
        value |= @as(u64, byte) << @intCast(index * 8);
    }
    return @bitCast(value);
}

fn checkedMul(lhs: i64, rhs: i64) i64 {
    const result = @mulWithOverflow(lhs, rhs);
    // CONTRACT-ABORT: arithmetic overflow from in-contract math = script-abort.
    if (result[1] != 0) @panic("runar integer overflow");
    return result[0];
}

fn checkedAbs(value: i64) i64 {
    // CONTRACT-ABORT: abs(i64::MIN) overflow from in-contract math = script-abort.
    if (value == std.math.minInt(i64)) @panic("runar integer overflow");
    return if (value < 0) -value else value;
}

fn unsignedAbs(value: i64) u64 {
    if (value >= 0) return @intCast(value);
    if (value == std.math.minInt(i64)) return @as(u64, 1) << 63;
    return @intCast(-value);
}

fn sha256CompressBlock(out: *[32]u8, state_bytes: []const u8, block_bytes: []const u8) void {
    var h: [8]u32 = undefined;
    var w: [64]u32 = undefined;

    for (0..8) |index| {
        h[index] = std.mem.readInt(u32, state_bytes[index * 4 ..][0..4], .big);
    }
    for (0..16) |index| {
        w[index] = std.mem.readInt(u32, block_bytes[index * 4 ..][0..4], .big);
    }
    for (16..64) |index| {
        const s0 = std.math.rotr(u32, w[index - 15], 7) ^ std.math.rotr(u32, w[index - 15], 18) ^ (w[index - 15] >> 3);
        const s1 = std.math.rotr(u32, w[index - 2], 17) ^ std.math.rotr(u32, w[index - 2], 19) ^ (w[index - 2] >> 10);
        w[index] = w[index - 16] +% s0 +% w[index - 7] +% s1;
    }

    var a = h[0];
    var b = h[1];
    var c = h[2];
    var d = h[3];
    var e = h[4];
    var f = h[5];
    var g = h[6];
    var hh = h[7];

    for (0..64) |index| {
        const big_s1 = std.math.rotr(u32, e, 6) ^ std.math.rotr(u32, e, 11) ^ std.math.rotr(u32, e, 25);
        const ch = (e & f) ^ ((~e) & g);
        const temp1 = hh +% big_s1 +% ch +% sha256_k[index] +% w[index];
        const big_s0 = std.math.rotr(u32, a, 2) ^ std.math.rotr(u32, a, 13) ^ std.math.rotr(u32, a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = big_s0 +% maj;

        hh = g;
        g = f;
        f = e;
        e = d +% temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 +% temp2;
    }

    h[0] +%= a;
    h[1] +%= b;
    h[2] +%= c;
    h[3] +%= d;
    h[4] +%= e;
    h[5] +%= f;
    h[6] +%= g;
    h[7] +%= hh;

    for (0..8) |index| {
        std.mem.writeInt(u32, out[index * 4 ..][0..4], h[index], .big);
    }
}

fn blake3Round(state: *[16]u32, msg: *const [16]u32) void {
    blake3G(state, 0, 4, 8, 12, msg[0], msg[1]);
    blake3G(state, 1, 5, 9, 13, msg[2], msg[3]);
    blake3G(state, 2, 6, 10, 14, msg[4], msg[5]);
    blake3G(state, 3, 7, 11, 15, msg[6], msg[7]);
    blake3G(state, 0, 5, 10, 15, msg[8], msg[9]);
    blake3G(state, 1, 6, 11, 12, msg[10], msg[11]);
    blake3G(state, 2, 7, 8, 13, msg[12], msg[13]);
    blake3G(state, 3, 4, 9, 14, msg[14], msg[15]);
}

fn blake3G(state: *[16]u32, a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) void {
    state[a] = state[a] +% state[b] +% mx;
    state[d] = std.math.rotr(u32, state[d] ^ state[a], 16);
    state[c] = state[c] +% state[d];
    state[b] = std.math.rotr(u32, state[b] ^ state[c], 12);
    state[a] = state[a] +% state[b] +% my;
    state[d] = std.math.rotr(u32, state[d] ^ state[a], 8);
    state[c] = state[c] +% state[d];
    state[b] = std.math.rotr(u32, state[b] ^ state[c], 7);
}

fn blake3Permute(msg: [16]u32) [16]u32 {
    var out: [16]u32 = undefined;
    for (0..16) |index| {
        out[index] = msg[blake3_msg_perm[index]];
    }
    return out;
}

const BigUint = struct {
    allocator: std.mem.Allocator,
    limbs: []u64,

    fn zero(allocator: std.mem.Allocator) !BigUint {
        var limbs = try allocator.alloc(u64, 1);
        limbs[0] = 0;
        return .{ .allocator = allocator, .limbs = limbs };
    }

    fn fromU64(allocator: std.mem.Allocator, value: u64) !BigUint {
        var limbs = try allocator.alloc(u64, 1);
        limbs[0] = value;
        return .{ .allocator = allocator, .limbs = limbs };
    }

    fn fromLeBytes(allocator: std.mem.Allocator, bytes: []const u8) !BigUint {
        if (bytes.len == 0) return zero(allocator);

        const limb_count = std.math.divCeil(usize, bytes.len, 8) catch unreachable;
        var limbs = try allocator.alloc(u64, limb_count);
        @memset(limbs, 0);
        var offset: usize = 0;
        while (offset < bytes.len) : (offset += 8) {
            var limb: u64 = 0;
            for (0..8) |j| {
                if (offset + j < bytes.len) {
                    limb |= @as(u64, bytes[offset + j]) << @intCast(j * 8);
                }
            }
            limbs[offset / 8] = limb;
        }
        return normalizeOwned(allocator, limbs);
    }

    fn fromBeBytes(allocator: std.mem.Allocator, bytes: []const u8) !BigUint {
        if (bytes.len == 0) return zero(allocator);

        const reversed = try allocator.alloc(u8, bytes.len);
        defer allocator.free(reversed);
        for (bytes, 0..) |byte, index| {
            reversed[bytes.len - 1 - index] = byte;
        }
        return fromLeBytes(allocator, reversed);
    }

    fn deinit(self: *BigUint) void {
        self.allocator.free(self.limbs);
        self.* = undefined;
    }

    fn isZero(self: *const BigUint) bool {
        for (self.limbs) |limb| {
            if (limb != 0) return false;
        }
        return true;
    }

    fn eql(self: *const BigUint, other: *const BigUint) bool {
        if (self.limbs.len != other.limbs.len) return false;
        return std.mem.eql(u64, self.limbs, other.limbs);
    }

    fn cmp(self: *const BigUint, other: *const BigUint) std.math.Order {
        if (self.limbs.len != other.limbs.len) return std.math.order(self.limbs.len, other.limbs.len);
        var i = self.limbs.len;
        while (i != 0) {
            i -= 1;
            if (self.limbs[i] != other.limbs[i]) return std.math.order(self.limbs[i], other.limbs[i]);
        }
        return .eq;
    }

    fn add(self: *const BigUint, other: *const BigUint) !BigUint {
        const max_len = @max(self.limbs.len, other.limbs.len);
        var result = try self.allocator.alloc(u64, max_len + 1);
        var carry: u64 = 0;
        for (0..max_len) |i| {
            const a = if (i < self.limbs.len) self.limbs[i] else 0;
            const b = if (i < other.limbs.len) other.limbs[i] else 0;
            const sum1 = @addWithOverflow(a, b);
            const sum2 = @addWithOverflow(sum1[0], carry);
            result[i] = sum2[0];
            carry = sum1[1] + sum2[1];
        }
        result[max_len] = carry;
        return normalizeOwned(self.allocator, result);
    }

    fn sub(self: *const BigUint, other: *const BigUint) !BigUint {
        if (self.cmp(other) == .lt) return error.BigUintUnderflow;

        var result = try self.allocator.alloc(u64, self.limbs.len);
        var borrow: u64 = 0;
        for (0..self.limbs.len) |i| {
            const a = self.limbs[i];
            const b = if (i < other.limbs.len) other.limbs[i] else 0;
            const sub1 = @subWithOverflow(a, b);
            const sub2 = @subWithOverflow(sub1[0], borrow);
            result[i] = sub2[0];
            borrow = sub1[1] + sub2[1];
        }
        return normalizeOwned(self.allocator, result);
    }

    fn mul(self: *const BigUint, other: *const BigUint) !BigUint {
        var result = try self.allocator.alloc(u64, self.limbs.len + other.limbs.len);
        @memset(result, 0);

        for (0..self.limbs.len) |i| {
            var carry: u64 = 0;
            for (0..other.limbs.len) |j| {
                const product = @as(u128, self.limbs[i]) * @as(u128, other.limbs[j]) +
                    @as(u128, result[i + j]) + @as(u128, carry);
                result[i + j] = @truncate(product);
                carry = @truncate(product >> 64);
            }
            result[i + other.limbs.len] +%= carry;
        }

        return normalizeOwned(self.allocator, result);
    }

    fn rem(self: *const BigUint, divisor: *const BigUint) !BigUint {
        if (divisor.isZero()) return error.DivisionByZero;
        if (self.cmp(divisor) == .lt) return self.clone();

        var remainder = try BigUint.zero(self.allocator);
        errdefer remainder.deinit();

        const total_bits = self.bitLen();
        var bit_index = total_bits;
        while (bit_index != 0) {
            bit_index -= 1;
            try remainder.shiftLeft1();
            if (self.bitAt(bit_index)) remainder.limbs[0] |= 1;
            if (remainder.cmp(divisor) != .lt) {
                const next = try remainder.sub(divisor);
                remainder.deinit();
                remainder = next;
            }
        }

        return remainder;
    }

    fn clone(self: *const BigUint) !BigUint {
        const limbs = try self.allocator.dupe(u64, self.limbs);
        return .{ .allocator = self.allocator, .limbs = limbs };
    }

    fn shiftLeft1(self: *BigUint) !void {
        var carry: u64 = 0;
        for (self.limbs) |*limb| {
            const new_carry = limb.* >> 63;
            limb.* = (limb.* << 1) | carry;
            carry = new_carry;
        }
        if (carry == 0) return;

        var expanded = try self.allocator.alloc(u64, self.limbs.len + 1);
        @memcpy(expanded[0..self.limbs.len], self.limbs);
        expanded[self.limbs.len] = carry;
        self.allocator.free(self.limbs);
        self.limbs = expanded;
    }

    fn bitLen(self: *const BigUint) usize {
        if (self.isZero()) return 0;
        const top = self.limbs[self.limbs.len - 1];
        return (self.limbs.len - 1) * 64 + (64 - @clz(top));
    }

    fn bitAt(self: *const BigUint, index: usize) bool {
        const limb_index = index / 64;
        const bit_index = index % 64;
        if (limb_index >= self.limbs.len) return false;
        return ((self.limbs[limb_index] >> @intCast(bit_index)) & 1) == 1;
    }

    fn toLeBytes(self: *const BigUint) ![]u8 {
        var bytes = try self.allocator.alloc(u8, self.limbs.len * 8);
        for (self.limbs, 0..) |limb, i| {
            std.mem.writeInt(u64, bytes[i * 8 ..][0..8], limb, .little);
        }
        var trimmed_len = bytes.len;
        while (trimmed_len > 1 and bytes[trimmed_len - 1] == 0) : (trimmed_len -= 1) {}
        if (trimmed_len == bytes.len) return bytes;

        const trimmed = try self.allocator.dupe(u8, bytes[0..trimmed_len]);
        self.allocator.free(bytes);
        return trimmed;
    }
};

pub const SignedBigint = struct {
    negative: bool,
    len: usize,
    limbs: [4]u64,

    fn zero() SignedBigint {
        return .{
            .negative = false,
            .len = 1,
            .limbs = .{ 0, 0, 0, 0 },
        };
    }

    pub fn fromI64(value: i64) SignedBigint {
        var out = zero();
        out.negative = value < 0;
        out.limbs[0] = unsignedAbs(value);
        out.normalize();
        return out;
    }

    pub fn from(value: anytype) SignedBigint {
        const Value = @TypeOf(value);
        if (Value == SignedBigint) return value;
        return switch (@typeInfo(Value)) {
            // INTERNAL-INVARIANT: only reachable if caller passes an integer
            // type that can't fit in i64 (e.g. u128); Rúnar front-ends only
            // pass i64-range values.
            .int, .comptime_int => fromI64(std.math.cast(i64, value) orelse @panic("scalar out of range")),
            else => @compileError("expected i64/comptime_int or SignedBigint"),
        };
    }

    fn fromLeSignedMagnitude(bytes: []const u8) SignedBigint {
        if (bytes.len == 0) return zero();
        // CONTRACT-ABORT: in-contract OP_BIN2NUM bound; magnitude > 32 bytes = script-abort.
        if (bytes.len > 32) @panic("bin2num: magnitude too large");

        var out = zero();
        const last_index = bytes.len - 1;
        out.negative = (bytes[last_index] & 0x80) != 0;

        for (bytes, 0..) |raw_byte, index| {
            const byte: u8 = if (index == last_index) (raw_byte & 0x7f) else raw_byte;
            const limb_index = index / 8;
            const shift = (index % 8) * 8;
            out.limbs[limb_index] |= @as(u64, byte) << @intCast(shift);
        }
        out.normalize();
        if (out.isZero()) out.negative = false;
        return out;
    }

    fn isZero(self: SignedBigint) bool {
        return self.len == 1 and self.limbs[0] == 0;
    }

    fn normalize(self: *SignedBigint) void {
        var new_len: usize = self.limbs.len;
        while (new_len > 1 and self.limbs[new_len - 1] == 0) : (new_len -= 1) {}
        self.len = new_len;
    }

    fn toI64Exact(self: SignedBigint) !i64 {
        if (self.isZero()) return 0;
        if (self.len > 1) return error.BigintTooLarge;

        const magnitude = self.limbs[0];
        if (!self.negative) {
            if (magnitude > std.math.maxInt(i64)) return error.BigintTooLarge;
            return @intCast(magnitude);
        }

        if (magnitude == (@as(u64, 1) << 63)) return std.math.minInt(i64);
        if (magnitude > std.math.maxInt(i64)) return error.BigintTooLarge;
        return -@as(i64, @intCast(magnitude));
    }

    fn toBigUint(self: SignedBigint) !BigUint {
        const limbs = try std.heap.page_allocator.alloc(u64, self.len);
        @memcpy(limbs[0..self.len], self.limbs[0..self.len]);
        return .{
            .allocator = std.heap.page_allocator,
            .limbs = limbs,
        };
    }

    fn toLeMagnitudeBytes(self: SignedBigint, buffer: *[32]u8) []const u8 {
        if (self.isZero()) return &.{};

        var used: usize = self.len * 8;
        @memset(buffer, 0);
        for (0..self.len) |limb_index| {
            const limb = self.limbs[limb_index];
            for (0..8) |byte_index| {
                buffer[limb_index * 8 + byte_index] = @truncate(limb >> @intCast(byte_index * 8));
            }
        }
        while (used > 1 and buffer[used - 1] == 0) : (used -= 1) {}
        return buffer[0..used];
    }
};

const ReducedScalar = struct {
    negative: bool,
    is_zero: bool,
    bytes: [32]u8,
};

fn normalizeOwned(allocator: std.mem.Allocator, limbs: []u64) !BigUint {
    var len = limbs.len;
    while (len > 1 and limbs[len - 1] == 0) : (len -= 1) {}
    if (len == limbs.len) return .{ .allocator = allocator, .limbs = limbs };

    const trimmed = try allocator.dupe(u64, limbs[0..len]);
    allocator.free(limbs);
    return .{ .allocator = allocator, .limbs = trimmed };
}

fn isIdentityPoint(point: []const u8) bool {
    if (point.len != 64) return false;
    for (point) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

fn parsePoint(point: []const u8) !bsvz.crypto.Point {
    if (isIdentityPoint(point)) return bsvz.crypto.Point.identity();
    return bsvz.crypto.Point.fromRaw64(point);
}

fn serializePoint(point: bsvz.crypto.Point) base.Point {
    return dupeBytes(&point.toRaw64());
}

fn signedBigintFrom(value: anytype) SignedBigint {
    return SignedBigint.from(value);
}

fn scriptNumFromValue(allocator: std.mem.Allocator, value: anytype) !bsvz.script.ScriptNum {
    const Value = @TypeOf(value);
    if (Value == SignedBigint) return scriptNumFromSignedBigint(allocator, value);
    return bsvz.script.ScriptNum.fromValue(allocator, value);
}

fn scriptNumFromSignedBigint(allocator: std.mem.Allocator, value: SignedBigint) !bsvz.script.ScriptNum {
    var magnitude_buffer: [32]u8 = undefined;
    const magnitude = value.toLeMagnitudeBytes(&magnitude_buffer);

    const needs_extra = magnitude.len != 0 and (magnitude[magnitude.len - 1] & 0x80) != 0;
    const encoded_len = magnitude.len + @intFromBool(needs_extra);
    const encoded = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded);

    if (magnitude.len != 0) @memcpy(encoded[0..magnitude.len], magnitude);
    if (needs_extra) {
        encoded[encoded_len - 1] = if (value.negative and !value.isZero()) 0x80 else 0x00;
    } else if (value.negative and !value.isZero()) {
        encoded[encoded_len - 1] |= 0x80;
    }

    return bsvz.script.ScriptNum.bin2num(allocator, encoded);
}

fn signedBigintFromScriptNum(script_num: *const bsvz.script.ScriptNum) SignedBigint {
    return switch (script_num.*) {
        .small => |value| SignedBigint.fromI64(value),
        .big => {
            // CONTRACT-ABORT: internal bigint<->ScriptNum bridge; OOM = script-abort.
            const encoded = script_num.encodeOwned(std.heap.page_allocator) catch @panic("OOM");
            defer std.heap.page_allocator.free(encoded);
            return SignedBigint.fromLeSignedMagnitude(encoded);
        },
    };
}

fn reduceScalarForSecp256k1(value: anytype) ReducedScalar {
    const bigint = signedBigintFrom(value);
    if (bigint.isZero()) {
        return .{
            .negative = false,
            .is_zero = true,
            .bytes = [_]u8{0} ** 32,
        };
    }

    // CONTRACT-ABORT: in-contract scalar reduction for EC ops; OOM/rem failure = script-abort.
    var order = BigUint.fromBeBytes(std.heap.page_allocator, &secp256k1_order_be) catch @panic("OOM");
    defer order.deinit();
    var magnitude = bigint.toBigUint() catch @panic("OOM");
    defer magnitude.deinit();
    var reduced = magnitude.rem(&order) catch @panic("failed to reduce scalar");
    defer reduced.deinit();

    if (reduced.isZero()) {
        return .{
            .negative = false,
            .is_zero = true,
            .bytes = [_]u8{0} ** 32,
        };
    }

    return .{
        .negative = bigint.negative,
        .is_zero = false,
        .bytes = bigUintToFixedBe32(&reduced),
    };
}

fn bigUintToFixedBe32(value: *const BigUint) [32]u8 {
    var out = [_]u8{0} ** 32;
    for (value.limbs, 0..) |limb, limb_index| {
        for (0..8) |byte_index| {
            const absolute_index = limb_index * 8 + byte_index;
            const byte: u8 = @truncate(limb >> @intCast(byte_index * 8));
            if (absolute_index >= out.len) {
                // INTERNAL-INVARIANT: unreachable — called only after
                // magnitude.rem(secp256k1_order), which bounds the value at
                // < 2^256 (i.e. fits in 32 bytes). A non-zero high byte here
                // would indicate a bug in BigUint.rem, not caller input.
                if (byte != 0) @panic("scalar exceeds 32 bytes");
                continue;
            }
            out[out.len - 1 - absolute_index] = byte;
        }
    }
    return out;
}

fn expectBigintEqI64(expected: i64, actual: SignedBigint) !void {
    try std.testing.expectEqual(expected, try actual.toI64Exact());
}

test "sign fixtures round trip through checkSig" {
    const sig = signTestMessage(test_keys.ALICE);
    defer freeIfOwned(sig);

    try std.testing.expect(checkSig(sig, test_keys.ALICE.pubKey));
    try std.testing.expect(!checkSig(sig, test_keys.BOB.pubKey));
}

test "fixture private keys derive the published compressed pubkeys" {
    const fixtures = [_]test_keys.TestKeyPair{
        test_keys.ALICE,
        test_keys.BOB,
        test_keys.CHARLIE,
    };

    for (fixtures) |fixture| {
        const private_key = try parseFixturePrivateKey(fixture.privKey);
        const derived_pub_key = try private_key.publicKey();
        try std.testing.expectEqualSlices(u8, fixture.pubKey, &derived_pub_key.bytes);
    }
}

test "signTestMessage matches the known alice fixture signature" {
    const expected = [_]u8{
        0x30, 0x45, 0x02, 0x21, 0x00, 0xe2, 0xaa, 0x12,
        0x65, 0xce, 0x57, 0xf5, 0x4b, 0x98, 0x1f, 0xfc,
        0x6a, 0x5f, 0x3d, 0x22, 0x9e, 0x90, 0x8d, 0x77,
        0x72, 0xfc, 0xeb, 0x75, 0xa5, 0x0c, 0x8c, 0x2d,
        0x60, 0x76, 0x31, 0x3d, 0xf0, 0x02, 0x20, 0x60,
        0x7d, 0xbc, 0xa2, 0xf9, 0xf6, 0x95, 0x43, 0x8b,
        0x49, 0xee, 0xfe, 0xa4, 0xe4, 0x45, 0x66, 0x4c,
        0x74, 0x01, 0x63, 0xaf, 0x8b, 0x62, 0xb1, 0x37,
        0x3f, 0x87, 0xd5, 0x0e, 0xb6, 0x44, 0x17,
    };

    const sig = signTestMessage(test_keys.ALICE);
    defer freeIfOwned(sig);
    try std.testing.expectEqualSlices(u8, &expected, sig);
}

test "checkSig accepts a trailing sighash byte" {
    const base_sig = signTestMessage(test_keys.ALICE);
    defer freeIfOwned(base_sig);

    // CONVERTED: use testing allocator + `try` instead of page_allocator + @panic("OOM").
    var with_sighash = try std.testing.allocator.alloc(u8, base_sig.len + 1);
    defer std.testing.allocator.free(with_sighash);
    @memcpy(with_sighash[0..base_sig.len], base_sig);
    with_sighash[base_sig.len] = 0x41;

    try std.testing.expect(checkSig(with_sighash, test_keys.ALICE.pubKey));
}

test "hash160 matches fixture hashes" {
    const alice_hash = hash160(test_keys.ALICE.pubKey);
    defer freeIfOwned(alice_hash);
    const bob_hash = hash160(test_keys.BOB.pubKey);
    defer freeIfOwned(bob_hash);
    const charlie_hash = hash160(test_keys.CHARLIE.pubKey);
    defer freeIfOwned(charlie_hash);

    try std.testing.expectEqualSlices(u8, test_keys.ALICE.pubKeyHash, alice_hash);
    try std.testing.expectEqualSlices(u8, test_keys.BOB.pubKeyHash, bob_hash);
    try std.testing.expectEqualSlices(u8, test_keys.CHARLIE.pubKeyHash, charlie_hash);
}

test "bytesEq compares byte content explicitly" {
    try std.testing.expect(bytesEq("abc", "abc"));
    try std.testing.expect(!bytesEq("abc", "abd"));
    try std.testing.expect(bytesEq(&.{}, &.{}));
}

test "buildChangeOutputChecked rejects malformed pubkey hash" {
    const allocator = std.testing.allocator;
    const bad_pkh = [_]u8{0} ** 19; // too short
    const result = buildChangeOutputChecked(allocator, &bad_pkh, 1000);
    try std.testing.expectError(BuildChangeOutputError.InvalidPubKeyHashLength, result);
}

test "buildChangeOutputChecked happy path matches buildChangeOutput" {
    const allocator = std.testing.allocator;
    const pkh = [_]u8{0x11} ** 20;
    const checked = try buildChangeOutputChecked(allocator, &pkh, 5000);
    defer allocator.free(checked);
    const legacy = buildChangeOutput(&pkh, 5000);
    defer freeIfOwned(legacy);
    try std.testing.expectEqualSlices(u8, legacy, checked);
}

test "mockPreimageChecked rejects out-of-range locktime" {
    const allocator = std.testing.allocator;
    const result = mockPreimageChecked(allocator, .{ .locktime = @as(i64, std.math.maxInt(u32)) + 1 });
    try std.testing.expectError(MockPreimageError.LocktimeOutOfRange, result);
}

test "mockPreimageChecked happy path matches mockPreimage" {
    const allocator = std.testing.allocator;
    const checked = try mockPreimageChecked(allocator, .{ .locktime = 42 });
    defer allocator.free(checked);
    const legacy = mockPreimage(.{ .locktime = 42 });
    defer freeIfOwned(legacy);
    try std.testing.expectEqualSlices(u8, legacy, checked);
}

test "signTestMessageChecked succeeds with known fixture" {
    const allocator = std.testing.allocator;
    const sig = try signTestMessageChecked(allocator, test_keys.ALICE);
    defer allocator.free(sig);
    try std.testing.expect(sig.len > 0);
    try std.testing.expect(checkSig(sig, test_keys.ALICE.pubKey));
}

test "cat and substr preserve current Runar byte-string semantics" {
    const joined = cat("hello", " world");
    defer freeIfOwned(joined);

    try std.testing.expectEqualSlices(u8, "hello world", joined);

    const middle = substr("hello world", 6, 5);
    defer freeIfOwned(middle);
    try std.testing.expectEqualSlices(u8, "world", middle);

    try std.testing.expectEqualSlices(u8, &.{}, substr("hello", -1, 2));
    try std.testing.expectEqualSlices(u8, &.{}, substr("hello", 0, 0));

    const past_end = substr("hello", 99, 3);
    defer freeIfOwned(past_end);
    try std.testing.expectEqualSlices(u8, &.{}, past_end);
}

test "mock preimage extractors round trip" {
    const expected_hash = hash256("prevouts");
    defer freeIfOwned(expected_hash);
    const output_hash = hash256("outputs");
    defer freeIfOwned(output_hash);

    const preimage = mockPreimage(.{
        .hashPrevouts = expected_hash,
        .outpoint = "outpoint-data",
        .outputHash = output_hash,
        .locktime = 500,
    });
    defer freeIfOwned(preimage);

    const extracted_hash = extractHashPrevouts(preimage);
    defer freeIfOwned(extracted_hash);
    try std.testing.expect(std.mem.eql(u8, extracted_hash, expected_hash));
    try std.testing.expectEqual(@as(i64, 500), extractLocktime(preimage));
}

test "num2bin and bin2num follow signed magnitude semantics" {
    const cases = [_]struct {
        value: i64,
        size: i64,
        expected: []const u8,
    }{
        .{ .value = 0, .size = 0, .expected = &.{} },
        .{ .value = 0, .size = 4, .expected = &[_]u8{ 0, 0, 0, 0 } },
        .{ .value = 1, .size = 1, .expected = &[_]u8{0x01} },
        .{ .value = -1, .size = 1, .expected = &[_]u8{0x81} },
        .{ .value = -1, .size = 4, .expected = &[_]u8{ 0x01, 0x00, 0x00, 0x80 } },
        .{ .value = 128, .size = 2, .expected = &[_]u8{ 0x80, 0x00 } },
        .{ .value = -128, .size = 2, .expected = &[_]u8{ 0x80, 0x80 } },
    };

    for (cases) |case| {
        const encoded = num2bin(case.value, case.size);
        defer freeIfOwned(encoded);
        try std.testing.expectEqualSlices(u8, case.expected, encoded);
        try expectBigintEqI64(case.value, bin2num(encoded));
    }

    try expectBigintEqI64(0, bin2num(&[_]u8{0x80}));
}

test "wide signed-magnitude values flow through bin2num and secp256k1 scalar multiplication" {
    const wide = [_]u8{
        0x5b, 0x62, 0x19, 0x4d, 0xc4, 0xa8, 0x71, 0x3f,
        0xe1, 0x94, 0x28, 0x67, 0x52, 0x11, 0xa9, 0x83,
        0x77, 0xc0, 0x42, 0x10, 0x9a, 0xde, 0x55, 0x34,
        0x98, 0x61, 0x44, 0x20, 0x17, 0xb2, 0x6c, 0x7f,
    };

    const scalar = bin2num(&wide);
    const encoded = num2bin(scalar, 32);
    defer freeIfOwned(encoded);
    try std.testing.expectEqualSlices(u8, &wide, encoded);

    const actual = ecMulGen(scalar);
    defer freeIfOwned(actual);

    const reduced = reduceScalarForSecp256k1(scalar);
    // CONVERTED: `try` inside test — basePointMul error is a legitimate test
    // failure to surface, not a runtime panic.
    var expected_point = try bsvz.crypto.Point.basePointMul(reduced.bytes);
    if (reduced.negative) expected_point = expected_point.negate();
    const expected = serializePoint(expected_point);
    defer freeIfOwned(expected);

    try std.testing.expectEqualSlices(u8, expected, actual);
}

test "safemod keeps the dividend sign" {
    try std.testing.expectEqual(@as(i64, -1), safemod(-7, 3));
    try std.testing.expectEqual(@as(i64, 1), safemod(7, 3));
    try std.testing.expectEqual(@as(i64, 0), safemod(7, 0));
}

test "sha256Compress matches known abc hash" {
    var block = [_]u8{0} ** 64;
    @memcpy(block[0..3], "abc");
    block[3] = 0x80;
    std.mem.writeInt(u64, block[56..64], 24, .big);

    const compressed = sha256Compress(sha256_initial_state[0..], &block);
    defer freeIfOwned(compressed);
    const expected = sha256("abc");
    defer freeIfOwned(expected);

    try std.testing.expectEqualSlices(u8, expected, compressed);
}

test "sha256Finalize matches standard sha256 for one and two block messages" {
    const short = sha256Finalize(sha256_initial_state[0..], "abc", 24);
    defer freeIfOwned(short);
    const short_expected = sha256("abc");
    defer freeIfOwned(short_expected);
    try std.testing.expectEqualSlices(u8, short_expected, short);

    const empty = sha256Finalize(sha256_initial_state[0..], "", 0);
    defer freeIfOwned(empty);
    const empty_expected = sha256("");
    defer freeIfOwned(empty_expected);
    try std.testing.expectEqualSlices(u8, empty_expected, empty);

    const long_message = "d" ** 100;
    const long_hash = sha256Finalize(sha256_initial_state[0..], long_message[0..], 800);
    defer freeIfOwned(long_hash);
    const expected_long_hash = sha256(long_message[0..]);
    defer freeIfOwned(expected_long_hash);
    try std.testing.expectEqualSlices(u8, expected_long_hash, long_hash);
}

test "blake3 helpers follow the single block runtime semantics" {
    // Standard BLAKE3 of "abc" (little-endian, block_len = 3).
    const expected_abc = [_]u8{
        0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33,
        0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a, 0x8d, 0xb5,
        0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03,
        0xfd, 0x35, 0x9c, 0x6c, 0xd5, 0xbd, 0x9d, 0x85,
    };

    const hashed = blake3Hash("abc");
    defer freeIfOwned(hashed);
    try std.testing.expectEqualSlices(u8, &expected_abc, hashed);

    // blake3Compress operates on a full 64-byte block (block_len = 64), so it
    // differs from blake3Hash("abc") (block_len = 3). Verify the compress KAT.
    const expected_compress = [_]u8{
        0xed, 0xf4, 0x47, 0xf5, 0xd5, 0xd7, 0x4c, 0xa1,
        0xc3, 0xb8, 0x79, 0xb0, 0x87, 0x25, 0x41, 0xb4,
        0x9e, 0x0f, 0xe6, 0xf4, 0xe0, 0x1a, 0xc3, 0xa9,
        0x2a, 0x8a, 0x81, 0xba, 0x47, 0x48, 0x70, 0x87,
    };
    var block = [_]u8{0} ** 64;
    @memcpy(block[0..3], "abc");
    const compressed = blake3Compress(blake3_iv_bytes[0..], &block);
    defer freeIfOwned(compressed);
    try std.testing.expectEqualSlices(u8, &expected_compress, compressed);
}

test "ec helpers use real secp256k1 arithmetic" {
    const g = ecMulGen(1);
    defer freeIfOwned(g);
    try std.testing.expectEqual(@as(usize, 64), g.len);
    try std.testing.expect(ecOnCurve(g));

    const doubled_via_add = ecAdd(g, g);
    defer freeIfOwned(doubled_via_add);
    const doubled_via_mul = ecMul(g, 2);
    defer freeIfOwned(doubled_via_mul);
    const doubled_via_gen = ecMulGen(2);
    defer freeIfOwned(doubled_via_gen);

    try std.testing.expectEqualSlices(u8, doubled_via_add, doubled_via_mul);
    try std.testing.expectEqualSlices(u8, doubled_via_add, doubled_via_gen);

    const neg = ecNegate(g);
    defer freeIfOwned(neg);
    try std.testing.expect(ecOnCurve(neg));

    const identity = ecAdd(g, neg);
    defer freeIfOwned(identity);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 64), identity);
    // NOT on the curve: this is the ONLY way a contract can detect O, and the
    // compiled script agrees (0^2 != 0^3 + 7). This assertion used to be
    // `expect(ecOnCurve(identity))` — the mock said yes where the script says
    // no, so an off-chain-green `assert(ecOnCurve(r))` deployed unspendable.
    try std.testing.expect(!ecOnCurve(identity));

    const compressed = ecEncodeCompressed(g);
    defer freeIfOwned(compressed);
    try std.testing.expectEqual(@as(usize, 33), compressed.len);
    try std.testing.expect(compressed[0] == 0x02 or compressed[0] == 0x03);
}

test "ec small-value point helpers round trip" {
    const p = ecMakePoint(12345, -67890);
    defer freeIfOwned(p);

    try std.testing.expectEqual(@as(i64, 12345), ecPointX(p));
    try std.testing.expectEqual(@as(i64, -67890), ecPointY(p));
    try std.testing.expect(!ecOnCurve(p));
}

test "verifyWOTS accepts a valid deterministic signature" {
    const seed = [_]u8{0x42} ** 32;
    const pub_seed = [_]u8{0x13} ** 32;
    const pk = wots.publicKeyFromSeed(&seed, &pub_seed);
    const sig = wots.signDeterministic("hello WOTS+", &seed, &pub_seed);

    try std.testing.expect(verifyWOTS("hello WOTS+", &sig, &pk));
    try std.testing.expect(!verifyWOTS("wrong message", &sig, &pk));
}

test "verifyRabinSig accepts a trivial valid signature construction" {
    const modulus = [_]u8{0xfb}; // 251, little-endian
    var hash_bytes: [32]u8 = undefined;
    Sha256Hasher.hash("oracle-message", &hash_bytes, .{});

    var hash_bn = try BigUint.fromLeBytes(std.heap.page_allocator, &hash_bytes);
    defer hash_bn.deinit();
    var modulus_bn = try BigUint.fromLeBytes(std.heap.page_allocator, &modulus);
    defer modulus_bn.deinit();
    var padding_bn = try hash_bn.rem(&modulus_bn);
    defer padding_bn.deinit();
    const padding = try padding_bn.toLeBytes();
    defer std.heap.page_allocator.free(padding);

    try std.testing.expect(verifyRabinSig("oracle-message", &[_]u8{0x00}, padding, &modulus));
    try std.testing.expect(!verifyRabinSig("wrong-message", &[_]u8{0x00}, padding, &modulus));
}

test "verifyRabinSig rejects the sig=0/padding=SHA256(msg) forgery via the padding bound" {
    // Realistic ~256-bit modulus (the shared oracle test key); for a typical
    // message SHA256(msg) < n, so the forged padding = SHA256(msg) >= 65536.
    const modulus = [_]u8{
        0x95, 0x0b, 0x36, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x63,
        0x62, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    };
    const message = "oracle-price:60000";

    // Forgery: sig=0, padding = SHA256(message). (0^2 + SHA256(msg)) mod n
    // == SHA256(msg) mod n trivially, so the only thing rejecting it is the
    // 0 <= padding < 65536 bound that mirrors the on-chain OP_WITHIN check.
    var hash_bytes: [32]u8 = undefined;
    Sha256Hasher.hash(message, &hash_bytes, .{});
    // SHA256 output is 32 bytes; as a number it is far above 65536, so the
    // guard must reject this forgery.
    try std.testing.expect(!verifyRabinSig(message, &[_]u8{0x00}, &hash_bytes, &modulus));

    // Honest small-padding signature (tiny modulus, padding < 65536) is still
    // accepted: sig=0, padding = SHA256(msg) mod 251, which fits in one byte.
    const small_mod = [_]u8{0xfb}; // 251, little-endian
    var honest_hash: [32]u8 = undefined;
    Sha256Hasher.hash(message, &honest_hash, .{});
    var honest_hash_bn = try BigUint.fromLeBytes(std.heap.page_allocator, &honest_hash);
    defer honest_hash_bn.deinit();
    var small_mod_bn = try BigUint.fromLeBytes(std.heap.page_allocator, &small_mod);
    defer small_mod_bn.deinit();
    var honest_pad_bn = try honest_hash_bn.rem(&small_mod_bn);
    defer honest_pad_bn.deinit();
    const honest_pad = try honest_pad_bn.toLeBytes();
    defer std.heap.page_allocator.free(honest_pad);
    try std.testing.expect(verifyRabinSig(message, &[_]u8{0x00}, honest_pad, &small_mod));
}

test "SLH SHA2 parameter sizes stay aligned with the published script matrix" {
    try std.testing.expectEqual(@as(usize, 7856), slh_sha2_128s.sig_len);
    try std.testing.expectEqual(@as(usize, 17088), slh_sha2_128f.sig_len);
    try std.testing.expectEqual(@as(usize, 16224), slh_sha2_192s.sig_len);
    try std.testing.expectEqual(@as(usize, 35664), slh_sha2_192f.sig_len);
    try std.testing.expectEqual(@as(usize, 29792), slh_sha2_256s.sig_len);
    try std.testing.expectEqual(@as(usize, 48736), slh_sha2_256f.sig_len);
}

test "verifySLHDSA_SHA2_128s accepts a real deterministic signature and rejects tampering" {
    const pk_hex =
        "00000000000000000000000000000000b253ffb61412a32b56e07eb091eef8c0";

    const sig_hex =
        "cd5d2806d6878f69ff9a5a05f9585587649dd5c8e389ae4c75b26baad9987ef06564596645fcff0ae66801ed11a3443a" ++
        "6735fd38612b35fa7445cacbce9df3a9ed1f1b09498db4411fbf737211f091bdeb8c5c1590efce25e26c197ed9a12ef6" ++
        "ae0cc67fe814dbc29b76d7f5a81ab254ad82d6eb512115c43ba1d65b8b2b19781161b0881b0dfaff7307ad05feae7b82" ++
        "1c824f6efdbaf8d94f048a99cc74e969fdd66e5b2f0ba998e3c56715b4ec47c6079d7aea694c7b525a8d3a810ee3fcbc" ++
        "7872e021cfcb3647d57711a787d80f94de1a7fed66e979f26c9129b10f2b2e03522690dfa3a1c0ceca40f0ee8910548e" ++
        "819ac7891e4884a616c80d845a54850a400305a12393a4c49eadd412cc500a5481b488ce475a468bfe35296b2fb4d6d1" ++
        "14541b094c43dc632519e7574fb4ed4ba4c77cef611d379e038d4e29c7a9c88b7090e7331f8d48569cde6dca8070c696" ++
        "098dc4b0326fe0e5bdc87f3313f302095c307fb9298e25789bef90f1422269675801ffb8df93995a0f995811a1f485f9" ++
        "69bcfc550e0ed30a15bdc68b897ad3104b21466e3e7df1a38e808c4b91eb3f067882276107a4558c2d23d7a4e35e4f74" ++
        "77732f641002d9b0f22d356440df5af03a5f3dfaba283853d9d1e4e1c502057f7f4434c19f041fe7e3ad27b1049e8eed" ++
        "2d9a44b12f0856c4ff88f395446e9582bb7af2df064e54bc0b47907780ec7d5b0e1138591b0453bdf888bfdc0efea43a" ++
        "7d6d448214b9e9e7024a60ac5d08c50b44274279a7bacfb82a775a61cc9893e94f7cdae080f09933bc03769e2ddbba45" ++
        "5ebb99b0b9fb4de374e7e25ab02330d6a795cb6c4a47d22a60b970333bea6e54b697eb68f4ec3c043011d019025a2bd7" ++
        "2404769c0c2e5beb64329afe8db78fc92a93ab194668301588a96c3f6f093b78d7d1cc5a42a8d2b81fe5ee6188020635" ++
        "ce353ea9c7a614f717fb366c34a76eaf70ad5e3e39e89735dea50dbaa34fbf08bbaed66fba6745d26254cc12eafa2127" ++
        "481a230d2cd0929de1b68d349353626d38e4773e485b986294ead6361cb0b43db2881ed089f20adce26deda306bdef70" ++
        "f535ec053b746faaed21f1af8692c0aee26ede958d4450c2b072ec3bf6aca0aecbda9615d4d4d816126348346d3abf2b" ++
        "93c8c12794a864a7f3f1520a410a87f50441d98afa6cc3c91de75c47e94fe73dfad2b897a2b3ff06e876f209e7ce5889" ++
        "34dd54717b834514806d6d60964c59888783c574f61d03a5bb005adc85cd9605aff037d70511eefb89891790b4ad6bc2" ++
        "c2994be8f003b1539a9162a21e745b6a75d2d3bf3df21df0710f351037143cfe4559796b1be3266ba237f5377e33a5ab" ++
        "d090af0ecf8e1f342d09ec427e20743da494fbd2ce9318fb668b0576844393e868f8f4d0d6bcf3656dd75d349ebfa290" ++
        "318d624d7986d44023dd66563df05d0b2c7e4998acb3440baad62ab8d1ae1a9c701e4b247fad4365b1570b10c1f16db1" ++
        "a0edef74181e7fc5bcb6edbbf53bb475d2c411cdffe9b6aef8b0786f10ad977b3c18d1bc1b8b72f1cd5b816a20ce20ea" ++
        "dd2f9bcf24997ca9b767da8c31802b23da6500d3be0df59081693c7e3eb9f63a240b0095ae95677569c3e932ceec09a6" ++
        "54dccb5da15ef717b7d4926403fb63e6777e0d8f29c21e5adf8edb88ff75e2263d59ea625f45bf25dec9ae82b11d4735" ++
        "10453dd26922f84040342f0a41d14a2c2ac77ddf21f9ea45120a4cd4dcd14717c48d5bad844164be3486dd4855f0adac" ++
        "6f4247701bf3b5a28e4bfee2124bc147c4e03deee93c3b0308140c1ae6beaa566c7deab4b79e3b806db7a95e904d6b09" ++
        "f8af9c99429423cd092d6b28922123e0795a939a2d4d212219b6862f916184683e00e41d7899098056c6c1bc14dc232b" ++
        "69900090fa555a1231421a92ead88b8d91cd171ebcda120b708df8b4a74eec8a8da5e21ae8e3a8bea63ef8caf10a5367" ++
        "723b8f36a2b42025f813bfd2e3363126c474842060908e207121d7f5087b4bd091dc31c6d96db338e91e3626e2c88864" ++
        "2adee1e2b4766ced933042d5396ccb95160d07ac830ee4378cdf54c213771a5c4f1ee7f06e7aad327f39a593d1abe20f" ++
        "5ca2a935c99025d12b556eed860d56992152eb1043bad513671ed18b79c4f77f4e5cb859717184d7f34c86552acf2a4b" ++
        "359ca7fc4d75733ade0efa598df011e5b6d3ffc3bac3d2b4f95135ea47dc8c6236f6dc3f1a532988e845ab00da610bbb" ++
        "bdffc0bfc4fe4bae5d1c0663fd15f5e302e9afcfbffb8be47140b2e4e895c7403a988c9c91ef3692979c40ceb3caa471" ++
        "0cfafb7de276618b2e54f656f673c98eae3b2210776fcef51cd29ada9e50a9827bedcb1dff97191c173bf214479d77db" ++
        "a8e494dfba21625e855e117ba18a15da5dc1995e118a0afc8a89b26876e689ffb3d5b6155b5c1f8baececfd967cd1c43" ++
        "e74506ea17b7d510285a282272910222d8e8bb4c2d208499edb81585b36520a95a209a3ae4ac1623bc8af902793009d2" ++
        "5ffee92cbf32819c1170e8387d07fefe2e69b1abe8a96fbba248abe38c794defea759db64ea54bf0d7f04e0a38529198" ++
        "7855b0380ae743dcf5db2e135c64285b91a8248348ad36a5ce1b2b0dbf58de4a6354e26f57383a5a463b4f524f639047" ++
        "057f36f30c83b162f51b066e830a3c919cf442c1563bb250573b8bbbb43581e3dee522c0e581b93b3ee7a04471696df2" ++
        "dbde0c4da7c287151235530c8da11e65e7dd27e17aff04da38ea79ee3f06b1878621ecf19f1e7f805c593262326a1a5c" ++
        "e394a804c6790f34b1eff1956d443209b4f4c0069622e7a2178629cf37e47340cb87b7a641a7e5cef96d29048fca393a" ++
        "0521f3880d94064978c15510400b190f10910e3a28b3ca1cd1e61d715f73e7bfb25c8ea501bc3de6843bb4e44e63621e" ++
        "7e38df07c7e710a72247ce6df26003fb9ad0ace176a9baa10b04ed8bb6eecdb7367ef120381cf0493894059fd0a69894" ++
        "12934f4c72788c25da0baa2b914f6336a04450006cbb64ad7b18bec35707cd7687a5cc0d1b260775fbd84dc520690c19" ++
        "0ce9a231722613dfae948619696e5acfdb5fde06911026e0bd0814f32f7616d9653a5abcad756bfd453195775dbbdc39" ++
        "df8642726c7f84a7894962e087643dce43233fe62edaded6af98ac1ca0ec77bd381617e494401f22bbaee9e4cd166663" ++
        "332e0ab7fe176b7c9b4e52f336d5bb1d58c2f82074befd6900b414b3c2a3d4f51e7a1c76d63b253a8fbf1b43b43edeb3" ++
        "d0adeb20d82b1922ac50f21a3a2a1348fb0706c313ac6f6838fef338b58f03c7bc835df9ff73223451386e47701d4fa9" ++
        "6d76ec4b796a3245eeff785eb1be1104f4627b049dd5f1e7afc12c7703b01473374edd8dda1ca167c30dbc88d71a1821" ++
        "af76317e8323e8c8731d475c802378782cbcbf8cc7f5480bdbc715e020a428170148b02554cebf136fafef79f4f9aee3" ++
        "b44553e347a0d35fa86f0e39e5ab5bc907828b41d2d6ef956631e36d99f12f6c22c6da11502e89d53cfe26eeb2da691f" ++
        "e9390e4347a201897d5c9e8554549b05763378f231fda9cb65570fab911ae46cf632904d666092ad8618106ce17121f3" ++
        "a885ff47eac30ed07ea00f8b9b17f83e49b010c209ee7c26526a502287217b46e1d92ed9f2497305740888fad46569df" ++
        "164b100085d59cf6b4d8292bb921ef4bea4a4367f6071f5b409822368ca4eff7fd9ff64c94f38669cce61e21d090557c" ++
        "35ceafbc77fe3962d8b4e90e9359c3876daa58498c6ebd8e3f02d27da5c7e40ca09cba36a1ea24afd53aab9a48b87de3" ++
        "ba3723dff67cd7e1047d43b4637c90585edb4cb27557204e0e92418ed4d5cc8451b2a8e6c7ca789834a8e11441836db0" ++
        "5360c2d61d9ed72c8f823ff3dbe73f69b16ff5f8e6c962f5f99f31a6db26c6ec51ee25961a2f137c332c474e9b9d403b" ++
        "692e279c46a8496439e3c75a1fa3372eaa5b39382356674bba59e30545634c47807f877e3f3e626f203775c149d5fe9e" ++
        "d100c182693e85a23852229c9ab714b31a0ca3ba9ef222ec3b5ae263cbb5f62f54a13f86b622e6182d005758c8dc88cd" ++
        "3bb70bf9dac87bd9404dae8378947761045a5f4aa3fd94aa9f62d8c5402de8cda0d3ad0e65ff316e3f5e6cea4fd9574e" ++
        "00ed788fd95075b21ec3b5efadcac8ad30fd578c90df7364fe57398a4770835ac9dd413e6a6ead4571a94d7ecad735ec" ++
        "747c47015f83f9c86dbfe6bbd49044a98c502bfbda7f23b7339a1b6cb91edd6a70734c59a8762e68532325012f907767" ++
        "039e82134047506ebabeb8724e6b38b738e2065b9109e7825822f05e7efbf633b367c588608e02318a300c98d4a9c66b" ++
        "2899baff5cbd4c8dbeece4dd041869e9dcd479dc879549d0015fd6763755a4ab8e7cdd7d3cc7ea3a7907698906bdca4c" ++
        "9d146fca38ba408c545be086a7091e70341667a4b300bfd117e4222a0d4150e2a6008f25b329d3559ff9e52c15a1b028" ++
        "cc232dc338fe02659311bfc9cb01f978e2f099ce65470c51f4907ce62a339cc8f7f56cfc48693396e0daef74125060df" ++
        "654230af193fe5add5d082f2083e0e8f5ac52407a7f55e5c5d92a313a2acb6b28b1a6e11be6ab224b6b4b008bcdb4a74" ++
        "a4bf95850abbd7d7ecdcca838063f5680c8610f3941e9f22db5c8682c78e53e2cd971dfb7a7c5af6d412237f7496f27f" ++
        "4640ff71e56edcffdba4528f4891a541ab3abee0555cfb36d7bfa5ac816b0258584e8b8c89a60333e4554bfd3db0455d" ++
        "681dda8e3643e6d60eddc79ed899b2253f65b5aae76e69a03774b63f81aa6a58b1acbc79e8fdd965152fa2ae5141fee7" ++
        "2bd51bcc9a7173af7ea71d1b1bce4d2bc31581c20eb8bf13393cd17a16265715ddb5f813feb5ac33e17a05c6b40e0708" ++
        "19d787de699da3ffb8a20d0533d07398db8cfac2e944b4942279af4f66f2dbff561e811856d662e07a617fb1641cc003" ++
        "c6f0a62dfb7d7733078e97a5ada580358e9ffd74ece3218c8a306b2f151b649258e7fc664710576a26cde9aba7baa192" ++
        "3d42fb53bdc3b8c6a7e3695b59e74efabbcb4b5f74ee415002519d433fac49ccdc179c9909d370ce29458f656bd790df" ++
        "5daf58a3273b49b45bb7c62b781cc9d2f55f2ce628322678c73f3bd66b48b74418323e28c25216cd45320bd004942866" ++
        "e20183a4e67d7253ff20a7b60dc79e257d7b7ed1e1ef6125da51ef86b510dbcf42a59a0e8c6a8dd77189aafa9dea45e1" ++
        "d0210bd1a37ddb592ae78c37d6930c1fc58e32dfe96e5bd0171fe3b01654fddbb91361500eaf9a8e7e6c91b7ba2b3d37" ++
        "43074157384007914074c160a426adb249f645a826e22d16c18d5e244bcd3666b22e8ac25b012b9c1d5f09755d095370" ++
        "062dfa60f847e6c5fdb923efcca1eccb3ce4a89da025643ef40e98908b6742cb19614ed9e8cacb4453e7b3a9a62cb817" ++
        "048cf869f3b6818f55257378b89facb3f747a2db651951abcf95e7c3f96a7255991e5de36ab421e8438c7e083fabe54d" ++
        "49e69b65b04835c93b5826e23f1f5c7cbfc8dd3f3983d6e0a8a354118cc0815ea44cf01ed3c41f2ed60a3f85bd35e2af" ++
        "39f2b871500db65cf99ce99caa5911dfe1f9150cf2a030c78e82534624d8b1bcac3533dd6f7e8f3921234f39c0bd27da" ++
        "3cb3d4d3bc047a677f803babb212156eac43b4d23891aff6f1b380ec9022d9e54a1a2d86c125b532d85be70b79aebbf3" ++
        "458de53b2e3f4014b6f8292c3395db024bd473de633ed37ffe0c9449b0d5a216b86d5613a0c91ddf4c4a4bc8af68bc91" ++
        "1d664748cb7afb824c3033f6d791e1a16c1e4b0baede7ea7caf8b31e2c2bd47b4ab67edf2e9ab54aae0c5c8eaaa92f7d" ++
        "c77d6b96c96ffec1d88953f5f3867f95ef700ebdc821192a664091e0ddc3de5f9f46128a50fbcca9b7495f3cf44f9886" ++
        "f74b5f12f96976456364615f8fad290e90c3e9fb7c3facf74499864cb8a25d0b2114b9adcdf4631fc0e54df68f3b6eeb" ++
        "5298f8ace209f1c46ebe6311e1d91d9bbe15f6906c7d0a9b5f197105f428e4d71ade29d3b390fda7a9b0bb7aeb8f35cd" ++
        "6c289c50cbfe21018afa25bb3009c5f862baa41ec493375ef692e59f3ba65acc547f64b1000b4db0dc60e475dcc9bf87" ++
        "d0888b1272fe35e928ce7aace5f8ff78afee1804057e223395b50f4f35cd8742c119bc287b3ec70a193f959d0e1f4445" ++
        "255f9951be7a3ff6c61872634ec62c7f0f9f3617cdb85d02b65deef4cc3e0770d78b007ab60453419e80ba8dff91eaef" ++
        "d22295d61220cfae88f1f661cffaf211a9cf61273e6fa049068fb35f5db700d0716ac80d54169621af8e05ea76385aab" ++
        "b66efc28b6d3da4150942af505c07bf9377e2c3e89c80f9b103cd9c46a30b71eeacb2ee1e7b22730e1180dcfc67d2de8" ++
        "ae6374c5666442a71c3a20a3011af0f581a3fdde3dc3390e197173872a3d961f994a2c2f84e82fdb07469aaca70007d9" ++
        "b1c2aea683d1fb1014d29ec80cdfc46e51e7b0da975770b0193ec1e3c7c3a9b437439bca7602873d7d7671aa00644591" ++
        "b65e1fffc4b83a0727d09a94bc9610924ab039709bb4534541f740f136ea3c32a3f69bce793b8231297d57982068c54d" ++
        "88712dffffad34c64c1b04fcf54b242045ff666f09cc304f00a8c695b9c1995cc319f80d5a0a0887b0920d009bec0a36" ++
        "4b48ba7b5de97c9586a64c36131812e31b9c7b9aeb42f7a3218ee342fdd2a9db25f1563df7ecfdc732415b5830dd0c6b" ++
        "5391847ad22545e9ced2b33059379160dfb9e706bf1b93e72948cb62080cd073ef1a6f9bd24169a6f9a94e197facc72f" ++
        "d407f78a46b435d696bde0e844b2c929471800b7e931062473baf1042d2cb7b6f587189737d40c8b690f69f19e7080c5" ++
        "2fc7383191fa9e1a9a11fae46f9a43ed0336ea1851e2a4bf3b815321d654520ebea885e4d27830d651fd7e9ee272d26e" ++
        "d2ffbea207e95b93fbc5f8a6c71e702a8b47edddcc8f6b9155b1a7ea590b8163353bf697769df311ae6ef1fee25be20c" ++
        "d68700be5a77a00b1c64c52e7b1fcafc3be490f55a8272f9517915780b296ea6408f1a5442004e866ac912710b4a3560" ++
        "c0959796d6e17e86ca39ec203133b25524a45868bf74b98fca8ad497bf47900e1b2808e250dcb30f2e391d4e2016d0d0" ++
        "ae3464eb0e10cdfeb24941e017df50255b08bd5625ab5cf698bbf6cfef17818dd178207ab55dcb2e0e6dec28bd4dec64" ++
        "1c1b7ea08d4305c05482c1c5c6ca85f03487d88b2795594119b7398aff6739b9ef46ff7cf9a3b16f9592926747208e42" ++
        "62ae0dfba713dc393e7d1f503c22887a64515e7c334a14a46621416e6257ed87c2c5102b41c5dbd390b6b8fd5ec9b1c7" ++
        "0f07f83fb0df7e442607bf32e8c794404dd60b946e7e93f5c3821fbd74c835ab82d1d237b1a7acee3ddf68a2935a12d3" ++
        "29a5d0e8350fde4be329bc7ce0860c54c63a29eada7d9e88b72eb7e14b77478af1187bf43033ef2278ea586cf52a3f5b" ++
        "a9185bd92f8f8c57842e388230ba319ee33913a6fdbfbec774c231c43dbb6181cbc97df240d241e5248c4fbd10fd35c1" ++
        "57516a2b393fa89e3369aa796eb519be304715987f74b0d681e99ee7f7c7ca7a03de3693580e99ae71d83064a3c49165" ++
        "774fef14bec0c936f0c62d37b4c0edac3db6f4c6abf6dbc5f56b66cf5b642ccd61cd26d7ee4b62e7ae338ea7555b7a39" ++
        "f79aa93b481eba2b65c34ef011b39a298b99e55d79b60a318af17cc4cb6946795b91425699a0b28ed2fde36e45f42c8c" ++
        "cdcefda806830aec69b803f889c9e64aa8a58962e3b77c2ee97c7063d5d25bf61c6d512ef41934ec8cb12c5be4cb3012" ++
        "ffc1774b0210441f7483e710fbafd0d8066173201de9ccdbb75f32c75439489d7d79d15032951f63117b5eb0447efc9a" ++
        "1076aa9e601d6099e97463b97c1fc62033308c07b2255418d9040c929b96679643d07c7d0b459e0e0da9f54e7aba5cc2" ++
        "fde3c11952e5faeb0781d42232e07f454754899797ed67c26f3f0465639b2685067ca57162f3eb67fce0be0d6cf57910" ++
        "8d830f301a767fe8e1965fcb8badd9d04315f19aae2b974754cfdc3c26f67a6e9ae02f48516476241c711e58332f6d35" ++
        "e98b19a87cdd5440b10c81649caef0788298165c61b4cf9f320a0ccf62400e84f06ba0c35f475429514b475560a8a502" ++
        "fd71e7b9d2ce703cb9c5ea22952aaddfdd2d4f2a2a7e94127d78d1be13572694270d6e5e31c9e00885eed117423db3b7" ++
        "92aa0c65eccedea811218421f06356f23ddef16686ab14d9cb5964b23f0fe8467c4181e5291b1c52bfe4297f087cb8c6" ++
        "51148b7c9da30eeb8d623e404b7aecd1cc93a8c6835363c093e56df17a3de15f466e41bf753d3f94a5b1f6bbf4ddddfe" ++
        "69d9300b75ac6398c7751277c3ccc7bf1dc52ef0e2eb87bc881f5595eef90c9279e93df924454efef1f08c0036eaac4b" ++
        "cd9213bb71a9246d34897dfd2f8bea492269fa45e3463c52a9b55ccf568d28d0563b0148c7c40648a23cad9e9b20f9d3" ++
        "d5340325c8dc590eefe25be759400e7367e15348e78b3f567cb332dbf41ee5b3104c0566cbab70b3a361c517d4e2f264" ++
        "0899ae4d30aff3c80f1f2579eb948db05a738292d285f3cef2effef6c63a37c6a994db4a0fbf53d005ed46a0d525cbcf" ++
        "a87c5e89e56cc29f54f5ff572db95c8250e920bbc3236fa7c79dd061d5a5020ac38ae132a6e4145f9ae605ef759d05ba" ++
        "28bf04a23cf8cadb7b035bdc19c65825c0632b464d6b3e5180961ebccc0bc5ce4e437ffddd3320589bd53648bd815d25" ++
        "325f834ab4765b9e9017c50dd8e6fff763c4410c51865980bf671306b6976073434006b36c2c2426ec9b4d74e808a3e6" ++
        "71c693e89b079b378f776e06dbb692d4e7502bd41c48cf56d46b8dc535672b07437cf31a90a1ebf8027c35ec0a0001fe" ++
        "71ae71eba10bf9abf899dcb02de666c368fd94b31822dc1932ff3a2a7586dd666ac39e3bd90e74e1a22f7751a02a56c6" ++
        "9a85be87586d6eec8089617377dd58ce9e95f6f753d490a99da665299252fbd240e501a43bbc9dd435549b9025c9cece" ++
        "f7bcd1fc4e08e76afb5a63e0e57cea19a04cfcfd9c6fe28cb77035686b138deda9b56b6745b9d4015bd568b2e3f004a0" ++
        "8332169195d8b80033606ef9abcc8ee1a07095ae11468feb1b0701286c1c92883d8590e43b241e3a46cca88e0c858822" ++
        "fd77e988c0b98c5a58916b8442356c360ea02758a3c6305f43116255c3a551869ccafc4361b2249f9428f38e2ba29f62" ++
        "28a710c0e94f45aaa921ccd6cadda70d898f013f5ba774bc672242af0e34ad104f41953a12c833fa683ac46485ab51af" ++
        "58cb06da7855e00c1304e6b587bf5d24dedea50030eb1f0bb02a305d454f01b272c35b53a1be6ddc95171597a5b0da98" ++
        "18c7ee2019d217fc13fde236cecd7d001dfc52d823c34e9294aeaea948a0233976fcaafdb6ed1b30cef38ccd488ca714" ++
        "9611effc81f0c7111e1549fbb00fce9ba1c1d9d272c26296dae5f7b2cbc439842cb28c1222e5060731ebd583991511a8" ++
        "a3e5d0804ec0a0c85f31cb45398f305ed646335229b4cf4b0f6dc013e5be0d4e22b8d7612beb49e84096d41ee00bf532" ++
        "84e5d0cae8fe5501be4af45b2197c9518bc64aefc83d2859b2c46e8b642209e3d9cd79b19e5cfdebc4ba923b8c2ce576" ++
        "97084e826b5be7c329689c71d1411c7e5aada4c744e9d8eae4579fd51c4226fba05794e9315591f377497b9f8fc1072a" ++
        "33b6c4539b138b537a9ffb28f21594709e120c25317aa3ec5449b184c0067b4e06c5864aec3ba3d9bc594608019401ac" ++
        "f50c3366c0f0672da8ba86c104cdcd1d12fde5e7910056073748294a29b5b60bbad9f0e9bb2ea6a64f54cfd61965914f" ++
        "0236baca65f7b4527339d58b71e536e7ff8c537562d90ca1575148d17ed68d6480f622ff7ddfccaf594275456b562190" ++
        "fd18591a7d82a3a1f7df71ec7c1c87e61ccfd3bae5473513d9b375b48932b6c679677825a3212955be9c5db46d67348d" ++
        "5752adc78f01434db5a507478828e6de9b7d09c452608e63d42ff7986552afacafbba26f44e03042e306b97bd111e6f2" ++
        "32c1c1dd0742d94a797727bcd964027a1d1a66e556d334b179044cd55df2de82ecd6e1a3ceb5c50017478d5c0b303317" ++
        "a90c7c7213a38161eb255ae97013ac75da9bc9dd299cd4bc757d59a98bd401df3fff7a4602ce21fa98d163d939798d4d" ++
        "e88b392e53aea0bf838c196354c98e497725c307e61e75dd811c2d5f87a9f5a416be2dbdc20e4c4ef294e5a1f04219ab" ++
        "18470c446132eb085db47e8705fdffde821cbecec780932a155724579279e3366e8c4e8c5dbad8d4df8357f26b47f002" ++
        "1448099541bb39446d8aff6a51a217c1351394ea55b41f8662eb57b6cf7c66ae62a3bab44dd480b6462ada2f9c3648d6" ++
        "8e667ba739fdfe605a0cec8b4ea60e38cfef5af6c6de540b26eaff666627a66c9ec3d1dd354a66231d6a151e5c86095f" ++
        "c3a69fc48e018b78c80352ebc0e809470605d60d8e295b1008e5811c14d1ba37a55fccbfa5090ddb38b8dda16c57430e" ++
        "4feb27668101a1ff76b287821fddbb82b5aefe19956370b5159051d106fa7512ef9b71120bbb01b48a3caeafd486d2ab" ++
        "163a20e8e282d946142951d1e09ed9d3aaece6693c13bbd321d7dcf58a90f4d05922d653c929233e38027a0ec303e197" ++
        "c925a4af5c2cfa489824f22c18faaeabfc1cab440bcbbfba6c9aa82339553e2b30e68e7ff1d1c1f7ff05a6e951d399c1" ++
        "f649184dcc271bf4dedb43b12234b5b4f83e3a516d7b72bd580d73657f3f68badc046ed25ab91f842d6fd7c8c0dbc815" ++
        "72420e7f8851c6af47cbcb856afb6c34ab215cbac2223dad4532d199543c3a10125fc5b0e616329f35704002541799dc" ++
        "d35fdc1a826b6836216b5ce0a18ca370b627f18db0751b313fadc761791a30fc5f0465d8abe871f33947ad6a40a35c0a" ++
        "4e8b84018bc147a1069edfe7b7dcc900cd04a3f92f05cdd80f2eaed99cc81b4fe0cc2ad78f430f34c040fb7ec8302b60" ++
        "b06e2a1c41c8a4a5186d2010180f44991d4e38fadea8ddaf64a904e904a5d3acd686068dc2382da83771a2a108a02df6" ++
        "260f11cd19d263694c95d3c91fb84c5e379693ef8b409a42d9716c306037639f";

    const pk = try hex.decodeAlloc(std.testing.allocator, pk_hex);
    defer std.testing.allocator.free(pk);

    const sig = try hex.decodeAlloc(std.testing.allocator, sig_hex);
    defer std.testing.allocator.free(sig);

    try std.testing.expect(verifySLHDSA_SHA2_128s("hello SLH-DSA", sig, pk));
    try std.testing.expect(!verifySLHDSA_SHA2_128s("wrong message", sig, pk));

    var bad_sig = try std.testing.allocator.dupe(u8, sig);
    defer std.testing.allocator.free(bad_sig);
    bad_sig[17] ^= 0xff;
    try std.testing.expect(!verifySLHDSA_SHA2_128s("hello SLH-DSA", bad_sig, pk));
}

test "verifySLHDSA_SHA2_128f accepts a real deterministic signature and rejects tampering" {
    try expectRealSlhVariant(
        "128f",
        "fixtures/slh-sha2-128f-pk.hex",
        "fixtures/slh-sha2-128f-sig.hex",
        23,
        &verifySLHDSA_SHA2_128f,
    );
}

test "verifySLHDSA_SHA2_192s accepts a real deterministic signature and rejects tampering" {
    try expectRealSlhVariant(
        "192s",
        "fixtures/slh-sha2-192s-pk.hex",
        "fixtures/slh-sha2-192s-sig.hex",
        31,
        &verifySLHDSA_SHA2_192s,
    );
}

test "verifySLHDSA_SHA2_192f accepts a real deterministic signature and rejects tampering" {
    try expectRealSlhVariant(
        "192f",
        "fixtures/slh-sha2-192f-pk.hex",
        "fixtures/slh-sha2-192f-sig.hex",
        37,
        &verifySLHDSA_SHA2_192f,
    );
}

test "verifySLHDSA_SHA2_256s accepts a real deterministic signature and rejects tampering" {
    try expectRealSlhVariant(
        "256s",
        "fixtures/slh-sha2-256s-pk.hex",
        "fixtures/slh-sha2-256s-sig.hex",
        41,
        &verifySLHDSA_SHA2_256s,
    );
}

test "verifySLHDSA_SHA2_256f accepts a real deterministic signature and rejects tampering" {
    try expectRealSlhVariant(
        "256f",
        "fixtures/slh-sha2-256f-pk.hex",
        "fixtures/slh-sha2-256f-sig.hex",
        47,
        &verifySLHDSA_SHA2_256f,
    );
}

test "non-SLH PQ stubs still fail closed" {
    try std.testing.expect(!verifyRabinSig("msg", "sig", "pad", ""));
    try std.testing.expect(!verifyWOTS("msg", "sig", "pub"));
}
