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

const blake3_iv_bytes = [_]u8{
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
    0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
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
    if (!condition) @panic(assert_failure_message);
}

pub fn sha256(data: base.ByteString) base.Sha256 {
    const digest = bsvz.crypto.hash.sha256(data);
    return dupeBytes(&digest.bytes);
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

pub fn signTestMessage(pair: test_keys.TestKeyPair) base.Sig {
    const private_key = parseFixturePrivateKey(pair.privKey) catch @panic("invalid fixture private key");
    const derived_pub_key = private_key.publicKey() catch @panic("invalid fixture private key");
    if (!std.mem.eql(u8, &derived_pub_key.bytes, pair.pubKey)) {
        @panic("fixture private/public key mismatch");
    }

    if (lookupCanonicalFixtureSig(pair)) |sig_bytes| {
        return dupeBytes(sig_bytes);
    }

    const sig = private_key.signSha256(test_message) catch @panic("unable to sign fixture test message");
    return dupeBytes(sig.asSlice());
}

pub fn mockPreimage(parts: MockPreimageParts) base.SigHashPreimage {
    var encoded = std.heap.page_allocator.alloc(u8, 4 + 32 + 32 + 36 + 1 + 8 + 4 + 32 + 4 + 4) catch @panic("OOM");
    std.mem.writeInt(i32, encoded[0..4], 2, .little);
    copyFixed(encoded[4..36], parts.hashPrevouts);
    @memset(encoded[36..68], 0);
    copyFixed(encoded[68..104], parts.outpoint);
    encoded[104] = 0x00;
    @memset(encoded[105..113], 0);
    std.mem.writeInt(u32, encoded[113..117], 0xffff_ffff, .little);
    copyFixed(encoded[117..149], parts.outputHash);
    const locktime: u32 = std.math.cast(u32, parts.locktime) orelse @panic("mockPreimage: locktime out of range");
    std.mem.writeInt(u32, encoded[149..153], locktime, .little);
    std.mem.writeInt(u32, encoded[153..157], 0x41, .little);
    return encoded;
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

pub fn buildChangeOutput(pkh: base.ByteString, amount: base.Bigint) base.ByteString {
    if (pkh.len != 20) @panic("buildChangeOutput: pubkey hash must be 20 bytes");

    var pubkey_hash: bsvz.crypto.Hash160 = undefined;
    @memcpy(&pubkey_hash.bytes, pkh[0..20]);

    const locking_script = bsvz.script.templates.p2pkh.encode(pubkey_hash);
    const output = bsvz.transaction.Output{
        .satoshis = amount,
        .locking_script = .{
            .bytes = &locking_script,
        },
    };
    const out = std.heap.page_allocator.alloc(u8, output.serializedLen()) catch @panic("OOM");
    _ = output.writeInto(out);

    return out;
}

pub fn cat(left: base.ByteString, right: base.ByteString) base.ByteString {
    return bsvz.script.cat(std.heap.page_allocator, left, right) catch @panic("OOM");
}

pub fn substr(bytes: base.ByteString, start: base.Bigint, len: base.Bigint) base.ByteString {
    if (start < 0 or len <= 0) return &.{};
    const start_usize = std.math.cast(usize, start) orelse return &.{};
    const len_usize = std.math.cast(usize, len) orelse return &.{};
    return bsvz.script.substr(std.heap.page_allocator, bytes, start_usize, len_usize) catch @panic("OOM");
}

pub fn num2bin(value: anytype, size: base.Bigint) base.ByteString {
    if (size < 0) return &.{};
    const size_usize = std.math.cast(usize, size) orelse return &.{};
    var script_num = scriptNumFromValue(std.heap.page_allocator, value) catch @panic("OOM");
    defer script_num.deinit();
    return script_num.num2binOwned(std.heap.page_allocator, size_usize) catch |err| switch (err) {
        error.InvalidEncoding => @panic("num2bin: size too small"),
        error.OutOfMemory => @panic("OOM"),
    };
}

pub fn bin2num(bytes: base.ByteString) SignedBigint {
    var script_num = bsvz.script.ScriptNum.bin2num(std.heap.page_allocator, bytes) catch @panic("bin2num: invalid encoding");
    defer script_num.deinit();
    return signedBigintFromScriptNum(&script_num);
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
    if (chaining_value.len != 32) @panic("sha256Compress: state must be 32 bytes");
    if (block.len != 64) @panic("sha256Compress: block must be 64 bytes");

    var out: [32]u8 = undefined;
    sha256CompressBlock(&out, chaining_value, block);
    return dupeBytes(&out);
}

pub fn sha256Finalize(chaining_value: base.ByteString, remaining: base.ByteString, total_len: base.Bigint) base.ByteString {
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

pub fn blake3Compress(chaining_value: base.ByteString, block: base.ByteString) base.ByteString {
    if (chaining_value.len != 32) @panic("blake3Compress: chaining value must be 32 bytes");
    if (block.len != 64) @panic("blake3Compress: block must be 64 bytes");

    var h: [8]u32 = undefined;
    var m: [16]u32 = undefined;
    for (0..8) |index| {
        h[index] = std.mem.readInt(u32, chaining_value[index * 4 ..][0..4], .big);
    }
    for (0..16) |index| {
        m[index] = std.mem.readInt(u32, block[index * 4 ..][0..4], .big);
    }

    var state = [_]u32{
        h[0], h[1], h[2], h[3],
        h[4], h[5], h[6], h[7],
        blake3_iv_words[0], blake3_iv_words[1], blake3_iv_words[2], blake3_iv_words[3],
        0, 0, 64, 11,
    };
    var msg = m;
    for (0..7) |round_index| {
        blake3Round(&state, &msg);
        if (round_index < 6) msg = blake3Permute(msg);
    }

    var out: [32]u8 = undefined;
    for (0..8) |index| {
        const word = state[index] ^ state[index + 8];
        std.mem.writeInt(u32, out[index * 4 ..][0..4], word, .big);
    }
    return dupeBytes(&out);
}

pub fn blake3Hash(message: base.ByteString) base.ByteString {
    if (message.len > 64) @panic("blake3Hash: message must be <= 64 bytes");

    var block = [_]u8{0} ** 64;
    @memcpy(block[0..message.len], message);
    return blake3Compress(blake3_iv_bytes[0..], &block);
}

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

    seed.appendSlice(std.heap.page_allocator, r) catch @panic("OOM");
    seed.appendSlice(std.heap.page_allocator, pk_seed) catch @panic("OOM");
    seed.appendSlice(std.heap.page_allocator, pk_root) catch @panic("OOM");
    seed.appendSlice(std.heap.page_allocator, msg) catch @panic("OOM");

    const hash = slhSha256Hash(seed.items);
    var out: [params.digest_len]u8 = undefined;
    var offset: usize = 0;
    var counter: u32 = 0;
    while (offset < params.digest_len) : (counter += 1) {
        var block_input: [36]u8 = undefined;
        @memcpy(block_input[0..32], &hash);
        std.mem.writeInt(u32, block_input[32..36], counter, .big);
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

    var pk_adrs = adrs.*;
    slhSetType(&pk_adrs, slh_adrs_wots_pk);
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
    if (point.len != 64) @panic("ecPointX: point must be 64 bytes");
    return @bitCast(std.mem.readInt(u64, point[24..32], .big));
}

pub fn ecPointY(point: base.Point) base.Bigint {
    if (point.len != 64) @panic("ecPointY: point must be 64 bytes");
    return @bitCast(std.mem.readInt(u64, point[56..64], .big));
}

pub fn ecAdd(left: base.Point, right: base.Point) base.Point {
    const lp = parsePoint(left) catch @panic("ecAdd: invalid point");
    const rp = parsePoint(right) catch @panic("ecAdd: invalid point");
    return serializePoint(lp.add(rp));
}

pub fn ecMul(point: base.Point, scalar: anytype) base.Point {
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

    var result = bsvz.crypto.Point.basePointMul(reduced_scalar.bytes) catch @panic("ecMulGen: invalid scalar");
    if (reduced_scalar.negative) result = result.negate();
    return serializePoint(result);
}

pub fn ecNegate(point: base.Point) base.Point {
    const p = parsePoint(point) catch @panic("ecNegate: invalid point");
    return serializePoint(p.negate());
}

pub fn ecOnCurve(point: base.Point) bool {
    const p = parsePoint(point) catch return false;
    return p.isOnCurve();
}

pub fn ecModReduce(value: base.Bigint, modulus: base.Bigint) base.Bigint {
    if (modulus == 0) return 0;
    const reduced = @mod(value, modulus);
    return if (reduced < 0) reduced + modulus else reduced;
}

pub fn ecEncodeCompressed(point: base.Point) base.ByteString {
    const p = parsePoint(point) catch @panic("ecEncodeCompressed: invalid point");
    if (isIdentityPoint(point)) return dupeBytes(&[_]u8{0x00});
    const compressed = p.toCompressedSec1();
    return dupeBytes(compressed.slice());
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
    return std.heap.page_allocator.dupe(u8, bytes) catch @panic("OOM");
}

fn freeIfOwned(bytes: []const u8) void {
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
    if (result[1] != 0) @panic("runar integer overflow");
    return result[0];
}

fn checkedAbs(value: i64) i64 {
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
            .int, .comptime_int => fromI64(std.math.cast(i64, value) orelse @panic("scalar out of range")),
            else => @compileError("expected i64/comptime_int or SignedBigint"),
        };
    }

    fn fromLeSignedMagnitude(bytes: []const u8) SignedBigint {
        if (bytes.len == 0) return zero();
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

    var with_sighash = std.heap.page_allocator.alloc(u8, base_sig.len + 1) catch @panic("OOM");
    defer std.heap.page_allocator.free(with_sighash);
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
    var expected_point = bsvz.crypto.Point.basePointMul(reduced.bytes) catch @panic("invalid test scalar");
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
    const expected_abc = [_]u8{
        0x6f, 0x98, 0x71, 0xb5, 0xd6, 0xe8, 0x0f, 0xc8,
        0x82, 0xe7, 0xbb, 0x57, 0x85, 0x7f, 0x8b, 0x27,
        0x9c, 0xdc, 0x22, 0x96, 0x64, 0xea, 0xb9, 0x38,
        0x2d, 0x28, 0x38, 0xdb, 0xf7, 0xd8, 0xa2, 0x0d,
    };

    const hashed = blake3Hash("abc");
    defer freeIfOwned(hashed);
    try std.testing.expectEqualSlices(u8, &expected_abc, hashed);

    var block = [_]u8{0} ** 64;
    @memcpy(block[0..3], "abc");
    const compressed = blake3Compress(blake3_iv_bytes[0..], &block);
    defer freeIfOwned(compressed);
    try std.testing.expectEqualSlices(u8, hashed, compressed);
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
    try std.testing.expect(ecOnCurve(identity));

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
        "00000000000000000000000000000000b618cb38f7f785488c9768f3a2972baf";

    const sig_hex =
        "d7faa49250ad65d5af4c1da328b47bd7c356054e85bb2fde8b95ce6c3cebdfea411008406d0d42d2b9ed6df787671eb7" ++
        "9c1befd68890c356f7e939a29aeb8a4ef18b34b9af949c3266f0b0c8bd3da305751488daf7562f99455982dd1f1e6bc2" ++
        "d7be83c459135c1ec9b0e2ff668e16fecce1d879801dd738f5c8719d2b7a3cb49f026783ea9fb2eb73df521665bc73c2" ++
        "79121b902d7fdfaae687272f85cf337d56301e38c0f1e2731963214208a045067ecf7fe8c8326e6fe23d2b83cdb81a1a" ++
        "a60f3edbc92eef1bdb24d45f78c3f3a93d6374e834fcee553091561c83012be4b037d04d9746e050680a9e573dacc383" ++
        "350adb715932fb2288c6acc6ff1f0c3087eddcb719e33dfda67896076bb9200346db5634789b8a232111626ce321578c" ++
        "88d09263b9bee284b49088b7c700b5db74c53ffad24b73ab68b5d60fe99e5a2827bd2101adf289bb45de3d9e4ed1673e" ++
        "290ce71ee4e75ece8b5fd6d9887d1df8c7cc274b267cbc0a6cd745572d33ae3ba1b3f0fc6c0d385fd6e9c11d4ae7631d" ++
        "9dd52f71a5a1b5413f1b2d354ccf96b796adde99bdf853d3d7890f1eceb70aae3f517ca031095e50e390040e9518b459" ++
        "3b6d0b183f950a3b1c425bbeecee3e23eb3e21994eaea6ecc518e29b71b2a230ac7b910df33656467cf69bdf55ffdd8c" ++
        "af7ca007dd50f2607a93d3b7e9c09e4da852814ed07fc71c4097d443e6ea88f9ab9b1d43756f0d143ba25c88e549397b" ++
        "66f196a8779bea8abe6578170c0f4a6da7b184162856dd8dd2398e8134cec1b79e1f0b67bc213189022e5680ab081d02" ++
        "6989733dc64c0eac6ac152acd7b82f20284c5456cb185d2fff284819860e3e7265c7c2f1c1b8e979d1e4220c5aa58c37" ++
        "39a6cc9b241a6654849155a2e1dd98cdaa2622c799092a297843116ac59bd4ceadfbb4200da7e398b6dd0064555d90e1" ++
        "63cf3ded06c56835a3ea9e12b4a4cea422da04de52000fec5487871c361c53111a13a0f2b6b68f0377b49e0d73311581" ++
        "b20ed6c5ce4d6ba2d9321bb10994c58912cf4dac85000b9270d2a3031e120d6b5c573d018afdb68fe503217cf5c53781" ++
        "d49d5be4cae1e1afc33e0e2cf8dec913eee51e42860181df35838face7c01383569248bd922159d144bd9b75c38fe613" ++
        "b642de2c84b972ac1c6a15ddb194c4bcb1e7eaee0901545db271e39a19083284417b2aabce688474a7a94ef4e0e6880e" ++
        "e360e088bd3b03050a6694b260fbea795f34ce1a55a45b90fae22ad469e81d157f329640e04f56203f9c5a062310adc3" ++
        "275755f95f5ec46ad8bfdbed5ed5c19d7149fe9ef677bf2d33cfd839bcafd66e68ddf156cf85029829db18ae44ffb181" ++
        "a689acccf7165ff899cbff070f72c45c3286fd5839666a4355eeeafab4219bd0e1f7ebdbcb9a2b97ca4866eef0040710" ++
        "1132e152cea20fe43fb62f183df80890f6e071ca031d59a8e90360cbc32d087c08010545b34f7408048cfd919fac5cfb" ++
        "10cab23146da9534a813a18aa7e663eb6f25a81393584e1e0ff8efa01971a0fb06da762b7386db3a2dad3e5475c83d43" ++
        "798512d7d9b158350f97b772d20ae044bc8ca7155b352d0d93af629135c1cc1a73611c1b449115c3ba020601422d5c0a" ++
        "bcc8cb07d42d45f5dd674378e36455bcbc536755f9637ba3226c9432013590965cf6441b9187ea564c714827783ddb7a" ++
        "ff817ce909ae3848fc4ccaf820117531fca47efcc1eec8e3eeb8fc18b48463b9e73c582062048f957312b362dc1e8525" ++
        "c93b7ee053f99f37a9dcdbf212c248c5ca25549d663a832b12de02e6e0d9913cb7e56c5874df5eb393bfc831f4a92078" ++
        "4a13de82908acbd5d4fbd538bb7fd7f6d3c80b7e48a78e8045ba1064e55f4a3a8b90f8a1a07fd0fd37828c936d8440da" ++
        "941d7bb2da85862f91e78cb96223334839becd87c6cd66287e22439db8f3de2aec7fb6ffa3f8d9263b9baf50709ee3cd" ++
        "1250b46e173135569f4061d75323eef5bf1ff75debc4aa5545981a7515cb979ed5083e96c7c20e88a7ba6b665029e291" ++
        "ca6cd4bc7054b935acb2baea9e205556e9e270f893b74409d120f1d3263d2633f5d1792ceb47aa5840872528b7403790" ++
        "4a50bef79fe46643dc2d5bc06583d3e629335faf4423cb42ee784b473b8201244a8e2d5f7ccb21308cf348eb86cfa740" ++
        "086ca7853d0b8aa476a423a82edc4f0886501c6145efbde6f0295f8d7af14a8ad872520f73796a7ca833bc3ea662f5ce" ++
        "3dd11a863b88e3065f1d1bd3af0dfa668b0dd11d4bb4e34e4eadead07ab1164e35c1994ee549250253741ade0dcb5437" ++
        "ef546dd40d3180941b6a35f8554676a4d00c7bb7433a7cedff80cfe93202aa1bb41c28c588824b6bdfb158b89b252116" ++
        "74ca44932a816df14c4477b2c18fc6c4bac959f07459e4c23ce8b1faeedc79db3acd31e71c79b95d9a04304b40228acc" ++
        "3a3fa7faf02cf59ad227236cb279bc210a0fee00c174c48b6ed828fab53ab9c3b5444d55db5aa6270b8473ed30cb1d12" ++
        "1fcf10aa74097963792c3d39cbaaf7a747749e36175247fdc6eb29af5ccbdae81829ecb521d92dde8fcda01f8ad16da7" ++
        "b2a4df25d66ce861d23b88d3ee0ba8d82d8082ab708d3a3707dbb477a64e5b9fdf0e25f512a64abb84f79ac727b77a50" ++
        "c86f540b5397e552d2371a43e706ca0c53d44ce638f7bd84b201b2188ac21487d8102ee28667b64e13dfa08e666bc035" ++
        "e40e0b9861e8b4857f89d723405a61c9150f009aeaf22bf68005b733382f6a51a431dc7c8981f3024ca9b0fe821a2a50" ++
        "1fc637f2552672fc1d479d82126a0d57dd40d3f7048dfd01cd3ff590b565fa5cd513ae5706695651ab3921e85523737b" ++
        "09dcacb419b80577306c5632fddab2d8867490f9bdba5d018583fb22f03d1178d77ade7b88428bee83a2f6a664f38170" ++
        "c3a3c764a6ea9735f9482e02d9db8a737b021684a08a3f4b4ed68f723e08efde08123c6607eae0a14b2438c9d3edd81e" ++
        "283e441bc524ff332f7f3bd8b178a4b84c80c370ef7ea36c8bba602a5905fe06db74618581d26c3b58474e93a91bd5be" ++
        "cdc94c1822bc6426efdcbcf995e7bf4b9a034b2edf69bb19b4f20f5ea27f785e633885a54aa83d377d3a3f1b964b3f5f" ++
        "0bda722a4c289152f9a51a76e13b151d40e12fabd3d7a70b03b783670ab90ae10c3081469d92c51e8f05380dd6a367b7" ++
        "c1f2d733e4fb49e18ab1f681ec6805fe81a6428fd22775e37e34fe781071928e4e9b46b12ff2a8d466af93d430f24275" ++
        "77d9979c9f7c4b9f0140e9d996ec59afc49529bbe29b5a208bfcc72e1992626158f306f25c99b6a3557b061a92953926" ++
        "d933a39c981739d8240e9cf81daad4ef18f0516ed4d4ec60f2548f56a4239a9712bbe06942d779ac0149639eb65c37a0" ++
        "ca8d3e9785a596a46b8bdc011b1c166b9ce09baf94d769d95a8c0b5ed626b19316ca1bfb839cb136dad929272adf30ce" ++
        "776d6ebee93a5f1096b8b62c248fe25895adce72450bf996ec2fe2c369f3e66f5c88d429b237a935c61f2d38a8cad5f8" ++
        "3bc5ab6e5c942665f564725e1279e8d40086327494373688bec13304078923a8be359b14aa8f68105ea1e4069773a418" ++
        "9de168651e52299622d315dcf0fd66743a0bfa7c36462edbcffa538176743046350af260b3d14f1e773a9f2e8f7e398c" ++
        "42456454a44e1ac48f6489470803c211f6a766bb2ee9177f8ea238ced5e48f80a9a79671877ee27edf1f8a77d23aa8e2" ++
        "10706e2ea21e202620bdf095b5a359eea80d35794a58a6f355708b73b753217cc3bc86c6459542bd8f57f810fa2f927a" ++
        "308bf497db90b9214a058f14b2559df867b8d18777125f17fba7eb8f2bc64e5c16d7c593c0852ee306851326a43666da" ++
        "ae15fd98f5d552f23c1212ac7df8ca6562ae4372171352ceb0b6558d9e521c03ac33190304ce9b3009d6a6c1b7783c6b" ++
        "4b8491731ab8d181679fe11b401253610827f7ae9ae0b39549f0c8fb8e36fd67754e1726d057ab0977db36149b026890" ++
        "77905d71c1580abc99c3ee6809147e62f6361c8e7c422e1764cf5a63697fd5ade947a0e1d316a34f665e05359b67623d" ++
        "4d09f5a865294fcd7132fbe923dee68f0105f111282fb63373747fffe96cbf3072563ad85a7fecddd8f0c6b0f1df93bb" ++
        "9e8bb001c56fee6ec96b0ae129224b13daa44637da6426aaf7eb044924497b0fa1503c532a575bd0c8fc11c36611ea60" ++
        "37f313debc46e1f7d3dda3e22b453f7b97a17ede755eb0902f8b14b8dfb5431fdca94f9f3c624927f74f7f5b2f883660" ++
        "865d2937b67f0234a51d83b05fdb87fc55ddf4a85797c7370812cea1066dc76a702f00353f0c3caabe0884e77694de95" ++
        "26c777256269feb8fc18c47a4ca687038c12c2362ac562b6436f7730db463e841efc6b9c980f7d8b7d10eb423b5653f8" ++
        "9e14cd5b37d9b1ad1ec3c32ccfd6b08f80802f4d0cc5f0368103a5d624b7172828727edf2ebf4f6b97e1508d564a0f3e" ++
        "776b16225b9a33f65c5b670a275bfe93f484e8231e8d8b95acda88635721250d84bd87d8741191b956378c753059b8c5" ++
        "806fe52168c1642f88b968f7c5ca8e702c27cc435d0b7c53713ae5b3c4008dc3aa28ea47f784dc7b08b4c723910be505" ++
        "aed9efa251216e4d576f0336bc08eddd56c06ab855cf2757e61ab4cde338499e758131547244ee8d1dbc6d6961b24708" ++
        "cf65d4766baeb4cb1f9003617d42d61f632feabafbc8ac93b7414f78d38bc8d13eb7e1d562aa7993c85f1d1a5ead5b91" ++
        "d158b62ce7e226801bab9cf6b9410bc3a583b1b59e6f37399299959c58943696054eb9c1cb29cbe0e275fdd9db3f3fce" ++
        "a9431f41c80124272b1725d857d531e9b6fa1e214ae9b355958fcffc34d15a635a7611d3f68db557ea6f15625f03f491" ++
        "0d3ab8714b5805ebfca125e14a6fdedde37584393e22d0f51e02c079dec0f301b11eb7d26560c4e95533c7785dc20802" ++
        "f66971dd7b5a85c55d7143c9608fe14a9b6934992858b5793b71c59d5fc6ba87a4ff517fe195a805d865ab35832482f0" ++
        "ff13166603d85e20b7ff22fd62d83d2a30d995a8ff0b8155a3ad062e0016a2013a7f558581522c78a1f6a044175dbe52" ++
        "c4786717e91f70010cd67b26529c6d5f216f2ce4ed662f1b231b848df9dab8023eb76e60ee30113e4f232a069bbfe469" ++
        "ae891624a468b29545e6b73c061c529dec9d77322f7a09390ded92e3029a9d21c93caaf31a2245573b030167152cfb3f" ++
        "d964258c2a54ba32584c899603c24b8761b4e419a36b95651b34cd73911d82039119f86c38323bb336ec3bb44920fb11" ++
        "ab1f9dfa837792605a64bbc734164364d472d45eea7157cf0f2b567935515be3960bdb197aefd932f73bc255e1f3fb6f" ++
        "340ad17776e137e42db60b7ebcf3e3dff4b4982e372fc1c34822d6e56f5c7a23f9522942f3cefe3953a99a6c48d4e9e8" ++
        "b827d28f50563ce7ce55b95592145a7a4916fd9ec1cf7dcda329082628d57b47417fc0c35bd25e91f29ed11670320414" ++
        "7ea01d7f2f54e10139b2d3b03b88821f18d8afa295156fb68c6e83668e959d9620bac9440f82def80da1972f4d245aa8" ++
        "f967e1ccdfc0a4c7cd59c658d0a423c120083cb3674d7e2a1bd8b0f2e19b62caaf59af3ba38966571ab364dbf4962901" ++
        "2f0feff42ccd2951bb2cef9869874d8b0dddd945bac511bc6cee40995c429756f65016f69985e293b9362a1224aaa077" ++
        "867b60f1b143932929c354e80c8fbe8abdef839cbc4ecbae82cecbf0ea7bd6db858f8711cd7b59d14ec0089b8338e9c5" ++
        "a820a2e5eadd3bf109d479643b8b8d34c6a1a7bc323dba63c23ec292e4e5cca5f10a445c097348bde4190841870407d6" ++
        "a0a6247869348d7bc4cd1619ca304e0fadd0b67100c090ac213292448ba5952621657be74f85da145396858f0efb9e5d" ++
        "56adc54c3a9f6a87e349a9551ac95c03cd7d1771586444b4f9d6ca966f896c2808c2cf76a969a57c17fbd4131a22d2a4" ++
        "df6f04602f783194e1daca18b18276052fb07a4294ca42f60b31ba5811a98cb8c554136b1306655c5b7d779834c9f7c5" ++
        "9a0579c4f56edab06630ad54f6e60e245404b4d45963111804e17e116f8443e5806d9e271443616168d083f5bfbcf8ec" ++
        "ba31828f3c344c547b2f4640d721ffb5471902675611d0a3632af5c13ec87532fdd45757213cca5d89278d07c0c3bcf2" ++
        "f6fe8f39ac35fc34c9d0891771a81d4085cbc2e5425f29e62367d30efc378fead146ecc6c840ad2e6cc36face2d24889" ++
        "9cfac93749ddd96a5e7272784301b13f3b2588d72d4a709d979f4104dc6122c3dd9707079485ef490745383e3dea4a9a" ++
        "33146a9105ddbf194c2923c68ae09e6572598d400b47eb06faaf048df0d38fb2bc6d4030ad4dc4db7ed1fd9278365447" ++
        "7d913cc42a4fd54ea32ad4840212296f696af3225c9e531afab0bf9c942e891058845453eb109fc2ffe8802f912dae0c" ++
        "4c763778c1956487af01f4001ea27509778ca3d8268c08a455ae093c6e779f949407e2465c8425f74af08322b44e031e" ++
        "141c4b35f76c92f975350326f5b68a2dc292c460063419694c0409e7fba32ddf970c670e2a895550ceb2f74954da638f" ++
        "2967730f0b64d42eb9b505c7df1585bfcd817c32de777f53f394380974c9a1dd4662e89542ffef5e0372b49dd02c7d38" ++
        "24de4612f74286f740683f7cc69f2e98c3b7c0362414967a6eda7bbb5f8fd719a46558c3db5bf4b12edcd39c5930c0e3" ++
        "316f9c549404a65ba2a590a50520b4a5924f352bdbe3478ea8d7ea1061e64ed66777fbe6d1695cb3c0244d0d1f1893ed" ++
        "a8a666e5a9fecb57eb48671790a6aacab0f137dac3ebe8ef9565f92842b845c07d53898922e1f39bdba5bb88968c019e" ++
        "26d11b8f3872e236b402dcfe878bbdcdb3d1041dfbdd7517d0f411842f18e467ed86fcaa771bb593e84e2352214ea299" ++
        "fb8a547138413bd3425d5e49ef5ac3a71e458b932465a8f5fe7e149f42e8a3c4df8eca18257f20f951f0678befd6f4df" ++
        "599ffbfe34c68cd761e8467cc7ba5c1319a8d0b13386780edde0e706e84f86bb2e080d44aeba0dcffe2d72d0d3bde5dc" ++
        "b305b8660e8371b315be4a54bff8c7b7f18b0cbe77bf3df58422a22767b8752c4baff693f0005b601359101882891313" ++
        "ed82acf431b16d84d4ee9441cad153df2b6f33f033400c703321c27257d06d897668751fb39b049a3cec25abf29a1e86" ++
        "6a1f7a344a284d3b1b3de9d0c75abe2dd9de9e2d18c309fd2aff12c6604aaf1d9259917728e3bd5617ddedb787647b8d" ++
        "1b96c101caf902007310055496703fd80a2512ef33ce510f90ba489d80d8b7299d4bcf855aec4493ca8867393e9c5ff9" ++
        "42b5ea29427e8cb4cf6d3bb79f4588d690e707e3f38d948c4b06b0bc19b434dc880afe9ff193ec4a24113eaa347640a2" ++
        "c96ef91b311906b7bccfc7a82edccf1c739c479167b3e282d677e0fffac7b04e879a73a1e577ac9bf6289259ff5a6203" ++
        "b65c99602b49f62579586ea86e765e07904096217c06bd95b1cb8c5a3d4c54359411d0b88e577fbf4baf1b6c1cf02e3e" ++
        "452a36a449badefd17e56fe8dc01e758e9011c1b0978a5871c185bbd0e37f89c8a9491c23588bb8f8b8057dd149f93d6" ++
        "ef1b907dfa3f8fb9f9338401a0460883d294e52832cfb08b414f99d6cd5f8a6825ff565967d07c8119fde22cedb58d45" ++
        "0bd4c3865c578621f37c32e900e6b26311cacb4a50b51f9cb60be4ec5caddfbe644af6e9d0c7fc2927a906dadc1665ba" ++
        "ebd1bcd09b8ad6212fef328b58062be51776deee45ed210ad621f94dcb8a593e0c51a33b4ec05c5e6a83d57614084e6a" ++
        "597961217a9726eb2f7f90afbab359f9479b28f2e2fd20f4f579c9c89e5e5e4e1f66f8865d70f65af183d619751ace8f" ++
        "4b7661ab1c9814d4fe701dd9cd0f083f162ec7b07ac809d9bbcedace9832ed048cc075d4ca16a0bef2390bfb16b1456e" ++
        "3a20ba68731d73a0b671ed4307c1a8db70c6eca3626e68b74110ee2351ea30e0d665bc193a5797832c7ab24acc6d9e60" ++
        "c8cf3651689fa4c326b76b64cd936ecfb5dd1d0c8fe87b6fdfc7c08d935116ea0361f17ea6470cf797dd05a7b270aa21" ++
        "4116a984d1cd2b1c6ca4cabfdf7143f7fcfcd5ea9089bfc3d467d19556cb219c52910cdd48fe16a64692dd3061e57529" ++
        "3730cbdfc50edd8cc70126dd4574a9a23b4522e74c2d74953ef30768a02d68a5570fee53b76ab5d1e4f0b0866345c0bc" ++
        "42432d5cb7ee46916b515a83b158f8c6976a7398913358f36f4653c9099f47e954794ca7c1f68126940d02d33a3736cf" ++
        "1dd80eea92c5bdb16b87cdd524d30d10b08195535b961789f2b3ead454aeb5a83700050b18ed5c9109efe755c7aa6574" ++
        "252e3fdcfd08b8367f08e1054d83fc0d6e93a6556d004fb2ac8fb8dc61f35b9ddaa44f3d3dfa013c4ae54c8a32beb831" ++
        "138e2567d64dffc784ca796a67e62dcb8213ecd32246aa92612f1b11ce8ea1e7ea0dc100b0517e0489da336b32d0dda6" ++
        "a59a9798d45295920bcf512b0a5a8f6b233bf3a0a4d2f6c6246d27bb8b747882ef2cd7504d45f885d732b3c507d6a354" ++
        "fc855116f54d5141310f55b10d672a72e1372a59ef98316419944a38413b94437ad6c6d83c9dc8f7564304c03bb01738" ++
        "225f2dc5c14c8656185acc0def3e9273c4ec3eb71d01bea53ea987568cfdbe6c05745dea501c63174908a2b98d446fdd" ++
        "302cdeb8f389c215ed9a73e170d5950f25de61bda45e063a61a438f679fa9d67e76066f48deb1d710a641d9f52b70cea" ++
        "fe88444a0dfb9abd839b57f7ce0169036e6a7090e52683dbe8a847054107643523de767223060fc4d3df3b108a6cda11" ++
        "ff000902a364906b69ffc9f355fd64c6c7d2bd90143437176e0d3c9073d0050ad55c180893b47387f7a19ea3fa92a664" ++
        "888a3c76d9b031dc6b6d7c87fb6a957e9191531a29184180af676819995540a16d5f427574447d7bee0dd4c5e7ba9177" ++
        "f08e36c73f151d2e0fa195e6cae6fc738cf4ae4bce77c0de48cddc740cd3bc1e470493a4096b043969d448002d1fac47" ++
        "8f88542ca828b95c87b963c83d3ca761f89a3e0ae3890865f5ac7280d59edc555d890de993fea4e9c7a23b494644a965" ++
        "cd008fae9d78e86e427529f1b7ae0b344e4bf3ff1be3984a8738d438796030d36f23d619f8989f03fb300985aa25e293" ++
        "5131c2f0750b5c89019cbe2c3f78f5d1c6bb84bbf0f02e0f2c0e607c75bec7a294932456f9ad3989f9b1b78f39b34398" ++
        "adef627f52468cae52bcdf1cfeafc22d6b2e724f06f08c9b70f3fffb1ed6d766e9e26d1d47006ef69ca69448017b3eec" ++
        "ec72f4af76de10e3756f528fbb6063827fac46bff86b4bdbc5af34f4da8950e30b0b1f07a38faa2e54b665f3a16e0444" ++
        "01148536b16fd1433467a64a0e139a10f0bb4f947933188cefb5939ce3bba1c848ca72377ebbf56f14819ba3eb8b80e9" ++
        "66cee692a9b1a084562ae1be974b3eeaa5f849290e679469de99aa3c09f45d2248ba633f8ae249c58d44c46406c74d1d" ++
        "d740d1fe7729c907019f31a9ecb507cc56e440632fac71ea0d82a84a04c1d6011d9a93281569b55a82d15e501df1c50b" ++
        "8586be887d0eda0ece2417abe209ad7556b672f1345968108c70fd92cc00a22258012d68abc7c9f8144b9e313d1258e4" ++
        "103bc8c7245703069fd3024ebea3b4ac56bf4aed6f84f7d31fd1b0fc78c43551761872498310390a52dc9a1a1ad40324" ++
        "d93d2ed43007078498aad44fd8bc0d48961e04842bc765653911f1deaea0140c675361c08f4143931376ce88919772f8" ++
        "6432de577034bf9764585608f0116002930cb6c943bea6f6effcbb3d29708db8ea72bcfb0c74f7e7e5259c7e30972c9f" ++
        "b25cd643a25cb20902add8fa9a58e42722c16cba83538bbfc3cdba390c22cd90c8636bd620c4c81a4c4086d3ccbe1848" ++
        "fe652522b839f272db4e3aa6b5cbfd200793e2d0af2611d64e8379805b8d9bbb46cd92f53260d84827dce11b5783f114" ++
        "3f1217fc8dddde62c368bbf5aa8da5d29f393ba969aff24db6eb04a011c619a7f75457a8b510f47f93daf66df1d2ce20" ++
        "620dc20f95384bcc90f239523a00d1ad100e4a1348c6f50f28ddd56c2e28b5ec3bbeeda4c3b706c4f5d8eda413635eac" ++
        "b37e4fe5442b5446c6a72898182edc5abec21caee11d33312c8b6765f6335566f30a5c90199c597cd9d0f27015560606" ++
        "9b5987e8b2d4e17876d114bdb66a61a321499bb3342df24fe886764f67da207d357f2b06f20fa2460c27483217f6eef7" ++
        "eade13d94be85c80ac250024c42b8373e53b22549d866bc9ed9bcbe05d6332dfe36a731bd0bfcdb1bf51701ef252370f" ++
        "91985452c749da78077bc84f187ea541a2db3205a328f3aa558464bd3c787da67faa883e65bd9a39085ed60ea083644c" ++
        "d86608812d4b96d9da9e5b29b0c782458495415531d1fc7ec336357ede190b9467f9e0e048b9066b98e797cdafdea76e" ++
        "fd4604a5bdd1b6be135d49adc4ccdf4f9ebb47a642feacd6741a53067b6765e4c75193a3139f6a43ac6f832ea46d771e" ++
        "5d7bd5a964998829006d54d4b32915cb7757b63b2f97d42136dc81239ca33b439e75c9f8bb851826cc1a499a144c5ad9" ++
        "06f98c212648bbb772f2ffca19e811c3f424e8e0798f9198ee2ae4746c73553cab374c0d34544066bb734af42a5f3dae" ++
        "6dfe23daa2b8089c777d1d96fa74ff9fa6405c840946e4f6cb6dbea7f246f9c3262a8a661fce7a91810ff67fad9ff149" ++
        "f678215889f542d8cd4c154459f8a51d80e4147978a68b1ff868e019ab49b4efb58bcf89959dfd3b8a707bec7e26fb85" ++
        "8c42b8b4a3e66b8ef58286cf7b3b1ff082cff5e22ab553ddccbcd546ce241fc65f320ff72f35a8554e04345dc6be0dda" ++
        "2769a6e61a583610679927ef004d7fccd4b55039ed863545fa311194dafe2ed268e55a71572322e8a06663e36975447f" ++
        "7ab8110d35780b332c0cd4fd99541bf5d2453bf9b91a2ac6a37edf913a1add96ee814ea7fc300b2188cd435733f0ead2" ++
        "0a42c4b6e328d78a1bc2a849cd9a4b91eee05c9b14d1867b1ce16086ea49917744029d9596be4f1a97ec2cf407c9851a" ++
        "177d08f2f21f0a6e63300c9611be8c2b52d4919a4325cddf0864b0046b976349";

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
