//! Signed-broadcast wire protocol for overlay apps. Byte-compatible with
//! the TypeScript reference in `packages/runar-sdk/src/envelope.ts`.
//!
//! Three primitives:
//!   - `canonicalJson` — RFC 8785 / JCS serializer.
//!   - `signEnvelope` — wrap data + nonce + expiresAt, sha256, sign-via-callback.
//!   - `verifyEnvelope` — six-reason rejection ladder.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

// ---------------------------------------------------------------------------
// Value tree — minimal JSON-shaped value used by the canonical serializer.
// Mirrors TypeScript `unknown` / Go `any` / Python `dict | list | primitive`.
// ---------------------------------------------------------------------------

pub const Value = union(enum) {
    Null,
    Bool: bool,
    Int: i64,
    Float: f64,
    String: []const u8,
    Array: []const Value,
    Object: []const KeyValue,

    pub const KeyValue = struct {
        key: []const u8,
        value: Value,
    };
};

// ---------------------------------------------------------------------------
// canonicalJson
// ---------------------------------------------------------------------------

pub const CanonicalError = error{ NonFiniteNumber, OutOfMemory, LoneSurrogate, InvalidUtf8, DuplicateObjectKey };

/// Serialize `value` to RFC 8785 / JCS canonical JSON. Caller owns result.
pub fn canonicalJson(allocator: std.mem.Allocator, value: Value) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    try canonicalAppend(allocator, &buf, value);
    return buf.toOwnedSlice(allocator);
}

fn canonicalAppend(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), value: Value) !void {
    switch (value) {
        .Null => try out.appendSlice(allocator, "null"),
        .Bool => |b| try out.appendSlice(allocator, if (b) "true" else "false"),
        .Int => |i| {
            var tmp: [32]u8 = undefined;
            const s = try std.fmt.bufPrint(&tmp, "{d}", .{i});
            try out.appendSlice(allocator, s);
        },
        .Float => |f| {
            if (std.math.isNan(f) or std.math.isInf(f)) return error.NonFiniteNumber;
            try appendEcma262Double(allocator, out, f);
        },
        .String => |s| try appendJsonString(allocator, out, s),
        .Array => |arr| {
            try out.append(allocator, '[');
            for (arr, 0..) |e, i| {
                if (i > 0) try out.append(allocator, ',');
                try canonicalAppend(allocator, out, e);
            }
            try out.append(allocator, ']');
        },
        .Object => |kvs| {
            // Sort keys by UTF-16 code-unit order (RFC 8785 / ES spec). Zig
            // strings are UTF-8, so we transcode each key to UTF-16LE once,
            // then compare those buffers by code unit. Byte-compare on the
            // raw UTF-8 diverges for astral-plane characters (audit D1):
            //   "\u{1F600}" → UTF-8 0xF0 0x9F 0x98 0x80  (4 bytes, 0xF0…)
            //                UTF-16  0xD83D 0xDE00      (surrogate pair)
            //   "\u{E000}"  → UTF-8 0xEE 0x80 0x80      (3 bytes, 0xEE…)
            //                UTF-16  0xE000             (BMP)
            // Byte-order puts U+E000 first; UTF-16 order puts U+1F600 first
            // because the high surrogate 0xD83D < 0xE000.
            const utf16_keys = try allocator.alloc([]u16, kvs.len);
            defer {
                for (utf16_keys) |k| allocator.free(k);
                allocator.free(utf16_keys);
            }
            for (kvs, 0..) |kv, i| {
                utf16_keys[i] = try std.unicode.utf8ToUtf16LeAlloc(allocator, kv.key);
            }
            const indices = try allocator.alloc(usize, kvs.len);
            defer allocator.free(indices);
            for (0..kvs.len) |i| indices[i] = i;
            std.mem.sort(usize, indices, utf16_keys, struct {
                fn lessThan(ctx: []const []u16, a: usize, b: usize) bool {
                    return utf16Less(ctx[a], ctx[b]);
                }
            }.lessThan);
            // Reject duplicate keys (audit D3 / RFC 8785 §3.2.3). Two keys
            // are duplicates iff their UTF-16 code-unit sequences are equal;
            // post-sort adjacency check is sufficient.
            var di: usize = 1;
            while (di < indices.len) : (di += 1) {
                const prev = utf16_keys[indices[di - 1]];
                const cur = utf16_keys[indices[di]];
                if (std.mem.eql(u16, prev, cur)) return error.DuplicateObjectKey;
            }
            try out.append(allocator, '{');
            for (indices, 0..) |idx, i| {
                if (i > 0) try out.append(allocator, ',');
                try appendJsonString(allocator, out, kvs[idx].key);
                try out.append(allocator, ':');
                try canonicalAppend(allocator, out, kvs[idx].value);
            }
            try out.append(allocator, '}');
        },
    }
}

fn appendJsonString(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), s: []const u8) !void {
    try out.append(allocator, '"');
    var i: usize = 0;
    while (i < s.len) {
        const b0 = s[i];
        // ASCII fast path.
        if (b0 < 0x80) {
            switch (b0) {
                '"' => try out.appendSlice(allocator, "\\\""),
                '\\' => try out.appendSlice(allocator, "\\\\"),
                0x08 => try out.appendSlice(allocator, "\\b"),
                0x0C => try out.appendSlice(allocator, "\\f"),
                '\n' => try out.appendSlice(allocator, "\\n"),
                '\r' => try out.appendSlice(allocator, "\\r"),
                '\t' => try out.appendSlice(allocator, "\\t"),
                else => {
                    if (b0 < 0x20) {
                        var tmp: [8]u8 = undefined;
                        const fmt = try std.fmt.bufPrint(&tmp, "\\u{x:0>4}", .{b0});
                        try out.appendSlice(allocator, fmt);
                    } else {
                        try out.append(allocator, b0);
                    }
                },
            }
            i += 1;
            continue;
        }
        // Multi-byte UTF-8 — validate well-formedness and reject the
        // 0xED, 0xA0..0xBF, 0x80..0xBF surrogate range (RFC 8785 §3.2.2.2
        // / audit D6). For valid multi-byte sequences, emit verbatim.
        if (b0 < 0xC2) return error.InvalidUtf8;
        const size: usize = if (b0 < 0xE0) 2 else if (b0 < 0xF0) 3 else if (b0 < 0xF8) 4 else return error.InvalidUtf8;
        if (i + size > s.len) return error.InvalidUtf8;
        // Validate continuation bytes.
        var j: usize = 1;
        while (j < size) : (j += 1) {
            if (s[i + j] & 0xC0 != 0x80) return error.InvalidUtf8;
        }
        // Surrogate detection: only possible for the 3-byte form starting
        // with 0xED, 0xA0..0xBF.
        if (size == 3 and b0 == 0xED and s[i + 1] >= 0xA0 and s[i + 1] <= 0xBF) {
            return error.LoneSurrogate;
        }
        try out.appendSlice(allocator, s[i .. i + size]);
        i += size;
    }
    try out.append(allocator, '"');
}

/// Append a finite f64 per ECMA-262 §6.1.6.1.13 Number::toString. Output is
/// byte-identical to JS `String(x)` / `JSON.stringify(x)` for any finite x.
/// Zig's stdlib {d}/{e} formatters diverge (audit D5), so we re-derive the
/// shortest digit string and decimal exponent from the surface form and
/// re-emit per the spec rules. Also fixes the @intFromFloat(1e21) overflow
/// panic in the old impl.
fn appendEcma262Double(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), x: f64) !void {
    if (x == 0.0) {
        try out.append(allocator, '0');
        return;
    }
    if (x < 0.0) {
        try out.append(allocator, '-');
        try appendEcma262Double(allocator, out, -x);
        return;
    }
    // Render with Zig's "shortest" decimal/scientific formatter (Ryu-style),
    // then re-parse. We use {e} which always gives "d.dddde±NN" form for
    // any non-zero positive finite double, which is straightforward to
    // tokenise and round-trip.
    var tmp: [64]u8 = undefined;
    const s = try std.fmt.bufPrint(&tmp, "{e}", .{x});
    // Parse: <int_part>[.<frac_part>]e<sign><exp_digits>
    var e_pos: ?usize = null;
    for (s, 0..) |c, idx| {
        if (c == 'e' or c == 'E') {
            e_pos = idx;
            break;
        }
    }
    const mantissa = if (e_pos) |p| s[0..p] else s;
    const exp_part: i32 = if (e_pos) |p| blk: {
        const exp_slice = s[p + 1 ..];
        break :blk std.fmt.parseInt(i32, exp_slice, 10) catch 0;
    } else 0;
    var dot_pos: ?usize = null;
    for (mantissa, 0..) |c, idx| {
        if (c == '.') {
            dot_pos = idx;
            break;
        }
    }
    const int_part: []const u8 = if (dot_pos) |p| mantissa[0..p] else mantissa;
    const frac_part: []const u8 = if (dot_pos) |p| mantissa[p + 1 ..] else "";
    // Concatenate digits, strip leading and trailing zeros.
    var digits_buf: [128]u8 = undefined;
    var dn: usize = 0;
    for (int_part) |c| {
        digits_buf[dn] = c;
        dn += 1;
    }
    for (frac_part) |c| {
        digits_buf[dn] = c;
        dn += 1;
    }
    var leading_zeros: usize = 0;
    while (leading_zeros < dn and digits_buf[leading_zeros] == '0') {
        leading_zeros += 1;
    }
    var end: usize = dn;
    while (end > leading_zeros and digits_buf[end - 1] == '0') {
        end -= 1;
    }
    if (end <= leading_zeros) {
        try out.append(allocator, '0');
        return;
    }
    const digits: []const u8 = digits_buf[leading_zeros..end];
    const s_len: i32 = @intCast(digits.len);
    const k: i32 = @as(i32, @intCast(int_part.len)) - @as(i32, @intCast(leading_zeros)) + exp_part;
    // ECMA-262 cases.
    if (k >= s_len and k <= 21) {
        try out.appendSlice(allocator, digits);
        var z: i32 = k - s_len;
        while (z > 0) : (z -= 1) try out.append(allocator, '0');
        return;
    }
    if (k > 0 and k <= 21) {
        const ku: usize = @intCast(k);
        try out.appendSlice(allocator, digits[0..ku]);
        try out.append(allocator, '.');
        try out.appendSlice(allocator, digits[ku..]);
        return;
    }
    if (k > -6 and k <= 0) {
        try out.appendSlice(allocator, "0.");
        var z: i32 = -k;
        while (z > 0) : (z -= 1) try out.append(allocator, '0');
        try out.appendSlice(allocator, digits);
        return;
    }
    // Scientific notation.
    if (s_len == 1) {
        try out.appendSlice(allocator, digits);
    } else {
        try out.appendSlice(allocator, digits[0..1]);
        try out.append(allocator, '.');
        try out.appendSlice(allocator, digits[1..]);
    }
    const exp = k - 1;
    var ebuf: [16]u8 = undefined;
    const estr = if (exp < 0)
        try std.fmt.bufPrint(&ebuf, "e-{d}", .{-exp})
    else
        try std.fmt.bufPrint(&ebuf, "e+{d}", .{exp});
    try out.appendSlice(allocator, estr);
}

/// Compare two strings that have already been transcoded to UTF-16LE code
/// units. Lexicographic, code-unit-by-code-unit — matches JS native string
/// comparison and the TS reference (`packages/runar-ir-schema/src/canonical-json.ts`).
fn utf16Less(a: []const u16, b: []const u16) bool {
    var i: usize = 0;
    while (i < a.len and i < b.len) : (i += 1) {
        if (a[i] != b[i]) return a[i] < b[i];
    }
    return a.len < b.len;
}

// ---------------------------------------------------------------------------
// SignedEnvelope
// ---------------------------------------------------------------------------

pub const SignedEnvelope = struct {
    payload: []const u8,
    sig: []const u8, // DER hex
    pubkey: []const u8, // 66-char compressed hex
    nonce: i64,
    expiresAt: i64,

    pub fn deinit(self: SignedEnvelope, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        allocator.free(self.sig);
        allocator.free(self.pubkey);
    }
};

/// Signer callback: receives a 32-byte digest, returns owned DER signature
/// bytes. Caller's responsibility to free the result.
pub const SignFn = *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, digest: [32]u8) anyerror![]u8;

pub const SignEnvelopeOpts = struct {
    data: []const Value.KeyValue,
    /// Function pointer + opaque context.
    sign_fn: SignFn,
    sign_ctx: *anyopaque,
    /// 66-char compressed hex pubkey of the signer. Caller-owned; envelope
    /// will copy.
    pubkey_hex: []const u8,
    ttl_ms: i64 = 30_000,
    /// Wall-clock ms used as the nonce. Required (Zig 0.16 std.time has no
    /// `milliTimestamp`; the caller is expected to supply its own clock).
    now_ms: i64,
};

pub fn signEnvelope(allocator: std.mem.Allocator, opts: SignEnvelopeOpts) !SignedEnvelope {
    const nonce: i64 = opts.now_ms;
    const expires_at = nonce + opts.ttl_ms;

    // Build merged object: caller's data + nonce + expiresAt.
    var merged: std.ArrayListUnmanaged(Value.KeyValue) = .empty;
    defer merged.deinit(allocator);
    try merged.appendSlice(allocator, opts.data);
    try merged.append(allocator, .{ .key = "nonce", .value = .{ .Int = nonce } });
    try merged.append(allocator, .{ .key = "expiresAt", .value = .{ .Int = expires_at } });

    const payload = try canonicalJson(allocator, .{ .Object = merged.items });
    errdefer allocator.free(payload);

    var digest: [32]u8 = undefined;
    Sha256.hash(payload, &digest, .{});

    const sig_bytes = try opts.sign_fn(opts.sign_ctx, allocator, digest);
    defer allocator.free(sig_bytes);

    const sig_hex = try bytesToHex(allocator, sig_bytes);
    errdefer allocator.free(sig_hex);

    const pubkey_copy = try allocator.dupe(u8, opts.pubkey_hex);

    return SignedEnvelope{
        .payload = payload,
        .sig = sig_hex,
        .pubkey = pubkey_copy,
        .nonce = nonce,
        .expiresAt = expires_at,
    };
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

pub const VerifyEnvelopeReason = enum {
    missing_fields,
    expired,
    bad_json,
    envelope_mismatch,
    bad_sig,
    pubkey_not_allowed,

    pub fn wire(self: VerifyEnvelopeReason) []const u8 {
        return switch (self) {
            .missing_fields => "missing-fields",
            .expired => "expired",
            .bad_json => "bad-json",
            .envelope_mismatch => "envelope-mismatch",
            .bad_sig => "bad-sig",
            .pubkey_not_allowed => "pubkey-not-allowed",
        };
    }
};

pub const VerifyEnvelopeOpts = struct {
    envelope: *const SignedEnvelope,
    expected_keys: ?[]const []const u8 = null,
    clock_skew_ms: i64 = 5_000,
    /// Wall-clock ms used to check expiry. Required (Zig 0.16 std.time
    /// has no `milliTimestamp`; the caller is expected to supply its
    /// own clock).
    now_ms: i64,
};

pub const VerifyEnvelopeResult = struct {
    ok: bool,
    reason: ?VerifyEnvelopeReason = null,
    /// Parsed payload JSON object. Caller owns the underlying memory when
    /// non-null; call `parsed.deinit()` to free.
    parsed: ?std.json.Parsed(std.json.Value) = null,

    pub fn deinit(self: *VerifyEnvelopeResult) void {
        if (self.parsed) |*p| p.deinit();
    }
};

pub fn verifyEnvelope(allocator: std.mem.Allocator, opts: VerifyEnvelopeOpts) !VerifyEnvelopeResult {
    const env = opts.envelope;

    // 1. Field presence + types.
    if (env.payload.len == 0 or env.sig.len == 0 or env.pubkey.len == 0
        or env.nonce == 0 or env.expiresAt == 0)
    {
        return .{ .ok = false, .reason = .missing_fields };
    }

    const now: i64 = opts.now_ms;

    // 2. Expiry.
    if (env.expiresAt < now - opts.clock_skew_ms) {
        return .{ .ok = false, .reason = .expired };
    }

    // 3. Parse payload.
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, env.payload, .{}) catch {
        return .{ .ok = false, .reason = .bad_json };
    };
    errdefer parsed.deinit();
    switch (parsed.value) {
        .object => {},
        else => {
            parsed.deinit();
            return .{ .ok = false, .reason = .bad_json };
        },
    }

    // 4. Inner nonce / expiresAt must match outer fields.
    const obj = parsed.value.object;
    const inner_nonce = readI64(obj.get("nonce"));
    const inner_expires = readI64(obj.get("expiresAt"));
    if (inner_nonce == null or inner_expires == null
        or inner_nonce.? != env.nonce or inner_expires.? != env.expiresAt)
    {
        return .{ .ok = false, .reason = .envelope_mismatch, .parsed = parsed };
    }

    // 5. ECDSA verify (raw, single sha256).
    var digest: [32]u8 = undefined;
    Sha256.hash(env.payload, &digest, .{});

    const sig_bytes = hexToBytes(allocator, env.sig) catch {
        return .{ .ok = false, .reason = .bad_sig, .parsed = parsed };
    };
    defer allocator.free(sig_bytes);
    const pk_bytes = hexToBytes(allocator, env.pubkey) catch {
        return .{ .ok = false, .reason = .bad_sig, .parsed = parsed };
    };
    defer allocator.free(pk_bytes);

    const verified = verifyRawEcdsa(digest, sig_bytes, pk_bytes) catch false;
    if (!verified) {
        return .{ .ok = false, .reason = .bad_sig, .parsed = parsed };
    }

    // 6. Allowlist.
    if (opts.expected_keys) |keys| {
        var found = false;
        for (keys) |k| {
            if (std.mem.eql(u8, k, env.pubkey)) {
                found = true;
                break;
            }
        }
        if (!found) {
            return .{ .ok = false, .reason = .pubkey_not_allowed, .parsed = parsed };
        }
    }

    return .{ .ok = true, .parsed = parsed };
}

fn readI64(value: ?std.json.Value) ?i64 {
    if (value) |v| switch (v) {
        .integer => |i| return i,
        .float => |f| return @intFromFloat(f),
        else => return null,
    };
    return null;
}

fn verifyRawEcdsa(digest: [32]u8, der_sig: []const u8, sec1_pubkey: []const u8) !bool {
    const pub_key = Ecdsa.PublicKey.fromSec1(sec1_pubkey) catch return false;
    const sig = Ecdsa.Signature.fromDer(der_sig) catch return false;
    sig.verifyPrehashed(digest, pub_key) catch return false;
    return true;
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

pub fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    const hex = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex[(b >> 4) & 0xf];
        out[i * 2 + 1] = hex[b & 0xf];
    }
    return out;
}

pub fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHexLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        const hi = try nibble(hex[i]);
        const lo = try nibble(hex[i + 1]);
        out[i / 2] = (hi << 4) | lo;
    }
    return out;
}

fn nibble(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidHexChar,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn alicePriv() [32]u8 {
    var b: [32]u8 = std.mem.zeroes([32]u8);
    b[31] = 1;
    return b;
}

fn bobPriv() [32]u8 {
    var b: [32]u8 = std.mem.zeroes([32]u8);
    b[31] = 2;
    return b;
}

const TestSigner = struct {
    priv_bytes: [32]u8,

    fn signCallback(ctx: *anyopaque, allocator: std.mem.Allocator, digest: [32]u8) anyerror![]u8 {
        const self: *TestSigner = @ptrCast(@alignCast(ctx));
        const kp = try Ecdsa.KeyPair.generateDeterministic(self.priv_bytes);
        const sig = try kp.signPrehashed(digest, null);
        var der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
        const der = sig.toDer(&der_buf);
        return allocator.dupe(u8, der);
    }
};

fn signerForFn(priv: [32]u8) struct { ctx: TestSigner, pubkey_hex: [66]u8 } {
    const kp = Ecdsa.KeyPair.generateDeterministic(priv) catch unreachable;
    const compressed = kp.public_key.toCompressedSec1();
    var hex: [66]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    for (compressed, 0..) |b, i| {
        hex[i * 2] = hex_chars[(b >> 4) & 0xf];
        hex[i * 2 + 1] = hex_chars[b & 0xf];
    }
    return .{ .ctx = .{ .priv_bytes = priv }, .pubkey_hex = hex };
}

test "canonicalJson order independent" {
    const a_obj = [_]Value.KeyValue{
        .{ .key = "a", .value = .{ .Int = 1 } },
        .{ .key = "b", .value = .{ .Int = 2 } },
    };
    const b_obj = [_]Value.KeyValue{
        .{ .key = "b", .value = .{ .Int = 2 } },
        .{ .key = "a", .value = .{ .Int = 1 } },
    };
    const out_a = try canonicalJson(testing.allocator, .{ .Object = &a_obj });
    defer testing.allocator.free(out_a);
    const out_b = try canonicalJson(testing.allocator, .{ .Object = &b_obj });
    defer testing.allocator.free(out_b);
    try testing.expectEqualStrings(out_a, out_b);
    try testing.expectEqualStrings("{\"a\":1,\"b\":2}", out_a);
}

test "round trip" {
    var signer = signerForFn(alicePriv());
    const data = [_]Value.KeyValue{
        .{ .key = "kind", .value = .{ .String = "hello" } },
        .{ .key = "n", .value = .{ .Int = 7 } },
    };
    var env = try signEnvelope(testing.allocator, .{
        .data = &data,
        .sign_fn = TestSigner.signCallback,
        .sign_ctx = &signer.ctx,
        .pubkey_hex = &signer.pubkey_hex,
        .now_ms = 1_000_000_000_000,
    });
    defer env.deinit(testing.allocator);
    var r = try verifyEnvelope(testing.allocator, .{
        .envelope = &env,
        .now_ms = 1_000_000_000_500,
    });
    defer r.deinit();
    try testing.expect(r.ok);
}

test "rejects missing fields" {
    var signer = signerForFn(alicePriv());
    const data = [_]Value.KeyValue{ .{ .key = "ok", .value = .{ .Int = 1 } } };
    var env = try signEnvelope(testing.allocator, .{
        .data = &data,
        .sign_fn = TestSigner.signCallback,
        .sign_ctx = &signer.ctx,
        .pubkey_hex = &signer.pubkey_hex,
        .now_ms = 1_000_000_000_000,
    });
    defer env.deinit(testing.allocator);
    // Zero out sig.
    const broken = SignedEnvelope{
        .payload = env.payload,
        .sig = "",
        .pubkey = env.pubkey,
        .nonce = env.nonce,
        .expiresAt = env.expiresAt,
    };
    var r = try verifyEnvelope(testing.allocator, .{
        .envelope = &broken,
        .now_ms = 1_000_000_000_500,
    });
    defer r.deinit();
    try testing.expect(!r.ok);
    try testing.expectEqual(VerifyEnvelopeReason.missing_fields, r.reason.?);
}

test "rejects expired" {
    var signer = signerForFn(alicePriv());
    const data = [_]Value.KeyValue{ .{ .key = "ok", .value = .{ .Int = 1 } } };
    var env = try signEnvelope(testing.allocator, .{
        .data = &data,
        .sign_fn = TestSigner.signCallback,
        .sign_ctx = &signer.ctx,
        .pubkey_hex = &signer.pubkey_hex,
        .now_ms = 1_000_000_000_000,
    });
    defer env.deinit(testing.allocator);
    var r = try verifyEnvelope(testing.allocator, .{
        .envelope = &env,
        .now_ms = 1_000_000_000_000 + 1_000_000,
    });
    defer r.deinit();
    try testing.expectEqual(VerifyEnvelopeReason.expired, r.reason.?);
}

test "rejects bad json" {
    var signer = signerForFn(alicePriv());
    const data = [_]Value.KeyValue{ .{ .key = "ok", .value = .{ .Int = 1 } } };
    var env = try signEnvelope(testing.allocator, .{
        .data = &data,
        .sign_fn = TestSigner.signCallback,
        .sign_ctx = &signer.ctx,
        .pubkey_hex = &signer.pubkey_hex,
        .now_ms = 1_000_000_000_000,
    });
    defer env.deinit(testing.allocator);
    const broken = SignedEnvelope{
        .payload = "not json{",
        .sig = env.sig,
        .pubkey = env.pubkey,
        .nonce = env.nonce,
        .expiresAt = env.expiresAt,
    };
    var r = try verifyEnvelope(testing.allocator, .{
        .envelope = &broken,
        .now_ms = 1_000_000_000_500,
    });
    defer r.deinit();
    try testing.expectEqual(VerifyEnvelopeReason.bad_json, r.reason.?);
}

test "rejects envelope mismatch" {
    var signer = signerForFn(alicePriv());
    const data = [_]Value.KeyValue{ .{ .key = "ok", .value = .{ .Int = 1 } } };
    var env = try signEnvelope(testing.allocator, .{
        .data = &data,
        .sign_fn = TestSigner.signCallback,
        .sign_ctx = &signer.ctx,
        .pubkey_hex = &signer.pubkey_hex,
        .now_ms = 1_000_000_000_000,
    });
    defer env.deinit(testing.allocator);
    const tampered = SignedEnvelope{
        .payload = env.payload,
        .sig = env.sig,
        .pubkey = env.pubkey,
        .nonce = env.nonce + 1,
        .expiresAt = env.expiresAt,
    };
    var r = try verifyEnvelope(testing.allocator, .{
        .envelope = &tampered,
        .now_ms = 1_000_000_000_500,
    });
    defer r.deinit();
    try testing.expectEqual(VerifyEnvelopeReason.envelope_mismatch, r.reason.?);
}

test "rejects bad sig" {
    var signer = signerForFn(alicePriv());
    const data = [_]Value.KeyValue{ .{ .key = "ok", .value = .{ .Int = 1 } } };
    var env = try signEnvelope(testing.allocator, .{
        .data = &data,
        .sign_fn = TestSigner.signCallback,
        .sign_ctx = &signer.ctx,
        .pubkey_hex = &signer.pubkey_hex,
        .now_ms = 1_000_000_000_000,
    });
    defer env.deinit(testing.allocator);
    // Flip a hex char in the middle.
    var sig_buf = try testing.allocator.dupe(u8, env.sig);
    defer testing.allocator.free(sig_buf);
    const mid = sig_buf.len / 2;
    sig_buf[mid] = if (sig_buf[mid] == '1') '2' else '1';
    const broken = SignedEnvelope{
        .payload = env.payload,
        .sig = sig_buf,
        .pubkey = env.pubkey,
        .nonce = env.nonce,
        .expiresAt = env.expiresAt,
    };
    var r = try verifyEnvelope(testing.allocator, .{
        .envelope = &broken,
        .now_ms = 1_000_000_000_500,
    });
    defer r.deinit();
    try testing.expectEqual(VerifyEnvelopeReason.bad_sig, r.reason.?);
}

test "rejects pubkey not allowed" {
    var alice = signerForFn(alicePriv());
    var bob = signerForFn(bobPriv());
    const data = [_]Value.KeyValue{ .{ .key = "ok", .value = .{ .Int = 1 } } };
    var env = try signEnvelope(testing.allocator, .{
        .data = &data,
        .sign_fn = TestSigner.signCallback,
        .sign_ctx = &alice.ctx,
        .pubkey_hex = &alice.pubkey_hex,
        .now_ms = 1_000_000_000_000,
    });
    defer env.deinit(testing.allocator);
    const bob_hex: []const u8 = &bob.pubkey_hex;
    const keys = [_][]const u8{bob_hex};
    var r = try verifyEnvelope(testing.allocator, .{
        .envelope = &env,
        .expected_keys = &keys,
        .now_ms = 1_000_000_000_500,
    });
    defer r.deinit();
    try testing.expectEqual(VerifyEnvelopeReason.pubkey_not_allowed, r.reason.?);
}

test "accepts pubkey in allowlist" {
    var signer = signerForFn(alicePriv());
    const data = [_]Value.KeyValue{ .{ .key = "ok", .value = .{ .Int = 1 } } };
    var env = try signEnvelope(testing.allocator, .{
        .data = &data,
        .sign_fn = TestSigner.signCallback,
        .sign_ctx = &signer.ctx,
        .pubkey_hex = &signer.pubkey_hex,
        .now_ms = 1_000_000_000_000,
    });
    defer env.deinit(testing.allocator);
    const keys = [_][]const u8{env.pubkey};
    var r = try verifyEnvelope(testing.allocator, .{
        .envelope = &env,
        .expected_keys = &keys,
        .now_ms = 1_000_000_000_500,
    });
    defer r.deinit();
    try testing.expect(r.ok);
}
