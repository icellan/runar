//! Cross-tier interop test for the signed-envelope wire protocol.
//!
//! Loads `conformance/sdk-envelope/fixtures.json` (TS reference) and asserts
//! canonical_json byte-parity + verify ok/reason parity. See CLAUDE.md
//! §"Seven SDKs Must Stay in Sync".

const std = @import("std");
const envelope = @import("sdk_envelope.zig");
const envelope_sign = @import("sdk_envelope_sign.zig");

const FIXTURE_REL_PATH = "../../conformance/sdk-envelope/fixtures.json";

fn loadFixtureBytes(allocator: std.mem.Allocator) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, FIXTURE_REL_PATH, allocator, .limited(1024 * 1024));
}

/// Convert a std.json.Value into our envelope.Value tree. Caller owns the
/// returned tree; freed via `freeValue`.
fn jsonToValue(allocator: std.mem.Allocator, j: std.json.Value) !envelope.Value {
    switch (j) {
        .null => return .Null,
        .bool => |b| return .{ .Bool = b },
        .integer => |i| return .{ .Int = i },
        .float => |f| return .{ .Float = f },
        .number_string => |s| {
            // Try parse as int first, fall back to float.
            const parsed = std.fmt.parseInt(i64, s, 10) catch null;
            if (parsed) |i| return .{ .Int = i };
            const f = try std.fmt.parseFloat(f64, s);
            return .{ .Float = f };
        },
        .string => |s| return .{ .String = try allocator.dupe(u8, s) },
        .array => |arr| {
            const out = try allocator.alloc(envelope.Value, arr.items.len);
            for (arr.items, 0..) |e, i| out[i] = try jsonToValue(allocator, e);
            return .{ .Array = out };
        },
        .object => |obj| {
            const out = try allocator.alloc(envelope.Value.KeyValue, obj.count());
            var it = obj.iterator();
            var i: usize = 0;
            while (it.next()) |entry| : (i += 1) {
                out[i] = .{
                    .key = try allocator.dupe(u8, entry.key_ptr.*),
                    .value = try jsonToValue(allocator, entry.value_ptr.*),
                };
            }
            return .{ .Object = out };
        },
    }
}

fn freeValue(allocator: std.mem.Allocator, v: envelope.Value) void {
    switch (v) {
        .String => |s| allocator.free(s),
        .Array => |arr| {
            for (arr) |e| freeValue(allocator, e);
            allocator.free(arr);
        },
        .Object => |kvs| {
            for (kvs) |kv| {
                allocator.free(kv.key);
                freeValue(allocator, kv.value);
            }
            allocator.free(kvs);
        },
        else => {},
    }
}

test "interop: canonical_json byte parity across every vector" {
    const allocator = std.testing.allocator;
    const bytes = try loadFixtureBytes(allocator);
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    const vectors = parsed.value.object.get("canonical_json_vectors").?.array;
    for (vectors.items, 0..) |entry, i| {
        const input_json = entry.object.get("input").?;
        const expected = entry.object.get("expected").?.string;
        const input_value = try jsonToValue(allocator, input_json);
        defer freeValue(allocator, input_value);
        const got = try envelope.canonicalJson(allocator, input_value);
        defer allocator.free(got);
        std.testing.expectEqualStrings(expected, got) catch |err| {
            std.debug.print("vector {d}: got {s} want {s}\n", .{ i, got, expected });
            return err;
        };
    }
}

fn envelopeFromJson(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !envelope.SignedEnvelope {
    return .{
        .payload = try allocator.dupe(u8, obj.get("payload").?.string),
        .sig = try allocator.dupe(u8, obj.get("sig").?.string),
        .pubkey = try allocator.dupe(u8, obj.get("pubkey").?.string),
        .nonce = obj.get("nonce").?.integer,
        .expiresAt = obj.get("expiresAt").?.integer,
    };
}

test "interop: verify valid envelope" {
    const allocator = std.testing.allocator;
    const bytes = try loadFixtureBytes(allocator);
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    const valid = parsed.value.object.get("valid_envelope").?.object;
    const env = try envelopeFromJson(allocator, valid);
    defer env.deinit(allocator);
    const now_ms = parsed.value.object.get("verify_now_ms").?.integer;
    var r = try envelope.verifyEnvelope(allocator, .{ .envelope = &env, .now_ms = now_ms });
    defer r.deinit();
    try std.testing.expect(r.ok);
}

test "interop: every rejection vector returns the listed reason" {
    const allocator = std.testing.allocator;
    const bytes = try loadFixtureBytes(allocator);
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    const now_ms = parsed.value.object.get("verify_now_ms").?.integer;
    const rejections = parsed.value.object.get("rejection_vectors").?.array;
    for (rejections.items) |rv| {
        const reason_wire = rv.object.get("reason").?.string;
        const env = try envelopeFromJson(allocator, rv.object.get("envelope").?.object);
        defer env.deinit(allocator);
        var r = try envelope.verifyEnvelope(allocator, .{ .envelope = &env, .now_ms = now_ms });
        defer r.deinit();
        try std.testing.expect(!r.ok);
        try std.testing.expectEqualStrings(reason_wire, r.reason.?.wire());
    }
}

// GAP-064 cross-tier signing reproduction. Signing the SAME payload with the
// SAME key (priv=1) via RFC 6979 deterministic ECDSA whose nonce uses PLAIN
// SHA-256 (sdk_envelope_sign.signDigestLowSDer) MUST yield the byte-identical
// low-S DER signature the TS reference committed. This is the Zig fix: the
// envelope signing path no longer routes through bsvz's SHA-256d-nonce
// signDigest256 (which diverges), but through Zig stdlib's plain-SHA-256-nonce
// EcdsaSecp256k1Sha256.
test "interop: signing vectors reproduce the reference DER byte-for-byte" {
    const allocator = std.testing.allocator;
    const bytes = try loadFixtureBytes(allocator);
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();

    // Alice private key = 1 (32-byte big-endian).
    var priv: [32]u8 = [_]u8{0} ** 32;
    priv[31] = 1;

    const svs = parsed.value.object.get("signing_vectors").?.array;
    try std.testing.expect(svs.items.len > 0);
    for (svs.items) |sv| {
        const data_obj = sv.object.get("data").?.object;
        const nonce = sv.object.get("nonce").?.integer;
        const expires_at = sv.object.get("expiresAt").?.integer;
        const expected_payload = sv.object.get("expected_payload").?.string;
        const expected_sig = sv.object.get("expected_sig").?.string;

        // Build merged object: { ...data, nonce, expiresAt } as our Value tree.
        const merged = try allocator.alloc(envelope.Value.KeyValue, data_obj.count() + 2);
        defer {
            for (merged) |kv| {
                allocator.free(kv.key);
                freeValue(allocator, kv.value);
            }
            allocator.free(merged);
        }
        var it = data_obj.iterator();
        var i: usize = 0;
        while (it.next()) |entry| : (i += 1) {
            merged[i] = .{
                .key = try allocator.dupe(u8, entry.key_ptr.*),
                .value = try jsonToValue(allocator, entry.value_ptr.*),
            };
        }
        merged[i] = .{ .key = try allocator.dupe(u8, "nonce"), .value = .{ .Int = nonce } };
        merged[i + 1] = .{ .key = try allocator.dupe(u8, "expiresAt"), .value = .{ .Int = expires_at } };

        const payload = try envelope.canonicalJson(allocator, .{ .Object = merged });
        defer allocator.free(payload);
        try std.testing.expectEqualStrings(expected_payload, payload);

        // Sign sha256(payload) with priv=1 deterministic ECDSA (plain SHA-256
        // nonce) -> low-S DER, hex-encode, compare byte-for-byte.
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
        var der_buf: [72]u8 = undefined;
        const der = try envelope_sign.signDigestLowSDer(priv, digest, &der_buf);

        const der_hex = try envelope.bytesToHex(allocator, der);
        defer allocator.free(der_hex);
        try std.testing.expectEqualStrings(expected_sig, der_hex);
    }
}

// The SDK convenience path `signEnvelopeWithKey` must produce the same
// cross-tier sv1 signature AND self-verify — proving overlay apps get
// byte-identical, verifiable envelopes without hand-rolling a sign_fn.
test "interop: signEnvelopeWithKey reproduces sv1 + self-verifies" {
    const allocator = std.testing.allocator;
    const bytes = try loadFixtureBytes(allocator);
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();

    // Locate sv1 in the fixture.
    const svs = parsed.value.object.get("signing_vectors").?.array;
    var sv1: ?std.json.ObjectMap = null;
    for (svs.items) |sv| {
        if (std.mem.eql(u8, sv.object.get("_vector_id").?.string, "sv1-ascii")) sv1 = sv.object;
    }
    const v = sv1.?;
    const nonce = v.get("nonce").?.integer;
    const expires_at = v.get("expiresAt").?.integer;
    const expected_sig = v.get("expected_sig").?.string;

    var priv: [32]u8 = [_]u8{0} ** 32;
    priv[31] = 1;

    // sv1 data = { kind: "order", qty: 3 }.
    const data = [_]envelope.Value.KeyValue{
        .{ .key = "kind", .value = .{ .String = "order" } },
        .{ .key = "qty", .value = .{ .Int = 3 } },
    };
    const env = try envelope.signEnvelopeWithKey(allocator, .{
        .data = &data,
        .private_key = priv,
        .ttl_ms = expires_at - nonce,
        .now_ms = nonce,
    });
    defer env.deinit(allocator);

    try std.testing.expectEqualStrings(expected_sig, env.sig);

    var r = try envelope.verifyEnvelope(allocator, .{ .envelope = &env, .now_ms = nonce + 500 });
    defer r.deinit();
    try std.testing.expect(r.ok);
}

// RFC 8785 §3.2.2.2 — canonical_json MUST reject malformed Unicode (lone
// surrogate). See audits/canonical-json-rfc8785-parity.md §3 rec 6 (D6).
//
// Each input is reconstructed from a UTF-16 code-unit array so that JSON-parse
// divergence (Go's encoding/json folds to U+FFFD, Ruby errors at parse-time,
// etc.) does not mask the canonical_json behaviour we are gating.
test "interop: canonical_json rejects malformed Unicode (D6)" {
    const allocator = std.testing.allocator;
    const bytes = try loadFixtureBytes(allocator);
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    const rvs = parsed.value.object.get("canonical_json_rejection_vectors").?.array;
    try std.testing.expect(rvs.items.len > 0);
    for (rvs.items) |rv| {
        const key = rv.object.get("input_object_key").?.string;
        const units = rv.object.get("input_value_utf16_units").?.array;
        // Encode each code unit as its (illegal-for-surrogates) 3-byte UTF-8
        // form so the canonical_json byte loop sees the lone surrogate
        // pattern verbatim.
        var bad_bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer bad_bytes.deinit(allocator);
        for (units.items) |u| {
            const cp: u32 = @intCast(u.integer);
            try bad_bytes.append(allocator, @intCast(0xe0 | (cp >> 12)));
            try bad_bytes.append(allocator, @intCast(0x80 | ((cp >> 6) & 0x3f)));
            try bad_bytes.append(allocator, @intCast(0x80 | (cp & 0x3f)));
        }
        const kvs = try allocator.alloc(envelope.Value.KeyValue, 1);
        kvs[0] = .{
            .key = try allocator.dupe(u8, key),
            .value = .{ .String = try allocator.dupe(u8, bad_bytes.items) },
        };
        const input_value: envelope.Value = .{ .Object = kvs };
        defer freeValue(allocator, input_value);
        if (envelope.canonicalJson(allocator, input_value)) |got| {
            defer allocator.free(got);
            std.debug.print("vector did NOT reject lone surrogate; got {s}\n", .{got});
            return error.TestExpectedError;
        } else |_| {
            // Any error is acceptable — the gate requires rejection.
        }
    }
}

// R-260. verifyEnvelope must bound payload nesting ITSELF rather than inherit
// whatever cap std.json happens to impose, because that cap differs per tier
// (ruby 100, rust 127, ts/go/python/zig none — THIS tier's scanner is
// iterative and took 100001 without complaint, java a StackOverflowError whose
// threshold is the JVM's -Xss flag). All seven tiers enforce
// MAX_ENVELOPE_PAYLOAD_DEPTH on the payload TEXT, so the same bytes get the
// same VerifyEnvelopeReason everywhere.
test "interop: shared payload depth bound" {
    const allocator = std.testing.allocator;
    const bytes = try loadFixtureBytes(allocator);
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();

    const limit = parsed.value.object.get("payload_depth_limit").?.integer;
    try std.testing.expectEqual(@as(i64, @intCast(envelope.MAX_ENVELOPE_PAYLOAD_DEPTH)), limit);

    const now_ms = parsed.value.object.get("verify_now_ms").?.integer;
    const dvs = parsed.value.object.get("depth_vectors").?.array;
    try std.testing.expect(dvs.items.len > 0);
    for (dvs.items) |dv| {
        const obj = dv.object;
        const vid = obj.get("_vector_id").?.string;
        const e = obj.get("envelope").?.object;
        const env = envelope.SignedEnvelope{
            .payload = e.get("payload").?.string,
            .sig = e.get("sig").?.string,
            .pubkey = e.get("pubkey").?.string,
            .nonce = e.get("nonce").?.integer,
            .expiresAt = e.get("expiresAt").?.integer,
        };
        var r = try envelope.verifyEnvelope(allocator, .{ .envelope = &env, .now_ms = now_ms });
        defer r.deinit();
        if (obj.get("expect_ok").?.bool) {
            if (!r.ok) {
                std.debug.print("{s}: expected ok=true, got reason={s}\n", .{ vid, if (r.reason) |x| x.wire() else "-" });
                return error.TestUnexpectedResult;
            }
            continue;
        }
        if (r.ok) {
            std.debug.print("{s}: expected ok=false\n", .{vid});
            return error.TestUnexpectedResult;
        }
        try std.testing.expectEqualStrings(obj.get("reason").?.string, r.reason.?.wire());
    }
}
