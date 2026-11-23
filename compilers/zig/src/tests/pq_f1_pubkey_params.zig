//! PQ-F1: the artifact lists every constructor param passed directly as the
//! public key of verifyWOTS / verifySLHDSA_SHA2_*, with the exact byte length
//! that verifier needs, so every SDK can refuse a wrong-length key before
//! deploying (stateless artifacts carry no ANF to walk).
//!
//! Proves: the exact JSON text of `pqPubKeyParams` (key order included) for a
//! stateless WOTS contract, an SLH-DSA-192f contract, and a key behind a local
//! alias plus a key read in a private helper; absent for a key passed as a
//! method argument.
//! Does NOT prove: cross-tier equality (conformance/negatives/artifact-flag-parity.test.ts).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

fn expectPq(source: []const u8, expected: ?[]const u8) !void {
    const allocator = std.testing.allocator;
    const result = try compiler_api.compileSource(allocator, source, "C.runar.ts");
    allocator.free(result.script_hex);
    for (result.warnings) |line| allocator.free(line);
    allocator.free(result.warnings);
    const json = result.artifact_json.?;
    defer allocator.free(json);
    const key = "\"pqPubKeyParams\":";
    const at = std.mem.indexOf(u8, json, key);
    if (expected) |want| {
        const start = (at orelse {
            std.debug.print("artifact has no pqPubKeyParams; want {s}\n", .{want});
            return error.MissingPqPubKeyParams;
        }) + key.len;
        const end = start + (std.mem.indexOfScalar(u8, json[start..], ']') orelse return error.Malformed) + 1;
        try std.testing.expectEqualStrings(want, json[start..end]);
    } else {
        try std.testing.expect(at == null);
    }
}

test "PQ-F1: stateless verifyWOTS key" {
    try expectPq(
        \\import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
        \\class C extends SmartContract {
        \\  readonly pk: ByteString;
        \\  constructor(pk: ByteString) { super(pk); this.pk = pk; }
        \\  public spend(msg: ByteString, sig: ByteString) { assert(verifyWOTS(msg, sig, this.pk)); }
        \\}
    , "[{\"index\":0,\"name\":\"pk\",\"scheme\":\"verifyWOTS\",\"length\":64}]");
}

test "PQ-F1: SLH-DSA-192f key" {
    try expectPq(
        \\import { SmartContract, ByteString, assert, verifySLHDSA_SHA2_192f } from 'runar-lang';
        \\class C extends SmartContract {
        \\  readonly pk: ByteString;
        \\  constructor(pk: ByteString) { super(pk); this.pk = pk; }
        \\  public spend(msg: ByteString, sig: ByteString) { assert(verifySLHDSA_SHA2_192f(msg, sig, this.pk)); }
        \\}
    , "[{\"index\":0,\"name\":\"pk\",\"scheme\":\"verifySLHDSA_SHA2_192f\",\"length\":48}]");
}

test "PQ-F1: key behind a local alias and a key in a private helper" {
    try expectPq(
        \\import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
        \\class C extends SmartContract {
        \\  readonly tag: bigint;
        \\  readonly a: ByteString;
        \\  readonly b: ByteString;
        \\  constructor(tag: bigint, a: ByteString, b: ByteString) { super(tag, a, b); this.tag = tag; this.a = a; this.b = b; }
        \\  private checkB(msg: ByteString, sig: ByteString): boolean { return verifyWOTS(msg, sig, this.b); }
        \\  public spend(msg: ByteString, sig: ByteString, sig2: ByteString) {
        \\    assert(this.checkB(msg, sig2));
        \\    const k = this.a;
        \\    assert(verifyWOTS(msg, sig, k));
        \\    assert(this.tag > 0n);
        \\  }
        \\}
    , "[{\"index\":1,\"name\":\"a\",\"scheme\":\"verifyWOTS\",\"length\":64},{\"index\":2,\"name\":\"b\",\"scheme\":\"verifyWOTS\",\"length\":64}]");
}

test "PQ-F1: a key passed as a method argument is not listed" {
    try expectPq(
        \\import { SmartContract, ByteString, Sha256, assert, sha256, verifyWOTS } from 'runar-lang';
        \\class C extends SmartContract {
        \\  readonly h: Sha256;
        \\  constructor(h: Sha256) { super(h); this.h = h; }
        \\  public spend(msg: ByteString, sig: ByteString, pk: ByteString) { assert(sha256(pk) === this.h); assert(verifyWOTS(msg, sig, pk)); }
        \\}
    , null);
}
