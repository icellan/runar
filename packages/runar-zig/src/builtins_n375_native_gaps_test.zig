//! N-375: native (off-chain) builtins the runar Zig package was missing, which
//! kept 17 examples/zig contracts compile-check only. Pins the in-process,
//! positive behaviour of: split, int2str, reverseBytes, p256Negate,
//! p256EncodeCompressed, p384Negate, p384EncodeCompressed, and the
//! mock knobs behind currentBlockHeight / extractPrevOutputScript /
//! requireOutputP2PKH.
//!
//! Proves: the answers match published or independently produced vectors (P-256
//! / P-384 generator, its negation and compressed encodings from Go's
//! crypto/elliptic; the OP_NUM2BIN sign-magnitude layout), and each knob
//! returns the previous value so a test can restore it.
//! Does not prove: the abort paths. A Zig @panic ends the process and cannot be
//! caught in-process, so they are exercised as abort probes by
//! examples/zig (assert_probe.zig) against the real example contracts.
const std = @import("std");
const root = @import("root.zig");

const g256 = root.hexToBytes("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
const neg_g256 = root.hexToBytes("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a");
const g256_compressed = root.hexToBytes("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
const neg_g256_compressed = root.hexToBytes("026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
const g384 = root.hexToBytes("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f");
const neg_g384 = root.hexToBytes("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7c9e821b569d9d390a26167406d6d23d6070be242d765eb831625ceec4a0f473ef59f4e30e2817e6285bce2846f15f1a0");
const g384_compressed = root.hexToBytes("03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7");
const neg_g384_compressed = root.hexToBytes("02aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7");

test "split returns the tail at the index, including the empty tail at len" {
    try std.testing.expectEqualStrings("cdef", root.split("abcdef", 2));
    try std.testing.expectEqualStrings("abcdef", root.split("abcdef", 0));
    try std.testing.expectEqualStrings("", root.split("abcdef", 6));
}

test "int2str is the fixed-width little-endian sign-magnitude encoding" {
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x01, 0x00, 0x00 }, root.int2str(258, 4));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x80 }, root.int2str(-1, 2));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00 }, root.int2str(0, 2));
    try std.testing.expectEqualSlices(u8, &[_]u8{}, root.int2str(0, 0));
}

test "reverseBytes reverses, and accepts exactly 520 bytes" {
    try std.testing.expectEqualStrings("cba", root.reverseBytes("abc"));
    try std.testing.expectEqualStrings("", root.reverseBytes(""));
    var buf: [520]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(i);
    const r = root.reverseBytes(&buf);
    try std.testing.expectEqual(@as(usize, 520), r.len);
    try std.testing.expectEqual(buf[0], r[519]);
    try std.testing.expectEqual(buf[519], r[0]);
}

test "p256Negate and p256EncodeCompressed match Go crypto/elliptic on G" {
    try std.testing.expectEqualSlices(u8, neg_g256, root.p256Negate(g256));
    try std.testing.expectEqualSlices(u8, g256, root.p256Negate(neg_g256));
    try std.testing.expectEqualSlices(u8, g256_compressed, root.p256EncodeCompressed(g256));
    try std.testing.expectEqualSlices(u8, neg_g256_compressed, root.p256EncodeCompressed(neg_g256));
}

test "p384Negate and p384EncodeCompressed match Go crypto/elliptic on G" {
    try std.testing.expectEqualSlices(u8, neg_g384, root.p384Negate(g384));
    try std.testing.expectEqualSlices(u8, g384, root.p384Negate(neg_g384));
    try std.testing.expectEqualSlices(u8, g384_compressed, root.p384EncodeCompressed(g384));
    try std.testing.expectEqualSlices(u8, neg_g384_compressed, root.p384EncodeCompressed(neg_g384));
}

test "p256Negate of a zero y coordinate stays zero (p - 0 reduced mod p)" {
    var pt = [_]u8{0} ** 64;
    pt[31] = 1;
    try std.testing.expectEqualSlices(u8, &pt, root.p256Negate(&pt));
}

test "setMockBlockHeight drives currentBlockHeight and returns the previous value" {
    try std.testing.expectEqual(@as(i64, 0), root.currentBlockHeight());
    const prev = root.setMockBlockHeight(812345);
    defer _ = root.setMockBlockHeight(prev);
    try std.testing.expectEqual(@as(i64, 0), prev);
    try std.testing.expectEqual(@as(i64, 812345), root.currentBlockHeight());
}

test "extractPrevOutputScript returns the witness bound to its input index when it hashes to the expected value" {
    const prev0 = root.setMockPrevOutputScript(0, "script-zero");
    defer _ = root.setMockPrevOutputScript(0, prev0);
    const prev1 = root.setMockPrevOutputScript(1, "script-one");
    defer _ = root.setMockPrevOutputScript(1, prev1);
    try std.testing.expectEqualStrings("script-zero", root.extractPrevOutputScript(0, root.hash256("script-zero")));
    try std.testing.expectEqualStrings("script-one", root.extractPrevOutputScript(1, root.hash256("script-one")));
    // Re-setting an index replaces it and hands back the old witness.
    try std.testing.expectEqualStrings("script-zero", root.setMockPrevOutputScript(0, "other"));
    try std.testing.expectEqualStrings("other", root.setMockPrevOutputScript(0, "script-zero"));
}

test "requireOutputP2PKH accepts the exact P2PKH output at index 0" {
    const pkh = root.hash160(root.ALICE.pubKey);
    const prev = root.setMockSerialisedOutputs(root.buildChangeOutput(pkh, 1234));
    defer _ = root.setMockSerialisedOutputs(prev);
    root.requireOutputP2PKH(0, pkh, 1234);
}
