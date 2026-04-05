const std = @import("std");

pub const CryptoBuiltin = enum {
    verify_rabin_sig,
    verify_wots,
    verify_slhdsa_sha2_128s,
    verify_slhdsa_sha2_128f,
    verify_slhdsa_sha2_192s,
    verify_slhdsa_sha2_192f,
    verify_slhdsa_sha2_256s,
    verify_slhdsa_sha2_256f,
    blake3_compress,
    blake3_hash,
    blake3,
    ec_add,
    ec_mul,
    ec_mul_gen,
    ec_negate,
    ec_on_curve,
    ec_mod_reduce,
    ec_encode_compressed,
    ec_make_point,
    ec_point_x,
    ec_point_y,
    bb_field_add,
    bb_field_sub,
    bb_field_mul,
    bb_field_inv,
    merkle_root_sha256,
    merkle_root_hash256,
};

pub const CryptoBuiltinGroup = enum {
    rabin,
    wots,
    slhdsa,
    blake3,
    ec,
    babybear,
    merkle,
};

pub const CryptoBuiltinStatus = enum {
    implemented,
    scaffolded,
};

const builtin_map = std.StaticStringMap(CryptoBuiltin).initComptime(.{
    .{ "verifyRabinSig", .verify_rabin_sig },
    .{ "verifyWOTS", .verify_wots },
    .{ "verifySLHDSA_SHA2_128s", .verify_slhdsa_sha2_128s },
    .{ "verifySLHDSA_SHA2_128f", .verify_slhdsa_sha2_128f },
    .{ "verifySLHDSA_SHA2_192s", .verify_slhdsa_sha2_192s },
    .{ "verifySLHDSA_SHA2_192f", .verify_slhdsa_sha2_192f },
    .{ "verifySLHDSA_SHA2_256s", .verify_slhdsa_sha2_256s },
    .{ "verifySLHDSA_SHA2_256f", .verify_slhdsa_sha2_256f },
    .{ "blake3Compress", .blake3_compress },
    .{ "blake3Hash", .blake3_hash },
    .{ "blake3", .blake3 },
    .{ "ecAdd", .ec_add },
    .{ "ecMul", .ec_mul },
    .{ "ecMulGen", .ec_mul_gen },
    .{ "ecNegate", .ec_negate },
    .{ "ecOnCurve", .ec_on_curve },
    .{ "ecModReduce", .ec_mod_reduce },
    .{ "ecEncodeCompressed", .ec_encode_compressed },
    .{ "ecMakePoint", .ec_make_point },
    .{ "ecPointX", .ec_point_x },
    .{ "ecPointY", .ec_point_y },
    .{ "bbFieldAdd", .bb_field_add },
    .{ "bbFieldSub", .bb_field_sub },
    .{ "bbFieldMul", .bb_field_mul },
    .{ "bbFieldInv", .bb_field_inv },
    .{ "merkleRootSha256", .merkle_root_sha256 },
    .{ "merkleRootHash256", .merkle_root_hash256 },
});

pub fn classify(name: []const u8) ?CryptoBuiltin {
    return builtin_map.get(name);
}

pub fn displayName(builtin: CryptoBuiltin) []const u8 {
    return switch (builtin) {
        .verify_rabin_sig => "verifyRabinSig",
        .verify_wots => "verifyWOTS",
        .verify_slhdsa_sha2_128s => "verifySLHDSA_SHA2_128s",
        .verify_slhdsa_sha2_128f => "verifySLHDSA_SHA2_128f",
        .verify_slhdsa_sha2_192s => "verifySLHDSA_SHA2_192s",
        .verify_slhdsa_sha2_192f => "verifySLHDSA_SHA2_192f",
        .verify_slhdsa_sha2_256s => "verifySLHDSA_SHA2_256s",
        .verify_slhdsa_sha2_256f => "verifySLHDSA_SHA2_256f",
        .blake3_compress => "blake3Compress",
        .blake3_hash => "blake3Hash",
        .blake3 => "blake3",
        .ec_add => "ecAdd",
        .ec_mul => "ecMul",
        .ec_mul_gen => "ecMulGen",
        .ec_negate => "ecNegate",
        .ec_on_curve => "ecOnCurve",
        .ec_mod_reduce => "ecModReduce",
        .ec_encode_compressed => "ecEncodeCompressed",
        .ec_make_point => "ecMakePoint",
        .ec_point_x => "ecPointX",
        .ec_point_y => "ecPointY",
        .bb_field_add => "bbFieldAdd",
        .bb_field_sub => "bbFieldSub",
        .bb_field_mul => "bbFieldMul",
        .bb_field_inv => "bbFieldInv",
        .merkle_root_sha256 => "merkleRootSha256",
        .merkle_root_hash256 => "merkleRootHash256",
    };
}

pub fn groupOf(builtin: CryptoBuiltin) CryptoBuiltinGroup {
    return switch (builtin) {
        .verify_rabin_sig => .rabin,
        .verify_wots => .wots,
        .verify_slhdsa_sha2_128s,
        .verify_slhdsa_sha2_128f,
        .verify_slhdsa_sha2_192s,
        .verify_slhdsa_sha2_192f,
        .verify_slhdsa_sha2_256s,
        .verify_slhdsa_sha2_256f,
        => .slhdsa,
        .blake3_compress,
        .blake3_hash,
        .blake3,
        => .blake3,
        .ec_add,
        .ec_mul,
        .ec_mul_gen,
        .ec_negate,
        .ec_on_curve,
        .ec_mod_reduce,
        .ec_encode_compressed,
        .ec_make_point,
        .ec_point_x,
        .ec_point_y,
        => .ec,
        .bb_field_add,
        .bb_field_sub,
        .bb_field_mul,
        .bb_field_inv,
        => .babybear,
        .merkle_root_sha256,
        .merkle_root_hash256,
        => .merkle,
    };
}

pub fn slhDsaParamKey(builtin: CryptoBuiltin) ?[]const u8 {
    return switch (builtin) {
        .verify_slhdsa_sha2_128s => "SHA2_128s",
        .verify_slhdsa_sha2_128f => "SHA2_128f",
        .verify_slhdsa_sha2_192s => "SHA2_192s",
        .verify_slhdsa_sha2_192f => "SHA2_192f",
        .verify_slhdsa_sha2_256s => "SHA2_256s",
        .verify_slhdsa_sha2_256f => "SHA2_256f",
        else => null,
    };
}

pub fn requiredArgCount(builtin: CryptoBuiltin) usize {
    return switch (builtin) {
        .verify_rabin_sig => 4,
        .verify_wots => 3,
        .verify_slhdsa_sha2_128s,
        .verify_slhdsa_sha2_128f,
        .verify_slhdsa_sha2_192s,
        .verify_slhdsa_sha2_192f,
        .verify_slhdsa_sha2_256s,
        .verify_slhdsa_sha2_256f,
        => 3,
        .blake3_compress => 2,
        .blake3_hash,
        .blake3,
        .ec_negate,
        .ec_on_curve,
        .ec_encode_compressed,
        .ec_point_x,
        .ec_point_y,
        => 1,
        .ec_add,
        .ec_mul,
        .ec_mod_reduce,
        .ec_make_point,
        .bb_field_add,
        .bb_field_sub,
        .bb_field_mul,
        => 2,
        .ec_mul_gen,
        .bb_field_inv,
        => 1,
        .merkle_root_sha256,
        .merkle_root_hash256,
        => 4,
    };
}

pub fn statusOf(builtin: CryptoBuiltin) CryptoBuiltinStatus {
    _ = builtin;
    // All crypto builtins are implemented: basic EC helpers and Rabin via
    // crypto_emitters, full EC via ec_emitters, BLAKE3 via blake3_emitters,
    // WOTS and SLH-DSA via pq_emitters, Baby Bear via babybear_emitters,
    // Merkle via merkle_emitters.
    return .implemented;
}

test "crypto builtin classification covers exact names" {
    try std.testing.expectEqual(CryptoBuiltin.verify_rabin_sig, classify("verifyRabinSig").?);
    try std.testing.expectEqual(CryptoBuiltin.verify_wots, classify("verifyWOTS").?);
    try std.testing.expectEqual(CryptoBuiltin.verify_slhdsa_sha2_256f, classify("verifySLHDSA_SHA2_256f").?);
    try std.testing.expectEqual(CryptoBuiltin.blake3_hash, classify("blake3Hash").?);
    try std.testing.expectEqual(CryptoBuiltin.ec_encode_compressed, classify("ecEncodeCompressed").?);
    try std.testing.expectEqual(CryptoBuiltin.bb_field_add, classify("bbFieldAdd").?);
    try std.testing.expectEqual(CryptoBuiltin.bb_field_inv, classify("bbFieldInv").?);
    try std.testing.expectEqual(CryptoBuiltin.merkle_root_sha256, classify("merkleRootSha256").?);
    try std.testing.expectEqual(CryptoBuiltin.merkle_root_hash256, classify("merkleRootHash256").?);
    try std.testing.expectEqual(@as(?CryptoBuiltin, null), classify("schnorrVerify"));
}

test "crypto builtin metadata stays consistent" {
    try std.testing.expectEqualStrings("ecPointX", displayName(.ec_point_x));
    try std.testing.expectEqual(CryptoBuiltinGroup.ec, groupOf(.ec_mul_gen));
    try std.testing.expectEqualStrings("SHA2_128s", slhDsaParamKey(.verify_slhdsa_sha2_128s).?);
    try std.testing.expectEqual(@as(?[]const u8, null), slhDsaParamKey(.ec_on_curve));
    try std.testing.expectEqual(@as(usize, 4), requiredArgCount(.verify_rabin_sig));
    try std.testing.expectEqual(CryptoBuiltinStatus.implemented, statusOf(.ec_negate));
    try std.testing.expectEqual(CryptoBuiltinStatus.implemented, statusOf(.verify_wots));
    try std.testing.expectEqual(CryptoBuiltinStatus.implemented, statusOf(.ec_add));
    try std.testing.expectEqual(CryptoBuiltinStatus.implemented, statusOf(.blake3));
    try std.testing.expectEqual(CryptoBuiltinStatus.implemented, statusOf(.verify_slhdsa_sha2_256f));
    try std.testing.expectEqual(CryptoBuiltinStatus.implemented, statusOf(.bb_field_add));
    try std.testing.expectEqual(CryptoBuiltinStatus.implemented, statusOf(.merkle_root_sha256));
    try std.testing.expectEqual(CryptoBuiltinGroup.babybear, groupOf(.bb_field_mul));
    try std.testing.expectEqual(CryptoBuiltinGroup.merkle, groupOf(.merkle_root_hash256));
    try std.testing.expectEqualStrings("bbFieldAdd", displayName(.bb_field_add));
    try std.testing.expectEqualStrings("merkleRootSha256", displayName(.merkle_root_sha256));
    try std.testing.expectEqual(@as(usize, 2), requiredArgCount(.bb_field_add));
    try std.testing.expectEqual(@as(usize, 1), requiredArgCount(.bb_field_inv));
    try std.testing.expectEqual(@as(usize, 4), requiredArgCount(.merkle_root_sha256));
}
