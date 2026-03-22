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
};

pub const CryptoBuiltinGroup = enum {
    rabin,
    wots,
    slhdsa,
    blake3,
    ec,
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
        => 2,
        .ec_mul_gen => 1,
    };
}

pub fn statusOf(builtin: CryptoBuiltin) CryptoBuiltinStatus {
    return switch (builtin) {
        .verify_rabin_sig,
        .ec_negate,
        .ec_mod_reduce,
        .ec_encode_compressed,
        .ec_make_point,
        .ec_point_x,
        .ec_point_y,
        => .implemented,
        else => .scaffolded,
    };
}

test "crypto builtin classification covers exact names" {
    try std.testing.expectEqual(CryptoBuiltin.verify_rabin_sig, classify("verifyRabinSig").?);
    try std.testing.expectEqual(CryptoBuiltin.verify_wots, classify("verifyWOTS").?);
    try std.testing.expectEqual(CryptoBuiltin.verify_slhdsa_sha2_256f, classify("verifySLHDSA_SHA2_256f").?);
    try std.testing.expectEqual(CryptoBuiltin.blake3_hash, classify("blake3Hash").?);
    try std.testing.expectEqual(CryptoBuiltin.ec_encode_compressed, classify("ecEncodeCompressed").?);
    try std.testing.expectEqual(@as(?CryptoBuiltin, null), classify("schnorrVerify"));
}

test "crypto builtin metadata stays consistent" {
    try std.testing.expectEqualStrings("ecPointX", displayName(.ec_point_x));
    try std.testing.expectEqual(CryptoBuiltinGroup.ec, groupOf(.ec_mul_gen));
    try std.testing.expectEqualStrings("SHA2_128s", slhDsaParamKey(.verify_slhdsa_sha2_128s).?);
    try std.testing.expectEqual(@as(?[]const u8, null), slhDsaParamKey(.ec_on_curve));
    try std.testing.expectEqual(@as(usize, 4), requiredArgCount(.verify_rabin_sig));
    try std.testing.expectEqual(CryptoBuiltinStatus.implemented, statusOf(.ec_negate));
    try std.testing.expectEqual(CryptoBuiltinStatus.scaffolded, statusOf(.verify_wots));
}
