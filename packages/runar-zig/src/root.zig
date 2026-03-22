const std = @import("std");
const build_options = @import("build_options");

pub const base = @import("base.zig");
pub const builtins = @import("builtins.zig");
pub const compile_check = @import("compile_check.zig");
pub const hex = @import("hex.zig");
pub const test_keys = @import("test_keys.zig");
pub const testing = @import("testing_helpers.zig");

pub const Int = base.Int;
pub const Bigint = builtins.SignedBigint;
pub const PubKey = base.PubKey;
pub const Sig = base.Sig;
pub const Addr = base.Addr;
pub const ByteString = base.ByteString;
pub const Sha256 = base.Sha256;
pub const Ripemd160 = base.Ripemd160;
pub const SigHashPreimage = base.SigHashPreimage;
pub const RabinSig = base.RabinSig;
pub const RabinPubKey = base.RabinPubKey;
pub const Point = base.Point;
pub const OutputValue = base.OutputValue;
pub const OutputSnapshot = base.OutputSnapshot;
pub const Readonly = base.Readonly;
pub const SmartContract = base.SmartContract;
pub const StatefulSmartContract = base.StatefulSmartContract;
pub const StatefulContext = base.StatefulContext;
pub const StatefulSmartContractError = base.StatefulSmartContractError;
pub const serializeTestStateValues = base.serializeTestStateValues;
pub const wrapTestContinuationScript = base.wrapTestContinuationScript;

pub const TestKeyPair = test_keys.TestKeyPair;
pub const ALICE = test_keys.ALICE;
pub const BOB = test_keys.BOB;
pub const CHARLIE = test_keys.CHARLIE;

pub const MockPreimageParts = builtins.MockPreimageParts;
pub const assertFailureMessage = builtins.assert_failure_message;

pub const CompileCheckStage = compile_check.CompileCheckStage;
pub const CompileCheckResult = compile_check.CompileCheckResult;
pub const compileCheckSource = compile_check.compileCheckSource;
pub const compileCheckFile = compile_check.compileCheckFile;
pub const bigint = builtins.SignedBigint.from;

pub const assert = builtins.assert;
pub const sha256 = builtins.sha256;
pub const ripemd160 = builtins.ripemd160;
pub const hash160 = builtins.hash160;
pub const hash256 = builtins.hash256;
pub const bytesEq = builtins.bytesEq;
pub const checkSig = builtins.checkSig;
pub const checkMultiSig = builtins.checkMultiSig;
pub const checkPreimage = builtins.checkPreimage;
pub const signTestMessage = builtins.signTestMessage;
pub const mockPreimage = builtins.mockPreimage;
pub const extractHashPrevouts = builtins.extractHashPrevouts;
pub const extractOutpoint = builtins.extractOutpoint;
pub const extractOutputHash = builtins.extractOutputHash;
pub const extractLocktime = builtins.extractLocktime;
pub const buildChangeOutput = builtins.buildChangeOutput;
pub const cat = builtins.cat;
pub const substr = builtins.substr;
pub const num2bin = builtins.num2bin;
pub const bin2num = builtins.bin2num;
pub const clamp = builtins.clamp;
pub const safediv = builtins.safediv;
pub const safemod = builtins.safemod;
pub const sign = builtins.sign;
pub const pow = builtins.pow;
pub const mulDiv = builtins.mulDiv;
pub const percentOf = builtins.percentOf;
pub const sqrt = builtins.sqrt;
pub const gcd = builtins.gcd;
pub const log2 = builtins.log2;
pub const sha256Compress = builtins.sha256Compress;
pub const sha256Finalize = builtins.sha256Finalize;
pub const blake3Compress = builtins.blake3Compress;
pub const blake3Hash = builtins.blake3Hash;
pub const verifyRabinSig = builtins.verifyRabinSig;
pub const verifyWOTS = builtins.verifyWOTS;
pub const verifySLHDSA_SHA2_128s = builtins.verifySLHDSA_SHA2_128s;
pub const verifySLHDSA_SHA2_128f = builtins.verifySLHDSA_SHA2_128f;
pub const verifySLHDSA_SHA2_192s = builtins.verifySLHDSA_SHA2_192s;
pub const verifySLHDSA_SHA2_192f = builtins.verifySLHDSA_SHA2_192f;
pub const verifySLHDSA_SHA2_256s = builtins.verifySLHDSA_SHA2_256s;
pub const verifySLHDSA_SHA2_256f = builtins.verifySLHDSA_SHA2_256f;
pub const ecAdd = builtins.ecAdd;
pub const ecMul = builtins.ecMul;
pub const ecMulGen = builtins.ecMulGen;
pub const ecNegate = builtins.ecNegate;
pub const ecOnCurve = builtins.ecOnCurve;
pub const ecModReduce = builtins.ecModReduce;
pub const ecEncodeCompressed = builtins.ecEncodeCompressed;
pub const ecMakePoint = builtins.ecMakePoint;
pub const ecPointX = builtins.ecPointX;
pub const ecPointY = builtins.ecPointY;

test "root exports compile helpers and fixtures" {
    try std.testing.expect(ALICE.pubKey.len != 0);
    try std.testing.expect(@TypeOf(compileCheckSource) == @TypeOf(compile_check.compileCheckSource));
}

test {
    _ = @import("base.zig");
    _ = @import("builtins.zig");
    _ = @import("compile_check.zig");
    _ = @import("hex.zig");
    _ = @import("testing_helpers.zig");
    if (build_options.has_bsvz_runar_harness) {
        _ = @import("script_integration_test.zig");
    }
}
