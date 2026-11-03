const std = @import("std");
const runtime = @import("runar");

const assert_probe_path = "zig-out/bin/assert_probe";
const assert_panic_tag = "RUNAR_ASSERT_PANIC";

pub const runar = struct {
    pub fn compileCheckSource(
        allocator: std.mem.Allocator,
        source: []const u8,
        file_name: []const u8,
    ) !void {
        const result = try runtime.compileCheckSource(allocator, source, file_name);
        defer result.deinit(allocator);
        if (!result.ok()) {
            for (result.messages) |message| {
                std.debug.print("compile-check {s}: {s}\n", .{ file_name, message });
            }
            return error.CompileCheckFailed;
        }
    }

    pub fn compileCheckFile(
        allocator: std.mem.Allocator,
        file_path: []const u8,
    ) !void {
        const result = try runtime.compileCheckFile(allocator, file_path);
        defer result.deinit(allocator);
        if (!result.ok()) {
            for (result.messages) |message| {
                std.debug.print("compile-check {s}: {s}\n", .{ file_path, message });
            }
            return error.CompileCheckFailed;
        }
    }

    pub fn expectAssertFailure(
        allocator: std.mem.Allocator,
        probe_case: []const u8,
    ) !void {
        const result = try std.process.run(allocator, std.testing.io, .{
            .argv = &.{ assert_probe_path, probe_case },
            .stdout_limit = .limited(64 * 1024),
            .stderr_limit = .limited(64 * 1024),
        });
        defer {
            allocator.free(result.stdout);
            allocator.free(result.stderr);
        }

        switch (result.term) {
            .exited => |code| try std.testing.expect(code != 0),
            .signal => {},
            else => return error.TestUnexpectedResult,
        }

        const saw_assert_panic =
            std.mem.indexOf(u8, result.stdout, assert_panic_tag) != null or
            std.mem.indexOf(u8, result.stderr, assert_panic_tag) != null or
            std.mem.indexOf(u8, result.stdout, runtime.assertFailureMessage) != null or
            std.mem.indexOf(u8, result.stderr, runtime.assertFailureMessage) != null;
        if (!saw_assert_panic) {
            std.debug.print(
                "assert probe {s} exited without the Runar assertion marker\nstdout:\n{s}\nstderr:\n{s}\n",
                .{ probe_case, result.stdout, result.stderr },
            );
        }
        try std.testing.expect(saw_assert_panic);
    }
};

pub fn expectAssertFailure(probe_case: []const u8) !void {
    try runar.expectAssertFailure(std.testing.allocator, probe_case);
}

/// F-033: an on-chain `abort` vector must abort natively too. The probe prints
/// `F033_VECTOR_CALL` right before the contract call, so dying earlier (bad
/// index, JSON error) does not count; after that the process must die with a
/// Runar assertion (the script's OP_VERIFY guards) or a division by zero (the
/// script's OP_DIV by zero). Returning normally exits 0 and fails here.
pub fn expectVectorAbort(probe_case: []const u8) !void {
    const allocator = std.testing.allocator;
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ assert_probe_path, probe_case },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    const aborted = switch (result.term) {
        .exited => |code| code != 0,
        .signal => true,
        else => false,
    };
    const out = result.stderr;
    const reached = std.mem.indexOf(u8, out, "F033_VECTOR_CALL") != null;
    const expected_abort =
        std.mem.indexOf(u8, out, runtime.assertFailureMessage) != null or
        std.mem.indexOf(u8, out, "division by zero") != null;
    if (!(aborted and reached and expected_abort)) {
        std.debug.print(
            "vector probe {s}: aborted={} reached={} expected_abort={}\nstdout:\n{s}\nstderr:\n{s}\n",
            .{ probe_case, aborted, reached, expected_abort, result.stdout, result.stderr },
        );
        return error.TestUnexpectedResult;
    }
}

test {
    _ = @import("./auction/Auction_test.zig");
    _ = @import("./babybear/BabyBearDemo_test.zig");
    _ = @import("./blake3/Blake3Test_test.zig");
    _ = @import("./bsv20-token/BSV20Token_test.zig");
    _ = @import("./bsv21-token/BSV21Token_test.zig");
    _ = @import("./convergence-proof/ConvergenceProof_test.zig");
    _ = @import("./covenant-vault/CovenantVault_test.zig");
    _ = @import("./cross-covenant/CrossCovenantRef_test.zig");
    _ = @import("./ec-demo/ECDemo_test.zig");
    _ = @import("./escrow/Escrow_test.zig");
    _ = @import("./function-patterns/FunctionPatterns_test.zig");
    _ = @import("./math-demo/MathDemo_test.zig");
    _ = @import("./merkle-proof/MerkleProofDemo_test.zig");
    _ = @import("./message-board/MessageBoard_test.zig");
    _ = @import("./multisig-2of3/MultiSig2of3_test.zig");
    _ = @import("./oracle-price/OraclePriceFeed_test.zig");
    _ = @import("./ordinal-nft/OrdinalNFT_test.zig");
    _ = @import("./p2blake3pkh/P2Blake3PKH_test.zig");
    _ = @import("./p2pkh/P2PKH_test.zig");
    _ = @import("./post-quantum-wallet/PostQuantumWallet_test.zig");
    _ = @import("./property-initializers/BoundedCounter_test.zig");
    _ = @import("./schnorr-zkp/SchnorrZKP_test.zig");
    _ = @import("./sha256-compress/Sha256CompressTest_test.zig");
    _ = @import("./sha256-finalize/Sha256FinalizeTest_test.zig");
    _ = @import("./sphincs-wallet/SPHINCSWallet_test.zig");
    _ = @import("./state-covenant/StateCovenant_test.zig");
    _ = @import("./stateful-counter/Counter_test.zig");
    _ = @import("./tic-tac-toe/TicTacToe_test.zig");
    _ = @import("./token-ft/FungibleTokenExample_test.zig");
    _ = @import("./token-nft/NFTExample_test.zig");
    _ = @import("./add-raw-output/RawOutputTest_test.zig");
    _ = @import("./babybear-ext4/BabyBearExt4Demo_test.zig");
    _ = @import("./bitwise-ops/BitwiseOps_test.zig");
    _ = @import("./ec-unit/ECUnit_test.zig");
    _ = @import("./fixed-array-nested/Grid2x2_test.zig");
    _ = @import("./p256-wallet/P256Wallet_test.zig");
    _ = @import("./p384-wallet/P384Wallet_test.zig");
    _ = @import("./add-data-output/DataOutputTest_test.zig");
    _ = @import("./private-helper-outputs/PrivateHelperOutputs_test.zig");
    _ = @import("./arithmetic/Arithmetic_test.zig");
    _ = @import("./boolean-logic/BooleanLogic_test.zig");
    _ = @import("./bounded-loop/BoundedLoop_test.zig");
    _ = @import("./ec-primitives/ECPrimitives_test.zig");
    _ = @import("./if-else/IfElse_test.zig");
    _ = @import("./if-without-else/IfWithoutElse_test.zig");
    _ = @import("./if-without-else-multi-temp/StackTrackerReproV10min_test.zig");
    _ = @import("./multi-method/MultiMethod_test.zig");
    _ = @import("./p256-primitives/P256Primitives_test.zig");
    _ = @import("./p384-primitives/P384Primitives_test.zig");
    _ = @import("./shift-ops/ShiftOps_test.zig");
    _ = @import("./state-ripemd160/HashRegistry_test.zig");
    _ = @import("./stateful/Stateful_test.zig");
    _ = @import("./post-quantum-wots-naive-INSECURE/PostQuantumWOTSNaiveInsecure_test.zig");
    _ = @import("./post-quantum-slhdsa-naive-INSECURE/PostQuantumSLHDSANaiveInsecure_test.zig");
    _ = @import("./compiler-directives/Directives_test.zig");
    _ = @import("./compiler-directives/EmbedTags_test.zig");
    _ = @import("./all-readonly-cleanstack/AllReadonlyCleanstack_test.zig");
    _ = @import("./annotated-vault/AnnotatedVault_test.zig");
    _ = @import("./asm-raw-script/Anyone_test.zig");
    _ = @import("./branch-merged-locals/BranchMergedLocals_test.zig");
    _ = @import("./branched-readonly-len/BranchedReadonlyLen_test.zig");
    _ = @import("./byte-builtins/ByteBuiltins_test.zig");
    _ = @import("./cond-write-multi-field/CondWriteMultiField_test.zig");
    _ = @import("./conditional-data-output/ConditionalDataOutput_test.zig");
    _ = @import("./countdown-loop/CountdownLoop_test.zig");
    _ = @import("./fixed-array-index/ArrayIndex_test.zig");
    _ = @import("./fixed-array-write/ArrayWrite_test.zig");
    _ = @import("./go-dsl-bytestring-literal/GoDslBytestringLiteral_test.zig");
    _ = @import("./integer-boundary/IntegerBoundary_test.zig");
    _ = @import("./intent-current-block-height/IntentCurrentBlockHeight_test.zig");
    _ = @import("./intent-output-p2pkh/IntentOutputP2PKH_test.zig");
    _ = @import("./intent-prev-output-script/IntentPrevOutputScript_test.zig");
    _ = @import("./loop-shapes/LoopShapes_test.zig");
    _ = @import("./p256-encode-negate/P256EncodeNegate_test.zig");
    _ = @import("./p384-encode-negate/P384EncodeNegate_test.zig");
    _ = @import("./param-shadow-branch-arm/ParamShadowBranchArm_test.zig");
    _ = @import("./post-quantum-slhdsa-naive-INSECURE-128f/PostQuantumSLHDSANaiveInsecure128f_test.zig");
    _ = @import("./post-quantum-slhdsa-naive-INSECURE-192f/PostQuantumSLHDSANaiveInsecure192f_test.zig");
    _ = @import("./post-quantum-slhdsa-naive-INSECURE-192s/PostQuantumSLHDSANaiveInsecure192s_test.zig");
    _ = @import("./post-quantum-slhdsa-naive-INSECURE-256f/PostQuantumSLHDSANaiveInsecure256f_test.zig");
    _ = @import("./post-quantum-slhdsa-naive-INSECURE-256s/PostQuantumSLHDSANaiveInsecure256s_test.zig");
    _ = @import("./property-shadow/PropertyShadow_test.zig");
    _ = @import("./r1-k1-wallet/R1K1Wallet_test.zig");
    _ = @import("./selector/Selector_test.zig");
    _ = @import("./sighash-single-stateful/SingleCounter_test.zig");
    _ = @import("./state-covenant-mechanics/StateCovenantMechanics_test.zig");
    _ = @import("./stateful-wots-gate/StatefulWOTSGate_test.zig");
    _ = @import("./terminal-varlen-read/TerminalVarlenRead_test.zig");
    _ = @import("./token-wallet-naive-INSECURE/WalletToken_test.zig");
}

// F-294: the `test {}` block above is a hand-maintained import list, so a new
// `<dir>/<Name>_test.zig` that nobody added to it registers nothing and the
// build still reports success. This walks every example directory and fails
// naming each `*_test.zig` whose `@import` line is missing from this file.
// Proves: no on-disk test file under examples/zig is unregistered.
// Does not prove: that every `.runar.zig` contract HAS a test file (some
// directories have none) or that a registered file contains any `test` blocks.
test "every example *_test.zig is imported by the test root" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const root_source = @embedFile("examples_test.zig");

    var missing: usize = 0;
    var root = try std.Io.Dir.cwd().openDir(io, ".", .{ .iterate = true });
    defer root.close(io);
    var dirs = root.iterate();
    while (try dirs.next(io)) |d| {
        if (d.kind != .directory) continue;
        if (std.mem.eql(u8, d.name, "zig-out") or std.mem.eql(u8, d.name, "zig-pkg") or
            std.mem.startsWith(u8, d.name, ".")) continue;
        var sub = try root.openDir(io, d.name, .{ .iterate = true });
        defer sub.close(io);
        var files = sub.iterate();
        while (try files.next(io)) |f| {
            if (f.kind != .file or !std.mem.endsWith(u8, f.name, "_test.zig")) continue;
            const needle = try std.fmt.allocPrint(allocator, "@import(\"./{s}/{s}\")", .{ d.name, f.name });
            defer allocator.free(needle);
            if (std.mem.indexOf(u8, root_source, needle) == null) {
                std.debug.print("F-294: {s}/{s} is not imported by examples_test.zig\n", .{ d.name, f.name });
                missing += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 0), missing);
}
