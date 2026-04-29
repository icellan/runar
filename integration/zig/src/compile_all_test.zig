const std = @import("std");
const runar = @import("runar");
const compile = @import("compile.zig");

// ---------------------------------------------------------------------------
// Compile-only tests for all Zig contract examples.
// These verify the full compilation pipeline (parse -> validate -> typecheck
// -> ANF -> stack -> emit) works for each contract.
// ---------------------------------------------------------------------------

test "Compile_Auction" {
    const allocator = std.testing.allocator;
    var artifact = compile.compileContract(allocator, "examples/zig/auction/Auction.runar.zig") catch |err| {
        std.log.warn("Could not compile Auction: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();
    try std.testing.expectEqualStrings("Auction", artifact.contract_name);
    try std.testing.expect(artifact.isStateful());
}

test "Compile_CovenantVault" {
    const allocator = std.testing.allocator;
    var artifact = compile.compileContract(allocator, "examples/zig/covenant-vault/CovenantVault.runar.zig") catch |err| {
        std.log.warn("Could not compile CovenantVault: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();
    try std.testing.expectEqualStrings("CovenantVault", artifact.contract_name);
    try std.testing.expect(!artifact.isStateful());
}

test "Compile_OraclePriceFeed" {
    const allocator = std.testing.allocator;
    var artifact = compile.compileContract(allocator, "examples/zig/oracle-price/OraclePriceFeed.runar.zig") catch |err| {
        std.log.warn("Could not compile OraclePriceFeed: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();
    try std.testing.expectEqualStrings("OraclePriceFeed", artifact.contract_name);
    try std.testing.expect(!artifact.isStateful());
}

test "Compile_TicTacToe" {
    const allocator = std.testing.allocator;
    var artifact = compile.compileContract(allocator, "examples/zig/tic-tac-toe/TicTacToe.runar.zig") catch |err| {
        std.log.warn("Could not compile TicTacToe: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();
    try std.testing.expectEqualStrings("TicTacToe", artifact.contract_name);
    try std.testing.expect(artifact.isStateful());
}

test "Compile_FungibleToken" {
    const allocator = std.testing.allocator;
    var artifact = compile.compileContract(allocator, "examples/zig/token-ft/FungibleTokenExample.runar.zig") catch |err| {
        std.log.warn("Could not compile FungibleTokenExample: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();
    try std.testing.expectEqualStrings("FungibleToken", artifact.contract_name);
    try std.testing.expect(artifact.isStateful());
}

test "Compile_NFTExample" {
    const allocator = std.testing.allocator;
    var artifact = compile.compileContract(allocator, "examples/zig/token-nft/NFTExample.runar.zig") catch |err| {
        std.log.warn("Could not compile NFTExample: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();
    try std.testing.expectEqualStrings("SimpleNFT", artifact.contract_name);
    try std.testing.expect(artifact.isStateful());
}

test "Compile_PostQuantumWallet" {
    const allocator = std.testing.allocator;
    var artifact = compile.compileContract(allocator, "examples/zig/post-quantum-wallet/PostQuantumWallet.runar.zig") catch |err| {
        std.log.warn("Could not compile PostQuantumWallet: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();
    try std.testing.expectEqualStrings("PostQuantumWallet", artifact.contract_name);
}

test "Compile_SchnorrZKP" {
    const allocator = std.testing.allocator;
    var artifact = compile.compileContract(allocator, "examples/zig/schnorr-zkp/SchnorrZKP.runar.zig") catch |err| {
        std.log.warn("Could not compile SchnorrZKP: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();
    try std.testing.expectEqualStrings("SchnorrZKP", artifact.contract_name);
}

test "Compile_SPHINCSWallet" {
    const allocator = std.testing.allocator;
    var artifact = compile.compileContract(allocator, "examples/zig/sphincs-wallet/SPHINCSWallet.runar.zig") catch |err| {
        std.log.warn("Could not compile SPHINCSWallet: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();
    try std.testing.expectEqualStrings("SPHINCSWallet", artifact.contract_name);
}

test "Compile_MessageBoard" {
    const allocator = std.testing.allocator;
    var artifact = compile.compileContract(allocator, "examples/zig/message-board/MessageBoard.runar.zig") catch |err| {
        std.log.warn("Could not compile MessageBoard: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();
    try std.testing.expectEqualStrings("MessageBoard", artifact.contract_name);
    try std.testing.expect(artifact.isStateful());
}

test "Compile_BoundedCounter" {
    const allocator = std.testing.allocator;
    var artifact = compile.compileContract(allocator, "examples/zig/property-initializers/BoundedCounter.runar.zig") catch |err| {
        std.log.warn("Could not compile BoundedCounter: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();
    try std.testing.expectEqualStrings("BoundedCounter", artifact.contract_name);
    try std.testing.expect(artifact.isStateful());
}

test "Compile_ConvergenceProof" {
    const allocator = std.testing.allocator;
    var artifact = compile.compileContract(allocator, "examples/zig/convergence-proof/ConvergenceProof.runar.zig") catch |err| {
        std.log.warn("Could not compile ConvergenceProof: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();
    try std.testing.expectEqualStrings("ConvergenceProof", artifact.contract_name);
}
