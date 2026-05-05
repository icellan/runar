const std = @import("std");
const helpers = @import("helpers.zig");

// Import all test modules so the Zig test runner discovers their tests.
comptime {
    _ = @import("p2pkh_test.zig");
    _ = @import("counter_test.zig");
    _ = @import("escrow_test.zig");
    _ = @import("math_demo_test.zig");
    _ = @import("function_patterns_test.zig");
    _ = @import("compile_all_test.zig");
    _ = @import("compile.zig");
    _ = @import("auction_test.zig");
    _ = @import("convergence_proof_test.zig");
    _ = @import("covenant_vault_test.zig");
    _ = @import("ec_isolation_test.zig");
    _ = @import("token_ft_test.zig");
    _ = @import("token_nft_test.zig");
    _ = @import("oracle_price_test.zig");
    _ = @import("schnorr_zkp_test.zig");
    _ = @import("sphincs_wallet_test.zig");
    _ = @import("tic_tac_toe_test.zig");
    _ = @import("post_quantum_wallet_test.zig");
    _ = @import("babybear_test.zig");
    _ = @import("merkle_proof_test.zig");
    _ = @import("private_helper_outputs_test.zig");
    _ = @import("state_covenant_test.zig");
    _ = @import("data_outputs_test.zig");
    _ = @import("blake3_test.zig");
    _ = @import("sha256_compress_test.zig");
    _ = @import("sha256_finalize_test.zig");
    _ = @import("wots_test.zig");
    _ = @import("slhdsa_test.zig");
    _ = @import("bsv20_token_test.zig");
    _ = @import("bsv21_token_test.zig");
}

test "integration_setup" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    // Mine initial blocks so coinbase UTXOs mature (100 block maturity).
    const current_height = try helpers.getBlockCount(allocator);

    const target_height: i64 = 101;
    const blocks_needed = target_height - current_height;
    if (blocks_needed > 0) {
        std.log.info("Mining {d} blocks (current height: {d}, target: {d})...", .{ blocks_needed, current_height, target_height });
        try helpers.mine(allocator, blocks_needed);
    }

    std.log.info("Integration test setup complete. Block height >= {d}", .{target_height});
}
