const std = @import("std");
const runar = @import("runar");

const Auction = @import("auction/Auction.runar.zig").Auction;
const Blake3Test = @import("blake3/Blake3Test.runar.zig").Blake3Test;
const ConvergenceProof = @import("convergence-proof/ConvergenceProof.runar.zig").ConvergenceProof;
const CovenantVault = @import("covenant-vault/CovenantVault.runar.zig").CovenantVault;
const ECDemo = @import("ec-demo/ECDemo.runar.zig").ECDemo;
const FunctionPatterns = @import("function-patterns/FunctionPatterns.runar.zig").FunctionPatterns;
const MathDemo = @import("math-demo/MathDemo.runar.zig").MathDemo;
const OraclePriceFeed = @import("oracle-price/OraclePriceFeed.runar.zig").OraclePriceFeed;
const P2Blake3PKH = @import("p2blake3pkh/P2Blake3PKH.runar.zig").P2Blake3PKH;
const P2PKH = @import("p2pkh/P2PKH.runar.zig").P2PKH;
const PostQuantumWallet = @import("post-quantum-wallet/PostQuantumWallet.runar.zig").PostQuantumWallet;
const BoundedCounter = @import("property-initializers/BoundedCounter.runar.zig").BoundedCounter;
const SchnorrZKP = @import("schnorr-zkp/SchnorrZKP.runar.zig").SchnorrZKP;
const Sha256CompressTest = @import("sha256-compress/Sha256CompressTest.runar.zig").Sha256CompressTest;
const Sha256FinalizeTest = @import("sha256-finalize/Sha256FinalizeTest.runar.zig").Sha256FinalizeTest;
const sphincs_fixtures = @import("sphincs-wallet/fixtures.zig");
const SPHINCSWallet = @import("sphincs-wallet/SPHINCSWallet.runar.zig").SPHINCSWallet;
const Counter = @import("stateful-counter/Counter.runar.zig").Counter;
const TicTacToe = @import("tic-tac-toe/TicTacToe.runar.zig").TicTacToe;
const FungibleTokenExample = @import("token-ft/FungibleTokenExample.runar.zig").FungibleTokenExample;
const NFTExample = @import("token-nft/NFTExample.runar.zig").NFTExample;

pub const assert_panic_tag = "RUNAR_ASSERT_PANIC";

pub fn panic(msg: []const u8, st: ?*std.builtin.StackTrace, addr: ?usize) noreturn {
    _ = st;
    if (std.mem.eql(u8, msg, runar.assertFailureMessage)) {
        var buf: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "{s}:{s}\n", .{ assert_panic_tag, msg }) catch assert_panic_tag ++ "\n";
        std.fs.File.stderr().writeAll(line) catch {};
    }
    std.debug.defaultPanic(msg, addr);
}

pub fn main() !void {
    var args = try std.process.argsWithAllocator(std.heap.page_allocator);
    defer args.deinit();
    _ = args.next();
    const probe_case = args.next() orelse return error.MissingProbeCase;
    try runCase(probe_case);
}

fn runCase(probe_case: []const u8) !void {
    if (std.mem.eql(u8, probe_case, "p2pkh-wrong-pubkey")) return probeP2PKHWrongPubkey();
    if (std.mem.eql(u8, probe_case, "p2pkh-wrong-sig")) return probeP2PKHWrongSig();
    if (std.mem.eql(u8, probe_case, "p2blake3pkh-wrong-pubkey")) return probeP2Blake3PKHWrongPubkey();
    if (std.mem.eql(u8, probe_case, "p2blake3pkh-wrong-sig")) return probeP2Blake3PKHWrongSig();
    if (std.mem.eql(u8, probe_case, "blake3-hash-mismatch")) return probeBlake3HashMismatch();
    if (std.mem.eql(u8, probe_case, "blake3-compress-mismatch")) return probeBlake3CompressMismatch();
    if (std.mem.eql(u8, probe_case, "sha256-compress-mismatch")) return probeSha256CompressMismatch();
    if (std.mem.eql(u8, probe_case, "sha256-finalize-mismatch")) return probeSha256FinalizeMismatch();
    if (std.mem.eql(u8, probe_case, "function-patterns-wrong-owner")) return probeFunctionPatternsWrongOwner();
    if (std.mem.eql(u8, probe_case, "function-patterns-overdraw")) return probeFunctionPatternsOverdraw();
    if (std.mem.eql(u8, probe_case, "math-demo-overdraw")) return probeMathDemoOverdraw();
    if (std.mem.eql(u8, probe_case, "bounded-counter-overflow")) return probeBoundedCounterOverflow();
    if (std.mem.eql(u8, probe_case, "bounded-counter-inactive")) return probeBoundedCounterInactive();
    if (std.mem.eql(u8, probe_case, "counter-underflow")) return probeCounterUnderflow();
    if (std.mem.eql(u8, probe_case, "auction-bid-too-low")) return probeAuctionBidTooLow();
    if (std.mem.eql(u8, probe_case, "auction-bid-too-late")) return probeAuctionBidTooLate();
    if (std.mem.eql(u8, probe_case, "auction-close-too-early")) return probeAuctionCloseTooEarly();
    if (std.mem.eql(u8, probe_case, "auction-close-wrong-sig")) return probeAuctionCloseWrongSig();
    if (std.mem.eql(u8, probe_case, "covenant-vault-wrong-output")) return probeCovenantVaultWrongOutput();
    if (std.mem.eql(u8, probe_case, "covenant-vault-wrong-sig")) return probeCovenantVaultWrongSig();
    if (std.mem.eql(u8, probe_case, "oracle-price-wrong-rabin-proof")) return probeOraclePriceWrongRabinProof();
    if (std.mem.eql(u8, probe_case, "oracle-price-below-threshold")) return probeOraclePriceBelowThreshold();
    if (std.mem.eql(u8, probe_case, "oracle-price-wrong-receiver-sig")) return probeOraclePriceWrongReceiverSig();
    if (std.mem.eql(u8, probe_case, "tictactoe-join-twice")) return probeTicTacToeJoinTwice();
    if (std.mem.eql(u8, probe_case, "tictactoe-move-wrong-player")) return probeTicTacToeMoveWrongPlayer();
    if (std.mem.eql(u8, probe_case, "tictactoe-move-occupied-cell")) return probeTicTacToeMoveOccupiedCell();
    if (std.mem.eql(u8, probe_case, "tictactoe-cancel-before-join-wrong-sig")) return probeTicTacToeCancelBeforeJoinWrongSig();
    if (std.mem.eql(u8, probe_case, "tictactoe-cancel-before-join-wrong-output")) return probeTicTacToeCancelBeforeJoinWrongOutput();
    if (std.mem.eql(u8, probe_case, "tictactoe-cancel-wrong-sig-x")) return probeTicTacToeCancelWrongSigX();
    if (std.mem.eql(u8, probe_case, "tictactoe-cancel-wrong-sig-o")) return probeTicTacToeCancelWrongSigO();
    if (std.mem.eql(u8, probe_case, "tictactoe-cancel-wrong-output")) return probeTicTacToeCancelWrongOutput();
    if (std.mem.eql(u8, probe_case, "tictactoe-move-and-win-wrong-sig")) return probeTicTacToeMoveAndWinWrongSig();
    if (std.mem.eql(u8, probe_case, "tictactoe-move-and-win-wrong-output")) return probeTicTacToeMoveAndWinWrongOutput();
    if (std.mem.eql(u8, probe_case, "tictactoe-move-and-tie-wrong-sig")) return probeTicTacToeMoveAndTieWrongSig();
    if (std.mem.eql(u8, probe_case, "tictactoe-move-and-tie-wrong-output")) return probeTicTacToeMoveAndTieWrongOutput();
    if (std.mem.eql(u8, probe_case, "token-ft-transfer-too-much")) return probeTokenFTTransferTooMuch();
    if (std.mem.eql(u8, probe_case, "token-ft-transfer-wrong-sig")) return probeTokenFTTransferWrongSig();
    if (std.mem.eql(u8, probe_case, "token-ft-merge-prevouts-mismatch")) return probeTokenFTMergePrevoutsMismatch();
    if (std.mem.eql(u8, probe_case, "token-nft-transfer-wrong-sig")) return probeTokenNFTTransferWrongSig();
    if (std.mem.eql(u8, probe_case, "token-nft-transfer-invalid-satoshis")) return probeTokenNFTTransferInvalidSatoshis();
    if (std.mem.eql(u8, probe_case, "token-nft-burn-wrong-sig")) return probeTokenNFTBurnWrongSig();
    if (std.mem.eql(u8, probe_case, "ec-demo-wrong-x")) return probeECDemoWrongX();
    if (std.mem.eql(u8, probe_case, "ec-demo-wrong-encoding")) return probeECDemoWrongEncoding();
    if (std.mem.eql(u8, probe_case, "convergence-proof-invalid-point")) return probeConvergenceProofInvalidPoint();
    if (std.mem.eql(u8, probe_case, "convergence-proof-wrong-delta")) return probeConvergenceProofWrongDelta();
    if (std.mem.eql(u8, probe_case, "post-quantum-wallet-wrong-ecdsa-pubkey")) return probePostQuantumWalletWrongECDSAPubkey();
    if (std.mem.eql(u8, probe_case, "post-quantum-wallet-wrong-ecdsa-sig")) return probePostQuantumWalletWrongECDSASig();
    if (std.mem.eql(u8, probe_case, "post-quantum-wallet-wrong-wots-key")) return probePostQuantumWalletWrongWOTSKey();
    if (std.mem.eql(u8, probe_case, "post-quantum-wallet-invalid-wots-proof")) return probePostQuantumWalletInvalidWOTSProof();
    if (std.mem.eql(u8, probe_case, "sphincs-wallet-wrong-ecdsa-pubkey")) return probeSPHINCSWalletWrongECDSAPubkey();
    if (std.mem.eql(u8, probe_case, "sphincs-wallet-wrong-ecdsa-sig")) return probeSPHINCSWalletWrongECDSASig();
    if (std.mem.eql(u8, probe_case, "sphincs-wallet-wrong-slhdsa-key")) return probeSPHINCSWalletWrongSLHDSAKey();
    if (std.mem.eql(u8, probe_case, "sphincs-wallet-invalid-slhdsa-proof")) return probeSPHINCSWalletInvalidSLHDSAProof();
    if (std.mem.eql(u8, probe_case, "schnorr-zkp-invalid-r-point")) return probeSchnorrZKPInvalidRPoint();
    return error.UnknownProbeCase;
}

fn payoutOutput(amount: i64, pub_key: []const u8) []const u8 {
    return runar.buildChangeOutput(runar.hash160(pub_key), amount);
}

fn buildVaultOutput(recipient: []const u8, min_amount: i64) []const u8 {
    return runar.buildChangeOutput(recipient, min_amount);
}

fn findRabinPadding(message: []const u8, modulus: []const u8) ![]const u8 {
    var pad_value: u16 = 0;
    while (pad_value <= std.math.maxInt(u8)) : (pad_value += 1) {
        const candidate = [_]u8{ @truncate(pad_value) };
        if (runar.verifyRabinSig(message, &[_]u8{0x00}, &candidate, modulus)) {
            return std.heap.page_allocator.dupe(u8, &candidate);
        }
    }
    return error.PaddingNotFound;
}

fn probeP2PKHWrongPubkey() !void {
    const contract = P2PKH.init(runar.hash160(runar.ALICE.pubKey));
    contract.unlock(runar.signTestMessage(runar.ALICE), runar.BOB.pubKey);
}

fn probeP2PKHWrongSig() !void {
    const contract = P2PKH.init(runar.hash160(runar.ALICE.pubKey));
    contract.unlock(runar.signTestMessage(runar.BOB), runar.ALICE.pubKey);
}

fn probeP2Blake3PKHWrongPubkey() !void {
    const contract = P2Blake3PKH.init(runar.blake3Hash(runar.ALICE.pubKey));
    contract.unlock(runar.signTestMessage(runar.ALICE), runar.BOB.pubKey);
}

fn probeP2Blake3PKHWrongSig() !void {
    const contract = P2Blake3PKH.init(runar.blake3Hash(runar.ALICE.pubKey));
    contract.unlock(runar.signTestMessage(runar.BOB), runar.ALICE.pubKey);
}

fn probeBlake3HashMismatch() !void {
    const contract = Blake3Test.init(runar.blake3Hash("abc"));
    contract.verifyHash("abd");
}

fn probeBlake3CompressMismatch() !void {
    const state = runar.sha256("state");
    const block = [_]u8{'a'} ** 64;
    const wrong_block = [_]u8{'b'} ** 64;
    const contract = Blake3Test.init(runar.blake3Compress(state, &block));
    contract.verifyCompress(state, &wrong_block);
}

fn probeSha256CompressMismatch() !void {
    const state = runar.sha256("state");
    const block = [_]u8{'a'} ** 64;
    const wrong_block = [_]u8{'b'} ** 64;
    const contract = Sha256CompressTest.init(runar.sha256Compress(state, &block));
    contract.verify(state, &wrong_block);
}

fn probeSha256FinalizeMismatch() !void {
    const state = runar.sha256("state");
    const contract = Sha256FinalizeTest.init(runar.sha256Finalize(state, "abc", 24));
    contract.verify(state, "abd", 24);
}

fn probeFunctionPatternsWrongOwner() !void {
    var contract = FunctionPatterns.init(runar.ALICE.pubKey, 1000);
    contract.deposit(runar.signTestMessage(runar.BOB), 250);
}

fn probeFunctionPatternsOverdraw() !void {
    var contract = FunctionPatterns.init(runar.ALICE.pubKey, 1000);
    contract.withdraw(runar.signTestMessage(runar.ALICE), 980, 500);
}

fn probeMathDemoOverdraw() !void {
    var demo = MathDemo.init(1000);
    demo.withdrawWithFee(980, 500);
}

fn probeBoundedCounterOverflow() !void {
    var counter = BoundedCounter.init(10);
    counter.increment(11);
}

fn probeBoundedCounterInactive() !void {
    var counter = BoundedCounter{ .count = 0, .maxCount = 10, .active = false };
    counter.increment(1);
}

fn probeCounterUnderflow() !void {
    var counter = Counter.init(0);
    counter.decrement();
}

fn probeAuctionBidTooLow() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    var auction = Auction.init(runar.ALICE.pubKey, runar.ALICE.pubKey, 100, 500);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{ .locktime = 499 }));
    auction.bid(ctx, runar.signTestMessage(runar.BOB), runar.BOB.pubKey, 100);
}

fn probeAuctionBidTooLate() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    var auction = Auction.init(runar.ALICE.pubKey, runar.ALICE.pubKey, 100, 500);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{ .locktime = 500 }));
    auction.bid(ctx, runar.signTestMessage(runar.BOB), runar.BOB.pubKey, 150);
}

fn probeAuctionCloseTooEarly() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    const auction = Auction.init(runar.ALICE.pubKey, runar.BOB.pubKey, 150, 500);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{ .locktime = 499 }));
    auction.close(ctx, runar.signTestMessage(runar.ALICE));
}

fn probeAuctionCloseWrongSig() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    const auction = Auction.init(runar.ALICE.pubKey, runar.BOB.pubKey, 150, 500);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{ .locktime = 500 }));
    auction.close(ctx, runar.signTestMessage(runar.BOB));
}

fn probeCovenantVaultWrongOutput() !void {
    const recipient = runar.BOB.pubKeyHash;
    const vault = CovenantVault.init(runar.ALICE.pubKey, recipient, 5000);
    const preimage = runar.mockPreimage(.{
        .outputHash = runar.hash256("wrong-output"),
    });
    vault.spend(runar.signTestMessage(runar.ALICE), preimage);
}

fn probeCovenantVaultWrongSig() !void {
    const recipient = runar.BOB.pubKeyHash;
    const vault = CovenantVault.init(runar.ALICE.pubKey, recipient, 5000);
    const expected_output = buildVaultOutput(recipient, 5000);
    const preimage = runar.mockPreimage(.{
        .outputHash = runar.hash256(expected_output),
    });
    vault.spend(runar.signTestMessage(runar.BOB), preimage);
}

fn probeOraclePriceWrongRabinProof() !void {
    const oracle_pub_key = [_]u8{0xfb};
    const contract = OraclePriceFeed.init(&oracle_pub_key, runar.ALICE.pubKey);
    const price: i64 = 60_000;
    const msg = runar.num2bin(price, 8);
    const padding = try findRabinPadding(msg, &oracle_pub_key);
    defer std.heap.page_allocator.free(padding);
    contract.settle(price, &[_]u8{0x01}, padding, runar.signTestMessage(runar.ALICE));
}

fn probeOraclePriceBelowThreshold() !void {
    const oracle_pub_key = [_]u8{0xfb};
    const contract = OraclePriceFeed.init(&oracle_pub_key, runar.ALICE.pubKey);
    const price: i64 = 50_000;
    const msg = runar.num2bin(price, 8);
    const padding = try findRabinPadding(msg, &oracle_pub_key);
    defer std.heap.page_allocator.free(padding);
    contract.settle(price, &[_]u8{0x00}, padding, runar.signTestMessage(runar.ALICE));
}

fn probeOraclePriceWrongReceiverSig() !void {
    const oracle_pub_key = [_]u8{0xfb};
    const contract = OraclePriceFeed.init(&oracle_pub_key, runar.ALICE.pubKey);
    const price: i64 = 60_000;
    const msg = runar.num2bin(price, 8);
    const padding = try findRabinPadding(msg, &oracle_pub_key);
    defer std.heap.page_allocator.free(padding);
    contract.settle(price, &[_]u8{0x00}, padding, runar.signTestMessage(runar.BOB));
}

fn probeTicTacToeJoinTwice() !void {
    var game = TicTacToe.init(runar.ALICE.pubKey, 100);
    game.join(runar.BOB.pubKey, runar.signTestMessage(runar.BOB));
    game.join(runar.CHARLIE.pubKey, runar.signTestMessage(runar.CHARLIE));
}

fn probeTicTacToeMoveWrongPlayer() !void {
    var game = TicTacToe.init(runar.ALICE.pubKey, 100);
    game.join(runar.BOB.pubKey, runar.signTestMessage(runar.BOB));
    game.move(0, runar.BOB.pubKey, runar.signTestMessage(runar.BOB));
}

fn probeTicTacToeMoveOccupiedCell() !void {
    var game = TicTacToe.init(runar.ALICE.pubKey, 100);
    game.join(runar.BOB.pubKey, runar.signTestMessage(runar.BOB));
    game.move(0, runar.ALICE.pubKey, runar.signTestMessage(runar.ALICE));
    game.move(0, runar.BOB.pubKey, runar.signTestMessage(runar.BOB));
}

fn probeTicTacToeCancelBeforeJoinWrongSig() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    const game = TicTacToe.init(runar.ALICE.pubKey, 100);
    const payout = payoutOutput(100, runar.ALICE.pubKey);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{
        .outputHash = runar.hash256(payout),
    }));
    game.cancelBeforeJoin(ctx, runar.signTestMessage(runar.BOB), runar.hash160(runar.BOB.pubKey), 0);
}

fn probeTicTacToeCancelBeforeJoinWrongOutput() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    const game = TicTacToe.init(runar.ALICE.pubKey, 100);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{
        .outputHash = runar.hash256("wrong-output"),
    }));
    game.cancelBeforeJoin(ctx, runar.signTestMessage(runar.ALICE), runar.hash160(runar.BOB.pubKey), 0);
}

fn probeTicTacToeCancelWrongSigX() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    var game = TicTacToe.init(runar.ALICE.pubKey, 100);
    game.join(runar.BOB.pubKey, runar.signTestMessage(runar.BOB));
    const out1 = payoutOutput(100, runar.ALICE.pubKey);
    const out2 = payoutOutput(100, runar.BOB.pubKey);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{
        .outputHash = runar.hash256(runar.cat(out1, out2)),
    }));
    game.cancel(ctx, runar.signTestMessage(runar.CHARLIE), runar.signTestMessage(runar.BOB), runar.hash160(runar.CHARLIE.pubKey), 0);
}

fn probeTicTacToeCancelWrongSigO() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    var game = TicTacToe.init(runar.ALICE.pubKey, 100);
    game.join(runar.BOB.pubKey, runar.signTestMessage(runar.BOB));
    const out1 = payoutOutput(100, runar.ALICE.pubKey);
    const out2 = payoutOutput(100, runar.BOB.pubKey);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{
        .outputHash = runar.hash256(runar.cat(out1, out2)),
    }));
    game.cancel(ctx, runar.signTestMessage(runar.ALICE), runar.signTestMessage(runar.CHARLIE), runar.hash160(runar.CHARLIE.pubKey), 0);
}

fn probeTicTacToeCancelWrongOutput() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    var game = TicTacToe.init(runar.ALICE.pubKey, 100);
    game.join(runar.BOB.pubKey, runar.signTestMessage(runar.BOB));
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{
        .outputHash = runar.hash256("wrong-output"),
    }));
    game.cancel(ctx, runar.signTestMessage(runar.ALICE), runar.signTestMessage(runar.BOB), runar.hash160(runar.CHARLIE.pubKey), 0);
}

fn probeTicTacToeMoveAndWinWrongSig() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    const game = TicTacToe{ .playerX = runar.ALICE.pubKey, .betAmount = 100, .playerO = runar.BOB.pubKey, .c0 = 1, .c1 = 1, .c3 = 2, .c4 = 2, .turn = 1, .status = 1 };
    const payout = payoutOutput(200, runar.ALICE.pubKey);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{
        .outputHash = runar.hash256(payout),
    }));
    game.moveAndWin(ctx, 2, runar.ALICE.pubKey, runar.signTestMessage(runar.BOB), runar.hash160(runar.CHARLIE.pubKey), 0);
}

fn probeTicTacToeMoveAndWinWrongOutput() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    const game = TicTacToe{ .playerX = runar.ALICE.pubKey, .betAmount = 100, .playerO = runar.BOB.pubKey, .c0 = 1, .c1 = 1, .c3 = 2, .c4 = 2, .turn = 1, .status = 1 };
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{
        .outputHash = runar.hash256("wrong-output"),
    }));
    game.moveAndWin(ctx, 2, runar.ALICE.pubKey, runar.signTestMessage(runar.ALICE), runar.hash160(runar.CHARLIE.pubKey), 0);
}

fn probeTicTacToeMoveAndTieWrongSig() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    const game = TicTacToe{ .playerX = runar.ALICE.pubKey, .betAmount = 100, .playerO = runar.BOB.pubKey, .c0 = 1, .c1 = 2, .c2 = 1, .c3 = 1, .c4 = 1, .c5 = 2, .c6 = 2, .c7 = 1, .turn = 2, .status = 1 };
    const out1 = payoutOutput(100, runar.ALICE.pubKey);
    const out2 = payoutOutput(100, runar.BOB.pubKey);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{
        .outputHash = runar.hash256(runar.cat(out1, out2)),
    }));
    game.moveAndTie(ctx, 8, runar.BOB.pubKey, runar.signTestMessage(runar.ALICE), runar.hash160(runar.CHARLIE.pubKey), 0);
}

fn probeTicTacToeMoveAndTieWrongOutput() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    const game = TicTacToe{ .playerX = runar.ALICE.pubKey, .betAmount = 100, .playerO = runar.BOB.pubKey, .c0 = 1, .c1 = 2, .c2 = 1, .c3 = 1, .c4 = 1, .c5 = 2, .c6 = 2, .c7 = 1, .turn = 2, .status = 1 };
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{
        .outputHash = runar.hash256("wrong-output"),
    }));
    game.moveAndTie(ctx, 8, runar.BOB.pubKey, runar.signTestMessage(runar.BOB), runar.hash160(runar.CHARLIE.pubKey), 0);
}

fn probeTokenFTTransferTooMuch() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    var token = FungibleTokenExample.init(runar.ALICE.pubKey, 40, 10, "token");
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));
    token.transfer(ctx, runar.signTestMessage(runar.ALICE), runar.BOB.pubKey, 51, 1);
}

fn probeTokenFTTransferWrongSig() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    var token = FungibleTokenExample.init(runar.ALICE.pubKey, 40, 10, "token");
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));
    token.transfer(ctx, runar.signTestMessage(runar.BOB), runar.BOB.pubKey, 30, 1);
}

fn probeTokenFTMergePrevoutsMismatch() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    var token = FungibleTokenExample.init(runar.ALICE.pubKey, 25, 5, "token");
    const first = [_]u8{'a'} ** 36;
    const second = [_]u8{'b'} ** 36;
    const all_prevouts = first ++ second;
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{
        .hashPrevouts = runar.hash256("wrong-prevouts"),
        .outpoint = first[0..],
    }));
    token.merge(ctx, runar.signTestMessage(runar.ALICE), 12, all_prevouts[0..], 1);
}

fn probeTokenNFTTransferWrongSig() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    var nft = NFTExample.init(runar.ALICE.pubKey, "token", "metadata");
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));
    nft.transfer(ctx, runar.signTestMessage(runar.BOB), runar.BOB.pubKey, 1);
}

fn probeTokenNFTTransferInvalidSatoshis() !void {
    var runtime = runar.StatefulSmartContract.init(std.heap.page_allocator);
    defer runtime.deinit();
    var nft = NFTExample.init(runar.ALICE.pubKey, "token", "metadata");
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));
    nft.transfer(ctx, runar.signTestMessage(runar.ALICE), runar.BOB.pubKey, 0);
}

fn probeTokenNFTBurnWrongSig() !void {
    const nft = NFTExample.init(runar.ALICE.pubKey, "token", "metadata");
    nft.burn(runar.signTestMessage(runar.BOB));
}

fn probeECDemoWrongX() !void {
    const point = runar.ecMulGen(3);
    const contract = ECDemo.init(point);
    contract.checkX(runar.ecPointX(point) + 1);
}

fn probeECDemoWrongEncoding() !void {
    const point = runar.ecMulGen(3);
    const contract = ECDemo.init(point);
    const compressed = runar.ecEncodeCompressed(point);
    var wrong = try std.heap.page_allocator.dupe(u8, compressed);
    defer std.heap.page_allocator.free(wrong);
    wrong[wrong.len - 1] ^= 0x01;
    contract.checkEncodeCompressed(wrong);
}

fn probeConvergenceProofInvalidPoint() !void {
    const bad_point = [_]u8{0x01} ** 64;
    const contract = ConvergenceProof.init(&bad_point, runar.ecMulGen(2));
    contract.proveConvergence(3);
}

fn probeConvergenceProofWrongDelta() !void {
    const contract = ConvergenceProof.init(runar.ecMulGen(5), runar.ecMulGen(2));
    contract.proveConvergence(2);
}

fn probePostQuantumWalletWrongECDSAPubkey() !void {
    const ecdsa_sig = runar.signTestMessage(runar.ALICE);
    const seed = [_]u8{0x42} ** 32;
    const pub_seed = [_]u8{0x13} ** 32;
    const wots_pub_key = runar.testing.wotsPublicKeyFromSeed(&seed, &pub_seed);
    const wots_sig = runar.testing.wotsSignDeterministic(ecdsa_sig, &seed, &pub_seed);
    const contract = PostQuantumWallet.init(runar.hash160(runar.ALICE.pubKey), runar.hash160(&wots_pub_key));
    contract.spend(&wots_sig, &wots_pub_key, ecdsa_sig, runar.BOB.pubKey);
}

fn probePostQuantumWalletWrongECDSASig() !void {
    const ecdsa_sig = runar.signTestMessage(runar.ALICE);
    const seed = [_]u8{0x42} ** 32;
    const pub_seed = [_]u8{0x13} ** 32;
    const wots_pub_key = runar.testing.wotsPublicKeyFromSeed(&seed, &pub_seed);
    const wots_sig = runar.testing.wotsSignDeterministic(ecdsa_sig, &seed, &pub_seed);
    const contract = PostQuantumWallet.init(runar.hash160(runar.ALICE.pubKey), runar.hash160(&wots_pub_key));
    contract.spend(&wots_sig, &wots_pub_key, runar.signTestMessage(runar.BOB), runar.ALICE.pubKey);
}

fn probePostQuantumWalletWrongWOTSKey() !void {
    const ecdsa_sig = runar.signTestMessage(runar.ALICE);
    const seed = [_]u8{0x42} ** 32;
    const pub_seed = [_]u8{0x13} ** 32;
    const wots_pub_key = runar.testing.wotsPublicKeyFromSeed(&seed, &pub_seed);
    const wrong_pub_key = runar.testing.wotsPublicKeyFromSeed(&([_]u8{0x43} ** 32), &pub_seed);
    const wots_sig = runar.testing.wotsSignDeterministic(ecdsa_sig, &seed, &pub_seed);
    const contract = PostQuantumWallet.init(runar.hash160(runar.ALICE.pubKey), runar.hash160(&wots_pub_key));
    contract.spend(&wots_sig, &wrong_pub_key, ecdsa_sig, runar.ALICE.pubKey);
}

fn probePostQuantumWalletInvalidWOTSProof() !void {
    const ecdsa_sig = runar.signTestMessage(runar.ALICE);
    const seed = [_]u8{0x42} ** 32;
    const pub_seed = [_]u8{0x13} ** 32;
    const wots_pub_key = runar.testing.wotsPublicKeyFromSeed(&seed, &pub_seed);
    var wots_sig = runar.testing.wotsSignDeterministic(ecdsa_sig, &seed, &pub_seed);
    wots_sig[17] ^= 0xff;
    const contract = PostQuantumWallet.init(runar.hash160(runar.ALICE.pubKey), runar.hash160(&wots_pub_key));
    contract.spend(&wots_sig, &wots_pub_key, ecdsa_sig, runar.ALICE.pubKey);
}

fn probeSPHINCSWalletWrongECDSAPubkey() !void {
    const ecdsa_sig = runar.signTestMessage(runar.ALICE);
    const slhdsa_sig = try runar.hex.decodeAlloc(std.heap.page_allocator, sphincs_fixtures.slhdsa_sig_hex);
    defer std.heap.page_allocator.free(slhdsa_sig);
    const contract = SPHINCSWallet.init(runar.hash160(runar.ALICE.pubKey), runar.hash160(&sphincs_fixtures.slhdsa_pub_key));
    contract.spend(slhdsa_sig, &sphincs_fixtures.slhdsa_pub_key, ecdsa_sig, runar.BOB.pubKey);
}

fn probeSPHINCSWalletWrongECDSASig() !void {
    const slhdsa_sig = try runar.hex.decodeAlloc(std.heap.page_allocator, sphincs_fixtures.slhdsa_sig_hex);
    defer std.heap.page_allocator.free(slhdsa_sig);
    const contract = SPHINCSWallet.init(runar.hash160(runar.ALICE.pubKey), runar.hash160(&sphincs_fixtures.slhdsa_pub_key));
    contract.spend(slhdsa_sig, &sphincs_fixtures.slhdsa_pub_key, runar.signTestMessage(runar.BOB), runar.ALICE.pubKey);
}

fn probeSPHINCSWalletWrongSLHDSAKey() !void {
    const ecdsa_sig = runar.signTestMessage(runar.ALICE);
    const slhdsa_sig = try runar.hex.decodeAlloc(std.heap.page_allocator, sphincs_fixtures.slhdsa_sig_hex);
    defer std.heap.page_allocator.free(slhdsa_sig);
    var wrong_pub_key = sphincs_fixtures.slhdsa_pub_key;
    wrong_pub_key[0] ^= 0xff;
    const contract = SPHINCSWallet.init(runar.hash160(runar.ALICE.pubKey), runar.hash160(&sphincs_fixtures.slhdsa_pub_key));
    contract.spend(slhdsa_sig, &wrong_pub_key, ecdsa_sig, runar.ALICE.pubKey);
}

fn probeSPHINCSWalletInvalidSLHDSAProof() !void {
    const ecdsa_sig = runar.signTestMessage(runar.ALICE);
    var slhdsa_sig = try runar.hex.decodeAlloc(std.heap.page_allocator, sphincs_fixtures.slhdsa_sig_hex);
    defer std.heap.page_allocator.free(slhdsa_sig);
    slhdsa_sig[17] ^= 0xff;
    const contract = SPHINCSWallet.init(runar.hash160(runar.ALICE.pubKey), runar.hash160(&sphincs_fixtures.slhdsa_pub_key));
    contract.spend(slhdsa_sig, &sphincs_fixtures.slhdsa_pub_key, ecdsa_sig, runar.ALICE.pubKey);
}

fn probeSchnorrZKPInvalidRPoint() !void {
    const pub_key = try runar.hex.decodeAlloc(
        std.heap.page_allocator,
        "fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af" ++
            "07b158f244cd0de2134ac7c1d371cffbfae4db40801a2572e531c573cda9b5b4",
    );
    defer std.heap.page_allocator.free(pub_key);
    const contract = SchnorrZKP.init(pub_key);
    const bad_point = [_]u8{0x01} ** 64;
    contract.verify(&bad_point, runar.bigint(1));
}
