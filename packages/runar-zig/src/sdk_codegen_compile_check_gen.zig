// N-190 — compile-check generator for the Zig typed-wrapper codegen.
//
// `conformance/sdk-codegen/README.md` used to document the Zig runner
// (`sdk_codegen_conformance_test.zig`) as "structural only, no compile step",
// the exact gap that let `sdk_codegen.zig`'s `fromTxId` emit a call to
// `provider.getUtxo(...)` — a method `sdk_provider.zig`'s `Provider.VTable`
// has never had (it ships `getTransaction` / `getUtxos` / `getContractUtxo`
// / `getNetwork` / `getFeeRate` / `getRawTransaction`, matching the
// TypeScript reference's `RunarContract.fromTxId`, which calls
// `provider.getTransaction` and reads `tx.outputs[outputIndex]`).
//
// Zig can't `eval` or in-memory-compile a string the way Java/Python/Ruby's
// codegen conformance runners do, so this program is the "compile the
// generated wrapper" step instead: it builds a minimal fixture artifact,
// calls the real `generateZig`, appends a small `test` block that exercises
// the generated `fromTxId` against a stub `Provider`, and prints the whole
// file to stdout. `build.zig`'s `codegen-compile-check` step feeds that
// output back in as a module importing `"runar-zig"` -> the real SDK, so a
// codegen bug that references a method the real `Provider` doesn't have
// fails to COMPILE, not just a substring check.
//
// What the appended `test` block proves: the generated `fromTxId` for a
// real (if minimal) artifact compiles against the actual `Provider.VTable`
// and `RunarContract.fromUtxo`, fetches via `getTransaction`, accepts a
// valid output index, and refuses both a negative index and one past the
// end of `tx.outputs` with `error.OutputIndexOutOfRange` rather than
// panicking or silently wrapping the wrong output.
// What it does NOT prove: that the restored contract's constructor args,
// state, or locking script are byte-correct for a non-trivial fixture (the
// `Simple` fixture has no constructor params and no state fields precisely
// so this check can stay focused on the Provider call shape), or anything
// about the other 6 tiers' `fromTxId` — this is a Zig-only codegen bug.
const std = @import("std");
const sdk = @import("runar-zig");

const TEST_BLOCK =
    \\
    \\const testing = std.testing;
    \\
    \\fn buildSimpleArtifact() sdk.RunarArtifact {
    \\    return sdk.RunarArtifact{
    \\        .allocator = testing.allocator,
    \\        .contract_name = "Simple",
    \\        .abi = .{ .constructor = .{ .params = &.{} }, .methods = &.{} },
    \\        .state_fields = &.{},
    \\    };
    \\}
    \\
    \\/// Stub `Provider` whose `getTransaction` answers with one output, the
    \\/// way the TypeScript reference's `fromTxId` expects to read
    \\/// `tx.outputs[outputIndex]` from. Every other VTable slot refuses —
    \\/// `fromTxId` must not reach them.
    \\const StubOneOutputProvider = struct {
    \\    const VTable = sdk.Provider.VTable;
    \\
    \\    const vtable = VTable{
    \\        .getTransaction = getTransactionImpl,
    \\        .broadcast = broadcastStub,
    \\        .getUtxos = getUtxosStub,
    \\        .getContractUtxo = getContractUtxoStub,
    \\        .getNetwork = getNetworkStub,
    \\        .getFeeRate = getFeeRateStub,
    \\        .getRawTransaction = getRawTransactionStub,
    \\    };
    \\
    \\    fn provider(self: *StubOneOutputProvider) sdk.Provider {
    \\        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    \\    }
    \\
    \\    fn getTransactionImpl(_: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) sdk.sdk_provider.ProviderError!sdk.sdk_types.TransactionData {
    \\        // `.script` is a string literal (not allocator-owned): TransactionData.deinit
    \\        // frees the `outputs` slice itself but NOT each entry's `.script` (it's a
    \\        // no-op loop over `*outp` in sdk_types.zig), so an allocated script here
    \\        // would trip the testing allocator's leak check.
    \\        const outputs = try allocator.alloc(sdk.sdk_types.TxOutput, 1);
    \\        outputs[0] = .{ .satoshis = 1000, .script = "76a914" };
    \\        return .{ .txid = try allocator.dupe(u8, txid), .outputs = outputs };
    \\    }
    \\
    \\    fn broadcastStub(_: *anyopaque, _: std.mem.Allocator, _: []const u8) sdk.sdk_provider.ProviderError![]u8 {
    \\        return sdk.sdk_provider.ProviderError.NetworkError;
    \\    }
    \\
    \\    fn getUtxosStub(_: *anyopaque, _: std.mem.Allocator, _: []const u8) sdk.sdk_provider.ProviderError![]sdk.UTXO {
    \\        return sdk.sdk_provider.ProviderError.NotFound;
    \\    }
    \\
    \\    fn getContractUtxoStub(_: *anyopaque, _: std.mem.Allocator, _: []const u8) sdk.sdk_provider.ProviderError!?sdk.UTXO {
    \\        return null;
    \\    }
    \\
    \\    fn getNetworkStub(_: *anyopaque) []const u8 {
    \\        return "mock";
    \\    }
    \\
    \\    fn getFeeRateStub(_: *anyopaque) sdk.sdk_provider.ProviderError!i64 {
    \\        return 1;
    \\    }
    \\
    \\    fn getRawTransactionStub(_: *anyopaque, _: std.mem.Allocator, _: []const u8) sdk.sdk_provider.ProviderError![]u8 {
    \\        return sdk.sdk_provider.ProviderError.NotFound;
    \\    }
    \\};
    \\
    \\test "N-190: fromTxId re-attaches via the real Provider.getTransaction" {
    \\    var artifact = buildSimpleArtifact();
    \\    var stub = StubOneOutputProvider{};
    \\    var contract = try SimpleContract.fromTxId(testing.allocator, &artifact, "ab" ** 32, 0, stub.provider());
    \\    defer contract.deinit();
    \\}
    \\
    \\test "N-190: fromTxId refuses an out-of-range output index" {
    \\    var artifact = buildSimpleArtifact();
    \\    var stub = StubOneOutputProvider{};
    \\    try testing.expectError(error.OutputIndexOutOfRange, SimpleContract.fromTxId(testing.allocator, &artifact, "ab" ** 32, 1, stub.provider()));
    \\}
    \\
    \\test "N-190: fromTxId refuses a negative output index" {
    \\    var artifact = buildSimpleArtifact();
    \\    var stub = StubOneOutputProvider{};
    \\    try testing.expectError(error.OutputIndexOutOfRange, SimpleContract.fromTxId(testing.allocator, &artifact, "ab" ** 32, -1, stub.provider()));
    \\}
    \\
;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var artifact = sdk.RunarArtifact{
        .allocator = allocator,
        .contract_name = "Simple",
        .abi = .{ .constructor = .{ .params = &.{} }, .methods = &.{} },
        .state_fields = &.{},
    };

    const wrapper_src = try sdk.generateZig(allocator, &artifact);
    defer allocator.free(wrapper_src);

    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    try w.interface.writeAll(wrapper_src);
    try w.interface.writeAll(TEST_BLOCK);
    try w.interface.flush();
}
