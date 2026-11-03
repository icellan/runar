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
//
// N-428 extends the same generate-and-compile pipeline to a STATEFUL wrapper
// (`MergeCounter`, built from `conformance/sdk-call/stateful-merge-prepared.json`)
// and runs the generated `increment` against a MockProvider: the options the
// wrapper declares (`change_pub_key`, `outputs`) must reach the tx it builds.
// Proves: a matching `change_pub_key` is not dropped (a dropped one makes the
// N-426 guard refuse `change_address`), and `outputs` yields one continuation
// output per entry (a dropped one keeps the single contract-UTXO amount).
// Does NOT prove: script validity of the resulting tx, the prepare/finalize
// wrapper methods, or any tier other than Zig.
//
// N-431 stops clearing the stateful artifact's constructor params before
// generating, so the wrapper's `init(allocator, artifact, args)` is compiled
// too, and a test asserts `init(.{count, owner})` yields the same locking
// script as `RunarContract.init` with the same args in ABI order (and that a
// different count changes it). Does NOT prove: init for other param types.
const std = @import("std");
const sdk = @import("runar-zig");

const VECTOR_PATH = "../../conformance/sdk-call/stateful-merge-prepared.json";

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

const TEST_BLOCK_STATEFUL =
    \\
    \\const VECTOR = "../../conformance/sdk-call/stateful-merge-prepared.json";
    \\const GUARD = "../../conformance/sdk-call/n426-change-address-guard.json";
    \\
    \\/// Runs the generated `MergeCounterContract.increment(options)` against the
    \\/// vector's contract + funding UTXOs and returns an owned copy of the tx the
    \\/// MockProvider saw broadcast.
    \\fn incrementViaWrapper(options: MergeCounterStatefulCallOptions) ![]u8 {
    \\    const allocator = testing.allocator;
    \\    const raw = try std.Io.Dir.cwd().readFileAlloc(testing.io, VECTOR, allocator, .limited(8 * 1024 * 1024));
    \\    defer allocator.free(raw);
    \\    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    \\    defer parsed.deinit();
    \\    const v = parsed.value.object;
    \\    const artifact_json = try std.json.Stringify.valueAlloc(allocator, v.get("artifact").?, .{});
    \\    defer allocator.free(artifact_json);
    \\    var artifact = try sdk.RunarArtifact.fromJson(allocator, artifact_json);
    \\    defer artifact.deinit();
    \\
    \\    const cu = v.get("contractUtxo").?.object;
    \\    const fu = v.get("fundingUtxo").?.object;
    \\    const contract_utxo = sdk.UTXO{
    \\        .txid = cu.get("txid").?.string,
    \\        .output_index = @intCast(cu.get("outputIndex").?.integer),
    \\        .satoshis = cu.get("satoshis").?.integer,
    \\        .script = cu.get("script").?.string,
    \\    };
    \\    const funding_utxo = sdk.UTXO{
    \\        .txid = fu.get("txid").?.string,
    \\        .output_index = @intCast(fu.get("outputIndex").?.integer),
    \\        .satoshis = fu.get("satoshis").?.integer,
    \\        .script = fu.get("script").?.string,
    \\    };
    \\
    \\    var prov = sdk.MockProvider.init(allocator, "testnet");
    \\    defer prov.deinit();
    \\    var signer = try sdk.LocalSigner.fromHex(v.get("privKeyHex").?.string);
    \\    {
    \\        const addr = try signer.signer().getAddress(allocator);
    \\        defer allocator.free(addr);
    \\        try prov.addUtxo(addr, funding_utxo);
    \\    }
    \\    try prov.addKnownOutpoint(contract_utxo.txid, contract_utxo.output_index, contract_utxo.script, contract_utxo.satoshis);
    \\
    \\    var wrapper = try MergeCounterContract.fromUtxo(allocator, &artifact, contract_utxo);
    \\    defer wrapper.deinit();
    \\    wrapper.connect(prov.provider(), signer.signer());
    \\
    \\    const txid = try wrapper.increment(options);
    \\    allocator.free(txid);
    \\    const sent = prov.getBroadcastedTxs();
    \\    try testing.expectEqual(@as(usize, 1), sent.len);
    \\    return allocator.dupe(u8, sent[0]);
    \\}
    \\
    \\fn countOf(hay: []const u8, needle: []const u8) usize {
    \\    return std.mem.count(u8, hay, needle);
    \\}
    \\
    \\test "N-428: generated wrapper forwards change_pub_key to the SDK call" {
    \\    const allocator = testing.allocator;
    \\    const raw = try std.Io.Dir.cwd().readFileAlloc(testing.io, GUARD, allocator, .limited(1024 * 1024));
    \\    defer allocator.free(raw);
    \\    const g = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    \\    defer g.deinit();
    \\    const state = [_]sdk.StateValue{.{ .int = 1 }};
    \\    // Another key's address WITHOUT its pubkey: the N-426 guard refuses.
    \\    try testing.expectError(error.ChangeAddressMismatch, incrementViaWrapper(.{
    \\        .change_address = g.value.object.get("otherAddress").?.string,
    \\        .new_state = &state,
    \\    }));
    \\    // The same address WITH the matching change_pub_key must reach the SDK
    \\    // and be accepted (dropped by the wrapper -> ChangeAddressMismatch).
    \\    const tx = try incrementViaWrapper(.{
    \\        .change_address = g.value.object.get("otherAddress").?.string,
    \\        .change_pub_key = g.value.object.get("otherPubKeyHex").?.string,
    \\        .new_state = &state,
    \\    });
    \\    defer allocator.free(tx);
    \\}
    \\
    \\test "N-428: generated wrapper forwards outputs to the SDK call" {
    \\    const allocator = testing.allocator;
    \\    const state = [_]sdk.StateValue{.{ .int = 1 }};
    \\    // 7000 sat as 8-byte LE. The vector's continuation keeps the contract
    \\    // UTXO's 10000 sat unless `outputs` overrides it.
    \\    const sats_7000 = "581b000000000000";
    \\    const plain = try incrementViaWrapper(.{ .new_state = &state });
    \\    defer allocator.free(plain);
    \\    try testing.expectEqual(@as(usize, 0), countOf(plain, sats_7000));
    \\    const specs = [_]OutputSpec{.{ .satoshis = 7000, .state = &state }};
    \\    const multi = try incrementViaWrapper(.{ .outputs = &specs });
    \\    defer allocator.free(multi);
    \\    try testing.expectEqual(@as(usize, 1), countOf(multi, sats_7000));
    \\}
    \\
    \\test "N-431: generated init(args) yields the same locking script as the direct SDK" {
    \\    const allocator = testing.allocator;
    \\    const raw = try std.Io.Dir.cwd().readFileAlloc(testing.io, VECTOR, allocator, .limited(8 * 1024 * 1024));
    \\    defer allocator.free(raw);
    \\    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    \\    defer parsed.deinit();
    \\    const v = parsed.value.object;
    \\    const artifact_json = try std.json.Stringify.valueAlloc(allocator, v.get("artifact").?, .{});
    \\    defer allocator.free(artifact_json);
    \\    var artifact = try sdk.RunarArtifact.fromJson(allocator, artifact_json);
    \\    defer artifact.deinit();
    \\    const owner = v.get("constructorArgs").?.object.get("owner").?.string;
    \\
    \\    var wrapper = try MergeCounterContract.init(allocator, &artifact, .{ .count = 7, .owner = owner });
    \\    defer wrapper.deinit();
    \\    const direct_args = [_]sdk.StateValue{ .{ .int = 7 }, .{ .bytes = owner } };
    \\    var direct = try sdk.RunarContract.init(allocator, &artifact, &direct_args);
    \\    defer direct.deinit();
    \\
    \\    const a = try wrapper.getLockingScript();
    \\    defer allocator.free(a);
    \\    const b = try direct.getLockingScript();
    \\    defer allocator.free(b);
    \\    try testing.expectEqualStrings(b, a);
    \\    // A different count must change the script (state is part of it), so the
    \\    // equality above is not vacuous.
    \\    var other = try MergeCounterContract.init(allocator, &artifact, .{ .count = 8, .owner = owner });
    \\    defer other.deinit();
    \\    const c = try other.getLockingScript();
    \\    defer allocator.free(c);
    \\    try testing.expect(!std.mem.eql(u8, a, c));
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

    // N-428: a stateful wrapper generated from the shared vector's real artifact.
    const raw = try std.Io.Dir.cwd().readFileAlloc(io, VECTOR_PATH, allocator, .limited(8 * 1024 * 1024));
    defer allocator.free(raw);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const artifact_json = try std.json.Stringify.valueAlloc(allocator, parsed.value.object.get("artifact").?, .{});
    defer allocator.free(artifact_json);
    var stateful_artifact = try sdk.RunarArtifact.fromJson(allocator, artifact_json);
    defer stateful_artifact.deinit();
    const stateful_src = try sdk.generateZig(allocator, &stateful_artifact);
    defer allocator.free(stateful_src);
    // Both wrappers share one file: drop the second one's duplicate imports.
    const import_end_marker = "const sdk = @import(\"runar-zig\");\n\n";
    const import_end = std.mem.indexOf(u8, stateful_src, import_end_marker).? + import_end_marker.len;

    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    try w.interface.writeAll(wrapper_src);
    try w.interface.writeAll(stateful_src[import_end..]);
    try w.interface.writeAll(TEST_BLOCK);
    try w.interface.writeAll(TEST_BLOCK_STATEFUL);
    try w.interface.flush();
}
