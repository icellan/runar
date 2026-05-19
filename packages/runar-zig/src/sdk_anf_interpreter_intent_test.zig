//! Intent-covenant intrinsic interpreter coverage (BSVM Phase 13 Major-1
//! follow-up, Zig tier port of the TS reference at
//! `packages/runar-testing/src/__tests__/intent-intrinsics-interpreter.test.ts`).
//!
//! ANF lowering desugars the four intent-covenant intrinsics
//! (`extractPrevOutputScript`, `requireOutputP2PKH`, `currentBlockHeight`,
//! and a `len`-branched stateful body) into chains of primitive nodes:
//! `load_param` of an auto-injected witness param (`_prevOutScript_<idx>`,
//! `_serialisedOutputs`), `hash256` / `substr` / `cat` / `num2bin`,
//! `extractLocktime` / `extractOutputHash`, and `assert(bin_op === ...)`.
//!
//! The Zig ANF interpreter walks the lowered IR; this test file proves
//! `MockEnv` correctly threads witness bytes and preimage overrides into
//! that lowered form, mirroring the 10 TS tests one-for-one:
//!   - intent-prev-output-script:    1 success + 2 failure (wrong hash, empty witness)
//!   - intent-output-p2pkh:          1 success + 2 failure (wrong PKH bytes, wrong hashOutputs)
//!   - intent-current-block-height:  1 success + 1 failure (locktime > deadline)
//!   - branched-readonly-len:        1 then-branch + 1 else-branch
//!
//! Each test builds an ANF body that mirrors what the compiler produces
//! for the corresponding source fixture under
//! `examples/ts/{intent-prev-output-script,intent-output-p2pkh,
//! intent-current-block-height,branched-readonly-len}/...`. The same
//! cross-tier conformance suite at `conformance/tests/<fixture>` carries
//! the exact `expected-ir.json` these mirror.

const std = @import("std");
const interp = @import("sdk_anf_interpreter.zig");

const ANFProgram = interp.ANFProgram;
const ANFProperty = interp.ANFProperty;
const ANFParam = interp.ANFParam;
const ANFMethod = interp.ANFMethod;
const ANFBinding = interp.ANFBinding;
const ANFNode = interp.ANFNode;
const ANFValue = interp.ANFValue;
const MockEnv = interp.MockEnv;
const StrictError = interp.StrictError;
const NewStateResult = interp.NewStateResult;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn freeResult(allocator: std.mem.Allocator, result: *NewStateResult) void {
    result.state.deinit();
    for (result.data_outputs) |d| allocator.free(d.script);
    allocator.free(result.data_outputs);
    for (result.raw_outputs) |d| allocator.free(d.script);
    allocator.free(result.raw_outputs);
}

fn hexEncode(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    const charset = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = charset[b >> 4];
        out[i * 2 + 1] = charset[b & 0x0f];
    }
    return out;
}

fn hash256Hex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var first: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &first, .{});
    var second: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&first, &second, .{});
    return hexEncode(allocator, &second);
}

/// Build a canonical 34-byte P2PKH output: 8 LE amount ‖ 0x19 0x76 0xa9 0x14
/// ‖ pkh (20 bytes) ‖ 0x88 0xac.
fn p2pkhOutput(allocator: std.mem.Allocator, amount: u64, pkh: []const u8) ![]u8 {
    std.debug.assert(pkh.len == 20);
    var buf: [34]u8 = undefined;
    var a = amount;
    for (0..8) |i| {
        buf[i] = @intCast(a & 0xff);
        a >>= 8;
    }
    buf[8] = 0x19;
    buf[9] = 0x76;
    buf[10] = 0xa9;
    buf[11] = 0x14;
    @memcpy(buf[12..32], pkh);
    buf[32] = 0x88;
    buf[33] = 0xac;
    return allocator.dupe(u8, &buf);
}

// ---------------------------------------------------------------------------
// IntentPrevOutputScript: ANF body matching the `bind` method desugar.
//
// Source method body (Rúnar):
//   const s = extractPrevOutputScript(0n, this.expectedHash);
//   assert(len(s) > 0n);
//   this.count = this.count + 1n;
//
// ANF lowering (slimmed to just what's needed to exercise the witness
// bridge + hash assertion, the len-check, and the count mutation):
//   t_witness     = load_param _prevOutScript_0
//   t_expected    = load_prop  expectedHash
//   t_actualHash  = call hash256(t_witness)
//   t_eq          = bin_op === t_actualHash t_expected
//   _             = assert t_eq                    <-- hash assertion
//   t_len         = call len(t_witness)
//   t_zero        = load_const 0
//   t_lenOk       = bin_op > t_len t_zero
//   _             = assert t_lenOk                 <-- non-empty assertion
//   t_count       = load_prop count
//   t_one         = load_const 1
//   t_newCount    = bin_op + t_count t_one
//   _             = update_prop count = t_newCount
// ---------------------------------------------------------------------------

fn buildIntentPrevOutputScriptAnf() ANFProgram {
    const props = struct {
        var p = [_]ANFProperty{
            .{ .name = "expectedHash", .type_name = "bytes", .readonly = true },
            .{ .name = "count", .type_name = "int", .readonly = false },
        };
    };
    const params = struct {
        var p = [_]ANFParam{
            .{ .name = "_prevOutScript_0", .type_name = "bytes" },
        };
    };
    const hash_args = struct {
        var a = [_][]const u8{"t_witness"};
    };
    const len_args = struct {
        var a = [_][]const u8{"t_witness"};
    };
    const body = struct {
        var b = [_]ANFBinding{
            .{ .name = "t_witness", .value = .{ .load_param = .{ .name = "_prevOutScript_0" } } },
            .{ .name = "t_expected", .value = .{ .load_prop = .{ .name = "expectedHash" } } },
            .{ .name = "t_actualHash", .value = .{ .call = .{ .func = "hash256", .args = &hash_args.a } } },
            .{ .name = "t_eq", .value = .{ .bin_op = .{ .op = "===", .left = "t_actualHash", .right = "t_expected", .result_type = "bytes" } } },
            .{ .name = "assertHash", .value = .{ .assert_node = .{ .value = "t_eq" } } },
            .{ .name = "t_len", .value = .{ .call = .{ .func = "len", .args = &len_args.a } } },
            .{ .name = "t_zero", .value = .{ .load_const = .{ .value = .{ .int = 0 } } } },
            .{ .name = "t_lenOk", .value = .{ .bin_op = .{ .op = ">", .left = "t_len", .right = "t_zero", .result_type = "bool" } } },
            .{ .name = "assertLen", .value = .{ .assert_node = .{ .value = "t_lenOk" } } },
            .{ .name = "t_count", .value = .{ .load_prop = .{ .name = "count" } } },
            .{ .name = "t_one", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "t_newCount", .value = .{ .bin_op = .{ .op = "+", .left = "t_count", .right = "t_one", .result_type = "int" } } },
            .{ .name = "updCount", .value = .{ .update_prop = .{ .name = "count", .value = "t_newCount" } } },
        };
    };
    const methods = struct {
        var m = [_]ANFMethod{
            .{ .name = "bind", .params = &params.p, .body = &body.b, .is_public = true },
        };
    };
    return .{
        .contract_name = "IntentPrevOutputScript",
        .properties = &props.p,
        .methods = &methods.m,
    };
}

test "intent-prev-output-script — success: hash256(witness) == expectedHash → count increments" {
    const allocator = std.testing.allocator;
    const anf = buildIntentPrevOutputScriptAnf();

    // Witness bytes: standard P2PKH 25-byte locking script.
    const witness_bytes = [_]u8{
        0x76, 0xa9, 0x14,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
        0x88, 0xac,
    };
    const witness_hex = try hexEncode(allocator, &witness_bytes);
    defer allocator.free(witness_hex);
    const expected_hex = try hash256Hex(allocator, &witness_bytes);
    defer allocator.free(expected_hex);

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("expectedHash", .{ .bytes = expected_hex });
    try current_state.put("count", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();

    var mock = MockEnv.init(allocator);
    defer mock.deinit();
    try mock.setPrevOutScript(0, witness_hex);

    var result = try interp.executeStrictWithMockEnv(
        allocator, &anf, "bind", current_state, args, &.{}, &mock,
    );
    defer freeResult(allocator, &result);

    try std.testing.expectEqual(@as(i64, 1), result.state.get("count").?.int);
}

test "intent-prev-output-script — failure: witness mismatches expectedHash → AssertionFailure" {
    const allocator = std.testing.allocator;
    const anf = buildIntentPrevOutputScriptAnf();

    // Build the "correct" expected hash, then bind a DIFFERENT witness so
    // hash256(witness) != expectedHash.
    const real_witness = [_]u8{ 0x76, 0xa9, 0x14, 0xaa, 0xbb, 0xcc };
    const expected_hex = try hash256Hex(allocator, &real_witness);
    defer allocator.free(expected_hex);

    const wrong_witness_hex = try allocator.dupe(u8, "deadbeef");
    defer allocator.free(wrong_witness_hex);

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("expectedHash", .{ .bytes = expected_hex });
    try current_state.put("count", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();

    var mock = MockEnv.init(allocator);
    defer mock.deinit();
    try mock.setPrevOutScript(0, wrong_witness_hex);

    const result = interp.executeStrictWithMockEnv(
        allocator, &anf, "bind", current_state, args, &.{}, &mock,
    );
    try std.testing.expectError(StrictError.AssertionFailure, result);
}

test "intent-prev-output-script — failure: no witness supplied → MissingWitness" {
    const allocator = std.testing.allocator;
    const anf = buildIntentPrevOutputScriptAnf();

    const dummy_hex = try allocator.dupe(u8, "00" ** 32);
    defer allocator.free(dummy_hex);

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("expectedHash", .{ .bytes = dummy_hex });
    try current_state.put("count", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();

    // Intentionally omit setPrevOutScript.
    var mock = MockEnv.init(allocator);
    defer mock.deinit();

    const result = interp.executeStrictWithMockEnv(
        allocator, &anf, "bind", current_state, args, &.{}, &mock,
    );
    try std.testing.expectError(StrictError.MissingWitness, result);
}

// ---------------------------------------------------------------------------
// IntentOutputP2PKH: ANF body matching the `payBond` method desugar.
//
// Source method body (Rúnar):
//   requireOutputP2PKH(0n, this.bondPKH, this.bondAmount);
//   this.count = this.count + 1n;
//
// ANF lowering (slimmed to the witness-bridge + per-output substring
// check; full pipeline would also build the change output + state output,
// but those are out of scope for this test's intent intrinsic):
//   t_serialised  = load_param _serialisedOutputs
//   t_outHash     = call hash256(t_serialised)
//   t_preimage    = load_param txPreimage
//   t_expectedOH  = call extractOutputHash(t_preimage)
//   t_hashEq      = bin_op === t_outHash t_expectedOH
//   _             = assert t_hashEq                <-- outer hash check
//
//   t_pkh         = load_prop bondPKH
//   t_amount      = load_prop bondAmount
//   t_eight       = load_const 8
//   t_amountBytes = call num2bin(t_amount, t_eight)
//   t_prefix      = load_const "1976a914"
//   t_suffix      = load_const "88ac"
//   t_cat1        = call cat(t_amountBytes, t_prefix)
//   t_cat2        = call cat(t_cat1, t_pkh)
//   t_expected    = call cat(t_cat2, t_suffix)
//
//   t_serialised2 = load_param _serialisedOutputs
//   t_offset      = load_const 0    (idx*34 = 0)
//   t_len34       = load_const 34
//   t_extracted   = call substr(t_serialised2, t_offset, t_len34)
//   t_outEq       = bin_op === t_extracted t_expected
//   _             = assert t_outEq                 <-- per-output check
//
//   t_count       = load_prop count
//   t_one         = load_const 1
//   t_newCount    = bin_op + t_count t_one
//   _             = update_prop count = t_newCount
// ---------------------------------------------------------------------------

fn buildIntentOutputP2PKHAnf() ANFProgram {
    const props = struct {
        var p = [_]ANFProperty{
            .{ .name = "bondPKH", .type_name = "bytes", .readonly = true },
            .{ .name = "bondAmount", .type_name = "int", .readonly = true },
            .{ .name = "count", .type_name = "int", .readonly = false },
        };
    };
    const params = struct {
        var p = [_]ANFParam{
            .{ .name = "txPreimage", .type_name = "bytes" },
            .{ .name = "_serialisedOutputs", .type_name = "bytes" },
        };
    };
    const h_args = struct {
        var a = [_][]const u8{"t_serialised"};
    };
    const outhash_args = struct {
        var a = [_][]const u8{"t_preimage"};
    };
    const num2bin_args = struct {
        var a = [_][]const u8{ "t_amount", "t_eight" };
    };
    const cat1_args = struct {
        var a = [_][]const u8{ "t_amountBytes", "t_prefix" };
    };
    const cat2_args = struct {
        var a = [_][]const u8{ "t_cat1", "t_pkh" };
    };
    const cat3_args = struct {
        var a = [_][]const u8{ "t_cat2", "t_suffix" };
    };
    const substr_args = struct {
        var a = [_][]const u8{ "t_serialised2", "t_offset", "t_len34" };
    };
    const body = struct {
        var b = [_]ANFBinding{
            // Outer hash check
            .{ .name = "t_serialised", .value = .{ .load_param = .{ .name = "_serialisedOutputs" } } },
            .{ .name = "t_outHash", .value = .{ .call = .{ .func = "hash256", .args = &h_args.a } } },
            .{ .name = "t_preimage", .value = .{ .load_param = .{ .name = "txPreimage" } } },
            .{ .name = "t_expectedOH", .value = .{ .call = .{ .func = "extractOutputHash", .args = &outhash_args.a } } },
            .{ .name = "t_hashEq", .value = .{ .bin_op = .{ .op = "===", .left = "t_outHash", .right = "t_expectedOH", .result_type = "bytes" } } },
            .{ .name = "assertHash", .value = .{ .assert_node = .{ .value = "t_hashEq" } } },
            // Build expected P2PKH bytes
            .{ .name = "t_pkh", .value = .{ .load_prop = .{ .name = "bondPKH" } } },
            .{ .name = "t_amount", .value = .{ .load_prop = .{ .name = "bondAmount" } } },
            .{ .name = "t_eight", .value = .{ .load_const = .{ .value = .{ .int = 8 } } } },
            .{ .name = "t_amountBytes", .value = .{ .call = .{ .func = "num2bin", .args = &num2bin_args.a } } },
            .{ .name = "t_prefix", .value = .{ .load_const = .{ .value = .{ .bytes = "1976a914" } } } },
            .{ .name = "t_suffix", .value = .{ .load_const = .{ .value = .{ .bytes = "88ac" } } } },
            .{ .name = "t_cat1", .value = .{ .call = .{ .func = "cat", .args = &cat1_args.a } } },
            .{ .name = "t_cat2", .value = .{ .call = .{ .func = "cat", .args = &cat2_args.a } } },
            .{ .name = "t_expected", .value = .{ .call = .{ .func = "cat", .args = &cat3_args.a } } },
            // Per-output check at idx=0 (offset=0*34, length=34)
            .{ .name = "t_serialised2", .value = .{ .load_param = .{ .name = "_serialisedOutputs" } } },
            .{ .name = "t_offset", .value = .{ .load_const = .{ .value = .{ .int = 0 } } } },
            .{ .name = "t_len34", .value = .{ .load_const = .{ .value = .{ .int = 34 } } } },
            .{ .name = "t_extracted", .value = .{ .call = .{ .func = "substr", .args = &substr_args.a } } },
            .{ .name = "t_outEq", .value = .{ .bin_op = .{ .op = "===", .left = "t_extracted", .right = "t_expected", .result_type = "bytes" } } },
            .{ .name = "assertOut", .value = .{ .assert_node = .{ .value = "t_outEq" } } },
            // Increment count
            .{ .name = "t_count", .value = .{ .load_prop = .{ .name = "count" } } },
            .{ .name = "t_one", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "t_newCount", .value = .{ .bin_op = .{ .op = "+", .left = "t_count", .right = "t_one", .result_type = "int" } } },
            .{ .name = "updCount", .value = .{ .update_prop = .{ .name = "count", .value = "t_newCount" } } },
        };
    };
    const methods = struct {
        var m = [_]ANFMethod{
            .{ .name = "payBond", .params = &params.p, .body = &body.b, .is_public = true },
        };
    };
    return .{
        .contract_name = "IntentOutputP2PKH",
        .properties = &props.p,
        .methods = &methods.m,
    };
}

test "intent-output-p2pkh — success: serialised P2PKH matches → count increments" {
    const allocator = std.testing.allocator;
    const anf = buildIntentOutputP2PKHAnf();

    const pkh_bytes = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
    };
    const bond_amount: u64 = 5000;
    const serialised = try p2pkhOutput(allocator, bond_amount, &pkh_bytes);
    defer allocator.free(serialised);
    const serialised_hex = try hexEncode(allocator, serialised);
    defer allocator.free(serialised_hex);
    const out_hash_hex = try hash256Hex(allocator, serialised);
    defer allocator.free(out_hash_hex);
    const pkh_hex = try hexEncode(allocator, &pkh_bytes);
    defer allocator.free(pkh_hex);

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("bondPKH", .{ .bytes = pkh_hex });
    try current_state.put("bondAmount", .{ .int = @intCast(bond_amount) });
    try current_state.put("count", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();

    var mock = MockEnv.init(allocator);
    defer mock.deinit();
    try mock.setSerialisedOutputs(serialised_hex);
    mock.setMockPreimageBytes(out_hash_hex);

    var result = try interp.executeStrictWithMockEnv(
        allocator, &anf, "payBond", current_state, args, &.{}, &mock,
    );
    defer freeResult(allocator, &result);

    try std.testing.expectEqual(@as(i64, 1), result.state.get("count").?.int);
}

test "intent-output-p2pkh — failure: wrong pubkey-hash → per-output AssertionFailure" {
    const allocator = std.testing.allocator;
    const anf = buildIntentOutputP2PKHAnf();

    // Build serialised outputs with WRONG pkh (matches preimage outputHash
    // so the OUTER hash check passes, but the per-output substring check
    // against expectedPKH trips).
    const real_pkh = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
    };
    const wrong_pkh = [_]u8{0xff} ** 20;
    const bond_amount: u64 = 5000;
    const wrong_serialised = try p2pkhOutput(allocator, bond_amount, &wrong_pkh);
    defer allocator.free(wrong_serialised);
    const wrong_hex = try hexEncode(allocator, wrong_serialised);
    defer allocator.free(wrong_hex);
    const wrong_out_hash_hex = try hash256Hex(allocator, wrong_serialised);
    defer allocator.free(wrong_out_hash_hex);
    const real_pkh_hex = try hexEncode(allocator, &real_pkh);
    defer allocator.free(real_pkh_hex);

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("bondPKH", .{ .bytes = real_pkh_hex });
    try current_state.put("bondAmount", .{ .int = @intCast(bond_amount) });
    try current_state.put("count", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();

    var mock = MockEnv.init(allocator);
    defer mock.deinit();
    try mock.setSerialisedOutputs(wrong_hex);
    mock.setMockPreimageBytes(wrong_out_hash_hex);

    const result = interp.executeStrictWithMockEnv(
        allocator, &anf, "payBond", current_state, args, &.{}, &mock,
    );
    try std.testing.expectError(StrictError.AssertionFailure, result);
}

test "intent-output-p2pkh — failure: hashOutputs mismatch → outer AssertionFailure" {
    const allocator = std.testing.allocator;
    const anf = buildIntentOutputP2PKHAnf();

    const pkh_bytes = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
    };
    const bond_amount: u64 = 5000;
    const serialised = try p2pkhOutput(allocator, bond_amount, &pkh_bytes);
    defer allocator.free(serialised);
    const serialised_hex = try hexEncode(allocator, serialised);
    defer allocator.free(serialised_hex);
    const pkh_hex = try hexEncode(allocator, &pkh_bytes);
    defer allocator.free(pkh_hex);

    // Override outputHash to all zeros → outer hash check fails.
    const wrong_out_hash_hex = try allocator.dupe(u8, "00" ** 32);
    defer allocator.free(wrong_out_hash_hex);

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("bondPKH", .{ .bytes = pkh_hex });
    try current_state.put("bondAmount", .{ .int = @intCast(bond_amount) });
    try current_state.put("count", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();

    var mock = MockEnv.init(allocator);
    defer mock.deinit();
    try mock.setSerialisedOutputs(serialised_hex);
    mock.setMockPreimageBytes(wrong_out_hash_hex);

    const result = interp.executeStrictWithMockEnv(
        allocator, &anf, "payBond", current_state, args, &.{}, &mock,
    );
    try std.testing.expectError(StrictError.AssertionFailure, result);
}

// ---------------------------------------------------------------------------
// IntentCurrentBlockHeight: ANF body matching the `spend` method desugar.
//
// Source method body:
//   const h = currentBlockHeight();
//   assert(h <= this.deadline);
//   this.count = this.count + 1n;
//
// ANF lowering:
//   t_preimage = load_param txPreimage
//   t_height   = call extractLocktime(t_preimage)
//   t_deadline = load_prop deadline
//   t_le       = bin_op <= t_height t_deadline
//   _          = assert t_le
//   t_count    = load_prop count
//   t_one      = load_const 1
//   t_newCount = bin_op + t_count t_one
//   _          = update_prop count = t_newCount
// ---------------------------------------------------------------------------

fn buildIntentCurrentBlockHeightAnf() ANFProgram {
    const props = struct {
        var p = [_]ANFProperty{
            .{ .name = "deadline", .type_name = "int", .readonly = true },
            .{ .name = "count", .type_name = "int", .readonly = false },
        };
    };
    const params = struct {
        var p = [_]ANFParam{
            .{ .name = "txPreimage", .type_name = "bytes" },
        };
    };
    const lock_args = struct {
        var a = [_][]const u8{"t_preimage"};
    };
    const body = struct {
        var b = [_]ANFBinding{
            .{ .name = "t_preimage", .value = .{ .load_param = .{ .name = "txPreimage" } } },
            .{ .name = "t_height", .value = .{ .call = .{ .func = "extractLocktime", .args = &lock_args.a } } },
            .{ .name = "t_deadline", .value = .{ .load_prop = .{ .name = "deadline" } } },
            .{ .name = "t_le", .value = .{ .bin_op = .{ .op = "<=", .left = "t_height", .right = "t_deadline", .result_type = "bool" } } },
            .{ .name = "assertLe", .value = .{ .assert_node = .{ .value = "t_le" } } },
            .{ .name = "t_count", .value = .{ .load_prop = .{ .name = "count" } } },
            .{ .name = "t_one", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "t_newCount", .value = .{ .bin_op = .{ .op = "+", .left = "t_count", .right = "t_one", .result_type = "int" } } },
            .{ .name = "updCount", .value = .{ .update_prop = .{ .name = "count", .value = "t_newCount" } } },
        };
    };
    const methods = struct {
        var m = [_]ANFMethod{
            .{ .name = "spend", .params = &params.p, .body = &body.b, .is_public = true },
        };
    };
    return .{
        .contract_name = "IntentCurrentBlockHeight",
        .properties = &props.p,
        .methods = &methods.m,
    };
}

test "intent-current-block-height — success: locktime <= deadline → count increments" {
    const allocator = std.testing.allocator;
    const anf = buildIntentCurrentBlockHeightAnf();

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("deadline", .{ .int = 1_000_000 });
    try current_state.put("count", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();

    var mock = MockEnv.init(allocator);
    defer mock.deinit();
    mock.setMockPreimage(.{ .locktime = 500_000 });

    var result = try interp.executeStrictWithMockEnv(
        allocator, &anf, "spend", current_state, args, &.{}, &mock,
    );
    defer freeResult(allocator, &result);

    try std.testing.expectEqual(@as(i64, 1), result.state.get("count").?.int);
}

test "intent-current-block-height — failure: locktime > deadline → AssertionFailure" {
    const allocator = std.testing.allocator;
    const anf = buildIntentCurrentBlockHeightAnf();

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("deadline", .{ .int = 100 });
    try current_state.put("count", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();

    var mock = MockEnv.init(allocator);
    defer mock.deinit();
    mock.setMockPreimage(.{ .locktime = 999_999 });

    const result = interp.executeStrictWithMockEnv(
        allocator, &anf, "spend", current_state, args, &.{}, &mock,
    );
    try std.testing.expectError(StrictError.AssertionFailure, result);
}

// ---------------------------------------------------------------------------
// BranchedReadonlyLen: ANF body matching the `spend(scratch)` method.
//
// Source method body:
//   if (len(scratch) > 0n) {
//     this.count = this.count + 1n;
//     this.tag = scratch;
//   } else {
//     this.count = this.count - 1n;
//     this.tag = '3030';
//   }
//   this.addOutput(1000n, this.count, this.tag);
//
// ANF lowering (just the branch + addOutput; no intent intrinsic here —
// this fixture exercises the affine checker, not a witness bridge):
//   t_scratch = load_param scratch
//   t_len     = call len(t_scratch)
//   t_zero    = load_const 0
//   t_cond    = bin_op > t_len t_zero
//   _ = if t_cond
//         then:
//           t0  = load_prop count
//           t1  = load_const 1
//           t2  = bin_op + t0 t1
//           _   = update_prop count = t2
//           _   = update_prop tag = t_scratch
//         else:
//           t3  = load_prop count
//           t4  = load_const 1
//           t5  = bin_op - t3 t4
//           _   = update_prop count = t5
//           t6  = load_const "3030"
//           _   = update_prop tag = t6
//   t_sat   = load_const 1000
//   t_newCt = load_prop count
//   t_newTg = load_prop tag
//   _ = add_output [t_newCt, t_newTg]
// ---------------------------------------------------------------------------

fn buildBranchedReadonlyLenAnf() ANFProgram {
    const props = struct {
        var p = [_]ANFProperty{
            .{ .name = "count", .type_name = "int", .readonly = false },
            .{ .name = "tag", .type_name = "bytes", .readonly = false },
        };
    };
    const params = struct {
        var p = [_]ANFParam{
            .{ .name = "scratch", .type_name = "bytes" },
        };
    };
    const len_args = struct {
        var a = [_][]const u8{"t_scratch"};
    };
    const then_body = struct {
        var b = [_]ANFBinding{
            .{ .name = "t_thenC", .value = .{ .load_prop = .{ .name = "count" } } },
            .{ .name = "t_thenOne", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "t_thenInc", .value = .{ .bin_op = .{ .op = "+", .left = "t_thenC", .right = "t_thenOne", .result_type = "int" } } },
            .{ .name = "thenUpdC", .value = .{ .update_prop = .{ .name = "count", .value = "t_thenInc" } } },
            .{ .name = "thenUpdT", .value = .{ .update_prop = .{ .name = "tag", .value = "t_scratch" } } },
        };
    };
    const else_body = struct {
        var b = [_]ANFBinding{
            .{ .name = "t_elseC", .value = .{ .load_prop = .{ .name = "count" } } },
            .{ .name = "t_elseOne", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "t_elseDec", .value = .{ .bin_op = .{ .op = "-", .left = "t_elseC", .right = "t_elseOne", .result_type = "int" } } },
            .{ .name = "elseUpdC", .value = .{ .update_prop = .{ .name = "count", .value = "t_elseDec" } } },
            .{ .name = "t_elseTag", .value = .{ .load_const = .{ .value = .{ .bytes = "3030" } } } },
            .{ .name = "elseUpdT", .value = .{ .update_prop = .{ .name = "tag", .value = "t_elseTag" } } },
        };
    };
    const add_out_refs = struct {
        var a = [_][]const u8{ "t_newCt", "t_newTg" };
    };
    const body = struct {
        var b = [_]ANFBinding{
            .{ .name = "t_scratch", .value = .{ .load_param = .{ .name = "scratch" } } },
            .{ .name = "t_len", .value = .{ .call = .{ .func = "len", .args = &len_args.a } } },
            .{ .name = "t_zero", .value = .{ .load_const = .{ .value = .{ .int = 0 } } } },
            .{ .name = "t_cond", .value = .{ .bin_op = .{ .op = ">", .left = "t_len", .right = "t_zero", .result_type = "bool" } } },
            .{ .name = "branch", .value = .{ .if_node = .{ .cond = "t_cond", .then_branch = &then_body.b, .else_branch = &else_body.b } } },
            .{ .name = "t_sat", .value = .{ .load_const = .{ .value = .{ .int = 1000 } } } },
            .{ .name = "t_newCt", .value = .{ .load_prop = .{ .name = "count" } } },
            .{ .name = "t_newTg", .value = .{ .load_prop = .{ .name = "tag" } } },
            .{ .name = "addOut", .value = .{ .add_output = .{ .state_values = &add_out_refs.a } } },
        };
    };
    const methods = struct {
        var m = [_]ANFMethod{
            .{ .name = "spend", .params = &params.p, .body = &body.b, .is_public = true },
        };
    };
    return .{
        .contract_name = "BranchedReadonlyLen",
        .properties = &props.p,
        .methods = &methods.m,
    };
}

test "branched-readonly-len — then-branch: len(scratch) > 0 → count += 1, tag := scratch" {
    const allocator = std.testing.allocator;
    const anf = buildBranchedReadonlyLenAnf();

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("count", .{ .int = 10 });
    try current_state.put("tag", .{ .bytes = "00" });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();
    try args.put("scratch", .{ .bytes = "aabbcc" });

    var mock = MockEnv.init(allocator);
    defer mock.deinit();

    var result = try interp.executeStrictWithMockEnv(
        allocator, &anf, "spend", current_state, args, &.{}, &mock,
    );
    defer freeResult(allocator, &result);

    try std.testing.expectEqual(@as(i64, 11), result.state.get("count").?.int);
    try std.testing.expectEqualStrings("aabbcc", result.state.get("tag").?.bytes);
}

test "branched-readonly-len — else-branch: len(scratch) == 0 → count -= 1, tag := \"3030\"" {
    const allocator = std.testing.allocator;
    const anf = buildBranchedReadonlyLenAnf();

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("count", .{ .int = 10 });
    try current_state.put("tag", .{ .bytes = "aa" });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();
    try args.put("scratch", .{ .bytes = "" });

    var mock = MockEnv.init(allocator);
    defer mock.deinit();

    var result = try interp.executeStrictWithMockEnv(
        allocator, &anf, "spend", current_state, args, &.{}, &mock,
    );
    defer freeResult(allocator, &result);

    try std.testing.expectEqual(@as(i64, 9), result.state.get("count").?.int);
    try std.testing.expectEqualStrings("3030", result.state.get("tag").?.bytes);
}
