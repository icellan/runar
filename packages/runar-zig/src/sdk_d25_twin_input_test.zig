//! D25 (twin-input binding) — the Zig SDK builds honest call chains for both
//! post-D25 contract shapes. Port of the honest-chain half of
//! packages/runar-sdk/src/__tests__/d25-twin-input.test.ts.
//!
//!   class 1 (Counter, every continuation method mutate-only): the methods
//!     carry ABI sigHashType 0x43, take `_newAmount, txPreimage` (no change
//!     params), the preimage is built under SIGHASH_SINGLE|FORKID and the
//!     continuation sits at output 0 (the contract's input index).
//!   class 2 (MixedPot, mutate-only `increment` beside an addOutput `bump`):
//!     a hidden last state field `_spentOutpointHash`, zero at deploy, set by
//!     every call to sha256 of the REAL outpoint the call spends.
//!
//! The Zig tier has no ScriptVM, so the covenant is not executed. What each
//! test checks instead, independently of the SDK's own bookkeeping, is the
//! relation the covenant enforces:
//!   - the BIP-143 preimage pushed in input 0's unlocking script is the one
//!     bsvz computes for the broadcast tx under the method's mode (so
//!     checkPreimage would accept it), its sighash-type field is that mode,
//!     and its hashOutputs field is hash256 of exactly the outputs the mode
//!     commits (output 0 alone for SINGLE; all outputs for ALL);
//!   - output 0 is the contract's code part + OP_RETURN + the state the SDK
//!     derived, and that state is the expected post-state, with (class 2) the
//!     hidden field equal to sha256 of the preimage's own outpoint field —
//!     the value `sha256(extractOutpoint(txPreimage))` yields on-chain;
//!   - the second call spends the first call's continuation.
//! Does NOT prove: script acceptance (the opcode-level comparison
//! hash256(computeStateOutput) == hashOutputs and the code-part / state
//! deserialization run only on a real interpreter: the TS @bsv/sdk Spend and
//! Go interpreter twin tests, plus the conformance goldens this tier's
//! compiler reproduces), nor the twin attacks themselves.

const std = @import("std");
const frontend = @import("runar_frontend");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");
const oppushtx = @import("sdk_oppushtx.zig");
const errors_mod = @import("sdk_errors.zig");

const KEY = "00" ** 31 ++ "07";
const FUND_SCRIPT = "76a914" ++ "00" ** 20 ++ "88ac";

const COUNTER =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class Counter extends StatefulSmartContract {
    \\  count: bigint;
    \\  constructor(count: bigint) { super(count); this.count = count; }
    \\  public increment() { this.count++; }
    \\  public decrement() { assert(this.count > 0n); this.count--; }
    \\}
;

const MIXED =
    \\import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';
    \\class MixedPot extends StatefulSmartContract {
    \\  count: bigint;
    \\  constructor(count: bigint) { super(count); this.count = count; }
    \\  public increment() { this.count++; }
    \\  public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }
    \\}
;

const SIG_COUNTER =
    \\import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
    \\import type { PubKey, Sig } from 'runar-lang';
    \\class SigCounter extends StatefulSmartContract {
    \\  count: bigint;
    \\  readonly owner: PubKey;
    \\  constructor(count: bigint, owner: PubKey) { super(count, owner); this.count = count; this.owner = owner; }
    \\  public increment(sig: Sig) { assert(checkSig(sig, this.owner)); this.count++; }
    \\}
;

// ---------------------------------------------------------------------------
// tx parsing (hex in, hex slices out)
// ---------------------------------------------------------------------------

fn byteAt(h: []const u8, off: usize) u8 {
    return std.fmt.parseInt(u8, h[off * 2 .. off * 2 + 2], 16) catch unreachable;
}

fn varInt(h: []const u8, cur: *usize) usize {
    const first = byteAt(h, cur.*);
    cur.* += 1;
    if (first < 0xfd) return first;
    const n: usize = if (first == 0xfd) 2 else if (first == 0xfe) 4 else 8;
    var v: usize = 0;
    for (0..n) |b| {
        v |= @as(usize, byteAt(h, cur.*)) << @intCast(8 * b);
        cur.* += 1;
    }
    return v;
}

const Output = struct { sats: u64, script: []const u8, raw: []const u8 };

const Tx = struct {
    input0_outpoint: []const u8,
    input0_unlock: []const u8,
    outputs: [8]Output = undefined,
    n_out: usize = 0,
    outputs_raw: []const u8,
};

fn parseTx(h: []const u8) Tx {
    var cur: usize = 4;
    const n_in = varInt(h, &cur);
    var tx: Tx = .{ .input0_outpoint = "", .input0_unlock = "", .outputs_raw = "" };
    for (0..n_in) |k| {
        const op = h[cur * 2 .. (cur + 36) * 2];
        cur += 36;
        const slen = varInt(h, &cur);
        if (k == 0) {
            tx.input0_outpoint = op;
            tx.input0_unlock = h[cur * 2 .. (cur + slen) * 2];
        }
        cur += slen + 4;
    }
    tx.n_out = varInt(h, &cur);
    const outs_start = cur;
    for (0..tx.n_out) |i| {
        const start = cur;
        var v: u64 = 0;
        for (0..8) |b| v |= @as(u64, byteAt(h, cur + b)) << @intCast(8 * b);
        cur += 8;
        const slen = varInt(h, &cur);
        tx.outputs[i] = .{ .sats = v, .script = h[cur * 2 .. (cur + slen) * 2], .raw = h[start * 2 .. (cur + slen) * 2] };
        cur += slen;
    }
    tx.outputs_raw = h[outs_start * 2 .. cur * 2];
    return tx;
}

/// BIP-143 outpoint of `txid:vout` as the preimage carries it (txid bytes
/// reversed from display order, vout u32 LE), computed here independently.
fn wireOutpoint(buf: *[72]u8, txid: []const u8, vout: u32) []const u8 {
    for (0..32) |i| {
        buf[i * 2] = txid[(31 - i) * 2];
        buf[i * 2 + 1] = txid[(31 - i) * 2 + 1];
    }
    const hx = "0123456789abcdef";
    for (0..4) |b| {
        const byte: u8 = @truncate(vout >> @intCast(b * 8));
        buf[64 + b * 2] = hx[byte >> 4];
        buf[64 + b * 2 + 1] = hx[byte & 0x0f];
    }
    return buf[0..72];
}

fn sha256Hex(a: std.mem.Allocator, hex: []const u8) ![64]u8 {
    const raw = try a.alloc(u8, hex.len / 2);
    defer a.free(raw);
    _ = try std.fmt.hexToBytes(raw, hex);
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &d, .{});
    return std.fmt.bytesToHex(d, .lower);
}

fn hash256Hex(a: std.mem.Allocator, hex: []const u8) ![64]u8 {
    const once = try sha256Hex(a, hex);
    return sha256Hex(a, &once);
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

const Fixture = struct {
    compiled: frontend.CompileResult,
    artifact: types.RunarArtifact,
    prov: provider_mod.MockProvider,
    signer: signer_mod.LocalSigner,

    fn deinit(self: *Fixture, a: std.mem.Allocator) void {
        self.prov.deinit();
        self.artifact.deinit();
        self.compiled.deinit(a);
    }
};

fn setup(a: std.mem.Allocator, fx: *Fixture, src: []const u8, file: []const u8) !void {
    fx.compiled = try frontend.compileSource(a, src, file);
    fx.artifact = try types.RunarArtifact.fromJson(a, fx.compiled.artifact_json.?);
    // The SDK derives state from the artifact's ANF; without it call() keeps
    // the old state and every assertion below would be about nothing.
    try std.testing.expect(fx.artifact.anf_json != null);
    fx.prov = provider_mod.MockProvider.init(a, "testnet");
    fx.signer = try signer_mod.LocalSigner.fromHex(KEY);
    const addr = try fx.signer.signer().getAddress(a);
    defer a.free(addr);
    for ([_][]const u8{ "aa" ** 32, "bb" ** 32, "cc" ** 32, "dd" ** 32 }) |t| {
        try fx.prov.addUtxo(addr, .{ .txid = t, .output_index = 0, .satoshis = 500_000, .script = FUND_SCRIPT });
    }
}

fn abiMethod(art: *const types.RunarArtifact, name: []const u8) types.ABIMethod {
    for (art.abi.methods) |m| {
        if (std.mem.eql(u8, m.name, name)) return m;
    }
    unreachable;
}

fn publicIndex(art: *const types.RunarArtifact, name: []const u8) usize {
    var i: usize = 0;
    for (art.abi.methods) |m| {
        if (!m.is_public) continue;
        if (std.mem.eql(u8, m.name, name)) return i;
        i += 1;
    }
    unreachable;
}

const Expect = struct { mode: u32, commits_all_outputs: bool };

/// Call `method` and check the broadcast tx against the covenant relation
/// (see the module comment). Returns the parsed tx (borrowing the
/// provider's copy) and the preimage hex (caller frees).
fn callAndCheck(
    a: std.mem.Allocator,
    fx: *Fixture,
    c: *contract_mod.RunarContract,
    method: []const u8,
    want: Expect,
    args: []const types.StateValue,
    opts: ?types.CallOptions,
) !struct { tx: Tx, preimage: []u8 } {
    const spent = c.getCurrentUtxo().?;
    const spent_txid = try a.dupe(u8, spent.txid);
    defer a.free(spent_txid);
    const spent_script = try a.dupe(u8, spent.script);
    defer a.free(spent_script);
    const spent_vout: u32 = @intCast(spent.output_index);
    const spent_sats = spent.satoshis;
    const code_sep = (try c.getCodeSepIndex(publicIndex(&fx.artifact, method))) orelse -1;

    const txid = try c.call(method, args, fx.prov.provider(), fx.signer.signer(), opts);
    defer a.free(txid);

    const txs = fx.prov.getBroadcastedTxs();
    const tx_hex = txs[txs.len - 1];
    const tx = parseTx(tx_hex);

    // Input 0 spends the contract UTXO the call was made from.
    var ob: [72]u8 = undefined;
    const outpoint = wireOutpoint(&ob, spent_txid, spent_vout);
    try std.testing.expectEqualStrings(outpoint, tx.input0_outpoint);

    // The preimage bsvz computes for this tx, input 0, under the method's
    // mode, is the one pushed in input 0's unlocking script.
    const pre = try oppushtx.computeOpPushTxPreimageWithSigHash(a, tx_hex, 0, spent_script, spent_sats, code_sep, want.mode);
    defer a.free(pre.sig_hex);
    const p = pre.preimage_hex;
    try std.testing.expect(std.mem.indexOf(u8, tx.input0_unlock, p) != null);
    // Its fields: sighash type, the spent outpoint, hashOutputs.
    var mode_le: [8]u8 = undefined;
    _ = try std.fmt.bufPrint(&mode_le, "{x:0>2}000000", .{want.mode});
    try std.testing.expectEqualStrings(&mode_le, p[p.len - 8 ..]);
    try std.testing.expectEqualStrings(outpoint, p[68 * 2 .. 104 * 2]);
    const committed = if (want.commits_all_outputs) tx.outputs_raw else tx.outputs[0].raw;
    const want_hash = try hash256Hex(a, committed);
    try std.testing.expectEqualStrings(&want_hash, p[p.len - 80 .. p.len - 16]);

    // Output 0 is the contract's continuation with the SDK's derived state.
    const lock = try c.getLockingScript();
    defer a.free(lock);
    try std.testing.expectEqualStrings(lock, tx.outputs[0].script);
    return .{ .tx = tx, .preimage = p };
}

// ---------------------------------------------------------------------------
// class 1
// ---------------------------------------------------------------------------

test "D25 class 1: Counter's ABI is SINGLE with no change params" {
    const a = std.testing.allocator;
    var fx: Fixture = undefined;
    try setup(a, &fx, COUNTER, "Counter.runar.ts");
    defer fx.deinit(a);
    for ([_][]const u8{ "increment", "decrement" }) |name| {
        const m = abiMethod(&fx.artifact, name);
        try std.testing.expectEqual(@as(?i64, 0x43), m.sig_hash_type);
        try std.testing.expectEqual(@as(usize, 2), m.params.len);
        try std.testing.expectEqualStrings("_newAmount", m.params[0].name);
        try std.testing.expectEqualStrings("txPreimage", m.params[1].name);
    }
    try std.testing.expectEqual(@as(usize, 1), fx.artifact.state_fields.len);
}

test "D25 class 1: two chained Counter calls build SINGLE spends whose continuation is output 0" {
    const a = std.testing.allocator;
    var fx: Fixture = undefined;
    try setup(a, &fx, COUNTER, "Counter.runar.ts");
    defer fx.deinit(a);
    const ctor = [_]types.StateValue{.{ .int = 0 }};
    var c = try contract_mod.RunarContract.init(a, &fx.artifact, &ctor);
    defer c.deinit();
    const deploy_txid = try c.deploy(fx.prov.provider(), fx.signer.signer(), .{ .satoshis = 10_000 });
    defer a.free(deploy_txid);

    var prev_txid = try a.dupe(u8, deploy_txid);
    defer a.free(prev_txid);
    for ([_]i64{ 1, 2 }) |want_count| {
        const r = try callAndCheck(a, &fx, &c, "increment", .{ .mode = 0x43, .commits_all_outputs = false }, &.{}, null);
        defer a.free(r.preimage);
        try std.testing.expectEqual(want_count, c.state[0].int);
        // The continuation keeps the input value (the F-024 floor) and the
        // change after it exists but is not committed by SINGLE.
        try std.testing.expectEqual(@as(u64, 10_000), r.tx.outputs[0].sats);
        try std.testing.expect(r.tx.n_out >= 2);
        const all = try hash256Hex(a, r.tx.outputs_raw);
        try std.testing.expect(!std.mem.eql(u8, &all, r.preimage[r.preimage.len - 80 .. r.preimage.len - 16]));
        // The tracked UTXO is this call's output 0.
        const cur = c.getCurrentUtxo().?;
        try std.testing.expectEqual(@as(usize, 0), @as(usize, @intCast(cur.output_index)));
        try std.testing.expect(!std.mem.eql(u8, cur.txid, prev_txid));
        a.free(prev_txid);
        prev_txid = try a.dupe(u8, cur.txid);
    }
}

// ---------------------------------------------------------------------------
// class 2
// ---------------------------------------------------------------------------

test "D25 class 2: MixedPot's increment and bump chain, each binding the outpoint it spends" {
    const a = std.testing.allocator;
    var fx: Fixture = undefined;
    try setup(a, &fx, MIXED, "MixedPot.runar.ts");
    defer fx.deinit(a);

    // Hidden trailing field, zero at deploy from the artifact, not a ctor arg.
    try std.testing.expectEqual(@as(usize, 2), fx.artifact.state_fields.len);
    try std.testing.expectEqualStrings("_spentOutpointHash", fx.artifact.state_fields[1].name);
    try std.testing.expectEqualStrings("00" ** 32, fx.artifact.state_fields[1].initial_value.?);
    try std.testing.expectEqual(@as(usize, 1), fx.artifact.abi.constructor.params.len);
    for ([_][]const u8{ "increment", "bump" }) |name| {
        try std.testing.expectEqual(@as(?i64, null), abiMethod(&fx.artifact, name).sig_hash_type);
    }

    const ctor = [_]types.StateValue{.{ .int = 5 }};
    var c = try contract_mod.RunarContract.init(a, &fx.artifact, &ctor);
    defer c.deinit();
    const deploy_txid = try c.deploy(fx.prov.provider(), fx.signer.signer(), .{ .satoshis = 10_000 });
    defer a.free(deploy_txid);
    try std.testing.expectEqualStrings("00" ** 32, c.state[1].bytes);
    {
        const lock = try c.getLockingScript();
        defer a.free(lock);
        // The state section is fixed-width raw bytes (no push opcodes), the
        // hidden field last.
        try std.testing.expect(std.mem.endsWith(u8, lock, "00" ** 32));
    }

    var first_hash: [64]u8 = undefined;
    // 1) increment: the auto-continuation writes sha256(spent outpoint).
    {
        const r = try callAndCheck(a, &fx, &c, "increment", .{ .mode = 0x41, .commits_all_outputs = true }, &.{}, null);
        defer a.free(r.preimage);
        try std.testing.expectEqual(@as(i64, 6), c.state[0].int);
        const h = try sha256Hex(a, r.preimage[68 * 2 .. 104 * 2]);
        try std.testing.expectEqualStrings(&h, c.state[1].bytes);
        try std.testing.expect(std.mem.endsWith(u8, r.tx.outputs[0].script, &h));
        first_hash = h;
    }
    // 2) bump: addOutput(extractAmount, count + 1) carries the new outpoint's hash.
    {
        const in_sats = c.getCurrentUtxo().?.satoshis;
        const r = try callAndCheck(a, &fx, &c, "bump", .{ .mode = 0x41, .commits_all_outputs = true }, &.{}, null);
        defer a.free(r.preimage);
        try std.testing.expectEqual(@as(i64, 7), c.state[0].int);
        const h = try sha256Hex(a, r.preimage[68 * 2 .. 104 * 2]);
        try std.testing.expectEqualStrings(&h, c.state[1].bytes);
        try std.testing.expect(std.mem.endsWith(u8, r.tx.outputs[0].script, &h));
        try std.testing.expect(!std.mem.eql(u8, &h, &first_hash));
        try std.testing.expectEqual(@as(u64, @intCast(in_sats)), r.tx.outputs[0].sats);
    }
}

// ---------------------------------------------------------------------------
// SDK rules
// ---------------------------------------------------------------------------

test "D25: additional_contract_inputs into a SINGLE continuation is refused before anything is built" {
    const a = std.testing.allocator;
    var fx: Fixture = undefined;
    try setup(a, &fx, COUNTER, "Counter.runar.ts");
    defer fx.deinit(a);
    const ctor = [_]types.StateValue{.{ .int = 0 }};
    var c = try contract_mod.RunarContract.init(a, &fx.artifact, &ctor);
    defer c.deinit();
    const deploy_txid = try c.deploy(fx.prov.provider(), fx.signer.signer(), .{ .satoshis = 10_000 });
    defer a.free(deploy_txid);
    const n_before = fx.prov.getBroadcastedTxs().len;

    const twin = [_]types.UTXO{.{ .txid = "ee" ** 32, .output_index = 0, .satoshis = 10_000, .script = c.getCurrentUtxo().?.script }};
    const args = [_]types.StateValue{};
    errors_mod.last_single_merge_len = 0;
    try std.testing.expectError(
        contract_mod.ContractError.SingleContinuationMergeUnsupported,
        c.call("increment", &args, fx.prov.provider(), fx.signer.signer(), .{ .additional_contract_inputs = &twin }),
    );
    try std.testing.expectEqualStrings(
        "RunarContract.call(increment): additionalContractInputs cannot be spent into one continuation by a " ++
            "SIGHASH_SINGLE method (the default for a contract whose continuation methods are all mutate-only, D25): " ++
            "SINGLE commits each input to its own output at its own index. Merge with an addOutput method instead " ++
            "(see FungibleToken.merge), or build each input's continuation with assembleMultiContractCall",
        errors_mod.lastSingleMergeMessage(),
    );
    const ns = [_]types.StateValue{.{ .int = 1 }};
    try std.testing.expectError(
        contract_mod.ContractError.SingleContinuationMergeUnsupported,
        c.prepareCall("increment", &args, fx.prov.provider(), fx.signer.signer(), .{ .additional_contract_inputs = &twin, .new_state = &ns }),
    );
    try std.testing.expectEqual(n_before, fx.prov.getBroadcastedTxs().len);
    try std.testing.expectEqual(@as(i64, 0), c.state[0].int);
}

test "D25: under a SINGLE covenant prepareCall hands out the ALL|FORKID digest for a user Sig" {
    const a = std.testing.allocator;
    var fx: Fixture = undefined;
    try setup(a, &fx, SIG_COUNTER, "SigCounter.runar.ts");
    defer fx.deinit(a);
    try std.testing.expectEqual(@as(?i64, 0x43), abiMethod(&fx.artifact, "increment").sig_hash_type);

    const pk = try fx.signer.signer().getPublicKey(a);
    defer a.free(pk);
    const ctor = [_]types.StateValue{ .{ .int = 0 }, .{ .bytes = pk } };
    var c = try contract_mod.RunarContract.init(a, &fx.artifact, &ctor);
    defer c.deinit();
    const deploy_txid = try c.deploy(fx.prov.provider(), fx.signer.signer(), .{ .satoshis = 10_000 });
    defer a.free(deploy_txid);

    const utxo = c.getCurrentUtxo().?;
    const code_sep = (try c.getCodeSepIndex(0)) orelse -1;
    const args = [_]types.StateValue{.{ .int = 0 }};
    const ns = [_]types.StateValue{.{ .int = 1 }};
    var prepared = try c.prepareCall("increment", &args, fx.prov.provider(), fx.signer.signer(), .{ .new_state = &ns });
    defer prepared.deinit(a);
    try std.testing.expectEqual(@as(usize, 1), prepared.sighashes.len);

    // The covenant preimage is SINGLE ...
    try std.testing.expectEqualStrings("43000000", prepared.preimage[prepared.preimage.len - 8 ..]);
    // ... while the user's Sig (which every signer suffixes with 0x41) must
    // sign the ALL|FORKID digest of the same tx, input and subscript.
    var all = try oppushtx.computeOpPushTxPreimageWithSigHash(a, prepared.tx_hex, 0, utxo.script, utxo.satoshis, code_sep, 0x41);
    defer all.deinit(a);
    var single = try oppushtx.computeOpPushTxPreimageWithSigHash(a, prepared.tx_hex, 0, utxo.script, utxo.satoshis, code_sep, 0x43);
    defer single.deinit(a);
    const want_all = try hash256Hex(a, all.preimage_hex);
    const not_single = try hash256Hex(a, single.preimage_hex);
    try std.testing.expectEqualStrings(&want_all, prepared.sighashes[0]);
    try std.testing.expect(!std.mem.eql(u8, &not_single, prepared.sighashes[0]));
}

test "D25 class 2: an explicit new_state (user fields only) gets the spent outpoint's hash, in call and prepareCall" {
    const a = std.testing.allocator;
    var fx: Fixture = undefined;
    try setup(a, &fx, MIXED, "MixedPot.runar.ts");
    defer fx.deinit(a);
    const ctor = [_]types.StateValue{.{ .int = 5 }};
    var c = try contract_mod.RunarContract.init(a, &fx.artifact, &ctor);
    defer c.deinit();
    const deploy_txid = try c.deploy(fx.prov.provider(), fx.signer.signer(), .{ .satoshis = 10_000 });
    defer a.free(deploy_txid);

    // call(): the caller names `count` only; the hidden field is appended.
    const ns = [_]types.StateValue{.{ .int = 6 }};
    const r = try callAndCheck(a, &fx, &c, "increment", .{ .mode = 0x41, .commits_all_outputs = true }, &.{}, .{ .new_state = &ns });
    defer a.free(r.preimage);
    try std.testing.expectEqual(@as(usize, 2), c.state.len);
    try std.testing.expectEqual(@as(i64, 6), c.state[0].int);
    const h = try sha256Hex(a, r.preimage[68 * 2 .. 104 * 2]);
    try std.testing.expectEqualStrings(&h, c.state[1].bytes);
    try std.testing.expect(std.mem.endsWith(u8, r.tx.outputs[0].script, &h));

    // prepareCall(): a full state carrying the stale hash is overwritten.
    const cur = c.getCurrentUtxo().?;
    var ob: [72]u8 = undefined;
    const want = try sha256Hex(a, wireOutpoint(&ob, cur.txid, @intCast(cur.output_index)));
    try std.testing.expect(!std.mem.eql(u8, &want, &h));
    const full = [_]types.StateValue{ .{ .int = 7 }, .{ .bytes = &h } };
    var prepared = try c.prepareCall("increment", &.{}, fx.prov.provider(), fx.signer.signer(), .{ .new_state = &full });
    defer prepared.deinit(a);
    try std.testing.expect(std.mem.endsWith(u8, prepared.new_locking_script, &want));
    try std.testing.expectEqualStrings(cur.txid, prepared.contract_utxo.txid);
}

test "D25 class 1: call() and finalizeCall sign a user Sig with ALL|FORKID under the SINGLE covenant" {
    const a = std.testing.allocator;
    var fx: Fixture = undefined;
    try setup(a, &fx, SIG_COUNTER, "SigCounter.runar.ts");
    defer fx.deinit(a);
    const pk = try fx.signer.signer().getPublicKey(a);
    defer a.free(pk);
    const ctor = [_]types.StateValue{ .{ .int = 0 }, .{ .bytes = pk } };
    var c = try contract_mod.RunarContract.init(a, &fx.artifact, &ctor);
    defer c.deinit();
    const deploy_txid = try c.deploy(fx.prov.provider(), fx.signer.signer(), .{ .satoshis = 10_000 });
    defer a.free(deploy_txid);

    // call(): the auto-signed Sig in input 0 is the signer's (deterministic)
    // ALL|FORKID signature over the broadcast tx, not a SINGLE one.
    {
        const utxo = try c.getCurrentUtxo().?.clone(a);
        defer {
            var u = utxo;
            u.deinit(a);
        }
        const code_sep = (try c.getCodeSepIndex(0)) orelse -1;
        const sub = if (code_sep >= 0) utxo.script[@as(usize, @intCast(code_sep + 1)) * 2 ..] else utxo.script;
        const r = try callAndCheck(a, &fx, &c, "increment", .{ .mode = 0x43, .commits_all_outputs = false }, &.{.{ .int = 0 }}, null);
        defer a.free(r.preimage);
        try std.testing.expectEqual(@as(i64, 1), c.state[0].int);
        const txs = fx.prov.getBroadcastedTxs();
        const tx_hex = txs[txs.len - 1];
        const sig_all = try fx.signer.signer().sign(a, tx_hex, 0, sub, utxo.satoshis, null);
        defer a.free(sig_all);
        const sig_single = try fx.signer.signer().sign(a, tx_hex, 0, sub, utxo.satoshis, 0x43);
        defer a.free(sig_single);
        try std.testing.expect(std.mem.endsWith(u8, sig_all, "41"));
        try std.testing.expect(std.mem.indexOf(u8, r.tx.input0_unlock, sig_all) != null);
        try std.testing.expect(std.mem.indexOf(u8, r.tx.input0_unlock, sig_single) == null);
    }

    // prepareCall + finalizeCall: a signature over the handed-out digest's
    // tx/input/subscript under ALL|FORKID lands in input 0 beside the
    // SINGLE covenant preimage.
    {
        const utxo = try c.getCurrentUtxo().?.clone(a);
        defer {
            var u = utxo;
            u.deinit(a);
        }
        const code_sep = (try c.getCodeSepIndex(0)) orelse -1;
        const sub = if (code_sep >= 0) utxo.script[@as(usize, @intCast(code_sep + 1)) * 2 ..] else utxo.script;
        const ns = [_]types.StateValue{.{ .int = 2 }};
        var prepared = try c.prepareCall("increment", &.{.{ .int = 0 }}, fx.prov.provider(), fx.signer.signer(), .{ .new_state = &ns });
        defer prepared.deinit(a);
        const sig = try fx.signer.signer().sign(a, prepared.tx_hex, 0, sub, utxo.satoshis, null);
        defer a.free(sig);
        const sigs = [_][]const u8{sig};
        const txid = try c.finalizeCall(&prepared, &sigs, fx.prov.provider());
        defer a.free(txid);
        const txs = fx.prov.getBroadcastedTxs();
        const tx = parseTx(txs[txs.len - 1]);
        try std.testing.expect(std.mem.indexOf(u8, tx.input0_unlock, sig) != null);
        try std.testing.expect(std.mem.indexOf(u8, tx.input0_unlock, prepared.preimage) != null);
        try std.testing.expectEqualStrings("43000000", prepared.preimage[prepared.preimage.len - 8 ..]);
        try std.testing.expectEqual(@as(i64, 2), c.state[0].int);
    }
}
