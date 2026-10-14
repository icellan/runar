const std = @import("std");
const bsvz = @import("bsvz");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const deploy_mod = @import("sdk_deploy.zig");
const call_mod = @import("sdk_call.zig");
const oppushtx_mod = @import("sdk_oppushtx.zig");
const anf_interp = @import("sdk_anf_interpreter.zig");
const ordinals = @import("sdk_ordinals.zig");
const errors_mod = @import("sdk_errors.zig");
const script_utils = @import("sdk_script_utils.zig");

/// The well-known ByteString parameter the SDK fills in with the transaction's
/// concatenated outpoints (36 bytes per input) once the input list has
/// converged. It is the ONLY ByteString slot for which the `.int = 0` call-arg
/// sentinel is an auto-resolve request rather than a legitimate empty value.
pub const AUTO_PREVOUTS_PARAM_NAME = "allPrevouts";

/// Does the locking script look like OR-CHECKSIG rather than genuine multi-sig?
/// Scopes the issue #106 soft warning.
///
/// ASM, not a hex substring test: searching the hex for "9b" matches any byte
/// pair anywhere, push data included, and even straddles two adjacent opcodes'
/// nibbles.
///
/// NEW-014: `||` no longer lowers to OP_BOOLOR — it lowers to real
/// OP_IF / OP_ELSE / OP_ENDIF control flow. The NULLFAIL hazard SURVIVES that
/// change: when the FIRST branch fails, its OP_CHECKSIG has already run with a
/// non-empty signature, which is exactly what BIP146 rejects. Short-circuiting
/// removes the hazard only when the first branch succeeds, so both the legacy
/// and the branch-shaped forms must warn.
fn isLikelyOrChecksig(artifact: types.RunarArtifact) bool {
    const asm_text = artifact.asm_text;
    if (asm_text.len == 0) return false;
    if (std.mem.indexOf(u8, asm_text, "OP_CHECKMULTISIG") != null) return false;
    if (std.mem.indexOf(u8, asm_text, "OP_CHECKSIG") == null) return false;
    return std.mem.indexOf(u8, asm_text, "OP_BOOLOR") != null or
        std.mem.indexOf(u8, asm_text, "OP_IF") != null;
}

// The issue #106 OR-CHECKSIG gate must recognise BOTH lowerings of `||`.
//
// It went blind once already: it tested for OP_BOOLOR, and NEW-014 stopped the
// compiler emitting that opcode, so the NULLFAIL warning silently never fired.
test "isLikelyOrChecksig recognises both `||` lowerings and excludes multi-sig" {
    const cases = [_]struct { text: []const u8, want: bool }{
        .{ .text = "OP_DUP OP_BOOLOR OP_CHECKSIG", .want = true },
        .{ .text = "OP_IF OP_CHECKSIG OP_ELSE OP_CHECKSIG OP_ENDIF", .want = true },
        .{ .text = "OP_IF OP_CHECKSIG OP_CHECKMULTISIG", .want = false },
        .{ .text = "OP_IF OP_DUP OP_ELSE OP_DROP OP_ENDIF", .want = false },
        .{ .text = "OP_DUP OP_HASH160 OP_CHECKSIG", .want = false },
        .{ .text = "", .want = false },
    };
    for (cases) |c| {
        var artifact: types.RunarArtifact = .{ .allocator = std.testing.allocator };
        artifact.asm_text = c.text;
        try std.testing.expectEqual(c.want, isLikelyOrChecksig(artifact));
    }
}

// ---------------------------------------------------------------------------
// Call-path funding fee-sizing helpers (findings C2 + C15)
// ---------------------------------------------------------------------------

/// Serialized bytes one contract/covenant input adds to the tx (finding C2):
/// prevout(32) + index(4) + varint(unlockLen) + unlockLen + sequence(4). The
/// deploy estimator models ONLY 148-byte P2PKH inputs, so a call spending a
/// contract input (tens of KB for a MERGE that embeds parent txs) under-provisions
/// funding unless these bytes are added. `unlock_hex_len` is the hex string length
/// (2 chars/byte). Mirrors TS `perInputBytes`.
fn contractInputSerializedBytes(unlock_hex_len: usize) i64 {
    const len: usize = unlock_hex_len / 2;
    const vi: usize = if (len < 0xfd) 1 else if (len <= 0xffff) 3 else if (len <= 0xffffffff) 5 else 9;
    return @intCast(32 + 4 + vi + len + 4);
}

/// Serialized framing one output adds to the tx (finding C15):
/// satoshis(8) + varint(scriptLen) + scriptLen. `script_byte_len` is in bytes.
/// Mirrors TS `outputFraming`.
fn outputFramingBytes(script_byte_len: usize) i64 {
    const vi: usize = if (script_byte_len < 0xfd) 1 else if (script_byte_len <= 0xffff) 3 else if (script_byte_len <= 0xffffffff) 5 else 9;
    return @intCast(8 + vi + script_byte_len);
}

// ---------------------------------------------------------------------------
// N-051 — deploy-time code-part length pins
// ---------------------------------------------------------------------------

/// One template substitution: the OP_0 placeholder at TEMPLATE `byte_offset`
/// was replaced by `encoded_len` bytes.
pub const SubShift = struct {
    byte_offset: i32,
    encoded_len: usize,
};

/// N-051 -- write the deployed code-part length into every `codePartLenSlots`
/// field of a spliced code script (hex, patched in place).
///
/// The compiler cannot know the deployed length of a code part that bakes a
/// variable-width readonly constructor arg (a ByteString, a bigint), so the
/// `SIZE(_codePart)` equality pin carries a 4-byte little-endian field the SDK
/// fills in. The field is fixed-width, so writing it changes no length and no
/// offset. A wrong or missing value is fail-safe on chain (honest spends fail
/// OP_NUMEQUAL); it is never a lower bound.
///
/// `subs` are every substitution applied to the template, by TEMPLATE byte
/// offset. `code_part_len` is the deployed code-part length in bytes,
/// including any inscription envelope (it is part of `_codePart`).
pub fn patchCodePartLenSlots(
    artifact: *const types.RunarArtifact,
    spliced: []u8,
    subs: []const SubShift,
    code_part_len: usize,
) !void {
    if (artifact.code_part_len_slots.len == 0) return;
    if (code_part_len > 0x7fffffff) return error.CodePartLenOutOfRange;
    const v: u32 = @intCast(code_part_len);
    var le: [8]u8 = undefined;
    _ = std.fmt.bufPrint(&le, "{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
        @as(u8, @truncate(v)),       @as(u8, @truncate(v >> 8)),
        @as(u8, @truncate(v >> 16)), @as(u8, @truncate(v >> 24)),
    }) catch unreachable;

    const template = artifact.script;
    for (artifact.code_part_len_slots) |slot| {
        // The template must carry `04 <4 bytes> OP_BIN2NUM OP_NUMEQUAL
        // OP_VERIFY` here; anything else means the descriptor does not
        // describe this script.
        if (slot.byte_offset < 1) return error.CodePartLenSlotMismatch;
        const off: usize = @intCast(slot.byte_offset);
        if ((off + 7) * 2 > template.len or
            !std.ascii.eqlIgnoreCase(template[(off - 1) * 2 .. off * 2], "04") or
            !std.ascii.eqlIgnoreCase(template[(off + 4) * 2 .. (off + 7) * 2], "819c69"))
        {
            return error.CodePartLenSlotMismatch;
        }
        var shift: i64 = 0;
        for (subs) |s| {
            if (s.byte_offset < slot.byte_offset) shift += @as(i64, @intCast(s.encoded_len)) - 1;
        }
        const resolved = @as(i64, @intCast(off)) + shift;
        if (resolved < 0) return error.CodePartLenSlotMismatch;
        const at: usize = @intCast(resolved * 2);
        if (at + 8 > spliced.len) return error.CodePartLenSlotMismatch;
        @memcpy(spliced[at .. at + 8], &le);
    }
}

// ---------------------------------------------------------------------------
// RunarContract — main contract runtime wrapper
// ---------------------------------------------------------------------------

/// Decode the value of every EQUALITY `verify_code_part_len` pin in a compiled
/// script.
///
/// The compiler emits the pin as a fixed-width, unambiguous nine-byte run:
///
///     76 | 04 LL LL LL LL | 81 | (9c | a2) | 69
///     OP_DUP  <len LE32>    OP_BIN2NUM  cmp  OP_VERIFY
///
/// `9c` is OP_NUMEQUAL -- an exact pin, the only variant a longer code part can
/// violate. `a2` is OP_GREATERTHANOREQUAL, the pre-N-051 lower bound that extra
/// bytes satisfy, so it is deliberately not returned here (the compiler no
/// longer emits it; old artifacts may still carry it).
///
/// The caller passes the BUILT code script (N-051): a deploy-time pin
/// (`codePartLenSlots`) only carries its real value once the SDK has patched
/// it, so decoding the raw template would compare against a placeholder.
fn decodeExactCodePartLenPins(
    allocator: std.mem.Allocator,
    script_hex: []const u8,
) !std.ArrayListUnmanaged(usize) {
    var values: std.ArrayListUnmanaged(usize) = .empty;
    errdefer values.deinit(allocator);

    var i: usize = 0;
    while (i + 18 <= script_hex.len) : (i += 2) {
        const seq = script_hex[i .. i + 18];
        if (!std.mem.eql(u8, seq[0..4], "7604")) continue;
        if (!std.mem.eql(u8, seq[12..14], "81")) continue;
        if (!std.mem.eql(u8, seq[14..16], "9c")) continue;
        if (!std.mem.eql(u8, seq[16..18], "69")) continue;

        var value: usize = 0;
        var b: usize = 4;
        while (b > 0) : (b -= 1) { // little-endian
            const byte = std.fmt.parseInt(u8, seq[4 + 2 * (b - 1) .. 6 + 2 * (b - 1)], 16) catch {
                value = 0;
                break;
            };
            value = (value << 8) | byte;
        } else {
            try values.append(allocator, value);
        }
    }
    return values;
}

pub const ContractError = error{
    NotDeployed,
    MethodNotFound,
    ArgCountMismatch,
    NoProviderOrSigner,
    DeployFailed,
    CallFailed,
    OutOfMemory,
    InsufficientFunds,
    /// Number of signatures supplied to `finalizeCall` does not match the
    /// number of `Sig` placeholders recorded in the `PreparedCall`.
    SignatureCountMismatch,
    /// A method interleaves `this.addRawOutput(...)` with a layout the SDK
    /// cannot represent alongside raw outputs — multi-output mode, two or more
    /// state continuations, or a missing continuation script (finding G1). The
    /// SDK fails closed rather than silently dropping outputs and stranding the
    /// funds (the built tx would mismatch the covenant's hashOutputs).
    RawOutputLayoutUnsupported,
    /// A call supplies BOTH `options.terminal_outputs` and
    /// `options.additional_contract_inputs` (N-271). The terminal builder
    /// lays out exactly one contract input (plus an optional fee/funding
    /// input) and never threads `additional_contract_inputs` into the tx.
    /// Fail closed rather than silently spending less than the caller asked
    /// for while reporting success.
    TerminalAdditionalContractInputsUnsupported,
    /// N-276 (port of N-227 Part 2 / N-258, mirrored from TS/Go/Rust/Python/
    /// Ruby): a non-terminal `call()`/`prepareCall()` supplies
    /// `options.additional_contract_inputs` on a path with no per-input
    /// unlock builder — only a StatefulSmartContract (with an SDK-derived
    /// preimage) builds a REAL unlock for each extra contract input; any
    /// other path would ship a placeholder/primary-only unlock and the
    /// resulting tx would be invalid (or, before this fix, silently drop
    /// the extra UTXOs while reporting success). Fail closed instead.
    AdditionalContractInputsUnsupported,
};

/// N-045 (defence in depth): every fixed-width method arg must have its
/// declared width — a covenant may copy it straight into its state. The
/// `.int = 0` auto-resolve markers (a PubKey taken from the signer, the
/// `allPrevouts` slot) are resolved later and skipped here.
fn checkFixedWidthArgs(params: []const types.ABIParam, args: []const types.StateValue) !void {
    for (params, args) |p, a| {
        if (a == .int and a.int == 0 and
            (std.mem.eql(u8, p.type_name, "PubKey") or std.mem.eql(u8, p.name, AUTO_PREVOUTS_PARAM_NAME)))
        {
            continue;
        }
        try state_mod.checkFixedWidthValue(a, p.type_name);
    }
}

/// RunarContract is a runtime wrapper for a compiled Runar contract. It handles
/// deployment, method invocation, state tracking, and script construction.
pub const RunarContract = struct {
    allocator: std.mem.Allocator,
    artifact: *types.RunarArtifact,
    constructor_args: []types.StateValue,
    state: []types.StateValue,
    code_script: ?[]u8 = null,
    inscription: ?ordinals.Inscription = null,
    current_utxo: ?types.UTXO = null,
    provider: ?provider_mod.Provider = null,
    signer: ?signer_mod.Signer = null,
    /// Witness values for intent-covenant intrinsic auto-injected params.
    /// `_prevOutScript_<i>` values are stored per-input-index in
    /// `prev_out_scripts`; `_serialisedOutputs` is stored in
    /// `serialised_outputs`. Both are owned lowercase hex strings (normalized
    /// in the setters). Read by the call-builder when assembling the
    /// unlocking script for methods that use extractPrevOutputScript /
    /// requireOutputP2PKH.
    prev_out_scripts: std.AutoHashMapUnmanaged(usize, []u8) = .{},
    serialised_outputs: ?[]u8 = null,

    /// Create a new contract instance from a compiled artifact and constructor arguments.
    pub fn init(
        allocator: std.mem.Allocator,
        artifact: *types.RunarArtifact,
        constructor_args: []const types.StateValue,
    ) !RunarContract {
        const expected = artifact.abi.constructor.params.len;
        if (constructor_args.len != expected) return ContractError.ArgCountMismatch;

        // Clone constructor args
        var args = try allocator.alloc(types.StateValue, constructor_args.len);
        for (constructor_args, 0..) |arg, i| {
            args[i] = try arg.clone(allocator);
        }

        // Initialize state from constructor args for stateful contracts
        var state_vals: []types.StateValue = &.{};
        if (artifact.state_fields.len > 0) {
            state_vals = try allocator.alloc(types.StateValue, artifact.state_fields.len);
            for (artifact.state_fields, 0..) |field, i| {
                if (field.initial_array) |leaves| {
                    // A FixedArray field's compile-time default. Parse each
                    // leaf against the array's LEAF type and regroup into the
                    // declared shape, so the serializer writes the values the
                    // contract declared. This branch used to be unreachable —
                    // the array was dropped on parse — and the field fell
                    // through to `.int = 0`, deploying N zero words whatever
                    // the source said.
                    state_vals[i] = buildInitialArrayValue(allocator, field, leaves) catch .{ .int = 0 };
                } else if (field.initial_value) |init_val| {
                    // Parse initial value string based on type
                    state_vals[i] = parseInitialValue(allocator, init_val, field.type_name) catch .{ .int = 0 };
                } else if (field.index >= 0 and @as(usize, @intCast(field.index)) < constructor_args.len) {
                    state_vals[i] = try constructor_args[@intCast(field.index)].clone(allocator);
                } else {
                    state_vals[i] = .{ .int = 0 };
                }
            }
        }

        return .{
            .allocator = allocator,
            .artifact = artifact,
            .constructor_args = args,
            .state = state_vals,
        };
    }

    pub fn deinit(self: *RunarContract) void {
        for (self.constructor_args) |*arg| arg.deinit(self.allocator);
        if (self.constructor_args.len > 0) self.allocator.free(self.constructor_args);
        for (self.state) |*s| s.deinit(self.allocator);
        if (self.state.len > 0) self.allocator.free(self.state);
        if (self.code_script) |cs| self.allocator.free(cs);
        if (self.inscription) |*insc| {
            var mi = insc.*;
            mi.deinit(self.allocator);
        }
        if (self.current_utxo) |*u| {
            var mu = u.*;
            mu.deinit(self.allocator);
        }
        // Free intent witness storage
        var it = self.prev_out_scripts.iterator();
        while (it.next()) |entry| self.allocator.free(entry.value_ptr.*);
        self.prev_out_scripts.deinit(self.allocator);
        if (self.serialised_outputs) |s| self.allocator.free(s);
        self.* = .{
            .allocator = self.allocator,
            .artifact = self.artifact,
            .constructor_args = &.{},
            .state = &.{},
        };
    }

    /// Supply the prev-output locking-script witness for input `input_index`.
    /// Required for methods that call `extractPrevOutputScript(input_index)`,
    /// which the compiler lowers into an auto-injected
    /// `_prevOutScript_<input_index>` ABI param. `bytes_hex` is a hex string
    /// (with or without 0x prefix, any casing).
    pub fn setPrevOutScript(self: *RunarContract, input_index: usize, bytes_hex: []const u8) !void {
        const normalized = try normalizeWitnessHex(self.allocator, bytes_hex);
        errdefer self.allocator.free(normalized);
        if (self.prev_out_scripts.fetchRemove(input_index)) |kv| {
            self.allocator.free(kv.value);
        }
        try self.prev_out_scripts.put(self.allocator, input_index, normalized);
    }

    /// Supply the serialised-outputs witness for the current call. Required
    /// for methods that call `requireOutputP2PKH(...)`, which the compiler
    /// lowers into an auto-injected `_serialisedOutputs` ABI param.
    pub fn setSerialisedOutputs(self: *RunarContract, bytes_hex: []const u8) !void {
        const normalized = try normalizeWitnessHex(self.allocator, bytes_hex);
        if (self.serialised_outputs) |old| self.allocator.free(old);
        self.serialised_outputs = normalized;
    }

    /// Build the trailing witness-hex for the auto-injected intent-intrinsic
    /// params of a method, in ABI order (`_prevOutScript_*` first, then
    /// `_serialisedOutputs`). Returns `error.WitnessValueMissing` (after
    /// recording diagnostic info via `raiseWitnessValueMissing`) for any
    /// auto-injected param the caller hasn't supplied.
    fn buildIntentWitnessHex(
        self: *const RunarContract,
        method: *const types.ABIMethod,
    ) ![]u8 {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        for (method.params) |p| {
            if (std.mem.startsWith(u8, p.name, "_prevOutScript_")) {
                const idx_str = p.name["_prevOutScript_".len..];
                const idx = std.fmt.parseInt(usize, idx_str, 10) catch {
                    return error.WitnessValueMissing;
                };
                const val = self.prev_out_scripts.get(idx) orelse {
                    return errors_mod.raiseWitnessValueMissing(p.name, method.name, self.artifact.contract_name);
                };
                const enc = try state_mod.encodePushData(self.allocator, val);
                defer self.allocator.free(enc);
                try out.appendSlice(self.allocator, enc);
            } else if (std.mem.eql(u8, p.name, "_serialisedOutputs")) {
                const val = self.serialised_outputs orelse {
                    return errors_mod.raiseWitnessValueMissing(p.name, method.name, self.artifact.contract_name);
                };
                const enc = try state_mod.encodePushData(self.allocator, val);
                defer self.allocator.free(enc);
                try out.appendSlice(self.allocator, enc);
            }
        }
        return out.toOwnedSlice(self.allocator);
    }

    /// Connect stores a provider and signer on this contract.
    pub fn connect(self: *RunarContract, provider: provider_mod.Provider, signer_val: signer_mod.Signer) void {
        self.provider = provider;
        self.signer = signer_val;
    }

    // -------------------------------------------------------------------------
    // Ordinals
    // -------------------------------------------------------------------------

    /// Attach a 1sat ordinals inscription to this contract. The inscription
    /// envelope is injected into the locking script between the compiled code
    /// and the state section (if any). Once deployed, the inscription is
    /// immutable -- it persists identically across all state transitions.
    ///
    /// N-043 -- returns `error.CodePartLengthPinViolated` when the envelope
    /// would break the contract's own `SIZE(_codePart)` pin. A stateful contract
    /// with a variable-length state section carries an equality pin on the
    /// deployed code-part length, and the envelope lands INSIDE the code part
    /// (see `getCodePartHex`). The compiler bakes that number before any
    /// inscription exists, so the pinned length and the real one differ by the
    /// envelope's size and every honest spend aborts at OP_VERIFY -- with the
    /// funds already committed. Refusing here turns a permanent, silent lock
    /// into a loud error before a single satoshi moves. The pinned / actual
    /// lengths are recorded in `sdk_errors.last_codepart_pin_error`.
    pub fn withInscription(self: *RunarContract, insc: ordinals.Inscription) !void {
        const previous = self.inscription;
        self.inscription = try insc.clone(self.allocator);
        self.assertCodePartLengthPinHonoured() catch |err| {
            if (self.inscription) |*attached| {
                var mi = attached.*;
                mi.deinit(self.allocator);
            }
            self.inscription = previous;
            return err;
        };
        if (previous) |*old| {
            var mi = old.*;
            mi.deinit(self.allocator);
        }
    }

    /// Verify that every equality `verify_code_part_len` pin the compiler baked
    /// into this artifact still describes the code part this contract produces.
    ///
    /// The check is the invariant itself, not a restatement of the compiler's
    /// derivation: it decodes the pinned number straight out of the built code
    /// script and compares it to `getCodePartHex()`. So it permits every
    /// combination that actually works -- a stateless contract or a fixed-size
    /// state layout carries no pin at all, a deploy-time pin (N-051) is written
    /// with the inscribed length, and a legacy lower-bound pin is satisfied by
    /// a longer code part -- and rejects only the shape that would lock funds.
    fn assertCodePartLengthPinHonoured(self: *RunarContract) !void {
        // Decode from the code this contract really deploys: a deploy-time pin
        // (N-051 `codePartLenSlots`) is patched to the inscribed length there.
        const built = try self.buildCodeScript();
        defer self.allocator.free(built);
        var pinned = try decodeExactCodePartLenPins(self.allocator, built);
        defer pinned.deinit(self.allocator);
        if (pinned.items.len == 0) return;

        const code = try self.getCodePartHex();
        defer self.allocator.free(code);
        const actual = code.len / 2;

        for (pinned.items) |value| {
            if (value == actual) continue;
            return errors_mod.raiseCodePartLengthPinViolated(value, actual, self.artifact.contract_name);
        }
    }

    /// Returns the current inscription, if any.
    pub fn getInscription(self: *const RunarContract) ?ordinals.Inscription {
        return self.inscription;
    }

    /// Deploy the contract by creating a UTXO with the locking script.
    pub fn deploy(
        self: *RunarContract,
        provider: ?provider_mod.Provider,
        signer_val: ?signer_mod.Signer,
        options: types.DeployOptions,
    ) ![]u8 {
        const prov = provider orelse self.provider orelse return ContractError.NoProviderOrSigner;
        const sign = signer_val orelse self.signer orelse return ContractError.NoProviderOrSigner;

        const address = try sign.getAddress(self.allocator);
        defer self.allocator.free(address);

        const change_address = options.change_address orelse address;

        const locking_script = try self.getLockingScript();
        defer self.allocator.free(locking_script);

        // DoS-bound: reject pathological scripts BEFORE any signing / broadcast.
        {
            var ctx_buf: [256]u8 = undefined;
            const ctx = std.fmt.bufPrint(&ctx_buf, "{s}.deploy", .{self.artifact.contract_name}) catch "RunarContract.deploy";
            try errors_mod.assertScriptHexUnderLimit(locking_script, errors_mod.MAX_SCRIPT_BYTES, ctx);

            // R-062: and refuse to fund a script reaching a builtin the
            // compiler does not claim is sound unless the caller says so here,
            // in the same breath as the money.
            try errors_mod.assertUnsoundPrimitivesAcknowledged(
                self.artifact.unsound_primitives,
                options.acknowledge_unsound,
                ctx,
            );
        }

        // Fetch fee rate and funding UTXOs
        const fee_rate = prov.getFeeRate() catch 100;
        const all_utxos = prov.getUtxos(self.allocator, address) catch return ContractError.DeployFailed;
        defer {
            for (all_utxos) |*u| u.deinit(self.allocator);
            self.allocator.free(all_utxos);
        }

        if (all_utxos.len == 0) return ContractError.InsufficientFunds;

        const selected = try deploy_mod.selectUtxos(self.allocator, all_utxos, options.satoshis, locking_script.len / 2, fee_rate, 0, 0);
        defer {
            for (selected) |*u| u.deinit(self.allocator);
            self.allocator.free(selected);
        }

        // Build the deploy transaction
        var deploy_result = deploy_mod.buildDeployTransaction(
            self.allocator,
            locking_script,
            selected,
            options.satoshis,
            change_address,
            fee_rate,
        ) catch return ContractError.DeployFailed;
        defer deploy_result.deinit(self.allocator);

        // Sign all P2PKH inputs. Funding inputs are signed by fundingSigner when
        // set (issue #134): the deploy signer may not own the funding coins.
        // Defaults to the connected signer.
        const funding_sign = options.funding_signer orelse sign;
        var signed_tx = try self.allocator.dupe(u8, deploy_result.tx_hex);
        errdefer self.allocator.free(signed_tx);

        for (selected, 0..) |utxo, i| {
            const sig = try funding_sign.sign(self.allocator, signed_tx, i, utxo.script, utxo.satoshis, null);
            defer self.allocator.free(sig);
            const pub_key = try funding_sign.getPublicKey(self.allocator);
            defer self.allocator.free(pub_key);

            // Build P2PKH unlocking script hex: push(sig) + push(pubkey)
            const sig_push = try state_mod.encodePushData(self.allocator, sig);
            defer self.allocator.free(sig_push);
            const pk_push = try state_mod.encodePushData(self.allocator, pub_key);
            defer self.allocator.free(pk_push);

            const unlock = try std.mem.concat(self.allocator, u8, &[_][]const u8{ sig_push, pk_push });
            defer self.allocator.free(unlock);

            const new_tx = try insertUnlockingScript(self.allocator, signed_tx, i, unlock);
            self.allocator.free(signed_tx);
            signed_tx = new_tx;
        }

        // Broadcast
        const txid = prov.broadcast(self.allocator, signed_tx) catch return ContractError.DeployFailed;
        errdefer self.allocator.free(txid);

        // Track the deployed UTXO
        if (self.current_utxo) |*old| {
            var mu = old.*;
            mu.deinit(self.allocator);
        }
        self.current_utxo = .{
            .txid = try self.allocator.dupe(u8, txid),
            .output_index = 0,
            .satoshis = options.satoshis,
            .script = try self.allocator.dupe(u8, locking_script),
        };

        self.allocator.free(signed_tx);
        return txid;
    }

    /// Call a public method on the contract. Handles:
    ///   - Stateless contracts: build unlocking script, sign Sig params, broadcast
    ///   - Stateful contracts: OP_PUSH_TX (k=1), two-pass preimage convergence,
    ///     state continuation output, method selector
    ///
    /// Returns the broadcast txid (caller owns).
    pub fn call(
        self: *RunarContract,
        method_name: []const u8,
        args: []const types.StateValue,
        prov_arg: ?provider_mod.Provider,
        signer_arg: ?signer_mod.Signer,
        options: ?types.CallOptions,
    ) ![]u8 {
        const prov = prov_arg orelse self.provider orelse return ContractError.NoProviderOrSigner;
        const sign = signer_arg orelse self.signer orelse return ContractError.NoProviderOrSigner;
        // Funding (and terminal fee) inputs are signed by fundingSigner when set
        // (issue #134); the method's own Sig args stay with the connected signer.
        const funding_sign = if (options) |o| (o.funding_signer orelse sign) else sign;

        if (self.current_utxo == null) return ContractError.NotDeployed;
        const contract_utxo = self.current_utxo.?;

        // DoS-bound: reject pathological scripts BEFORE any signing / broadcast.
        {
            var ctx_buf: [256]u8 = undefined;
            const ctx = std.fmt.bufPrint(&ctx_buf, "{s}.call({s})", .{ self.artifact.contract_name, method_name }) catch "RunarContract.call";
            try errors_mod.assertScriptHexUnderLimit(contract_utxo.script, errors_mod.MAX_SCRIPT_BYTES, ctx);
        }

        // Resolve method
        const method = self.findMethod(method_name) orelse return ContractError.MethodNotFound;
        _ = method;

        const is_stateful = self.artifact.state_fields.len > 0;
        // parent_stateful gates the issue-#42/#44 terminal sighash subscript
        // trim AND the stateful-vs-stateless code path: a StatefulSmartContract
        // with zero mutable fields has empty state_fields yet still injects
        // checkPreimage at method entry (so it needs OP_PUSH_TX and the
        // subscript trim). It is the authoritative signal; is_stateful still
        // exclusively drives state-continuation output construction (a
        // zero-mutable contract has no state to continue).
        const parent_stateful = self.artifact.parentStateful();

        // Determine method index for method selector
        const public_methods = try self.getPublicMethods();
        defer self.allocator.free(public_methods);

        var method_index: usize = 0;
        if (public_methods.len > 1) {
            for (public_methods, 0..) |m, i| {
                if (std.mem.eql(u8, m.name, method_name)) {
                    method_index = i;
                    break;
                }
            }
        }

        // Detect which params need auto-resolution
        const abi_method = self.findMethod(method_name).?;
        var needs_change = false;
        var needs_new_amount = false;
        for (abi_method.params) |p| {
            if (std.mem.eql(u8, p.name, "_changePKH")) needs_change = true;
            if (std.mem.eql(u8, p.name, "_newAmount")) needs_new_amount = true;
        }
        // Whether the unlocking script is prefixed with _codePart. New artifacts
        // carry the authoritative usesCodePart flag (true for continuation
        // builders AND terminal var-length-state readers — issue #100). Older
        // artifacts lack it; fall back to the legacy rule (codePart iff change).
        const method_uses_code_part = abi_method.uses_code_part orelse needs_change;
        // N-038: "has a continuation" for the state auto-compute below. A
        // SIGHASH_SINGLE method continues without a _changePKH param.
        const has_continuation = abi_method.hasContinuation();

        // Drop auto-injected continuation params AND intent-intrinsic
        // witness params (`_prevOutScript_<i>`, `_serialisedOutputs`) from
        // the user-facing arg count check. Witness values come from
        // setPrevOutScript / setSerialisedOutputs, not the args slice.
        // Shared with the typed-wrapper codegen (F-245).
        var user_param_count: usize = 0;
        for (abi_method.params) |p| {
            if (!types.isSdkSuppliedParam(p, is_stateful)) user_param_count += 1;
        }

        if (args.len != user_param_count) return ContractError.ArgCountMismatch;

        // Resolve args: auto-fill Sig (placeholder), PubKey (signer's key)
        var resolved_args = try self.allocator.alloc(types.StateValue, args.len);
        defer {
            for (resolved_args) |*a| a.deinit(self.allocator);
            self.allocator.free(resolved_args);
        }

        // Build user param list to know types
        var user_params = try self.allocator.alloc(types.ABIParam, user_param_count);
        defer self.allocator.free(user_params);
        {
            var idx: usize = 0;
            for (abi_method.params) |p| {
                if (!types.isSdkSuppliedParam(p, is_stateful)) {
                    user_params[idx] = p;
                    idx += 1;
                }
            }
        }

        // N-045 (defence in depth): a fixed-width arg must have its declared width.
        try checkFixedWidthArgs(user_params, args);

        var sig_indices: std.ArrayListUnmanaged(usize) = .empty;
        defer sig_indices.deinit(self.allocator);
        // Indices of `ByteString` / `Ripemd160` user params the caller passed
        // as the placeholder `0` to request auto-resolution as `allPrevouts`
        // (concatenated outpoints of every input). Mirrors the Go SDK's
        // `prevoutsIndices` (sdk_contract.go:381) — populated below and
        // consumed after the tx converges to substitute the real bytes.
        var prevouts_indices: std.ArrayListUnmanaged(usize) = .empty;
        defer prevouts_indices.deinit(self.allocator);

        // Number of additional contract inputs the caller is providing; used
        // to size the allPrevouts placeholder so the convergence loop's
        // preimage and final tx size agree.
        const n_extra_contract_inputs: usize =
            if (options) |o| (if (o.additional_contract_inputs) |aci| aci.len else 0) else 0;

        for (args, 0..) |arg, i| {
            const param_type = user_params[i].type_name;
            const param_name = user_params[i].name;
            if (std.mem.eql(u8, param_type, "Sig") and arg == .int and arg.int == 0) {
                // Placeholder sig: 72 zero bytes
                try sig_indices.append(self.allocator, i);
                resolved_args[i] = .{ .bytes = try self.allocator.dupe(u8, "00" ** 72) };
            } else if (std.mem.eql(u8, param_type, "PubKey") and arg == .int and arg.int == 0) {
                // Auto-fill from signer
                const pk = try sign.getPublicKey(self.allocator);
                resolved_args[i] = .{ .bytes = pk };
            } else if ((std.mem.eql(u8, param_type, "ByteString") or
                std.mem.eql(u8, param_type, "Ripemd160")) and
                arg == .int and arg.int == 0 and
                std.mem.eql(u8, param_name, AUTO_PREVOUTS_PARAM_NAME))
            {
                // Auto-resolve `allPrevouts`: placeholder of 36*(1+n_extra+1)
                // zero bytes — sized for the primary contract input + every
                // additional contract input + one P2PKH funding input. The
                // real bytes are spliced in after tx convergence below.
                // Gated on the well-known param name `allPrevouts`; otherwise
                // the user's `.int = 0` for a ByteString param is a legitimate
                // empty-bytestring value (encodes as OP_0).
                try prevouts_indices.append(self.allocator, i);
                const placeholder_inputs: usize = 1 + n_extra_contract_inputs + 1;
                const placeholder_hex_len: usize = 36 * 2 * placeholder_inputs;
                const buf = try self.allocator.alloc(u8, placeholder_hex_len);
                @memset(buf, '0');
                resolved_args[i] = .{ .bytes = buf };
            } else {
                resolved_args[i] = try arg.clone(self.allocator);
            }
        }

        // Soft heuristic (issue #106): warn only for likely OR-CHECKSIG, not
        // genuine multi-sig. Two or more AUTO-signed Sig slots on an OR-CHECKSIG
        // method means every branch gets a real signature, and the branch that
        // fails then carries a non-empty invalid one — which BIP146 NULLFAIL
        // rejects, taking the whole spend with it. Pass the empty-sig marker for
        // the non-matching branch instead.
        if (sig_indices.items.len >= 2 and isLikelyOrChecksig(self.artifact.*)) {
            std.debug.print(
                "runar-sdk: warning: {s}.call(\"{s}\") has {d} auto-signed Sig slots. " ++
                    "If this is an OR-CHECKSIG method, pass an empty sig for the " ++
                    "non-matching branch(es) to satisfy BIP146 NULLFAIL (issue #106).\n",
                .{ self.artifact.contract_name, method_name, sig_indices.items.len },
            );
        }

        const address = try sign.getAddress(self.allocator);
        defer self.allocator.free(address);
        const change_address = if (options) |o| (o.change_address orelse address) else address;

        // Detect terminal-output call: contract is fully spent, outputs are
        // the exact list provided in options.terminal_outputs (replaces
        // continuation), funding inputs come from options.funding_utxos
        // (rather than provider-fetched UTXOs), and there is no change.
        const is_terminal_call = if (options) |o| o.terminal_outputs != null else false;
        // N-271: the terminal layout below is exactly one contract input
        // (plus an optional fee/funding input); additional_contract_inputs
        // is never threaded through it. Fail closed instead of silently
        // spending less than the caller asked for while reporting success.
        if (is_terminal_call) {
            if (options) |o| {
                if (o.additional_contract_inputs) |aci| {
                    if (aci.len > 0) return ContractError.TerminalAdditionalContractInputsUnsupported;
                }
            }
        }
        // N-276 (port of N-227 Part 2 / N-258): a NON-terminal call with
        // additional_contract_inputs on a plain SmartContract (!parent_stateful)
        // has no per-input unlock builder below -- the stateless path (guarded
        // on `!parent_stateful` further down) threads only the primary
        // contract input into buildCallTransaction and never reads
        // additional_contract_inputs at all. Fail closed instead of silently
        // dropping the extra UTXOs while reporting success. parent_stateful
        // contracts (including the zero-mutable-field case) are unaffected --
        // they route through the OP_PUSH_TX stateful path, which threads a
        // REAL per-input unlock for every extra contract input via
        // `extra_call_inputs`.
        if (!parent_stateful and n_extra_contract_inputs > 0) {
            return ContractError.AdditionalContractInputsUnsupported;
        }
        const terminal_outputs: []const types.ContractOutput =
            if (is_terminal_call) options.?.terminal_outputs.? else &.{};
        const terminal_funding: []const types.UTXO =
            if (is_terminal_call) (if (options.?.funding_utxos) |fu| fu else &.{}) else &.{};

        // Fetch fee rate and funding UTXOs (skip provider lookup when
        // terminal — funding is caller-provided).
        const fee_rate = prov.getFeeRate() catch 100;
        const all_utxos: []types.UTXO = if (is_terminal_call)
            &.{}
        else
            prov.getUtxos(self.allocator, address) catch return ContractError.CallFailed;
        defer if (!is_terminal_call) {
            for (all_utxos) |*u| u.deinit(self.allocator);
            if (all_utxos.len > 0) self.allocator.free(all_utxos);
        };

        // Filter out the contract UTXO from funding UTXOs
        var additional_utxos: std.ArrayListUnmanaged(types.UTXO) = .empty;
        defer additional_utxos.deinit(self.allocator);
        if (is_terminal_call) {
            for (terminal_funding) |u| {
                try additional_utxos.append(self.allocator, u);
            }
            // Issue #118: a single P2PKH fee input, added to the terminal tx
            // BEFORE the OP_PUSH_TX preimage (so hashPrevouts covers it) and
            // consumed entirely as fee — no change output. Merges into the same
            // terminal funding-input path as funding_utxos.
            if (options) |o| if (o.fee_utxo) |fee| try additional_utxos.append(self.allocator, fee);
        } else {
            for (all_utxos) |u| {
                if (!(std.mem.eql(u8, u.txid, contract_utxo.txid) and u.output_index == contract_utxo.output_index)) {
                    try additional_utxos.append(self.allocator, u);
                }
            }
        }

        // Build new locking script for stateful continuation
        var new_locking_script: []u8 = &.{};
        var new_satoshis: i64 = 0;
        defer if (new_locking_script.len > 0) self.allocator.free(new_locking_script);

        // Data outputs resolved from this.addDataOutput(...) in the method
        // body (or supplied explicitly via options.data_outputs). We free
        // these — including each entry's script slice — at call-scope exit.
        var anf_data_outputs: []anf_interp.DataOutputEntry = &.{};
        defer {
            for (anf_data_outputs) |d| self.allocator.free(d.script);
            if (anf_data_outputs.len > 0) self.allocator.free(anf_data_outputs);
        }

        // Finding G1: state-class outputs (state continuation + raw) in SOURCE
        // order, surfaced from the ANF interpreter. Empty for methods with no
        // `this.addRawOutput(...)` — the raw-output rebuild below is then a
        // no-op. Owned; each `.raw` entry's script + the slice are freed here.
        var anf_ordered_outputs: std.ArrayListUnmanaged(anf_interp.OrderedOutputEntry) = .empty;
        defer {
            for (anf_ordered_outputs.items) |o| {
                if (o.kind == .raw and o.script.len > 0) self.allocator.free(@constCast(o.script));
            }
            anf_ordered_outputs.deinit(self.allocator);
        }

        // Multi-output continuation: methods like `transfer` on a fungible
        // token emit N continuation outputs (each with the same code part +
        // a different state push). Caller supplies one OutputSpec per
        // continuation; we materialise N { script: codePart || 6a ||
        // serializeState(out.state), satoshis } records and skip the
        // single-`new_locking_script` continuation path. Owned slice; freed
        // at call-scope exit. Exclusive with `terminal_outputs` and
        // mutually-overrides `new_state` for the continuation count.
        var multi_outputs_hex: std.ArrayListUnmanaged(types.ContractOutput) = .empty;
        defer {
            for (multi_outputs_hex.items) |co| self.allocator.free(@constCast(co.script));
            multi_outputs_hex.deinit(self.allocator);
        }
        const multi_output_specs: ?[]const types.OutputSpec =
            if (options) |o| o.outputs else null;
        const has_multi_output =
            multi_output_specs != null and multi_output_specs.?.len > 0 and
            !is_terminal_call;

        // A StatefulSmartContract with zero mutable fields (parent_stateful but
        // !is_stateful) still routes through the OP_PUSH_TX stateful path (it
        // needs op_push_tx + the issue-#44 subscript trim) but produces NO
        // state-continuation output — it spends fully, exactly like a terminal
        // call. Fold it into the terminal-suppression logic below.
        const no_state_continuation = parent_stateful and !is_stateful;
        const suppress_continuation = is_terminal_call or no_state_continuation;

        if (is_stateful and !is_terminal_call) {
            new_satoshis = contract_utxo.satoshis;
            if (options) |o| {
                if (o.satoshis > 0) new_satoshis = o.satoshis;
            }
            // Resolve new state + data outputs. Three paths:
            //   - `options.outputs` (multi-output): caller supplies N
            //     OutputSpec entries; we build one continuation output per
            //     entry below. Still run ANF for data-output side effects
            //     (no state mutation — the multi-output specs ARE the
            //     state). Most fungible-token / NFT methods use this.
            //   - explicit `options.new_state`: caller-supplied state takes
            //     priority. We STILL run the ANF interpreter (without mutating
            //     self.state) to extract any addDataOutput(...) emissions, so
            //     the broadcast tx contains the data outputs the contract's
            //     compile-time hashOutputs check expects between the state
            //     and change outputs. Without this, a stateful method that
            //     calls addDataOutput would build a tx with no data output
            //     and the on-chain hashOutputs equality check would fail.
            //   - no explicit state: auto-compute both from ANF.
            const has_explicit_state = if (options) |o| o.new_state != null else false;
            if (has_multi_output) {
                if (has_continuation and self.artifact.anf_json != null) {
                    anf_data_outputs = try self.autoComputeDataOutputs(method_name, user_params, resolved_args, &anf_ordered_outputs);
                }
                const code_part = try self.getCodePartHex();
                defer self.allocator.free(code_part);
                for (multi_output_specs.?) |out| {
                    const state_hex = try state_mod.serializeState(
                        self.allocator,
                        self.artifact.state_fields,
                        out.state,
                    );
                    defer self.allocator.free(state_hex);
                    const script_hex = try std.mem.concat(self.allocator, u8, &[_][]const u8{ code_part, "6a", state_hex });
                    try multi_outputs_hex.append(self.allocator, .{
                        .script = script_hex,
                        .satoshis = out.satoshis,
                    });
                }
                // Mirror the first OutputSpec's state into self.state so any
                // post-call observers (or follow-up call without explicit
                // new_state) see consistent contract state. The "primary"
                // continuation is by convention the first entry.
                const primary_state = multi_output_specs.?[0].state;
                for (self.state) |*s| s.deinit(self.allocator);
                if (self.state.len > 0) self.allocator.free(self.state);
                var vals = try self.allocator.alloc(types.StateValue, primary_state.len);
                for (primary_state, 0..) |s, i| {
                    vals[i] = try s.clone(self.allocator);
                }
                self.state = vals;
                new_satoshis = multi_output_specs.?[0].satoshis;
                // Skip new_locking_script — multi_outputs_hex feeds the
                // tx builder via stateful_contract_outputs below.
            } else if (has_explicit_state) {
                if (has_continuation and self.artifact.anf_json != null) {
                    anf_data_outputs = try self.autoComputeDataOutputs(method_name, user_params, resolved_args, &anf_ordered_outputs);
                }
                const ns = options.?.new_state.?;
                for (self.state) |*s| s.deinit(self.allocator);
                if (self.state.len > 0) self.allocator.free(self.state);
                var vals = try self.allocator.alloc(types.StateValue, ns.len);
                for (ns, 0..) |s, i| {
                    vals[i] = try s.clone(self.allocator);
                }
                self.state = vals;
                new_locking_script = try self.getLockingScript();
            } else if (has_continuation and self.artifact.anf_json != null) {
                // Auto-compute new state + data outputs from ANF IR
                anf_data_outputs = try self.autoComputeState(method_name, user_params, resolved_args, &anf_ordered_outputs, .{
                    .input_amount = contract_utxo.satoshis,
                    .new_amount = new_satoshis,
                });
                new_locking_script = try self.getLockingScript();
            } else {
                new_locking_script = try self.getLockingScript();
            }
            // DoS-bound: also reject pathological continuation scripts BEFORE broadcast.
            if (new_locking_script.len > 0) {
                var ctx_buf: [256]u8 = undefined;
                const ctx = std.fmt.bufPrint(&ctx_buf, "{s}.call({s}).continuation", .{ self.artifact.contract_name, method_name }) catch "RunarContract.call.continuation";
                try errors_mod.assertScriptHexUnderLimit(new_locking_script, errors_mod.MAX_SCRIPT_BYTES, ctx);
            }
        }

        // Finding G1, generalized to the no-raw single-continuation path: when a
        // method emits EXACTLY ONE ordered output of kind `state` (a single
        // `this.addOutput(<N>, ...)`, no raw outputs) the ANF interpreter records
        // that amount in `anf_ordered_outputs`. Honor it for the continuation so
        // `addOutput(1000, ...)` builds a 1000-sat continuation (matching the
        // covenant's hashOutputs binding) instead of defaulting to the spent
        // input's value — otherwise the built tx mismatches hashOutputs and the
        // funds are stranded. An explicit `options.satoshis` still wins (the
        // default block above already applied it); a method with NO explicit
        // addOutput has an EMPTY ordered-outputs list (auto-injected
        // continuation) so the input-value default is kept. The raw-output
        // branch below (has_raw_ordered) threads its own amount and is naturally
        // excluded here — a raw layout's ordered list is never a single
        // `state` entry. Multi-output is excluded too. Mirrors the single-stateful
        // branch in packages/runar-sdk/src/contract.ts.
        if (is_stateful and !is_terminal_call and !has_multi_output) {
            const explicit_satoshis = if (options) |o| o.satoshis > 0 else false;
            if (!explicit_satoshis and anf_ordered_outputs.items.len == 1 and
                anf_ordered_outputs.items[0].kind == .state)
            {
                new_satoshis = anf_ordered_outputs.items[0].satoshis;
            }
        }

        // Finding G1: a method that calls `this.addRawOutput(...)` folds the raw
        // output(s) into the covenant's continuation hashOutputs IN SOURCE ORDER,
        // interleaved with the state continuation `this.addOutput(...)`. The
        // single-continuation path above builds only the state output, so the
        // built tx would emit it alone at output 0 and mismatch hashOutputs —
        // input 0's auto-injected state-check OP_VERIFY would reject and the
        // funds would be stranded. Rebuild an ORDERED contract-output list from
        // the interpreter's source-ordered outputs. Purely additive: with no raw
        // outputs `has_raw_ordered` stays false and every path below is
        // byte-for-byte unchanged. Owned; scripts + slice freed at call exit.
        var raw_ordered_hex: std.ArrayListUnmanaged(types.ContractOutput) = .empty;
        defer {
            for (raw_ordered_hex.items) |co| self.allocator.free(@constCast(co.script));
            raw_ordered_hex.deinit(self.allocator);
        }
        var has_raw_ordered = false;
        if (is_stateful and !is_terminal_call) {
            var any_raw = false;
            var state_count: usize = 0;
            for (anf_ordered_outputs.items) |o| {
                switch (o.kind) {
                    .raw => any_raw = true,
                    .state => state_count += 1,
                }
            }
            if (any_raw) {
                // Fail closed. The covenant machinery below threads exactly one
                // continuation script/amount, so multi-output mode, two or more
                // continuations, or a missing continuation script are not
                // representable — error rather than silently drop outputs.
                if (has_multi_output or state_count >= 2 or (state_count == 1 and new_locking_script.len == 0)) {
                    return ContractError.RawOutputLayoutUnsupported;
                }
                for (anf_ordered_outputs.items) |o| {
                    const script_dup = if (o.kind == .raw)
                        try self.allocator.dupe(u8, o.script)
                    else
                        try self.allocator.dupe(u8, new_locking_script);
                    try raw_ordered_hex.append(self.allocator, .{ .script = script_dup, .satoshis = o.satoshis });
                }
                // Keep the preimage's new-amount (buildStatefulUnlockScript) in
                // step with the continuation output's sats — `this.addOutput(0,
                // ...)` makes it 0, not the input value the single-continuation
                // path defaulted to.
                if (state_count == 1) {
                    for (anf_ordered_outputs.items) |o| {
                        if (o.kind == .state) {
                            new_satoshis = o.satoshis;
                            break;
                        }
                    }
                }
                has_raw_ordered = true;
            }
        }

        // Compute change PKH for stateful methods that need it
        var change_pkh_hex: ?[]u8 = null;
        defer if (change_pkh_hex) |c| self.allocator.free(c);

        if (is_stateful and needs_change) {
            const pub_key_hex = try sign.getPublicKey(self.allocator);
            defer self.allocator.free(pub_key_hex);
            const pub_key_bytes = try state_mod.hexToBytes(self.allocator, pub_key_hex);
            defer self.allocator.free(pub_key_bytes);
            // hash160 = RIPEMD160(SHA256(pubkey))
            const ripe_hash = bsvz.crypto.hash.hash160(pub_key_bytes);
            const hex_buf = try self.allocator.alloc(u8, 40);
            _ = bsvz.primitives.hex.encodeLower(&ripe_hash.bytes, hex_buf) catch {
                self.allocator.free(hex_buf);
                return ContractError.CallFailed;
            };
            change_pkh_hex = hex_buf;
        }

        // Build method selector hex
        var method_selector_hex: ?[]u8 = null;
        defer if (method_selector_hex) |ms| self.allocator.free(ms);

        if (is_stateful and public_methods.len > 1) {
            method_selector_hex = try state_mod.encodeScriptNumber(self.allocator, @intCast(method_index));
        }

        const code_sep_idx = try self.getCodeSepIndex(method_index);

        // Pre-resolve intent-intrinsic witness hex (returns
        // `error.WitnessValueMissing` if a `_prevOutScript_<i>` or
        // `_serialisedOutputs` param wasn't set on the contract). Resolving
        // up-front means the error is raised BEFORE any signing / broadcast
        // work, mirroring the script-size guard above.
        const witness_hex = try self.buildIntentWitnessHex(abi_method);
        defer self.allocator.free(witness_hex);

        // ---------------------------------------------------------------
        // Additional contract inputs (e.g. `merge` on a fungible token spends
        // 2 contract UTXOs into 1). Each entry is unlocked with the same
        // method but possibly different args (per
        // options.additional_contract_input_args). Mirrors Go's
        // AdditionalContractInputs/AdditionalContractInputArgs handling at
        // sdk_contract.go:466-585.
        // ---------------------------------------------------------------
        const extra_contract_utxos: []const types.UTXO =
            if (options) |o| (if (o.additional_contract_inputs) |aci| aci else &.{}) else &.{};

        // Per-input resolved args. Owned by `self.allocator`. Each
        // resolved_args entry mirrors the primary `resolved_args` shape:
        // a slice of StateValue with placeholders pre-filled.
        var extra_resolved_args_list: std.ArrayListUnmanaged([]types.StateValue) = .empty;
        defer {
            for (extra_resolved_args_list.items) |slice| {
                for (slice) |*sv| sv.deinit(self.allocator);
                if (slice.len > 0) self.allocator.free(slice);
            }
            extra_resolved_args_list.deinit(self.allocator);
        }

        for (extra_contract_utxos, 0..) |_, ei| {
            const per_input_args: ?[]const types.StateValue = blk: {
                if (options) |o| {
                    if (o.additional_contract_input_args) |aia| {
                        if (ei < aia.len) break :blk aia[ei];
                    }
                }
                break :blk null;
            };

            // If the caller did not supply per-input args, reuse the primary
            // resolved_args wholesale (same as Go's `extraResolvedArgs[i] =
            // resolvedArgs` fallback at sdk_contract.go:584).
            if (per_input_args == null) {
                var clone_slice = try self.allocator.alloc(types.StateValue, resolved_args.len);
                errdefer {
                    for (clone_slice) |*sv| sv.deinit(self.allocator);
                    self.allocator.free(clone_slice);
                }
                for (resolved_args, 0..) |a, j| clone_slice[j] = try a.clone(self.allocator);
                try extra_resolved_args_list.append(self.allocator, clone_slice);
                continue;
            }

            // Per-input args supplied: clone with the same placeholder rules
            // we apply to the primary args. nil entries (encoded as `int 0`
            // for Sig/PubKey/ByteString/Ripemd160 typed user params) get
            // auto-resolved exactly like the primary call.
            const per = per_input_args.?;
            var slice = try self.allocator.alloc(types.StateValue, per.len);
            errdefer {
                for (slice) |*sv| sv.deinit(self.allocator);
                self.allocator.free(slice);
            }
            for (per, 0..) |arg, j| {
                if (j >= user_params.len) {
                    slice[j] = try arg.clone(self.allocator);
                    continue;
                }
                const param_type = user_params[j].type_name;
                if (std.mem.eql(u8, param_type, "Sig") and arg == .int and arg.int == 0) {
                    slice[j] = .{ .bytes = try self.allocator.dupe(u8, "00" ** 72) };
                } else if (std.mem.eql(u8, param_type, "PubKey") and arg == .int and arg.int == 0) {
                    const pk = try sign.getPublicKey(self.allocator);
                    slice[j] = .{ .bytes = pk };
                } else if ((std.mem.eql(u8, param_type, "ByteString") or
                    std.mem.eql(u8, param_type, "Ripemd160")) and
                    arg == .int and arg.int == 0 and
                    std.mem.eql(u8, user_params[j].name, AUTO_PREVOUTS_PARAM_NAME))
                {
                    // Same name gate as the primary resolution above: without it
                    // a user's `.int = 0` for an ordinary ByteString param (a
                    // legitimate empty bytestring) is replaced by the prevouts
                    // blob, and the spend fails at script execution.
                    const placeholder_inputs: usize = 1 + n_extra_contract_inputs + 1;
                    const placeholder_hex_len: usize = 36 * 2 * placeholder_inputs;
                    const buf = try self.allocator.alloc(u8, placeholder_hex_len);
                    @memset(buf, '0');
                    slice[j] = .{ .bytes = buf };
                } else {
                    slice[j] = try arg.clone(self.allocator);
                }
            }
            try extra_resolved_args_list.append(self.allocator, slice);
        }
        const extra_resolved_args: [][]types.StateValue = extra_resolved_args_list.items;

        // Convert data outputs (interpreter DataOutputEntry -> ContractOutput)
        // for the tx builder. CallBuildOptions.data_outputs scripts are hex
        // strings; the ANF interpreter already stores `script` as a hex string
        // (matching the TS reference, see conformance/anf-interpreter/expected/
        // add-data-output-publish.json), so we just dupe it.
        // Explicit options.data_outputs wins over the ANF-resolved set.
        var data_outputs_hex: std.ArrayListUnmanaged(types.ContractOutput) = .empty;
        defer {
            for (data_outputs_hex.items) |co| self.allocator.free(@constCast(co.script));
            data_outputs_hex.deinit(self.allocator);
        }
        if (is_stateful) {
            const explicit_do: ?[]const types.ContractOutput =
                if (options) |o| o.data_outputs else null;
            if (explicit_do) |eo| {
                for (eo) |co| {
                    const dup_script = try self.allocator.dupe(u8, co.script);
                    try data_outputs_hex.append(self.allocator, .{ .script = dup_script, .satoshis = co.satoshis });
                }
            } else {
                for (anf_data_outputs) |d| {
                    const dup_script = try self.allocator.dupe(u8, d.script);
                    try data_outputs_hex.append(self.allocator, .{ .script = dup_script, .satoshis = d.satoshis });
                }
            }
        }

        // Issue #133: coin-select the non-terminal call's P2PKH funding inputs
        // instead of sweeping the whole wallet. `additional_utxos` currently
        // holds every candidate wallet UTXO; keep only the smallest-sufficient,
        // largest-first subset (deploy's selectUtxos strategy) that covers the
        // output/fee shortfall the contract's own input value does not.
        {
            var contract_output_sats: i64 = 0;
            if (has_multi_output) {
                for (multi_outputs_hex.items) |co| contract_output_sats += co.satoshis;
            } else if (has_raw_ordered) {
                // Raw + state continuation in source order (finding G1): sum
                // every ordered contract output (raw sats + continuation sats).
                for (raw_ordered_hex.items) |co| contract_output_sats += co.satoshis;
            } else if (new_locking_script.len > 0) {
                contract_output_sats += new_satoshis;
            }
            for (data_outputs_hex.items) |do_| contract_output_sats += do_.satoshis;
            var contract_input_sats: i64 = contract_utxo.satoshis;
            for (extra_contract_utxos) |u| contract_input_sats += u.satoshis;
            const funding_lock_len: usize = if (new_locking_script.len > 0)
                new_locking_script.len / 2
            else if (has_multi_output and multi_outputs_hex.items.len > 0)
                multi_outputs_hex.items[0].script.len / 2
            else
                0;

            // C2: the deploy estimator is blind to the contract input(s) the call
            // spends. Size the funding fee against the SAME serialized per-input
            // bytes buildCallTransaction emits (built here as sizing-only unlocks,
            // freed immediately — the real unlocks are rebuilt below). For a MERGE
            // each covenant input embeds parent txs (tens of KB); ignoring them
            // under-provisions funding and the covenant's [continuation][change]
            // reconstruction then fails hashOutputs. Add a per-contract-input
            // overhead of 2*fundingLockLen + 512 covering the codePart + preimage
            // scriptCode + framing the real unlock carries but the placeholder omits.
            // Over-estimating only pulls slightly more funding (bigger change) — safe.
            const num_contract_inputs: usize = 1 + extra_contract_utxos.len;
            const per_contract_input_overhead: i64 = 2 * @as(i64, @intCast(funding_lock_len)) + 512;
            var contract_input_bytes: i64 = @as(i64, @intCast(num_contract_inputs)) * per_contract_input_overhead;
            if (parent_stateful) {
                const su = try self.buildStatefulUnlockScript(
                    "00" ** 72, resolved_args, method_uses_code_part, change_pkh_hex,
                    0, needs_new_amount, new_satoshis, "00" ** 181, method_selector_hex, witness_hex,
                );
                contract_input_bytes += contractInputSerializedBytes(su.len);
                self.allocator.free(su);
                for (extra_resolved_args) |earg| {
                    const eu = try self.buildStatefulUnlockScript(
                        "00" ** 72, earg, method_uses_code_part, change_pkh_hex,
                        0, needs_new_amount, new_satoshis, "00" ** 181, method_selector_hex, witness_hex,
                    );
                    contract_input_bytes += contractInputSerializedBytes(eu.len);
                    self.allocator.free(eu);
                }
            } else {
                const su = try self.buildUnlockingScript(method_name, resolved_args);
                contract_input_bytes += contractInputSerializedBytes(su.len);
                self.allocator.free(su);
            }

            // C15: size against ALL outputs, not just the single continuation the
            // estimator counts. Sum the framing (8 + varint + scriptLen) of every
            // contract output (multi-output + raw, source order, finding G1) and
            // every data output, then subtract the one output the estimator already
            // covers (funding_lock_len). Clamp >= 0; single-output calls net 0.
            var total_output_framing: i64 = 0;
            if (has_multi_output) {
                for (multi_outputs_hex.items) |co| total_output_framing += outputFramingBytes(co.script.len / 2);
            } else if (has_raw_ordered) {
                for (raw_ordered_hex.items) |co| total_output_framing += outputFramingBytes(co.script.len / 2);
            } else if (new_locking_script.len > 0) {
                total_output_framing += outputFramingBytes(new_locking_script.len / 2);
            }
            for (data_outputs_hex.items) |do_| total_output_framing += outputFramingBytes(do_.script.len / 2);
            var extra_output_bytes: i64 = total_output_framing - outputFramingBytes(funding_lock_len);
            if (extra_output_bytes < 0) extra_output_bytes = 0;

            try self.selectCallFunding(
                &additional_utxos,
                is_terminal_call,
                contract_output_sats,
                contract_input_sats,
                funding_lock_len,
                fee_rate,
                contract_input_bytes,
                extra_output_bytes,
                if (options) |o| o.max_funding_inputs else null,
            );
        }

        // ---------------------------------------------------------------
        // Stateless path
        // ---------------------------------------------------------------
        // Gated on parent_stateful (NOT is_stateful): a StatefulSmartContract
        // with zero mutable fields routes through the OP_PUSH_TX stateful path
        // below so its auto-injected checkPreimage gets a preimage AND its user
        // checkSig is signed over the trimmed subscript (issue #44).
        if (!parent_stateful) {
            // Build unlocking script: args + method selector
            const unlock = try self.buildUnlockingScript(method_name, resolved_args);
            defer self.allocator.free(unlock);

            // Terminal stateless: outputs are the caller-supplied
            // terminal_outputs (replace any auto-computed change), funding
            // inputs are the caller-supplied funding_utxos. No change.
            const stateless_build_opts: call_mod.CallBuildOptions = .{
                .contract_outputs = terminal_outputs,
                // Thread CallOptions.locktime so contracts asserting
                // extractLocktime(preimage) can succeed. null → 0 (legacy).
                .locktime = if (options) |o| o.locktime else null,
                .sequence = if (options) |o| o.sequence else null,
            };
            const stateless_change_address: ?[]const u8 =
                if (is_terminal_call) null else change_address;
            const stateless_build_opts_ptr: ?*const call_mod.CallBuildOptions =
                if (is_terminal_call or (if (options) |o| o.locktime != null else false) or (if (options) |o| o.sequence != null else false)) &stateless_build_opts else null;

            var call_result = call_mod.buildCallTransaction(
                self.allocator,
                contract_utxo,
                unlock,
                "",
                0,
                stateless_change_address,
                additional_utxos.items,
                fee_rate,
                stateless_build_opts_ptr,
            ) catch return ContractError.CallFailed;
            defer call_result.deinit(self.allocator);

            // Sign P2PKH funding inputs
            var signed_tx = try self.allocator.dupe(u8, call_result.tx_hex);
            errdefer self.allocator.free(signed_tx);

            const p2pkh_start: usize = 1;
            var inp_idx: usize = p2pkh_start;
            while (inp_idx < call_result.input_count) : (inp_idx += 1) {
                const utxo_idx = inp_idx - p2pkh_start;
                if (utxo_idx < additional_utxos.items.len) {
                    const utxo = additional_utxos.items[utxo_idx];
                    const sig_val = try funding_sign.sign(self.allocator, signed_tx, inp_idx, utxo.script, utxo.satoshis, null);
                    defer self.allocator.free(sig_val);
                    const pub_key = try funding_sign.getPublicKey(self.allocator);
                    defer self.allocator.free(pub_key);
                    const sig_push = try state_mod.encodePushData(self.allocator, sig_val);
                    defer self.allocator.free(sig_push);
                    const pk_push = try state_mod.encodePushData(self.allocator, pub_key);
                    defer self.allocator.free(pk_push);
                    const p2pkh_unlock = try std.mem.concat(self.allocator, u8, &[_][]const u8{ sig_push, pk_push });
                    defer self.allocator.free(p2pkh_unlock);
                    const new_tx = try insertUnlockingScript(self.allocator, signed_tx, inp_idx, p2pkh_unlock);
                    self.allocator.free(signed_tx);
                    signed_tx = new_tx;
                }
            }

            // Now sign the contract input's Sig params
            for (sig_indices.items) |idx| {
                const real_sig = try sign.sign(self.allocator, signed_tx, 0, contract_utxo.script, contract_utxo.satoshis, null);
                defer self.allocator.free(real_sig);
                resolved_args[idx].deinit(self.allocator);
                resolved_args[idx] = .{ .bytes = try self.allocator.dupe(u8, real_sig) };
            }

            // Rebuild the unlocking script with real signatures
            if (sig_indices.items.len > 0) {
                const real_unlock = try self.buildUnlockingScript(method_name, resolved_args);
                defer self.allocator.free(real_unlock);
                const new_tx = try insertUnlockingScript(self.allocator, signed_tx, 0, real_unlock);
                self.allocator.free(signed_tx);
                signed_tx = new_tx;
            }

            // Broadcast
            const txid = prov.broadcast(self.allocator, signed_tx) catch return ContractError.CallFailed;
            errdefer self.allocator.free(txid);

            // Stateless: UTXO is spent
            if (self.current_utxo) |*old| {
                var mu = old.*;
                mu.deinit(self.allocator);
            }
            self.current_utxo = null;

            self.allocator.free(signed_tx);
            return txid;
        }

        // ---------------------------------------------------------------
        // Stateful path: OP_PUSH_TX with two-pass convergence
        // ---------------------------------------------------------------

        // First pass: build with placeholder unlocking script
        const placeholder_unlock = try self.buildStatefulUnlockScript(
            "00" ** 72, // placeholder sig
            resolved_args,
            method_uses_code_part,
            change_pkh_hex,
            0, // placeholder change amount
            needs_new_amount,
            new_satoshis,
            "00" ** 181, // placeholder preimage
            method_selector_hex,
            witness_hex,
        );
        defer self.allocator.free(placeholder_unlock);

        // Build placeholder unlocks for additional contract inputs. Owned;
        // freed at call-scope exit. Each is a stateful unlock with the same
        // shape as the primary placeholder (zero-sig + zero-preimage), built
        // from per-input resolved args so the placeholder size accurately
        // reflects what each extra input's final unlock will look like.
        var extra_placeholder_unlocks: std.ArrayListUnmanaged([]u8) = .empty;
        defer {
            for (extra_placeholder_unlocks.items) |u| self.allocator.free(u);
            extra_placeholder_unlocks.deinit(self.allocator);
        }
        for (extra_resolved_args) |earg| {
            const u = try self.buildStatefulUnlockScript(
                "00" ** 72,
                earg,
                method_uses_code_part,
                change_pkh_hex,
                0,
                needs_new_amount,
                new_satoshis,
                "00" ** 181,
                method_selector_hex,
                witness_hex,
            );
            try extra_placeholder_unlocks.append(self.allocator, u);
        }

        // Build the AdditionalContractInput slice for the call_mod builder.
        // Reused (with updated unlocks) across the placeholder/rebuild/final
        // tx-build passes.
        var extra_call_inputs: std.ArrayListUnmanaged(call_mod.AdditionalContractInput) = .empty;
        defer extra_call_inputs.deinit(self.allocator);
        for (extra_contract_utxos, 0..) |u, ei| {
            try extra_call_inputs.append(self.allocator, .{
                .utxo = u,
                .unlocking_script = extra_placeholder_unlocks.items[ei],
            });
        }

        // For terminal stateful calls, the contract is fully spent: outputs
        // are exactly `terminal_outputs` (no continuation), there is no
        // change, and funding inputs come from `funding_utxos`.
        // For multi-output stateful (e.g. token transfer): contract_outputs
        // carry the N continuation outputs and we skip the single
        // new_locking_script slot.
        // Otherwise (regular single-continuation stateful), we keep the
        // traditional `new_locking_script + data_outputs + change` layout.
        const stateful_contract_outputs: []const types.ContractOutput = blk: {
            if (is_terminal_call) break :blk terminal_outputs;
            if (has_multi_output) break :blk multi_outputs_hex.items;
            // Finding G1: raw outputs interleaved with the state continuation,
            // in source order. The continuation lives inside this list (not the
            // single new_locking_script slot below).
            if (has_raw_ordered) break :blk raw_ordered_hex.items;
            break :blk &.{};
        };
        const stateful_data_outputs: []const types.ContractOutput =
            if (suppress_continuation) &.{} else data_outputs_hex.items;
        const stateful_change_address: ?[]const u8 =
            if (is_terminal_call) null else change_address;
        // When raw outputs are present the continuation is emitted via
        // contract_outputs (raw_ordered_hex), so the single new_locking_script
        // slot must be empty to avoid double-emitting it (finding G1).
        const stateful_new_locking_script: []const u8 =
            if (suppress_continuation or has_multi_output or has_raw_ordered) "" else new_locking_script;
        const stateful_new_satoshis: i64 =
            if (suppress_continuation or has_multi_output or has_raw_ordered) 0 else new_satoshis;

        const build_opts: call_mod.CallBuildOptions = .{
            .contract_outputs = stateful_contract_outputs,
            .data_outputs = stateful_data_outputs,
            .additional_contract_inputs = extra_call_inputs.items,
            // Thread CallOptions.locktime through the stateful build + rebuild
            // path so the preimage's locktime matches the final on-chain tx.
            .locktime = if (options) |o| o.locktime else null,
                .sequence = if (options) |o| o.sequence else null,
        };
        const build_opts_ptr: ?*const call_mod.CallBuildOptions =
            if (is_terminal_call or has_multi_output or has_raw_ordered or data_outputs_hex.items.len > 0 or extra_call_inputs.items.len > 0 or (if (options) |o| o.locktime != null else false) or (if (options) |o| o.sequence != null else false)) &build_opts else null;

        var call_result = call_mod.buildCallTransaction(
            self.allocator,
            contract_utxo,
            placeholder_unlock,
            stateful_new_locking_script,
            stateful_new_satoshis,
            stateful_change_address,
            additional_utxos.items,
            fee_rate,
            build_opts_ptr,
        ) catch return ContractError.CallFailed;
        defer call_result.deinit(self.allocator);

        var change_amount = call_result.change_amount;

        // Sign P2PKH funding inputs (offset past contract + extra-contract inputs).
        var signed_tx = try self.allocator.dupe(u8, call_result.tx_hex);
        errdefer self.allocator.free(signed_tx);

        const p2pkh_start: usize = 1 + extra_contract_utxos.len;
        {
            var inp_idx: usize = p2pkh_start;
            while (inp_idx < call_result.input_count) : (inp_idx += 1) {
                const utxo_idx = inp_idx - p2pkh_start;
                if (utxo_idx < additional_utxos.items.len) {
                    const utxo = additional_utxos.items[utxo_idx];
                    const sig_val = try funding_sign.sign(self.allocator, signed_tx, inp_idx, utxo.script, utxo.satoshis, null);
                    defer self.allocator.free(sig_val);
                    const pub_key = try funding_sign.getPublicKey(self.allocator);
                    defer self.allocator.free(pub_key);
                    const sig_push = try state_mod.encodePushData(self.allocator, sig_val);
                    defer self.allocator.free(sig_push);
                    const pk_push = try state_mod.encodePushData(self.allocator, pub_key);
                    defer self.allocator.free(pk_push);
                    const p2pkh_unlock = try std.mem.concat(self.allocator, u8, &[_][]const u8{ sig_push, pk_push });
                    defer self.allocator.free(p2pkh_unlock);
                    const new_tx = try insertUnlockingScript(self.allocator, signed_tx, inp_idx, p2pkh_unlock);
                    self.allocator.free(signed_tx);
                    signed_tx = new_tx;
                }
            }
        }

        // Issue #123: build every preimage on this path under the method's
        // declared @sighash mode (default 0x41 for methods with no directive).
        const sig_hash_type = self.methodSigHashType(method_name);

        // First pass: compute OP_PUSH_TX
        var ptx_result = oppushtx_mod.computeOpPushTxWithSigHash(
            self.allocator,
            signed_tx,
            0,
            contract_utxo.script,
            contract_utxo.satoshis,
            code_sep_idx orelse -1,
            sig_hash_type,
        ) catch return ContractError.CallFailed;

        // Build first real unlocking script
        const first_unlock = try self.buildStatefulUnlockScript(
            ptx_result.sig_hex,
            resolved_args,
            method_uses_code_part,
            change_pkh_hex,
            change_amount,
            needs_new_amount,
            new_satoshis,
            ptx_result.preimage_hex,
            method_selector_hex,
            witness_hex,
        );

        // Rebuild transaction with real unlocking script (size may differ)
        {
            var rebuild_result = call_mod.buildCallTransaction(
                self.allocator,
                contract_utxo,
                first_unlock,
                stateful_new_locking_script,
                stateful_new_satoshis,
                stateful_change_address,
                additional_utxos.items,
                fee_rate,
                build_opts_ptr,
            ) catch {
                self.allocator.free(first_unlock);
                ptx_result.deinit(self.allocator);
                return ContractError.CallFailed;
            };
            change_amount = rebuild_result.change_amount;

            self.allocator.free(signed_tx);
            signed_tx = try self.allocator.dupe(u8, rebuild_result.tx_hex);
            rebuild_result.deinit(self.allocator);
        }

        self.allocator.free(first_unlock);

        // Re-sign P2PKH funding inputs. Input layout in the tx:
        //   0:                       primary contract input
        //   1..1+n_extra:            additional contract inputs
        //   1+n_extra..end:          P2PKH funding inputs (these — sign here)
        // Extra contract inputs keep their pre-built placeholder unlocks for
        // this convergence pass; we patch real ones below in the final pass.
        {
            const funding_offset: usize = 1 + extra_call_inputs.items.len;
            for (additional_utxos.items, 0..) |utxo, ui| {
                const inp_idx = funding_offset + ui;
                const sig_val = try funding_sign.sign(self.allocator, signed_tx, inp_idx, utxo.script, utxo.satoshis, null);
                defer self.allocator.free(sig_val);
                const pub_key = try funding_sign.getPublicKey(self.allocator);
                defer self.allocator.free(pub_key);
                const sig_push = try state_mod.encodePushData(self.allocator, sig_val);
                defer self.allocator.free(sig_push);
                const pk_push = try state_mod.encodePushData(self.allocator, pub_key);
                defer self.allocator.free(pk_push);
                const p2pkh_unlock = try std.mem.concat(self.allocator, u8, &[_][]const u8{ sig_push, pk_push });
                defer self.allocator.free(p2pkh_unlock);
                const new_tx = try insertUnlockingScript(self.allocator, signed_tx, inp_idx, p2pkh_unlock);
                self.allocator.free(signed_tx);
                signed_tx = new_tx;
            }
        }

        // Second pass: recompute with final tx (preimage depends on tx size)
        ptx_result.deinit(self.allocator);
        ptx_result = oppushtx_mod.computeOpPushTxWithSigHash(
            self.allocator,
            signed_tx,
            0,
            contract_utxo.script,
            contract_utxo.satoshis,
            code_sep_idx orelse -1,
            sig_hash_type,
        ) catch return ContractError.CallFailed;
        defer ptx_result.deinit(self.allocator);

        // Sign Sig params after convergence. The convergence loop used 72-byte
        // placeholder sigs; the real DER sig may be 70-72 bytes. We do NOT
        // recompute fees/change after signing — the preimage was computed with
        // the placeholder-sized tx, and the slightly smaller real sig just means
        // a marginally higher miner fee. This matches the Python/Go SDK approach.
        if (sig_indices.items.len > 0) {
            var sig_subscript = contract_utxo.script;
            if (code_sep_idx) |cs| {
                const hex_offset: usize = @intCast((@as(usize, @intCast(cs)) + 1) * 2);
                if (hex_offset <= sig_subscript.len) {
                    sig_subscript = sig_subscript[hex_offset..];
                }
            }
            for (sig_indices.items) |idx| {
                const real_sig = try sign.sign(self.allocator, signed_tx, 0, sig_subscript, contract_utxo.satoshis, null);
                resolved_args[idx].deinit(self.allocator);
                resolved_args[idx] = .{ .bytes = real_sig };
            }
        }

        // Substitute the real concatenated prevouts into every ByteString
        // param the caller asked us to auto-resolve. The contract verifies
        // hash256(allPrevouts) == extractHashPrevouts(ctx.txPreimage); the
        // placeholder zero-byte string we used during the convergence pass
        // would fail that check. Mirrors Go's loop at sdk_contract.go:686.
        if (prevouts_indices.items.len > 0) {
            const real_prevouts = try extractAllPrevoutsHex(self.allocator, signed_tx);
            defer self.allocator.free(real_prevouts);
            for (prevouts_indices.items) |idx| {
                resolved_args[idx].deinit(self.allocator);
                resolved_args[idx] = .{ .bytes = try self.allocator.dupe(u8, real_prevouts) };
            }
        }

        // Build final unlocking script
        const final_unlock = try self.buildStatefulUnlockScript(
            ptx_result.sig_hex,
            resolved_args,
            method_uses_code_part,
            change_pkh_hex,
            change_amount,
            needs_new_amount,
            new_satoshis,
            ptx_result.preimage_hex,
            method_selector_hex,
            witness_hex,
        );
        defer self.allocator.free(final_unlock);

        const final_tx = try insertUnlockingScript(self.allocator, signed_tx, 0, final_unlock);
        self.allocator.free(signed_tx);
        signed_tx = final_tx;

        // Build & insert real unlocks for each additional contract input.
        // Each input gets its own preimage (BIP-143 sighash depends on input
        // index) and its own placeholder→real arg resolution. nil entries
        // inside an input's arg slot mean "auto-resolve" — Sig auto-signs,
        // ByteString param treated as allPrevouts gets the substituted value.
        for (extra_contract_utxos, 0..) |xu, ei| {
            const inp_idx = 1 + ei;
            // Per-input args: copy primary resolved_args (which already has
            // real sig for slot 0 and real prevouts substituted), then apply
            // any per-input overrides from `additional_contract_input_args`.
            var per_input_args = try self.allocator.alloc(types.StateValue, resolved_args.len);
            defer {
                for (per_input_args) |*pa| pa.deinit(self.allocator);
                self.allocator.free(per_input_args);
            }
            for (resolved_args, 0..) |a, ai| per_input_args[ai] = try a.clone(self.allocator);

            if (options) |o| {
                if (o.additional_contract_input_args) |aia| {
                    if (ei < aia.len) {
                        const overrides = aia[ei];
                        for (overrides, 0..) |ov, oi| {
                            if (oi >= per_input_args.len) break;
                            // `.int = 0` means "auto-resolve" for Sig/ByteString
                            // (same convention as the primary args). For other
                            // types, a literal 0 user value is taken at face.
                            if (ov == .int and ov.int == 0) {
                                const ptype = user_params[oi].type_name;
                                if (std.mem.eql(u8, ptype, "Sig")) {
                                    var sig_subscript = xu.script;
                                    if (code_sep_idx) |cs| {
                                        const off: usize = @intCast((@as(usize, @intCast(cs)) + 1) * 2);
                                        if (off <= sig_subscript.len) sig_subscript = sig_subscript[off..];
                                    }
                                    const real_sig = try sign.sign(self.allocator, signed_tx, inp_idx, sig_subscript, xu.satoshis, null);
                                    per_input_args[oi].deinit(self.allocator);
                                    per_input_args[oi] = .{ .bytes = real_sig };
                                    continue;
                                }
                                // Name-gated exactly like the primary resolution:
                                // only the well-known `allPrevouts` slot is the
                                // SDK's to fill. For any other ByteString param
                                // `.int = 0` is the caller's own empty value, and
                                // substituting prevouts here is what actually
                                // reaches the chain (the placeholder pass above
                                // is only used for fee sizing).
                                if ((std.mem.eql(u8, ptype, "ByteString") or std.mem.eql(u8, ptype, "Ripemd160")) and
                                    std.mem.eql(u8, user_params[oi].name, AUTO_PREVOUTS_PARAM_NAME))
                                {
                                    const real_pv = try extractAllPrevoutsHex(self.allocator, signed_tx);
                                    per_input_args[oi].deinit(self.allocator);
                                    per_input_args[oi] = .{ .bytes = real_pv };
                                    continue;
                                }
                            }
                            per_input_args[oi].deinit(self.allocator);
                            per_input_args[oi] = try ov.clone(self.allocator);
                        }
                    }
                }
            }

            // Compute OP_PUSH_TX preimage for this input.
            var xptx = oppushtx_mod.computeOpPushTxWithSigHash(
                self.allocator,
                signed_tx,
                inp_idx,
                xu.script,
                xu.satoshis,
                code_sep_idx orelse -1,
                sig_hash_type,
            ) catch return ContractError.CallFailed;
            defer xptx.deinit(self.allocator);

            const x_unlock = try self.buildStatefulUnlockScript(
                xptx.sig_hex,
                per_input_args,
                method_uses_code_part,
                change_pkh_hex,
                change_amount,
                needs_new_amount,
                new_satoshis,
                xptx.preimage_hex,
                method_selector_hex,
                witness_hex,
            );
            defer self.allocator.free(x_unlock);
            const new_tx = try insertUnlockingScript(self.allocator, signed_tx, inp_idx, x_unlock);
            self.allocator.free(signed_tx);
            signed_tx = new_tx;
        }

        // Re-sign P2PKH funding inputs after final unlock insertion (matches Go/Python SDKs).
        // Funding inputs sit AFTER the primary contract input and AFTER any
        // additional contract inputs.
        {
            const funding_offset: usize = 1 + extra_call_inputs.items.len;
            for (additional_utxos.items, 0..) |utxo, ui| {
                const inp_idx = funding_offset + ui;
                const sig_val = try funding_sign.sign(self.allocator, signed_tx, inp_idx, utxo.script, utxo.satoshis, null);
                defer self.allocator.free(sig_val);
                const pub_key = try funding_sign.getPublicKey(self.allocator);
                defer self.allocator.free(pub_key);
                const s_push = try state_mod.encodePushData(self.allocator, sig_val);
                defer self.allocator.free(s_push);
                const p_push = try state_mod.encodePushData(self.allocator, pub_key);
                defer self.allocator.free(p_push);
                const p2pkh_u = try std.mem.concat(self.allocator, u8, &[_][]const u8{ s_push, p_push });
                defer self.allocator.free(p2pkh_u);
                const new_tx = try insertUnlockingScript(self.allocator, signed_tx, inp_idx, p2pkh_u);
                self.allocator.free(signed_tx);
                signed_tx = new_tx;
            }
        }

        // Broadcast
        const txid = prov.broadcast(self.allocator, signed_tx) catch return ContractError.CallFailed;
        errdefer self.allocator.free(txid);

        // Update tracked UTXO. For terminal stateful calls the contract is
        // fully spent (no continuation) — drop the current UTXO. For
        // non-terminal stateful calls, the continuation lives at output 0
        // of the broadcast tx.
        if (self.current_utxo) |*old| {
            var mu = old.*;
            mu.deinit(self.allocator);
        }
        if (suppress_continuation) {
            // Terminal call or zero-mutable stateful spend: fully spent, no
            // continuation UTXO to track.
            self.current_utxo = null;
        } else if (has_raw_ordered) {
            // Finding G1: raw outputs pushed ahead of the state continuation, so
            // it is no longer output 0. Track it at its REAL index and value
            // (which may legitimately be 0) by finding the ordered contract
            // output whose script is the continuation locking script.
            var cont_idx: i32 = 0;
            var cont_sats: i64 = new_satoshis;
            for (raw_ordered_hex.items, 0..) |co, i| {
                if (std.mem.eql(u8, co.script, new_locking_script)) {
                    cont_idx = @intCast(i);
                    cont_sats = co.satoshis;
                    break;
                }
            }
            self.current_utxo = .{
                .txid = try self.allocator.dupe(u8, txid),
                .output_index = cont_idx,
                .satoshis = cont_sats,
                .script = try self.allocator.dupe(u8, new_locking_script),
            };
        } else {
            self.current_utxo = .{
                .txid = try self.allocator.dupe(u8, txid),
                .output_index = 0,
                .satoshis = new_satoshis,
                .script = try self.allocator.dupe(u8, new_locking_script),
            };
        }

        self.allocator.free(signed_tx);
        return txid;
    }

    // ------------------------------------------------------------------
    // Multi-signer API (prepareCall / finalizeCall)
    // ------------------------------------------------------------------

    /// Prepare a method call for external signing. Mirrors the Go SDK's
    /// `PrepareCall`, the Ruby SDK's `prepare_call`, and Java's
    /// `prepareCall`.
    ///
    /// Builds the call transaction with 72-byte zero-filled placeholders
    /// at every `Sig` slot, signs all P2PKH funding inputs with the
    /// connected signer, and returns a `PreparedCall` containing the
    /// BIP-143 sighash(es) for an external signer to sign. Pass the
    /// resulting DER signature(s) back via `finalizeCall`.
    ///
    /// Supports stateless contracts and stateful contracts that
    /// expose `Sig` params on their public methods. Stateful
    /// `prepareCall` runs the full OP_PUSH_TX preimage convergence
    /// with 72-byte zero-filled Sig placeholders, captures the
    /// converged preimage and the k=1 OP_PUSH_TX signature in the
    /// returned `PreparedCall`, then computes the BIP-143 sighash
    /// over the placeholder-sized tx. `finalizeCall` splices the
    /// external signatures back into the same unlock script — BIP-143
    /// excludes input scriptSigs from the sighash, so the externally
    /// signed message remains valid even though the real DER sig may
    /// be 1–2 bytes shorter than the placeholder. The miner sees a
    /// marginally higher effective fee; the contract verifies cleanly.
    pub fn prepareCall(
        self: *RunarContract,
        method_name: []const u8,
        args: []const types.StateValue,
        prov_arg: ?provider_mod.Provider,
        signer_arg: ?signer_mod.Signer,
        options: ?types.CallOptions,
    ) !types.PreparedCall {
        const prov = prov_arg orelse self.provider orelse return ContractError.NoProviderOrSigner;
        const sign = signer_arg orelse self.signer orelse return ContractError.NoProviderOrSigner;
        // Funding (and terminal fee) inputs are signed by fundingSigner when set
        // (issue #134); the method's own Sig args stay with the connected signer.
        const funding_sign = if (options) |o| (o.funding_signer orelse sign) else sign;

        if (self.current_utxo == null) return ContractError.NotDeployed;
        const contract_utxo = self.current_utxo.?;

        // DoS-bound: reject pathological scripts BEFORE any signing / broadcast.
        {
            var ctx_buf: [256]u8 = undefined;
            const ctx = std.fmt.bufPrint(&ctx_buf, "{s}.prepareCall({s})", .{ self.artifact.contract_name, method_name }) catch "RunarContract.prepareCall";
            try errors_mod.assertScriptHexUnderLimit(contract_utxo.script, errors_mod.MAX_SCRIPT_BYTES, ctx);
        }

        const is_stateful = self.artifact.state_fields.len > 0;
        if (is_stateful) {
            return self.prepareCallStateful(method_name, args, prov, sign, options);
        }

        const abi_method = self.findMethod(method_name) orelse return ContractError.MethodNotFound;
        if (args.len != abi_method.params.len) return ContractError.ArgCountMismatch;
        // N-045 (defence in depth): a fixed-width arg must have its declared width.
        try checkFixedWidthArgs(abi_method.params, args);

        // ---- Resolve user args ------------------------------------------
        var resolved_args = try self.allocator.alloc(types.StateValue, args.len);
        var resolved_filled: usize = 0;
        errdefer {
            var i: usize = 0;
            while (i < resolved_filled) : (i += 1) resolved_args[i].deinit(self.allocator);
            self.allocator.free(resolved_args);
        }

        var sig_idx_list: std.ArrayListUnmanaged(usize) = .empty;
        defer sig_idx_list.deinit(self.allocator);

        for (args, 0..) |arg, i| {
            const param_type = abi_method.params[i].type_name;
            if (std.mem.eql(u8, param_type, "Sig") and arg == .int and arg.int == 0) {
                try sig_idx_list.append(self.allocator, i);
                resolved_args[i] = .{ .bytes = try self.allocator.dupe(u8, "00" ** 72) };
            } else if (std.mem.eql(u8, param_type, "PubKey") and arg == .int and arg.int == 0) {
                resolved_args[i] = .{ .bytes = try sign.getPublicKey(self.allocator) };
            } else {
                resolved_args[i] = try arg.clone(self.allocator);
            }
            resolved_filled = i + 1;
        }

        // ---- Funding UTXOs + change address -----------------------------
        const address = try sign.getAddress(self.allocator);
        defer self.allocator.free(address);
        const change_address = if (options) |o| (o.change_address orelse address) else address;

        // Terminal-output detection: caller-supplied outputs replace the
        // automatic continuation/change layout. See `call()` for details.
        const is_terminal_call = if (options) |o| o.terminal_outputs != null else false;
        // N-271: see the identical guard in `call()` -- this builder also
        // lays out exactly one contract input for a terminal call.
        if (is_terminal_call) {
            if (options) |o| {
                if (o.additional_contract_inputs) |aci| {
                    if (aci.len > 0) return ContractError.TerminalAdditionalContractInputsUnsupported;
                }
            }
        }
        // N-276 (port of N-227 Part 2 / N-258): this branch is prepareCall's
        // entire non-stateful path (entered whenever is_stateful is false --
        // the dispatch to prepareCallStateful above only catches real
        // StatefulSmartContracts). It has NO per-input unlock builder for
        // ANY non-stateful shape (plain SmartContract or zero-mutable-field
        // StatefulSmartContract): it never reads
        // options.additional_contract_inputs outside the terminal check
        // above. Unlike call() (which threads extras for the zero-mutable
        // case via its own `!parent_stateful` gate), there is no
        // "legitimate" merge path here to preserve, so this refusal is
        // unconditional within this branch.
        if (options) |o| {
            if (o.additional_contract_inputs) |aci| {
                if (aci.len > 0) return ContractError.AdditionalContractInputsUnsupported;
            }
        }
        const terminal_outputs: []const types.ContractOutput =
            if (is_terminal_call) options.?.terminal_outputs.? else &.{};
        const terminal_funding: []const types.UTXO =
            if (is_terminal_call) (if (options.?.funding_utxos) |fu| fu else &.{}) else &.{};

        const fee_rate = prov.getFeeRate() catch 100;
        const all_utxos: []types.UTXO = if (is_terminal_call)
            &.{}
        else
            prov.getUtxos(self.allocator, address) catch return ContractError.CallFailed;
        defer if (!is_terminal_call) {
            for (all_utxos) |*u| u.deinit(self.allocator);
            if (all_utxos.len > 0) self.allocator.free(all_utxos);
        };

        var additional_utxos: std.ArrayListUnmanaged(types.UTXO) = .empty;
        defer additional_utxos.deinit(self.allocator);
        if (is_terminal_call) {
            for (terminal_funding) |u| try additional_utxos.append(self.allocator, u);
            // Issue #118: a single P2PKH fee input, added BEFORE the OP_PUSH_TX
            // preimage and consumed entirely as fee (no change output). Merges
            // into the same terminal funding-input path as funding_utxos.
            if (options) |o| if (o.fee_utxo) |fee| try additional_utxos.append(self.allocator, fee);
        } else {
            for (all_utxos) |u| {
                if (!(std.mem.eql(u8, u.txid, contract_utxo.txid) and u.output_index == contract_utxo.output_index)) {
                    try additional_utxos.append(self.allocator, u);
                }
            }
        }

        // ---- Build placeholder unlock (sized into funding fee below) -----
        const placeholder_unlock = try self.buildUnlockingScript(method_name, resolved_args);
        defer self.allocator.free(placeholder_unlock);

        // Issue #133: coin-select funding instead of sweeping the wallet. A
        // stateless prepare has no continuation output (build is called with no
        // new locking script), so contract_output_sats is 0 and there are no
        // extra outputs (C15 = 0). C2: still size the fee against the single
        // contract input's unlock bytes the deploy estimator ignores.
        const contract_input_bytes: i64 =
            contractInputSerializedBytes(placeholder_unlock.len) + 512;
        try self.selectCallFunding(
            &additional_utxos,
            is_terminal_call,
            0,
            contract_utxo.satoshis,
            0,
            fee_rate,
            contract_input_bytes,
            0,
            if (options) |o| o.max_funding_inputs else null,
        );

        const stateless_build_opts: call_mod.CallBuildOptions = .{
            .contract_outputs = terminal_outputs,
            // Thread CallOptions.locktime so contracts asserting
            // extractLocktime(preimage) can succeed. null → 0 (legacy).
            .locktime = if (options) |o| o.locktime else null,
                .sequence = if (options) |o| o.sequence else null,
        };
        const stateless_change_address: ?[]const u8 =
            if (is_terminal_call) null else change_address;
        const stateless_build_opts_ptr: ?*const call_mod.CallBuildOptions =
            if (is_terminal_call or (if (options) |o| o.locktime != null else false) or (if (options) |o| o.sequence != null else false)) &stateless_build_opts else null;

        var call_result = call_mod.buildCallTransaction(
            self.allocator,
            contract_utxo,
            placeholder_unlock,
            "",
            0,
            stateless_change_address,
            additional_utxos.items,
            fee_rate,
            stateless_build_opts_ptr,
        ) catch return ContractError.CallFailed;
        defer call_result.deinit(self.allocator);

        // ---- Sign P2PKH funding inputs (so external signer only owns Sig) ----
        var signed_tx = try self.allocator.dupe(u8, call_result.tx_hex);
        errdefer self.allocator.free(signed_tx);

        {
            var inp_idx: usize = 1;
            while (inp_idx < call_result.input_count) : (inp_idx += 1) {
                const utxo_idx = inp_idx - 1;
                if (utxo_idx >= additional_utxos.items.len) break;
                const utxo = additional_utxos.items[utxo_idx];
                const sig_val = try funding_sign.sign(self.allocator, signed_tx, inp_idx, utxo.script, utxo.satoshis, null);
                defer self.allocator.free(sig_val);
                const pub_key = try funding_sign.getPublicKey(self.allocator);
                defer self.allocator.free(pub_key);
                const sig_push = try state_mod.encodePushData(self.allocator, sig_val);
                defer self.allocator.free(sig_push);
                const pk_push = try state_mod.encodePushData(self.allocator, pub_key);
                defer self.allocator.free(pk_push);
                const p2pkh_unlock = try std.mem.concat(self.allocator, u8, &[_][]const u8{ sig_push, pk_push });
                defer self.allocator.free(p2pkh_unlock);
                const new_tx = try insertUnlockingScript(self.allocator, signed_tx, inp_idx, p2pkh_unlock);
                self.allocator.free(signed_tx);
                signed_tx = new_tx;
            }
        }

        // ---- Compute BIP-143 sighash for input 0 ------------------------
        // BIP-143 is invariant under scriptSig contents (it hashes the
        // *subscript* — the locking script of the input being signed —
        // not the unlocking script). Every Sig placeholder in the same
        // input therefore needs the same sighash, so we compute it once.
        var sighashes = try self.allocator.alloc([]const u8, sig_idx_list.items.len);
        var sighashes_filled: usize = 0;
        errdefer {
            var i: usize = 0;
            while (i < sighashes_filled) : (i += 1) self.allocator.free(@constCast(sighashes[i]));
            if (sighashes.len > 0) self.allocator.free(sighashes);
        }

        if (sig_idx_list.items.len > 0) {
            const sh_hex = try computeBip143Sighash(
                self.allocator, signed_tx, 0, contract_utxo.script, contract_utxo.satoshis,
            );
            defer self.allocator.free(sh_hex);
            for (sighashes, 0..) |_, i| {
                sighashes[i] = try self.allocator.dupe(u8, sh_hex);
                sighashes_filled = i + 1;
            }
        }

        const sig_indices_owned = try self.allocator.dupe(usize, sig_idx_list.items);
        const method_name_owned = try self.allocator.dupe(u8, method_name);
        const utxo_owned = try contract_utxo.clone(self.allocator);

        return types.PreparedCall{
            .tx_hex = signed_tx,
            .sighashes = sighashes,
            .sig_indices = sig_indices_owned,
            .method_name = method_name_owned,
            .resolved_args = resolved_args,
            .contract_utxo = utxo_owned,
            .is_stateful = false,
            .new_locking_script = &.{},
            .new_satoshis = 0,
        };
    }

    /// Stateful prepareCall — mirrors the OP_PUSH_TX two-pass convergence
    /// in `call()` but stops short of signing the user-Sig parameters.
    /// Captures the converged preimage and OP_PUSH_TX k=1 signature so
    /// `finalizeCall` can rebuild the stateful unlock with the same
    /// preimage-equality witness after splicing external Sigs.
    ///
    /// State auto-compute via the ANF interpreter is intentionally NOT
    /// run here — for prepare/finalize flows the caller should pass
    /// `options.new_state` explicitly so the prepared tx commits to a
    /// known continuation. (The ANF interpreter requires the artifact's
    /// `anfJson`, which most prepare/finalize callers do not have.)
    fn prepareCallStateful(
        self: *RunarContract,
        method_name: []const u8,
        args: []const types.StateValue,
        prov: provider_mod.Provider,
        sign: signer_mod.Signer,
        options: ?types.CallOptions,
    ) !types.PreparedCall {
        const contract_utxo = self.current_utxo.?;
        // Funding (and terminal fee) inputs are signed by fundingSigner when set
        // (issue #134); the method's own Sig args stay with the connected signer.
        const funding_sign = if (options) |o| (o.funding_signer orelse sign) else sign;

        // ---- Method lookup + multi-method index --------------------------
        const public_methods = try self.getPublicMethods();
        defer self.allocator.free(public_methods);

        var method_index: usize = 0;
        if (public_methods.len > 1) {
            for (public_methods, 0..) |m, i| {
                if (std.mem.eql(u8, m.name, method_name)) {
                    method_index = i;
                    break;
                }
            }
        }

        const abi_method = self.findMethod(method_name) orelse return ContractError.MethodNotFound;

        var needs_change = false;
        var needs_new_amount = false;
        for (abi_method.params) |p| {
            if (std.mem.eql(u8, p.name, "_changePKH")) needs_change = true;
            if (std.mem.eql(u8, p.name, "_newAmount")) needs_new_amount = true;
        }
        // _codePart prefix decision (issue #100); see other call site.
        const method_uses_code_part = abi_method.uses_code_part orelse needs_change;

        // ---- Filter user params ------------------------------------------
        // Drop auto-injected continuation params AND intent-intrinsic
        // witness params (`_prevOutScript_<i>`, `_serialisedOutputs`) from
        // the user-facing arg count check. Witness values come from
        // setPrevOutScript / setSerialisedOutputs, not the args slice.
        const isAutoInjectedWitness = struct {
            fn check(name: []const u8) bool {
                return std.mem.startsWith(u8, name, "_prevOutScript_") or
                    std.mem.eql(u8, name, "_serialisedOutputs");
            }
        }.check;

        var user_param_count: usize = 0;
        for (abi_method.params) |p| {
            if (!std.mem.eql(u8, p.type_name, "SigHashPreimage") and
                !std.mem.eql(u8, p.name, "_changePKH") and
                !std.mem.eql(u8, p.name, "_changeAmount") and
                !std.mem.eql(u8, p.name, "_newAmount") and
                !isAutoInjectedWitness(p.name))
            {
                user_param_count += 1;
            }
        }
        if (args.len != user_param_count) return ContractError.ArgCountMismatch;

        var user_params = try self.allocator.alloc(types.ABIParam, user_param_count);
        defer self.allocator.free(user_params);
        {
            var idx: usize = 0;
            for (abi_method.params) |p| {
                if (!std.mem.eql(u8, p.type_name, "SigHashPreimage") and
                    !std.mem.eql(u8, p.name, "_changePKH") and
                    !std.mem.eql(u8, p.name, "_changeAmount") and
                    !std.mem.eql(u8, p.name, "_newAmount") and
                    !isAutoInjectedWitness(p.name))
                {
                    user_params[idx] = p;
                    idx += 1;
                }
            }
        }

        // N-045 (defence in depth): a fixed-width arg must have its declared width.
        try checkFixedWidthArgs(user_params, args);

        // ---- Resolve args (Sig → 72-byte placeholder) --------------------
        var resolved_args = try self.allocator.alloc(types.StateValue, args.len);
        var resolved_filled: usize = 0;
        errdefer {
            var i: usize = 0;
            while (i < resolved_filled) : (i += 1) resolved_args[i].deinit(self.allocator);
            self.allocator.free(resolved_args);
        }

        var sig_idx_list: std.ArrayListUnmanaged(usize) = .empty;
        defer sig_idx_list.deinit(self.allocator);

        for (args, 0..) |arg, i| {
            const param_type = user_params[i].type_name;
            if (std.mem.eql(u8, param_type, "Sig") and arg == .int and arg.int == 0) {
                try sig_idx_list.append(self.allocator, i);
                resolved_args[i] = .{ .bytes = try self.allocator.dupe(u8, "00" ** 72) };
            } else if (std.mem.eql(u8, param_type, "PubKey") and arg == .int and arg.int == 0) {
                resolved_args[i] = .{ .bytes = try sign.getPublicKey(self.allocator) };
            } else {
                resolved_args[i] = try arg.clone(self.allocator);
            }
            resolved_filled = i + 1;
        }

        // ---- Funding UTXOs + change address ------------------------------
        const address = try sign.getAddress(self.allocator);
        defer self.allocator.free(address);
        const change_address = if (options) |o| (o.change_address orelse address) else address;

        // Terminal-output detection (mirrors `call`). When the caller
        // supplies `terminal_outputs`, the prepared tx has no continuation
        // and no change; funding inputs come from `funding_utxos`.
        const is_terminal_call = if (options) |o| o.terminal_outputs != null else false;
        // N-271: see the identical guard in `call()` -- this builder also
        // lays out exactly one contract input for a terminal call.
        if (is_terminal_call) {
            if (options) |o| {
                if (o.additional_contract_inputs) |aci| {
                    if (aci.len > 0) return ContractError.TerminalAdditionalContractInputsUnsupported;
                }
            }
        }
        const terminal_outputs: []const types.ContractOutput =
            if (is_terminal_call) options.?.terminal_outputs.? else &.{};
        const terminal_funding: []const types.UTXO =
            if (is_terminal_call) (if (options.?.funding_utxos) |fu| fu else &.{}) else &.{};

        const fee_rate = prov.getFeeRate() catch 100;
        const all_utxos: []types.UTXO = if (is_terminal_call)
            &.{}
        else
            prov.getUtxos(self.allocator, address) catch return ContractError.CallFailed;
        defer if (!is_terminal_call) {
            for (all_utxos) |*u| u.deinit(self.allocator);
            if (all_utxos.len > 0) self.allocator.free(all_utxos);
        };

        var additional_utxos: std.ArrayListUnmanaged(types.UTXO) = .empty;
        defer additional_utxos.deinit(self.allocator);
        if (is_terminal_call) {
            for (terminal_funding) |u| try additional_utxos.append(self.allocator, u);
            // Issue #118: a single P2PKH fee input, added BEFORE the OP_PUSH_TX
            // preimage and consumed entirely as fee (no change output). Merges
            // into the same terminal funding-input path as funding_utxos.
            if (options) |o| if (o.fee_utxo) |fee| try additional_utxos.append(self.allocator, fee);
        } else {
            for (all_utxos) |u| {
                if (!(std.mem.eql(u8, u.txid, contract_utxo.txid) and u.output_index == contract_utxo.output_index)) {
                    try additional_utxos.append(self.allocator, u);
                }
            }
        }

        // ---- Apply explicit new_state (no ANF auto-compute in prepare) ---
        var new_satoshis: i64 = contract_utxo.satoshis;
        if (options) |o| {
            if (o.satoshis > 0) new_satoshis = o.satoshis;
            if (o.new_state) |ns| {
                for (self.state) |*s| s.deinit(self.allocator);
                if (self.state.len > 0) self.allocator.free(self.state);
                var vals = try self.allocator.alloc(types.StateValue, ns.len);
                for (ns, 0..) |s, i| vals[i] = try s.clone(self.allocator);
                self.state = vals;
            }
        }

        // Continuation locking script — empty for terminal calls.
        const new_locking_script: []u8 = if (is_terminal_call)
            try self.allocator.alloc(u8, 0)
        else
            try self.getLockingScript();
        errdefer self.allocator.free(new_locking_script);
        const stateful_new_satoshis: i64 = if (is_terminal_call) 0 else new_satoshis;
        const stateful_change_address: ?[]const u8 =
            if (is_terminal_call) null else change_address;
        const stateful_build_opts: call_mod.CallBuildOptions = .{
            .contract_outputs = terminal_outputs,
            // Thread CallOptions.locktime through both the prepare build and
            // rebuild paths so the preimage matches the final on-chain tx.
            .locktime = if (options) |o| o.locktime else null,
                .sequence = if (options) |o| o.sequence else null,
        };
        const stateful_build_opts_ptr: ?*const call_mod.CallBuildOptions =
            if (is_terminal_call or (if (options) |o| o.locktime != null else false) or (if (options) |o| o.sequence != null else false)) &stateful_build_opts else null;

        // (Issue #133 funding coin-selection runs AFTER the placeholder unlock is
        // built, below, so finding C2 can size the fee against that input's real
        // unlock bytes.)

        // ---- Compute change PKH for stateful methods needing it ----------
        var change_pkh_buf: []u8 = &.{};
        errdefer if (change_pkh_buf.len > 0) self.allocator.free(change_pkh_buf);
        if (needs_change) {
            const pub_key_hex = try sign.getPublicKey(self.allocator);
            defer self.allocator.free(pub_key_hex);
            const pub_key_bytes = try state_mod.hexToBytes(self.allocator, pub_key_hex);
            defer self.allocator.free(pub_key_bytes);
            const ripe_hash = bsvz.crypto.hash.hash160(pub_key_bytes);
            change_pkh_buf = try self.allocator.alloc(u8, 40);
            _ = bsvz.primitives.hex.encodeLower(&ripe_hash.bytes, change_pkh_buf) catch {
                self.allocator.free(change_pkh_buf);
                return ContractError.CallFailed;
            };
        }

        // ---- Method selector hex -----------------------------------------
        var method_selector_buf: []u8 = &.{};
        errdefer if (method_selector_buf.len > 0) self.allocator.free(method_selector_buf);
        if (public_methods.len > 1) {
            method_selector_buf = try state_mod.encodeScriptNumber(self.allocator, @intCast(method_index));
        }

        const code_sep_idx = (try self.getCodeSepIndex(method_index)) orelse -1;

        // Pre-resolve intent-intrinsic witness hex (returns
        // `error.WitnessValueMissing` if a `_prevOutScript_<i>` or
        // `_serialisedOutputs` param wasn't set on the contract).
        const witness_hex = try self.buildIntentWitnessHex(abi_method);
        defer self.allocator.free(witness_hex);

        // ---- Pass 1: placeholder unlock → tx → P2PKH sign → preimage -----
        const change_pkh_opt: ?[]const u8 = if (change_pkh_buf.len > 0) change_pkh_buf else null;
        const method_selector_opt: ?[]const u8 = if (method_selector_buf.len > 0) method_selector_buf else null;

        const placeholder_unlock = try self.buildStatefulUnlockScript(
            "00" ** 72, resolved_args,
            method_uses_code_part, change_pkh_opt, 0,
            needs_new_amount, new_satoshis,
            "00" ** 181, method_selector_opt,
            witness_hex,
        );
        defer self.allocator.free(placeholder_unlock);

        // Issue #133: coin-select funding instead of sweeping the wallet. The
        // continuation output value (stateful_new_satoshis) is the only output
        // this prepare path emits before change; no data/multi outputs, so C15
        // extra_output_bytes nets 0. C2: size the fee against the contract input's
        // real unlock bytes (codePart + args + preimage) the deploy estimator is
        // blind to, plus the 2*fundingLockLen + 512 per-input overhead.
        {
            const funding_lock_len: usize = if (new_locking_script.len > 0) new_locking_script.len / 2 else 0;
            const contract_input_bytes: i64 =
                contractInputSerializedBytes(placeholder_unlock.len) +
                2 * @as(i64, @intCast(funding_lock_len)) + 512;
            try self.selectCallFunding(
                &additional_utxos,
                is_terminal_call,
                stateful_new_satoshis,
                contract_utxo.satoshis,
                funding_lock_len,
                fee_rate,
                contract_input_bytes,
                0,
                if (options) |o| o.max_funding_inputs else null,
            );
        }

        var call_result = call_mod.buildCallTransaction(
            self.allocator, contract_utxo, placeholder_unlock,
            new_locking_script, stateful_new_satoshis, stateful_change_address,
            additional_utxos.items, fee_rate, stateful_build_opts_ptr,
        ) catch return ContractError.CallFailed;
        defer call_result.deinit(self.allocator);

        var change_amount = call_result.change_amount;

        var signed_tx = try self.allocator.dupe(u8, call_result.tx_hex);
        errdefer self.allocator.free(signed_tx);

        try signFundingInputs(self, &signed_tx, funding_sign, additional_utxos.items, call_result.input_count);

        // Issue #123: build the preimage under the method's declared @sighash
        // mode (default 0x41 for methods with no directive).
        const sig_hash_type = self.methodSigHashType(method_name);

        var ptx_result = oppushtx_mod.computeOpPushTxWithSigHash(
            self.allocator, signed_tx, 0,
            contract_utxo.script, contract_utxo.satoshis, code_sep_idx,
            sig_hash_type,
        ) catch return ContractError.CallFailed;

        // ---- Pass 2: rebuild with real preimage + real change_amount -----
        {
            const first_unlock = try self.buildStatefulUnlockScript(
                ptx_result.sig_hex, resolved_args,
                method_uses_code_part, change_pkh_opt, change_amount,
                needs_new_amount, new_satoshis,
                ptx_result.preimage_hex, method_selector_opt,
                witness_hex,
            );
            errdefer self.allocator.free(first_unlock);

            var rebuild_result = call_mod.buildCallTransaction(
                self.allocator, contract_utxo, first_unlock,
                new_locking_script, stateful_new_satoshis, stateful_change_address,
                additional_utxos.items, fee_rate, stateful_build_opts_ptr,
            ) catch {
                self.allocator.free(first_unlock);
                ptx_result.deinit(self.allocator);
                return ContractError.CallFailed;
            };
            change_amount = rebuild_result.change_amount;

            self.allocator.free(signed_tx);
            signed_tx = try self.allocator.dupe(u8, rebuild_result.tx_hex);
            rebuild_result.deinit(self.allocator);
            self.allocator.free(first_unlock);
        }

        try signFundingInputs(self, &signed_tx, funding_sign, additional_utxos.items, 1 + additional_utxos.items.len);

        // Recompute preimage on the final tx (depends on tx size).
        ptx_result.deinit(self.allocator);
        ptx_result = oppushtx_mod.computeOpPushTxWithSigHash(
            self.allocator, signed_tx, 0,
            contract_utxo.script, contract_utxo.satoshis, code_sep_idx,
            sig_hash_type,
        ) catch return ContractError.CallFailed;
        defer ptx_result.deinit(self.allocator);

        // Insert the final placeholder unlock (real preimage + placeholder Sig)
        // into the tx so finalizeCall just splices Sig and broadcasts.
        const final_placeholder = try self.buildStatefulUnlockScript(
            ptx_result.sig_hex, resolved_args,
            method_uses_code_part, change_pkh_opt, change_amount,
            needs_new_amount, new_satoshis,
            ptx_result.preimage_hex, method_selector_opt,
            witness_hex,
        );
        defer self.allocator.free(final_placeholder);

        const tx_with_final = try insertUnlockingScript(self.allocator, signed_tx, 0, final_placeholder);
        self.allocator.free(signed_tx);
        signed_tx = tx_with_final;

        // ---- BIP-143 sighash for the contract input ---------------------
        // Subscript honours the OP_CODESEPARATOR boundary: only the bytes
        // after the separator participate in the sighash.
        var sig_subscript: []const u8 = contract_utxo.script;
        if (code_sep_idx >= 0) {
            const hex_offset: usize = @intCast((@as(usize, @intCast(code_sep_idx)) + 1) * 2);
            if (hex_offset <= sig_subscript.len) sig_subscript = sig_subscript[hex_offset..];
        }

        var sighashes = try self.allocator.alloc([]const u8, sig_idx_list.items.len);
        var sighashes_filled: usize = 0;
        errdefer {
            var i: usize = 0;
            while (i < sighashes_filled) : (i += 1) self.allocator.free(@constCast(sighashes[i]));
            if (sighashes.len > 0) self.allocator.free(sighashes);
        }

        if (sig_idx_list.items.len > 0) {
            const sh_hex = try computeBip143Sighash(
                self.allocator, signed_tx, 0, sig_subscript, contract_utxo.satoshis,
            );
            defer self.allocator.free(sh_hex);
            for (sighashes, 0..) |_, i| {
                sighashes[i] = try self.allocator.dupe(u8, sh_hex);
                sighashes_filled = i + 1;
            }
        }

        // Take ownership of opaque plumbing the finalize step needs.
        const sig_indices_owned = try self.allocator.dupe(usize, sig_idx_list.items);
        const method_name_owned = try self.allocator.dupe(u8, method_name);
        const utxo_owned = try contract_utxo.clone(self.allocator);
        // N-213: ptx_result.sig_hex has no consumer post-BUG-100 (PreparedCall
        // has no op_push_tx_sig field to carry it to) -- don't dupe/own it.
        const preimage_owned = try self.allocator.dupe(u8, ptx_result.preimage_hex);
        const intent_witness_owned = try self.allocator.dupe(u8, witness_hex);

        return types.PreparedCall{
            .tx_hex = signed_tx,
            .sighashes = sighashes,
            .sig_indices = sig_indices_owned,
            .method_name = method_name_owned,
            .resolved_args = resolved_args,
            .contract_utxo = utxo_owned,
            .is_stateful = true,
            .new_locking_script = new_locking_script,
            .new_satoshis = new_satoshis,
            .preimage = preimage_owned,
            .method_selector = method_selector_buf,
            .needs_change = needs_change,
            .method_uses_code_part = method_uses_code_part,
            .change_pkh = change_pkh_buf,
            .change_amount = change_amount,
            .needs_new_amount = needs_new_amount,
            .code_sep_idx = code_sep_idx,
            .intent_witness_hex = intent_witness_owned,
        };
    }

    /// Coin-select the non-terminal call's P2PKH funding inputs (issue #133).
    ///
    /// `additional_utxos` arrives holding every candidate wallet UTXO (borrowed
    /// references). Replace the full-wallet sweep with the smallest-sufficient,
    /// largest-first subset — the same strategy deploy's selectUtxos uses —
    /// covering `funding_target = contract_output_sats - contract_input_sats`
    /// (clamped to 0) plus the tx fee. selectUtxos returns clones, so we map the
    /// selection back to the borrowed candidate references and keep only those:
    /// ownership is unchanged (the entries still borrow from the caller's
    /// `all_utxos`). Terminal calls are left untouched (their funding is caller-
    /// supplied). Fails with InsufficientFunds when the selection would exceed
    /// `max_funding_inputs`.
    fn selectCallFunding(
        self: *RunarContract,
        additional_utxos: *std.ArrayListUnmanaged(types.UTXO),
        is_terminal_call: bool,
        contract_output_sats: i64,
        contract_input_sats: i64,
        funding_lock_len: usize,
        fee_rate: i64,
        // finding C2: serialized bytes of the contract/covenant input(s) the tx
        // spends (blind to the deploy estimator). finding C15: framing of every
        // output beyond the single continuation the estimator counts. Both keep
        // the fee — and therefore how much funding gets selected — from being
        // under-provisioned on the call path. Deploy passes 0.
        extra_input_bytes: i64,
        extra_output_bytes: i64,
        max_funding_inputs: ?usize,
    ) !void {
        if (is_terminal_call or additional_utxos.items.len == 0) return;

        var funding_target: i64 = contract_output_sats - contract_input_sats;
        if (funding_target < 0) funding_target = 0;

        const selected = try deploy_mod.selectUtxos(
            self.allocator,
            additional_utxos.items,
            funding_target,
            funding_lock_len,
            fee_rate,
            extra_input_bytes,
            extra_output_bytes,
        );
        defer {
            for (selected) |*u| u.deinit(self.allocator);
            self.allocator.free(selected);
        }

        if (max_funding_inputs) |cap| {
            if (selected.len > cap) return ContractError.InsufficientFunds;
        }

        // Rebuild `additional_utxos` as the borrowed subset matching the
        // selection (map selectUtxos' clones back to the original refs by
        // prevout).
        var kept: std.ArrayListUnmanaged(types.UTXO) = .empty;
        defer kept.deinit(self.allocator);
        for (additional_utxos.items) |cand| {
            for (selected) |sel| {
                if (std.mem.eql(u8, cand.txid, sel.txid) and cand.output_index == sel.output_index) {
                    try kept.append(self.allocator, cand);
                    break;
                }
            }
        }
        additional_utxos.clearRetainingCapacity();
        try additional_utxos.appendSlice(self.allocator, kept.items);
    }

    /// Sign every P2PKH funding input on `tx_hex` (input 0 is the contract).
    /// Mutates `tx_hex` in place by reallocating with each splice.
    fn signFundingInputs(
        self: *RunarContract,
        tx_hex_inout: *[]u8,
        funding_sign: signer_mod.Signer,
        additional_utxos: []const types.UTXO,
        input_count: usize,
    ) !void {
        var inp_idx: usize = 1;
        while (inp_idx < input_count) : (inp_idx += 1) {
            const utxo_idx = inp_idx - 1;
            if (utxo_idx >= additional_utxos.len) break;
            const utxo = additional_utxos[utxo_idx];
            const sig_val = try funding_sign.sign(self.allocator, tx_hex_inout.*, inp_idx, utxo.script, utxo.satoshis, null);
            defer self.allocator.free(sig_val);
            const pub_key = try funding_sign.getPublicKey(self.allocator);
            defer self.allocator.free(pub_key);
            const sig_push = try state_mod.encodePushData(self.allocator, sig_val);
            defer self.allocator.free(sig_push);
            const pk_push = try state_mod.encodePushData(self.allocator, pub_key);
            defer self.allocator.free(pk_push);
            const p2pkh_unlock = try std.mem.concat(self.allocator, u8, &[_][]const u8{ sig_push, pk_push });
            defer self.allocator.free(p2pkh_unlock);
            const new_tx = try insertUnlockingScript(self.allocator, tx_hex_inout.*, inp_idx, p2pkh_unlock);
            self.allocator.free(tx_hex_inout.*);
            tx_hex_inout.* = new_tx;
        }
    }

    /// Finalise a prepared call by splicing external DER signatures into
    /// the unlocking script and broadcasting. Mirrors Go `FinalizeCall`,
    /// Ruby `finalize_call`, and Java `finalizeCall`.
    ///
    /// `signatures` must be one entry per `prepared.sig_indices`, in the
    /// same order. Each entry is a hex-encoded DER signature with the
    /// `SIGHASH_ALL | FORKID` byte already appended (matching the format
    /// returned by `Signer.sign`).
    pub fn finalizeCall(
        self: *RunarContract,
        prepared: *types.PreparedCall,
        signatures: []const []const u8,
        prov_arg: ?provider_mod.Provider,
    ) ![]u8 {
        const prov = prov_arg orelse self.provider orelse return ContractError.NoProviderOrSigner;

        if (signatures.len != prepared.sig_indices.len) {
            return ContractError.SignatureCountMismatch;
        }

        // Splice each external signature into resolved_args at the
        // recorded sig index (replacing the 72-byte zero placeholder).
        for (signatures, 0..) |sig_hex, i| {
            const idx = prepared.sig_indices[i];
            prepared.resolved_args[idx].deinit(self.allocator);
            prepared.resolved_args[idx] = .{ .bytes = try self.allocator.dupe(u8, sig_hex) };
        }

        // Rebuild the unlocking script. Stateful flow uses the saved
        // preimage (computed during prepareCall's convergence); stateless
        // rebuilds from args alone.
        const final_unlock = if (prepared.is_stateful) blk: {
            const change_pkh_opt: ?[]const u8 = if (prepared.change_pkh.len > 0) prepared.change_pkh else null;
            const method_selector_opt: ?[]const u8 = if (prepared.method_selector.len > 0) prepared.method_selector else null;
            // N-213: buildStatefulUnlockScript's first param is accepted for
            // call-site compatibility but ignored (post-BUG-100 no signature
            // is pushed) -- pass an empty slice rather than a now-nonexistent
            // prepared.op_push_tx_sig.
            break :blk try self.buildStatefulUnlockScript(
                &[_]u8{},
                prepared.resolved_args,
                prepared.method_uses_code_part,
                change_pkh_opt,
                prepared.change_amount,
                prepared.needs_new_amount,
                prepared.new_satoshis,
                prepared.preimage,
                method_selector_opt,
                prepared.intent_witness_hex,
            );
        } else try self.buildUnlockingScript(prepared.method_name, prepared.resolved_args);
        defer self.allocator.free(final_unlock);

        const final_tx = try insertUnlockingScript(self.allocator, prepared.tx_hex, 0, final_unlock);
        defer self.allocator.free(final_tx);

        const txid = prov.broadcast(self.allocator, final_tx) catch return ContractError.CallFailed;
        errdefer self.allocator.free(txid);

        // Terminal calls — stateful or stateless — fully spend the
        // contract: there is no continuation, so `current_utxo` must
        // become null. We detect them by an empty `new_locking_script`,
        // which `prepareCallStateful` sets when CallOptions.terminal_outputs
        // is non-null. For non-terminal stateful calls the locking script
        // is always populated (it carries the contract code), so the
        // empty-vs-set test cleanly disambiguates.
        const is_terminal_prepared = prepared.new_locking_script.len == 0;
        if (prepared.is_stateful and !is_terminal_prepared) {
            // Stateful non-terminal: track the new contract continuation UTXO.
            if (self.current_utxo) |*old| {
                var mu = old.*;
                mu.deinit(self.allocator);
            }
            self.current_utxo = .{
                .txid = try self.allocator.dupe(u8, txid),
                .output_index = 0,
                .satoshis = prepared.new_satoshis,
                .script = try self.allocator.dupe(u8, prepared.new_locking_script),
            };
        } else {
            // Stateless or stateful-terminal: contract UTXO consumed.
            if (self.current_utxo) |*old| {
                var mu = old.*;
                mu.deinit(self.allocator);
            }
            self.current_utxo = null;
        }

        return txid;
    }

    /// Build the full stateful unlocking script:
    ///   [codePart] + args + [changePKH + changeAmount] + preimage + [witnessHex] + [methodSelector]
    /// `intent_witness_hex` carries pre-encoded PUSHDATA pushes for the
    /// compiler's auto-injected intent-intrinsic params (`_prevOutScript_*`
    /// then `_serialisedOutputs`, ABI order). Empty when the method has no
    /// auto-injected intent params.
    ///
    /// BUG-100 fix: the OP_PUSH_TX signature is now derived on-chain from the
    /// preimage (see codegen emitCheckPreimageBinding), so NO signature is pushed
    /// here — the unlocking script carries only _codePart (if needed) and the
    /// preimage. The op_sig_hex parameter is retained for call-site compatibility
    /// but ignored.
    fn buildStatefulUnlockScript(
        self: *const RunarContract,
        op_sig_hex: []const u8,
        resolved_args: []const types.StateValue,
        needs_code_part: bool,
        change_pkh_hex: ?[]const u8,
        change_amount: i64,
        needs_new_amount: bool,
        new_amount: i64,
        preimage_hex: []const u8,
        method_selector_hex: ?[]const u8,
        intent_witness_hex: []const u8,
    ) ![]u8 {
        // BUG-100 fix: op_sig_hex is no longer pushed (the signature is derived
        // on-chain from the preimage). Retained for call-site compatibility.
        _ = op_sig_hex;

        var script: std.ArrayListUnmanaged(u8) = .empty;
        errdefer script.deinit(self.allocator);

        // _codePart (only for non-terminal stateful calls that need code)
        if (needs_code_part and self.hasCodeSeparator()) {
            const code_part = try self.getCodePartHex();
            defer self.allocator.free(code_part);
            const encoded = try state_mod.encodePushData(self.allocator, code_part);
            defer self.allocator.free(encoded);
            try script.appendSlice(self.allocator, encoded);
        }

        // User args
        for (resolved_args) |arg| {
            const encoded = try state_mod.encodeArg(self.allocator, arg);
            defer self.allocator.free(encoded);
            try script.appendSlice(self.allocator, encoded);
        }

        // _changePKH + _changeAmount (for stateful methods that need change)
        if (change_pkh_hex) |pkh| {
            const pkh_push = try state_mod.encodePushData(self.allocator, pkh);
            defer self.allocator.free(pkh_push);
            try script.appendSlice(self.allocator, pkh_push);

            const change_enc = try state_mod.encodeScriptNumber(self.allocator, change_amount);
            defer self.allocator.free(change_enc);
            try script.appendSlice(self.allocator, change_enc);
        }

        // _newAmount (for stateful methods that need new amount)
        if (needs_new_amount) {
            const encoded = try state_mod.encodeScriptNumber(self.allocator, new_amount);
            defer self.allocator.free(encoded);
            try script.appendSlice(self.allocator, encoded);
        }

        // Preimage
        {
            const encoded = try state_mod.encodePushData(self.allocator, preimage_hex);
            defer self.allocator.free(encoded);
            try script.appendSlice(self.allocator, encoded);
        }

        // Intent-intrinsic witness pushes (`_prevOutScript_*` then
        // `_serialisedOutputs`, ABI order). Empty for methods with no
        // auto-injected intent params.
        if (intent_witness_hex.len > 0) {
            try script.appendSlice(self.allocator, intent_witness_hex);
        }

        // Method selector
        if (method_selector_hex) |ms| {
            try script.appendSlice(self.allocator, ms);
        }

        return script.toOwnedSlice(self.allocator);
    }

    /// Returns true if the artifact has OP_CODESEPARATOR support.
    fn hasCodeSeparator(self: *const RunarContract) bool {
        return self.artifact.code_separator_index != null or self.artifact.code_separator_indices.len > 0;
    }

    /// GetLockingScript returns the full locking script hex for the contract.
    /// For stateful contracts this includes the code followed by OP_RETURN and
    /// the serialized state fields. When an inscription is attached and the
    /// script is built from the template (not loaded from chain), the envelope
    /// is spliced between the code and the state section.
    pub fn getLockingScript(self: *const RunarContract) ![]u8 {
        // Use stored code script from chain if available (reconnected contract).
        // When loaded from chain, code_script already contains the inscription
        // envelope (if any). When built from the template, we splice it in.
        const built_from_template = self.code_script == null;
        var code = if (self.code_script) |cs|
            try self.allocator.dupe(u8, cs)
        else
            try self.buildCodeScript();
        errdefer self.allocator.free(code);

        // Inject inscription envelope between code and state (template-built
        // only; chain-loaded code_script already includes it).
        if (built_from_template) {
            if (self.inscription) |insc| {
                const envelope = try ordinals.buildInscriptionEnvelope(self.allocator, insc.content_type, insc.data);
                defer self.allocator.free(envelope);
                const new_code = try std.mem.concat(self.allocator, u8, &[_][]const u8{ code, envelope });
                self.allocator.free(code);
                code = new_code;
            }
        }

        if (self.artifact.state_fields.len > 0 and self.state.len > 0) {
            const state_hex = try state_mod.serializeState(
                self.allocator,
                self.artifact.state_fields,
                self.state,
            );
            defer self.allocator.free(state_hex);

            if (state_hex.len > 0) {
                const result = try std.mem.concat(self.allocator, u8, &[_][]const u8{ code, "6a", state_hex });
                self.allocator.free(code);
                return result;
            }
        }

        return code;
    }

    /// BuildUnlockingScript builds the unlocking script hex for a method call.
    pub fn buildUnlockingScript(
        self: *const RunarContract,
        method_name: []const u8,
        args: []const types.StateValue,
    ) ![]u8 {
        var script: std.ArrayListUnmanaged(u8) = .empty;
        errdefer script.deinit(self.allocator);

        // Push each argument
        for (args) |arg| {
            const encoded = try state_mod.encodeArg(self.allocator, arg);
            defer self.allocator.free(encoded);
            try script.appendSlice(self.allocator, encoded);
        }

        // Method selector if multiple public methods
        const public_methods = try self.getPublicMethods();
        defer self.allocator.free(public_methods);

        if (public_methods.len > 1) {
            var method_index: ?usize = null;
            for (public_methods, 0..) |m, i| {
                if (std.mem.eql(u8, m.name, method_name)) {
                    method_index = i;
                    break;
                }
            }
            if (method_index) |idx| {
                const selector = try state_mod.encodeScriptNumber(self.allocator, @intCast(idx));
                defer self.allocator.free(selector);
                try script.appendSlice(self.allocator, selector);
            }
        }

        return script.toOwnedSlice(self.allocator);
    }

    /// Get a copy of the current state values.
    pub fn getState(self: *const RunarContract) ![]types.StateValue {
        var result = try self.allocator.alloc(types.StateValue, self.state.len);
        for (self.state, 0..) |s, i| {
            result[i] = try s.clone(self.allocator);
        }
        return result;
    }

    /// Set state values directly.
    pub fn setState(self: *RunarContract, new_state: []const types.StateValue) !void {
        for (self.state) |*s| s.deinit(self.allocator);
        if (self.state.len > 0) self.allocator.free(self.state);
        var vals = try self.allocator.alloc(types.StateValue, new_state.len);
        for (new_state, 0..) |s, i| {
            vals[i] = try s.clone(self.allocator);
        }
        self.state = vals;
    }

    /// Get the current UTXO (null if not deployed or spent).
    pub fn getCurrentUtxo(self: *const RunarContract) ?types.UTXO {
        return self.current_utxo;
    }

    /// Set the current UTXO.
    pub fn setCurrentUtxo(self: *RunarContract, utxo: ?types.UTXO) !void {
        if (self.current_utxo) |*old| {
            var mu = old.*;
            mu.deinit(self.allocator);
        }
        if (utxo) |u| {
            self.current_utxo = .{
                .txid = try self.allocator.dupe(u8, u.txid),
                .output_index = u.output_index,
                .satoshis = u.satoshis,
                .script = try self.allocator.dupe(u8, u.script),
            };
        } else {
            self.current_utxo = null;
        }
    }

    // ---------------------------------------------------------------------------
    // fromUtxo — reconnect a contract from an on-chain UTXO
    // ---------------------------------------------------------------------------

    /// Reconstruct a RunarContract from an existing on-chain UTXO. The code
    /// script is extracted from the UTXO's locking script, and if an
    /// inscription envelope is present it is detected and stored. State is
    /// deserialized for stateful contracts.
    /// Recover the positional constructor argument list from a deployed locking
    /// script, so a restored contract (fromUtxo) operates on the real baked-in
    /// values rather than 0 placeholders (issue #119). readonly ctor params feed
    /// the state-continuation formula and adjustCodeSepOffset; zeros there yield
    /// the wrong continuation and the wrong OP_CODESEPARATOR offset, making
    /// restored stateful spends unspendable.
    ///
    /// extractConstructorArgs returns a name->value map; artifact.abi.constructor
    /// .params is ordered by paramIndex, so mapping over it yields the positional
    /// slice the RunarContract expects. Params that carry no constructor slot
    /// (mutable state fields — restored separately by extractStateFromScript) are
    /// absent from the map and fall back to int64(0), matching the prior
    /// placeholder behaviour.
    fn restoreConstructorArgs(
        allocator: std.mem.Allocator,
        artifact: *const types.RunarArtifact,
        script_hex: []const u8,
    ) ![]types.StateValue {
        const params = artifact.abi.constructor.params;
        var out = try allocator.alloc(types.StateValue, params.len);
        if (params.len == 0) return out;

        var extracted = try script_utils.extractConstructorArgs(artifact, script_hex, allocator);
        defer {
            var it = extracted.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(allocator);
            }
            extracted.deinit();
        }

        for (params, 0..) |p, i| {
            if (extracted.get(p.name)) |v| {
                out[i] = try v.clone(allocator);
            } else {
                out[i] = .{ .int = 0 };
            }
        }
        return out;
    }

    pub fn fromUtxo(
        allocator: std.mem.Allocator,
        artifact: *types.RunarArtifact,
        utxo: types.UTXO,
    ) !RunarContract {
        // Recover the real baked-in constructor args from the deployed script so
        // a restored contract operates on the true values rather than 0
        // placeholders (issue #119).
        const restored_args = try restoreConstructorArgs(allocator, artifact, utxo.script);

        var contract = RunarContract{
            .allocator = allocator,
            .artifact = artifact,
            .constructor_args = restored_args,
            .state = &.{},
        };

        // Extract code script from UTXO
        if (artifact.state_fields.len > 0) {
            const op_return_pos = state_mod.findLastOpReturn(utxo.script);
            if (op_return_pos) |pos| {
                contract.code_script = try allocator.dupe(u8, utxo.script[0..pos]);
            } else {
                contract.code_script = try allocator.dupe(u8, utxo.script);
            }
        } else {
            contract.code_script = try allocator.dupe(u8, utxo.script);
        }

        // Detect inscription envelope in the code portion. Keep it in code_script
        // (do NOT strip) so that stateful continuation outputs preserve it.
        if (contract.code_script) |cs| {
            if (try ordinals.parseInscriptionEnvelope(allocator, cs)) |insc| {
                contract.inscription = insc;
            }
        }

        // Track the UTXO
        contract.current_utxo = .{
            .txid = try allocator.dupe(u8, utxo.txid),
            .output_index = utxo.output_index,
            .satoshis = utxo.satoshis,
            .script = try allocator.dupe(u8, utxo.script),
        };

        // Deserialize state for stateful contracts
        if (artifact.state_fields.len > 0) {
            if (try state_mod.extractStateFromScript(allocator, artifact, utxo.script)) |state_vals| {
                contract.state = state_vals;
            }
        }

        return contract;
    }

    // ---------------------------------------------------------------------------
    // ANF auto-state computation
    // ---------------------------------------------------------------------------

    /// Populate the ANF interpreter's `property name -> ANFValue` map from
    /// `self.state`.
    ///
    /// A `FixedArray` state field is keyed by its SYNTHETIC LEAF names, never
    /// by its grouped one. Pass `03b-expand-fixed-arrays` runs before ANF
    /// lowering, so the ANF program has no property called `table` at all — it
    /// has `table__0`..`table__3`, and every `load_prop` / `update_prop` in the
    /// method body names one of those. Keying the map by `field.name` left the
    /// interpreter evaluating `this.table[i]++` against an ABSENT property.
    ///
    /// Mirrors `flattenFixedArrayState` in `packages/runar-sdk/src/contract.ts`
    /// and `_flatten_fixed_array_state` in `packages/runar-py/runar/sdk/
    /// contract.py`. Those two also copy the grouped entry through; this tier
    /// does not, because nothing reads it and `stateValueToAnf` on an
    /// `.array_value` allocates a slice the interpreter would never look at.
    fn putCurrentState(
        self: *RunarContract,
        map: *std.StringHashMap(anf_interp.ANFValue),
    ) void {
        for (self.artifact.state_fields, 0..) |field, i| {
            if (i >= self.state.len) continue;
            if (field.fixed_array) |fa| {
                // A non-array value cannot be spread over N leaves; leave the
                // leaves absent rather than guess, as the TS/Python tiers do.
                if (self.state[i] != .array_value) continue;
                var next: usize = 0;
                putSyntheticLeaves(map, fa.synthetic_names, self.state[i], &next);
            } else {
                map.put(field.name, stateValueToAnf(self.state[i])) catch continue;
            }
        }
    }

    /// Auto-compute state transitions from the ANF IR embedded in the artifact.
    /// Also returns any data outputs declared via `this.addDataOutput(...)` in
    /// the method body, allocated from `self.allocator`. Caller owns both the
    /// returned slice and each entry's `script`. Returns an empty slice if the
    /// artifact has no ANF IR or the interpreter fails.
    ///
    /// `ordered_out`, when non-null, is appended with the interpreter's
    /// source-ordered state-class outputs (state continuation + raw), finding
    /// G1. Each `.raw` entry's `script` is duped into `self.allocator` and its
    /// ownership transfers to `ordered_out` (the caller frees it); `.state`
    /// entries carry an empty script. Passing `null` discards them.
    fn autoComputeState(
        self: *RunarContract,
        method_name: []const u8,
        user_params: []types.ABIParam,
        resolved_args: []const types.StateValue,
        ordered_out: ?*std.ArrayListUnmanaged(anf_interp.OrderedOutputEntry),
        // F-024 (R14): the spent UTXO's satoshis (`extractAmount(txPreimage)`)
        // and the continuation's (`continuationAmount()` = `_newAmount`).
        continuation: struct { input_amount: i64, new_amount: i64 },
    ) ![]anf_interp.DataOutputEntry {
        const empty: []anf_interp.DataOutputEntry = &.{};
        const anf_json = self.artifact.anf_json orelse return empty;

        // Use an arena for all ANF parsing and interpretation work
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const work = arena.allocator();

        // Parse the ANF IR from JSON.
        //
        // FAIL CLOSED, same reasoning as the interpreter call below (NEW-006)
        // and by a shorter route: swallowing a parse failure returns before the
        // state-application loop, so `self.state` keeps its PRE-CALL value, the
        // method's data / raw outputs vanish, and the caller is handed a txid
        // for a continuation the covenant's `hashOutputs` binding rejects. No
        // peer tier swallows this.
        const anf_program = try anf_interp.parseANFFromJson(work, anf_json);

        // Build current state map: property name -> ANFValue. A FixedArray
        // field is keyed by its SYNTHETIC leaf names, not its grouped one —
        // see `putCurrentState`.
        var current_state = std.StringHashMap(anf_interp.ANFValue).init(work);
        self.putCurrentState(&current_state);

        // Build named args map: param name -> ANFValue
        var named_args = std.StringHashMap(anf_interp.ANFValue).init(work);
        for (user_params, 0..) |param, i| {
            if (i < resolved_args.len) {
                named_args.put(param.name, stateValueToAnf(resolved_args[i])) catch continue;
            }
        }
        // F-024 (R14): a default single-output continuation reads both amounts,
        // and the state the script re-derives must match. The interpreter binds
        // them only for a method that declares the matching implicit params.
        try named_args.put("txPreimage", .{ .int = continuation.input_amount });
        try named_args.put("_newAmount", .{ .int = continuation.new_amount });

        // R67: extractScriptCode(txPreimage) gets the contract's OWN real
        // codePart (post-OP_CODESEPARATOR, CompactSize-prefixed exactly as
        // the BIP-143 preimage carries it) instead of the historical empty
        // dummy, so a method like FungibleToken#merge that inspects its own
        // scriptCode during off-chain state derivation sees realistic bytes
        // rather than aborting substr on an empty value. getCodeSepIndex is
        // the SAME call every other signing path uses to trim the codePart
        // to the post-separator subscript.
        // N-189: trim the SPENT UTXO's locking script (the subscript the
        // primary input's preimage signs), not the bare codePart -- BIP-143's
        // scriptCode carries the `OP_RETURN <state>` tail too.
        const spent_script_hex = if (self.current_utxo) |u| u.script else return ContractError.NotDeployed;
        const public_methods_for_sep = try self.getPublicMethods();
        defer self.allocator.free(public_methods_for_sep);
        var method_index_for_sep: usize = 0;
        for (public_methods_for_sep, 0..) |m, i| {
            if (std.mem.eql(u8, m.name, method_name)) {
                method_index_for_sep = i;
                break;
            }
        }
        const code_sep_idx = try self.getCodeSepIndex(method_index_for_sep);
        const script_code_body = if (code_sep_idx) |idx|
            spent_script_hex[@as(usize, @intCast(idx + 1)) * 2 ..]
        else
            spent_script_hex;
        const script_code_hex = try std.fmt.allocPrint(work, "{s}{s}", .{
            try writeVarIntHex(work, script_code_body.len / 2), script_code_body,
        });
        var mock_env = anf_interp.MockEnv.init(work);
        defer mock_env.deinit();
        mock_env.script_code_hex = script_code_hex;

        // Convert constructor_args to ANFValue slice for the interpreter
        var ctor_anf_args = try work.alloc(anf_interp.ANFValue, self.constructor_args.len);
        for (self.constructor_args, 0..) |arg, i| {
            ctor_anf_args[i] = stateValueToAnf(arg);
        }

        // Snapshot the current self.state .bytes pointers — these are the
        // "borrowed" slices that runMethod passed through into state_map
        // entries (current_state passthrough). State_delta updates were
        // duped into self.allocator and DO need freeing. We use this
        // snapshot to distinguish the two in the cleanup pass below.
        // A FixedArray field passes its LEAVES through, so the walk has to
        // descend into `.array_value` or those pointers look unborrowed and
        // the cleanup frees memory `self.state` still owns.
        var borrowed_ptrs: std.ArrayListUnmanaged([*]const u8) = .empty;
        defer borrowed_ptrs.deinit(self.allocator);
        for (self.state) |sv| collectBorrowedPtrs(&borrowed_ptrs, self.allocator, sv);

        // Compute new state AND data outputs.
        //
        // FAIL CLOSED (NEW-006). Swallowing this built the stateful
        // continuation from the CURRENT (pre-call) state, which the covenant's
        // hashOutputs binding then rejects — a silent "your call cannot be
        // broadcast", plus silent loss of the method's data / raw outputs. The
        // interpreter is the only thing that knows the post-state and those
        // payloads, so there is nothing to fall back TO. Matches the TS, Go and
        // Rust tiers.
        const result = anf_interp.computeNewStateWithMockEnv(
            self.allocator, &anf_program, method_name, current_state, named_args, ctor_anf_args, &mock_env,
        ) catch |err| switch (err) {
            // Lenient mode (strict=false, passed internally by
            // computeNewStateWithMockEnv) never reports AssertionFailure or
            // MissingWitness -- mirrors computeNewStateAndDataOutputs's own
            // coercion.
            error.AssertionFailure => unreachable,
            error.MissingWitness => unreachable,
            else => |e| return e,
        };
        var state_map = result.state;
        defer {
            var it = state_map.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.* == .bytes) {
                    const ptr = entry.value_ptr.*.bytes.ptr;
                    var borrowed = false;
                    for (borrowed_ptrs.items) |bp| {
                        if (bp == ptr) {
                            borrowed = true;
                            break;
                        }
                    }
                    if (!borrowed) self.allocator.free(entry.value_ptr.*.bytes);
                }
            }
            state_map.deinit();
        }

        // Apply computed state back to self.state. anfToStateValue dupes
        // bytes into self.allocator before we free the old state value, so
        // there's no use-after-free even when the new value is a passthrough
        // pointer into the old self.state slot.
        for (self.artifact.state_fields, 0..) |field, i| {
            if (i < self.state.len) {
                // A FixedArray field's post-state lives under its synthetic
                // leaf names; `field.name` is never a key of the result map.
                if (field.fixed_array) |fa| {
                    // Fail closed on an allocation failure here, same as the
                    // interpreter call above: silently keeping the pre-call
                    // array is exactly the defect this branch exists to fix.
                    if (try regroupFromStateMap(
                        self.allocator,
                        field.type_name,
                        fa.synthetic_names,
                        state_map,
                        self.state[i],
                    )) |regrouped| {
                        self.state[i].deinit(self.allocator);
                        self.state[i] = regrouped;
                    }
                } else if (state_map.get(field.name)) |anf_val| {
                    const new_val = anfToStateValue(self.allocator, anf_val) catch types.StateValue{ .int = 0 };
                    self.state[i].deinit(self.allocator);
                    self.state[i] = new_val;
                }
            }
        }

        // Surface (or discard) the source-ordered state-class outputs, finding
        // G1. Moving each entry into `ordered_out` transfers ownership of the
        // `.raw` script dupe; discarding frees it. Either way the outer slice
        // is freed here (previously leaked alongside `raw_outputs`).
        if (ordered_out) |oo| {
            try oo.appendSlice(self.allocator, result.outputs);
        } else {
            for (result.outputs) |o| if (o.kind == .raw and o.script.len > 0) self.allocator.free(@constCast(o.script));
        }
        if (result.outputs.len > 0) self.allocator.free(result.outputs);
        // Free the raw outputs (unused here) — previously leaked.
        for (result.raw_outputs) |d| self.allocator.free(d.script);
        if (result.raw_outputs.len > 0) self.allocator.free(result.raw_outputs);

        return result.data_outputs;
    }

    /// Run the ANF interpreter purely for the side-emission of data outputs
    /// (`this.addDataOutput(...)`); do NOT mutate `self.state`.
    ///
    /// Used when the caller supplies an explicit `options.new_state`: their
    /// state value wins, but we still need to materialise any data outputs
    /// the method body emits so the broadcast tx layout matches the contract's
    /// compile-time `hashOutputs` check.
    fn autoComputeDataOutputs(
        self: *RunarContract,
        method_name: []const u8,
        user_params: []types.ABIParam,
        resolved_args: []const types.StateValue,
        ordered_out: ?*std.ArrayListUnmanaged(anf_interp.OrderedOutputEntry),
    ) ![]anf_interp.DataOutputEntry {
        const empty: []anf_interp.DataOutputEntry = &.{};
        const anf_json = self.artifact.anf_json orelse return empty;

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const work = arena.allocator();

        // FAIL CLOSED — see the matching note in autoComputeState. The caller's
        // explicit `new_state` wins here, but the method's data / raw outputs
        // still have to materialise or the broadcast tx layout mismatches the
        // compile-time `hashOutputs` check.
        const anf_program = try anf_interp.parseANFFromJson(work, anf_json);

        var current_state = std.StringHashMap(anf_interp.ANFValue).init(work);
        self.putCurrentState(&current_state);

        var named_args = std.StringHashMap(anf_interp.ANFValue).init(work);
        for (user_params, 0..) |param, i| {
            if (i < resolved_args.len) {
                named_args.put(param.name, stateValueToAnf(resolved_args[i])) catch continue;
            }
        }

        var ctor_anf_args = try work.alloc(anf_interp.ANFValue, self.constructor_args.len);
        for (self.constructor_args, 0..) |arg, i| {
            ctor_anf_args[i] = stateValueToAnf(arg);
        }

        // Snapshot the borrowed (passthrough) ptrs in self.state — see the
        // matching pass in autoComputeState. This caller never mutates
        // self.state, so the snapshot is identical to the current set.
        var borrowed_ptrs: std.ArrayListUnmanaged([*]const u8) = .empty;
        defer borrowed_ptrs.deinit(self.allocator);
        for (self.state) |sv| {
            collectBorrowedPtrs(&borrowed_ptrs, self.allocator, sv);
        }

        // R67: extractScriptCode(txPreimage) gets the contract's OWN real
        // codePart -- see the matching note in autoComputeState.
        // N-189: trim the SPENT UTXO's locking script (the subscript the
        // primary input's preimage signs), not the bare codePart -- BIP-143's
        // scriptCode carries the `OP_RETURN <state>` tail too.
        const spent_script_hex = if (self.current_utxo) |u| u.script else return ContractError.NotDeployed;
        const public_methods_for_sep = try self.getPublicMethods();
        defer self.allocator.free(public_methods_for_sep);
        var method_index_for_sep: usize = 0;
        for (public_methods_for_sep, 0..) |m, i| {
            if (std.mem.eql(u8, m.name, method_name)) {
                method_index_for_sep = i;
                break;
            }
        }
        const code_sep_idx = try self.getCodeSepIndex(method_index_for_sep);
        const script_code_body = if (code_sep_idx) |idx|
            spent_script_hex[@as(usize, @intCast(idx + 1)) * 2 ..]
        else
            spent_script_hex;
        const script_code_hex = try std.fmt.allocPrint(work, "{s}{s}", .{
            try writeVarIntHex(work, script_code_body.len / 2), script_code_body,
        });
        var mock_env = anf_interp.MockEnv.init(work);
        defer mock_env.deinit();
        mock_env.script_code_hex = script_code_hex;

        // FAIL CLOSED (NEW-006) — see the matching note in autoComputeState.
        const result = anf_interp.computeNewStateWithMockEnv(
            self.allocator, &anf_program, method_name, current_state, named_args, ctor_anf_args, &mock_env,
        ) catch |err| switch (err) {
            error.AssertionFailure => unreachable,
            error.MissingWitness => unreachable,
            else => |e| return e,
        };
        var state_map = result.state;
        {
            var it = state_map.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.* == .bytes) {
                    const ptr = entry.value_ptr.*.bytes.ptr;
                    var borrowed = false;
                    for (borrowed_ptrs.items) |bp| {
                        if (bp == ptr) {
                            borrowed = true;
                            break;
                        }
                    }
                    if (!borrowed) self.allocator.free(entry.value_ptr.*.bytes);
                }
            }
        }
        state_map.deinit();

        // Surface (or discard) the source-ordered state-class outputs, finding
        // G1 — same ownership transfer as autoComputeState. Also free the raw
        // outputs (unused here) and the outer ordered slice, previously leaked.
        if (ordered_out) |oo| {
            try oo.appendSlice(self.allocator, result.outputs);
        } else {
            for (result.outputs) |o| if (o.kind == .raw and o.script.len > 0) self.allocator.free(@constCast(o.script));
        }
        if (result.outputs.len > 0) self.allocator.free(result.outputs);
        for (result.raw_outputs) |d| self.allocator.free(d.script);
        if (result.raw_outputs.len > 0) self.allocator.free(result.raw_outputs);

        return result.data_outputs;
    }

    // ---------------------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------------------

    /// N-223: shared out-of-range guard for every `self.constructor_args[param_index]`
    /// read in this file. The constructor only checks
    /// `constructor_args.len == abi.constructor.params.len` (see `init`) -- it
    /// never cross-checks that every constructor slot's `param_index` actually
    /// falls within that range. Before this fix, `buildCodeScript`,
    /// `adjustCodeSepOffset`, and `resolvedCodeSepSlotValues` each silently
    /// SKIPPED a slot whose `param_index` was out of range (the placeholder
    /// byte stayed unfilled, or the offset shift was simply wrong) instead of
    /// refusing. Parity target: TS `RunarContract#resolveConstructorArg`
    /// (N-081 / N-223).
    fn resolveConstructorArg(self: *const RunarContract, param_index: i32) !types.StateValue {
        if (param_index < 0) return error.ConstructorArgParamIndexOutOfRange;
        const idx: usize = @intCast(param_index);
        if (idx >= self.constructor_args.len) return error.ConstructorArgParamIndexOutOfRange;
        return self.constructor_args[idx];
    }

    fn buildCodeScript(self: *const RunarContract) ![]u8 {
        var script = try self.allocator.dupe(u8, self.artifact.script);
        errdefer self.allocator.free(script);

        const has_constructor_slots = self.artifact.constructor_slots.len > 0;
        const has_code_sep_slots = self.artifact.code_sep_index_slots.len > 0;

        if (has_constructor_slots or has_code_sep_slots) {
            // Build a unified list of all template slot substitutions, then process
            // them in descending byte-offset order so each splice doesn't invalidate
            // the positions of earlier (higher-offset) entries.
            const SubEntry = struct {
                byte_offset: i32,
                encoded: []u8,
            };
            var subs: std.ArrayListUnmanaged(SubEntry) = .empty;
            defer {
                for (subs.items) |item| self.allocator.free(item.encoded);
                subs.deinit(self.allocator);
            }

            // Constructor arg slots: replace OP_0 placeholder with encoded arg
            if (has_constructor_slots) {
                for (self.artifact.constructor_slots) |slot| {
                    const encoded = try state_mod.encodeArg(self.allocator, try self.resolveConstructorArg(slot.param_index));
                    try subs.append(self.allocator, .{
                        .byte_offset = slot.byte_offset,
                        .encoded = encoded,
                    });
                }
            }

            // CodeSepIndex slots: replace OP_0 placeholder with encoded adjusted
            // codeSeparatorIndex.
            if (has_code_sep_slots) {
                const resolved = try self.resolvedCodeSepSlotValues();
                defer self.allocator.free(resolved);
                for (resolved) |rs| {
                    const encoded = try state_mod.encodeScriptNumber(self.allocator, rs.adjusted_value);
                    try subs.append(self.allocator, .{
                        .byte_offset = rs.template_byte_offset,
                        .encoded = encoded,
                    });
                }
            }

            // Sort descending by byte offset and apply
            std.mem.sort(SubEntry, subs.items, {}, struct {
                fn lessThan(_: void, a: SubEntry, b: SubEntry) bool {
                    return a.byte_offset > b.byte_offset;
                }
            }.lessThan);

            for (subs.items) |sub| {
                const hex_offset: usize = @intCast(sub.byte_offset * 2);
                if (hex_offset + 2 <= script.len) {
                    var new_script = try self.allocator.alloc(u8, script.len - 2 + sub.encoded.len);
                    @memcpy(new_script[0..hex_offset], script[0..hex_offset]);
                    @memcpy(new_script[hex_offset .. hex_offset + sub.encoded.len], sub.encoded);
                    @memcpy(new_script[hex_offset + sub.encoded.len ..], script[hex_offset + 2 ..]);
                    self.allocator.free(script);
                    script = new_script;
                }
            }

            // N-051: the deploy-time code-part length pins. The inscription
            // envelope, when present, is part of `_codePart` (see getCodePartHex).
            if (self.artifact.code_part_len_slots.len > 0) {
                var envelope_len: usize = 0;
                if (self.inscription) |insc| {
                    const envelope = try ordinals.buildInscriptionEnvelope(self.allocator, insc.content_type, insc.data);
                    defer self.allocator.free(envelope);
                    envelope_len = envelope.len / 2;
                }
                const shifts = try self.allocator.alloc(SubShift, subs.items.len);
                defer self.allocator.free(shifts);
                for (subs.items, 0..) |sub, i| {
                    shifts[i] = .{ .byte_offset = sub.byte_offset, .encoded_len = sub.encoded.len / 2 };
                }
                try patchCodePartLenSlots(self.artifact, script, shifts, script.len / 2 + envelope_len);
            }
        }
        // R84: no fallback append for args without a constructor slot. A
        // ctor arg with no corresponding constructor_slots entry means the
        // property it initializes was eliminated by DCE (never read by any
        // surviving method), so there is no placeholder in the compiled
        // template for it to fill -- appending it would deploy a script
        // that is not the one the compiler produced (and fails the
        // consensus clean-stack rule on spend; see packages/runar-sdk's
        // n013-dce-eliminated-ctor-args.test.ts). Matches the Java SDK,
        // which never had this fallback.

        return script;
    }

    fn getPublicMethods(self: *const RunarContract) ![]types.ABIMethod {
        var result: std.ArrayListUnmanaged(types.ABIMethod) = .empty;
        for (self.artifact.abi.methods) |m| {
            if (m.is_public) try result.append(self.allocator, m);
        }
        return result.toOwnedSlice(self.allocator);
    }

    fn findMethod(self: *const RunarContract, name: []const u8) ?*types.ABIMethod {
        for (self.artifact.abi.methods) |*m| {
            if (m.is_public and std.mem.eql(u8, m.name, name)) return m;
        }
        return null;
    }

    /// adjustCodeSepOffset adjusts a code separator byte offset from the base
    /// (template) script to the fully-substituted script. Both constructor arg
    /// slots and codeSepIndex slots replace OP_0 (1 byte) with encoded push
    /// data, shifting subsequent byte offsets.
    pub fn adjustCodeSepOffset(self: *const RunarContract, base_offset: i32) !i32 {
        var shift: i32 = 0;
        for (self.artifact.constructor_slots) |slot| {
            if (slot.byte_offset < base_offset) {
                const encoded = try state_mod.encodeArg(self.allocator, try self.resolveConstructorArg(slot.param_index));
                defer self.allocator.free(encoded);
                shift += @as(i32, @intCast(encoded.len / 2)) - 1;
            }
        }
        // Account for codeSepIndex slot expansions
        const resolved = try self.resolvedCodeSepSlotValues();
        defer self.allocator.free(resolved);
        for (resolved) |rs| {
            if (rs.template_byte_offset < base_offset) {
                const encoded = try state_mod.encodeScriptNumber(self.allocator, rs.adjusted_value);
                defer self.allocator.free(encoded);
                shift += @as(i32, @intCast(encoded.len / 2)) - 1;
            }
        }
        return base_offset + shift;
    }

    /// Resolved code separator index slot entry.
    const ResolvedCodeSepEntry = struct {
        template_byte_offset: i32,
        adjusted_value: i64,
    };

    /// Resolve the adjusted codeSep index values for all codeSepIndex slots,
    /// processing them in ascending template byte-offset order so that each
    /// slot's value correctly accounts for earlier slots' expansions.
    fn resolvedCodeSepSlotValues(self: *const RunarContract) ![]ResolvedCodeSepEntry {
        if (self.artifact.code_sep_index_slots.len == 0) {
            return try self.allocator.alloc(ResolvedCodeSepEntry, 0);
        }

        // Sort by template byte offset ascending (left-to-right in the script)
        const sorted_indices = try self.allocator.alloc(usize, self.artifact.code_sep_index_slots.len);
        defer self.allocator.free(sorted_indices);
        for (0..self.artifact.code_sep_index_slots.len) |i| sorted_indices[i] = i;
        const slot_data = self.artifact.code_sep_index_slots;
        std.mem.sort(usize, sorted_indices, slot_data, struct {
            fn lessThan(ctx: []const types.CodeSepIndexSlot, a: usize, b: usize) bool {
                return ctx[a].byte_offset < ctx[b].byte_offset;
            }
        }.lessThan);

        var result: std.ArrayListUnmanaged(ResolvedCodeSepEntry) = .empty;
        errdefer result.deinit(self.allocator);

        for (sorted_indices) |idx| {
            const slot = slot_data[idx];
            // Compute the fully-adjusted codeSep index: constructor expansion +
            // expansion from earlier codeSepIndex slots that precede this slot's codeSepIndex.
            var shift: i32 = 0;
            for (self.artifact.constructor_slots) |cs| {
                if (cs.byte_offset < slot.code_sep_index) {
                    const encoded = try state_mod.encodeArg(self.allocator, try self.resolveConstructorArg(cs.param_index));
                    defer self.allocator.free(encoded);
                    shift += @as(i32, @intCast(encoded.len / 2)) - 1;
                }
            }
            for (result.items) |prev| {
                if (prev.template_byte_offset < slot.code_sep_index) {
                    const prev_encoded = try state_mod.encodeScriptNumber(self.allocator, prev.adjusted_value);
                    defer self.allocator.free(prev_encoded);
                    shift += @as(i32, @intCast(prev_encoded.len / 2)) - 1;
                }
            }
            try result.append(self.allocator, .{
                .template_byte_offset = slot.byte_offset,
                .adjusted_value = @as(i64, slot.code_sep_index) + @as(i64, shift),
            });
        }

        return result.toOwnedSlice(self.allocator);
    }

    /// getCodeSepIndex returns the adjusted code separator byte offset for a
    /// given method index, or null if no OP_CODESEPARATOR is present.
    /// getCodeSepIndex returns the byte offset of an OP_CODESEPARATOR for the
    /// given method index, or null if none is present.
    ///
    /// When code_script is set (the contract is loaded from chain, or the deploy
    /// script has already been built from real constructor args), walk the
    /// actual script and return the true on-chain byte position. This is
    /// required because fromTxid populates constructor args with dummy
    /// placeholders — the real arg bytes are already baked into the on-chain
    /// locking script — so adjustCodeSepOffset computes a shift of zero and
    /// returns the wrong offset whenever the OP_CODESEPARATOR sits after
    /// constructor slots that expand at deploy time (issue #42: NULLFAIL at
    /// OP_CHECKSIG for terminal methods).
    ///
    /// Falls back to the legacy template-adjusted offset for synthetic /
    /// unit-test paths that have no code_script available.
    /// Resolve the BIP-143 sighash type a method's OP_PUSH_TX preimage must be
    /// built under (issue #123). Returns the ABI-declared `@sighash` mode for
    /// the named public method, or the default ALL|FORKID (0x41) when the method
    /// carries no directive. Keeps every call/finalize path mode-aware with no
    /// call-site churn (mirrors the Go SDK's methodSigHashType).
    fn methodSigHashType(self: *const RunarContract, method_name: []const u8) u32 {
        for (self.artifact.abi.methods) |m| {
            if (m.is_public and std.mem.eql(u8, m.name, method_name)) {
                if (m.sig_hash_type) |st| return @intCast(st & 0xff);
            }
        }
        return 0x41;
    }

    pub fn getCodeSepIndex(self: *const RunarContract, method_index: usize) !?i32 {
        if (self.code_script) |cs| {
            const real_offsets = try findCodesepOffsets(self.allocator, cs);
            defer self.allocator.free(real_offsets);
            if (self.artifact.code_separator_indices.len > 0) {
                if (method_index < self.artifact.code_separator_indices.len and method_index < real_offsets.len) {
                    return real_offsets[method_index];
                }
            }
            if (self.artifact.code_separator_index != null and real_offsets.len > 0) {
                return real_offsets[0];
            }
        }

        if (self.artifact.code_separator_indices.len > 0 and method_index < self.artifact.code_separator_indices.len) {
            return try self.adjustCodeSepOffset(self.artifact.code_separator_indices[method_index]);
        }
        if (self.artifact.code_separator_index) |idx| {
            return try self.adjustCodeSepOffset(idx);
        }
        return null;
    }

    /// getCodePartHex returns the code portion of the locking script (without state).
    /// Includes the inscription envelope if one is attached -- this is required for
    /// stateful contracts where the on-chain hashOutputs verification includes
    /// the envelope as part of the codePart.
    pub fn getCodePartHex(self: *const RunarContract) ![]u8 {
        if (self.code_script) |cs| return self.allocator.dupe(u8, cs);
        var code = try self.buildCodeScript();
        if (self.inscription) |insc| {
            const envelope = try ordinals.buildInscriptionEnvelope(self.allocator, insc.content_type, insc.data);
            defer self.allocator.free(envelope);
            const new_code = try std.mem.concat(self.allocator, u8, &[_][]const u8{ code, envelope });
            self.allocator.free(code);
            code = new_code;
        }
        return code;
    }
};

// ---------------------------------------------------------------------------
// ANFValue <-> StateValue conversion helpers
// ---------------------------------------------------------------------------

/// Walk a (possibly nested) FixedArray state value depth-first and bind each
/// LEAF to the correspondingly-positioned synthetic property name. `next` is
/// the running leaf index, shared across the recursion.
///
/// An existing entry is never overwritten — mirrors the TS tier's
/// `if (!(synth in out))` guard, which keeps an explicitly-supplied scalar
/// winning over the grouped array it was also spelled inside.
fn putSyntheticLeaves(
    map: *std.StringHashMap(anf_interp.ANFValue),
    names: []const []const u8,
    value: types.StateValue,
    next: *usize,
) void {
    switch (value) {
        .array_value => |items| {
            for (items) |it| putSyntheticLeaves(map, names, it, next);
        },
        else => {
            if (next.* >= names.len) return;
            const name = names[next.*];
            next.* += 1;
            if (map.contains(name)) return;
            map.put(name, stateValueToAnf(value)) catch {};
        },
    }
}

/// Collect the `.bytes` pointers a state value lends to the interpreter,
/// descending into `.array_value` leaves. The cleanup pass after
/// `computeNewStateAndDataOutputs` frees any `.bytes` in the result map whose
/// pointer is NOT in this set, so a leaf that is missed here gets freed while
/// `self.state` still owns it.
fn collectBorrowedPtrs(
    out: *std.ArrayListUnmanaged([*]const u8),
    allocator: std.mem.Allocator,
    sv: types.StateValue,
) void {
    switch (sv) {
        .bytes => |b| out.append(allocator, b.ptr) catch {},
        .array_value => |items| {
            for (items) |it| collectBorrowedPtrs(out, allocator, it);
        },
        else => {},
    }
}

/// Rebuild a FixedArray state field's grouped value from the interpreter's
/// result map, which keys the post-call state by the synthetic leaf names.
///
/// Returns `null` when the map carries none of this field's leaves — the
/// method did not touch the array, so the caller must leave `self.state` alone
/// rather than overwrite it with a reconstruction. A leaf the method did not
/// write falls back to its pre-call value in `prior`, so a partial write keeps
/// the untouched slots instead of zeroing them.
///
/// Mirrors `regroupFixedArrayState` in `packages/runar-sdk/src/contract.ts` and
/// `_regroup_fixed_array_state` in `packages/runar-py/runar/sdk/contract.py`.
fn regroupFromStateMap(
    allocator: std.mem.Allocator,
    type_name: []const u8,
    names: []const []const u8,
    state_map: std.StringHashMap(anf_interp.ANFValue),
    prior: types.StateValue,
) !?types.StateValue {
    var saw_any = false;
    for (names) |n| {
        if (state_map.contains(n)) {
            saw_any = true;
            break;
        }
    }
    if (!saw_any) return null;

    const flat = try allocator.alloc(types.StateValue, names.len);
    var filled: usize = 0;
    defer {
        for (flat[0..filled]) |v| v.deinit(allocator);
        allocator.free(flat);
    }
    for (names, 0..) |name, i| {
        if (state_map.get(name)) |anf_val| {
            // anfToStateValue dupes `.bytes`, so `flat` never aliases the
            // result map (which is freed by the caller's cleanup pass).
            flat[filled] = try anfToStateValue(allocator, anf_val);
        } else {
            flat[filled] = try clonePriorLeaf(allocator, prior, i);
        }
        filled += 1;
    }

    var dims_buf: [state_mod.MAX_FIXED_ARRAY_DIMS]u32 = undefined;
    const dims = state_mod.parseFixedArrayDims(type_name, &dims_buf);
    // Same fallback as `buildInitialArrayValue`: a declared shape that does not
    // multiply out to the leaf count means `type` and `fixedArray` disagree —
    // keep the leaves flat rather than drop the whole update.
    return state_mod.regroupStateValues(allocator, flat[0..filled], dims) catch
        try state_mod.regroupStateValues(allocator, flat[0..filled], &[_]u32{@intCast(filled)});
}

/// The `index`-th depth-first leaf of `prior`, cloned; `.int = 0` when `prior`
/// has no such leaf (a shorter or non-array pre-call value).
fn clonePriorLeaf(
    allocator: std.mem.Allocator,
    prior: types.StateValue,
    index: usize,
) !types.StateValue {
    var cursor: usize = 0;
    if (findLeaf(prior, index, &cursor)) |leaf| return try leaf.clone(allocator);
    return types.StateValue{ .int = 0 };
}

fn findLeaf(value: types.StateValue, index: usize, cursor: *usize) ?types.StateValue {
    switch (value) {
        .array_value => |items| {
            for (items) |it| {
                if (findLeaf(it, index, cursor)) |found| return found;
            }
            return null;
        },
        else => {
            if (cursor.* == index) return value;
            cursor.* += 1;
            return null;
        },
    }
}

fn stateValueToAnf(sv: types.StateValue) anf_interp.ANFValue {
    return switch (sv) {
        .int => |n| .{ .int = n },
        // N-163: outside i64 -> `.wide` (refused on arithmetic use), never 0.
        .big_int => |s| if (std.fmt.parseInt(i64, s, 10)) |n| .{ .int = n } else |_| .{ .wide = s },
        .boolean => |b| .{ .boolean = b },
        .bytes => |hex| .{ .bytes = hex },
        // Issue #106: EmptySig -> an empty signature push (empty bytes). The
        // off-chain interpreter mocks checkSig, so the empty branch of an
        // OR-CHECKSIG simply carries no bytes here.
        .empty_sig => .{ .bytes = "" },
        // Arrays — used by callers that pass `[sig1, sig2, ...]` /
        // `[pk1, pk2, pk3, ...]` shapes to `checkMultiSig`. The conversion
        // borrows element storage; the StateValue is owned by the caller
        // and outlives the per-call interpreter run. (FixedArray state
        // fields are still expanded into per-index scalar properties
        // before reaching this path; they never observe this branch.)
        .array_value => |items| stateValueArrayToAnf(items),
    };
}

fn stateValueArrayToAnf(items: []const types.StateValue) anf_interp.ANFValue {
    // Allocate the ANFValue slice with the page allocator so the lifetime
    // is independent of any per-call arena. The slice is small (one entry
    // per array element, typically <16 in multisig usage) and short-lived
    // (one ANF run); rest of this file already returns small one-shot
    // allocations from the same allocator. On allocation failure we fall
    // back to .none so the enclosing real-crypto check fails closed.
    const allocator = std.heap.page_allocator;
    const out = allocator.alloc(anf_interp.ANFValue, items.len) catch {
        return .{ .none = {} };
    };
    for (items, 0..) |it, i| {
        out[i] = stateValueToAnf(it);
    }
    return .{ .array = out };
}

fn anfToStateValue(allocator: std.mem.Allocator, av: anf_interp.ANFValue) !types.StateValue {
    return switch (av) {
        .int => |n| .{ .int = n },
        .boolean => |b| .{ .boolean = b },
        .bytes => |hex| .{ .bytes = try allocator.dupe(u8, hex) },
        .wide => |s| .{ .big_int = try allocator.dupe(u8, s) },
        .array => |items| {
            const out = try allocator.alloc(types.StateValue, items.len);
            errdefer allocator.free(out);
            for (items, 0..) |it, i| {
                out[i] = try anfToStateValue(allocator, it);
            }
            return .{ .array_value = out };
        },
        .none => .{ .int = 0 },
    };
}

// ---------------------------------------------------------------------------
// Helper: parse initial value string to StateValue
// ---------------------------------------------------------------------------

/// Build the grouped `.array_value` for a FixedArray state field from its
/// flattened per-leaf default literals.
fn buildInitialArrayValue(
    allocator: std.mem.Allocator,
    field: types.StateField,
    leaves: []const []const u8,
) !types.StateValue {
    const leaf_type = state_mod.unwrapFixedArrayLeaf(field.type_name);

    const flat = try allocator.alloc(types.StateValue, leaves.len);
    var filled: usize = 0;
    defer {
        for (flat[0..filled]) |v| v.deinit(allocator);
        allocator.free(flat);
    }
    for (leaves) |leaf| {
        flat[filled] = parseInitialValue(allocator, leaf, leaf_type) catch types.StateValue{ .int = 0 };
        filled += 1;
    }

    var dims_buf: [state_mod.MAX_FIXED_ARRAY_DIMS]u32 = undefined;
    const dims = state_mod.parseFixedArrayDims(field.type_name, &dims_buf);
    // A declared shape that does not multiply out to the leaf count means the
    // artifact's `type` and its `initialValue` disagree; keep the leaves as one
    // flat array rather than dropping the default entirely.
    return state_mod.regroupStateValues(allocator, flat[0..filled], dims) catch
        try state_mod.regroupStateValues(allocator, flat[0..filled], &[_]u32{@intCast(filled)});
}

fn parseInitialValue(allocator: std.mem.Allocator, init_str: []const u8, type_name: []const u8) !types.StateValue {
    if (std.mem.eql(u8, type_name, "int") or std.mem.eql(u8, type_name, "bigint")) {
        // Handle BigInt strings with "n" suffix
        var s = init_str;
        if (std.mem.endsWith(u8, s, "n")) {
            s = s[0 .. s.len - 1];
        }
        if (std.fmt.parseInt(i64, s, 10)) |n| {
            return .{ .int = n };
        } else |_| {
            // Value exceeds i64 range; store as big_int decimal string
            return .{ .big_int = try allocator.dupe(u8, s) };
        }
    } else if (std.mem.eql(u8, type_name, "bool")) {
        return .{ .boolean = std.mem.eql(u8, init_str, "true") };
    } else {
        return .{ .bytes = try allocator.dupe(u8, init_str) };
    }
}

// ---------------------------------------------------------------------------
// Helper: insert unlocking script into raw tx hex at given input index
// ---------------------------------------------------------------------------

/// Compute the BIP-143 sighash (SIGHASH_ALL | FORKID) for an input of a
/// raw transaction. Returns the 32-byte digest as 64 lowercase hex chars
/// (caller-owned). Used by `prepareCall` to hand external signers
/// something well-defined to sign without exposing the private key.
fn computeBip143Sighash(
    allocator: std.mem.Allocator,
    tx_hex: []const u8,
    input_index: usize,
    subscript_hex: []const u8,
    satoshis: i64,
) ![]u8 {
    const tx_bytes = try bsvz.primitives.hex.decode(allocator, tx_hex);
    defer allocator.free(tx_bytes);
    var tx = try bsvz.transaction.Transaction.parse(allocator, tx_bytes);
    defer tx.deinit(allocator);

    const script_bytes = try bsvz.primitives.hex.decode(allocator, subscript_hex);
    defer allocator.free(script_bytes);
    const subscript = bsvz.script.Script.init(script_bytes);

    const scope: u32 = bsvz.transaction.sighash.SigHashType.forkid | bsvz.transaction.sighash.SigHashType.all;
    const digest_result = try bsvz.transaction.sighash.digest(allocator, &tx, input_index, subscript, satoshis, scope);

    const out = try allocator.alloc(u8, 64);
    _ = try bsvz.primitives.hex.encodeLower(&digest_result.bytes, out);
    return out;
}

/// Extract `prev_txid (32 bytes LE) || prev_index (4 bytes LE)` for every
/// input in `tx_hex`, concatenated. Returns the lower-hex string. The
/// format mirrors Bitcoin's `hashPrevouts` preimage — used by contracts
/// that declare an `allPrevouts: ByteString` param to assert
/// `hash256(allPrevouts) == extractHashPrevouts(ctx.txPreimage)`. Mirrors
/// Go's `extractAllPrevouts` (`packages/runar-go/sdk_contract.go:1664`).
/// Normalize a witness-value hex string (optional `0x` prefix, any casing)
/// into an owned lowercase hex slice suitable for `encodePushData`. Errors
/// on odd-length / non-hex inputs.
fn normalizeWitnessHex(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var h = s;
    if (h.len >= 2 and (std.mem.eql(u8, h[0..2], "0x") or std.mem.eql(u8, h[0..2], "0X"))) {
        h = h[2..];
    }
    if (h.len % 2 != 0) return error.InvalidWitnessHex;
    const out = try allocator.alloc(u8, h.len);
    errdefer allocator.free(out);
    for (h, 0..) |c, i| {
        const lc: u8 = if (c >= 'A' and c <= 'F') c + 32 else c;
        if (!((lc >= '0' and lc <= '9') or (lc >= 'a' and lc <= 'f'))) {
            return error.InvalidWitnessHex;
        }
        out[i] = lc;
    }
    return out;
}

pub fn extractAllPrevoutsHex(allocator: std.mem.Allocator, tx_hex: []const u8) ![]u8 {
    if (tx_hex.len < 10) return allocator.dupe(u8, "");
    var pos: usize = 8; // skip version (4 bytes = 8 hex chars)
    const ic = readVarIntHex(tx_hex, pos);
    const input_count = ic.value;
    pos += ic.hex_len;

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    var i: usize = 0;
    while (i < input_count) : (i += 1) {
        // outpoint = 32 bytes txid + 4 bytes vout = 36 bytes = 72 hex chars
        if (pos + 72 > tx_hex.len) break;
        try out.appendSlice(allocator, tx_hex[pos .. pos + 72]);
        pos += 72;
        // skip scriptSig
        const sl = readVarIntHex(tx_hex, pos);
        pos += sl.hex_len + sl.value * 2;
        // skip sequence (4 bytes = 8 hex chars)
        pos += 8;
    }

    return out.toOwnedSlice(allocator);
}

pub fn insertUnlockingScript(allocator: std.mem.Allocator, tx_hex: []const u8, input_index: usize, unlock_script_hex: []const u8) ![]u8 {
    var pos: usize = 0;

    // Skip version (4 bytes = 8 hex chars)
    pos += 8;

    // Read input count
    const ic = readVarIntHex(tx_hex, pos);
    const input_count = ic.value;
    pos += ic.hex_len;

    if (input_index >= input_count) return error.OutOfMemory; // index out of range

    var i: usize = 0;
    while (i < input_count) : (i += 1) {
        // Skip prevTxid (32 bytes = 64 hex chars)
        pos += 64;
        // Skip prevOutputIndex (4 bytes = 8 hex chars)
        pos += 8;

        // Read scriptSig length
        const sl = readVarIntHex(tx_hex, pos);
        const script_len = sl.value;
        const sl_hex_len = sl.hex_len;

        if (i == input_index) {
            // Build replacement
            const new_script_byte_len = unlock_script_hex.len / 2;
            const new_varint = try writeVarIntHex(allocator, new_script_byte_len);
            defer allocator.free(new_varint);

            const before = tx_hex[0..pos];
            const after = tx_hex[pos + sl_hex_len + script_len * 2 ..];
            return std.mem.concat(allocator, u8, &[_][]const u8{ before, new_varint, unlock_script_hex, after });
        }

        // Skip this input's scriptSig + sequence (4 bytes = 8 hex chars)
        pos += sl_hex_len + script_len * 2 + 8;
    }

    return error.OutOfMemory; // should not reach here
}

const VarIntResult = struct {
    value: usize,
    hex_len: usize,
};

fn readVarIntHex(hex: []const u8, pos: usize) VarIntResult {
    const first = hexByteAt(hex, pos);
    if (first < 0xfd) return .{ .value = first, .hex_len = 2 };
    if (first == 0xfd) {
        const lo = hexByteAt(hex, pos + 2);
        const hi = hexByteAt(hex, pos + 4);
        return .{ .value = lo | (hi << 8), .hex_len = 6 };
    }
    if (first == 0xfe) {
        const b0 = hexByteAt(hex, pos + 2);
        const b1 = hexByteAt(hex, pos + 4);
        const b2 = hexByteAt(hex, pos + 6);
        const b3 = hexByteAt(hex, pos + 8);
        return .{ .value = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24), .hex_len = 10 };
    }
    // 0xff — 8-byte varint; low 4 bytes only
    const b0 = hexByteAt(hex, pos + 2);
    const b1 = hexByteAt(hex, pos + 4);
    const b2 = hexByteAt(hex, pos + 6);
    const b3 = hexByteAt(hex, pos + 8);
    return .{ .value = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24), .hex_len = 18 };
}

fn writeVarIntHex(allocator: std.mem.Allocator, n: usize) ![]u8 {
    if (n < 0xfd) {
        var buf: [2]u8 = undefined;
        _ = std.fmt.bufPrint(&buf, "{x:0>2}", .{n}) catch unreachable;
        return allocator.dupe(u8, &buf);
    }
    if (n <= 0xffff) {
        var buf: [6]u8 = undefined;
        const lo = n & 0xff;
        const hi = (n >> 8) & 0xff;
        _ = std.fmt.bufPrint(&buf, "fd{x:0>2}{x:0>2}", .{ lo, hi }) catch unreachable;
        return allocator.dupe(u8, &buf);
    }
    if (n <= 0xffffffff) {
        var buf: [10]u8 = undefined;
        const b0 = n & 0xff;
        const b1 = (n >> 8) & 0xff;
        const b2 = (n >> 16) & 0xff;
        const b3 = (n >> 24) & 0xff;
        _ = std.fmt.bufPrint(&buf, "fe{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{ b0, b1, b2, b3 }) catch unreachable;
        return allocator.dupe(u8, &buf);
    }
    return error.OutOfMemory;
}

fn hexByteAt(hex: []const u8, pos: usize) usize {
    if (pos + 2 > hex.len) return 0;
    const high = hexNibble(hex[pos]);
    const low = hexNibble(hex[pos + 1]);
    return (@as(usize, high) << 4) | @as(usize, low);
}

fn hexNibble(c: u8) u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => 0,
    };
}

/// Walk a hex-encoded script and return the byte offsets of every
/// OP_CODESEPARATOR (0xab) that sits at a real opcode boundary (i.e. not inside
/// push-data). Correctly skips all BSV push opcodes (0x01..0x4b,
/// OP_PUSHDATA1/2/4). Caller owns the returned slice.
///
/// Used by getCodeSepIndex to recover the true on-chain byte offsets when the
/// in-memory constructor args don't reflect what was actually baked into the
/// locking script (e.g. after fromTxid populates dummy placeholders).
pub fn findCodesepOffsets(allocator: std.mem.Allocator, script_hex: []const u8) ![]i32 {
    var out: std.ArrayListUnmanaged(i32) = .empty;
    errdefer out.deinit(allocator);
    var off: usize = 0;
    const n = script_hex.len;
    while (off + 2 <= n) {
        const op = hexByteAt(script_hex, off);
        const byte_pos: i32 = @intCast(off / 2);
        if (op == 0xab) {
            try out.append(allocator, byte_pos);
            off += 2;
        } else if (op >= 0x01 and op <= 0x4b) {
            off += 2 + op * 2;
        } else if (op == 0x4c) {
            if (off + 4 > n) break;
            const push_len = hexByteAt(script_hex, off + 2);
            off += 4 + push_len * 2;
        } else if (op == 0x4d) {
            if (off + 6 > n) break;
            const lo = hexByteAt(script_hex, off + 2);
            const hi = hexByteAt(script_hex, off + 4);
            const push_len = lo | (hi << 8);
            off += 6 + push_len * 2;
        } else if (op == 0x4e) {
            if (off + 10 > n) break;
            const b0 = hexByteAt(script_hex, off + 2);
            const b1 = hexByteAt(script_hex, off + 4);
            const b2 = hexByteAt(script_hex, off + 6);
            const b3 = hexByteAt(script_hex, off + 8);
            const push_len = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
            off += 10 + push_len * 2;
        } else {
            off += 2;
        }
    }
    return out.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "RunarContract.init and getLockingScript for stateless contract" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"P2PKH","version":"1","compilerVersion":"1.0","script":"76a914","asm":"OP_DUP OP_HASH160",
        \\"abi":{"constructor":{"params":[{"name":"pubKeyHash","type":"Addr"}]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .bytes = "aabbccdd" }});
    defer contract.deinit();

    const ls = try contract.getLockingScript();
    defer allocator.free(ls);
    // R84: a ctor arg with no constructorSlots entry is never appended --
    // the deployed script is exactly the compiled template ("76a914").
    // Previously this appended the raw arg ("76a914" + push("aabbccdd")),
    // which deploys a script the compiler never produced and fails the
    // consensus clean-stack rule on spend (see packages/runar-sdk's
    // n013-dce-eliminated-ctor-args.test.ts, proved against the real
    // @bsv/sdk Spend oracle).
    try std.testing.expectEqualStrings("76a914", ls);
}

// Issue #42: terminal-method sighash subscript byte-walker.
test "findCodesepOffsets returns real byte position, skipping push-data" {
    const allocator = std.testing.allocator;
    // 51            OP_1
    // 02 ab cd      push 2 bytes (0xab inside push-data, must be ignored)
    // ab            OP_CODESEPARATOR  <- real, byte offset 4
    // ac            OP_CHECKSIG
    const offsets = try findCodesepOffsets(allocator, "5102abcdabac");
    defer allocator.free(offsets);
    try std.testing.expectEqual(@as(usize, 1), offsets.len);
    try std.testing.expectEqual(@as(i32, 4), offsets[0]);
}

test "findCodesepOffsets handles OP_PUSHDATA1" {
    const allocator = std.testing.allocator;
    // 4c (OP_PUSHDATA1) 02 (len) abab (data, contains 0xab) ab (real codesep)
    const offsets = try findCodesepOffsets(allocator, "4c02ababab");
    defer allocator.free(offsets);
    try std.testing.expectEqual(@as(usize, 1), offsets.len);
    try std.testing.expectEqual(@as(i32, 4), offsets[0]);
}

test "findCodesepOffsets trims subscript at real codesep byte position" {
    const allocator = std.testing.allocator;
    const full_script = "5102abcdabac"; // real codesep at byte index 4
    const offsets = try findCodesepOffsets(allocator, full_script);
    defer allocator.free(offsets);
    try std.testing.expectEqual(@as(i32, 4), offsets[0]);
    const hex_offset: usize = @intCast((@as(usize, @intCast(offsets[0])) + 1) * 2);
    const subscript = full_script[hex_offset..];
    try std.testing.expectEqualStrings("ac", subscript);
}

// Issue #132: the OP_CODESEPARATOR offset used for a covenant input's
// OP_PUSH_TX signature must be derived by byte-walking the REAL code script when
// it is present (chain-loaded, or a deploy script already built from real
// constructor args) — mirroring getSubscriptForSigning — NOT recomputed from the
// in-memory constructor args (which are placeholders on the restore path).
//
// Zig centralises this in getCodeSepIndex, which byte-walks code_script via
// findCodesepOffsets whenever code_script is set and only falls back to the
// template adjustCodeSepOffset when code_script == null (deploy-time). Like Go
// (and unlike the TS reference), Zig has no divergent public sibling that
// bypassed the byte-walk, so no production change is needed — this test pins the
// invariant: with a real code_script present, the resolved offset is the
// byte-walked position and is independent of the (placeholder) constructor args.
test "getCodeSepIndex byte-walks the real code script, independent of placeholder args (#132)" {
    const allocator = std.testing.allocator;

    // code script: OP_1..OP_8 (eight single-byte opcodes) then OP_CODESEPARATOR
    // (0xab) at byte offset 8, then a trailing opcode. findCodesepOffsets -> [8].
    const code_script_hex = "5152535455565758ab51";
    const real_offsets = try findCodesepOffsets(allocator, code_script_hex);
    defer allocator.free(real_offsets);
    try std.testing.expectEqual(@as(usize, 1), real_offsets.len);
    try std.testing.expectEqual(@as(i32, 8), real_offsets[0]);

    // Artifact carrying a deliberately WRONG template codeSeparatorIndex (5) and
    // no constructor slots, so adjustCodeSepOffset(5) == 5 — diverging from the
    // byte-walked answer (8).
    const json =
        \\{"contractName":"Cov","version":"1","compilerVersion":"1.0","script":"005100","asm":"OP_0 OP_1 OP_0",
        \\"abi":{"constructor":{"params":[{"name":"count","type":"int"}]},"methods":[{"name":"spend","params":[],"isPublic":true}]},
        \\"stateFields":[{"name":"count","type":"int","index":0}],
        \\"constructorSlots":[],"codeSeparatorIndex":5,"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 0 }});
    defer contract.deinit();

    // With a real code_script present, the offset is byte-walked (8), not the
    // template (5).
    contract.code_script = try allocator.dupe(u8, code_script_hex);
    const got = (try contract.getCodeSepIndex(0)) orelse return error.TestExpectedIndex;
    try std.testing.expectEqual(@as(i32, 8), got);
    try std.testing.expect(got != try contract.adjustCodeSepOffset(5));

    // Without a code_script, the template (deploy-time) path is used.
    var contract2 = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 0 }});
    defer contract2.deinit();
    const got2 = (try contract2.getCodeSepIndex(0)) orelse return error.TestExpectedIndex;
    try std.testing.expectEqual(try contract2.adjustCodeSepOffset(5), got2);
}

test "RunarContract.init and getLockingScript for stateful contract" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"Counter","version":"1","compilerVersion":"1.0","script":"005100","asm":"OP_0 OP_1 OP_0",
        \\"abi":{"constructor":{"params":[{"name":"count","type":"int"}]},"methods":[{"name":"increment","params":[],"isPublic":true}]},
        \\"stateFields":[{"name":"count","type":"int","index":0}],
        \\"constructorSlots":[{"paramIndex":0,"byteOffset":0}],
        \\"codeSeparatorIndex":2,"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 0 }});
    defer contract.deinit();

    const ls = try contract.getLockingScript();
    defer allocator.free(ls);
    // Should contain OP_RETURN (6a) separator
    try std.testing.expect(std.mem.indexOf(u8, ls, "6a") != null);
}

test "RunarContract.buildUnlockingScript basic" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"Test","version":"1","compilerVersion":"1.0","script":"5100","asm":"OP_1 OP_0",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"unlock","params":[{"name":"x","type":"int"}],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &.{});
    defer contract.deinit();

    const unlock = try contract.buildUnlockingScript("unlock", &[_]types.StateValue{.{ .int = 42 }});
    defer allocator.free(unlock);
    try std.testing.expect(unlock.len > 0);
}

test "insertUnlockingScript replaces empty scriptSig" {
    const allocator = std.testing.allocator;
    // Minimal tx: version + 1 input (with 0-length scriptSig) + 0 outputs + locktime
    const tx = "01000000" ++ // version
        "01" ++ // 1 input
        "aa" ** 32 ++ // txid
        "00000000" ++ // vout
        "00" ++ // scriptSig length = 0
        "ffffffff" ++ // sequence
        "00" ++ // 0 outputs
        "00000000"; // locktime

    const result = try insertUnlockingScript(allocator, tx, 0, "51");
    defer allocator.free(result);

    // Should contain "0151" (varint 1 + OP_1)
    try std.testing.expect(std.mem.indexOf(u8, result, "0151") != null);
}

test "RunarContract.withInscription injects envelope into locking script" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"P2PKH","version":"1","compilerVersion":"1.0","script":"76a914","asm":"OP_DUP OP_HASH160",
        \\"abi":{"constructor":{"params":[{"name":"pubKeyHash","type":"Addr"}]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .bytes = "aabbccdd" }});
    defer contract.deinit();

    // Attach an inscription
    try contract.withInscription(.{ .content_type = "text/plain", .data = "48656c6c6f" });

    const ls = try contract.getLockingScript();
    defer allocator.free(ls);

    // Should contain the inscription envelope pattern
    try std.testing.expect(std.mem.indexOf(u8, ls, "0063036f726451") != null);
    // Should still start with the code
    try std.testing.expect(std.mem.startsWith(u8, ls, "76a914"));
    // getInscription should return it
    const insc = contract.getInscription().?;
    try std.testing.expectEqualStrings("text/plain", insc.content_type);
    try std.testing.expectEqualStrings("48656c6c6f", insc.data);
}

test "RunarContract.withInscription on stateful contract injects between code and state" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"Counter","version":"1","compilerVersion":"1.0","script":"005100","asm":"OP_0 OP_1 OP_0",
        \\"abi":{"constructor":{"params":[{"name":"count","type":"int"}]},"methods":[{"name":"increment","params":[],"isPublic":true}]},
        \\"stateFields":[{"name":"count","type":"int","index":0}],
        \\"constructorSlots":[{"paramIndex":0,"byteOffset":0}],
        \\"codeSeparatorIndex":2,"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 42 }});
    defer contract.deinit();

    try contract.withInscription(.{ .content_type = "text/plain", .data = "48656c6c6f" });

    const ls = try contract.getLockingScript();
    defer allocator.free(ls);

    // Should contain OP_RETURN (6a) and the inscription envelope
    try std.testing.expect(std.mem.indexOf(u8, ls, "6a") != null);
    try std.testing.expect(std.mem.indexOf(u8, ls, "0063036f726451") != null);

    // Envelope should appear before OP_RETURN (between code and state)
    const envelope_pos = std.mem.indexOf(u8, ls, "0063036f726451").?;
    const op_return_pos = std.mem.lastIndexOf(u8, ls, "6a").?;
    try std.testing.expect(envelope_pos < op_return_pos);
}

// ---------------------------------------------------------------------------
// N-043 — an ordinals inscription must not break the code-part length pin.
//
// A stateful contract with a variable-length state section carries an EQUALITY
// pin on the deployed code-part length, emitted as a fixed-width nine-byte run:
//
//     76 | 04 LL LL LL LL | 81 | 9c | 69
//     OP_DUP  <len LE32>    OP_BIN2NUM  OP_NUMEQUAL  OP_VERIFY
//
// (Pre-N-051 compilers emitted `a2`, a lower bound, when the length was not
// known at compile time; that is now a deploy-time `codePartLenSlots` pin.)
//
// `getCodePartHex` concatenates the inscription envelope INTO the code part, so
// attaching one makes the real code part longer than the pinned number and every
// honest spend aborts at OP_VERIFY with the funds already committed.
//
// Each template below is a 10-byte script — `OP_1` followed by the nine-byte pin
// run — except the unpinned one and the deploy-time one. The inscription is a two-byte `text/plain`
// payload whose envelope is exactly 23 bytes, so an inscribed code part is
// 10 + 23 = 33 bytes.
// ---------------------------------------------------------------------------

fn pinFixtureArtifactJson(comptime script: []const u8) []const u8 {
    return "{\"contractName\":\"PinFixture\",\"version\":\"runar-v1.0.0-rc.1\",\"compilerVersion\":\"1.0.0-rc.1\"," ++
        "\"parentClass\":\"StatefulSmartContract\",\"script\":\"" ++ script ++ "\",\"asm\":\"\"," ++
        "\"abi\":{\"constructor\":{\"params\":[{\"name\":\"memo\",\"type\":\"ByteString\"}]}," ++
        "\"methods\":[{\"name\":\"post\",\"params\":[{\"name\":\"newMemo\",\"type\":\"ByteString\"}],\"isPublic\":true}]}," ++
        "\"stateFields\":[{\"name\":\"memo\",\"type\":\"ByteString\",\"index\":0}],\"constructorSlots\":[]," ++
        "\"buildTimestamp\":\"2024-01-01\"}";
}

const pin_fixture_inscription: ordinals.Inscription = .{ .content_type = "text/plain", .data = "6869" };

/// Exact pin of 10: correct WITHOUT an envelope, violated by one. Refuse.
const pin_template_exact_10 = "5176040a000000819c69";
/// Exact pin of 33 (0x21): correct WITH the envelope attached. Accept — and a
/// decoder that reads the length big-endian gets 0x21000000 here and wrongly
/// refuses.
const pin_template_exact_33 = "51760421000000819c69";
/// N-051 DEPLOY-TIME pin: a readonly variable-width `tag` placeholder (OP_0 at
/// byte 0) followed by an equality pin whose 4-byte field (byte 3) is listed in
/// `codePartLenSlots`. The template value (10) is only a placeholder; the SDK
/// writes the deployed code-part length, envelope included.
const pin_fixture_deploy_time_json =
    "{\"contractName\":\"PinFixture\",\"version\":\"runar-v1.0.0-rc.1\",\"compilerVersion\":\"1.0.0-rc.1\"," ++
    "\"parentClass\":\"StatefulSmartContract\",\"script\":\"0076040a000000819c69\",\"asm\":\"\"," ++
    "\"abi\":{\"constructor\":{\"params\":[{\"name\":\"memo\",\"type\":\"ByteString\"},{\"name\":\"tag\",\"type\":\"ByteString\"}]}," ++
    "\"methods\":[{\"name\":\"post\",\"params\":[{\"name\":\"newMemo\",\"type\":\"ByteString\"}],\"isPublic\":true}]}," ++
    "\"stateFields\":[{\"name\":\"memo\",\"type\":\"ByteString\",\"index\":0}]," ++
    "\"constructorSlots\":[{\"paramIndex\":1,\"byteOffset\":0}],\"codePartLenSlots\":[{\"byteOffset\":3}]," ++
    "\"buildTimestamp\":\"2024-01-01\"}";
/// No pin at all (a bare P2PKH template). Accept.
const pin_template_none = "76a90088ac";

test "N-043 withInscription refuses an envelope that breaks an exact pin" {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, pinFixtureArtifactJson(pin_template_exact_10));
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .bytes = "48656c6c6f" }});
    defer contract.deinit();

    errors_mod.last_codepart_pin_error = null;
    const result = contract.withInscription(pin_fixture_inscription);
    try std.testing.expectError(errors_mod.CodePartPinError.CodePartLengthPinViolated, result);

    // Assert the REASON, not merely that something failed: a test that accepts
    // any error passes when an unrelated one fires.
    const rec = errors_mod.last_codepart_pin_error.?;
    try std.testing.expectEqual(@as(usize, 10), rec.pinned);
    try std.testing.expectEqual(@as(usize, 33), rec.actual);
    try std.testing.expectEqualStrings("PinFixture", rec.contractName());

    // The contract must be left un-inscribed rather than half-mutated.
    try std.testing.expect(contract.getInscription() == null);
    const code = try contract.getCodePartHex();
    defer allocator.free(code);
    try std.testing.expectEqual(@as(usize, 10), code.len / 2);
}

test "N-043 withInscription accepts a pin that already matches the inscribed length" {
    // Control: a pin whose value already accounts for the envelope is honoured.
    // Also pins the little-endian decode — a big-endian reader sees 0x21000000.
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, pinFixtureArtifactJson(pin_template_exact_33));
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .bytes = "48656c6c6f" }});
    defer contract.deinit();

    try contract.withInscription(pin_fixture_inscription);
    try std.testing.expect(contract.getInscription() != null);

    const code = try contract.getCodePartHex();
    defer allocator.free(code);
    try std.testing.expectEqual(@as(usize, 33), code.len / 2);
}

test "N-043 withInscription accepts a deploy-time pin and sets it to the inscribed length" {
    // Control 1 (mandatory). This used to be a LOWER-bound (`a2`) pin, which
    // the envelope's extra bytes satisfied. N-051 made it an equality whose
    // value the SDK writes at deploy time (`codePartLenSlots`); the envelope is
    // part of `_codePart`, so the SDK writes the INSCRIBED length and the
    // inscription stays accepted. Refusing it would turn the fix into an
    // outage for every variable-width-constructor contract.
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, pin_fixture_deploy_time_json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{
        .{ .bytes = "48656c6c6f" }, .{ .bytes = "aa" },
    });
    defer contract.deinit();

    try contract.withInscription(pin_fixture_inscription);
    try std.testing.expect(contract.getInscription() != null);

    // Equality against the inscribed code part, not merely a bound:
    // 2-byte `01aa` + 9-byte pin = 11, plus the 23-byte envelope = 34.
    const code = try contract.getCodePartHex();
    defer allocator.free(code);
    try std.testing.expectEqual(@as(usize, 34), code.len / 2);
    var pins = try decodeExactCodePartLenPins(allocator, code);
    defer pins.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), pins.items.len);
    try std.testing.expectEqual(@as(usize, 34), pins.items[0]);
}

test "N-043 withInscription accepts an unpinned contract" {
    // Control 2 (mandatory): a contract with no pin at all (stateless, or a
    // fixed-size state layout) must still accept an inscription.
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, pinFixtureArtifactJson(pin_template_none));
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .bytes = "48656c6c6f" }});
    defer contract.deinit();

    try contract.withInscription(pin_fixture_inscription);
    try std.testing.expect(contract.getInscription() != null);
}

// ---------------------------------------------------------------------------
// prepareCall / finalizeCall round-trip — multi-signer support (parity with
// Go/Ruby/Java/Rust/Python prepare_call / prepareCall).
// ---------------------------------------------------------------------------

test "prepareCall returns sighashes and sig_indices for stateless Sig param" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"P2PKH","version":"1","compilerVersion":"1.0","script":"5151","asm":"OP_1 OP_1",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"unlock","params":[{"name":"sig","type":"Sig"},{"name":"pubKey","type":"PubKey"}],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &.{});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");
    const signer_iface = signer.signer();

    // Pre-attach the contract UTXO so prepareCall doesn't fail with NotDeployed.
    try contract.setCurrentUtxo(.{
        .txid = "ab" ** 32,
        .output_index = 0,
        .satoshis = 10_000,
        .script = "5151",
    });

    // Both Sig and PubKey are auto-resolved when passed as int(0).
    const args = [_]types.StateValue{ .{ .int = 0 }, .{ .int = 0 } };
    var prepared = try contract.prepareCall("unlock", &args, prov.provider(), signer_iface, null);
    defer prepared.deinit(allocator);

    // 1 Sig → 1 sighash, 1 sig_index pointing at arg position 0.
    try std.testing.expectEqual(@as(usize, 1), prepared.sighashes.len);
    try std.testing.expectEqual(@as(usize, 1), prepared.sig_indices.len);
    try std.testing.expectEqual(@as(usize, 0), prepared.sig_indices[0]);
    try std.testing.expectEqual(@as(usize, 64), prepared.sighashes[0].len);
    try std.testing.expect(prepared.tx_hex.len > 0);
    try std.testing.expectEqualStrings("unlock", prepared.method_name);
    try std.testing.expect(!prepared.is_stateful);
}

test "prepareCall handles stateful contract with Sig param (full OP_PUSH_TX convergence)" {
    const allocator = std.testing.allocator;
    // Stateful counter with a Sig param on increment. Constructor has
    // a single bigint state field (count). The OP_PUSH_TX convergence
    // path runs end-to-end and returns one BIP-143 sighash.
    const json =
        \\{"contractName":"SignedCounter","version":"1","compilerVersion":"1.0","script":"005100","asm":"OP_0 OP_1 OP_0",
        \\"abi":{"constructor":{"params":[{"name":"count","type":"int"}]},"methods":[{"name":"increment","params":[{"name":"sig","type":"Sig"},{"name":"txPreimage","type":"SigHashPreimage"}],"isPublic":true}]},
        \\"stateFields":[{"name":"count","type":"int","index":0}],
        \\"constructorSlots":[{"paramIndex":0,"byteOffset":0}],
        \\"codeSeparatorIndex":2,"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 0 }});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");

    try contract.setCurrentUtxo(.{
        .txid = "cd" ** 32,
        .output_index = 0,
        .satoshis = 1_000,
        .script = "005100",
    });

    // Pass new_state explicitly — the prepareCall path does not run the
    // ANF interpreter (this fixture has no anfJson anyway).
    const new_state = [_]types.StateValue{.{ .int = 1 }};
    const opts = types.CallOptions{ .new_state = &new_state };

    const args = [_]types.StateValue{.{ .int = 0 }};
    var prepared = try contract.prepareCall("increment", &args, prov.provider(), signer.signer(), opts);
    defer prepared.deinit(allocator);

    try std.testing.expect(prepared.is_stateful);
    try std.testing.expectEqual(@as(usize, 1), prepared.sig_indices.len);
    try std.testing.expectEqual(@as(usize, 0), prepared.sig_indices[0]);
    try std.testing.expectEqual(@as(usize, 64), prepared.sighashes[0].len);
    // Continuation captured for finalizeCall to track the new UTXO.
    try std.testing.expect(prepared.new_locking_script.len > 0);
    try std.testing.expectEqual(@as(i64, 1_000), prepared.new_satoshis);
    // OP_PUSH_TX preimage evidence captured (non-empty hex). N-213: there is
    // no op_push_tx_sig to assert on -- PreparedCall carries no such field.
    try std.testing.expect(prepared.preimage.len > 0);
    try std.testing.expectEqual(@as(i32, 2), prepared.code_sep_idx);
}

test "prepareCall → finalizeCall round-trip on stateful Sig-bearing contract" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"SignedCounter","version":"1","compilerVersion":"1.0","script":"005100","asm":"OP_0 OP_1 OP_0",
        \\"abi":{"constructor":{"params":[{"name":"count","type":"int"}]},"methods":[{"name":"increment","params":[{"name":"sig","type":"Sig"},{"name":"txPreimage","type":"SigHashPreimage"}],"isPublic":true}]},
        \\"stateFields":[{"name":"count","type":"int","index":0}],
        \\"constructorSlots":[{"paramIndex":0,"byteOffset":0}],
        \\"codeSeparatorIndex":2,"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 0 }});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");

    // The fail-closed MockProvider must also know the outpoint the call
    // spends, or it would have nothing to check (Phase A5 non-vacuity).
    try prov.addKnownOutpoint("ee" ** 32, 0, "005100", 2_000);
    try contract.setCurrentUtxo(.{
        .txid = "ee" ** 32,
        .output_index = 0,
        .satoshis = 2_000,
        .script = "005100",
    });

    const new_state = [_]types.StateValue{.{ .int = 1 }};
    const opts = types.CallOptions{ .new_state = &new_state };

    const args = [_]types.StateValue{.{ .int = 0 }};
    var prepared = try contract.prepareCall("increment", &args, prov.provider(), signer.signer(), opts);
    defer prepared.deinit(allocator);

    // External signer would deliver a real DER sig; MockProvider does not
    // validate scripts so a well-shaped placeholder suffices for the
    // splice-and-broadcast path.
    const fake_sig: []const u8 = "30" ++ "44" ++ "02" ++ "20" ++ ("11" ** 32) ++ "02" ++ "20" ++ ("22" ** 32) ++ "41";
    const sigs = [_][]const u8{fake_sig};

    const txid = try contract.finalizeCall(&prepared, &sigs, prov.provider());
    defer allocator.free(txid);

    try std.testing.expectEqual(@as(usize, 64), txid.len);
    // Stateful: tracked UTXO must point at the broadcast tx as the
    // continuation output.
    const utxo = contract.getCurrentUtxo().?;
    try std.testing.expectEqualStrings(txid, utxo.txid);
    try std.testing.expectEqual(@as(i32, 0), utxo.output_index);
    try std.testing.expectEqual(@as(i64, 2_000), utxo.satoshis);
}

// N-213 -- the Zig half of "remove the dead PreparedCall.opPushTxSig field
// (and its wasted ECDSA sign per stateful call) from
// Go/Rust/Python/Ruby/Zig SDKs, as F-369 did for TS".
//
// Since BUG-100 the unlocking script carries no spender-supplied OP_PUSH_TX
// signature: buildStatefulUnlockScript's first parameter is accepted for
// call-site compatibility but ignored (see its "_ = op_sig_hex" discard).
// op_push_tx_sig was documented public surface on PreparedCall that backed
// nothing a caller could use.
//
// This test proves (a) PreparedCall declares no op_push_tx_sig field at all
// -- checked via @hasField at comptime, the Zig analogue of the Go sibling
// test's JSON-key check and the TS reference test's
// `'opPushTxSig' in prepared` -- and (b) the prepareCall -> finalizeCall
// round-trip (reusing the fixture from the preceding
// "prepareCall -> finalizeCall round-trip" test) still broadcasts
// successfully with the field gone.
//
// It does NOT prove anything about the other four SDKs in scope for N-213
// (Go/Rust/Python/Ruby -- each gets its own language-appropriate
// field-absence test) or a real on-chain broadcast -- Zig has no ScriptVM
// (see CLAUDE.md), and MockProvider does not validate scripts.
test "PreparedCall has no op_push_tx_sig field (N-213)" {
    try std.testing.expect(!@hasField(types.PreparedCall, "op_push_tx_sig"));

    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"SignedCounter","version":"1","compilerVersion":"1.0","script":"005100","asm":"OP_0 OP_1 OP_0",
        \\"abi":{"constructor":{"params":[{"name":"count","type":"int"}]},"methods":[{"name":"increment","params":[{"name":"sig","type":"Sig"},{"name":"txPreimage","type":"SigHashPreimage"}],"isPublic":true}]},
        \\"stateFields":[{"name":"count","type":"int","index":0}],
        \\"constructorSlots":[{"paramIndex":0,"byteOffset":0}],
        \\"codeSeparatorIndex":2,"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 0 }});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");

    try prov.addKnownOutpoint("ee" ** 32, 0, "005100", 2_000);
    try contract.setCurrentUtxo(.{
        .txid = "ee" ** 32,
        .output_index = 0,
        .satoshis = 2_000,
        .script = "005100",
    });

    const new_state = [_]types.StateValue{.{ .int = 1 }};
    const opts = types.CallOptions{ .new_state = &new_state };

    const args = [_]types.StateValue{.{ .int = 0 }};
    var prepared = try contract.prepareCall("increment", &args, prov.provider(), signer.signer(), opts);
    defer prepared.deinit(allocator);

    // Multi-signer flow: external wallet delivers a real DER sig over
    // prepared.sighashes[0] (MockProvider does not validate scripts, so a
    // well-shaped placeholder of the right length suffices for the
    // splice-and-broadcast path -- same as the sibling round-trip test).
    const fake_sig: []const u8 = "30" ++ "44" ++ "02" ++ "20" ++ ("11" ** 32) ++ "02" ++ "20" ++ ("22" ** 32) ++ "41";
    const sigs = [_][]const u8{fake_sig};

    const txid = try contract.finalizeCall(&prepared, &sigs, prov.provider());
    defer allocator.free(txid);

    try std.testing.expectEqual(@as(usize, 64), txid.len);
}

test "finalizeCall errors on signature count mismatch" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"P2PKH","version":"1","compilerVersion":"1.0","script":"5151","asm":"OP_1 OP_1",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"unlock","params":[{"name":"sig","type":"Sig"},{"name":"pubKey","type":"PubKey"}],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &.{});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");

    try contract.setCurrentUtxo(.{
        .txid = "ef" ** 32,
        .output_index = 0,
        .satoshis = 5_000,
        .script = "5151",
    });

    const args = [_]types.StateValue{ .{ .int = 0 }, .{ .int = 0 } };
    var prepared = try contract.prepareCall("unlock", &args, prov.provider(), signer.signer(), null);
    defer prepared.deinit(allocator);

    // 0 signatures supplied for 1 expected → SignatureCountMismatch.
    const result = contract.finalizeCall(&prepared, &.{}, prov.provider());
    try std.testing.expectError(ContractError.SignatureCountMismatch, result);
}

test "prepareCall → finalizeCall round-trip broadcasts a tx" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"P2PKH","version":"1","compilerVersion":"1.0","script":"5151","asm":"OP_1 OP_1",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"unlock","params":[{"name":"sig","type":"Sig"},{"name":"pubKey","type":"PubKey"}],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &.{});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");

    // The fail-closed MockProvider must also know the outpoint the call
    // spends, or it would have nothing to check (Phase A5 non-vacuity).
    try prov.addKnownOutpoint("12" ** 32, 0, "5151", 4_000);
    try contract.setCurrentUtxo(.{
        .txid = "12" ** 32,
        .output_index = 0,
        .satoshis = 4_000,
        .script = "5151",
    });

    const args = [_]types.StateValue{ .{ .int = 0 }, .{ .int = 0 } };
    var prepared = try contract.prepareCall("unlock", &args, prov.provider(), signer.signer(), null);
    defer prepared.deinit(allocator);

    // External signer produces a 73-byte hex sig (DER ~71 + sighash byte = 144 hex).
    // For round-trip verification we just need a well-shaped placeholder
    // (MockProvider does not validate scripts on broadcast).
    const fake_sig: []const u8 = "30" ++ "44" ++ "02" ++ "20" ++ ("11" ** 32) ++ "02" ++ "20" ++ ("22" ** 32) ++ "41";
    const sigs = [_][]const u8{fake_sig};

    const txid = try contract.finalizeCall(&prepared, &sigs, prov.provider());
    defer allocator.free(txid);

    // MockProvider mints a 64-char mock hash on broadcast.
    try std.testing.expectEqual(@as(usize, 64), txid.len);
    // Stateless terminal call must clear currentUtxo.
    try std.testing.expect(contract.getCurrentUtxo() == null);
}

test "call with terminal_outputs builds tx with exact outputs and clears UTXO" {
    const allocator = std.testing.allocator;
    // Stateless contract that always succeeds (script "51" = OP_1).
    // No Sig params — exercises the terminal-output path on the simplest
    // possible contract so failures point at output handling, not signing.
    const json =
        \\{"contractName":"OpOne","version":"1","compilerVersion":"1.0","script":"51","asm":"OP_1",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"go","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &.{});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");

    // The fail-closed MockProvider must also know the outpoint the call
    // spends, or it would have nothing to check (Phase A5 non-vacuity).
    try prov.addKnownOutpoint("fe" ** 32, 0, "51", 5_000);
    try contract.setCurrentUtxo(.{
        .txid = "fe" ** 32,
        .output_index = 0,
        .satoshis = 5_000,
        .script = "51",
    });

    // Two terminal outputs: 1500 sats to a P2PKH script + 2000 sats to a
    // raw script (OP_1). 5000 input - 3500 output = 1500 sats absorbed
    // as fee (more than enough for a tiny tx).
    const term_p2pkh = "76a914" ++ ("aa" ** 20) ++ "88ac";
    const term_outputs = [_]types.ContractOutput{
        .{ .script = term_p2pkh, .satoshis = 1500 },
        .{ .script = "51", .satoshis = 2000 },
    };
    const opts = types.CallOptions{ .terminal_outputs = &term_outputs };

    const txid = try contract.call("go", &.{}, prov.provider(), signer.signer(), opts);
    defer allocator.free(txid);

    // MockProvider mints a 64-char mock txid on broadcast.
    try std.testing.expectEqual(@as(usize, 64), txid.len);
    // Terminal call must clear currentUtxo (contract is fully spent).
    try std.testing.expect(contract.getCurrentUtxo() == null);

    // The broadcast tx must contain both terminal output scripts.
    const raw_tx = try prov.provider().getRawTransaction(allocator, txid);
    defer allocator.free(raw_tx);
    try std.testing.expect(std.mem.indexOf(u8, raw_tx, term_p2pkh) != null);
    // The OP_1 output is one byte; check by surrounding length-prefix
    // pattern "0151" (varint length 1, OP_1).
    try std.testing.expect(std.mem.indexOf(u8, raw_tx, "0151") != null);
}

// Issue #118: CallOptions.fee_utxo adds a single P2PKH input to a terminal call
// tx purely to pay the miner fee — added before the OP_PUSH_TX preimage and
// consumed entirely as fee (no change output). Merges into the terminal
// funding-input path.
test "terminal call adds fee_utxo input to pay the miner fee (#118)" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"OpOne","version":"1","compilerVersion":"1.0","script":"51","asm":"OP_1",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"go","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");
    const term_p2pkh = "76a914" ++ ("aa" ** 20) ++ "88ac";
    // Terminal output pays out the full 5000 contract balance, so the fee must
    // come from the fee_utxo. The fee input's txid is all-0xcc, which is a
    // palindrome under the little-endian prevout byte reversal.
    const term_outputs = [_]types.ContractOutput{.{ .script = term_p2pkh, .satoshis = 5000 }};
    const fee_utxo = types.UTXO{ .txid = "cc" ** 32, .output_index = 1, .satoshis = 1000, .script = "76a914" ++ ("bb" ** 20) ++ "88ac" };

    // WITH fee_utxo: the fee input's prevout appears in the broadcast tx.
    {
        var contract = try RunarContract.init(allocator, &artifact, &.{});
        defer contract.deinit();
        var prov = provider_mod.MockProvider.init(allocator, "testnet");
        defer prov.deinit();
        // Phase A5 non-vacuity: teach the validating provider the contract
        // outpoint (and, below, the fee coin) this call spends.
        try prov.addKnownOutpoint("fe" ** 32, 0, "51", 5000);
        try prov.addKnownOutpoint(fee_utxo.txid, fee_utxo.output_index, fee_utxo.script, fee_utxo.satoshis);
        try contract.setCurrentUtxo(.{ .txid = "fe" ** 32, .output_index = 0, .satoshis = 5000, .script = "51" });
        const opts = types.CallOptions{ .terminal_outputs = &term_outputs, .fee_utxo = fee_utxo };
        const txid = try contract.call("go", &.{}, prov.provider(), signer.signer(), opts);
        defer allocator.free(txid);
        try std.testing.expect(contract.getCurrentUtxo() == null);
        const raw_tx = try prov.provider().getRawTransaction(allocator, txid);
        defer allocator.free(raw_tx);
        try std.testing.expect(std.mem.indexOf(u8, raw_tx, "cc" ** 32) != null);
        try std.testing.expect(std.mem.indexOf(u8, raw_tx, term_p2pkh) != null);
    }

    // WITHOUT fee_utxo: no such input (baseline).
    {
        var contract = try RunarContract.init(allocator, &artifact, &.{});
        defer contract.deinit();
        var prov = provider_mod.MockProvider.init(allocator, "testnet");
        defer prov.deinit();
        // Phase A5 non-vacuity: teach the validating provider the contract
        // outpoint (and, below, the fee coin) this call spends.
        try prov.addKnownOutpoint("fe" ** 32, 0, "51", 5000);
        try prov.addKnownOutpoint(fee_utxo.txid, fee_utxo.output_index, fee_utxo.script, fee_utxo.satoshis);
        try contract.setCurrentUtxo(.{ .txid = "fe" ** 32, .output_index = 0, .satoshis = 5000, .script = "51" });
        const opts = types.CallOptions{ .terminal_outputs = &term_outputs };
        const txid = try contract.call("go", &.{}, prov.provider(), signer.signer(), opts);
        defer allocator.free(txid);
        const raw_tx = try prov.provider().getRawTransaction(allocator, txid);
        defer allocator.free(raw_tx);
        try std.testing.expect(std.mem.indexOf(u8, raw_tx, "cc" ** 32) == null);
    }
}

// N-271: a call that supplies BOTH terminal_outputs and
// additional_contract_inputs must refuse with a named error. The terminal
// builder lays out exactly one contract input (plus an optional fee/funding
// input) and never threads additional_contract_inputs into the tx. Before
// the fix this proves the extra UTXO is silently dropped instead of being
// rejected or spent -- the call succeeds and returns a txid, but the
// broadcast tx has only one contract input, not two.
//
// This does NOT prove additional_contract_inputs could ever be made to work
// on the terminal path (merging it validly) -- only that dropping it
// silently is unacceptable and must become a refusal.
test "call with terminal_outputs and additional_contract_inputs fails closed" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"OpOne","version":"1","compilerVersion":"1.0","script":"51","asm":"OP_1",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"go","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &.{});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");

    try prov.addKnownOutpoint("fe" ** 32, 0, "51", 5_000);
    try contract.setCurrentUtxo(.{
        .txid = "fe" ** 32,
        .output_index = 0,
        .satoshis = 5_000,
        .script = "51",
    });

    const term_p2pkh = "76a914" ++ ("aa" ** 20) ++ "88ac";
    const term_outputs = [_]types.ContractOutput{.{ .script = term_p2pkh, .satoshis = 4500 }};
    const extra_utxos = [_]types.UTXO{.{ .txid = "ee" ** 32, .output_index = 0, .satoshis = 1000, .script = "51" }};
    const opts = types.CallOptions{ .terminal_outputs = &term_outputs, .additional_contract_inputs = &extra_utxos };

    const result = contract.call("go", &.{}, prov.provider(), signer.signer(), opts);
    try std.testing.expectError(ContractError.TerminalAdditionalContractInputsUnsupported, result);
}

// N-276 (port of N-227 Part 2 / N-258 to Zig; TS/Go/Rust/Python/Ruby already
// refuse this exact shape): a NON-terminal call on a plain SmartContract
// (parentClass neither set nor "StatefulSmartContract", so `!parent_stateful`)
// with `options.additional_contract_inputs` must refuse instead of silently
// dropping the extra UTXO. Before the fix, call()'s stateless path (guarded
// on `!parent_stateful`, see sdk_contract.zig) never read
// `options.additional_contract_inputs` at all: it built and broadcast a tx
// spending ONLY the primary contract input, returning a txid as if the call
// fully succeeded, while the caller's extra UTXO was neither spent nor
// refused.
//
// Does NOT prove additional_contract_inputs could ever be made to work on a
// plain SmartContract -- only that silently dropping it is unacceptable.
// Does NOT exercise the zero-mutable-field StatefulSmartContract merge path
// (parent_stateful but !is_stateful) -- call() already threads extra inputs
// correctly there via `extra_call_inputs` (see
// sdk_n227_zero_mutable_field_fee_floor_test.zig), and this fix must not
// change that: the guard below is conditioned on `!parent_stateful`, which
// is false for that case.
test "call on a plain SmartContract with additional_contract_inputs fails closed (non-terminal)" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"OpOne","version":"1","compilerVersion":"1.0","script":"51","asm":"OP_1",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"go","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &.{});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");

    try prov.addKnownOutpoint("fe" ** 32, 0, "51", 5_000);
    try contract.setCurrentUtxo(.{
        .txid = "fe" ** 32,
        .output_index = 0,
        .satoshis = 5_000,
        .script = "51",
    });

    // A funding UTXO so the (pre-fix) build has everything it needs to
    // succeed and broadcast -- the RED failure must be "silently dropped
    // the extra input", not an unrelated InsufficientFunds/CallFailed.
    const addr = try signer.signer().getAddress(allocator);
    defer allocator.free(addr);
    try prov.addUtxo(addr, .{
        .txid = "fd" ** 32,
        .output_index = 0,
        .satoshis = 100_000,
        .script = "76a914" ++ ("00" ** 20) ++ "88ac",
    });

    const extra_utxos = [_]types.UTXO{.{ .txid = "ee" ** 32, .output_index = 0, .satoshis = 1000, .script = "51" }};
    const opts = types.CallOptions{ .additional_contract_inputs = &extra_utxos };

    const result = contract.call("go", &.{}, prov.provider(), signer.signer(), opts);
    try std.testing.expectError(ContractError.AdditionalContractInputsUnsupported, result);
}

// N-276 companion for `prepareCall()`. Unlike `call()`, prepareCall's
// non-stateful path (entered whenever `is_stateful` is false -- see
// `prepareCall`'s dispatch to `prepareCallStateful`) has NO per-input unlock
// builder at all, for either shape of non-stateful contract: it never reads
// `options.additional_contract_inputs` outside the N-271 terminal guard. So
// the refusal added here is unconditional within that branch (not gated on
// `parent_stateful` the way call()'s is) -- there is no "legitimate"
// zero-mutable-field merge path in prepareCall to preserve; prepareCall does
// not thread additional_contract_inputs for ANY non-stateful shape today.
//
// Does NOT prove additional_contract_inputs could be made to work via
// prepareCall for a plain SmartContract or a zero-mutable-field
// StatefulSmartContract. Does NOT exercise `prepareCallStateful` (a REAL
// StatefulSmartContract with mutable fields) -- that function also never
// threads additional_contract_inputs, a separate, pre-existing gap outside
// this item's scope (see dispatcher notes).
test "prepareCall on a plain SmartContract with additional_contract_inputs fails closed (non-terminal)" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"OpOne","version":"1","compilerVersion":"1.0","script":"51","asm":"OP_1",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"go","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &.{});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");

    try contract.setCurrentUtxo(.{
        .txid = "fe" ** 32,
        .output_index = 0,
        .satoshis = 10_000,
        .script = "51",
    });

    const extra_utxos = [_]types.UTXO{.{ .txid = "ee" ** 32, .output_index = 0, .satoshis = 1000, .script = "51" }};
    const opts = types.CallOptions{ .additional_contract_inputs = &extra_utxos };

    const result = contract.prepareCall("go", &.{}, prov.provider(), signer.signer(), opts);
    try std.testing.expectError(ContractError.AdditionalContractInputsUnsupported, result);
}

// Issue #133: the non-terminal call funding path coin-selects the smallest
// largest-first subset of wallet UTXOs (reusing selectUtxos) instead of sweeping
// every candidate, and enforces max_funding_inputs.
test "selectCallFunding trims the wallet sweep to the minimal subset (#133)" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"Trivial","version":"1","compilerVersion":"1.0","script":"51","asm":"OP_1",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();
    var contract = try RunarContract.init(allocator, &artifact, &.{});
    defer contract.deinit();

    const p2pkh = "76a914" ++ ("00" ** 20) ++ "88ac";
    const cands = [_]types.UTXO{
        .{ .txid = "01" ** 32, .output_index = 0, .satoshis = 1000, .script = p2pkh },
        .{ .txid = "02" ** 32, .output_index = 0, .satoshis = 2000, .script = p2pkh },
        .{ .txid = "03" ** 32, .output_index = 0, .satoshis = 10000, .script = p2pkh },
        .{ .txid = "04" ** 32, .output_index = 0, .satoshis = 500, .script = p2pkh },
        .{ .txid = "05" ** 32, .output_index = 0, .satoshis = 3000, .script = p2pkh },
    };

    // funding_target = output(0) - input(0) = 0 → cover just the fee. The
    // largest UTXO (10000) alone covers it → exactly 1 input, and it is the
    // largest (not the whole 5-UTXO wallet).
    {
        var au: std.ArrayListUnmanaged(types.UTXO) = .empty;
        defer au.deinit(allocator);
        for (cands) |c| try au.append(allocator, c);
        try contract.selectCallFunding(&au, false, 0, 0, 25, 100, 0, 0, null);
        try std.testing.expectEqual(@as(usize, 1), au.items.len);
        try std.testing.expectEqual(@as(i64, 10000), au.items[0].satoshis);
    }

    // A terminal call leaves the caller-supplied funding untouched.
    {
        var au: std.ArrayListUnmanaged(types.UTXO) = .empty;
        defer au.deinit(allocator);
        for (cands) |c| try au.append(allocator, c);
        try contract.selectCallFunding(&au, true, 0, 0, 25, 100, 0, 0, null);
        try std.testing.expectEqual(@as(usize, 5), au.items.len);
    }

    // max_funding_inputs cap: covering funding_target 5000 needs the 10000 UTXO
    // (1 input), which exceeds a cap of 0 → fail loudly.
    {
        var au: std.ArrayListUnmanaged(types.UTXO) = .empty;
        defer au.deinit(allocator);
        for (cands) |c| try au.append(allocator, c);
        try std.testing.expectError(
            ContractError.InsufficientFunds,
            contract.selectCallFunding(&au, false, 5000, 0, 25, 100, 0, 0, 0),
        );
    }
}

test "resolveTerminalOutputs converts addresses and script_hex into ContractOutput list" {
    const allocator = std.testing.allocator;
    const inputs = [_]types.TerminalOutput{
        .{ .satoshis = 1000, .script_hex = "76a914aabbccddeeff00112233445566778899aabbccdd88ac" },
        .{ .satoshis = 2000, .address = "abcdef0123456789abcdef0123456789abcdef01" }, // 40-char hex pkh
    };
    const out = try call_mod.resolveTerminalOutputs(allocator, &inputs);
    defer call_mod.freeResolvedTerminalOutputs(allocator, out);

    try std.testing.expectEqual(@as(usize, 2), out.len);
    try std.testing.expectEqual(@as(i64, 1000), out[0].satoshis);
    try std.testing.expectEqualStrings("76a914aabbccddeeff00112233445566778899aabbccdd88ac", out[0].script);
    try std.testing.expectEqual(@as(i64, 2000), out[1].satoshis);
    try std.testing.expectEqualStrings("76a914abcdef0123456789abcdef0123456789abcdef0188ac", out[1].script);
}

test "RunarContract.fromUtxo detects inscription in code script" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"P2PKH","version":"1","compilerVersion":"1.0","script":"76a914","asm":"OP_DUP OP_HASH160",
        \\"abi":{"constructor":{"params":[{"name":"pubKeyHash","type":"Addr"}]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    // Build a script with an inscription envelope
    const code = "76a914" ++ "00" ** 20 ++ "88ac";
    const envelope = try ordinals.buildInscriptionEnvelope(allocator, "text/plain", "48656c6c6f");
    defer allocator.free(envelope);
    const script = try std.mem.concat(allocator, u8, &[_][]const u8{ code, envelope });
    defer allocator.free(script);

    const utxo = types.UTXO{
        .txid = "aa" ** 32,
        .output_index = 0,
        .satoshis = 1,
        .script = script,
    };

    var contract = try RunarContract.fromUtxo(allocator, &artifact, utxo);
    defer contract.deinit();

    // Should have detected the inscription
    const insc = contract.getInscription().?;
    try std.testing.expectEqualStrings("text/plain", insc.content_type);
    try std.testing.expectEqualStrings("48656c6c6f", insc.data);

    // code_script should include the envelope (not stripped)
    try std.testing.expect(contract.code_script != null);
    try std.testing.expect(std.mem.indexOf(u8, contract.code_script.?, "0063036f726451") != null);
}

// Issue #119: fromUtxo must recover the REAL baked-in constructor args from the
// deployed script (via extractConstructorArgs), not fill them with 0
// placeholders. readonly ctor params feed the state-continuation formula and the
// OP_CODESEPARATOR / OP_PUSH_TX offset, so zeros there make restored stateful
// spends unspendable.
test "fromUtxo recovers real constructor args from the deployed script (#119)" {
    const allocator = std.testing.allocator;
    // Stateful artifact: readonly ctor param `owner` (int) baked at byte 0 via a
    // constructor slot; mutable state field `count`.
    const json =
        \\{"contractName":"Vault","version":"1","compilerVersion":"1.0","script":"0087","asm":"OP_0 OP_EQUAL",
        \\"abi":{"constructor":{"params":[{"name":"owner","type":"int"}]},"methods":[{"name":"spend","params":[],"isPublic":true}]},
        \\"stateFields":[{"name":"count","type":"int","index":0}],
        \\"constructorSlots":[{"paramIndex":0,"byteOffset":0}],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    // Deployed script: OP_5 (owner=5, baked at byte 0), OP_EQUAL, then an
    // OP_RETURN state section.
    //
    // The state section is the NUM2BIN-8 word for count=1. It used to be the
    // two bytes "0101", which is not a state section any contract declaring one
    // `int` field can produce — an `int` is 8 raw bytes. The old decoder read it
    // as int(0), advanced the nominal 8 bytes anyway and returned; this test
    // only asserted the constructor args, so it passed on a blob the contract
    // could never have written. C2's fail-closed decoder rejects it, correctly.
    const script = "5587" ++ "6a" ++ "0100000000000000";
    const utxo = types.UTXO{ .txid = "bb" ** 32, .output_index = 0, .satoshis = 1000, .script = script };

    var contract = try RunarContract.fromUtxo(allocator, &artifact, utxo);
    defer contract.deinit();

    // Pre-#119 this was int64(0); after the fix it is the real baked value 5.
    try std.testing.expectEqual(@as(usize, 1), contract.constructor_args.len);
    try std.testing.expectEqual(@as(i64, 5), contract.constructor_args[0].int);
}

// ---------------------------------------------------------------------------
// Item 8 — ScriptSizeExceededError at SDK entry points
// ---------------------------------------------------------------------------

test "Item 8 — MockProvider.getUtxos rejects oversized script" {
    const allocator = std.testing.allocator;

    // Build a hex-encoded script that exceeds MAX_SCRIPT_BYTES.
    const limit = errors_mod.MAX_SCRIPT_BYTES;
    const hex_len = (limit + 1) * 2;
    const oversized = try allocator.alloc(u8, hex_len);
    defer allocator.free(oversized);
    @memset(oversized, '5');
    var i: usize = 1;
    while (i < oversized.len) : (i += 2) oversized[i] = '1';

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();

    const utxo = types.UTXO{
        .txid = "aa" ** 32,
        .output_index = 0,
        .satoshis = 1000,
        .script = oversized,
    };
    try prov.addUtxo("addr", utxo);

    const provider = prov.provider();
    const result = provider.getUtxos(allocator, "addr");
    try std.testing.expectError(provider_mod.ProviderError.ScriptSizeExceeded, result);

    const rec = errors_mod.last_error.?;
    try std.testing.expectEqual(@as(usize, limit), rec.limit);
    try std.testing.expectEqual(@as(usize, limit + 1), rec.actual);
    try std.testing.expect(std.mem.indexOf(u8, rec.contextSlice(), "MockProvider.getUtxos") != null);
}

test "Item 8 — at-limit script passes MockProvider guard" {
    const allocator = std.testing.allocator;

    const limit = errors_mod.MAX_SCRIPT_BYTES;
    const hex_len = limit * 2;
    const at_limit = try allocator.alloc(u8, hex_len);
    defer allocator.free(at_limit);
    @memset(at_limit, '5');
    var j: usize = 1;
    while (j < at_limit.len) : (j += 2) at_limit[j] = '1';

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    try prov.addUtxo("addr", types.UTXO{
        .txid = "bb" ** 32,
        .output_index = 0,
        .satoshis = 1000,
        .script = at_limit,
    });

    const provider = prov.provider();
    const utxos = try provider.getUtxos(allocator, "addr");
    defer {
        for (utxos) |*u| u.deinit(allocator);
        allocator.free(utxos);
    }
    try std.testing.expectEqual(@as(usize, 1), utxos.len);
    try std.testing.expectEqual(hex_len, utxos[0].script.len);
}

test "Item 8 — RunarContract.deploy rejects oversized locking script" {
    const allocator = std.testing.allocator;

    // Stateless artifact whose `script` already exceeds MAX_SCRIPT_BYTES.
    // Build it as JSON so we go through the real loader.
    const limit = errors_mod.MAX_SCRIPT_BYTES;
    const script_hex_len = (limit + 1) * 2;
    var script_hex = try allocator.alloc(u8, script_hex_len);
    defer allocator.free(script_hex);
    @memset(script_hex, '5');
    var k: usize = 1;
    while (k < script_hex.len) : (k += 2) script_hex[k] = '1';

    const json_template =
        \\{"contractName":"OversizedContract","version":"1","compilerVersion":"1.0","script":"
    ;
    const json_tail =
        \\","asm":"","abi":{"constructor":{"params":[]},"methods":[]},"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    const json = try std.mem.concat(allocator, u8, &[_][]const u8{ json_template, script_hex, json_tail });
    defer allocator.free(json);

    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &.{});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    try prov.addUtxo("00" ** 20, types.UTXO{
        .txid = "aa" ** 32,
        .output_index = 0,
        .satoshis = 100_000,
        .script = "76a914" ++ "00" ** 20 ++ "88ac",
    });

    var mock_signer = signer_mod.MockSigner.init(null, null);
    const signer = mock_signer.signer();
    const provider = prov.provider();

    const result = contract.deploy(provider, signer, .{ .satoshis = 1000, .change_address = null });
    try std.testing.expectError(error.ScriptSizeExceeded, result);

    const rec = errors_mod.last_error.?;
    try std.testing.expectEqual(@as(usize, limit), rec.limit);
    try std.testing.expectEqual(@as(usize, limit + 1), rec.actual);
    try std.testing.expect(std.mem.indexOf(u8, rec.contextSlice(), "OversizedContract.deploy") != null);

    // No broadcast should have happened.
    try std.testing.expectEqual(@as(usize, 0), prov.getBroadcastedTxs().len);
}

// Issue #134: P2PKH funding inputs must be signed by DeployOptions.funding_signer
// (CallOptions.funding_signer for calls) when set — the funding coins may be
// owned by a different key than the connected method/deploy signer. Defaults to
// the connected signer (zero behaviour change).
test "deploy signs funding inputs with fundingSigner when set (#134)" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"Trivial","version":"1","compilerVersion":"1.0","script":"51","asm":"OP_1",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var signer_a = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");
    var signer_b = try signer_mod.LocalSigner.fromHex("0000000000000000000000000000000000000000000000000000000000000003");

    const addr_a = try signer_a.signer().getAddress(allocator);
    defer allocator.free(addr_a);
    const pub_a = try signer_a.signer().getPublicKey(allocator);
    defer allocator.free(pub_a);
    const pub_b = try signer_b.signer().getPublicKey(allocator);
    defer allocator.free(pub_b);
    try std.testing.expect(!std.mem.eql(u8, pub_a, pub_b));

    // WITH fundingSigner = B: the funding input pushes B's pubkey, not A's.
    // (The change output is a P2PKH to A's hash160 — the full pubkey A only
    // appears in the tx if A signs an input.)
    {
        var contract = try RunarContract.init(allocator, &artifact, &.{});
        defer contract.deinit();
        var prov = provider_mod.MockProvider.init(allocator, "testnet");
        defer prov.deinit();
        try prov.addUtxo(addr_a, .{ .txid = "aa" ** 32, .output_index = 0, .satoshis = 100_000, .script = "76a914" ++ "00" ** 20 ++ "88ac" });
        const txid = try contract.deploy(prov.provider(), signer_a.signer(), .{ .satoshis = 1000, .funding_signer = signer_b.signer() });
        allocator.free(txid);
        const txs = prov.getBroadcastedTxs();
        try std.testing.expectEqual(@as(usize, 1), txs.len);
        try std.testing.expect(std.mem.indexOf(u8, txs[0], pub_b) != null);
        try std.testing.expect(std.mem.indexOf(u8, txs[0], pub_a) == null);
    }

    // WITHOUT fundingSigner: the funding input pushes A's pubkey (default).
    {
        var contract = try RunarContract.init(allocator, &artifact, &.{});
        defer contract.deinit();
        var prov = provider_mod.MockProvider.init(allocator, "testnet");
        defer prov.deinit();
        try prov.addUtxo(addr_a, .{ .txid = "aa" ** 32, .output_index = 0, .satoshis = 100_000, .script = "76a914" ++ "00" ** 20 ++ "88ac" });
        const txid = try contract.deploy(prov.provider(), signer_a.signer(), .{ .satoshis = 1000 });
        allocator.free(txid);
        const txs = prov.getBroadcastedTxs();
        try std.testing.expect(std.mem.indexOf(u8, txs[0], pub_a) != null);
        try std.testing.expect(std.mem.indexOf(u8, txs[0], pub_b) == null);
    }
}

// ===========================================================================
// R-6 — SDK consumer support for intent-intrinsic auto-injected witness params
// (`_prevOutScript_<i>`, `_serialisedOutputs`).
// ===========================================================================

fn makeIntentWitnessArtifact(
    allocator: std.mem.Allocator,
    prev_out_inputs: []const usize,
    serialised: bool,
) !types.RunarArtifact {
    // Build the params JSON list dynamically based on the input args.
    var params_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer params_buf.deinit(allocator);
    try params_buf.appendSlice(allocator,
        \\{"name":"amount","type":"int"},{"name":"_changePKH","type":"Ripemd160"},{"name":"_changeAmount","type":"int"},{"name":"_newAmount","type":"int"},{"name":"txPreimage","type":"SigHashPreimage"}
    );
    for (prev_out_inputs) |idx| {
        var n_buf: [128]u8 = undefined;
        const n_str = try std.fmt.bufPrint(&n_buf, ",{{\"name\":\"_prevOutScript_{d}\",\"type\":\"ByteString\"}}", .{idx});
        try params_buf.appendSlice(allocator, n_str);
    }
    if (serialised) {
        try params_buf.appendSlice(allocator,
            \\,{"name":"_serialisedOutputs","type":"ByteString"}
        );
    }
    const params_json = params_buf.items;

    const head =
        \\{"contractName":"IntentWitnessTest","version":"1","compilerVersion":"1.0","script":"005100","asm":"",
        \\"abi":{"constructor":{"params":[{"name":"count","type":"int"}]},"methods":[{"name":"move","params":[
    ;
    const tail =
        \\],"isPublic":true}]},
        \\"stateFields":[{"name":"count","type":"int","index":0}],
        \\"constructorSlots":[{"paramIndex":0,"byteOffset":0}],
        \\"codeSeparatorIndex":2,"buildTimestamp":"2024-01-01"}
    ;
    const json = try std.mem.concat(allocator, u8, &[_][]const u8{ head, params_json, tail });
    defer allocator.free(json);
    return types.RunarArtifact.fromJson(allocator, json);
}

test "R-6 — filter excludes auto-injected intent witness params from arg count" {
    const allocator = std.testing.allocator;
    var artifact = try makeIntentWitnessArtifact(allocator, &[_]usize{ 0, 1 }, true);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 0 }});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");

    try contract.setCurrentUtxo(.{
        .txid = "cd" ** 32,
        .output_index = 0,
        .satoshis = 1_000,
        .script = "005100",
    });

    try contract.setPrevOutScript(0, "aa");
    try contract.setPrevOutScript(1, "bb");
    try contract.setSerialisedOutputs("cc");

    // 1 user arg only — without the filter we'd hit ArgCountMismatch.
    const args = [_]types.StateValue{.{ .int = 123 }};
    const new_state = [_]types.StateValue{.{ .int = 1 }};
    const opts = types.CallOptions{ .new_state = &new_state };
    var prepared = try contract.prepareCall("move", &args, prov.provider(), signer.signer(), opts);
    defer prepared.deinit(allocator);

    // intent_witness_hex should be non-empty (3 pushes captured).
    try std.testing.expect(prepared.intent_witness_hex.len > 0);
}

test "R-6 — filter still rejects real arg count mismatches" {
    const allocator = std.testing.allocator;
    var artifact = try makeIntentWitnessArtifact(allocator, &[_]usize{0}, true);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 0 }});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");

    try contract.setCurrentUtxo(.{
        .txid = "cd" ** 32, .output_index = 0, .satoshis = 1_000, .script = "005100",
    });

    // 2 args when only `amount` is user-facing
    const args = [_]types.StateValue{ .{ .int = 1 }, .{ .int = 2 } };
    const result = contract.prepareCall("move", &args, prov.provider(), signer.signer(), null);
    try std.testing.expectError(error.ArgCountMismatch, result);
}

test "R-6 — missing `_prevOutScript_<i>` raises WitnessValueMissing" {
    const allocator = std.testing.allocator;
    var artifact = try makeIntentWitnessArtifact(allocator, &[_]usize{0}, false);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 0 }});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");

    try contract.setCurrentUtxo(.{
        .txid = "cd" ** 32, .output_index = 0, .satoshis = 1_000, .script = "005100",
    });

    const args = [_]types.StateValue{.{ .int = 1 }};
    const new_state = [_]types.StateValue{.{ .int = 1 }};
    const opts = types.CallOptions{ .new_state = &new_state };
    const result = contract.prepareCall("move", &args, prov.provider(), signer.signer(), opts);
    try std.testing.expectError(error.WitnessValueMissing, result);

    const rec = errors_mod.last_witness_error.?;
    try std.testing.expectEqualStrings("_prevOutScript_0", rec.paramName());
    try std.testing.expectEqualStrings("move", rec.methodName());
    try std.testing.expectEqualStrings("IntentWitnessTest", rec.contractName());
}

test "R-6 — missing `_serialisedOutputs` raises WitnessValueMissing" {
    const allocator = std.testing.allocator;
    var artifact = try makeIntentWitnessArtifact(allocator, &[_]usize{}, true);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 0 }});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");

    try contract.setCurrentUtxo(.{
        .txid = "cd" ** 32, .output_index = 0, .satoshis = 1_000, .script = "005100",
    });

    const args = [_]types.StateValue{.{ .int = 1 }};
    const new_state = [_]types.StateValue{.{ .int = 1 }};
    const opts = types.CallOptions{ .new_state = &new_state };
    const result = contract.prepareCall("move", &args, prov.provider(), signer.signer(), opts);
    try std.testing.expectError(error.WitnessValueMissing, result);

    const rec = errors_mod.last_witness_error.?;
    try std.testing.expectEqualStrings("_serialisedOutputs", rec.paramName());
}

test "R-6 — appends multiple `_prevOutScript_*` pushes in ABI order" {
    const allocator = std.testing.allocator;
    var artifact = try makeIntentWitnessArtifact(allocator, &[_]usize{ 0, 1 }, false);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 0 }});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");

    try contract.setCurrentUtxo(.{
        .txid = "cd" ** 32, .output_index = 0, .satoshis = 1_000, .script = "005100",
    });

    try contract.setPrevOutScript(0, "deadbeef");
    try contract.setPrevOutScript(1, "cafebabe");

    const args = [_]types.StateValue{.{ .int = 1 }};
    const new_state = [_]types.StateValue{.{ .int = 1 }};
    const opts = types.CallOptions{ .new_state = &new_state };
    var prepared = try contract.prepareCall("move", &args, prov.provider(), signer.signer(), opts);
    defer prepared.deinit(allocator);

    // PUSHDATA for 4 bytes = "04" + data
    const push0 = "04deadbeef";
    const push1 = "04cafebabe";
    const idx0 = std.mem.indexOf(u8, prepared.intent_witness_hex, push0).?;
    const idx1 = std.mem.indexOf(u8, prepared.intent_witness_hex, push1).?;
    try std.testing.expect(idx1 > idx0);
}

test "R-6 — appends `_prevOutScript_*` then `_serialisedOutputs` in ABI order" {
    const allocator = std.testing.allocator;
    var artifact = try makeIntentWitnessArtifact(allocator, &[_]usize{0}, true);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 0 }});
    defer contract.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");

    try contract.setCurrentUtxo(.{
        .txid = "cd" ** 32, .output_index = 0, .satoshis = 1_000, .script = "005100",
    });

    try contract.setPrevOutScript(0, "11223344");
    try contract.setSerialisedOutputs("55667788");

    const args = [_]types.StateValue{.{ .int = 1 }};
    const new_state = [_]types.StateValue{.{ .int = 1 }};
    const opts = types.CallOptions{ .new_state = &new_state };
    var prepared = try contract.prepareCall("move", &args, prov.provider(), signer.signer(), opts);
    defer prepared.deinit(allocator);

    const idx_prev = std.mem.indexOf(u8, prepared.intent_witness_hex, "0411223344").?;
    const idx_serial = std.mem.indexOf(u8, prepared.intent_witness_hex, "0455667788").?;
    try std.testing.expect(idx_serial > idx_prev);
}

test "R-6 — setPrevOutScript rejects invalid hex" {
    const allocator = std.testing.allocator;
    var artifact = try makeIntentWitnessArtifact(allocator, &[_]usize{0}, false);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 0 }});
    defer contract.deinit();

    try std.testing.expectError(error.InvalidWitnessHex, contract.setPrevOutScript(0, "not-hex!"));
    try std.testing.expectError(error.InvalidWitnessHex, contract.setSerialisedOutputs("abc"));
}

// ---------------------------------------------------------------------------
// N-223 — out-of-range constructorSlots paramIndex
// ---------------------------------------------------------------------------
//
// The constructor only checks constructor_args.len == abi.constructor.params.len
// (see `init`) -- it never cross-checks that every constructor slot's
// param_index actually falls within that range. Before this fix,
// buildCodeScript, adjustCodeSepOffset, and resolvedCodeSepSlotValues each
// silently SKIPPED a slot whose param_index was out of range (the OP_0
// placeholder byte stayed unfilled, or the offset shift was simply wrong)
// instead of refusing. This item's brief says "Zig ... crash[es] with a raw
// index error", which does not match this tier: these three functions have
// carried defensive `if (idx >= len) continue`/skip bound checks since this
// file's very first commit, but those checks fail OPEN (silently skip
// instead of refusing) -- the same bug shape as the Java SDK (brief: "Java
// silently skips the slot"). Parity target: TS N-081 / N-223
// (packages/runar-sdk/src/__tests__/constructor-slots.test.ts).

test "N-223 buildCodeScript refuses an out-of-range constructorSlots paramIndex" {
    const allocator = std.testing.allocator;
    // Exactly 1 constructor arg below (matching the 1 ABI param), but the
    // slot references paramIndex 1 -- out of range.
    var artifact = try types.RunarArtifact.fromJson(allocator,
        "{\"contractName\":\"Test\",\"version\":\"runar-v1.0.0-rc.1\",\"compilerVersion\":\"1.0.0-rc.1\"," ++
        "\"script\":\"009c69\",\"asm\":\"\"," ++
        "\"abi\":{\"constructor\":{\"params\":[{\"name\":\"threshold\",\"type\":\"bigint\"}]}," ++
        "\"methods\":[{\"name\":\"check\",\"params\":[],\"isPublic\":true}]}," ++
        "\"stateFields\":[]," ++
        "\"constructorSlots\":[{\"paramIndex\":1,\"byteOffset\":0}]," ++
        "\"buildTimestamp\":\"2024-01-01\"}");
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 1000 }});
    defer contract.deinit();

    try std.testing.expectError(error.ConstructorArgParamIndexOutOfRange, contract.getLockingScript());
}

test "N-223 adjustCodeSepOffset refuses an out-of-range paramIndex, reached WITHOUT buildCodeScript" {
    // getCodeSepIndex falls straight to adjustCodeSepOffset when code_script
    // is null -- this never calls buildCodeScript at all, proving the gap
    // the primary-site fix alone does not cover.
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator,
        "{\"contractName\":\"CodeSep\",\"version\":\"runar-v1.0.0-rc.1\",\"compilerVersion\":\"1.0.0-rc.1\"," ++
        "\"script\":\"00ab9c69\",\"asm\":\"\"," ++
        "\"abi\":{\"constructor\":{\"params\":[{\"name\":\"threshold\",\"type\":\"bigint\"}]}," ++
        "\"methods\":[{\"name\":\"check\",\"params\":[],\"isPublic\":true}]}," ++
        "\"stateFields\":[]," ++
        "\"constructorSlots\":[{\"paramIndex\":1,\"byteOffset\":0}]," ++
        "\"codeSeparatorIndex\":2,\"codeSeparatorIndices\":[2]," ++
        "\"buildTimestamp\":\"2024-01-01\"}");
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 1000 }});
    defer contract.deinit();

    try std.testing.expectError(error.ConstructorArgParamIndexOutOfRange, contract.getCodeSepIndex(0));
}

// ---------------------------------------------------------------------------
// N-163 (design B, refuse on use): a `StateValue.big_int` outside i64 used to
// reach the ANF interpreter as 0 (`stateValueToAnf`: `parseInt(i64) catch 0`),
// so arithmetic on it derived a post-state the script never produces.
//
// Proves: (i) a stateful method that carries wide values without computing
// with them (the BlackjackBet shape: a wide `RabinPubKey` property and a wide
// `RabinSig` param fed only to `verifyRabinSig`) still derives its post-state;
// a wide value assigned to state comes back as the same `big_int`; (ii) a
// wide value used as a `bin_op` / `unary_op` operand, a builtin argument, or
// an output's satoshis is refused, never computed as 0.
// Does NOT prove: arithmetic on wide values (refused; the on-chain script
// computes it), wide literals inside the ANF itself, or the compiled script.
// ---------------------------------------------------------------------------

const N163 = struct {
    // 2^300 + 12345 and 2^260 + 12345: both outside i64.
    const wide_key = "2037035976334486086268445688409378161051468393665936250636140449354381299763336706183409721";
    const wide_sig = "1852673427797059126777135760139006525652319754650249024631321344126610074251321";

    fn run(a: std.mem.Allocator, params: []const anf_interp.ANFParam, body: []anf_interp.ANFBinding) !std.StringHashMap(anf_interp.ANFValue) {
        var props = [_]anf_interp.ANFProperty{
            .{ .name = "oraclePubKey", .type_name = "RabinPubKey", .readonly = true },
            .{ .name = "count", .type_name = "bigint", .readonly = false },
            .{ .name = "lastSig", .type_name = "RabinSig", .readonly = false },
        };
        var methods = [_]anf_interp.ANFMethod{
            .{ .name = "settle", .params = @constCast(params), .body = body, .is_public = true },
        };
        const anf = anf_interp.ANFProgram{ .contract_name = "WideProbe", .properties = &props, .methods = &methods };
        var cs = std.StringHashMap(anf_interp.ANFValue).init(a);
        defer cs.deinit();
        try cs.put("count", stateValueToAnf(.{ .int = 0 }));
        try cs.put("lastSig", stateValueToAnf(.{ .int = 0 }));
        var args = std.StringHashMap(anf_interp.ANFValue).init(a);
        defer args.deinit();
        try args.put("rabinSig", stateValueToAnf(.{ .big_int = wide_sig }));
        try args.put("w", stateValueToAnf(.{ .big_int = wide_sig }));
        try args.put("padding", stateValueToAnf(.{ .bytes = "00" }));
        const ctor = [_]anf_interp.ANFValue{
            stateValueToAnf(.{ .big_int = wide_key }),
            stateValueToAnf(.{ .int = 0 }),
            stateValueToAnf(.{ .int = 0 }),
        };
        return anf_interp.computeNewState(a, &anf, "settle", cs, args, &ctor);
    }

    const blackjack_params = [_]anf_interp.ANFParam{
        .{ .name = "rabinSig", .type_name = "RabinSig" },
        .{ .name = "padding", .type_name = "ByteString" },
    };

    fn blackjackBody(comptime extra: []const anf_interp.ANFBinding) [10 + extra.len]anf_interp.ANFBinding {
        const v = anf_interp.ANFValue;
        return [_]anf_interp.ANFBinding{
            .{ .name = "m", .value = .{ .load_const = .{ .value = v{ .bytes = "aa" } } } },
            .{ .name = "s", .value = .{ .load_param = .{ .name = "rabinSig" } } },
            .{ .name = "p", .value = .{ .load_param = .{ .name = "padding" } } },
            .{ .name = "k", .value = .{ .load_prop = .{ .name = "oraclePubKey" } } },
            .{ .name = "v", .value = .{ .call = .{ .func = "verifyRabinSig", .args = &.{ "m", "s", "p", "k" } } } },
            .{ .name = "a", .value = .{ .assert_node = .{ .value = "v" } } },
            .{ .name = "c", .value = .{ .load_prop = .{ .name = "count" } } },
            .{ .name = "one", .value = .{ .load_const = .{ .value = v{ .int = 1 } } } },
            .{ .name = "n", .value = .{ .bin_op = .{ .op = "+", .left = "c", .right = "one" } } },
            .{ .name = "u", .value = .{ .update_prop = .{ .name = "count", .value = "n" } } },
        } ++ extra[0..extra.len].*;
    }

    /// `w` (wide param) and `c` (count) loaded, then `tail`.
    fn refused(a: std.mem.Allocator, what: []const u8, comptime tail: []const anf_interp.ANFBinding) !void {
        const w_params = [_]anf_interp.ANFParam{.{ .name = "w", .type_name = "bigint" }};
        var body = [_]anf_interp.ANFBinding{
            .{ .name = "w0", .value = .{ .load_param = .{ .name = "w" } } },
            .{ .name = "c", .value = .{ .load_prop = .{ .name = "count" } } },
        } ++ tail[0..tail.len].*;
        if (run(a, &w_params, &body)) |ns_const| {
            var ns = ns_const;
            defer ns.deinit();
            std.debug.print("N-163: {s} with a wide operand returned count={any}\n", .{ what, ns.get("count") });
            return error.TestUnexpectedResult;
        } else |_| {}
    }
};

test "N-163: wide values carried without arithmetic still derive state (BlackjackBet shape)" {
    const a = std.testing.allocator;
    var body = N163.blackjackBody(&.{});
    var ns = try N163.run(a, &N163.blackjack_params, &body);
    defer ns.deinit();
    try std.testing.expectEqual(@as(i64, 1), ns.get("count").?.int);
}

test "N-163: a wide value assigned to state round-trips exactly" {
    const a = std.testing.allocator;
    var body = N163.blackjackBody(&.{
        .{ .name = "u2", .value = .{ .update_prop = .{ .name = "lastSig", .value = "s" } } },
    });
    var ns = try N163.run(a, &N163.blackjack_params, &body);
    defer ns.deinit();
    const sv = try anfToStateValue(a, ns.get("lastSig").?);
    defer sv.deinit(a);
    switch (sv) {
        .big_int => |s| try std.testing.expectEqualStrings(N163.wide_sig, s),
        else => {
            std.debug.print("N-163: wide value reached state as {any}\n", .{sv});
            return error.TestUnexpectedResult;
        },
    }
}

test "N-163: a wide value used in arithmetic is refused, never computed as 0" {
    const a = std.testing.allocator;
    try N163.refused(a, "bin_op +", &.{
        .{ .name = "n", .value = .{ .bin_op = .{ .op = "+", .left = "c", .right = "w0" } } },
        .{ .name = "u", .value = .{ .update_prop = .{ .name = "count", .value = "n" } } },
    });
    try N163.refused(a, "bin_op > (readonly prop)", &.{
        .{ .name = "k", .value = .{ .load_prop = .{ .name = "oraclePubKey" } } },
        .{ .name = "n", .value = .{ .bin_op = .{ .op = ">", .left = "k", .right = "c" } } },
        .{ .name = "u", .value = .{ .update_prop = .{ .name = "count", .value = "n" } } },
    });
    try N163.refused(a, "unary_op -", &.{
        .{ .name = "n", .value = .{ .unary_op = .{ .op = "-", .operand = "w0" } } },
        .{ .name = "u", .value = .{ .update_prop = .{ .name = "count", .value = "n" } } },
    });
    try N163.refused(a, "builtin abs", &.{
        .{ .name = "n", .value = .{ .call = .{ .func = "abs", .args = &.{"w0"} } } },
        .{ .name = "u", .value = .{ .update_prop = .{ .name = "count", .value = "n" } } },
    });
    try N163.refused(a, "add_data_output satoshis", &.{
        .{ .name = "sc", .value = .{ .load_const = .{ .value = .{ .bytes = "6a" } } } },
        .{ .name = "o", .value = .{ .add_data_output = .{ .satoshis = "w0", .script_bytes = "sc" } } },
    });
}
