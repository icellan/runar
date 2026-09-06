const std = @import("std");
const bsvz = @import("bsvz");

// ---------------------------------------------------------------------------
// ANF Interpreter — compute state transitions from ANF IR
//
// Given a compiled artifact's ANF IR, the current contract state, and
// method arguments, this interpreter walks the ANF bindings and computes
// the new state. It handles `update_prop` and `add_output` nodes to track
// state mutations, surfaces `add_data_output` and `add_raw_output` entries
// in the result envelope, and skips on-chain-only operations like
// `check_preimage`, `deserialize_state`, and `get_state_script`.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ANF IR types (mirrors runar-ir-schema)
// ---------------------------------------------------------------------------

/// ANFProgram is the top-level ANF IR for a compiled contract.
pub const ANFProgram = struct {
    contract_name: []const u8 = "",
    properties: []ANFProperty = &.{},
    methods: []ANFMethod = &.{},
};

/// ANFProperty describes a contract property in ANF IR.
pub const ANFProperty = struct {
    name: []const u8 = "",
    type_name: []const u8 = "",
    readonly: bool = false,
    initial_value: ?ANFValue = null,
};

/// ANFMethod describes a contract method in ANF IR.
pub const ANFMethod = struct {
    name: []const u8 = "",
    params: []ANFParam = &.{},
    body: []ANFBinding = &.{},
    is_public: bool = false,
};

/// ANFParam describes a method parameter in ANF IR.
pub const ANFParam = struct {
    name: []const u8 = "",
    type_name: []const u8 = "",
};

/// ANFBinding represents a single let-binding in the ANF IR.
pub const ANFBinding = struct {
    name: []const u8 = "",
    value: ANFNode = .{ .unknown = {} },
};

/// ANFValue is a dynamically-typed value used in the interpreter environment.
pub const ANFValue = union(enum) {
    int: i64,
    boolean: bool,
    bytes: []const u8, // hex-encoded string
    /// Heterogeneous list of values. Used for `array_literal` ANF bindings
    /// and for arrays passed in via the SDK's `StateValue.array_value` API
    /// — see `stateValueToAnf` in `sdk_contract.zig`. The interpreter does
    /// not free the slice or its element-owned bytes on its own; arenas /
    /// per-call allocators owned by the caller cover the lifetime, matching
    /// how `bytes` storage is managed everywhere else in this file.
    array: []const ANFValue,
    none: void,
};

/// ANFNode represents the different kinds of ANF IR nodes.
pub const ANFNode = union(enum) {
    load_param: struct { name: []const u8 = "" },
    load_prop: struct { name: []const u8 = "" },
    load_const: struct { value: ANFValue = .{ .none = {} } },
    bin_op: struct {
        op: []const u8 = "",
        left: []const u8 = "",
        right: []const u8 = "",
        result_type: []const u8 = "",
    },
    unary_op: struct {
        op: []const u8 = "",
        operand: []const u8 = "",
        result_type: []const u8 = "",
    },
    call: struct {
        func: []const u8 = "",
        args: []const []const u8 = &.{},
    },
    method_call: struct {
        method: []const u8 = "",
        args: []const []const u8 = &.{},
    },
    if_node: struct {
        cond: []const u8 = "",
        then_branch: []ANFBinding = &.{},
        else_branch: []ANFBinding = &.{},
    },
    loop_node: struct {
        count: usize = 0,
        iter_var: []const u8 = "",
        body: []ANFBinding = &.{},
        // Iteration `i` binds `iter_var = start + i*step` (issue #121). Older
        // ANF payloads without start/step describe zero-start counting-up loops.
        start: i64 = 0,
        step: i64 = 1,
    },
    assert_node: struct {
        // Reference to the binding holding the predicate value. Used by
        // strict-mode evaluation to enforce the predicate; lenient mode
        // ignores it (and earlier ANF emitters didn't always populate it,
        // so the strict path also tolerates an empty ref by treating the
        // most recent binding as the predicate via `strict_ctx`).
        value: []const u8 = "",
        // Marker: `true` only on the compiler-emitted
        // `assert(hash256(continuationOutputs) === extractOutputHash(
        // preimage))` (see `compilers/zig/src/passes/anf_lower.zig`).
        // Strict-mode SDK execution skips this assert via the marker
        // instead of structural heuristics that misfire on developer
        // covenant asserts whose IR shape is identical.
        is_auto_injected_state_check: bool = false,
    },
    update_prop: struct {
        name: []const u8 = "",
        value: []const u8 = "",
    },
    add_output: struct {
        // Reference to the binding holding the state continuation's satoshis
        // operand. Recorded in the source-ordered output list (finding G1) so
        // the SDK call path can emit the continuation at the right index and
        // sync the OP_PUSH_TX preimage's new-amount to it.
        satoshis: []const u8 = "",
        state_values: []const []const u8 = &.{},
    },
    // On-chain-only operations — skip in simulation
    check_preimage: struct {},
    deserialize_state: struct {},
    get_state_script: struct {},
    add_raw_output: struct {
        satoshis: []const u8 = "",
        script_bytes: []const u8 = "",
    },
    add_data_output: struct {
        satoshis: []const u8 = "",
        script_bytes: []const u8 = "",
    },
    /// `array_literal` collects the values of `elements` (binding refs in the
    /// current env) into an `ANFValue.array`. Used by `checkMultiSig` and any
    /// future built-in that takes a list of bytes-shaped args.
    array_literal: struct {
        elements: []const []const u8 = &.{},
    },
    unknown: void,
};

pub const InterpreterError = error{
    MethodNotFound,
    OutOfMemory,
};

/// Errors `executeStrict` can return on top of the lenient ones. `AssertionFailure`
/// is raised on the first `assert(predicate)` (or `call(assert, x)`) whose
/// predicate evaluates to a falsy value. Crypto built-ins (`checkSig`,
/// `checkMultiSig`, `checkPreimage`) still mock-return `true` even in strict
/// mode — strict only enforces explicit `assert(...)` predicates. Use this
/// before broadcasting a transaction to surface guard failures off-chain
/// instead of relying on a node rejection.
pub const StrictError = error{
    MethodNotFound,
    OutOfMemory,
    AssertionFailure,
    /// An ANF binding referenced an auto-injected witness param
    /// (`_prevOutScript_<idx>` or `_serialisedOutputs`) but the caller did
    /// not bind it via `MockEnv.setPrevOutScript` / `setSerialisedOutputs`.
    /// Mirrors the TS interpreter's "requires witness bytes" error.
    MissingWitness,
    /// A bigint `& | ^` was applied to operands whose minimal script-number
    /// encodings differ in length, or a `<< >>` used a negative shift count.
    /// On-chain OP_AND/OP_OR/OP_XOR/OP_LSHIFT/OP_RSHIFT abort the script in
    /// exactly these cases; the interpreter surfaces the same failure so
    /// off-chain simulation agrees with the deployed script byte-for-byte.
    ScriptNumberError,
};

/// Context for strict-mode evaluation. Carries the public method name being
/// executed plus the binding name of the most recent ANF binding so a failing
/// assert can be reported with both. `last_binding_name` is mutated as
/// `evalBindings` walks the body so error reports always reference the
/// failing binding.
///
/// When `real_crypto` is non-null, crypto built-ins (`checkSig`,
/// `checkMultiSig`, `checkPreimage`) verify against the supplied 32-byte
/// sighash instead of mock-returning `true`. See `executeOnChainAuthoritative`.
const StrictCtx = struct {
    method_name: []const u8,
    last_binding_name: []const u8 = "<anonymous>",
    real_crypto: ?*const RealCryptoCtx = null,
};

/// Bag of optional contexts threaded through evaluation. Kept as a
/// pointer-bag struct so we don't grow the signature of every helper.
const EvalCtx = struct {
    strict: ?*StrictCtx = null,
    mock_env: ?*const MockEnv = null,
    /// Per-binding raw stack bytes for numeric byte-array-op results
    /// (`& | ^ << >> ~`). Keyed by the producing binding's name; lets a
    /// CHAINED op read the real (possibly NON-minimal) byte length of a prior
    /// op's result instead of re-minimizing its numeric value. A shift/bitwise
    /// result can be non-minimal on-chain (e.g. `2 << 8` leaves a 1-byte
    /// `0x00`, not the empty encoding of 0); feeding it to a length-sensitive
    /// `& | ^`/shift must see that real length to agree with the deployed
    /// script byte-for-byte. `env` stays pure (decoded i64 values) so state
    /// serialization is unaffected. Mirrors the `scriptBytes` side-map in
    /// packages/runar-sdk/src/anf-interpreter.ts. Backed by the interpretation
    /// arena (freed at arena.deinit); a FRESH map is used per private-method
    /// body (see evalMethodCall), matching the TS reference.
    script_bytes: *std.StringHashMap([]const u8),
    /// Source-ordered state-class outputs (state continuation + raw), finding
    /// G1. Appended to in the `add_output` / `add_raw_output` arms and shared
    /// across every recursive walk site (if / loop / private method_call) so a
    /// method that interleaves `this.addOutput(...)` and
    /// `this.addRawOutput(...)` records them in source order — the same order
    /// the compiler folds into the covenant `hashOutputs`. Arena-backed during
    /// interpretation; runMethod dupes the raw scripts into the caller
    /// allocator before returning.
    ordered_outputs: *std.ArrayList(OrderedOutputEntry),
};

/// Real-crypto context for `executeOnChainAuthoritative`. The 32-byte
/// `sighash` is what `checkSig` ECDSA-verifies signatures against and what
/// `checkPreimage` requires `hash256(preimage)` to equal.
pub const RealCryptoCtx = struct {
    sighash: [32]u8,
};

/// Mock environment for intent-covenant intrinsics (BSVM Phase 13).
///
/// Mirrors the TS reference at
/// `packages/runar-testing/src/interpreter/interpreter.ts` — its
/// `_witnessBytes` map plus `_mockPreimage` / `_mockPreimageBytes` shims —
/// for the Zig ANF interpreter.
///
/// ANF lowering desugars `extractPrevOutputScript(idx, ...)` /
/// `requireOutputP2PKH(...)` / `currentBlockHeight()` into ANF chains that
/// load auto-injected method params (`_prevOutScript_<idx>`,
/// `_serialisedOutputs`) and call primitive intrinsics (`hash256`,
/// `substr`, `cat`, `num2bin`, `extractLocktime`, `extractOutputHash`,
/// `bin_op`, `assert`). The Zig interpreter walks that lowered ANF;
/// `MockEnv` lets callers supply the auto-injected witness bytes (via
/// setters) and override the preimage fields the desugar reads.
///
/// Ownership: `setPrevOutScript` / `setSerialisedOutputs` borrow the
/// caller-supplied hex slice — the caller must keep it alive for the
/// duration of any `execute*WithMockEnv` call. `MockEnv` does NOT dupe.
/// Call `deinit` after use to free the witness-name map (the bytes
/// themselves are caller-owned). `output_hash_hex` /
/// `hash_prevouts_hex` / `hash_sequence_hex` are also borrows.
pub const MockEnv = struct {
    /// Witness bytes keyed by the ANF-level synthetic name
    /// (`_prevOutScript_<idx>`, `_serialisedOutputs`). Hex-encoded slices,
    /// matching the rest of the Zig interpreter's `ANFValue.bytes` convention.
    witness_bytes: std.StringHashMap([]const u8),

    /// Preimage scalar fields surfaced by `extractLocktime` /
    /// `extractAmount` / `extractVersion` / `extractSequence`. Defaults
    /// mirror the TS reference: locktime=0, amount=10000, version=1,
    /// sequence=0xfffffffe.
    locktime: i64 = 0,
    amount: i64 = 10000,
    version: i64 = 1,
    sequence: i64 = 0xfffffffe,

    /// Preimage byte fields surfaced by `extractOutputHash` /
    /// `extractHashPrevouts` / `extractHashSequence`. Hex-encoded; null
    /// falls back to the legacy stub ("00" * 32).
    output_hash_hex: ?[]const u8 = null,
    hash_prevouts_hex: ?[]const u8 = null,
    hash_sequence_hex: ?[]const u8 = null,

    /// Caller-supplied allocator used to allocate the witness-name keys
    /// (the bytes themselves are caller-owned). Same allocator must be
    /// used for both `init` and `deinit`.
    name_allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MockEnv {
        return .{
            .witness_bytes = std.StringHashMap([]const u8).init(allocator),
            .name_allocator = allocator,
        };
    }

    pub fn deinit(self: *MockEnv) void {
        // Free the duped key strings allocated by setPrevOutScript.
        // setSerialisedOutputs uses a static literal so no free is needed.
        var it = self.witness_bytes.iterator();
        while (it.next()) |entry| {
            const k = entry.key_ptr.*;
            if (!std.mem.eql(u8, k, "_serialisedOutputs")) {
                self.name_allocator.free(k);
            }
        }
        self.witness_bytes.deinit();
    }

    /// Bind witness bytes for `extractPrevOutputScript(idx, ...)`. Mirrors
    /// `TestContract.setPrevOutScript(idx, bytes)` from the TS reference.
    /// `bytes_hex` is a hex-encoded slice; ownership stays with the caller.
    pub fn setPrevOutScript(self: *MockEnv, input_index: i64, bytes_hex: []const u8) !void {
        // Build the synthetic param name "_prevOutScript_<idx>".
        var buf: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&buf, "_prevOutScript_{d}", .{input_index});
        const owned = try self.name_allocator.dupe(u8, name);
        // If a previous binding for the same idx existed, free its key first.
        if (self.witness_bytes.fetchRemove(owned)) |old| {
            self.name_allocator.free(old.key);
        }
        try self.witness_bytes.put(owned, bytes_hex);
    }

    /// Bind serialised-outputs witness bytes for `requireOutputP2PKH(...)`.
    /// Mirrors `TestContract.setSerialisedOutputs(bytes)`. `bytes_hex` is
    /// caller-owned.
    pub fn setSerialisedOutputs(self: *MockEnv, bytes_hex: []const u8) !void {
        try self.witness_bytes.put("_serialisedOutputs", bytes_hex);
    }

    /// Override preimage byte fields. Mirrors
    /// `TestContract.setMockPreimageBytes({ outputHash: ... })`.
    pub fn setMockPreimageBytes(self: *MockEnv, output_hash_hex: ?[]const u8) void {
        self.output_hash_hex = output_hash_hex;
    }

    /// Override preimage scalar fields. Mirrors
    /// `TestContract.setMockPreimage({ locktime, amount, version, sequence })`.
    pub fn setMockPreimage(self: *MockEnv, opts: struct {
        locktime: ?i64 = null,
        amount: ?i64 = null,
        version: ?i64 = null,
        sequence: ?i64 = null,
    }) void {
        if (opts.locktime) |v| self.locktime = v;
        if (opts.amount) |v| self.amount = v;
        if (opts.version) |v| self.version = v;
        if (opts.sequence) |v| self.sequence = v;
    }
};

/// Sentinel value for "no result" / undefined.
const anf_none: ANFValue = .{ .none = {} };

/// A data output resolved from `this.addDataOutput(...)` in the method body.
/// Caller owns the `script` slice (allocated from the caller's allocator).
pub const DataOutputEntry = struct {
    satoshis: i64,
    script: []u8,
};

/// Discriminates a source-ordered state-class output (finding G1).
pub const OrderedOutputKind = enum { state, raw };

/// A single state-class output in the exact SOURCE order the method body emits
/// it, capturing the interleaving of `this.addOutput(...)` (state continuation)
/// and `this.addRawOutput(...)` (caller-supplied script). The compiler folds
/// these into the continuation `hashOutputs` in this same order (see
/// `compilers/zig/src/passes/anf_lower.zig` — `add_output` and `add_raw_output`
/// share one output ref list), so a transaction builder MUST emit them in this
/// order or the on-chain state-check OP_VERIFY rejects (finding G1). `script`
/// is populated for `.raw` entries only (caller-owned dupe); `.state` entries
/// take the freshly computed continuation locking script from the caller and
/// carry an empty `script`. Data outputs (`add_data_output`) are NOT included
/// here — they are always emitted after every state-class output in their own
/// `data_outputs` list.
pub const OrderedOutputEntry = struct {
    kind: OrderedOutputKind,
    satoshis: i64,
    script: []const u8 = "",
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Result of `computeNewStateAndDataOutputs`: the new state map, a slice
/// of data outputs (from `this.addDataOutput(...)`), and a slice of raw
/// outputs (from `this.addRawOutput(...)`). Caller owns all three.
///
/// Raw outputs carry caller-supplied locking-script bytes that the
/// simulator does not introspect — they are surfaced verbatim so an
/// off-chain transaction builder can splice them in at the correct index.
/// Entries appear in declaration order, after the state output and after
/// `data_outputs`. Each entry's `script` is duped into the caller
/// allocator (same lifetime semantics as `data_outputs`).
pub const NewStateResult = struct {
    state: std.StringHashMap(ANFValue),
    data_outputs: []DataOutputEntry,
    raw_outputs: []DataOutputEntry,
    /// State-class outputs (state continuation + raw) in SOURCE order
    /// (finding G1). Each `.raw` entry's `script` is duped into the caller
    /// allocator (same lifetime as `data_outputs`); `.state` entries carry an
    /// empty `script`. Caller owns the slice.
    outputs: []OrderedOutputEntry,
};

/// Compute the new state after executing a contract method.
///
/// Returns a map from property name to new value. Caller owns the map.
pub fn computeNewState(
    allocator: std.mem.Allocator,
    anf: *const ANFProgram,
    method_name: []const u8,
    current_state: std.StringHashMap(ANFValue),
    args: std.StringHashMap(ANFValue),
    constructor_args: []const ANFValue,
) !std.StringHashMap(ANFValue) {
    const result = try computeNewStateAndDataOutputs(
        allocator, anf, method_name, current_state, args, constructor_args,
    );
    // Discard data + raw + ordered outputs — free their script allocations.
    for (result.data_outputs) |d| allocator.free(d.script);
    allocator.free(result.data_outputs);
    for (result.raw_outputs) |d| allocator.free(d.script);
    allocator.free(result.raw_outputs);
    for (result.outputs) |o| if (o.kind == .raw and o.script.len > 0) allocator.free(@constCast(o.script));
    allocator.free(result.outputs);
    return result.state;
}

/// Strict-mode entry point with a `MockEnv` for intent-covenant intrinsics
/// (BSVM Phase 13). Mirrors `executeStrict` but additionally consults
/// `mock_env` for auto-injected witness params (`_prevOutScript_<idx>`,
/// `_serialisedOutputs`) and overridden preimage fields (extractLocktime,
/// extractOutputHash, etc.). If `_prevOutScript_<idx>` is referenced in the
/// ANF body and `mock_env` has no matching binding, evaluation returns
/// `error.MissingWitness` so the caller can surface a clear "call
/// setPrevOutScript(...) first" diagnostic.
pub fn executeStrictWithMockEnv(
    allocator: std.mem.Allocator,
    anf: *const ANFProgram,
    method_name: []const u8,
    current_state: std.StringHashMap(ANFValue),
    args: std.StringHashMap(ANFValue),
    constructor_args: []const ANFValue,
    mock_env: *const MockEnv,
) StrictError!NewStateResult {
    return runMethod(allocator, anf, method_name, current_state, args, constructor_args, true, null, null, mock_env);
}

/// Lenient counterpart to `executeStrictWithMockEnv`: same MockEnv plumbing
/// but skips assert enforcement (matches `computeNewState` semantics).
pub fn computeNewStateWithMockEnv(
    allocator: std.mem.Allocator,
    anf: *const ANFProgram,
    method_name: []const u8,
    current_state: std.StringHashMap(ANFValue),
    args: std.StringHashMap(ANFValue),
    constructor_args: []const ANFValue,
    mock_env: *const MockEnv,
) StrictError!NewStateResult {
    return runMethod(allocator, anf, method_name, current_state, args, constructor_args, false, null, null, mock_env);
}

/// On `error.AssertionFailure`, callers that supply
/// `executeStrictWithFailureInfo`'s `out_info` parameter can read the
/// failing method + binding name. Both fields point into the ANF program's
/// own storage (which the caller owns), so they remain valid as long as
/// the ANF stays alive.
pub const AssertionFailureInfo = struct {
    method_name: []const u8 = "",
    binding_name: []const u8 = "",
};

/// Strict-mode counterpart to `computeNewStateAndDataOutputs`: walks the same
/// ANF body but returns `error.AssertionFailure` on the first `assert(...)`
/// whose predicate evaluates to a falsy value. Use this before broadcasting a
/// transaction to surface guard failures off-chain instead of relying on a
/// node rejection. Crypto built-ins (`checkSig`, `checkMultiSig`,
/// `checkPreimage`) still mock-return `true` — strict mode only enforces
/// explicit `assert(...)` predicates. State + data-output ownership matches
/// the lenient entry point: caller owns both the state map and the returned
/// data-output slice (including each entry's `script`).
pub fn executeStrict(
    allocator: std.mem.Allocator,
    anf: *const ANFProgram,
    method_name: []const u8,
    current_state: std.StringHashMap(ANFValue),
    args: std.StringHashMap(ANFValue),
    constructor_args: []const ANFValue,
) StrictError!NewStateResult {
    return runMethod(allocator, anf, method_name, current_state, args, constructor_args, true, null, null, null);
}

/// Like `executeStrict` but additionally populates `out_info.method_name`
/// and `out_info.binding_name` with the failing context when
/// `error.AssertionFailure` is returned. Use this from drivers that need to
/// emit a structured assertion-failure envelope on the wire (`{error,
/// methodName, bindingName}`) for cross-tier parity. On success or any other
/// error variant `out_info` is left untouched.
pub fn executeStrictWithFailureInfo(
    allocator: std.mem.Allocator,
    anf: *const ANFProgram,
    method_name: []const u8,
    current_state: std.StringHashMap(ANFValue),
    args: std.StringHashMap(ANFValue),
    constructor_args: []const ANFValue,
    out_info: *AssertionFailureInfo,
) StrictError!NewStateResult {
    return runMethod(allocator, anf, method_name, current_state, args, constructor_args, true, null, out_info, null);
}

/// On-chain authoritative simulation: strict assert enforcement PLUS real
/// ECDSA verification (`checkSig`, `checkMultiSig`) and real SHA-256
/// preimage check (`checkPreimage`) against the supplied 32-byte BIP-143
/// sighash in `ctx`. The signature shape requires `ctx`, so callers cannot
/// invoke this entry point accidentally without supplying the cryptographic
/// inputs that verification needs.
///
/// `checkSig(sig, pk)` parses `pk` as SEC1 secp256k1 (compressed or
/// uncompressed), parses `sig` as DER (with optional trailing sighash byte
/// stripped), and calls `verifyDigest256RelaxedSec1(pk, ctx.sighash, sig)`.
/// Failure trips the enclosing `assert(...)` and returns
/// `error.AssertionFailure`.
///
/// `checkMultiSig(sigs, pks)` iterates signatures left-to-right and consumes
/// pubkeys greedily, mirroring Bitcoin's `OP_CHECKMULTISIG`. Right now the
/// interpreter has no array values surface (sigs/pks come in as arrays of
/// hex strings via `args`), so this path is exercised only when the caller
/// supplies array-of-bytes args; behaviour matches the TS SDK reference.
///
/// `checkPreimage(preimage)` computes `hash256(preimage)`
/// (`SHA256(SHA256(preimage))`) and compares to `ctx.sighash` byte-for-byte
/// — the on-chain `OP_PUSH_TX` semantic.
pub fn executeOnChainAuthoritative(
    allocator: std.mem.Allocator,
    anf: *const ANFProgram,
    method_name: []const u8,
    current_state: std.StringHashMap(ANFValue),
    args: std.StringHashMap(ANFValue),
    constructor_args: []const ANFValue,
    ctx: RealCryptoCtx,
) StrictError!NewStateResult {
    return runMethod(allocator, anf, method_name, current_state, args, constructor_args, true, &ctx, null, null);
}

/// Like `executeOnChainAuthoritative` but additionally populates
/// `out_info.method_name` and `out_info.binding_name` with the failing
/// context when `error.AssertionFailure` is returned. Use this from
/// drivers that need the structured `{error, methodName, bindingName}`
/// envelope on the wire. Symmetrical to `executeStrictWithFailureInfo`.
pub fn executeOnChainAuthoritativeWithFailureInfo(
    allocator: std.mem.Allocator,
    anf: *const ANFProgram,
    method_name: []const u8,
    current_state: std.StringHashMap(ANFValue),
    args: std.StringHashMap(ANFValue),
    constructor_args: []const ANFValue,
    ctx: RealCryptoCtx,
    out_info: *AssertionFailureInfo,
) StrictError!NewStateResult {
    return runMethod(allocator, anf, method_name, current_state, args, constructor_args, true, &ctx, out_info, null);
}

/// Like `computeNewState` but also returns data outputs resolved from
/// `this.addDataOutput(...)` calls in declaration order. Caller owns both
/// the state map and the returned data-output slice (including each
/// entry's `script`).
pub fn computeNewStateAndDataOutputs(
    allocator: std.mem.Allocator,
    anf: *const ANFProgram,
    method_name: []const u8,
    current_state: std.StringHashMap(ANFValue),
    args: std.StringHashMap(ANFValue),
    constructor_args: []const ANFValue,
) !NewStateResult {
    return runMethod(allocator, anf, method_name, current_state, args, constructor_args, false, null, null, null) catch |err| switch (err) {
        // Lenient mode never reports AssertionFailure (asserts are skipped),
        // but the unified runMethod return type includes it, so coerce away.
        // Likewise lenient mode without a MockEnv cannot surface
        // MissingWitness — the auto-injected params either get values
        // (none/empty) or stay unbound (also fine for lenient).
        error.AssertionFailure => unreachable,
        error.MissingWitness => unreachable,
        else => |e| return e,
    };
}

/// Internal worker shared by `computeNewStateAndDataOutputs` (strict=false) and
/// `executeStrict` (strict=true). Returns the StrictError union; lenient
/// callers prove the AssertionFailure variant is unreachable.
fn runMethod(
    allocator: std.mem.Allocator,
    anf: *const ANFProgram,
    method_name: []const u8,
    current_state: std.StringHashMap(ANFValue),
    args: std.StringHashMap(ANFValue),
    constructor_args: []const ANFValue,
    strict: bool,
    real_crypto: ?*const RealCryptoCtx,
    out_failure_info: ?*AssertionFailureInfo,
    mock_env: ?*const MockEnv,
) StrictError!NewStateResult {
    // Use an arena for all intermediate allocations during interpretation
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    // Find the method
    var method: ?*const ANFMethod = null;
    for (anf.methods) |*m| {
        if (m.is_public and std.mem.eql(u8, m.name, method_name)) {
            method = m;
            break;
        }
    }

    if (method == null) return StrictError.MethodNotFound;
    const meth = method.?;

    // Initialize environment with property values
    var env = std.StringHashMap(ANFValue).init(arena_alloc);

    // Build constructor param index: position among non-initialized properties.
    // Properties with initialValue are excluded from the constructor, so
    // constructor_args[i] corresponds to the i-th property without initialValue.
    var ctor_idx = std.StringHashMap(usize).init(arena_alloc);
    {
        var ci: usize = 0;
        for (anf.properties) |prop| {
            if (prop.initial_value == null) {
                try ctor_idx.put(prop.name, ci);
                ci += 1;
            }
        }
    }

    for (anf.properties) |prop| {
        if (current_state.get(prop.name)) |val| {
            try env.put(prop.name, val);
        } else if (prop.initial_value) |iv| {
            try env.put(prop.name, iv);
        } else if (ctor_idx.get(prop.name)) |ci| {
            if (ci < constructor_args.len) {
                try env.put(prop.name, constructor_args[ci]);
            }
        }
    }

    // Load method params (skip implicit ones)
    for (meth.params) |param| {
        if (isImplicitParam(param.name)) continue;
        if (args.get(param.name)) |val| {
            try env.put(param.name, val);
        }
    }

    // Track state mutations, data outputs, and raw outputs. Both output
    // arenas hold arena-allocated scripts; we dupe them into the caller
    // allocator below so they survive the arena deinit.
    var state_delta = std.StringHashMap(ANFValue).init(arena_alloc);
    var data_outputs_arena = std.ArrayList(DataOutputEntry).empty;
    var raw_outputs_arena = std.ArrayList(DataOutputEntry).empty;
    // Source-ordered state-class outputs (state continuation + raw), finding
    // G1. Arena-backed during interpretation (raw scripts reference env-held
    // arena slices); duped into the caller allocator below so they survive the
    // arena deinit.
    var ordered_outputs_arena = std.ArrayList(OrderedOutputEntry).empty;

    // Walk bindings — strict-mode context (or null for lenient). When
    // `real_crypto` is non-null we wire it into StrictCtx so crypto
    // built-ins can verify against the supplied sighash instead of
    // mock-returning true.
    var strict_ctx_storage: StrictCtx = .{ .method_name = method_name, .real_crypto = real_crypto };
    const strict_ctx_ptr: ?*StrictCtx = if (strict) &strict_ctx_storage else null;
    // Side map for numeric byte-array-op results (see EvalCtx.script_bytes).
    // Arena-backed — freed with everything else at arena.deinit.
    var script_bytes_map = std.StringHashMap([]const u8).init(arena_alloc);
    const eval_ctx: EvalCtx = .{ .strict = strict_ctx_ptr, .mock_env = mock_env, .script_bytes = &script_bytes_map, .ordered_outputs = &ordered_outputs_arena };
    evalBindings(arena_alloc, meth.body, &env, &state_delta, &data_outputs_arena, &raw_outputs_arena, anf, eval_ctx) catch |err| {
        // On strict-mode AssertionFailure, populate the caller-supplied
        // out_failure_info (if any) so the driver can emit a structured
        // {error, methodName, bindingName} envelope on the wire. Both names
        // are slices into the ANF program's own storage, not the arena, so
        // they remain valid after this function returns.
        if (err == error.AssertionFailure or err == error.MissingWitness) {
            if (out_failure_info) |info| {
                info.method_name = strict_ctx_storage.method_name;
                info.binding_name = strict_ctx_storage.last_binding_name;
            }
        }
        return err;
    };

    // Merge with current state — use caller allocator for result
    var result = std.StringHashMap(ANFValue).init(allocator);
    var cs_it = current_state.iterator();
    while (cs_it.next()) |entry| {
        try result.put(entry.key_ptr.*, entry.value_ptr.*);
    }
    var sd_it = state_delta.iterator();
    while (sd_it.next()) |entry| {
        // For bytes values from the arena, we need to dupe them into the caller allocator
        const val = switch (entry.value_ptr.*) {
            .bytes => |b| ANFValue{ .bytes = try allocator.dupe(u8, b) },
            else => entry.value_ptr.*,
        };
        try result.put(entry.key_ptr.*, val);
    }

    // Dupe data-output and raw-output scripts into the caller allocator so
    // they survive the arena deinit.
    const do_out = try allocator.alloc(DataOutputEntry, data_outputs_arena.items.len);
    for (data_outputs_arena.items, 0..) |d, i| {
        do_out[i] = .{ .satoshis = d.satoshis, .script = try allocator.dupe(u8, d.script) };
    }
    const ro_out = try allocator.alloc(DataOutputEntry, raw_outputs_arena.items.len);
    for (raw_outputs_arena.items, 0..) |d, i| {
        ro_out[i] = .{ .satoshis = d.satoshis, .script = try allocator.dupe(u8, d.script) };
    }

    // Dupe the source-ordered outputs (finding G1). `.raw` entries carry a
    // caller-owned script dupe; `.state` entries carry an empty script.
    const oo_out = try allocator.alloc(OrderedOutputEntry, ordered_outputs_arena.items.len);
    for (ordered_outputs_arena.items, 0..) |o, i| {
        oo_out[i] = .{
            .kind = o.kind,
            .satoshis = o.satoshis,
            .script = if (o.kind == .raw) try allocator.dupe(u8, o.script) else "",
        };
    }

    return .{ .state = result, .data_outputs = do_out, .raw_outputs = ro_out, .outputs = oo_out };
}

// ---------------------------------------------------------------------------
// Implicit parameter detection
// ---------------------------------------------------------------------------

fn isImplicitParam(name: []const u8) bool {
    return std.mem.eql(u8, name, "_changePKH") or
        std.mem.eql(u8, name, "_changeAmount") or
        std.mem.eql(u8, name, "_newAmount") or
        std.mem.eql(u8, name, "txPreimage");
}

// ---------------------------------------------------------------------------
// Binding evaluation
// ---------------------------------------------------------------------------

fn evalBindings(
    allocator: std.mem.Allocator,
    bindings: []const ANFBinding,
    env: *std.StringHashMap(ANFValue),
    state_delta: *std.StringHashMap(ANFValue),
    data_outputs: *std.ArrayList(DataOutputEntry),
    raw_outputs: *std.ArrayList(DataOutputEntry),
    anf: *const ANFProgram,
    eval_ctx: EvalCtx,
) error{ OutOfMemory, AssertionFailure, MissingWitness, ScriptNumberError }!void {
    for (bindings) |binding| {
        if (eval_ctx.strict) |ctx| ctx.last_binding_name = binding.name;
        const val = try evalNode(allocator, binding.value, binding.name, env, state_delta, data_outputs, raw_outputs, anf, eval_ctx);
        try env.put(binding.name, val);
    }
}

fn evalNode(
    allocator: std.mem.Allocator,
    node: ANFNode,
    // Name of the binding this node's result is stored under. Used as the key
    // for the byte-array-op side map (see EvalCtx.script_bytes) so a chained
    // op can look up this result's raw stack bytes by the operand ref.
    binding_name: []const u8,
    env: *std.StringHashMap(ANFValue),
    state_delta: *std.StringHashMap(ANFValue),
    data_outputs: *std.ArrayList(DataOutputEntry),
    raw_outputs: *std.ArrayList(DataOutputEntry),
    anf: *const ANFProgram,
    eval_ctx: EvalCtx,
) error{ OutOfMemory, AssertionFailure, MissingWitness, ScriptNumberError }!ANFValue {
    const strict_ctx = eval_ctx.strict;
    switch (node) {
        .load_param => |lp| {
            // Consult the MockEnv witness map FIRST for auto-injected intent
            // params (`_prevOutScript_<idx>`, `_serialisedOutputs`). If the
            // ANF references such a param and the caller did not bind it
            // via MockEnv.setPrevOutScript / setSerialisedOutputs, surface
            // `error.MissingWitness` so the driver can emit a clear
            // diagnostic — mirrors the TS interpreter's "requires witness
            // bytes" error.
            const is_witness_param = std.mem.startsWith(u8, lp.name, "_prevOutScript_") or
                std.mem.eql(u8, lp.name, "_serialisedOutputs");
            if (is_witness_param) {
                if (eval_ctx.mock_env) |me| {
                    if (me.witness_bytes.get(lp.name)) |bytes_hex| {
                        return .{ .bytes = bytes_hex };
                    }
                    return error.MissingWitness;
                }
                // No MockEnv supplied — fall through to env so existing
                // callers (which may still set the param via `args`) keep
                // working. If nothing is bound, return none and the
                // downstream desugar will fail its hash check, which
                // matches lenient behaviour.
            }
            return env.get(lp.name) orelse anf_none;
        },
        .load_prop => |lp| {
            return env.get(lp.name) orelse anf_none;
        },
        .load_const => |lc| {
            // Handle @ref: aliases and @this marker
            switch (lc.value) {
                .bytes => |b| {
                    if (b.len > 5 and std.mem.startsWith(u8, b, "@ref:")) {
                        // ALIAS: this binding IS the target's stack slot, so it
                        // inherits (or, when the target has none, drops) the
                        // target's raw byte-op width. See `aliasScriptBytes`.
                        const target = b[5..];
                        try aliasScriptBytes(eval_ctx.script_bytes, target, binding_name);
                        return env.get(target) orelse anf_none;
                    }
                    if (std.mem.eql(u8, b, "@this")) {
                        return anf_none;
                    }
                },
                else => {},
            }
            return lc.value;
        },
        .bin_op => |bo| {
            const left = env.get(bo.left) orelse anf_none;
            const right = env.get(bo.right) orelse anf_none;
            // Numeric byte-array ops (& | ^ << >>) thread the operands' real
            // stack bytes so CHAINED expressions match the deployed script (a
            // shift/bitwise result can be non-minimal; the next length-sensitive
            // op must see that). ByteString ops (result_type 'bytes' / bytes
            // operands) fall through to evalBinOp's minimal-operand path, which
            // stays byte-identical for a SINGLE op on minimal operands.
            if (isNumericByteOp(bo.op, bo.result_type, left, right)) {
                const op_byte = bo.op[0]; // '&' '|' '^' '<' (<<) '>' (>>)
                // Left raw bytes: prior byte-op result from the side map, else
                // this value's minimal script-number encoding.
                const ab: []const u8 = eval_ctx.script_bytes.get(bo.left) orelse
                    try minimalBytesArena(allocator, toInt(left));
                const rb: []const u8 = blk: {
                    if (op_byte == '<' or op_byte == '>') {
                        // Shift count is read as a number on-chain — only `ab`'s
                        // length matters, so the count never enters the side map.
                        // But being read AS A NUMBER means the count itself must
                        // be minimally encoded, or the shift aborts.
                        try assertMinimalNumericOperand(eval_ctx, bo.right, right);
                        break :blk try shiftBytes(allocator, op_byte, ab, toInt(right));
                    }
                    const bb: []const u8 = eval_ctx.script_bytes.get(bo.right) orelse
                        try minimalBytesArena(allocator, toInt(right));
                    break :blk try bitwiseBytes(allocator, op_byte, ab, bb);
                };
                try eval_ctx.script_bytes.put(binding_name, rb);
                return .{ .int = scriptNumDecode(rb) };
            }
            // Numeric consumers decode BOTH operands with fRequireMinimal, so a
            // threaded non-minimal intermediate (e.g. the 1-byte [0x00] that
            // `1 >> 1` leaves) aborts the script rather than silently
            // re-minimising to 0. Byte-typed ops are exempt: they never carry
            // threaded bytes and OP_CAT/OP_EQUAL impose no numeric decode.
            const is_bytes_path = std.mem.eql(u8, bo.result_type, "bytes") or
                (left == .bytes and right == .bytes);
            if (isNumericConsumerOp(bo.op) and !is_bytes_path) {
                try assertMinimalNumericOperand(eval_ctx, bo.left, left);
                try assertMinimalNumericOperand(eval_ctx, bo.right, right);
            }
            return try evalBinOp(allocator, bo.op, left, right, bo.result_type);
        },
        .unary_op => |uo| {
            const operand = env.get(uo.operand) orelse anf_none;
            // Numeric OP_INVERT threads raw stack bytes for chained expressions,
            // same as the bitwise/shift ops above. Bytes-typed `~` and other
            // unary ops use evalUnaryOp's minimal/native path (unchanged).
            if (std.mem.eql(u8, uo.op, "~") and !std.mem.eql(u8, uo.result_type, "bytes") and operand != .bytes) {
                const ab: []const u8 = eval_ctx.script_bytes.get(uo.operand) orelse
                    try minimalBytesArena(allocator, toInt(operand));
                const rb = try invertBytes(allocator, ab);
                try eval_ctx.script_bytes.put(binding_name, rb);
                return .{ .int = scriptNumDecode(rb) };
            }
            // Every other unary op reads its operand as a script NUMBER
            // (`-` -> OP_NEGATE) or coerces it to a boolean (`!` -> OP_NOT),
            // both fRequireMinimal decodes. `~` never reaches here on the
            // numeric path — it is a byte op and must keep accepting
            // non-minimal bytes.
            try assertMinimalNumericOperand(eval_ctx, uo.operand, operand);
            return evalUnaryOp(allocator, uo.op, operand, uo.result_type);
        },
        .call => |c| {
            // The single funnel every numeric builtin (`abs`, `min`, `max`,
            // `within`, `safediv`, `clamp`, `sign`, `bool`, ...) reads its
            // operands through. Only a NUMERIC byte-op result ever carries
            // threaded bytes, and a bigint argument is exactly what those
            // builtins decode with fRequireMinimal on chain — a ByteString
            // argument can never carry an entry here, so gating every argument
            // costs nothing and cannot miss a builtin.
            for (c.args) |arg_ref| {
                try assertMinimalNumericOperand(eval_ctx, arg_ref, env.get(arg_ref) orelse anf_none);
            }
            // Strict mode: a `call(assert, x)` lowering path must enforce the
            // predicate the same way the dedicated `assert` ANF node does.
            // Crypto built-ins (`checkSig`, `checkMultiSig`, `checkPreimage`)
            // still mock-return `true` even in strict mode; only explicit
            // `assert(...)` predicates are enforced.
            if (strict_ctx != null and std.mem.eql(u8, c.func, "assert")) {
                const arg = if (c.args.len > 0) (env.get(c.args[0]) orelse anf_none) else anf_none;
                if (!isTruthy(arg)) return error.AssertionFailure;
                return anf_none;
            }
            const real_crypto = if (strict_ctx) |sc| sc.real_crypto else null;
            return evalCall(allocator, c.func, c.args, env, real_crypto, eval_ctx.mock_env);
        },
        .method_call => |mc| {
            return evalMethodCall(allocator, mc.method, mc.args, env, state_delta, data_outputs, raw_outputs, anf, eval_ctx);
        },
        .if_node => |ifn| {
            const cond = env.get(ifn.cond) orelse anf_none;
            const branch = if (isTruthy(cond)) ifn.then_branch else ifn.else_branch;
            try evalBindings(allocator, branch, env, state_delta, data_outputs, raw_outputs, anf, eval_ctx);
            if (branch.len > 0) {
                // ALIAS: the `if` binding adopts the taken arm's last slot.
                const last_name = branch[branch.len - 1].name;
                try aliasScriptBytes(eval_ctx.script_bytes, last_name, binding_name);
                return env.get(last_name) orelse anf_none;
            }
            return anf_none;
        },
        .loop_node => |ln| {
            var last_val: ANFValue = anf_none;
            for (0..ln.count) |i| {
                // Iteration `i` binds `start + i*step` (issue #121).
                try env.put(ln.iter_var, .{ .int = ln.start + @as(i64, @intCast(i)) * ln.step });
                try evalBindings(allocator, ln.body, env, state_delta, data_outputs, raw_outputs, anf, eval_ctx);
                if (ln.body.len > 0) {
                    // ALIAS: the `loop` binding adopts the body's last slot.
                    const last_name = ln.body[ln.body.len - 1].name;
                    try aliasScriptBytes(eval_ctx.script_bytes, last_name, binding_name);
                    last_val = env.get(last_name) orelse anf_none;
                }
            }
            return last_val;
        },
        .assert_node => |an| {
            // Strict mode: evaluate the referenced predicate and abort with
            // `error.AssertionFailure` if it is falsy. Lenient mode skips
            // (the on-chain script handles enforcement). Crypto built-ins
            // remain mocked even in strict mode — see `executeStrict` doc.
            //
            // Marker-based skip: the auto-injected stateful-continuation
            // assert (`hash256(continuationOutputs) === extractOutputHash(
            // preimage)`) carries `is_auto_injected_state_check = true`
            // (set in `compilers/zig/src/passes/anf_lower.zig`). The
            // on-chain VM is authoritative for that check; off-chain we
            // have no realistic continuation hash. Developer-written
            // covenant asserts with the identical IR shape carry no
            // marker and ARE enforced (see BUG-002).
            if (strict_ctx != null) {
                if (an.is_auto_injected_state_check) return anf_none;
                if (an.value.len > 0) {
                    const predicate = env.get(an.value) orelse anf_none;
                    if (!isTruthy(predicate)) return error.AssertionFailure;
                }
            }
            return anf_none;
        },
        .update_prop => |up| {
            const new_val = env.get(up.value) orelse anf_none;
            try env.put(up.name, new_val);
            try state_delta.put(up.name, new_val);
            return anf_none;
        },
        .add_output => |ao| {
            // Extract implicit state changes from stateValues array.
            if (ao.state_values.len > 0) {
                // Collect mutable properties
                var mut_idx: usize = 0;
                for (anf.properties) |prop| {
                    if (!prop.readonly and mut_idx < ao.state_values.len) {
                        const ref = ao.state_values[mut_idx];
                        const new_val = env.get(ref) orelse anf_none;
                        try env.put(prop.name, new_val);
                        try state_delta.put(prop.name, new_val);
                        mut_idx += 1;
                    }
                }
            }
            // Record the state continuation in SOURCE order (finding G1): a
            // method may interleave raw outputs around it, and the on-chain
            // covenant folds them into hashOutputs in exactly this order.
            const sat_val = env.get(ao.satoshis) orelse anf_none;
            try eval_ctx.ordered_outputs.append(allocator, .{ .kind = .state, .satoshis = toInt(sat_val) });
            return anf_none;
        },
        .add_data_output => |ado| {
            // Resolve the two arg refs from env and record the data output.
            const sat_val = env.get(ado.satoshis) orelse anf_none;
            const script_val = env.get(ado.script_bytes) orelse anf_none;
            const sats: i64 = toInt(sat_val);
            const script_bytes: []const u8 = switch (script_val) {
                .bytes => |b| b,
                else => "",
            };
            try data_outputs.append(allocator, .{
                .satoshis = sats,
                .script = try allocator.dupe(u8, script_bytes),
            });
            return anf_none;
        },
        .add_raw_output => |aro| {
            // `addRawOutput(satoshis, scriptBytes)`. The simulator does not
            // introspect the script bytes (they're caller-supplied raw
            // locking script); it simply forwards them in the result envelope
            // so an off-chain transaction builder can emit the output at the
            // correct index. Crypto built-ins remain mocked even in strict
            // mode (matches TS reference at
            // packages/runar-sdk/src/anf-interpreter.ts).
            const sat_val = env.get(aro.satoshis) orelse anf_none;
            const script_val = env.get(aro.script_bytes) orelse anf_none;
            const sats: i64 = toInt(sat_val);
            const script_bytes: []const u8 = switch (script_val) {
                .bytes => |b| b,
                else => "",
            };
            try raw_outputs.append(allocator, .{
                .satoshis = sats,
                .script = try allocator.dupe(u8, script_bytes),
            });
            // Also record in the SOURCE-ordered state-class output list so a
            // transaction builder can emit it at the correct source-order index
            // (finding G1). The script slice references env-held arena storage;
            // runMethod dupes it into the caller allocator before returning.
            try eval_ctx.ordered_outputs.append(allocator, .{ .kind = .raw, .satoshis = sats, .script = script_bytes });
            return anf_none;
        },
        // On-chain-only operations — skip
        .check_preimage, .deserialize_state, .get_state_script => {
            return anf_none;
        },
        .array_literal => |al| {
            // Resolve each element ref from env into an ANFValue, then own
            // the slice on the caller's allocator. Element values are NOT
            // deep-copied: their `bytes`/inner-array storage is whatever the
            // referenced binding allocated, which already lives at least as
            // long as this evaluation.
            const elems = allocator.alloc(ANFValue, al.elements.len) catch return anf_none;
            for (al.elements, 0..) |ref, i| {
                elems[i] = env.get(ref) orelse anf_none;
            }
            return .{ .array = elems };
        },
        .unknown => {
            return anf_none;
        },
    }
}

// ---------------------------------------------------------------------------
// Script-number bitwise / shift semantics (byte-array ops, NOT numeric)
// ---------------------------------------------------------------------------
//
// `& | ^ ~ << >>` on bigint compile to OP_AND/OP_OR/OP_XOR/OP_INVERT/
// OP_LSHIFT/OP_RSHIFT, which operate on the RAW BYTES of each operand's
// minimal script-number encoding, not on its numeric value. AND/OR/XOR require
// equal-length operands (abort otherwise); shifts treat the bytes as a
// big-endian bit string and preserve length (LSHIFT masks off overflow MSBs).
// These helpers reproduce what the deployed script does, so the i64-valued
// interpreter agrees with it byte-for-byte. Mirrors
// packages/runar-testing/src/vm/utils.ts scriptNumber*.

/// Encode an i64 as minimal little-endian sign-magnitude bytes; 0 -> empty.
/// Writes into `buf` (needs 9 bytes for the full i64 range) and returns the
/// used sub-slice.
fn scriptNumEncode(n: i64, buf: *[9]u8) []u8 {
    if (n == 0) return buf[0..0];
    const negative = n < 0;
    // Magnitude via i128 so i64's most-negative value doesn't overflow.
    var abs: u64 = if (negative) @intCast(-@as(i128, n)) else @intCast(n);
    var len: usize = 0;
    while (abs > 0) : (len += 1) {
        buf[len] = @intCast(abs & 0xff);
        abs >>= 8;
    }
    const last = buf[len - 1];
    if (last & 0x80 != 0) {
        buf[len] = if (negative) 0x80 else 0x00;
        len += 1;
    } else if (negative) {
        buf[len - 1] = last | 0x80;
    }
    return buf[0..len];
}

/// Decode minimal little-endian sign-magnitude bytes to i64; empty -> 0.
/// Accumulates in u128 so a 9-byte encoding (e.g. i64's most-negative value)
/// never overflows a u64 shift.
fn scriptNumDecode(bytes: []const u8) i64 {
    if (bytes.len == 0) return 0;
    var result: u128 = 0;
    for (bytes, 0..) |b, i| {
        result |= @as(u128, b) << @intCast(8 * i);
    }
    const last = bytes[bytes.len - 1];
    if (last & 0x80 != 0) {
        // Clear the sign bit (MSB of the last byte) and negate.
        result &= ~(@as(u128, 0x80) << @intCast(8 * (bytes.len - 1)));
        return @intCast(-@as(i128, @intCast(result)));
    }
    return @intCast(result);
}

/// OP_AND/OP_OR/OP_XOR. `op` is '&' | '|' | '^'. Aborts on length mismatch,
/// exactly like the on-chain opcodes.
fn scriptNumBitwise(op: u8, a: i64, b: i64) error{ScriptNumberError}!i64 {
    var abuf: [9]u8 = undefined;
    var bbuf: [9]u8 = undefined;
    const av = scriptNumEncode(a, &abuf);
    const bv = scriptNumEncode(b, &bbuf);
    if (av.len != bv.len) return error.ScriptNumberError;
    var rbuf: [9]u8 = undefined;
    for (av, 0..) |x, i| {
        const y = bv[i];
        rbuf[i] = switch (op) {
            '&' => x & y,
            '|' => x | y,
            else => x ^ y,
        };
    }
    return scriptNumDecode(rbuf[0..av.len]);
}

/// OP_INVERT: flip every bit of the operand's minimal script-number bytes.
fn scriptNumInvert(a: i64) i64 {
    var abuf: [9]u8 = undefined;
    const av = scriptNumEncode(a, &abuf);
    var rbuf: [9]u8 = undefined;
    for (av, 0..) |x, i| rbuf[i] = ~x;
    return scriptNumDecode(rbuf[0..av.len]);
}

/// OP_LSHIFT/OP_RSHIFT. `op` is '<' (<<) | '>' (>>). Shifts the operand's bytes
/// as a big-endian bit string, preserving byte length (LSHIFT masks off the
/// overflow MSBs). A negative shift count aborts, like the opcodes.
fn scriptNumShift(op: u8, a: i64, shift: i64) error{ScriptNumberError}!i64 {
    if (shift < 0) return error.ScriptNumberError;
    var abuf: [9]u8 = undefined;
    const val = scriptNumEncode(a, &abuf);
    const n: usize = @intCast(shift);
    if (val.len == 0 or n == 0) return scriptNumDecode(val);
    var num: u128 = 0;
    for (val) |byte| num = (num << 8) | @as(u128, byte);
    if (op == '<') {
        num = std.math.shl(u128, num, n);
        const bit_len: usize = val.len * 8;
        const mask: u128 = std.math.shl(u128, @as(u128, 1), bit_len) -% 1;
        num &= mask;
    } else {
        num = std.math.shr(u128, num, n);
    }
    var rbuf: [9]u8 = undefined;
    var idx: usize = val.len;
    while (idx > 0) {
        idx -= 1;
        rbuf[idx] = @intCast(num & 0xff);
        num = std.math.shr(u128, num, 8);
    }
    return scriptNumDecode(rbuf[0..val.len]);
}

// ---------------------------------------------------------------------------
// Raw-byte script-number ops (chained byte-array-op threading)
// ---------------------------------------------------------------------------
//
// The scriptNum* helpers above take an i64 and re-derive its MINIMAL bytes per
// op — correct for a SINGLE op on freshly-minimal operands (what evalBinOp /
// evalUnaryOp and the truth-table test pin). The helpers below instead operate
// on RAW stack bytes supplied by the caller, so a CHAINED expression can thread
// a prior op's actual (possibly non-minimal) result bytes via the side map (see
// EvalCtx.script_bytes / the .bin_op + .unary_op arms of evalNode). All three
// allocate their result on the caller's (arena) allocator. Mirrors the
// scriptNumber*Bytes helpers in packages/runar-sdk/src/anf-interpreter.ts.

/// Whether a bin_op should thread raw stack bytes: a numeric (non-bytes)
/// `& | ^ << >>`. ByteString operands / result fall through to evalBinOp,
/// matching the TS SDK's `typeof !== 'string'` guard on both operands.
fn isNumericByteOp(op: []const u8, result_type: []const u8, left: ANFValue, right: ANFValue) bool {
    if (std.mem.eql(u8, result_type, "bytes")) return false;
    if (left == .bytes or right == .bytes) return false;
    return std.mem.eql(u8, op, "&") or std.mem.eql(u8, op, "|") or
        std.mem.eql(u8, op, "^") or std.mem.eql(u8, op, "<<") or
        std.mem.eql(u8, op, ">>");
}

/// Carry a binding's raw stack bytes across an ALIAS — a binding whose value IS
/// another binding's slot: the `load_const "@ref:<name>"` every local rebind
/// lowers to, an `if` adopting its taken arm's last value, a `loop` adopting its
/// body's. Without this, a chained length-sensitive op re-minimises the aliased
/// value and disagrees with the deployed script (NEW-006: `2 << 8` is a 1-byte
/// `0x00` on the stack but `[]` when re-minimised from `0`).
///
/// Mirrors `05-stack-lower.ts`, which carries its `rawSlots` marker across the
/// same constructs, and `aliasScriptBytes` in
/// packages/runar-sdk/src/anf-interpreter.ts.
///
/// CLEARS when `from` has no entry: the alias target is a freshly pushed,
/// minimal value, so a stale entry left by an earlier binding of the SAME name
/// (`let m0 = 2n << 8n; m0 = 300n;`) would otherwise be read as this slot's
/// width. `to` is the binding name, a slice into the ANF program's own storage,
/// so the key outlives the arena exactly like the `put` sites in `.bin_op` /
/// `.unary_op`; the value is the arena slice already held by `from`.
fn aliasScriptBytes(
    script_bytes: *std.StringHashMap([]const u8),
    from: []const u8,
    to: []const u8,
) error{OutOfMemory}!void {
    if (script_bytes.get(from)) |bytes| {
        try script_bytes.put(to, bytes);
    } else {
        _ = script_bytes.remove(to);
    }
}

/// Minimal little-endian sign-magnitude bytes of an i64, duped onto `allocator`.
fn minimalBytesArena(allocator: std.mem.Allocator, n: i64) error{OutOfMemory}![]u8 {
    var buf: [9]u8 = undefined;
    return allocator.dupe(u8, scriptNumEncode(n, &buf));
}

/// Whether a bin_op consumes its operands NUMERICALLY, i.e. lowers to an opcode
/// that decodes them with `fRequireMinimal = true`: OP_ADD/OP_SUB/OP_MUL/OP_DIV/
/// OP_MOD, OP_NUMEQUAL(VERIFY)/OP_NUMNOTEQUAL and the relational ops. The
/// byte-array ops `& | ^` and a shift's VALUE operand are deliberately NOT here
/// — they take raw bytes and only require equal length. `&&`/`||` cast to bool,
/// which has no minimal-encoding requirement either.
fn isNumericConsumerOp(op: []const u8) bool {
    return std.mem.eql(u8, op, "+") or std.mem.eql(u8, op, "-") or
        std.mem.eql(u8, op, "*") or std.mem.eql(u8, op, "/") or
        std.mem.eql(u8, op, "%") or std.mem.eql(u8, op, "==") or
        std.mem.eql(u8, op, "===") or std.mem.eql(u8, op, "!=") or
        std.mem.eql(u8, op, "!==") or std.mem.eql(u8, op, "<") or
        std.mem.eql(u8, op, "<=") or std.mem.eql(u8, op, ">") or
        std.mem.eql(u8, op, ">=");
}

/// Abort if `ref`'s threaded stack bytes are a NON-minimal encoding of its
/// decoded value — the exact case a numeric consumer rejects on chain
/// ("non-minimally encoded script number"). Only byte-array ops thread bytes, so
/// a ref absent from the side map is minimal by construction and always passes.
///
/// Without this, `1 >> 1` (which leaves the 1-byte `[0x00]`, NOT the empty
/// minimal zero) would be re-minimised to `0` by the numeric path: the
/// interpreter reports a VALID spend for a script that aborts on chain, leaving
/// the UTXO permanently unspendable.
fn assertMinimalNumericOperand(eval_ctx: EvalCtx, ref: []const u8, val: ANFValue) error{ScriptNumberError}!void {
    const raw = eval_ctx.script_bytes.get(ref) orelse return;
    var buf: [9]u8 = undefined;
    const minimal = scriptNumEncode(toInt(val), &buf);
    if (!std.mem.eql(u8, raw, minimal)) return error.ScriptNumberError;
}

/// Raw-byte OP_AND/OP_OR/OP_XOR. `op` is '&' | '|' | '^'. Aborts on length
/// mismatch (exactly like the on-chain opcodes). Result allocated on `allocator`.
fn bitwiseBytes(allocator: std.mem.Allocator, op: u8, av: []const u8, bv: []const u8) error{ ScriptNumberError, OutOfMemory }![]u8 {
    if (av.len != bv.len) return error.ScriptNumberError;
    const result = try allocator.alloc(u8, av.len);
    for (av, 0..) |x, i| {
        result[i] = switch (op) {
            '&' => x & bv[i],
            '|' => x | bv[i],
            else => x ^ bv[i],
        };
    }
    return result;
}

/// Raw-byte OP_INVERT: flip every bit, length-preserving. Result allocated.
fn invertBytes(allocator: std.mem.Allocator, av: []const u8) error{OutOfMemory}![]u8 {
    const result = try allocator.alloc(u8, av.len);
    for (av, 0..) |x, i| result[i] = ~x;
    return result;
}

/// Raw-byte OP_LSHIFT/OP_RSHIFT. `op` is '<' (<<) | '>' (>>). Treats `val` as a
/// big-endian bit string, preserving byte length (LSHIFT masks off overflow
/// MSBs). Negative shift aborts. Result allocated on `allocator`. `val` is at
/// most 9 bytes (minimal i64 encoding) and byte ops preserve length, so the
/// u128 accumulator never overflows.
fn shiftBytes(allocator: std.mem.Allocator, op: u8, val: []const u8, shift: i64) error{ ScriptNumberError, OutOfMemory }![]u8 {
    if (shift < 0) return error.ScriptNumberError;
    const result = try allocator.alloc(u8, val.len);
    const n: usize = @intCast(shift);
    if (val.len == 0 or n == 0) {
        @memcpy(result, val);
        return result;
    }
    var num: u128 = 0;
    for (val) |byte| num = (num << 8) | @as(u128, byte);
    if (op == '<') {
        num = std.math.shl(u128, num, n);
        const bit_len: usize = val.len * 8;
        const mask: u128 = std.math.shl(u128, @as(u128, 1), bit_len) -% 1;
        num &= mask;
    } else {
        num = std.math.shr(u128, num, n);
    }
    var idx: usize = val.len;
    while (idx > 0) {
        idx -= 1;
        result[idx] = @intCast(num & 0xff);
        num = std.math.shr(u128, num, 8);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Binary operations
// ---------------------------------------------------------------------------

fn evalBinOp(allocator: std.mem.Allocator, op: []const u8, left: ANFValue, right: ANFValue, result_type: []const u8) error{ScriptNumberError}!ANFValue {
    // Bytes operations
    if (std.mem.eql(u8, result_type, "bytes") or (left == .bytes and right == .bytes)) {
        return evalBytesBinOp(allocator, op, left, right);
    }

    const l = toInt(left);
    const r = toInt(right);

    if (std.mem.eql(u8, op, "+")) return .{ .int = l +% r };
    if (std.mem.eql(u8, op, "-")) return .{ .int = l -% r };
    if (std.mem.eql(u8, op, "*")) return .{ .int = l *% r };
    if (std.mem.eql(u8, op, "/")) return .{ .int = if (r == 0) 0 else @divTrunc(l, r) };
    if (std.mem.eql(u8, op, "%")) return .{ .int = if (r == 0) 0 else @rem(l, r) };
    if (std.mem.eql(u8, op, "==") or std.mem.eql(u8, op, "===")) return .{ .boolean = l == r };
    if (std.mem.eql(u8, op, "!=") or std.mem.eql(u8, op, "!==")) return .{ .boolean = l != r };
    if (std.mem.eql(u8, op, "<")) return .{ .boolean = l < r };
    if (std.mem.eql(u8, op, "<=")) return .{ .boolean = l <= r };
    if (std.mem.eql(u8, op, ">")) return .{ .boolean = l > r };
    if (std.mem.eql(u8, op, ">=")) return .{ .boolean = l >= r };
    if (std.mem.eql(u8, op, "&&")) return .{ .boolean = isTruthy(left) and isTruthy(right) };
    if (std.mem.eql(u8, op, "||")) return .{ .boolean = isTruthy(left) or isTruthy(right) };
    // Bitwise / shift: byte-array script-number semantics (see scriptNum*).
    if (std.mem.eql(u8, op, "&")) return .{ .int = try scriptNumBitwise('&', l, r) };
    if (std.mem.eql(u8, op, "|")) return .{ .int = try scriptNumBitwise('|', l, r) };
    if (std.mem.eql(u8, op, "^")) return .{ .int = try scriptNumBitwise('^', l, r) };
    if (std.mem.eql(u8, op, "<<")) return .{ .int = try scriptNumShift('<', l, r) };
    if (std.mem.eql(u8, op, ">>")) return .{ .int = try scriptNumShift('>', l, r) };

    return .{ .int = 0 };
}

fn evalBytesBinOp(allocator: std.mem.Allocator, op: []const u8, left: ANFValue, right: ANFValue) ANFValue {
    const l_str = switch (left) {
        .bytes => |b| b,
        else => "",
    };
    const r_str = switch (right) {
        .bytes => |b| b,
        else => "",
    };

    if (std.mem.eql(u8, op, "+")) {
        // cat: concatenate hex strings
        const result = std.mem.concat(allocator, u8, &[_][]const u8{ l_str, r_str }) catch return .{ .bytes = "" };
        return .{ .bytes = result };
    }
    if (std.mem.eql(u8, op, "==") or std.mem.eql(u8, op, "===")) {
        return .{ .boolean = std.mem.eql(u8, l_str, r_str) };
    }
    if (std.mem.eql(u8, op, "!=") or std.mem.eql(u8, op, "!==")) {
        return .{ .boolean = !std.mem.eql(u8, l_str, r_str) };
    }
    return .{ .bytes = "" };
}

// ---------------------------------------------------------------------------
// Unary operations
// ---------------------------------------------------------------------------

fn evalUnaryOp(allocator: std.mem.Allocator, op: []const u8, operand: ANFValue, result_type: []const u8) ANFValue {
    if (std.mem.eql(u8, result_type, "bytes")) {
        // Bitwise NOT on bytes
        if (std.mem.eql(u8, op, "~")) {
            const hex = switch (operand) {
                .bytes => |b| b,
                else => return operand,
            };
            const raw_bytes = bsvz.primitives.hex.decode(allocator, hex) catch return .{ .bytes = "" };
            defer allocator.free(raw_bytes);
            const result = allocator.alloc(u8, raw_bytes.len) catch return .{ .bytes = "" };
            for (raw_bytes, 0..) |b, i| {
                result[i] = ~b;
            }
            const hex_out = allocator.alloc(u8, result.len * 2) catch {
                allocator.free(result);
                return .{ .bytes = "" };
            };
            _ = bsvz.primitives.hex.encodeLower(result, hex_out) catch {
                allocator.free(result);
                allocator.free(hex_out);
                return .{ .bytes = "" };
            };
            allocator.free(result);
            return .{ .bytes = hex_out };
        }
        return operand;
    }

    const val = toInt(operand);

    if (std.mem.eql(u8, op, "-")) return .{ .int = -%val };
    if (std.mem.eql(u8, op, "!")) return .{ .boolean = !isTruthy(operand) };
    // OP_INVERT flips the operand's minimal script-number bytes, not native ~n.
    if (std.mem.eql(u8, op, "~")) return .{ .int = scriptNumInvert(val) };

    return .{ .int = val };
}

// ---------------------------------------------------------------------------
// Built-in function calls
// ---------------------------------------------------------------------------

fn evalCall(
    allocator: std.mem.Allocator,
    func: []const u8,
    arg_names: []const []const u8,
    env: *const std.StringHashMap(ANFValue),
    real_crypto: ?*const RealCryptoCtx,
    mock_env: ?*const MockEnv,
) ANFValue {
    // Crypto — mocked unless real_crypto context is present.
    if (std.mem.eql(u8, func, "checkSig")) {
        if (real_crypto) |rc| {
            const sig_val = getArg(arg_names, 0, env);
            const pk_val = getArg(arg_names, 1, env);
            return .{ .boolean = verifyEcdsaReal(allocator, sig_val, pk_val, rc.sighash) };
        }
        return .{ .boolean = true };
    }
    if (std.mem.eql(u8, func, "checkMultiSig")) {
        if (real_crypto) |rc| {
            const sigs_val = getArg(arg_names, 0, env);
            const pks_val = getArg(arg_names, 1, env);
            return .{ .boolean = verifyMultiSigReal(allocator, sigs_val, pks_val, rc.sighash) };
        }
        return .{ .boolean = true };
    }
    if (std.mem.eql(u8, func, "checkPreimage")) {
        if (real_crypto) |rc| {
            const pre_val = getArg(arg_names, 0, env);
            return .{ .boolean = verifyPreimageReal(allocator, pre_val, rc.sighash) };
        }
        return .{ .boolean = true };
    }

    // Assert — skip
    if (std.mem.eql(u8, func, "assert")) return anf_none;

    // On-chain-only — skip
    if (std.mem.eql(u8, func, "buildChangeOutput")) return anf_none;
    if (std.mem.eql(u8, func, "computeStateOutput")) return anf_none;

    // Crypto — real hashes
    if (std.mem.eql(u8, func, "sha256")) return hashFn(allocator, "sha256", getArg(arg_names, 0, env));
    if (std.mem.eql(u8, func, "hash256")) return hashFn(allocator, "hash256", getArg(arg_names, 0, env));
    if (std.mem.eql(u8, func, "hash160")) return hashFn(allocator, "hash160", getArg(arg_names, 0, env));
    if (std.mem.eql(u8, func, "ripemd160")) return hashFn(allocator, "ripemd160", getArg(arg_names, 0, env));

    // Math builtins
    if (std.mem.eql(u8, func, "abs")) {
        const v = toInt(getArg(arg_names, 0, env));
        return .{ .int = if (v < 0) -v else v };
    }
    if (std.mem.eql(u8, func, "min")) {
        const a = toInt(getArg(arg_names, 0, env));
        const b = toInt(getArg(arg_names, 1, env));
        return .{ .int = if (a < b) a else b };
    }
    if (std.mem.eql(u8, func, "max")) {
        const a = toInt(getArg(arg_names, 0, env));
        const b = toInt(getArg(arg_names, 1, env));
        return .{ .int = if (a > b) a else b };
    }
    if (std.mem.eql(u8, func, "within")) {
        const x = toInt(getArg(arg_names, 0, env));
        const lo = toInt(getArg(arg_names, 1, env));
        const hi = toInt(getArg(arg_names, 2, env));
        return .{ .boolean = x >= lo and x < hi };
    }
    if (std.mem.eql(u8, func, "safediv")) {
        const a = toInt(getArg(arg_names, 0, env));
        const b = toInt(getArg(arg_names, 1, env));
        return .{ .int = if (b == 0) 0 else @divTrunc(a, b) };
    }
    if (std.mem.eql(u8, func, "safemod")) {
        const a = toInt(getArg(arg_names, 0, env));
        const b = toInt(getArg(arg_names, 1, env));
        return .{ .int = if (b == 0) 0 else @rem(a, b) };
    }
    if (std.mem.eql(u8, func, "clamp")) {
        const v = toInt(getArg(arg_names, 0, env));
        const lo = toInt(getArg(arg_names, 1, env));
        const hi = toInt(getArg(arg_names, 2, env));
        return .{ .int = if (v < lo) lo else if (v > hi) hi else v };
    }
    if (std.mem.eql(u8, func, "sign")) {
        const v = toInt(getArg(arg_names, 0, env));
        return .{ .int = if (v > 0) 1 else if (v < 0) -1 else 0 };
    }
    if (std.mem.eql(u8, func, "pow")) {
        const base = toInt(getArg(arg_names, 0, env));
        const exp = toInt(getArg(arg_names, 1, env));
        if (exp < 0) return .{ .int = 0 };
        var result: i64 = 1;
        var i: i64 = 0;
        while (i < exp) : (i += 1) {
            result *%= base;
        }
        return .{ .int = result };
    }
    if (std.mem.eql(u8, func, "sqrt")) {
        const v = toInt(getArg(arg_names, 0, env));
        if (v <= 0) return .{ .int = 0 };
        var x = v;
        var y = @divTrunc(x + 1, 2);
        while (y < x) {
            x = y;
            y = @divTrunc(x + @divTrunc(v, x), 2);
        }
        return .{ .int = x };
    }
    if (std.mem.eql(u8, func, "gcd")) {
        var a = toInt(getArg(arg_names, 0, env));
        var b = toInt(getArg(arg_names, 1, env));
        if (a < 0) a = -a;
        if (b < 0) b = -b;
        while (b != 0) {
            const t = b;
            b = @rem(a, b);
            a = t;
        }
        return .{ .int = a };
    }
    if (std.mem.eql(u8, func, "divmod")) {
        const a = toInt(getArg(arg_names, 0, env));
        const b = toInt(getArg(arg_names, 1, env));
        if (b == 0) return .{ .int = 0 };
        return .{ .int = @divTrunc(a, b) };
    }
    if (std.mem.eql(u8, func, "log2")) {
        const v = toInt(getArg(arg_names, 0, env));
        if (v <= 0) return .{ .int = 0 };
        var bits: i64 = 0;
        var x = v;
        while (x > 1) {
            x >>= 1;
            bits += 1;
        }
        return .{ .int = bits };
    }
    if (std.mem.eql(u8, func, "bool")) {
        return .{ .int = if (isTruthy(getArg(arg_names, 0, env))) 1 else 0 };
    }
    if (std.mem.eql(u8, func, "mulDiv")) {
        const a = toInt(getArg(arg_names, 0, env));
        const b = toInt(getArg(arg_names, 1, env));
        const c = toInt(getArg(arg_names, 2, env));
        if (c == 0) return .{ .int = 0 };
        return .{ .int = @divTrunc(a *% b, c) };
    }
    if (std.mem.eql(u8, func, "percentOf")) {
        const a = toInt(getArg(arg_names, 0, env));
        const b = toInt(getArg(arg_names, 1, env));
        return .{ .int = @divTrunc(a *% b, 10000) };
    }

    // Byte operations
    if (std.mem.eql(u8, func, "cat")) {
        const a_hex = asHex(getArg(arg_names, 0, env));
        const b_hex = asHex(getArg(arg_names, 1, env));
        const result = std.mem.concat(allocator, u8, &[_][]const u8{ a_hex, b_hex }) catch return .{ .bytes = "" };
        return .{ .bytes = result };
    }
    if (std.mem.eql(u8, func, "len")) {
        const hex = asHex(getArg(arg_names, 0, env));
        return .{ .int = @intCast(hex.len / 2) };
    }
    if (std.mem.eql(u8, func, "substr")) {
        const hex = asHex(getArg(arg_names, 0, env));
        const start: usize = @intCast(@max(0, toInt(getArg(arg_names, 1, env))));
        const length: usize = @intCast(@max(0, toInt(getArg(arg_names, 2, env))));
        const hex_start = start * 2;
        const hex_end = @min((start + length) * 2, hex.len);
        if (hex_start >= hex.len) return .{ .bytes = "" };
        const result = allocator.dupe(u8, hex[hex_start..hex_end]) catch return .{ .bytes = "" };
        return .{ .bytes = result };
    }
    if (std.mem.eql(u8, func, "split")) {
        // split returns the first part; in ANF the second result is in a separate binding
        const hex = asHex(getArg(arg_names, 0, env));
        const pos: usize = @intCast(@max(0, toInt(getArg(arg_names, 1, env))));
        const hex_pos = @min(pos * 2, hex.len);
        const result = allocator.dupe(u8, hex[0..hex_pos]) catch return .{ .bytes = "" };
        return .{ .bytes = result };
    }
    if (std.mem.eql(u8, func, "left")) {
        const hex = asHex(getArg(arg_names, 0, env));
        const length: usize = @intCast(@max(0, toInt(getArg(arg_names, 1, env))));
        const hex_len = @min(length * 2, hex.len);
        const result = allocator.dupe(u8, hex[0..hex_len]) catch return .{ .bytes = "" };
        return .{ .bytes = result };
    }
    if (std.mem.eql(u8, func, "right")) {
        const hex = asHex(getArg(arg_names, 0, env));
        const length: usize = @intCast(@max(0, toInt(getArg(arg_names, 1, env))));
        const hex_len = length * 2;
        if (hex_len >= hex.len) {
            const result = allocator.dupe(u8, hex) catch return .{ .bytes = "" };
            return .{ .bytes = result };
        }
        const result = allocator.dupe(u8, hex[hex.len - hex_len ..]) catch return .{ .bytes = "" };
        return .{ .bytes = result };
    }
    if (std.mem.eql(u8, func, "reverseBytes")) {
        const hex = asHex(getArg(arg_names, 0, env));
        if (hex.len == 0) return .{ .bytes = "" };
        const result = allocator.alloc(u8, hex.len) catch return .{ .bytes = "" };
        const num_bytes = hex.len / 2;
        var i: usize = 0;
        while (i < num_bytes) : (i += 1) {
            const src_pos = (num_bytes - 1 - i) * 2;
            result[i * 2] = hex[src_pos];
            result[i * 2 + 1] = hex[src_pos + 1];
        }
        return .{ .bytes = result };
    }
    if (std.mem.eql(u8, func, "num2bin")) {
        const n = toInt(getArg(arg_names, 0, env));
        const byte_len: usize = @intCast(@max(0, toInt(getArg(arg_names, 1, env))));
        return num2binHex(allocator, n, byte_len);
    }
    if (std.mem.eql(u8, func, "bin2num")) {
        const hex = asHex(getArg(arg_names, 0, env));
        return .{ .int = bin2numInt(hex) };
    }

    // Baby Bear field arithmetic (p = 2013265921)
    const bb_p: i64 = 2013265921;
    if (std.mem.eql(u8, func, "bbFieldAdd")) {
        const a = toInt(getArg(arg_names, 0, env));
        const b = toInt(getArg(arg_names, 1, env));
        return .{ .int = @rem(@rem(a, bb_p) + @rem(b, bb_p) + bb_p, bb_p) };
    }
    if (std.mem.eql(u8, func, "bbFieldSub")) {
        const a = toInt(getArg(arg_names, 0, env));
        const b = toInt(getArg(arg_names, 1, env));
        return .{ .int = @rem(@rem(a, bb_p) - @rem(b, bb_p) + bb_p, bb_p) };
    }
    if (std.mem.eql(u8, func, "bbFieldMul")) {
        const a = toInt(getArg(arg_names, 0, env));
        const b = toInt(getArg(arg_names, 1, env));
        return .{ .int = @rem(@rem(a, bb_p) *% @rem(b, bb_p), bb_p) };
    }
    if (std.mem.eql(u8, func, "bbFieldInv")) {
        const a = toInt(getArg(arg_names, 0, env));
        // Fermat's little theorem: a^(p-2) mod p
        return .{ .int = modPow(a, bb_p - 2, bb_p) };
    }

    // Merkle root computation
    if (std.mem.eql(u8, func, "merkleRootSha256") or std.mem.eql(u8, func, "merkleRootHash256")) {
        const use_double = std.mem.eql(u8, func, "merkleRootHash256");
        return computeMerkleRoot(allocator, arg_names, env, use_double);
    }

    // Preimage intrinsics — surface MockEnv overrides if present, else
    // legacy stubs. `extractAmount` is treated as a bytes-shaped output by
    // the legacy stub but the TS reference returns it as a bigint; we
    // preserve the existing Zig stub shape for `extractAmount` so existing
    // callers don't regress, while exposing the MockEnv override path for
    // `extractOutputHash` / `extractLocktime` which the intent intrinsic
    // desugars actually consume.
    if (std.mem.eql(u8, func, "extractOutputHash")) {
        if (mock_env) |me| {
            if (me.output_hash_hex) |h| return .{ .bytes = h };
        }
        return .{ .bytes = "0000000000000000000000000000000000000000000000000000000000000000" };
    }
    if (std.mem.eql(u8, func, "extractAmount")) {
        if (mock_env) |me| return .{ .int = me.amount };
        return .{ .bytes = "0000000000000000000000000000000000000000000000000000000000000000" };
    }
    if (std.mem.eql(u8, func, "extractLocktime")) {
        if (mock_env) |me| return .{ .int = me.locktime };
        return .{ .int = 0 };
    }
    if (std.mem.eql(u8, func, "extractVersion")) {
        if (mock_env) |me| return .{ .int = me.version };
        return .{ .int = 1 };
    }
    if (std.mem.eql(u8, func, "extractSequence")) {
        if (mock_env) |me| return .{ .int = me.sequence };
        return .{ .int = 0xfffffffe };
    }
    if (std.mem.eql(u8, func, "extractHashPrevouts")) {
        if (mock_env) |me| {
            if (me.hash_prevouts_hex) |h| return .{ .bytes = h };
        }
        return .{ .bytes = "0000000000000000000000000000000000000000000000000000000000000000" };
    }
    if (std.mem.eql(u8, func, "extractHashSequence")) {
        if (mock_env) |me| {
            if (me.hash_sequence_hex) |h| return .{ .bytes = h };
        }
        return .{ .bytes = "0000000000000000000000000000000000000000000000000000000000000000" };
    }

    return anf_none;
}

fn evalMethodCall(
    allocator: std.mem.Allocator,
    method_name: []const u8,
    arg_names: []const []const u8,
    env: *std.StringHashMap(ANFValue),
    state_delta: *std.StringHashMap(ANFValue),
    data_outputs: *std.ArrayList(DataOutputEntry),
    raw_outputs: *std.ArrayList(DataOutputEntry),
    anf: *const ANFProgram,
    eval_ctx: EvalCtx,
) error{ OutOfMemory, AssertionFailure, MissingWitness, ScriptNumberError }!ANFValue {
    // Find the private method
    for (anf.methods) |*m| {
        if (!m.is_public and std.mem.eql(u8, m.name, method_name)) {
            // Build method env: copy property values
            var method_env = std.StringHashMap(ANFValue).init(allocator);
            defer method_env.deinit();

            for (anf.properties) |prop| {
                if (env.get(prop.name)) |val| {
                    try method_env.put(prop.name, val);
                }
            }

            // Map method params to passed args
            for (m.params, 0..) |param, i| {
                if (i < arg_names.len) {
                    const val = env.get(arg_names[i]) orelse anf_none;
                    try method_env.put(param.name, val);
                }
            }

            // Execute the method body — propagate strict + MockEnv so nested
            // private-method asserts (and overrides) also apply, but with a
            // FRESH byte-op side map: the method's binding names are scoped to
            // its own body, so its byte-op results must not collide with (or
            // leak into) the caller's side map. Mirrors the TS reference, which
            // recurses into a private method with a default-empty scriptBytes.
            var method_script_bytes = std.StringHashMap([]const u8).init(allocator);
            defer method_script_bytes.deinit();
            const method_ctx: EvalCtx = .{
                .strict = eval_ctx.strict,
                .mock_env = eval_ctx.mock_env,
                .script_bytes = &method_script_bytes,
                // Share the caller's source-ordered output list (finding G1) so
                // add_output / add_raw_output inside a private method append in
                // the same interleaved source order the compiler folds.
                .ordered_outputs = eval_ctx.ordered_outputs,
            };
            try evalBindings(allocator, m.body, &method_env, state_delta, data_outputs, raw_outputs, anf, method_ctx);

            // Propagate property changes back
            for (anf.properties) |prop| {
                if (method_env.get(prop.name)) |val| {
                    try env.put(prop.name, val);
                }
            }

            // Return last binding's value
            if (m.body.len > 0) {
                return method_env.get(m.body[m.body.len - 1].name) orelse anf_none;
            }
            return anf_none;
        }
    }
    return anf_none;
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

fn hashFn(allocator: std.mem.Allocator, name: []const u8, input: ANFValue) ANFValue {
    const hex_str = switch (input) {
        .bytes => |b| b,
        else => return .{ .bytes = "" },
    };

    // Decode hex to bytes
    const bytes = bsvz.primitives.hex.decode(allocator, hex_str) catch return .{ .bytes = "" };
    defer allocator.free(bytes);

    if (std.mem.eql(u8, name, "sha256")) {
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
        const result = allocator.alloc(u8, 64) catch return .{ .bytes = "" };
        _ = bsvz.primitives.hex.encodeLower(&hash, result) catch {
            allocator.free(result);
            return .{ .bytes = "" };
        };
        return .{ .bytes = result };
    }

    if (std.mem.eql(u8, name, "hash256")) {
        // hash256 = SHA256(SHA256(data))
        var first: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &first, .{});
        var second: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&first, &second, .{});
        const result = allocator.alloc(u8, 64) catch return .{ .bytes = "" };
        _ = bsvz.primitives.hex.encodeLower(&second, result) catch {
            allocator.free(result);
            return .{ .bytes = "" };
        };
        return .{ .bytes = result };
    }

    if (std.mem.eql(u8, name, "hash160")) {
        // hash160 = RIPEMD160(SHA256(data))
        const h = bsvz.crypto.hash.hash160(bytes);
        const result = allocator.alloc(u8, 40) catch return .{ .bytes = "" };
        _ = bsvz.primitives.hex.encodeLower(&h.bytes, result) catch {
            allocator.free(result);
            return .{ .bytes = "" };
        };
        return .{ .bytes = result };
    }

    if (std.mem.eql(u8, name, "ripemd160")) {
        const h = bsvz.crypto.hash.ripemd160(bytes);
        const result = allocator.alloc(u8, 40) catch return .{ .bytes = "" };
        _ = bsvz.primitives.hex.encodeLower(&h.bytes, result) catch {
            allocator.free(result);
            return .{ .bytes = "" };
        };
        return .{ .bytes = result };
    }

    return .{ .bytes = "" };
}

// ---------------------------------------------------------------------------
// Real ECDSA / preimage verification (used by executeOnChainAuthoritative)
// ---------------------------------------------------------------------------

/// Verify an ECDSA signature against a sighash digest using bsvz's
/// secp256k1 primitives. The pubkey must be SEC1-encoded
/// (compressed 33 bytes or uncompressed 65 bytes); the signature is DER
/// (with optional trailing sighash type byte stripped). Returns false on
/// any decode error so the enclosing assert fires.
fn verifyEcdsaReal(
    allocator: std.mem.Allocator,
    sig_val: ANFValue,
    pk_val: ANFValue,
    sighash: [32]u8,
) bool {
    const sig_hex = switch (sig_val) {
        .bytes => |b| b,
        else => return false,
    };
    const pk_hex = switch (pk_val) {
        .bytes => |b| b,
        else => return false,
    };
    const sig_bytes = bsvz.primitives.hex.decode(allocator, sig_hex) catch return false;
    defer allocator.free(sig_bytes);
    const pk_bytes = bsvz.primitives.hex.decode(allocator, pk_hex) catch return false;
    defer allocator.free(pk_bytes);

    // Strip optional trailing sighash type byte from a DER+hashtype blob.
    var der_slice = sig_bytes;
    if (der_slice.len >= 2 and der_slice[0] == 0x30) {
        const declared: usize = @as(usize, der_slice[1]) + 2;
        if (der_slice.len == declared + 1) {
            der_slice = der_slice[0..declared];
        }
    }

    return bsvz.crypto.verifyDigest256RelaxedSec1(pk_bytes, sighash, der_slice) catch false;
}

/// Real `checkMultiSig` verification: iterate `sigs` left-to-right and
/// consume `pks` greedily (mirrors the on-chain `OP_CHECKMULTISIG` semantic
/// and the TS / Java SDK references at
/// `packages/runar-sdk/src/anf-interpreter.ts::verifyMultiSig` and
/// `packages/runar-java/src/main/java/runar/lang/sdk/AnfInterpreter.java::verifyMultiSigReal`).
///
/// `sigs_val` and `pks_val` must be `ANFValue.array` whose elements are
/// `ANFValue.bytes` (hex-encoded) — what `stateValueToAnf` produces for a
/// `StateValue.array_value` of `bytes` leaves and what an `array_literal`
/// ANF binding produces from byte-shaped element refs. Returns `false` on
/// any other shape so an enclosing `assert(checkMultiSig(...))` fails loudly.
fn verifyMultiSigReal(
    allocator: std.mem.Allocator,
    sigs_val: ANFValue,
    pks_val: ANFValue,
    sighash: [32]u8,
) bool {
    const sigs = switch (sigs_val) {
        .array => |a| a,
        else => return false,
    };
    const pks = switch (pks_val) {
        .array => |a| a,
        else => return false,
    };
    if (sigs.len > pks.len) return false;
    var pk_idx: usize = 0;
    for (sigs) |sig| {
        var matched = false;
        while (pk_idx < pks.len) : (pk_idx += 1) {
            const ok = verifyEcdsaReal(allocator, sig, pks[pk_idx], sighash);
            if (ok) {
                pk_idx += 1;
                matched = true;
                break;
            }
        }
        if (!matched) return false;
    }
    return true;
}

/// Verify that hash256(preimage) equals the supplied 32-byte sighash —
/// the on-chain `OP_PUSH_TX` semantic for `checkPreimage`.
fn verifyPreimageReal(
    allocator: std.mem.Allocator,
    pre_val: ANFValue,
    sighash: [32]u8,
) bool {
    const pre_hex = switch (pre_val) {
        .bytes => |b| b,
        else => return false,
    };
    const pre_bytes = bsvz.primitives.hex.decode(allocator, pre_hex) catch return false;
    defer allocator.free(pre_bytes);
    var first: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(pre_bytes, &first, .{});
    var second: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&first, &second, .{});
    return std.mem.eql(u8, &second, &sighash);
}

// ---------------------------------------------------------------------------
// Numeric/truthiness helpers
// ---------------------------------------------------------------------------

fn getArg(arg_names: []const []const u8, idx: usize, env: *const std.StringHashMap(ANFValue)) ANFValue {
    if (idx >= arg_names.len) return anf_none;
    return env.get(arg_names[idx]) orelse anf_none;
}

fn toInt(v: ANFValue) i64 {
    return switch (v) {
        .int => |n| n,
        .boolean => |b| if (b) @as(i64, 1) else @as(i64, 0),
        .bytes => |b| {
            // Handle "42n" format from JSON
            if (b.len > 0 and b[b.len - 1] == 'n') {
                return std.fmt.parseInt(i64, b[0 .. b.len - 1], 10) catch 0;
            }
            return std.fmt.parseInt(i64, b, 10) catch 0;
        },
        // Arrays and none have no numeric coercion — fall through to 0 to
        // mirror how `asHex` returns "" and the rest of the lenient
        // interpreter degrades gracefully on type mismatches.
        .array => 0,
        .none => 0,
    };
}

fn isTruthy(v: ANFValue) bool {
    return switch (v) {
        .boolean => |b| b,
        .int => |n| n != 0,
        .bytes => |b| b.len > 0 and !std.mem.eql(u8, b, "0") and !std.mem.eql(u8, b, "false"),
        // A non-empty array is truthy; an empty array is falsy. Matches the
        // TS / Java reference shapes (empty `[]` is falsy in lenient mode).
        .array => |a| a.len > 0,
        .none => false,
    };
}

fn asHex(v: ANFValue) []const u8 {
    return switch (v) {
        .bytes => |b| b,
        else => "",
    };
}

// ---------------------------------------------------------------------------
// Byte encoding helpers
// ---------------------------------------------------------------------------

/// `num2bin(n, byte_len)` — exactly what OP_NUM2BIN computes (NEW-013).
///
/// The order of the two steps below is load-bearing. This used to set the sign
/// bit on the last MAGNITUDE byte and pad zeros AFTER it, so `num2bin(-1, 2)`
/// produced `8100` while the script produces `0180`. The result is the bytes
/// the SDK puts in the call transaction, so the wrong order built continuations
/// the deployed script rejects — and six of the seven SDKs shared the mistake,
/// which is why tier-vs-tier parity never caught it.
///
/// The engine pads FIRST and then puts the sign bit on the new most-significant
/// byte.
fn num2binHex(allocator: std.mem.Allocator, n: i64, byte_len: usize) ANFValue {
    if (byte_len == 0) return .{ .bytes = "" };

    // 1. Minimal BSV script-number encoding: little-endian magnitude with the
    //    sign in bit 7 of the top byte, growing one byte when magnitude data
    //    already occupies that bit.
    const negative = n < 0;
    var abs_val: u64 = @abs(n);

    var bytes_buf: [17]u8 = undefined;
    var num_bytes: usize = 0;
    while (abs_val > 0 and num_bytes < bytes_buf.len) : (num_bytes += 1) {
        bytes_buf[num_bytes] = @intCast(abs_val & 0xff);
        abs_val >>= 8;
    }
    if (num_bytes > 0) {
        if ((bytes_buf[num_bytes - 1] & 0x80) != 0) {
            if (num_bytes < bytes_buf.len) {
                bytes_buf[num_bytes] = if (negative) 0x80 else 0x00;
                num_bytes += 1;
            }
        } else if (negative) {
            bytes_buf[num_bytes - 1] |= 0x80;
        }
    }

    // 2b. Padded: lift the sign bit off the magnitude so it can be re-applied
    //     to the byte that is now most significant. 2a (field narrower than the
    //     value, which OP_NUM2BIN rejects outright as an impossible encoding)
    //     keeps the historical truncation: the encoding is used as-is.
    var sign_bit: u8 = 0;
    if (num_bytes > 0 and num_bytes < byte_len) {
        sign_bit = bytes_buf[num_bytes - 1] & 0x80;
        bytes_buf[num_bytes - 1] &= 0x7f;
    }

    const result = allocator.alloc(u8, byte_len * 2) catch return .{ .bytes = "" };
    @memset(result, '0');

    // Write LE bytes as hex; everything past `write_len` stays zero-padded.
    const hex_chars = "0123456789abcdef";
    const write_len = @min(num_bytes, byte_len);
    for (0..write_len) |i| {
        const b = bytes_buf[i];
        result[i * 2] = hex_chars[b >> 4];
        result[i * 2 + 1] = hex_chars[b & 0x0f];
    }

    // The sign lands on the new most-significant byte, which is pure padding
    // here (`num_bytes < byte_len` guarded above), so it is exactly 0x80.
    if (sign_bit != 0) {
        result[(byte_len - 1) * 2] = '8';
        result[(byte_len - 1) * 2 + 1] = '0';
    }

    return .{ .bytes = result };
}

fn bin2numInt(hex: []const u8) i64 {
    if (hex.len == 0) return 0;

    // Decode hex to bytes (LE)
    const num_bytes = hex.len / 2;
    if (num_bytes == 0) return 0;

    var bytes_buf: [16]u8 = undefined;
    const decode_len = @min(num_bytes, bytes_buf.len);
    for (0..decode_len) |i| {
        bytes_buf[i] = hexByteDecode(hex[i * 2], hex[i * 2 + 1]);
    }

    // Strip trailing zero bytes (MSB-side padding from num2bin) so the sign bit
    // is located on the last non-zero byte, matching Bitcoin script-num semantics.
    var eff_len: usize = decode_len;
    while (eff_len > 0 and bytes_buf[eff_len - 1] == 0) : (eff_len -= 1) {}
    if (eff_len == 0) return 0;

    // Check sign bit
    const negative = (bytes_buf[eff_len - 1] & 0x80) != 0;
    if (negative) {
        bytes_buf[eff_len - 1] &= 0x7f;
    }

    // Build integer from LE bytes
    var result: i64 = 0;
    var i: usize = eff_len;
    while (i > 0) {
        i -= 1;
        result = (result << 8) | @as(i64, bytes_buf[i]);
    }

    return if (negative) -result else result;
}

fn hexByteDecode(hi: u8, lo: u8) u8 {
    return (hexNibble(hi) << 4) | hexNibble(lo);
}

fn hexNibble(c: u8) u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    if (c >= 'A' and c <= 'F') return c - 'A' + 10;
    return 0;
}

// ---------------------------------------------------------------------------
// Modular exponentiation (for Baby Bear field inverse)
// ---------------------------------------------------------------------------

fn modPow(base_val: i64, exp_val: i64, modulus: i64) i64 {
    if (modulus == 1) return 0;
    var result: i128 = 1;
    var b: i128 = @rem(@as(i128, base_val), @as(i128, modulus));
    if (b < 0) b += modulus;
    var e: i128 = exp_val;
    const m: i128 = modulus;
    while (e > 0) {
        if (@rem(e, 2) == 1) {
            result = @rem(result * b, m);
        }
        e = @divTrunc(e, 2);
        b = @rem(b * b, m);
    }
    return @intCast(result);
}

// ---------------------------------------------------------------------------
// Merkle root computation
// ---------------------------------------------------------------------------

fn computeMerkleRoot(allocator: std.mem.Allocator, arg_names: []const []const u8, env: *const std.StringHashMap(ANFValue), use_double: bool) ANFValue {
    // merkleRootSha256(leaf, path, flags) or merkleRootHash256(leaf, path, flags)
    // For the interpreter, return a dummy 32-byte hash
    _ = allocator;
    _ = arg_names;
    _ = env;
    _ = use_double;
    return .{ .bytes = "00" ** 32 };
}

// ---------------------------------------------------------------------------
// JSON parsing for ANF IR
// ---------------------------------------------------------------------------

/// Parse an ANFProgram from JSON text. The parsed ANF shares lifetime with
/// the returned program; caller must keep the allocator alive.
pub fn parseANFFromJson(allocator: std.mem.Allocator, json_text: []const u8) !ANFProgram {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_text, .{});
    defer parsed.deinit();

    return parseANFFromJsonValue(allocator, parsed.value);
}

fn parseANFFromJsonValue(allocator: std.mem.Allocator, root_val: std.json.Value) error{OutOfMemory}!ANFProgram {
    if (root_val != .object) return ANFProgram{};
    const root = root_val.object;

    var program = ANFProgram{};

    if (root.get("contractName")) |v| {
        if (v == .string) program.contract_name = try allocator.dupe(u8, v.string);
    }

    // Parse properties
    if (root.get("properties")) |props_val| {
        if (props_val == .array) {
            const items = props_val.array.items;
            var props = try allocator.alloc(ANFProperty, items.len);
            for (items, 0..) |item, i| {
                props[i] = try parseANFProperty(allocator, item);
            }
            program.properties = props;
        }
    }

    // Parse methods
    if (root.get("methods")) |methods_val| {
        if (methods_val == .array) {
            const items = methods_val.array.items;
            var methods = try allocator.alloc(ANFMethod, items.len);
            for (items, 0..) |item, i| {
                methods[i] = try parseANFMethod(allocator, item);
            }
            program.methods = methods;
        }
    }

    return program;
}

fn parseANFProperty(allocator: std.mem.Allocator, val: std.json.Value) error{OutOfMemory}!ANFProperty {
    if (val != .object) return ANFProperty{};
    const obj = val.object;
    var prop = ANFProperty{};
    if (obj.get("name")) |v| {
        if (v == .string) prop.name = try allocator.dupe(u8, v.string);
    }
    if (obj.get("type")) |v| {
        if (v == .string) prop.type_name = try allocator.dupe(u8, v.string);
    }
    if (obj.get("readonly")) |v| {
        if (v == .bool) prop.readonly = v.bool;
    }
    if (obj.get("initialValue")) |v| {
        prop.initial_value = try parseJSONToANFValue(allocator, v);
    }
    return prop;
}

fn parseANFMethod(allocator: std.mem.Allocator, val: std.json.Value) error{OutOfMemory}!ANFMethod {
    if (val != .object) return ANFMethod{};
    const obj = val.object;
    var meth = ANFMethod{};
    if (obj.get("name")) |v| {
        if (v == .string) meth.name = try allocator.dupe(u8, v.string);
    }
    if (obj.get("isPublic")) |v| {
        if (v == .bool) meth.is_public = v.bool;
    }
    if (obj.get("params")) |params_val| {
        if (params_val == .array) {
            const items = params_val.array.items;
            var params = try allocator.alloc(ANFParam, items.len);
            for (items, 0..) |item, i| {
                params[i] = try parseANFParam(allocator, item);
            }
            meth.params = params;
        }
    }
    if (obj.get("body")) |body_val| {
        if (body_val == .array) {
            const items = body_val.array.items;
            var body = try allocator.alloc(ANFBinding, items.len);
            for (items, 0..) |item, i| {
                body[i] = try parseANFBinding(allocator, item);
            }
            meth.body = body;
        }
    }
    return meth;
}

fn parseANFParam(allocator: std.mem.Allocator, val: std.json.Value) error{OutOfMemory}!ANFParam {
    if (val != .object) return ANFParam{};
    const obj = val.object;
    var param = ANFParam{};
    if (obj.get("name")) |v| {
        if (v == .string) param.name = try allocator.dupe(u8, v.string);
    }
    if (obj.get("type")) |v| {
        if (v == .string) param.type_name = try allocator.dupe(u8, v.string);
    }
    return param;
}

fn parseANFBinding(allocator: std.mem.Allocator, val: std.json.Value) error{OutOfMemory}!ANFBinding {
    if (val != .object) return ANFBinding{};
    const obj = val.object;
    var binding = ANFBinding{};
    if (obj.get("name")) |v| {
        if (v == .string) binding.name = try allocator.dupe(u8, v.string);
    }
    if (obj.get("value")) |v| {
        binding.value = try parseANFNode(allocator, v);
    }
    return binding;
}

fn parseANFNode(allocator: std.mem.Allocator, val: std.json.Value) error{OutOfMemory}!ANFNode {
    if (val != .object) return .{ .unknown = {} };
    const obj = val.object;

    const kind = if (obj.get("kind")) |v| (if (v == .string) v.string else "") else "";

    if (std.mem.eql(u8, kind, "load_param")) {
        const name = if (obj.get("name")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "";
        return .{ .load_param = .{ .name = name } };
    }
    if (std.mem.eql(u8, kind, "load_prop")) {
        const name = if (obj.get("name")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "";
        return .{ .load_prop = .{ .name = name } };
    }
    if (std.mem.eql(u8, kind, "load_const")) {
        const value_node = obj.get("value") orelse return .{ .load_const = .{} };
        return .{ .load_const = .{ .value = try parseJSONToANFValue(allocator, value_node) } };
    }
    if (std.mem.eql(u8, kind, "bin_op")) {
        return .{ .bin_op = .{
            .op = if (obj.get("op")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "",
            .left = if (obj.get("left")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "",
            .right = if (obj.get("right")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "",
            .result_type = if (obj.get("result_type")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else if (obj.get("resultType")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "",
        } };
    }
    if (std.mem.eql(u8, kind, "unary_op")) {
        return .{ .unary_op = .{
            .op = if (obj.get("op")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "",
            .operand = if (obj.get("operand")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "",
            .result_type = if (obj.get("result_type")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else if (obj.get("resultType")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "",
        } };
    }
    if (std.mem.eql(u8, kind, "call")) {
        const func_name = if (obj.get("func")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "";
        var call_args: std.ArrayListUnmanaged([]const u8) = .empty;
        if (obj.get("args")) |a| {
            if (a == .array) {
                for (a.array.items) |item| {
                    if (item == .string) {
                        try call_args.append(allocator, try allocator.dupe(u8, item.string));
                    }
                }
            }
        }
        return .{ .call = .{ .func = func_name, .args = try call_args.toOwnedSlice(allocator) } };
    }
    if (std.mem.eql(u8, kind, "method_call")) {
        const mname = if (obj.get("method")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "";
        var call_args: std.ArrayListUnmanaged([]const u8) = .empty;
        if (obj.get("args")) |a| {
            if (a == .array) {
                for (a.array.items) |item| {
                    if (item == .string) {
                        try call_args.append(allocator, try allocator.dupe(u8, item.string));
                    }
                }
            }
        }
        return .{ .method_call = .{ .method = mname, .args = try call_args.toOwnedSlice(allocator) } };
    }
    if (std.mem.eql(u8, kind, "update_prop")) {
        return .{ .update_prop = .{
            .name = if (obj.get("name")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "",
            .value = if (obj.get("value")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "",
        } };
    }
    if (std.mem.eql(u8, kind, "assert")) {
        const value_ref = if (obj.get("value")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "";
        const marker = if (obj.get("isAutoInjectedStateCheck")) |v| (v == .bool and v.bool) else false;
        return .{ .assert_node = .{ .value = value_ref, .is_auto_injected_state_check = marker } };
    }
    if (std.mem.eql(u8, kind, "check_preimage")) return .{ .check_preimage = .{} };
    if (std.mem.eql(u8, kind, "deserialize_state")) return .{ .deserialize_state = .{} };
    if (std.mem.eql(u8, kind, "get_state_script")) return .{ .get_state_script = .{} };
    if (std.mem.eql(u8, kind, "add_raw_output")) {
        return .{ .add_raw_output = .{
            .satoshis = if (obj.get("satoshis")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "",
            .script_bytes = if (obj.get("scriptBytes")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "",
        } };
    }
    if (std.mem.eql(u8, kind, "add_data_output")) {
        return .{ .add_data_output = .{
            .satoshis = if (obj.get("satoshis")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "",
            .script_bytes = if (obj.get("scriptBytes")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "",
        } };
    }
    if (std.mem.eql(u8, kind, "add_output")) {
        var state_values: std.ArrayListUnmanaged([]const u8) = .empty;
        if (obj.get("stateValues")) |sv| {
            if (sv == .array) {
                for (sv.array.items) |item| {
                    if (item == .string) {
                        try state_values.append(allocator, try allocator.dupe(u8, item.string));
                    }
                }
            }
        }
        const satoshis = if (obj.get("satoshis")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "";
        return .{ .add_output = .{ .satoshis = satoshis, .state_values = try state_values.toOwnedSlice(allocator) } };
    }
    if (std.mem.eql(u8, kind, "array_literal")) {
        var elements: std.ArrayListUnmanaged([]const u8) = .empty;
        if (obj.get("elements")) |e| {
            if (e == .array) {
                for (e.array.items) |item| {
                    if (item == .string) {
                        try elements.append(allocator, try allocator.dupe(u8, item.string));
                    }
                }
            }
        }
        return .{ .array_literal = .{ .elements = try elements.toOwnedSlice(allocator) } };
    }
    if (std.mem.eql(u8, kind, "if")) {
        const cond = if (obj.get("cond")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "";
        var then_branch: std.ArrayListUnmanaged(ANFBinding) = .empty;
        if (obj.get("then")) |t| {
            if (t == .array) {
                for (t.array.items) |item| {
                    try then_branch.append(allocator, try parseANFBinding(allocator, item));
                }
            }
        }
        var else_branch: std.ArrayListUnmanaged(ANFBinding) = .empty;
        if (obj.get("else")) |e| {
            if (e == .array) {
                for (e.array.items) |item| {
                    try else_branch.append(allocator, try parseANFBinding(allocator, item));
                }
            }
        }
        return .{ .if_node = .{
            .cond = cond,
            .then_branch = try then_branch.toOwnedSlice(allocator),
            .else_branch = try else_branch.toOwnedSlice(allocator),
        } };
    }
    if (std.mem.eql(u8, kind, "loop")) {
        const count: usize = if (obj.get("count")) |v| (if (v == .integer) @as(usize, @intCast(v.integer)) else 0) else 0;
        const iter_var = if (obj.get("iterVar")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "";
        // Issue #121: iterator start value (bare number or decimal `Nn` string)
        // and step direction. Absent fields default to a zero-start counting-up
        // loop.
        const start: i64 = if (obj.get("start")) |v| switch (v) {
            .integer => |i| i,
            .string => |s| blk: {
                const text = if (s.len > 0 and s[s.len - 1] == 'n') s[0 .. s.len - 1] else s;
                break :blk std.fmt.parseInt(i64, text, 10) catch 0;
            },
            else => 0,
        } else 0;
        const step: i64 = if (obj.get("step")) |v| (if (v == .integer and v.integer < 0) @as(i64, -1) else 1) else 1;
        var body: std.ArrayListUnmanaged(ANFBinding) = .empty;
        if (obj.get("body")) |b| {
            if (b == .array) {
                for (b.array.items) |item| {
                    try body.append(allocator, try parseANFBinding(allocator, item));
                }
            }
        }
        return .{ .loop_node = .{
            .count = count,
            .iter_var = iter_var,
            .body = try body.toOwnedSlice(allocator),
            .start = start,
            .step = step,
        } };
    }
    // nop — skip
    if (std.mem.eql(u8, kind, "nop")) return .{ .unknown = {} };

    return .{ .unknown = {} };
}

fn parseJSONToANFValue(allocator: std.mem.Allocator, val: std.json.Value) error{OutOfMemory}!ANFValue {
    return switch (val) {
        .integer => |n| .{ .int = n },
        .bool => |b| .{ .boolean = b },
        .string => |s| blk: {
            // Handle BigInt strings like "42n"
            if (s.len > 0 and s[s.len - 1] == 'n') {
                if (std.fmt.parseInt(i64, s[0 .. s.len - 1], 10)) |n| {
                    break :blk .{ .int = n };
                } else |_| {}
            }
            // Plain numeric string
            if (std.fmt.parseInt(i64, s, 10)) |n| {
                break :blk .{ .int = n };
            } else |_| {}
            // Dupe the string — the source std.json.Parsed is deinit'd by the
            // caller, so we can't hold a slice into its arena.
            break :blk .{ .bytes = try allocator.dupe(u8, s) };
        },
        .float => |f| .{ .int = @intFromFloat(f) },
        else => .{ .none = {} },
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "computeNewState with simple increment" {
    const allocator = std.testing.allocator;

    // Build a simple Counter.increment() ANF:
    // load_prop count -> t0
    // load_const 1 -> t1
    // bin_op + t0 t1 -> t2
    // update_prop count t2

    var props = [_]ANFProperty{
        .{ .name = "count", .type_name = "int", .readonly = false },
    };
    var bindings = [_]ANFBinding{
        .{ .name = "t0", .value = .{ .load_prop = .{ .name = "count" } } },
        .{ .name = "t1", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
        .{ .name = "t2", .value = .{ .bin_op = .{ .op = "+", .left = "t0", .right = "t1", .result_type = "int" } } },
        .{ .name = "t3", .value = .{ .update_prop = .{ .name = "count", .value = "t2" } } },
    };
    var methods = [_]ANFMethod{
        .{ .name = "increment", .params = &.{}, .body = &bindings, .is_public = true },
    };
    const anf = ANFProgram{
        .contract_name = "Counter",
        .properties = &props,
        .methods = &methods,
    };

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("count", .{ .int = 5 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();

    var new_state = try computeNewState(allocator, &anf, "increment", current_state, args, &.{});
    defer new_state.deinit();

    const count = new_state.get("count").?;
    try std.testing.expectEqual(@as(i64, 6), count.int);
}

test "computeNewState with update_prop and if" {
    const allocator = std.testing.allocator;

    // Test that update_prop works correctly
    var props = [_]ANFProperty{
        .{ .name = "value", .type_name = "int", .readonly = false },
    };
    var bindings = [_]ANFBinding{
        .{ .name = "t0", .value = .{ .load_const = .{ .value = .{ .int = 42 } } } },
        .{ .name = "t1", .value = .{ .update_prop = .{ .name = "value", .value = "t0" } } },
    };
    var methods = [_]ANFMethod{
        .{ .name = "set", .params = &.{}, .body = &bindings, .is_public = true },
    };
    const anf = ANFProgram{
        .contract_name = "Test",
        .properties = &props,
        .methods = &methods,
    };

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("value", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();

    var new_state = try computeNewState(allocator, &anf, "set", current_state, args, &.{});
    defer new_state.deinit();

    const val = new_state.get("value").?;
    try std.testing.expectEqual(@as(i64, 42), val.int);
}

test "computeNewState returns error for unknown method" {
    const allocator = std.testing.allocator;

    const anf = ANFProgram{
        .contract_name = "Test",
        .properties = &.{},
        .methods = &.{},
    };

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();

    const result = computeNewState(allocator, &anf, "nonexistent", current_state, args, &.{});
    try std.testing.expectError(InterpreterError.MethodNotFound, result);
}

test "evalBinOp bytes concatenation" {
    const allocator = std.testing.allocator;
    const result = try evalBinOp(allocator, "+", .{ .bytes = "aabb" }, .{ .bytes = "ccdd" }, "bytes");
    switch (result) {
        .bytes => |b| {
            try std.testing.expectEqualStrings("aabbccdd", b);
            allocator.free(b);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "bigint bitwise/shift use script-number byte semantics (truth table)" {
    const H = struct {
        // Evaluate a bigint binary op through the interpreter, returning the
        // i64 result (or propagating the on-chain ABORT as error).
        fn bin(op: []const u8, a: i64, b: i64) !i64 {
            const r = try evalBinOp(std.testing.allocator, op, .{ .int = a }, .{ .int = b }, "int");
            return switch (r) {
                .int => |v| v,
                else => error.TestUnexpectedResult,
            };
        }
        fn un(op: []const u8, a: i64) i64 {
            const r = evalUnaryOp(std.testing.allocator, op, .{ .int = a }, "int");
            return switch (r) {
                .int => |v| v,
                else => 0,
            };
        }
    };

    // Shifts operate on the minimal script-number BYTES, not the numeric value.
    try std.testing.expectEqual(@as(i64, 254), try H.bin("<<", 255, 1)); // NOT 510
    try std.testing.expectEqual(@as(i64, 512), try H.bin("<<", 256, 1));
    try std.testing.expectEqual(@as(i64, 40), try H.bin("<<", 5, 3));
    try std.testing.expectEqual(@as(i64, 4), try H.bin(">>", 32, 3));
    try std.testing.expectEqual(@as(i64, -127), try H.bin(">>", 255, 1));

    // Bitwise NOT flips the operand's script-number bytes.
    try std.testing.expectEqual(@as(i64, -122), H.un("~", 5)); // NOT -6
    try std.testing.expectEqual(@as(i64, -32512), H.un("~", 255));
    try std.testing.expectEqual(@as(i64, 0), H.un("~", 0)); // encode(0) is empty

    // AND/OR/XOR require equal-length operands.
    try std.testing.expectEqual(@as(i64, 1), try H.bin("&", 5, 3));
    try std.testing.expectEqual(@as(i64, 1), try H.bin("&", -1, 5)); // NOT 5

    // Length mismatch / negative shift ABORT, exactly like the opcodes.
    try std.testing.expectError(error.ScriptNumberError, H.bin("&", 255, 1));
    try std.testing.expectError(error.ScriptNumberError, H.bin("|", 7, 0));
    try std.testing.expectError(error.ScriptNumberError, H.bin("<<", 5, -1));
}

test "chained bigint byte-ops thread raw stack bytes through the interpreter" {
    // A shift/bitwise RESULT is a fixed-length, possibly NON-minimal byte array
    // on-chain (`2 << 8` leaves a 1-byte `0x00`; minimal encoding of 0 is
    // empty). Feeding that result to a length-sensitive `& | ^`/shift/`~` must
    // see the REAL length, or the interpreter diverges from the deployed script
    // — a funds-relevant bug. These run through the full interpreter (evalNode +
    // the byte-op side map), unlike the single-op truth-table test above which
    // pins evalBinOp/evalUnaryOp directly.
    const allocator = std.testing.allocator;

    const H = struct {
        // Run a single public method whose body stores the chained result into
        // the mutable `result` property; return `result` (or propagate the
        // on-chain ScriptNumberError abort).
        fn run(a: std.mem.Allocator, body: []ANFBinding) !i64 {
            var props = [_]ANFProperty{
                .{ .name = "result", .type_name = "int", .readonly = false },
            };
            var methods = [_]ANFMethod{
                .{ .name = "run", .params = &.{}, .body = body, .is_public = true },
            };
            const anf = ANFProgram{
                .contract_name = "Chain",
                .properties = &props,
                .methods = &methods,
            };
            var cs = std.StringHashMap(ANFValue).init(a);
            defer cs.deinit();
            try cs.put("result", .{ .int = 0 });
            var args = std.StringHashMap(ANFValue).init(a);
            defer args.deinit();
            var ns = try computeNewState(a, &anf, "run", cs, args, &.{});
            defer ns.deinit();
            return ns.get("result").?.int;
        }
    };

    // (2 << 8) | 5 == 5   — on-chain OP_OR([0x00],[0x05]) = [0x05].
    // Buggy re-minimize path: OP_OR of empty-encoded-0 vs [0x05] length mismatch → abort.
    {
        var body = [_]ANFBinding{
            .{ .name = "c2", .value = .{ .load_const = .{ .value = .{ .int = 2 } } } },
            .{ .name = "c8", .value = .{ .load_const = .{ .value = .{ .int = 8 } } } },
            .{ .name = "sh", .value = .{ .bin_op = .{ .op = "<<", .left = "c2", .right = "c8", .result_type = "int" } } },
            .{ .name = "c5", .value = .{ .load_const = .{ .value = .{ .int = 5 } } } },
            .{ .name = "orr", .value = .{ .bin_op = .{ .op = "|", .left = "sh", .right = "c5", .result_type = "int" } } },
            .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "orr" } } },
        };
        try std.testing.expectEqual(@as(i64, 5), try H.run(allocator, &body));
    }

    // ~(2 << 8) == -127  — on-chain OP_INVERT([0x00]) = [0xff] = -127.
    // Buggy re-minimize path: ~0 with empty encoding → 0.
    {
        var body = [_]ANFBinding{
            .{ .name = "c2", .value = .{ .load_const = .{ .value = .{ .int = 2 } } } },
            .{ .name = "c8", .value = .{ .load_const = .{ .value = .{ .int = 8 } } } },
            .{ .name = "sh", .value = .{ .bin_op = .{ .op = "<<", .left = "c2", .right = "c8", .result_type = "int" } } },
            .{ .name = "inv", .value = .{ .unary_op = .{ .op = "~", .operand = "sh", .result_type = "int" } } },
            .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "inv" } } },
        };
        try std.testing.expectEqual(@as(i64, -127), try H.run(allocator, &body));
    }

    // (256 << 8) & 256 == 0  — both operands are 2-byte; OP_AND -> [0x00,0x00].
    {
        var body = [_]ANFBinding{
            .{ .name = "c256", .value = .{ .load_const = .{ .value = .{ .int = 256 } } } },
            .{ .name = "c8", .value = .{ .load_const = .{ .value = .{ .int = 8 } } } },
            .{ .name = "sh", .value = .{ .bin_op = .{ .op = "<<", .left = "c256", .right = "c8", .result_type = "int" } } },
            .{ .name = "andd", .value = .{ .bin_op = .{ .op = "&", .left = "sh", .right = "c256", .result_type = "int" } } },
            .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "andd" } } },
        };
        try std.testing.expectEqual(@as(i64, 0), try H.run(allocator, &body));
    }

    // ((1 << 8) & 0) ABORTS — on-chain OP_AND([0x00],[]) length mismatch.
    // The buggy re-minimize path computed 0 & 0 == 0 (a funds-loss spend).
    {
        var body = [_]ANFBinding{
            .{ .name = "c1", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "c8", .value = .{ .load_const = .{ .value = .{ .int = 8 } } } },
            .{ .name = "sh", .value = .{ .bin_op = .{ .op = "<<", .left = "c1", .right = "c8", .result_type = "int" } } },
            .{ .name = "c0", .value = .{ .load_const = .{ .value = .{ .int = 0 } } } },
            .{ .name = "andd", .value = .{ .bin_op = .{ .op = "&", .left = "sh", .right = "c0", .result_type = "int" } } },
            .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "andd" } } },
        };
        try std.testing.expectError(error.ScriptNumberError, H.run(allocator, &body));
    }
}

// ---------------------------------------------------------------------------
// NEW-006 — a byte-op's raw stack bytes must follow the value across an ALIAS.
//
// An ALIAS is a binding whose value IS another binding's stack slot: the
// `load_const "@ref:<name>"` every local rebind lowers to, an `if` adopting its
// taken arm's last value, a `loop` adopting its body's. The side map
// (EvalCtx.script_bytes) is keyed by the PRODUCING binding's name, so without an
// explicit carry the alias loses the width and the next length-sensitive op
// re-minimises the value — diverging from the deployed script. Port of the TS
// fix in packages/runar-sdk/src/anf-interpreter.ts (`aliasScriptBytes`).
// ---------------------------------------------------------------------------

/// Run `body` as the sole public method of a one-property contract and return
/// the final `result` (or propagate the on-chain ScriptNumberError abort).
fn runAliasBody(a: std.mem.Allocator, body: []ANFBinding) !i64 {
    var props = [_]ANFProperty{
        .{ .name = "result", .type_name = "int", .readonly = false },
    };
    var methods = [_]ANFMethod{
        .{ .name = "run", .params = &.{}, .body = body, .is_public = true },
    };
    const anf = ANFProgram{
        .contract_name = "Alias",
        .properties = &props,
        .methods = &methods,
    };
    var cs = std.StringHashMap(ANFValue).init(a);
    defer cs.deinit();
    try cs.put("result", .{ .int = 0 });
    var args = std.StringHashMap(ANFValue).init(a);
    defer args.deinit();
    var ns = try computeNewState(a, &anf, "run", cs, args, &.{});
    defer ns.deinit();
    return ns.get("result").?.int;
}

test "NEW-006 alias PROPAGATE — load_const @ref: carries the byte-op width" {
    // The shape a local rebind (`let m0 = 2n << 8n; m0 = m0 | 5n;`) lowers to.
    // On-chain: OP_OR([0x00],[0x05]) = [0x05] = 5.
    // Unfixed: `m0` has no side-map entry, so `2 << 8` re-minimises to the
    // EMPTY encoding of 0 and OP_OR aborts on the 0-vs-1 length mismatch.
    var body = [_]ANFBinding{
        .{ .name = "c2", .value = .{ .load_const = .{ .value = .{ .int = 2 } } } },
        .{ .name = "c8", .value = .{ .load_const = .{ .value = .{ .int = 8 } } } },
        .{ .name = "sh", .value = .{ .bin_op = .{ .op = "<<", .left = "c2", .right = "c8", .result_type = "int" } } },
        .{ .name = "m0", .value = .{ .load_const = .{ .value = .{ .bytes = "@ref:sh" } } } },
        .{ .name = "c5", .value = .{ .load_const = .{ .value = .{ .int = 5 } } } },
        .{ .name = "orr", .value = .{ .bin_op = .{ .op = "|", .left = "m0", .right = "c5", .result_type = "int" } } },
        .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "orr" } } },
    };
    try std.testing.expectEqual(@as(i64, 5), try runAliasBody(std.testing.allocator, &body));
}

test "NEW-006 alias CLEAR — a re-bound name must not inherit a dead width" {
    // `m0` is re-bound to an alias of a plain `load_const 300`, so its slot now
    // holds the minimal 2-byte [0x2c,0x01]; the stale 1-byte [0x00] left by the
    // earlier `2 << 8` binding of the SAME name must NOT be read as its width.
    // On-chain: OP_AND([0x2c,0x01],[0xff,0x00]) = [0x2c,0x00] = 44.
    //
    // HONEST NOTE: this case PASSES against the unfixed interpreter — nothing
    // keys the side map by a re-bound name yet, so the lookup already misses.
    // It is here as the guard that makes a COPY-ONLY fix go RED: copy-only
    // leaves the dead [0x00] under "m0" and OP_AND then aborts on a 1-vs-2
    // length mismatch. In TS the same shape against a 1-byte second operand
    // yields a silently WRONG value rather than an abort — the worse failure
    // the clear half exists to prevent.
    var body = [_]ANFBinding{
        .{ .name = "c2", .value = .{ .load_const = .{ .value = .{ .int = 2 } } } },
        .{ .name = "c8", .value = .{ .load_const = .{ .value = .{ .int = 8 } } } },
        .{ .name = "sh", .value = .{ .bin_op = .{ .op = "<<", .left = "c2", .right = "c8", .result_type = "int" } } },
        .{ .name = "m0", .value = .{ .load_const = .{ .value = .{ .bytes = "@ref:sh" } } } },
        .{ .name = "c300", .value = .{ .load_const = .{ .value = .{ .int = 300 } } } },
        .{ .name = "m0", .value = .{ .load_const = .{ .value = .{ .bytes = "@ref:c300" } } } },
        .{ .name = "c255", .value = .{ .load_const = .{ .value = .{ .int = 255 } } } },
        .{ .name = "andd", .value = .{ .bin_op = .{ .op = "&", .left = "m0", .right = "c255", .result_type = "int" } } },
        .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "andd" } } },
    };
    try std.testing.expectEqual(@as(i64, 44), try runAliasBody(std.testing.allocator, &body));
}

test "NEW-006 alias PROPAGATE — an `if` adopts its taken arm's byte-op width" {
    // The taken arm ends in `2 << 8`; the `if` binding adopts that slot.
    var then_branch = [_]ANFBinding{
        .{ .name = "c2", .value = .{ .load_const = .{ .value = .{ .int = 2 } } } },
        .{ .name = "c8", .value = .{ .load_const = .{ .value = .{ .int = 8 } } } },
        .{ .name = "sh", .value = .{ .bin_op = .{ .op = "<<", .left = "c2", .right = "c8", .result_type = "int" } } },
    };
    var else_branch = [_]ANFBinding{
        .{ .name = "z", .value = .{ .load_const = .{ .value = .{ .int = 0 } } } },
    };
    var body = [_]ANFBinding{
        .{ .name = "cond", .value = .{ .load_const = .{ .value = .{ .boolean = true } } } },
        .{ .name = "iv", .value = .{ .if_node = .{ .cond = "cond", .then_branch = &then_branch, .else_branch = &else_branch } } },
        .{ .name = "c5", .value = .{ .load_const = .{ .value = .{ .int = 5 } } } },
        .{ .name = "orr", .value = .{ .bin_op = .{ .op = "|", .left = "iv", .right = "c5", .result_type = "int" } } },
        .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "orr" } } },
    };
    try std.testing.expectEqual(@as(i64, 5), try runAliasBody(std.testing.allocator, &body));
}

test "NEW-006 alias PROPAGATE — a `loop` adopts its body's byte-op width" {
    // The body's last binding is `2 << 8`; the loop binding adopts it.
    var loop_body = [_]ANFBinding{
        .{ .name = "c2", .value = .{ .load_const = .{ .value = .{ .int = 2 } } } },
        .{ .name = "c8", .value = .{ .load_const = .{ .value = .{ .int = 8 } } } },
        .{ .name = "sh", .value = .{ .bin_op = .{ .op = "<<", .left = "c2", .right = "c8", .result_type = "int" } } },
    };
    var body = [_]ANFBinding{
        .{ .name = "lv", .value = .{ .loop_node = .{ .count = 1, .iter_var = "i", .body = &loop_body } } },
        .{ .name = "c5", .value = .{ .load_const = .{ .value = .{ .int = 5 } } } },
        .{ .name = "orr", .value = .{ .bin_op = .{ .op = "|", .left = "lv", .right = "c5", .result_type = "int" } } },
        .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "orr" } } },
    };
    try std.testing.expectEqual(@as(i64, 5), try runAliasBody(std.testing.allocator, &body));
}

// NEW-013 — `num2bin` sign-bit placement.
//
// The ANF interpreter models what the DEPLOYED SCRIPT computes. For negative
// values it used to set the sign bit on the last MAGNITUDE byte and pad zeros
// AFTER it, so `num2bin(-1, 2)` came out `8100` where OP_NUM2BIN yields `0180`.
// Those bytes go into the call transaction, so a legal method built a
// continuation the script rejects.
//
// Every expectation below is the output of OP_NUM2BIN on the real `@bsv/sdk`
// Spend interpreter, derived by
// `conformance/anf-interpreter/num2bin-engine-parity.test.ts`, which re-runs
// the engine live rather than trusting a table. Do NOT re-stamp these from this
// implementation's own output — that is precisely how six of seven SDKs agreed
// on the wrong answer.
test "num2bin matches OP_NUM2BIN" {
    const allocator = std.testing.allocator;

    const Case = struct { n: i64, byte_len: usize, want: []const u8, why: []const u8 };
    const cases = [_]Case{
        // Negative, padded — the NEW-013 corner. The sign bit belongs on the
        // byte that is most significant AFTER padding, not before it.
        .{ .n = -1, .byte_len = 2, .want = "0180", .why = "negative padded" },
        .{ .n = -1, .byte_len = 4, .want = "01000080", .why = "negative padded" },
        .{ .n = -1, .byte_len = 8, .want = "0100000000000080", .why = "negative padded" },
        .{ .n = -5, .byte_len = 4, .want = "05000080", .why = "negative padded" },
        .{ .n = -1000, .byte_len = 4, .want = "e8030080", .why = "negative padded" },
        .{ .n = -1000, .byte_len = 8, .want = "e803000000000080", .why = "negative padded" },
        .{ .n = -255, .byte_len = 3, .want = "ff0080", .why = "negative padded" },
        .{ .n = -256, .byte_len = 3, .want = "000180", .why = "negative padded" },
        // Negative, exact width — the minimal encoding already fills the field,
        // so it is pushed unchanged and the sign bit does not move.
        .{ .n = -1, .byte_len = 1, .want = "81", .why = "negative exact width" },
        .{ .n = -127, .byte_len = 1, .want = "ff", .why = "negative exact width" },
        .{ .n = -1000, .byte_len = 2, .want = "e883", .why = "negative exact width" },
        .{ .n = -256, .byte_len = 2, .want = "0081", .why = "negative exact width" },
        // Negative, sign-bit carry — the top magnitude byte already uses bit 7,
        // so the minimal encoding grows a byte before any padding happens.
        .{ .n = -128, .byte_len = 2, .want = "8080", .why = "negative carry, exact" },
        .{ .n = -128, .byte_len = 3, .want = "800080", .why = "negative carry, padded" },
        .{ .n = -128, .byte_len = 8, .want = "8000000000000080", .why = "negative carry, padded" },
        .{ .n = -32768, .byte_len = 3, .want = "008080", .why = "negative carry, exact" },
        .{ .n = -32768, .byte_len = 4, .want = "00800080", .why = "negative carry, padded" },
        // Positive at the same widths — must be untouched by the fix.
        .{ .n = 1, .byte_len = 1, .want = "01", .why = "positive exact width" },
        .{ .n = 1, .byte_len = 2, .want = "0100", .why = "positive padded" },
        .{ .n = 1, .byte_len = 8, .want = "0100000000000000", .why = "positive padded" },
        .{ .n = 1000, .byte_len = 2, .want = "e803", .why = "positive exact width" },
        .{ .n = 1000, .byte_len = 4, .want = "e8030000", .why = "positive padded" },
        .{ .n = 1000, .byte_len = 8, .want = "e803000000000000", .why = "positive padded" },
        .{ .n = 127, .byte_len = 1, .want = "7f", .why = "positive exact width" },
        .{ .n = 128, .byte_len = 2, .want = "8000", .why = "positive carry, exact" },
        .{ .n = 128, .byte_len = 3, .want = "800000", .why = "positive carry, padded" },
        .{ .n = 255, .byte_len = 2, .want = "ff00", .why = "positive carry, exact" },
        // Zero — an all-zero field, no sign bit anywhere.
        .{ .n = 0, .byte_len = 1, .want = "00", .why = "zero" },
        .{ .n = 0, .byte_len = 4, .want = "00000000", .why = "zero" },
        .{ .n = 0, .byte_len = 8, .want = "0000000000000000", .why = "zero" },
    };

    for (cases) |c| {
        const got = num2binHex(allocator, c.n, c.byte_len);
        switch (got) {
            .bytes => |hex| {
                defer allocator.free(hex);
                std.testing.expectEqualStrings(c.want, hex) catch |err| {
                    std.debug.print("num2bin({d}, {d}) [{s}]\n", .{ c.n, c.byte_len, c.why });
                    return err;
                };
            },
            else => return error.TestUnexpectedResult,
        }
    }

    // Non-vacuity: this table only earns its keep if it can see the pre-fix
    // answer. `8100` is exactly what this function used to return.
    const pre_fix = num2binHex(allocator, -1, 2);
    switch (pre_fix) {
        .bytes => |hex| {
            defer allocator.free(hex);
            try std.testing.expect(!std.mem.eql(u8, hex, "8100"));
        },
        else => return error.TestUnexpectedResult,
    }
}

// bin2num is this interpreter's own inverse, so this proves only
// self-consistency — it passed throughout the NEW-013 bug and is the reason
// nothing here saw it. Kept as a smoke test; "num2bin matches OP_NUM2BIN"
// above is the evidence.
test "num2bin and bin2num roundtrip (smoke test only, NOT the evidence)" {
    const allocator = std.testing.allocator;

    // num2bin(42, 4) -> hex LE with 4 bytes
    const result = num2binHex(allocator, 42, 4);
    switch (result) {
        .bytes => |hex| {
            try std.testing.expectEqual(@as(usize, 8), hex.len); // 4 bytes * 2 hex chars
            // bin2num should recover the original value
            const recovered = bin2numInt(hex);
            try std.testing.expectEqual(@as(i64, 42), recovered);
            allocator.free(hex);
        },
        else => return error.TestUnexpectedResult,
    }

    // num2bin(-5, 4) -> negative number
    const neg_result = num2binHex(allocator, -5, 4);
    switch (neg_result) {
        .bytes => |hex| {
            const recovered = bin2numInt(hex);
            try std.testing.expectEqual(@as(i64, -5), recovered);
            allocator.free(hex);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseANFFromJson simple counter" {
    const allocator = std.testing.allocator;

    const json =
        \\{"contractName":"Counter","properties":[{"name":"count","type":"bigint","readonly":false}],
        \\"methods":[{"name":"increment","params":[],"body":[
        \\{"name":"t0","value":{"kind":"load_prop","name":"count"}},
        \\{"name":"t1","value":{"kind":"load_const","value":1}},
        \\{"name":"t2","value":{"kind":"bin_op","op":"+","left":"t0","right":"t1"}},
        \\{"name":"t3","value":{"kind":"update_prop","name":"count","value":"t2"}}
        \\],"isPublic":true}]}
    ;

    // Use arena for parsing (parsed data references the arena)
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const program = try parseANFFromJson(arena.allocator(), json);

    try std.testing.expectEqualStrings("Counter", program.contract_name);
    try std.testing.expectEqual(@as(usize, 1), program.properties.len);
    try std.testing.expectEqualStrings("count", program.properties[0].name);
    try std.testing.expectEqual(@as(usize, 1), program.methods.len);
    try std.testing.expectEqualStrings("increment", program.methods[0].name);
    try std.testing.expect(program.methods[0].is_public);
    try std.testing.expectEqual(@as(usize, 4), program.methods[0].body.len);
}

// ---------------------------------------------------------------------------
// Strict-mode tests
//
// Mirror the TS spec at packages/runar-sdk/src/__tests__/anf-interpreter-strict.spec.ts:
// the same Guard contract + bump(amount) shape with two asserts. Lenient mode
// must accept all inputs (the canonical pre-broadcast simulation behaviour);
// strict mode must surface failed asserts as `error.AssertionFailure`.
// ---------------------------------------------------------------------------

fn buildGuardAnf() ANFProgram {
    const props = struct {
        var p = [_]ANFProperty{
            .{ .name = "value", .type_name = "int", .readonly = false },
        };
    };
    const params = struct {
        var p = [_]ANFParam{
            .{ .name = "amount", .type_name = "int" },
        };
    };
    const body = struct {
        var b = [_]ANFBinding{
            // assert(amount > 0)
            .{ .name = "t0", .value = .{ .load_param = .{ .name = "amount" } } },
            .{ .name = "t1", .value = .{ .load_const = .{ .value = .{ .int = 0 } } } },
            .{ .name = "t2", .value = .{ .bin_op = .{ .op = ">", .left = "t0", .right = "t1", .result_type = "bool" } } },
            .{ .name = "assertPositive", .value = .{ .assert_node = .{ .value = "t2" } } },
            // assert(amount < 1000)
            .{ .name = "t3", .value = .{ .load_const = .{ .value = .{ .int = 1000 } } } },
            .{ .name = "t4", .value = .{ .bin_op = .{ .op = "<", .left = "t0", .right = "t3", .result_type = "bool" } } },
            .{ .name = "assertBounded", .value = .{ .assert_node = .{ .value = "t4" } } },
            // value = value + amount
            .{ .name = "t5", .value = .{ .load_prop = .{ .name = "value" } } },
            .{ .name = "t6", .value = .{ .bin_op = .{ .op = "+", .left = "t5", .right = "t0", .result_type = "int" } } },
            .{ .name = "t7", .value = .{ .update_prop = .{ .name = "value", .value = "t6" } } },
        };
    };
    const methods = struct {
        var m = [_]ANFMethod{
            .{ .name = "bump", .params = &params.p, .body = &body.b, .is_public = true },
        };
    };
    return .{
        .contract_name = "Guard",
        .properties = &props.p,
        .methods = &methods.m,
    };
}

test "executeStrict — lenient computeNewState passes when assert would fail" {
    const allocator = std.testing.allocator;
    const anf = buildGuardAnf();

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("value", .{ .int = 10 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();
    try args.put("amount", .{ .int = 0 }); // would fail assert(amount > 0)

    var new_state = try computeNewState(allocator, &anf, "bump", current_state, args, &.{});
    defer new_state.deinit();

    // Lenient: assert is skipped, value still mutates to 10 + 0 = 10.
    try std.testing.expectEqual(@as(i64, 10), new_state.get("value").?.int);
}

test "executeStrict — strict mode passes for valid input" {
    const allocator = std.testing.allocator;
    const anf = buildGuardAnf();

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("value", .{ .int = 10 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();
    try args.put("amount", .{ .int = 5 });

    const result = try executeStrict(allocator, &anf, "bump", current_state, args, &.{});
    var state = result.state;
    defer state.deinit();
    defer {
        for (result.data_outputs) |d| allocator.free(d.script);
        allocator.free(result.data_outputs);
        for (result.raw_outputs) |d| allocator.free(d.script);
        allocator.free(result.raw_outputs);
    }

    try std.testing.expectEqual(@as(i64, 15), state.get("value").?.int);
    try std.testing.expectEqual(@as(usize, 0), result.data_outputs.len);
}

test "executeStrict — strict mode returns AssertionFailure on first failing assert" {
    const allocator = std.testing.allocator;
    const anf = buildGuardAnf();

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("value", .{ .int = 10 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();
    try args.put("amount", .{ .int = 0 }); // fails assert(amount > 0)

    const result = executeStrict(allocator, &anf, "bump", current_state, args, &.{});
    try std.testing.expectError(StrictError.AssertionFailure, result);
}

test "executeStrict — strict mode returns AssertionFailure on second failing assert" {
    const allocator = std.testing.allocator;
    const anf = buildGuardAnf();

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("value", .{ .int = 10 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();
    try args.put("amount", .{ .int = 5000 }); // fails assert(amount < 1000)

    const result = executeStrict(allocator, &anf, "bump", current_state, args, &.{});
    try std.testing.expectError(StrictError.AssertionFailure, result);
}

test "executeStrict — crypto mocks (checkSig/checkMultiSig/checkPreimage) still return true in strict" {
    // P2PKH-style guard: assert(checkSig(sig, pk)). Strict mode keeps
    // checkSig mocked, so any sig+pk pair passes — strict only enforces
    // explicit assert predicates, never crypto. Mirrors the TS spec's
    // "strict mode does NOT verify signatures" test.
    const allocator = std.testing.allocator;

    const props = struct {
        var p = [_]ANFProperty{
            .{ .name = "value", .type_name = "int", .readonly = false },
        };
    };
    const params = struct {
        var p = [_]ANFParam{
            .{ .name = "sig", .type_name = "bytes" },
            .{ .name = "pk", .type_name = "bytes" },
        };
    };
    var sig_args = [_][]const u8{ "sigArg", "pkArg" };
    const body = struct {
        var b: [6]ANFBinding = undefined;
    };
    body.b = [_]ANFBinding{
        .{ .name = "sigArg", .value = .{ .load_param = .{ .name = "sig" } } },
        .{ .name = "pkArg", .value = .{ .load_param = .{ .name = "pk" } } },
        .{ .name = "sigOk", .value = .{ .call = .{ .func = "checkSig", .args = &sig_args } } },
        .{ .name = "assertSig", .value = .{ .assert_node = .{ .value = "sigOk" } } },
        .{ .name = "one", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
        .{ .name = "upd", .value = .{ .update_prop = .{ .name = "value", .value = "one" } } },
    };
    const methods = struct {
        var m: [1]ANFMethod = undefined;
    };
    methods.m = [_]ANFMethod{
        .{ .name = "unlock", .params = &params.p, .body = &body.b, .is_public = true },
    };
    const anf = ANFProgram{
        .contract_name = "SigGuard",
        .properties = &props.p,
        .methods = &methods.m,
    };

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("value", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();
    try args.put("sig", .{ .bytes = "deadbeef" });
    try args.put("pk", .{ .bytes = "cafebabe" });

    const result = try executeStrict(allocator, &anf, "unlock", current_state, args, &.{});
    var state = result.state;
    defer state.deinit();
    defer {
        for (result.data_outputs) |d| allocator.free(d.script);
        allocator.free(result.data_outputs);
        for (result.raw_outputs) |d| allocator.free(d.script);
        allocator.free(result.raw_outputs);
    }

    // checkSig mocked to true → strict assert passes → value mutates to 1.
    try std.testing.expectEqual(@as(i64, 1), state.get("value").?.int);
}

test "executeStrict — strict mode evaluates call(assert, ...) lowering" {
    // Some lowering paths emit `call(assert, predicateRef)` rather than the
    // dedicated `assert` ANF node. Strict mode covers both. Mirrors the
    // TS spec's "strict mode evaluates assert built-in call" test.
    const allocator = std.testing.allocator;

    const props = struct {
        var p = [_]ANFProperty{
            .{ .name = "value", .type_name = "int", .readonly = false },
        };
    };
    const params = struct {
        var p = [_]ANFParam{
            .{ .name = "flag", .type_name = "bool" },
        };
    };
    var call_args = [_][]const u8{"arg"};
    const body = struct {
        var b: [4]ANFBinding = undefined;
    };
    body.b = [_]ANFBinding{
        .{ .name = "arg", .value = .{ .load_param = .{ .name = "flag" } } },
        .{ .name = "callAssert", .value = .{ .call = .{ .func = "assert", .args = &call_args } } },
        .{ .name = "one", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
        .{ .name = "upd", .value = .{ .update_prop = .{ .name = "value", .value = "one" } } },
    };
    const methods = struct {
        var m: [1]ANFMethod = undefined;
    };
    methods.m = [_]ANFMethod{
        .{ .name = "check", .params = &params.p, .body = &body.b, .is_public = true },
    };
    const anf = ANFProgram{
        .contract_name = "CallAssert",
        .properties = &props.p,
        .methods = &methods.m,
    };

    // Lenient ignores the failing predicate.
    {
        var cs = std.StringHashMap(ANFValue).init(allocator);
        defer cs.deinit();
        try cs.put("value", .{ .int = 0 });
        var ar = std.StringHashMap(ANFValue).init(allocator);
        defer ar.deinit();
        try ar.put("flag", .{ .boolean = false });
        var ns = try computeNewState(allocator, &anf, "check", cs, ar, &.{});
        defer ns.deinit();
        try std.testing.expectEqual(@as(i64, 1), ns.get("value").?.int);
    }

    // Strict throws on falsy flag.
    {
        var cs = std.StringHashMap(ANFValue).init(allocator);
        defer cs.deinit();
        try cs.put("value", .{ .int = 0 });
        var ar = std.StringHashMap(ANFValue).init(allocator);
        defer ar.deinit();
        try ar.put("flag", .{ .boolean = false });
        const result = executeStrict(allocator, &anf, "check", cs, ar, &.{});
        try std.testing.expectError(StrictError.AssertionFailure, result);
    }

    // Strict passes on truthy flag.
    {
        var cs = std.StringHashMap(ANFValue).init(allocator);
        defer cs.deinit();
        try cs.put("value", .{ .int = 0 });
        var ar = std.StringHashMap(ANFValue).init(allocator);
        defer ar.deinit();
        try ar.put("flag", .{ .boolean = true });
        const result = try executeStrict(allocator, &anf, "check", cs, ar, &.{});
        var state = result.state;
        defer state.deinit();
        defer {
            for (result.data_outputs) |d| allocator.free(d.script);
            allocator.free(result.data_outputs);
            for (result.raw_outputs) |d| allocator.free(d.script);
            allocator.free(result.raw_outputs);
        }
        try std.testing.expectEqual(@as(i64, 1), state.get("value").?.int);
    }
}

// ---------------------------------------------------------------------------
// Real-crypto mode tests (executeOnChainAuthoritative)
//
// Mirror packages/runar-sdk/src/__tests__/anf-interpreter-real-crypto.spec.ts:
// the same P2PKH-like Guard contract + checkPreimage guard, with a real
// secp256k1 sign/verify round-trip and a real hash256-preimage round-trip.
// Lenient + strict suites (above) must not regress; the new mode is opt-in
// via `executeOnChainAuthoritative` and requires a 32-byte sighash.
// ---------------------------------------------------------------------------

fn buildSigGuardAnf() ANFProgram {
    const props = struct {
        var p = [_]ANFProperty{
            .{ .name = "value", .type_name = "int", .readonly = false },
        };
    };
    const params = struct {
        var p = [_]ANFParam{
            .{ .name = "sig", .type_name = "bytes" },
            .{ .name = "pk", .type_name = "bytes" },
        };
    };
    const sig_args = struct {
        var a = [_][]const u8{ "sigArg", "pkArg" };
    };
    const body = struct {
        var b: [6]ANFBinding = undefined;
    };
    body.b = [_]ANFBinding{
        .{ .name = "sigArg", .value = .{ .load_param = .{ .name = "sig" } } },
        .{ .name = "pkArg", .value = .{ .load_param = .{ .name = "pk" } } },
        .{ .name = "sigOk", .value = .{ .call = .{ .func = "checkSig", .args = &sig_args.a } } },
        .{ .name = "assertSig", .value = .{ .assert_node = .{ .value = "sigOk" } } },
        .{ .name = "one", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
        .{ .name = "upd", .value = .{ .update_prop = .{ .name = "value", .value = "one" } } },
    };
    const methods = struct {
        var m: [1]ANFMethod = undefined;
    };
    methods.m = [_]ANFMethod{
        .{ .name = "unlock", .params = &params.p, .body = &body.b, .is_public = true },
    };
    return .{
        .contract_name = "SigGuard",
        .properties = &props.p,
        .methods = &methods.m,
    };
}

fn buildPreimageGuardAnf() ANFProgram {
    const props = struct {
        var p = [_]ANFProperty{
            .{ .name = "value", .type_name = "int", .readonly = false },
        };
    };
    const params = struct {
        var p = [_]ANFParam{
            .{ .name = "preimage", .type_name = "bytes" },
        };
    };
    const call_args = struct {
        var a = [_][]const u8{"preArg"};
    };
    const body = struct {
        var b: [5]ANFBinding = undefined;
    };
    body.b = [_]ANFBinding{
        .{ .name = "preArg", .value = .{ .load_param = .{ .name = "preimage" } } },
        .{ .name = "preOk", .value = .{ .call = .{ .func = "checkPreimage", .args = &call_args.a } } },
        .{ .name = "assertPre", .value = .{ .assert_node = .{ .value = "preOk" } } },
        .{ .name = "one", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
        .{ .name = "upd", .value = .{ .update_prop = .{ .name = "value", .value = "one" } } },
    };
    const methods = struct {
        var m: [1]ANFMethod = undefined;
    };
    methods.m = [_]ANFMethod{
        .{ .name = "unlock", .params = &params.p, .body = &body.b, .is_public = true },
    };
    return .{
        .contract_name = "PreimageGuard",
        .properties = &props.p,
        .methods = &methods.m,
    };
}

/// Compute a deterministic 32-byte digest used as the test sighash.
fn deterministicSighash() [32]u8 {
    const msg = "runar-zig-anf-real-crypto-test";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
    return digest;
}

/// Hex-encode a byte buffer into a caller-allocated buffer (lowercase).
fn hexEncode(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    _ = try bsvz.primitives.hex.encodeLower(bytes, out);
    return out;
}

test "executeOnChainAuthoritative — checkSig passes with a real signature" {
    const allocator = std.testing.allocator;
    const anf = buildSigGuardAnf();

    const sighash = deterministicSighash();
    var priv_bytes: [32]u8 = undefined;
    @memset(&priv_bytes, 0xaa);
    priv_bytes[0] = 0x01; // ensure non-zero, well within range
    const priv = try bsvz.crypto.PrivateKey.fromBytes(priv_bytes);
    const pub_key = try priv.publicKey();
    const sig = try priv.signDigest256(sighash);

    const sig_hex = try hexEncode(allocator, sig.asSlice());
    defer allocator.free(sig_hex);
    const pk_hex = try hexEncode(allocator, &pub_key.bytes);
    defer allocator.free(pk_hex);

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("value", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();
    try args.put("sig", .{ .bytes = sig_hex });
    try args.put("pk", .{ .bytes = pk_hex });

    const result = try executeOnChainAuthoritative(
        allocator, &anf, "unlock", current_state, args, &.{},
        .{ .sighash = sighash },
    );
    var state = result.state;
    defer state.deinit();
    defer {
        for (result.data_outputs) |d| allocator.free(d.script);
        allocator.free(result.data_outputs);
        for (result.raw_outputs) |d| allocator.free(d.script);
        allocator.free(result.raw_outputs);
    }
    try std.testing.expectEqual(@as(i64, 1), state.get("value").?.int);
}

test "executeOnChainAuthoritative — checkSig fails with a corrupted signature" {
    const allocator = std.testing.allocator;
    const anf = buildSigGuardAnf();

    const sighash = deterministicSighash();
    var priv_bytes: [32]u8 = undefined;
    @memset(&priv_bytes, 0xaa);
    priv_bytes[0] = 0x01;
    const priv = try bsvz.crypto.PrivateKey.fromBytes(priv_bytes);
    const pub_key = try priv.publicKey();
    const sig = try priv.signDigest256(sighash);

    var sig_bytes_buf: [128]u8 = undefined;
    @memcpy(sig_bytes_buf[0..sig.asSlice().len], sig.asSlice());
    const sig_slice = sig_bytes_buf[0..sig.asSlice().len];
    sig_slice[sig_slice.len - 1] ^= 0xff; // corrupt the last byte of S

    const sig_hex = try hexEncode(allocator, sig_slice);
    defer allocator.free(sig_hex);
    const pk_hex = try hexEncode(allocator, &pub_key.bytes);
    defer allocator.free(pk_hex);

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("value", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();
    try args.put("sig", .{ .bytes = sig_hex });
    try args.put("pk", .{ .bytes = pk_hex });

    const result = executeOnChainAuthoritative(
        allocator, &anf, "unlock", current_state, args, &.{},
        .{ .sighash = sighash },
    );
    try std.testing.expectError(StrictError.AssertionFailure, result);
}

test "executeOnChainAuthoritative — checkPreimage passes when hash256(preimage) == sighash" {
    const allocator = std.testing.allocator;
    const anf = buildPreimageGuardAnf();

    // Pick an arbitrary preimage and derive its hash256 as the matching
    // sighash. Pre-broadcast simulation: caller knows both the preimage
    // they'll push on the stack and the on-chain sighash that must equal
    // hash256(preimage).
    const preimage_bytes = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe };
    var first: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&preimage_bytes, &first, .{});
    var sighash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&first, &sighash, .{});

    const pre_hex = try hexEncode(allocator, &preimage_bytes);
    defer allocator.free(pre_hex);

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("value", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();
    try args.put("preimage", .{ .bytes = pre_hex });

    const result = try executeOnChainAuthoritative(
        allocator, &anf, "unlock", current_state, args, &.{},
        .{ .sighash = sighash },
    );
    var state = result.state;
    defer state.deinit();
    defer {
        for (result.data_outputs) |d| allocator.free(d.script);
        allocator.free(result.data_outputs);
        for (result.raw_outputs) |d| allocator.free(d.script);
        allocator.free(result.raw_outputs);
    }
    try std.testing.expectEqual(@as(i64, 1), state.get("value").?.int);
}

test "executeOnChainAuthoritative — checkPreimage fails with the wrong preimage" {
    const allocator = std.testing.allocator;
    const anf = buildPreimageGuardAnf();

    const preimage_bytes = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var first: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&preimage_bytes, &first, .{});
    var sighash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&first, &sighash, .{});

    // Hand the interpreter a different preimage — its hash256 won't match
    // the supplied sighash, so checkPreimage returns false and the assert
    // trips.
    const wrong_pre = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const wrong_hex = try hexEncode(allocator, &wrong_pre);
    defer allocator.free(wrong_hex);

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("value", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();
    try args.put("preimage", .{ .bytes = wrong_hex });

    const result = executeOnChainAuthoritative(
        allocator, &anf, "unlock", current_state, args, &.{},
        .{ .sighash = sighash },
    );
    try std.testing.expectError(StrictError.AssertionFailure, result);
}

test "executeOnChainAuthoritative — lenient + strict modes still mock checkSig" {
    // Sanity check: lenient and strict (without real_crypto) MUST keep
    // mocking checkSig so the existing 35-test SDK test surface doesn't
    // regress when the new mode lands.
    const allocator = std.testing.allocator;
    const anf = buildSigGuardAnf();

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("value", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();
    try args.put("sig", .{ .bytes = "deadbeef" });
    try args.put("pk", .{ .bytes = "cafebabe" });

    // Lenient: no asserts enforced, value still mutates.
    {
        var ns = try computeNewState(allocator, &anf, "unlock", current_state, args, &.{});
        defer ns.deinit();
        try std.testing.expectEqual(@as(i64, 1), ns.get("value").?.int);
    }

    // Strict (no real_crypto): assert(checkSig(...)) — checkSig still
    // mock-true, so the assert holds and value mutates.
    {
        const r = try executeStrict(allocator, &anf, "unlock", current_state, args, &.{});
        var state = r.state;
        defer state.deinit();
        defer {
            for (r.data_outputs) |d| allocator.free(d.script);
            allocator.free(r.data_outputs);
            for (r.raw_outputs) |d| allocator.free(d.script);
            allocator.free(r.raw_outputs);
        }
        try std.testing.expectEqual(@as(i64, 1), state.get("value").?.int);
    }
}

// ---------------------------------------------------------------------------
// Multisig real-crypto tests.
//
// `buildMultiSigGuardAnf` constructs an ANF body that loads `sig0`, `pk0`,
// `pk1` from method params, builds two `array_literal` bindings (`sigsArr`,
// `pksArr`), passes them to `checkMultiSig`, and asserts the result.
// 1-of-2: the lone `sig0` must verify against `pk0` OR `pk1`. With the
// real-crypto path enabled, the iteration is left-to-right: try sig0 vs
// pk0, advance pk_idx, try sig0 vs pk1, etc. (mirrors OP_CHECKMULTISIG).
// ---------------------------------------------------------------------------

fn buildMultiSigGuardAnf() ANFProgram {
    const props = struct {
        var p = [_]ANFProperty{
            .{ .name = "value", .type_name = "int", .readonly = false },
        };
    };
    const params = struct {
        var p = [_]ANFParam{
            .{ .name = "sig0", .type_name = "bytes" },
            .{ .name = "pk0", .type_name = "bytes" },
            .{ .name = "pk1", .type_name = "bytes" },
        };
    };
    const sigs_elems = struct {
        var e = [_][]const u8{"sig0Arg"};
    };
    const pks_elems = struct {
        var e = [_][]const u8{ "pk0Arg", "pk1Arg" };
    };
    const multi_args = struct {
        var a = [_][]const u8{ "sigsArr", "pksArr" };
    };
    const body = struct {
        var b: [9]ANFBinding = undefined;
    };
    body.b = [_]ANFBinding{
        .{ .name = "sig0Arg", .value = .{ .load_param = .{ .name = "sig0" } } },
        .{ .name = "pk0Arg", .value = .{ .load_param = .{ .name = "pk0" } } },
        .{ .name = "pk1Arg", .value = .{ .load_param = .{ .name = "pk1" } } },
        .{ .name = "sigsArr", .value = .{ .array_literal = .{ .elements = &sigs_elems.e } } },
        .{ .name = "pksArr", .value = .{ .array_literal = .{ .elements = &pks_elems.e } } },
        .{ .name = "multiOk", .value = .{ .call = .{ .func = "checkMultiSig", .args = &multi_args.a } } },
        .{ .name = "assertMulti", .value = .{ .assert_node = .{ .value = "multiOk" } } },
        .{ .name = "one", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
        .{ .name = "upd", .value = .{ .update_prop = .{ .name = "value", .value = "one" } } },
    };
    const methods = struct {
        var m: [1]ANFMethod = undefined;
    };
    methods.m = [_]ANFMethod{
        .{ .name = "unlock", .params = &params.p, .body = &body.b, .is_public = true },
    };
    return .{
        .contract_name = "MultiSigGuard",
        .properties = &props.p,
        .methods = &methods.m,
    };
}

test "executeOnChainAuthoritative — checkMultiSig 1-of-2 passes when sig matches second pk" {
    const allocator = std.testing.allocator;
    const anf = buildMultiSigGuardAnf();

    const sighash = deterministicSighash();

    // Two keys: priv0 unrelated, priv1 the actual signer.
    var priv0_bytes: [32]u8 = undefined;
    @memset(&priv0_bytes, 0x11);
    priv0_bytes[0] = 0x01;
    var priv1_bytes: [32]u8 = undefined;
    @memset(&priv1_bytes, 0x22);
    priv1_bytes[0] = 0x01;
    const priv0 = try bsvz.crypto.PrivateKey.fromBytes(priv0_bytes);
    const priv1 = try bsvz.crypto.PrivateKey.fromBytes(priv1_bytes);
    const pub0 = try priv0.publicKey();
    const pub1 = try priv1.publicKey();
    const sig1 = try priv1.signDigest256(sighash);

    const sig1_hex = try hexEncode(allocator, sig1.asSlice());
    defer allocator.free(sig1_hex);
    const pk0_hex = try hexEncode(allocator, &pub0.bytes);
    defer allocator.free(pk0_hex);
    const pk1_hex = try hexEncode(allocator, &pub1.bytes);
    defer allocator.free(pk1_hex);

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("value", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();
    try args.put("sig0", .{ .bytes = sig1_hex });
    try args.put("pk0", .{ .bytes = pk0_hex });
    try args.put("pk1", .{ .bytes = pk1_hex });

    const result = try executeOnChainAuthoritative(
        allocator, &anf, "unlock", current_state, args, &.{},
        .{ .sighash = sighash },
    );
    var state = result.state;
    defer state.deinit();
    defer {
        for (result.data_outputs) |d| allocator.free(d.script);
        allocator.free(result.data_outputs);
        for (result.raw_outputs) |d| allocator.free(d.script);
        allocator.free(result.raw_outputs);
    }
    try std.testing.expectEqual(@as(i64, 1), state.get("value").?.int);
}

test "executeOnChainAuthoritative — checkMultiSig 1-of-2 fails when sig matches no pk" {
    const allocator = std.testing.allocator;
    const anf = buildMultiSigGuardAnf();

    const sighash = deterministicSighash();

    // Sign with a third key that isn't in the pks set; multisig must reject.
    var priv0_bytes: [32]u8 = undefined;
    @memset(&priv0_bytes, 0x11);
    priv0_bytes[0] = 0x01;
    var priv1_bytes: [32]u8 = undefined;
    @memset(&priv1_bytes, 0x22);
    priv1_bytes[0] = 0x01;
    var priv2_bytes: [32]u8 = undefined;
    @memset(&priv2_bytes, 0x33);
    priv2_bytes[0] = 0x01;
    const priv0 = try bsvz.crypto.PrivateKey.fromBytes(priv0_bytes);
    const priv1 = try bsvz.crypto.PrivateKey.fromBytes(priv1_bytes);
    const priv2 = try bsvz.crypto.PrivateKey.fromBytes(priv2_bytes);
    const pub0 = try priv0.publicKey();
    const pub1 = try priv1.publicKey();
    const sig2 = try priv2.signDigest256(sighash);

    const sig2_hex = try hexEncode(allocator, sig2.asSlice());
    defer allocator.free(sig2_hex);
    const pk0_hex = try hexEncode(allocator, &pub0.bytes);
    defer allocator.free(pk0_hex);
    const pk1_hex = try hexEncode(allocator, &pub1.bytes);
    defer allocator.free(pk1_hex);

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("value", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();
    try args.put("sig0", .{ .bytes = sig2_hex });
    try args.put("pk0", .{ .bytes = pk0_hex });
    try args.put("pk1", .{ .bytes = pk1_hex });

    const result = executeOnChainAuthoritative(
        allocator, &anf, "unlock", current_state, args, &.{},
        .{ .sighash = sighash },
    );
    try std.testing.expectError(StrictError.AssertionFailure, result);
}

test "executeOnChainAuthoritative — checkMultiSig real-crypto rejects non-array sig arg" {
    // Defensive: if a caller passes a `bytes` value where multisig expects
    // an `array`, the helper must return false (closed) rather than
    // mock-pass. Mirrors the TS reference at `verifyMultiSig` which also
    // rejects non-Array sig/pk shapes.
    const allocator = std.testing.allocator;
    const anf = buildMultiSigGuardAnf();
    const sighash = deterministicSighash();

    var priv0_bytes: [32]u8 = undefined;
    @memset(&priv0_bytes, 0x11);
    priv0_bytes[0] = 0x01;
    const priv0 = try bsvz.crypto.PrivateKey.fromBytes(priv0_bytes);
    const pub0 = try priv0.publicKey();
    const pk0_hex = try hexEncode(allocator, &pub0.bytes);
    defer allocator.free(pk0_hex);

    // Bypass the array_literal binding by overriding `sigsArr` directly in
    // the env after method-param load. The simplest way: pass empty bytes
    // for sig0 so the array_literal still produces an ANFValue.array, but
    // the inner verifyEcdsaReal call rejects an empty hex sig.
    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("value", .{ .int = 0 });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();
    try args.put("sig0", .{ .bytes = "" });
    try args.put("pk0", .{ .bytes = pk0_hex });
    try args.put("pk1", .{ .bytes = pk0_hex });

    const result = executeOnChainAuthoritative(
        allocator, &anf, "unlock", current_state, args, &.{},
        .{ .sighash = sighash },
    );
    try std.testing.expectError(StrictError.AssertionFailure, result);
}

test "numeric consumers reject non-minimal threaded operands (fRequireMinimal)" {
    // A shift/bitwise result keeps its operand's byte LENGTH, so `1 >> 1` leaves
    // the 1-byte `[0x00]` — a NON-minimal zero (minimal zero is empty). Every
    // NUMERIC consumer on-chain (OP_ADD/OP_SUB/OP_MUL/OP_DIV/OP_MOD,
    // OP_NUMEQUAL and the relational ops, and a shift's COUNT operand) decodes
    // with fRequireMinimal = true and ABORTS on that encoding. Threading the
    // real bytes but then reading only the decoded value re-minimises `[0x00]`
    // to `0`, so the interpreter reports a VALID spend for a script that aborts
    // on chain — the deployed UTXO is permanently unspendable.
    //
    // The byte-array ops `& | ^` and a shift's VALUE operand legitimately take
    // non-minimal bytes (they only require equal length) and must stay working;
    // the controls below pin that.
    const allocator = std.testing.allocator;

    const H = struct {
        // Run a one-method contract whose body stores its result into the
        // mutable `result` property; return that value, or propagate the
        // on-chain abort.
        fn run(a: std.mem.Allocator, body: []ANFBinding) !ANFValue {
            var props = [_]ANFProperty{
                .{ .name = "result", .type_name = "bool", .readonly = false },
            };
            var methods = [_]ANFMethod{
                .{ .name = "run", .params = &.{}, .body = body, .is_public = true },
            };
            const anf = ANFProgram{ .contract_name = "Minimal", .properties = &props, .methods = &methods };
            var cs = std.StringHashMap(ANFValue).init(a);
            defer cs.deinit();
            try cs.put("result", .{ .boolean = false });
            var args = std.StringHashMap(ANFValue).init(a);
            defer args.deinit();
            var ns = try computeNewState(a, &anf, "run", cs, args, &.{});
            defer ns.deinit();
            return ns.get("result").?;
        }
    };

    // `(1 >> 1) === 0` ABORTS — OP_NUMEQUAL on the non-minimal [0x00].
    // The buggy path decoded [0x00] to 0 and answered `true` (a funds-loss
    // spend: off-chain valid, on-chain "non-minimally encoded script number").
    {
        var body = [_]ANFBinding{
            .{ .name = "n", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "one", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "sh", .value = .{ .bin_op = .{ .op = ">>", .left = "n", .right = "one", .result_type = "int" } } },
            .{ .name = "z", .value = .{ .load_const = .{ .value = .{ .int = 0 } } } },
            .{ .name = "eq", .value = .{ .bin_op = .{ .op = "===", .left = "sh", .right = "z", .result_type = "bool" } } },
            .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "eq" } } },
        };
        try std.testing.expectError(error.ScriptNumberError, H.run(allocator, &body));
    }

    // `(1 >> 1) + 0` ABORTS — OP_ADD is a numeric consumer too.
    {
        var body = [_]ANFBinding{
            .{ .name = "n", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "one", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "sh", .value = .{ .bin_op = .{ .op = ">>", .left = "n", .right = "one", .result_type = "int" } } },
            .{ .name = "z", .value = .{ .load_const = .{ .value = .{ .int = 0 } } } },
            .{ .name = "sum", .value = .{ .bin_op = .{ .op = "+", .left = "sh", .right = "z", .result_type = "int" } } },
            .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "sum" } } },
        };
        try std.testing.expectError(error.ScriptNumberError, H.run(allocator, &body));
    }

    // `4 >> (1 >> 1)` ABORTS — a shift's COUNT operand is read as a number, so
    // the non-minimal [0x00] count aborts even though the VALUE operand may be
    // non-minimal.
    {
        var body = [_]ANFBinding{
            .{ .name = "n", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "one", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "cnt", .value = .{ .bin_op = .{ .op = ">>", .left = "n", .right = "one", .result_type = "int" } } },
            .{ .name = "four", .value = .{ .load_const = .{ .value = .{ .int = 4 } } } },
            .{ .name = "sh2", .value = .{ .bin_op = .{ .op = ">>", .left = "four", .right = "cnt", .result_type = "int" } } },
            .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "sh2" } } },
        };
        try std.testing.expectError(error.ScriptNumberError, H.run(allocator, &body));
    }

    // CONTROL — a shift whose result IS minimal stays accepted: `2 >> 1` leaves
    // [0x01], the minimal encoding of 1, so OP_NUMEQUAL is happy.
    {
        var body = [_]ANFBinding{
            .{ .name = "two", .value = .{ .load_const = .{ .value = .{ .int = 2 } } } },
            .{ .name = "one", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "sh", .value = .{ .bin_op = .{ .op = ">>", .left = "two", .right = "one", .result_type = "int" } } },
            .{ .name = "c1", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "eq", .value = .{ .bin_op = .{ .op = "===", .left = "sh", .right = "c1", .result_type = "bool" } } },
            .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "eq" } } },
        };
        const v = try H.run(allocator, &body);
        try std.testing.expectEqual(true, v.boolean);
    }

    // CONTROL — `& | ^` still take non-minimal equal-length operands:
    // `(2 << 8) | 5` ORs the non-minimal [0x00] with [0x05] to give [0x05],
    // which IS minimal for 5, so the following `=== 5` accepts. Pinned by
    // conformance/fuzz-regressions/entries/2026-07-14-chained-shift-or-nonminimal
    // — a fix that rejects this is WRONG.
    {
        var body = [_]ANFBinding{
            .{ .name = "two", .value = .{ .load_const = .{ .value = .{ .int = 2 } } } },
            .{ .name = "eight", .value = .{ .load_const = .{ .value = .{ .int = 8 } } } },
            .{ .name = "sh", .value = .{ .bin_op = .{ .op = "<<", .left = "two", .right = "eight", .result_type = "int" } } },
            .{ .name = "five", .value = .{ .load_const = .{ .value = .{ .int = 5 } } } },
            .{ .name = "orr", .value = .{ .bin_op = .{ .op = "|", .left = "sh", .right = "five", .result_type = "int" } } },
            .{ .name = "c5", .value = .{ .load_const = .{ .value = .{ .int = 5 } } } },
            .{ .name = "eq", .value = .{ .bin_op = .{ .op = "===", .left = "orr", .right = "c5", .result_type = "bool" } } },
            .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "eq" } } },
        };
        const v = try H.run(allocator, &body);
        try std.testing.expectEqual(true, v.boolean);
    }
}

test "unary ops and numeric builtins reject non-minimal threaded operands" {
    // The binary-op gate above only sees a value consumed by a BINARY numeric
    // op. A non-minimal shift result can also reach a UNARY op or a numeric
    // BUILTIN without passing through one, and those opcodes decode with
    // fRequireMinimal = true as well:
    //
    //   abs(n >> 1)    OP_ABS
    //   bool(n >> 1)   OP_0NOTEQUAL
    //   !(n >> 1)      OP_NOT
    //   -(n >> 1)      OP_NEGATE
    //
    // With n = 1 the shift leaves the 1-byte [0x00]. Reading only the decoded
    // value re-minimises it to 0, reports a VALID spend, and the deployed
    // script aborts — the UTXO is permanently unspendable.
    //
    // Mirrors the TS reference widening at the `toBigInt` / `toBool` funnels in
    // packages/runar-testing/src/interpreter/interpreter.ts.
    const allocator = std.testing.allocator;

    const H = struct {
        fn run(a: std.mem.Allocator, body: []ANFBinding) !ANFValue {
            var props = [_]ANFProperty{
                .{ .name = "result", .type_name = "int", .readonly = false },
            };
            var methods = [_]ANFMethod{
                .{ .name = "run", .params = &.{}, .body = body, .is_public = true },
            };
            const anf = ANFProgram{ .contract_name = "UnaryMinimal", .properties = &props, .methods = &methods };
            var cs = std.StringHashMap(ANFValue).init(a);
            defer cs.deinit();
            try cs.put("result", .{ .int = 0 });
            var args = std.StringHashMap(ANFValue).init(a);
            defer args.deinit();
            var ns = try computeNewState(a, &anf, "run", cs, args, &.{});
            defer ns.deinit();
            return ns.get("result").?;
        }

        // `sh` = 1 >> 1 -> raw stack bytes [0x00]; `z` = 0; `one` = 1.
        fn prefix() [5]ANFBinding {
            return .{
                .{ .name = "n", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
                .{ .name = "one", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
                .{ .name = "sh", .value = .{ .bin_op = .{ .op = ">>", .left = "n", .right = "one", .result_type = "int" } } },
                .{ .name = "z", .value = .{ .load_const = .{ .value = .{ .int = 0 } } } },
                .{ .name = "u0", .value = .{ .load_const = .{ .value = .{ .int = 0 } } } },
            };
        }
    };

    // Every numeric BUILTIN reads its operand through the same fRequireMinimal
    // decode a binary numeric op does, so a non-minimal argument must ABORT.
    {
        const one_arg = [_][]const u8{"sh"};
        const two_arg_left = [_][]const u8{ "sh", "one" };
        const two_arg_right = [_][]const u8{ "one", "sh" };
        const three_arg = [_][]const u8{ "sh", "z", "one" };

        const tails = [_]ANFNode{
            .{ .call = .{ .func = "abs", .args = &one_arg } },
            .{ .call = .{ .func = "bool", .args = &one_arg } },
            .{ .call = .{ .func = "sign", .args = &one_arg } },
            .{ .call = .{ .func = "min", .args = &two_arg_left } },
            .{ .call = .{ .func = "min", .args = &two_arg_right } },
            .{ .call = .{ .func = "max", .args = &two_arg_left } },
            .{ .call = .{ .func = "within", .args = &three_arg } },
            .{ .call = .{ .func = "safediv", .args = &two_arg_left } },
            .{ .call = .{ .func = "clamp", .args = &three_arg } },
            .{ .unary_op = .{ .op = "-", .operand = "sh", .result_type = "int" } },
            .{ .unary_op = .{ .op = "!", .operand = "sh", .result_type = "bool" } },
        };

        for (tails) |tail| {
            var body: [7]ANFBinding = undefined;
            const pre = H.prefix();
            @memcpy(body[0..5], &pre);
            body[5] = .{ .name = "r", .value = tail };
            body[6] = .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "z" } } };
            try std.testing.expectError(error.ScriptNumberError, H.run(allocator, &body));
        }
    }

    // The shape the lowering actually emits: a named local is an `@ref:` alias,
    // so the alias must carry the threaded bytes into the builtin.
    {
        const one_arg = [_][]const u8{"s"};
        var body = [_]ANFBinding{
            .{ .name = "n", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "one", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "sh", .value = .{ .bin_op = .{ .op = ">>", .left = "n", .right = "one", .result_type = "int" } } },
            .{ .name = "s", .value = .{ .load_const = .{ .value = .{ .bytes = "@ref:sh" } } } },
            .{ .name = "r", .value = .{ .call = .{ .func = "abs", .args = &one_arg } } },
            .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "r" } } },
        };
        try std.testing.expectError(error.ScriptNumberError, H.run(allocator, &body));
    }
}

test "unary/builtin minimal-encoding controls stay accepted" {
    // CONTROLS for the widened gate. These must be green BEFORE and AFTER the
    // widening — they pin the spends the chain accepts, so a fix that rejects
    // any of them is WRONG. Kept in their own test block so the abort cases
    // above (which bail the block on first failure) cannot mask them.
    const allocator = std.testing.allocator;

    const H = struct {
        fn run(a: std.mem.Allocator, body: []ANFBinding) !ANFValue {
            var props = [_]ANFProperty{
                .{ .name = "result", .type_name = "int", .readonly = false },
            };
            var methods = [_]ANFMethod{
                .{ .name = "run", .params = &.{}, .body = body, .is_public = true },
            };
            const anf = ANFProgram{ .contract_name = "UnaryControls", .properties = &props, .methods = &methods };
            var cs = std.StringHashMap(ANFValue).init(a);
            defer cs.deinit();
            try cs.put("result", .{ .int = 0 });
            var args = std.StringHashMap(ANFValue).init(a);
            defer args.deinit();
            var ns = try computeNewState(a, &anf, "run", cs, args, &.{});
            defer ns.deinit();
            return ns.get("result").?;
        }
    };

    // CONTROL — a MINIMAL operand through a builtin still spends: `2 >> 1`
    // leaves [0x01], the minimal encoding of 1, so OP_ABS is legal.
    {
        const one_arg = [_][]const u8{"sh"};
        var body = [_]ANFBinding{
            .{ .name = "two", .value = .{ .load_const = .{ .value = .{ .int = 2 } } } },
            .{ .name = "one", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "sh", .value = .{ .bin_op = .{ .op = ">>", .left = "two", .right = "one", .result_type = "int" } } },
            .{ .name = "r", .value = .{ .call = .{ .func = "abs", .args = &one_arg } } },
            .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "r" } } },
        };
        const v = try H.run(allocator, &body);
        try std.testing.expectEqual(@as(i64, 1), v.int);
    }

    // CONTROL — `~` is a byte op with its own path and must NOT be gated:
    // `~(2 << 8)` inverts the non-minimal [0x00] to [0xff] = -127.
    {
        var body = [_]ANFBinding{
            .{ .name = "two", .value = .{ .load_const = .{ .value = .{ .int = 2 } } } },
            .{ .name = "eight", .value = .{ .load_const = .{ .value = .{ .int = 8 } } } },
            .{ .name = "sh", .value = .{ .bin_op = .{ .op = "<<", .left = "two", .right = "eight", .result_type = "int" } } },
            .{ .name = "inv", .value = .{ .unary_op = .{ .op = "~", .operand = "sh", .result_type = "int" } } },
            .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "inv" } } },
        };
        const v = try H.run(allocator, &body);
        try std.testing.expectEqual(@as(i64, -127), v.int);
    }

}

test "@ref: alias carries the threaded stack bytes" {
    // An @ref: alias is a pure rename — the lowering emits one for every named
    // local, so almost every byte-op result passes through one before reaching
    // a consumer. It occupies the SAME stack bytes as its target, but the side
    // map is keyed by binding name, so an alias that creates no entry drops the
    // real bytes. That blinds the minimal-encoding gate AND makes
    // `(2 << 8) | 5` through an alias FALSE-abort on an OP_OR length mismatch
    // the chain never sees — the interpreter rejecting a spend the chain
    // accepts. Go, Python and Ruby already carry the entry across an alias.
    const allocator = std.testing.allocator;

    const H = struct {
        fn run(a: std.mem.Allocator, body: []ANFBinding) !ANFValue {
            var props = [_]ANFProperty{
                .{ .name = "result", .type_name = "int", .readonly = false },
            };
            var methods = [_]ANFMethod{
                .{ .name = "run", .params = &.{}, .body = body, .is_public = true },
            };
            const anf = ANFProgram{ .contract_name = "AliasBytes", .properties = &props, .methods = &methods };
            var cs = std.StringHashMap(ANFValue).init(a);
            defer cs.deinit();
            try cs.put("result", .{ .int = 0 });
            var args = std.StringHashMap(ANFValue).init(a);
            defer args.deinit();
            var ns = try computeNewState(a, &anf, "run", cs, args, &.{});
            defer ns.deinit();
            return ns.get("result").?;
        }
    };

    // CONTROL — `(2 << 8) | 5 == 5` through a named-local alias. OP_OR takes
    // non-minimal bytes and only requires equal length; rejecting this is WRONG
    // (pinned by conformance/fuzz-regressions/entries/
    // 2026-07-14-chained-shift-or-nonminimal).
    {
        var body = [_]ANFBinding{
            .{ .name = "two", .value = .{ .load_const = .{ .value = .{ .int = 2 } } } },
            .{ .name = "eight", .value = .{ .load_const = .{ .value = .{ .int = 8 } } } },
            .{ .name = "sh", .value = .{ .bin_op = .{ .op = "<<", .left = "two", .right = "eight", .result_type = "int" } } },
            .{ .name = "s", .value = .{ .load_const = .{ .value = .{ .bytes = "@ref:sh" } } } },
            .{ .name = "five", .value = .{ .load_const = .{ .value = .{ .int = 5 } } } },
            .{ .name = "orr", .value = .{ .bin_op = .{ .op = "|", .left = "s", .right = "five", .result_type = "int" } } },
            .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "orr" } } },
        };
        const v = try H.run(allocator, &body);
        try std.testing.expectEqual(@as(i64, 5), v.int);
    }
}
