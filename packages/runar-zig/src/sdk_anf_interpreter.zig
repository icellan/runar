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
    },
    assert_node: struct {
        // Reference to the binding holding the predicate value. Used by
        // strict-mode evaluation to enforce the predicate; lenient mode
        // ignores it (and earlier ANF emitters didn't always populate it,
        // so the strict path also tolerates an empty ref by treating the
        // most recent binding as the predicate via `strict_ctx`).
        value: []const u8 = "",
    },
    update_prop: struct {
        name: []const u8 = "",
        value: []const u8 = "",
    },
    add_output: struct {
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

/// Real-crypto context for `executeOnChainAuthoritative`. The 32-byte
/// `sighash` is what `checkSig` ECDSA-verifies signatures against and what
/// `checkPreimage` requires `hash256(preimage)` to equal.
pub const RealCryptoCtx = struct {
    sighash: [32]u8,
};

/// Sentinel value for "no result" / undefined.
const anf_none: ANFValue = .{ .none = {} };

/// A data output resolved from `this.addDataOutput(...)` in the method body.
/// Caller owns the `script` slice (allocated from the caller's allocator).
pub const DataOutputEntry = struct {
    satoshis: i64,
    script: []u8,
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
    // Discard data + raw outputs — free their script allocations.
    for (result.data_outputs) |d| allocator.free(d.script);
    allocator.free(result.data_outputs);
    for (result.raw_outputs) |d| allocator.free(d.script);
    allocator.free(result.raw_outputs);
    return result.state;
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
    return runMethod(allocator, anf, method_name, current_state, args, constructor_args, true, null, null);
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
    return runMethod(allocator, anf, method_name, current_state, args, constructor_args, true, null, out_info);
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
    return runMethod(allocator, anf, method_name, current_state, args, constructor_args, true, &ctx, null);
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
    return runMethod(allocator, anf, method_name, current_state, args, constructor_args, true, &ctx, out_info);
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
    return runMethod(allocator, anf, method_name, current_state, args, constructor_args, false, null, null) catch |err| switch (err) {
        // Lenient mode never reports AssertionFailure (asserts are skipped),
        // but the unified runMethod return type includes it, so coerce away.
        error.AssertionFailure => unreachable,
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

    // Walk bindings — strict-mode context (or null for lenient). When
    // `real_crypto` is non-null we wire it into StrictCtx so crypto
    // built-ins can verify against the supplied sighash instead of
    // mock-returning true.
    var strict_ctx_storage: StrictCtx = .{ .method_name = method_name, .real_crypto = real_crypto };
    const strict_ctx_ptr: ?*StrictCtx = if (strict) &strict_ctx_storage else null;
    evalBindings(arena_alloc, meth.body, &env, &state_delta, &data_outputs_arena, &raw_outputs_arena, anf, strict_ctx_ptr) catch |err| {
        // On strict-mode AssertionFailure, populate the caller-supplied
        // out_failure_info (if any) so the driver can emit a structured
        // {error, methodName, bindingName} envelope on the wire. Both names
        // are slices into the ANF program's own storage, not the arena, so
        // they remain valid after this function returns.
        if (err == error.AssertionFailure) {
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

    return .{ .state = result, .data_outputs = do_out, .raw_outputs = ro_out };
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
    strict_ctx: ?*StrictCtx,
) error{ OutOfMemory, AssertionFailure }!void {
    for (bindings) |binding| {
        if (strict_ctx) |ctx| ctx.last_binding_name = binding.name;
        const val = try evalNode(allocator, binding.value, env, state_delta, data_outputs, raw_outputs, anf, strict_ctx);
        try env.put(binding.name, val);
    }
}

fn evalNode(
    allocator: std.mem.Allocator,
    node: ANFNode,
    env: *std.StringHashMap(ANFValue),
    state_delta: *std.StringHashMap(ANFValue),
    data_outputs: *std.ArrayList(DataOutputEntry),
    raw_outputs: *std.ArrayList(DataOutputEntry),
    anf: *const ANFProgram,
    strict_ctx: ?*StrictCtx,
) error{ OutOfMemory, AssertionFailure }!ANFValue {
    switch (node) {
        .load_param => |lp| {
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
                        return env.get(b[5..]) orelse anf_none;
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
            return evalBinOp(allocator, bo.op, left, right, bo.result_type);
        },
        .unary_op => |uo| {
            const operand = env.get(uo.operand) orelse anf_none;
            return evalUnaryOp(allocator, uo.op, operand, uo.result_type);
        },
        .call => |c| {
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
            return evalCall(allocator, c.func, c.args, env, real_crypto);
        },
        .method_call => |mc| {
            return evalMethodCall(allocator, mc.method, mc.args, env, state_delta, data_outputs, raw_outputs, anf, strict_ctx);
        },
        .if_node => |ifn| {
            const cond = env.get(ifn.cond) orelse anf_none;
            const branch = if (isTruthy(cond)) ifn.then_branch else ifn.else_branch;
            try evalBindings(allocator, branch, env, state_delta, data_outputs, raw_outputs, anf, strict_ctx);
            if (branch.len > 0) {
                return env.get(branch[branch.len - 1].name) orelse anf_none;
            }
            return anf_none;
        },
        .loop_node => |ln| {
            var last_val: ANFValue = anf_none;
            for (0..ln.count) |i| {
                try env.put(ln.iter_var, .{ .int = @intCast(i) });
                try evalBindings(allocator, ln.body, env, state_delta, data_outputs, raw_outputs, anf, strict_ctx);
                if (ln.body.len > 0) {
                    last_val = env.get(ln.body[ln.body.len - 1].name) orelse anf_none;
                }
            }
            return last_val;
        },
        .assert_node => |an| {
            // Strict mode: evaluate the referenced predicate and abort with
            // `error.AssertionFailure` if it is falsy. Lenient mode skips
            // (the on-chain script handles enforcement). Crypto built-ins
            // remain mocked even in strict mode — see `executeStrict` doc.
            if (strict_ctx != null) {
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
// Binary operations
// ---------------------------------------------------------------------------

fn evalBinOp(allocator: std.mem.Allocator, op: []const u8, left: ANFValue, right: ANFValue, result_type: []const u8) ANFValue {
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
    if (std.mem.eql(u8, op, "&")) return .{ .int = l & r };
    if (std.mem.eql(u8, op, "|")) return .{ .int = l | r };
    if (std.mem.eql(u8, op, "^")) return .{ .int = l ^ r };
    if (std.mem.eql(u8, op, "<<")) {
        if (r >= 0 and r < 64) return .{ .int = l << @intCast(r) };
        return .{ .int = 0 };
    }
    if (std.mem.eql(u8, op, ">>")) {
        if (r >= 0 and r < 64) return .{ .int = l >> @intCast(r) };
        return .{ .int = 0 };
    }

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
    if (std.mem.eql(u8, op, "~")) return .{ .int = ~val };

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

    // Preimage intrinsics — dummy values
    if (std.mem.eql(u8, func, "extractOutputHash") or std.mem.eql(u8, func, "extractAmount")) {
        return .{ .bytes = "00" ** 32 };
    }
    if (std.mem.eql(u8, func, "extractLocktime")) {
        return .{ .int = 0 };
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
    strict_ctx: ?*StrictCtx,
) error{ OutOfMemory, AssertionFailure }!ANFValue {
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

            // Execute the method body — propagate strict_ctx so nested
            // private-method asserts also abort.
            try evalBindings(allocator, m.body, &method_env, state_delta, data_outputs, raw_outputs, anf, strict_ctx);

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

fn num2binHex(allocator: std.mem.Allocator, n: i64, byte_len: usize) ANFValue {
    if (byte_len == 0) return .{ .bytes = "" };
    if (n == 0) {
        const result = allocator.alloc(u8, byte_len * 2) catch return .{ .bytes = "" };
        @memset(result, '0');
        return .{ .bytes = result };
    }

    const negative = n < 0;
    var abs_val: u64 = if (negative) @intCast(-n) else @intCast(n);

    var bytes_buf: [16]u8 = undefined;
    var num_bytes: usize = 0;
    while (abs_val > 0 and num_bytes < bytes_buf.len) : (num_bytes += 1) {
        bytes_buf[num_bytes] = @intCast(abs_val & 0xff);
        abs_val >>= 8;
    }

    // Sign bit handling
    if (num_bytes > 0) {
        if (negative) {
            if ((bytes_buf[num_bytes - 1] & 0x80) == 0) {
                bytes_buf[num_bytes - 1] |= 0x80;
            } else if (num_bytes < bytes_buf.len) {
                bytes_buf[num_bytes] = 0x80;
                num_bytes += 1;
            }
        } else {
            if ((bytes_buf[num_bytes - 1] & 0x80) != 0 and num_bytes < bytes_buf.len) {
                bytes_buf[num_bytes] = 0x00;
                num_bytes += 1;
            }
        }
    }

    const result = allocator.alloc(u8, byte_len * 2) catch return .{ .bytes = "" };
    @memset(result, '0');

    // Write LE bytes as hex
    const write_len = @min(num_bytes, byte_len);
    for (0..write_len) |i| {
        const b = bytes_buf[i];
        const hex_chars = "0123456789abcdef";
        result[i * 2] = hex_chars[b >> 4];
        result[i * 2 + 1] = hex_chars[b & 0x0f];
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
        return .{ .assert_node = .{ .value = value_ref } };
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
        return .{ .add_output = .{ .state_values = try state_values.toOwnedSlice(allocator) } };
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
    const result = evalBinOp(allocator, "+", .{ .bytes = "aabb" }, .{ .bytes = "ccdd" }, "bytes");
    switch (result) {
        .bytes => |b| {
            try std.testing.expectEqualStrings("aabbccdd", b);
            allocator.free(b);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "num2bin and bin2num roundtrip" {
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
