const std = @import("std");
const bsvz = @import("bsvz");

// ---------------------------------------------------------------------------
// ANF Interpreter — compute state transitions from ANF IR
//
// Given a compiled artifact's ANF IR, the current contract state, and
// method arguments, this interpreter walks the ANF bindings and computes
// the new state. It handles `update_prop` and `add_output` nodes to track
// state mutations, while skipping on-chain-only operations like
// `check_preimage`, `deserialize_state`, `get_state_script`, and `add_raw_output`.
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
    assert_node: struct {},
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
    add_raw_output: struct {},
    unknown: void,
};

pub const InterpreterError = error{
    MethodNotFound,
    OutOfMemory,
};

/// Sentinel value for "no result" / undefined.
const anf_none: ANFValue = .{ .none = {} };

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute the new state after executing a contract method.
///
/// Returns a map from property name to new value. Caller owns the map.
pub fn computeNewState(
    allocator: std.mem.Allocator,
    anf: *const ANFProgram,
    method_name: []const u8,
    current_state: std.StringHashMap(ANFValue),
    args: std.StringHashMap(ANFValue),
) !std.StringHashMap(ANFValue) {
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

    if (method == null) return InterpreterError.MethodNotFound;
    const meth = method.?;

    // Initialize environment with property values
    var env = std.StringHashMap(ANFValue).init(arena_alloc);

    for (anf.properties) |prop| {
        if (current_state.get(prop.name)) |val| {
            try env.put(prop.name, val);
        } else if (prop.initial_value) |iv| {
            try env.put(prop.name, iv);
        }
    }

    // Load method params (skip implicit ones)
    for (meth.params) |param| {
        if (isImplicitParam(param.name)) continue;
        if (args.get(param.name)) |val| {
            try env.put(param.name, val);
        }
    }

    // Track state mutations
    var state_delta = std.StringHashMap(ANFValue).init(arena_alloc);

    // Walk bindings
    try evalBindings(arena_alloc, meth.body, &env, &state_delta, anf);

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

    return result;
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
    anf: *const ANFProgram,
) error{OutOfMemory}!void {
    for (bindings) |binding| {
        const val = try evalNode(allocator, binding.value, env, state_delta, anf);
        try env.put(binding.name, val);
    }
}

fn evalNode(
    allocator: std.mem.Allocator,
    node: ANFNode,
    env: *std.StringHashMap(ANFValue),
    state_delta: *std.StringHashMap(ANFValue),
    anf: *const ANFProgram,
) error{OutOfMemory}!ANFValue {
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
            return evalCall(allocator, c.func, c.args, env);
        },
        .method_call => |mc| {
            return evalMethodCall(allocator, mc.method, mc.args, env, state_delta, anf);
        },
        .if_node => |ifn| {
            const cond = env.get(ifn.cond) orelse anf_none;
            const branch = if (isTruthy(cond)) ifn.then_branch else ifn.else_branch;
            try evalBindings(allocator, branch, env, state_delta, anf);
            if (branch.len > 0) {
                return env.get(branch[branch.len - 1].name) orelse anf_none;
            }
            return anf_none;
        },
        .loop_node => |ln| {
            var last_val: ANFValue = anf_none;
            for (0..ln.count) |i| {
                try env.put(ln.iter_var, .{ .int = @intCast(i) });
                try evalBindings(allocator, ln.body, env, state_delta, anf);
                if (ln.body.len > 0) {
                    last_val = env.get(ln.body[ln.body.len - 1].name) orelse anf_none;
                }
            }
            return last_val;
        },
        .assert_node => {
            // Skip asserts in simulation
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
        // On-chain-only operations — skip
        .check_preimage, .deserialize_state, .get_state_script, .add_raw_output => {
            return anf_none;
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

fn evalCall(allocator: std.mem.Allocator, func: []const u8, arg_names: []const []const u8, env: *const std.StringHashMap(ANFValue)) ANFValue {
    // Crypto — mock
    if (std.mem.eql(u8, func, "checkSig")) return .{ .boolean = true };
    if (std.mem.eql(u8, func, "checkMultiSig")) return .{ .boolean = true };
    if (std.mem.eql(u8, func, "checkPreimage")) return .{ .boolean = true };

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
    anf: *const ANFProgram,
) error{OutOfMemory}!ANFValue {
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

            // Execute the method body
            try evalBindings(allocator, m.body, &method_env, state_delta, anf);

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
        .none => 0,
    };
}

fn isTruthy(v: ANFValue) bool {
    return switch (v) {
        .boolean => |b| b,
        .int => |n| n != 0,
        .bytes => |b| b.len > 0 and !std.mem.eql(u8, b, "0") and !std.mem.eql(u8, b, "false"),
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

    // Check sign bit
    const negative = (bytes_buf[decode_len - 1] & 0x80) != 0;
    if (negative) {
        bytes_buf[decode_len - 1] &= 0x7f;
    }

    // Build integer from LE bytes
    var result: i64 = 0;
    var i: usize = decode_len;
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
        prop.initial_value = parseJSONToANFValue(v);
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
        return .{ .load_const = .{ .value = parseJSONToANFValue(value_node) } };
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
        var call_args = std.ArrayListUnmanaged([]const u8){};
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
        var call_args = std.ArrayListUnmanaged([]const u8){};
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
    if (std.mem.eql(u8, kind, "assert")) return .{ .assert_node = .{} };
    if (std.mem.eql(u8, kind, "check_preimage")) return .{ .check_preimage = .{} };
    if (std.mem.eql(u8, kind, "deserialize_state")) return .{ .deserialize_state = .{} };
    if (std.mem.eql(u8, kind, "get_state_script")) return .{ .get_state_script = .{} };
    if (std.mem.eql(u8, kind, "add_raw_output")) return .{ .add_raw_output = .{} };
    if (std.mem.eql(u8, kind, "add_output")) {
        var state_values = std.ArrayListUnmanaged([]const u8){};
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
    if (std.mem.eql(u8, kind, "if")) {
        const cond = if (obj.get("cond")) |v| (if (v == .string) try allocator.dupe(u8, v.string) else "") else "";
        var then_branch = std.ArrayListUnmanaged(ANFBinding){};
        if (obj.get("then")) |t| {
            if (t == .array) {
                for (t.array.items) |item| {
                    try then_branch.append(allocator, try parseANFBinding(allocator, item));
                }
            }
        }
        var else_branch = std.ArrayListUnmanaged(ANFBinding){};
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
        var body = std.ArrayListUnmanaged(ANFBinding){};
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

fn parseJSONToANFValue(val: std.json.Value) ANFValue {
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
            break :blk .{ .bytes = s };
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

    var new_state = try computeNewState(allocator, &anf, "increment", current_state, args);
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

    var new_state = try computeNewState(allocator, &anf, "set", current_state, args);
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

    const result = computeNewState(allocator, &anf, "nonexistent", current_state, args);
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
