//! JSON parser and serializer for Runar ANF IR artifacts.
//! Reads the canonical JSON format produced by other Runar compilers
//! and produces canonical JSON with sorted keys and 2-space indentation
//! for conformance testing.

const std = @import("std");
const types = @import("types.zig");
const opcodes = @import("../codegen/opcodes.zig");
const unknown_anf_kind = @import("unknown_anf_kind.zig");

const ParseError = error{
    MissingField,
    InvalidKind,
    InvalidType,
    InvalidOperator,
    InvalidConstValue,
    UnexpectedValueType,
    MaxRecursionDepthExceeded,
    // BUG-008 follow-up: typed DoS-bound rejection of oversized IR JSON.
    IRSizeExceeded,
    // N-113 / R-079: a raw_script span with an empty body but a declared stack
    // effect. Distinct from InvalidConstValue so the diagnostic names the
    // shape — Zig's IR loader is an error-enum channel with no message
    // payload, so the error NAME is the whole diagnostic.
    EmptyRawScriptBody,
    // N-113 / R-081: no public method => no spending entry point => an empty,
    // anyone-can-spend locking script.
    NoPublicMethods,
    // N-115: a `loop` count above types.MAX_LOOP_COUNT. Distinct from
    // UnexpectedValueType because the value's TYPE is fine — an integer count
    // is exactly what the field takes; it is the MAGNITUDE that no emitter can
    // honour. Zig's IR loader carries no message payload, so the error name is
    // the whole diagnostic and has to say which rule fired.
    LoopCountExceedsMaximum,
    // R-126 / CL-BUG-164: an `add_output` whose stateValues list does not have
    // exactly one entry per MUTABLE property. Distinct from UnexpectedValueType
    // because the field's type is fine — it is the LENGTH that no emitter can
    // honour. Zig's IR loader carries no message payload, so the error name is
    // the whole diagnostic and has to say which rule fired.
    AddOutputArityMismatch,
    // R-164 / CL-BUG-134: a `super` call outside a constructor. `super` emits
    // no opcodes — the constructor args are already on the stack — but stack
    // lowering pushes a model slot for it anyway (+1 model, +0 physical), so
    // every later PICK/ROLL depth in the method is off by one. Distinct error
    // name because Zig's IR loader carries no message payload.
    SuperOutsideConstructor,
    // N-131: a number written in FLOAT SYNTAX anywhere in the document. The
    // ANF IR has no float-typed field, so this is never a legal payload; the
    // name says "float", not "InvalidConstValue", because the offending token
    // is frequently nowhere near a const (loop.step and raw_script.out_arity
    // are two of the shapes this tier used to accept) and Zig's IR loader
    // carries no message payload, so the error name is the whole diagnostic.
    FloatNotAllowedInIR,
};

const max_parse_depth: u32 = 256;

/// Mirrors InputLimits.MAX_IR_BYTES (16 MiB) from the TS schema package.
/// Any ANF IR JSON larger than this is rejected at parseANFProgram BEFORE
/// std.json.parseFromSlice runs so a malicious caller cannot exhaust
/// memory / CPU with a giant payload. BUG-008 follow-up.
pub const MAX_IR_BYTES: usize = 16 * 1024 * 1024;

/// Mirrors InputLimits.MAX_NESTING (512) from the TS schema package
/// for the structural-depth pre-walk. Note that the existing
/// per-binding parser also enforces max_parse_depth = 256 as a defense
/// in depth; whichever fires first wins. BUG-008 follow-up.
pub const MAX_IR_NESTING: usize = 512;

/// N-115 (second half) — total `f64` -> integer narrowing for the `--ir`
/// trust boundary.
///
/// `@intFromFloat` is ILLEGAL BEHAVIOUR whenever the value's integer part does
/// not fit the destination: a safety-checked abort in Debug/ReleaseSafe,
/// undefined behaviour in ReleaseFast. Every float this loader sees arrived as
/// JSON written outside the compiler, so the range check has to happen BEFORE
/// the cast — which is exactly what the first N-115 fix got wrong. It put the
/// loop-count magnitude guard on the line AFTER the narrowing, so
/// `{"count":1e30}` aborted (rc=134) instead of being refused, and three other
/// call sites had no guard anywhere near them. All six `@intFromFloat` sites
/// in this file were reachable from ordinary IR JSON; all six now come through
/// here.
///
/// The bounds are exact powers of two, so the comparison itself is exact: a
/// signed `T` of N bits holds [-2^(N-1), 2^(N-1) - 1], and both -2^(N-1) and
/// 2^(N-1) are representable in f64 with no rounding. `f >= -2^(N-1) and
/// f < 2^(N-1)` therefore admits precisely the values the cast can take. NaN
/// and the infinities fail both comparisons, so the same expression refuses
/// them without a special case — a bounds check written as `if (f > limit)`
/// would have let them straight through to the abort.
///
/// Fractional values are deliberately NOT rejected here. Truncation is what
/// this loader already did, four tiers agree on it, and tightening it is a
/// separate cross-tier decision; this change is about the abort class alone.
/// Call sites that need exactness keep their own round-trip check.
fn floatToInt(comptime T: type, f: f64) ParseError!T {
    const bits = @typeInfo(T).int.bits;
    const limit: f64 = @floatFromInt(@as(u128, 1) << (bits - 1));
    if (!(f >= -limit and f < limit)) return ParseError.InvalidConstValue;
    return @intFromFloat(f);
}

/// Walks the raw JSON bytes and returns ParseError.MaxRecursionDepthExceeded
/// the first time the structural nesting (objects + arrays) exceeds
/// MAX_IR_NESTING. Runs BEFORE std.json.parseFromSlice so a deeply-nested
/// payload cannot exhaust the thread stack inside the deserializer.
///
/// Skips strings (respecting backslash-escapes).
fn assertIRNestingUnderLimit(data: []const u8) ParseError!void {
    var depth: usize = 0;
    var in_string = false;
    var escaped = false;
    for (data) |b| {
        if (in_string) {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (b == '\\') {
                escaped = true;
                continue;
            }
            if (b == '"') in_string = false;
            continue;
        }
        switch (b) {
            '"' => in_string = true,
            '{', '[' => {
                depth += 1;
                if (depth > MAX_IR_NESTING) {
                    return ParseError.MaxRecursionDepthExceeded;
                }
            },
            '}', ']' => {
                if (depth > 0) depth -= 1;
            },
            else => {},
        }
    }
}

/// Walks a parsed JSON document and returns ParseError.FloatNotAllowedInIR the
/// first time a number written in FLOAT SYNTAX appears. N-131.
///
/// # Why this is a rejection at all
///
/// The ANF IR has no float-typed field. The schema
/// (`packages/runar-ir-schema/src/schemas/anf-ir.schema.json`) types
/// `loop.count`, `loop.step` and the `raw_script` arities as `integer`, and
/// `loop.start` / `load_const.value` as integer-or-string; a value too large
/// for a native integer is written as a decimal string with an `n` suffix.
/// What the six `--ir` tiers did with a float was therefore unspecified, and
/// they disagreed in emitted BYTES rather than in diagnostics: `{"start":1e30}`
/// produced three different answers across the tiers.
///
/// This tier's share of that was the quiet one. N-115 stopped the six
/// `@intFromFloat` sites from ABORTING, and deliberately left truncation
/// alone -- "tightening it is a separate cross-tier decision". This is that
/// decision. Until now `{"count":3.5}` unrolled three bodies and
/// `{"out_arity":1.0}` compiled clean, in both cases while five peers refused
/// the same file.
///
/// # Why the rule is lexical, and why the walk is generic
///
/// `1.0` and `1e2` name integers, so a value-based rule would admit them --
/// and a value-based rule is exactly what this tier already had, which is how
/// `{"out_arity":1.0}` got through. Go and Java, the two tiers that were
/// already right, refuse float syntax outright, so converging on them means
/// taking the syntactic rule. `std.json` classifies the token, not the value:
/// `1.0`, `1e2` and `3.5` all arrive as `.float`, `5` as `.integer`. So the
/// parser has already applied the rule and this walk only acts on it.
///
/// Walking the GENERIC document rather than checking named fields is the
/// point. The six `.float` arms in this file were each written for one field,
/// and the two fields nobody wrote an arm for -- `loop.step` and the
/// `raw_script` arities -- are among the ones that diverged.
///
/// `.number_string` is the arm `std.json` uses when a number is kept
/// unparsed; it is refused on the same syntactic test, so the rule does not
/// depend on which representation the parser chose.
fn assertNoJSONFloats(value: std.json.Value) ParseError!void {
    switch (value) {
        .float => return ParseError.FloatNotAllowedInIR,
        .number_string => |s| {
            for (s) |c| {
                if (c == '.' or c == 'e' or c == 'E') return ParseError.FloatNotAllowedInIR;
            }
        },
        .object => |obj| {
            var it = obj.iterator();
            while (it.next()) |entry| try assertNoJSONFloats(entry.value_ptr.*);
        },
        .array => |arr| {
            for (arr.items) |item| try assertNoJSONFloats(item);
        },
        else => {},
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Parse a JSON string into an ANFProgram.
///
/// Rejects oversized (>MAX_IR_BYTES) payloads with the typed
/// ParseError.IRSizeExceeded BEFORE std.json.parseFromSlice runs.
/// Depth is bounded by std.json's parseFromSlice with max_value_len /
/// max_parse_depth; the structural-nesting cap is enforced indirectly
/// by max_parse_depth = 256 inside this module. BUG-008 follow-up.
pub fn parseANFProgram(allocator: std.mem.Allocator, json_source: []const u8) !types.ANFProgram {
    if (json_source.len > MAX_IR_BYTES) {
        return ParseError.IRSizeExceeded;
    }
    try assertIRNestingUnderLimit(json_source);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_source, .{
        .max_value_len = MAX_IR_BYTES,
    });
    defer parsed.deinit();

    const root = parsed.value;
    // N-131: refuse float syntax at the door, before any field-specific
    // decoding. See assertNoJSONFloats.
    try assertNoJSONFloats(root);
    return try parseProgram(allocator, root);
}

/// Serialize ANF IR to canonical JSON with sorted keys and 2-space indentation.
/// Used for conformance testing — SHA-256 of this output must match other compilers.
pub fn serializeCanonicalJSON(allocator: std.mem.Allocator, program: types.ANFProgram) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    const w = opcodes.ArrayListWriter{ .list = &buf, .allocator = allocator };
    try writeCanonicalProgram(w, program, 0);
    try buf.append(allocator, '\n');

    return buf.toOwnedSlice(allocator);
}

/// Serialize the final artifact to JSON.
pub fn serializeArtifact(allocator: std.mem.Allocator, artifact: types.Artifact) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    const w = opcodes.ArrayListWriter{ .list = &buf, .allocator = allocator };
    try writeCanonicalArtifact(w, artifact, 0);
    try buf.append(allocator, '\n');

    return buf.toOwnedSlice(allocator);
}

// ============================================================================
// JSON Parsing — ANFProgram from dynamic JSON values
// ============================================================================

fn parseProgram(allocator: std.mem.Allocator, root: std.json.Value) !types.ANFProgram {
    const obj = root.object;

    const contract_name = try getString(obj, "contractName");
    const properties = try parseProperties(allocator, obj);
    const methods_val = obj.get("methods") orelse return ParseError.MissingField;
    const methods_arr = methods_val.array;

    var method_list: std.ArrayListUnmanaged(types.ANFMethod) = .empty;
    errdefer method_list.deinit(allocator);

    for (methods_arr.items) |method_val| {
        const method = try parseMethod(allocator, method_val.object);
        try method_list.append(allocator, method);
    }

    // N-113 / R-081: a contract with no public method has no spending entry
    // point and emits an EMPTY locking script — which is anyone-can-spend, not
    // merely useless. On the real @bsv/sdk `Spend` engine under full consensus
    // rules, an empty locking script with the one-byte push-only witness OP_1
    // (0x51) validates. Before this guard the --ir path exited 0 and handed the
    // SDKs a well-formed artifact whose "script" was "".
    //
    // The source pipeline already rejects the same shape in
    // passes/validate.zig; this parser is reached only from the IR loader, so
    // this closes the rule's gap on externally supplied IR.
    //
    // Checked LAST so the structural diagnostics above keep priority — a
    // malformed binding is the more actionable error when both are present.
    // Mirrors compilers/go/ir/loader.go, including the ordering.
    //
    // N-113: the CONSTRUCTOR does not count. This mirrors passes/validate.zig,
    // but runs over a differently-shaped list: the AST keeps the constructor
    // in its own field while ANF lowering flattens it INTO the method list, so
    // one `isPublic: true` on the constructor walked past the guard. It is
    // never a spending entry point (emit and stack lowering both filter it out
    // by NAME) and the contract emitted a bare OP_1 locking script at exit 0 —
    // spendable with no witness at all.
    var has_public = false;
    for (method_list.items) |m| {
        if (m.is_public and !std.mem.eql(u8, m.name, "constructor")) {
            has_public = true;
            break;
        }
    }
    if (!has_public) return ParseError.NoPublicMethods;

    // R-126 / CL-BUG-164: an add_output must name exactly one state value per
    // MUTABLE property.
    //
    // The source pipeline counts addOutput arity in the typechecker (the
    // N20 / N23 / N26 negatives). `--ir` runs no frontend, so such a node
    // reached stack lowering directly, and lowerAddOutput serializes the
    // OP_RETURN payload with the MIN of the two lists. Under-arity emitted an
    // output carrying fewer state fields than the contract has; over-arity
    // silently dropped the surplus. Measured through each tier's own --ir CLI
    // on a two-mutable-field contract (correct arity = 1394 hexchars): go,
    // rust, zig, ruby, python and java ALL accepted, emitting 1388 and 1396
    // hexchars respectively.
    //
    // CL-BUG-164 settled the cost: every SDK's StateSerializer writes ALL
    // mutable fields, so a short-payload continuation is spendable only by a
    // hand-crafted transaction, and the successor it produces is permanently
    // unspendable because the next call's deserialize_state slices at fixed
    // offsets.
    var mutable_count: usize = 0;
    for (properties) |prop| {
        if (!prop.readonly) mutable_count += 1;
    }
    for (method_list.items) |m| {
        try checkAddOutputArity(m.body, mutable_count);
        if (!std.mem.eql(u8, m.name, "constructor")) try checkNoSuperCall(m.body);
    }

    return types.ANFProgram{
        .contract_name = try allocator.dupe(u8, contract_name),
        .properties = properties,
        .methods = try method_list.toOwnedSlice(allocator),
    };
}

/// Walk a binding list — nested `if` arms and `loop` bodies included — and
/// refuse any `add_output` whose stateValues list is not exactly
/// `mutable_count` long. See the call site in `parseProgram` for why.
fn checkAddOutputArity(bindings: []const types.ANFBinding, mutable_count: usize) ParseError!void {
    for (bindings) |binding| {
        switch (binding.value) {
            .add_output => |ao| {
                if (ao.state_values.len != mutable_count) {
                    return ParseError.AddOutputArityMismatch;
                }
            },
            .@"if" => |iv| {
                try checkAddOutputArity(iv.then, mutable_count);
                try checkAddOutputArity(iv.@"else", mutable_count);
            },
            .loop => |lv| try checkAddOutputArity(lv.body, mutable_count),
            else => {},
        }
    }
}

/// Refuse a `super` call anywhere in a non-constructor method body (R-164).
/// See the `SuperOutsideConstructor` error for why.
fn checkNoSuperCall(bindings: []const types.ANFBinding) ParseError!void {
    for (bindings) |binding| {
        switch (binding.value) {
            .call => |c| {
                if (std.mem.eql(u8, c.func, "super")) return ParseError.SuperOutsideConstructor;
            },
            .@"if" => |iv| {
                try checkNoSuperCall(iv.then);
                try checkNoSuperCall(iv.@"else");
            },
            .loop => |lv| try checkNoSuperCall(lv.body),
            else => {},
        }
    }
}

fn parseProperties(allocator: std.mem.Allocator, obj: std.json.ObjectMap) ![]types.ANFProperty {
    const props_val = obj.get("properties") orelse return &.{};
    const props_arr = props_val.array;

    var result = try allocator.alloc(types.ANFProperty, props_arr.items.len);
    for (props_arr.items, 0..) |prop_val, i| {
        const prop_obj = prop_val.object;
        const type_str = try getString(prop_obj, "type");
        const initial_value = if (prop_obj.get("initialValue")) |initial| switch (initial) {
            .integer => |v| @as(?types.ConstValue, .{ .integer = v }),
            .float => |f| blk: {
                const int_val: i128 = try floatToInt(i128, f);
                const roundtrip: f64 = @floatFromInt(int_val);
                if (roundtrip != f) return ParseError.InvalidConstValue;
                break :blk @as(?types.ConstValue, .{ .integer = int_val });
            },
            .bool => |b| @as(?types.ConstValue, .{ .boolean = b }),
            .string => |s| blk: {
                // Same `n`-suffix discriminator used by parseLoadConst —
                // oversize bigint initializers (e.g. property defaults) round
                // through the same encoding as inline literals.
                if (isDecimalBigIntLiteral(s)) {
                    const decimal = try allocator.dupe(u8, s[0 .. s.len - 1]);
                    break :blk @as(?types.ConstValue, .{ .big_integer = decimal });
                }
                break :blk @as(?types.ConstValue, .{ .string = try allocator.dupe(u8, s) });
            },
            // A bare JSON number too large for i64 arrives as `.number_string`.
            .number_string => |s| @as(?types.ConstValue, try constFromNumberString(allocator, s)),
            else => return ParseError.InvalidConstValue,
        } else null;
        // N-095: recover the synthetic-array chain so an ANF produced by ANY
        // tier still regroups into one FixedArray state field here. Dropping it
        // was invisible in the script hex and only showed up as four raw
        // `grid__i__j` entries where the SDK expects `state.grid`.
        const chain: ?[]const types.SyntheticArrayLevel = if (prop_obj.get("syntheticArrayChain")) |raw| blk: {
            const levels_json = switch (raw) {
                .array => |a| a,
                else => return ParseError.UnexpectedValueType,
            };
            const levels = try allocator.alloc(types.SyntheticArrayLevel, levels_json.items.len);
            for (levels_json.items, 0..) |level_val, li| {
                const level_obj = switch (level_val) {
                    .object => |o| o,
                    else => return ParseError.UnexpectedValueType,
                };
                levels[li] = .{
                    .base = try allocator.dupe(u8, try getString(level_obj, "base")),
                    .index = try getU32(level_obj, "index"),
                    .length = try getU32(level_obj, "length"),
                };
            }
            break :blk levels;
        } else null;

        result[i] = .{
            .name = try allocator.dupe(u8, try getString(prop_obj, "name")),
            .type_name = try allocator.dupe(u8, type_str),
            .type_info = types.parseRunarType(type_str),
            .readonly = try getBool(prop_obj, "readonly"),
            .initial_value = initial_value,
            .synthetic_array_chain = chain,
        };
    }
    return result;
}

fn parseMethod(allocator: std.mem.Allocator, method_obj: std.json.ObjectMap) !types.ANFMethod {
    const name = try getString(method_obj, "name");
    const is_public = try getBool(method_obj, "isPublic");
    const params = try parseParams(allocator, method_obj);

    const body_val = method_obj.get("body") orelse return .{
        .name = try allocator.dupe(u8, name),
        .is_public = is_public,
        .params = params,
        .body = &.{},
    };
    const bindings = try parseBindings(allocator, body_val.array, 0);

    return .{
        .name = try allocator.dupe(u8, name),
        .is_public = is_public,
        .params = params,
        .body = bindings,
    };
}

fn parseParams(allocator: std.mem.Allocator, method_obj: std.json.ObjectMap) ![]types.ANFParam {
    const params_val = method_obj.get("params") orelse return &.{};
    const params_arr = params_val.array;

    var result = try allocator.alloc(types.ANFParam, params_arr.items.len);
    for (params_arr.items, 0..) |param_val, i| {
        const param_obj = param_val.object;
        result[i] = .{
            .name = try allocator.dupe(u8, try getString(param_obj, "name")),
            .type_name = try allocator.dupe(u8, try getString(param_obj, "type")),
        };
    }
    return result;
}

const BindingError = ParseError || std.mem.Allocator.Error || unknown_anf_kind.UnknownAnfKindError;

fn parseBindings(allocator: std.mem.Allocator, arr: std.json.Array, depth: u32) BindingError![]types.ANFBinding {
    var result = try allocator.alloc(types.ANFBinding, arr.items.len);
    for (arr.items, 0..) |binding_val, i| {
        result[i] = try parseBinding(allocator, binding_val.object, depth);
    }
    return result;
}

fn parseBinding(allocator: std.mem.Allocator, obj: std.json.ObjectMap, depth: u32) BindingError!types.ANFBinding {
    const name = try getString(obj, "name");
    const value_json = obj.get("value") orelse return ParseError.MissingField;
    const value = try parseANFValue(allocator, value_json.object, depth);

    return .{
        .name = try allocator.dupe(u8, name),
        .value = value,
    };
}

const KindTag = enum {
    load_param, load_prop, load_const, bin_op, unary_op, call, method_call,
    @"if", loop, assert, update_prop, get_state_script, check_preimage,
    deserialize_state, add_output, add_raw_output, add_data_output, array_literal,
    raw_script,
};

const kind_map = std.StaticStringMap(KindTag).initComptime(.{
    .{ "load_param", .load_param },
    .{ "load_prop", .load_prop },
    .{ "load_const", .load_const },
    .{ "bin_op", .bin_op },
    .{ "unary_op", .unary_op },
    .{ "call", .call },
    .{ "method_call", .method_call },
    .{ "if", .@"if" },
    .{ "loop", .loop },
    .{ "assert", .assert },
    .{ "update_prop", .update_prop },
    .{ "get_state_script", .get_state_script },
    .{ "check_preimage", .check_preimage },
    .{ "deserialize_state", .deserialize_state },
    .{ "add_output", .add_output },
    .{ "add_raw_output", .add_raw_output },
    .{ "add_data_output", .add_data_output },
    .{ "array_literal", .array_literal },
    .{ "raw_script", .raw_script },
});

fn parseANFValue(allocator: std.mem.Allocator, obj: std.json.ObjectMap, depth: u32) BindingError!types.ANFValue {
    if (depth >= max_parse_depth) return ParseError.MaxRecursionDepthExceeded;

    const kind = try getString(obj, "kind");
    // F-003: unknown ANF kinds used to return a generic InvalidKind; now they
    // raise UnknownAnfKind via the typed helper so a missing ANFValue variant
    // fails loudly with a useful diagnostic.
    const tag = kind_map.get(kind) orelse
        return unknown_anf_kind.unknownAnfKind(kind, "ir.json.parseANFValue");

    return switch (tag) {
        .load_param => .{ .load_param = .{
            .name = try allocator.dupe(u8, try getString(obj, "name")),
        } },
        .load_prop => .{ .load_prop = .{
            .name = try allocator.dupe(u8, try getString(obj, "name")),
        } },
        .load_const => try parseLoadConst(allocator, obj),
        .bin_op => try parseBinOp(allocator, obj),
        .unary_op => try parseUnaryOp(allocator, obj),
        .call => try parseCall(allocator, obj),
        .method_call => try parseMethodCall(allocator, obj),
        .@"if" => try parseIf(allocator, obj, depth),
        .loop => try parseLoop(allocator, obj, depth),
        .assert => try parseAssert(allocator, obj),
        .update_prop => try parseUpdateProp(allocator, obj),
        .get_state_script => .{ .get_state_script = {} },
        .check_preimage => .{ .check_preimage = .{
            .preimage = try allocator.dupe(u8, try getString(obj, "preimage")),
            // #123: optional non-default sighash flag (default 0 = ALL|FORKID).
            .sighash_flag = getOptionalI32(obj, "sighashFlag"),
        } },
        .deserialize_state => .{ .deserialize_state = .{
            .preimage = try allocator.dupe(u8, try getString(obj, "preimage")),
        } },
        .add_output => try parseAddOutput(allocator, obj),
        .add_raw_output => try parseAddRawOutput(allocator, obj),
        .add_data_output => try parseAddDataOutput(allocator, obj),
        .array_literal => .{ .array_literal = .{
            .elements = try parseStringArray(allocator, obj, "elements"),
        } },
        .raw_script => try parseRawScript(allocator, obj),
    };
}

/// Parse a raw_script ANF value from JSON. Validates the hex-shape of the
/// `bytes` field (even length, hex-only) and rejects negative arities.
fn parseRawScript(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !types.ANFValue {
    const bytes_str = try getString(obj, "bytes");
    // N-113 / R-079: an empty span is a claim the emitter cannot honour. Stack
    // lowering models a raw_script purely from its declared arities (it pops
    // in_arity and pushes out_arity) because the bytes are opaque to it, while
    // emission writes nothing at all for a zero-length span. The stack model
    // and the script then disagree, and every later PICK/ROLL depth derived
    // from that model addresses the wrong slot — the span silently degrades to
    // the identity function and a different witness spends the output than the
    // IR declared.
    //
    // The source path already rejects this ("asm() body must be a non-empty
    // hex string literal", passes/validate.zig); --ir is the same rule at the
    // external-input trust boundary. All empty bodies are rejected, including
    // the degenerate in=0/out=0 case, because mirroring the source validator
    // exactly is worth more than an arity-conditional rule that would differ
    // from the rule one pass earlier.
    if (bytes_str.len == 0) return ParseError.EmptyRawScriptBody;
    if (bytes_str.len % 2 != 0) return ParseError.InvalidConstValue;
    for (bytes_str) |c| {
        const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
        if (!is_hex) return ParseError.InvalidConstValue;
    }

    const in_arity_val = obj.get("in_arity") orelse return ParseError.MissingField;
    const in_arity: i32 = switch (in_arity_val) {
        .integer => |i| @intCast(i),
        .float => |f| blk: {
            const i: i64 = try floatToInt(i64, f);
            const roundtrip: f64 = @floatFromInt(i);
            if (roundtrip != f) return ParseError.InvalidConstValue;
            break :blk @intCast(i);
        },
        else => return ParseError.UnexpectedValueType,
    };
    if (in_arity < 0) return ParseError.InvalidConstValue;

    const out_arity_val = obj.get("out_arity") orelse return ParseError.MissingField;
    const out_arity: i32 = switch (out_arity_val) {
        .integer => |i| @intCast(i),
        .float => |f| blk: {
            const i: i64 = try floatToInt(i64, f);
            const roundtrip: f64 = @floatFromInt(i);
            if (roundtrip != f) return ParseError.InvalidConstValue;
            break :blk @intCast(i);
        },
        else => return ParseError.UnexpectedValueType,
    };
    if (out_arity < 0) return ParseError.InvalidConstValue;

    return .{ .raw_script = .{
        .bytes = try allocator.dupe(u8, bytes_str),
        .in_arity = in_arity,
        .out_arity = out_arity,
    } };
}

fn parseLoadConst(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !types.ANFValue {
    const val = obj.get("value") orelse return ParseError.MissingField;

    switch (val) {
        .integer => |i| return .{ .load_const = .{ .value = .{ .integer = i } } },
        .float => |f| {
            const int_val: i128 = try floatToInt(i128, f);
            const roundtrip: f64 = @floatFromInt(int_val);
            if (roundtrip != f) return ParseError.InvalidConstValue;
            return .{ .load_const = .{ .value = .{ .integer = int_val } } };
        },
        .bool => |b| return .{ .load_const = .{ .value = .{ .boolean = b } } },
        .string => |s| {
            // Cross-tier IR producers (TS / Go / Python) emit oversize bigints
            // as a quoted decimal string with the canonical JS BigInt `n`
            // suffix so the value survives JSON precision loss. Distinguish
            // this shape from hex-encoded ByteString literals (which never
            // carry the suffix) before falling back to `string`.
            if (isDecimalBigIntLiteral(s)) {
                const decimal = try allocator.dupe(u8, s[0 .. s.len - 1]);
                return .{ .load_const = .{ .value = .{ .big_integer = decimal } } };
            }
            return .{ .load_const = .{ .value = .{ .string = try allocator.dupe(u8, s) } } };
        },
        // A bare JSON number too large for i64 arrives as `.number_string`.
        .number_string => |s| return .{ .load_const = .{ .value = try constFromNumberString(allocator, s) } },
        else => return ParseError.InvalidConstValue,
    }
}

/// True if `s` matches the canonical JS BigInt decimal-literal encoding used
/// by the TS / Go / Python IR emitters for oversize values: optional leading
/// `-`, one or more ASCII digits, and a REQUIRED trailing `n` marker. The
/// trailing `n` is the discriminator that separates a decimal-encoded BigInt
/// from a hex-encoded ByteString literal (which never carries the suffix),
/// so a hex string like "3030" is not mis-decoded as the integer 3030.
/// True for canonical decimal integer text with no `n` suffix: optional
/// leading `-` followed by one or more ASCII digits.
fn isDecimalIntegerText(s: []const u8) bool {
    const body = if (s.len > 0 and s[0] == '-') s[1..] else s;
    if (body.len == 0) return false;
    for (body) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

/// Decode a bare JSON number that did not fit `i64` (issue #162).
///
/// `std.json` hands those back as `.number_string` rather than `.integer`,
/// and the loader used to drop them into its `else` arm and fail the whole
/// program with `InvalidConstValue` — while the Go tier compiled the same IR.
/// Integral text within `i128` lands in `.integer` and anything larger in
/// `.big_integer`, per the ConstValue contract in ir/types.zig. Genuinely
/// non-integral text (a fraction or exponent) is still rejected: script
/// numbers are integers.
fn constFromNumberString(allocator: std.mem.Allocator, s: []const u8) !types.ConstValue {
    if (!isDecimalIntegerText(s)) return ParseError.InvalidConstValue;
    if (std.fmt.parseInt(i128, s, 10)) |v| {
        return .{ .integer = v };
    } else |_| {}
    return .{ .big_integer = try allocator.dupe(u8, s) };
}

fn isDecimalBigIntLiteral(s: []const u8) bool {
    if (s.len < 2 or s[s.len - 1] != 'n') return false;
    var start: usize = 0;
    if (s[0] == '-') start = 1;
    const body = s[start .. s.len - 1];
    if (body.len == 0) return false;
    for (body) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

fn parseBinOp(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !types.ANFValue {
    const op_str = try getString(obj, "op");
    const left = try getString(obj, "left");
    const right = try getString(obj, "right");

    // Optional result_type field
    const result_type: ?[]const u8 = if (obj.get("result_type")) |rt|
        switch (rt) {
            .string => |s| try allocator.dupe(u8, s),
            else => null,
        }
    else
        null;

    return .{ .bin_op = .{
        .op = try allocator.dupe(u8, op_str),
        .left = try allocator.dupe(u8, left),
        .right = try allocator.dupe(u8, right),
        .result_type = result_type,
    } };
}

fn parseUnaryOp(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !types.ANFValue {
    const op_str = try getString(obj, "op");
    const operand = try getString(obj, "operand");

    return .{ .unary_op = .{
        .op = try allocator.dupe(u8, op_str),
        .operand = try allocator.dupe(u8, operand),
    } };
}

fn parseCall(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !types.ANFValue {
    const func_name = try getString(obj, "func");
    const args = try parseStringArray(allocator, obj, "args");

    return .{ .call = .{
        .func = try allocator.dupe(u8, func_name),
        .args = args,
    } };
}

fn parseMethodCall(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !types.ANFValue {
    const object = try getString(obj, "object");
    const method = try getString(obj, "method");
    const args = try parseStringArray(allocator, obj, "args");

    return .{ .method_call = .{
        .object = try allocator.dupe(u8, object),
        .method = try allocator.dupe(u8, method),
        .args = args,
    } };
}

fn parseIf(allocator: std.mem.Allocator, obj: std.json.ObjectMap, depth: u32) BindingError!types.ANFValue {
    const cond = try getString(obj, "cond");
    const then_val = obj.get("then") orelse return ParseError.MissingField;
    const then_bindings = try parseBindings(allocator, then_val.array, depth + 1);

    const else_bindings: []types.ANFBinding = if (obj.get("else")) |else_val|
        try parseBindings(allocator, else_val.array, depth + 1)
    else
        try allocator.alloc(types.ANFBinding, 0);

    var results: []const []const u8 = &.{};
    if (obj.get("results")) |results_val| {
        const items = results_val.array.items;
        const out = try allocator.alloc([]const u8, items.len);
        for (items, 0..) |item, i| {
            out[i] = try allocator.dupe(u8, item.string);
        }
        results = out;
    }

    const if_expr = try allocator.create(types.ANFIf);
    if_expr.* = .{
        .cond = try allocator.dupe(u8, cond),
        .then = then_bindings,
        .@"else" = else_bindings,
        .results = results,
    };

    return .{ .@"if" = if_expr };
}

fn parseLoop(allocator: std.mem.Allocator, obj: std.json.ObjectMap, depth: u32) BindingError!types.ANFValue {
    const count_val = obj.get("count") orelse return ParseError.MissingField;

    // N-115: the unroll ceiling, checked BEFORE the narrowing cast.
    //
    // Two defects share this line and one guard closes both.
    //
    // 1. The ceiling itself. types.MAX_LOOP_COUNT (10000) existed and was
    //    applied on the SOURCE path only; nothing bounded a count arriving as
    //    IR. This tier accepted count=10001 and emitted a 199734-hexchar
    //    (~97 KB) script. Rust and Java accepted the same input and emitted the
    //    SAME bytes (sha256 e2c1be39...), which is why cross-tier hex parity
    //    never saw it — the three offenders agreed with each other.
    //
    // 2. The cast. `@intCast` to `u32` is a safety-checked PANIC in
    //    Debug/ReleaseSafe and undefined behaviour in ReleaseFast — the exact
    //    failure the doc comment on types.MAX_LOOP_COUNT predicts. Measured on
    //    count=2^33 before this guard: `thread N panic: integer does not fit in
    //    destination type`. A panic is not a rejection: the process dies on a
    //    signal, so it renders no verdict at all and any caller reading only
    //    the exit status learns nothing.
    //
    // Comparing the raw i64 first is what makes the cast total: everything that
    // reaches @intCast is now in [0, 10000].
    // N-115 second half: a float whose integer part does not fit `i64` is at
    // least 2^63 in magnitude — six orders of magnitude past the 10000 ceiling
    // this function is about — or is not a number at all. Refusing it under
    // the cap's own error name is both accurate and what the peers say:
    // python reports "loop count 1e+30 exceeding maximum 10000", ruby the
    // same. The narrowing itself can no longer abort.
    const raw_count: i64 = switch (count_val) {
        .integer => |i| i,
        .float => |f| floatToInt(i64, f) catch return ParseError.LoopCountExceedsMaximum,
        else => return ParseError.UnexpectedValueType,
    };
    if (raw_count > types.MAX_LOOP_COUNT or raw_count < 0) {
        return ParseError.LoopCountExceedsMaximum;
    }
    const count: u32 = @intCast(raw_count);
    const iter_var = try getString(obj, "iterVar");
    const body_val = obj.get("body") orelse return ParseError.MissingField;
    const body_bindings = try parseBindings(allocator, body_val.array, depth + 1);

    // Issue #121: decode the iterator start value (a bare number, or a decimal
    // `Nn` string for oversize starts) and step direction. Older ANF payloads
    // without start/step describe zero-start counting-up loops (start=0, step=1).
    // N-115 second half: this site had NO bounds check of any kind, so moving
    // the loop-count guard above its own cast would have left it open.
    // `{"start":1e30}` aborted here.
    const start: i64 = if (obj.get("start")) |v| switch (v) {
        .integer => |i| i,
        .float => |f| try floatToInt(i64, f),
        .string => |s| blk: {
            const text = if (s.len > 0 and s[s.len - 1] == 'n') s[0 .. s.len - 1] else s;
            break :blk std.fmt.parseInt(i64, text, 10) catch 0;
        },
        else => 0,
    } else 0;
    const step: i8 = if (obj.get("step")) |v| switch (v) {
        .integer => |i| if (i < 0) @as(i8, -1) else 1,
        .float => |f| if (f < 0) @as(i8, -1) else 1,
        else => 1,
    } else 1;

    const loop_node = try allocator.create(types.ANFLoop);
    loop_node.* = .{
        .count = count,
        .body = body_bindings,
        .iter_var = try allocator.dupe(u8, iter_var),
        .start = start,
        .step = step,
    };

    return .{ .loop = loop_node };
}

fn parseAssert(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !types.ANFValue {
    const val_ref = try getString(obj, "value");
    const marker = if (obj.get("isAutoInjectedStateCheck")) |v|
        v == .bool and v.bool
    else
        false;

    return .{ .assert = .{
        .value = try allocator.dupe(u8, val_ref),
        .is_auto_injected_state_check = marker,
    } };
}

fn parseUpdateProp(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !types.ANFValue {
    const name = try getString(obj, "name");
    const val = try getString(obj, "value");

    return .{ .update_prop = .{
        .name = try allocator.dupe(u8, name),
        .value = try allocator.dupe(u8, val),
    } };
}

fn parseAddOutput(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !types.ANFValue {
    const satoshis = try getString(obj, "satoshis");
    const state_values = try parseStringArray(allocator, obj, "stateValues");

    // preimage field is present in JSON but may be empty string
    const preimage: []const u8 = if (obj.get("preimage")) |p|
        switch (p) {
            .string => |s| try allocator.dupe(u8, s),
            else => try allocator.dupe(u8, ""),
        }
    else
        try allocator.dupe(u8, "");

    return .{ .add_output = .{
        .satoshis = try allocator.dupe(u8, satoshis),
        .state_values = state_values,
        .preimage = preimage,
    } };
}

fn parseAddRawOutput(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !types.ANFValue {
    const satoshis = try getString(obj, "satoshis");
    const script_bytes = try getString(obj, "scriptBytes");

    return .{ .add_raw_output = .{
        .satoshis = try allocator.dupe(u8, satoshis),
        .script_bytes = try allocator.dupe(u8, script_bytes),
    } };
}

fn parseAddDataOutput(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !types.ANFValue {
    const satoshis = try getString(obj, "satoshis");
    const script_bytes = try getString(obj, "scriptBytes");

    return .{ .add_data_output = .{
        .satoshis = try allocator.dupe(u8, satoshis),
        .script_bytes = try allocator.dupe(u8, script_bytes),
    } };
}

// ============================================================================
// Helper functions for JSON value extraction
// ============================================================================

fn getString(obj: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const val = obj.get(key) orelse return ParseError.MissingField;
    return switch (val) {
        .string => |s| s,
        else => ParseError.UnexpectedValueType,
    };
}

/// Read an optional integer field, returning 0 when absent or not an integer.
/// Used for the #123 check_preimage `sighashFlag` (default 0 = ALL|FORKID).
fn getOptionalI32(obj: std.json.ObjectMap, key: []const u8) i32 {
    const val = obj.get(key) orelse return 0;
    return switch (val) {
        .integer => |i| @intCast(i),
        else => 0,
    };
}

/// Read a required non-negative integer field. N-095 (`syntheticArrayChain`
/// levels) is the only caller; `index` and `length` are `u32` in
/// `types.SyntheticArrayLevel`.
fn getU32(obj: std.json.ObjectMap, key: []const u8) !u32 {
    const val = obj.get(key) orelse return ParseError.MissingField;
    return switch (val) {
        .integer => |i| if (i < 0) ParseError.UnexpectedValueType else @intCast(i),
        else => ParseError.UnexpectedValueType,
    };
}

fn getBool(obj: std.json.ObjectMap, key: []const u8) !bool {
    const val = obj.get(key) orelse return ParseError.MissingField;
    return switch (val) {
        .bool => |b| b,
        else => ParseError.UnexpectedValueType,
    };
}

fn parseStringArray(allocator: std.mem.Allocator, obj: std.json.ObjectMap, key: []const u8) ![]const []const u8 {
    const val = obj.get(key) orelse return &.{};
    const arr = val.array;

    var result = try allocator.alloc([]const u8, arr.items.len);
    for (arr.items, 0..) |item, i| {
        result[i] = try allocator.dupe(u8, switch (item) {
            .string => |s| s,
            else => return ParseError.UnexpectedValueType,
        });
    }
    return result;
}

// ============================================================================
// Canonical JSON Serialization — Sorted keys, 2-space indentation
// ============================================================================

fn writeCanonicalProgram(writer: anytype, program: types.ANFProgram, depth: usize) !void {
    try writer.writeAll("{\n");

    // Keys in alphabetical order: contractName, methods, properties
    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "contractName");
    try writer.writeAll(": ");
    try writeJsonString(writer, program.contract_name);
    try writer.writeAll(",\n");

    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "methods");
    try writer.writeAll(": ");
    try writeMethodsArray(writer, program.methods, depth + 1);
    try writer.writeAll(",\n");

    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "properties");
    try writer.writeAll(": ");
    try writePropertiesArray(writer, program.properties, depth + 1);
    try writer.writeByte('\n');

    try writeIndent(writer, depth);
    try writer.writeByte('}');
}

fn writeMethodsArray(writer: anytype, methods: []const types.ANFMethod, depth: usize) !void {
    if (methods.len == 0) {
        try writer.writeAll("[]");
        return;
    }

    try writer.writeAll("[\n");
    for (methods, 0..) |method, i| {
        try writeIndent(writer, depth + 1);
        try writeMethodObject(writer, method, depth + 1);
        if (i + 1 < methods.len) try writer.writeByte(',');
        try writer.writeByte('\n');
    }
    try writeIndent(writer, depth);
    try writer.writeByte(']');
}

fn writeMethodObject(writer: anytype, method: types.ANFMethod, depth: usize) !void {
    try writer.writeAll("{\n");

    // Sorted keys: body, isPublic, name, params
    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "body");
    try writer.writeAll(": ");
    try writeBindingsArray(writer, method.body, depth + 1);
    try writer.writeAll(",\n");

    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "isPublic");
    try writer.writeAll(": ");
    if (method.is_public) {
        try writer.writeAll("true");
    } else {
        try writer.writeAll("false");
    }
    try writer.writeAll(",\n");

    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "name");
    try writer.writeAll(": ");
    try writeJsonString(writer, method.name);
    try writer.writeAll(",\n");

    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "params");
    try writer.writeAll(": ");
    try writeParamsArray(writer, method.params, depth + 1);
    try writer.writeByte('\n');

    try writeIndent(writer, depth);
    try writer.writeByte('}');
}

fn writeParamsArray(writer: anytype, params: []const types.ANFParam, depth: usize) !void {
    if (params.len == 0) {
        try writer.writeAll("[]");
        return;
    }

    try writer.writeAll("[\n");
    for (params, 0..) |param, i| {
        try writeIndent(writer, depth + 1);
        try writer.writeAll("{\n");

        // Sorted keys: name, type
        try writeIndent(writer, depth + 2);
        try writeJsonString(writer, "name");
        try writer.writeAll(": ");
        try writeJsonString(writer, param.name);
        try writer.writeAll(",\n");

        try writeIndent(writer, depth + 2);
        try writeJsonString(writer, "type");
        try writer.writeAll(": ");
        try writeJsonString(writer, param.type_name);
        try writer.writeByte('\n');

        try writeIndent(writer, depth + 1);
        try writer.writeByte('}');
        if (i + 1 < params.len) try writer.writeByte(',');
        try writer.writeByte('\n');
    }
    try writeIndent(writer, depth);
    try writer.writeByte(']');
}

fn writePropertiesArray(writer: anytype, properties: []const types.ANFProperty, depth: usize) !void {
    if (properties.len == 0) {
        try writer.writeAll("[]");
        return;
    }

    try writer.writeAll("[\n");
    for (properties, 0..) |prop, i| {
        try writeIndent(writer, depth + 1);
        try writer.writeAll("{\n");

        // Sorted keys: initialValue (optional), name, readonly, type
        if (prop.initial_value) |initial_value| {
            try writeIndent(writer, depth + 2);
            try writeJsonString(writer, "initialValue");
            try writer.writeAll(": ");
            try writeConstValue(writer, initial_value);
            try writer.writeAll(",\n");
        }

        try writeIndent(writer, depth + 2);
        try writeJsonString(writer, "name");
        try writer.writeAll(": ");
        try writeJsonString(writer, prop.name);
        try writer.writeAll(",\n");

        try writeIndent(writer, depth + 2);
        try writeJsonString(writer, "readonly");
        try writer.writeAll(": ");
        if (prop.readonly) {
            try writer.writeAll("true");
        } else {
            try writer.writeAll("false");
        }
        try writer.writeAll(",\n");

        // N-095: the synthetic-array chain is what `regroupStateFields` in
        // codegen/emit.zig collapses the expanded FixedArray leaves by. It was
        // threaded correctly through the AST and ANF but never written here, so
        // `--emit-ir` dropped it and no `compile-ir` run -- this tier's own
        // included -- could recover the regrouping. Omitted when null, matching
        // Go's `omitempty` and Rust's `skip_serializing_if`, so a
        // FixedArray-free contract's ANF bytes do not move.
        if (prop.synthetic_array_chain) |chain| {
            try writeIndent(writer, depth + 2);
            try writeJsonString(writer, "syntheticArrayChain");
            try writer.writeAll(": [\n");
            for (chain, 0..) |level, li| {
                try writeIndent(writer, depth + 3);
                try writer.writeAll("{\n");
                try writeIndent(writer, depth + 4);
                try writeJsonString(writer, "base");
                try writer.writeAll(": ");
                try writeJsonString(writer, level.base);
                try writer.writeAll(",\n");
                try writeIndent(writer, depth + 4);
                try writeJsonString(writer, "index");
                try writer.print(": {d},\n", .{level.index});
                try writeIndent(writer, depth + 4);
                try writeJsonString(writer, "length");
                try writer.print(": {d}\n", .{level.length});
                try writeIndent(writer, depth + 3);
                try writer.writeByte('}');
                if (li + 1 < chain.len) try writer.writeByte(',');
                try writer.writeByte('\n');
            }
            try writeIndent(writer, depth + 2);
            try writer.writeAll("],\n");
        }

        try writeIndent(writer, depth + 2);
        try writeJsonString(writer, "type");
        try writer.writeAll(": ");
        try writeJsonString(writer, prop.type_name);
        try writer.writeByte('\n');

        try writeIndent(writer, depth + 1);
        try writer.writeByte('}');
        if (i + 1 < properties.len) try writer.writeByte(',');
        try writer.writeByte('\n');
    }
    try writeIndent(writer, depth);
    try writer.writeByte(']');
}

fn writeBindingsArray(writer: anytype, bindings: []const types.ANFBinding, depth: usize) anyerror!void {
    if (bindings.len == 0) {
        try writer.writeAll("[]");
        return;
    }

    try writer.writeAll("[\n");
    for (bindings, 0..) |binding, i| {
        try writeIndent(writer, depth + 1);
        try writeBindingObject(writer, binding, depth + 1);
        if (i + 1 < bindings.len) try writer.writeByte(',');
        try writer.writeByte('\n');
    }
    try writeIndent(writer, depth);
    try writer.writeByte(']');
}

fn writeBindingObject(writer: anytype, binding: types.ANFBinding, depth: usize) anyerror!void {
    try writer.writeAll("{\n");

    // Sorted keys: name, value
    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "name");
    try writer.writeAll(": ");
    try writeJsonString(writer, binding.name);
    try writer.writeAll(",\n");

    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "value");
    try writer.writeAll(": ");
    try writeANFValue(writer, binding.value, depth + 1);
    try writer.writeByte('\n');

    try writeIndent(writer, depth);
    try writer.writeByte('}');
}

fn writeANFValue(writer: anytype, value: types.ANFValue, depth: usize) anyerror!void {
    switch (value) {
        .load_param => |lp| {
            try writer.writeAll("{\n");
            // Sorted keys: kind, name
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "load_param");
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "name");
            try writer.writeAll(": ");
            try writeJsonString(writer, lp.name);
            try writer.writeByte('\n');
            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .load_prop => |lp| {
            try writer.writeAll("{\n");
            // Sorted keys: kind, name
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "load_prop");
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "name");
            try writer.writeAll(": ");
            try writeJsonString(writer, lp.name);
            try writer.writeByte('\n');
            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .load_const => |lc| {
            try writer.writeAll("{\n");
            // Sorted keys: kind, value
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "load_const");
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "value");
            try writer.writeAll(": ");
            try writeConstValue(writer, lc.value);
            try writer.writeByte('\n');
            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .bin_op => |bop| {
            try writer.writeAll("{\n");
            // Sorted keys: kind, left, op, [result_type], right
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "bin_op");
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "left");
            try writer.writeAll(": ");
            try writeJsonString(writer, bop.left);
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "op");
            try writer.writeAll(": ");
            try writeJsonString(writer, bop.op);
            try writer.writeAll(",\n");
            if (bop.result_type) |rt| {
                try writeIndent(writer, depth + 1);
                try writeJsonString(writer, "result_type");
                try writer.writeAll(": ");
                try writeJsonString(writer, rt);
                try writer.writeAll(",\n");
            }
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "right");
            try writer.writeAll(": ");
            try writeJsonString(writer, bop.right);
            try writer.writeByte('\n');
            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .unary_op => |uop| {
            try writer.writeAll("{\n");
            // Sorted keys: kind, op, operand
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "unary_op");
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "op");
            try writer.writeAll(": ");
            try writeJsonString(writer, uop.op);
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "operand");
            try writer.writeAll(": ");
            try writeJsonString(writer, uop.operand);
            try writer.writeByte('\n');
            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .call => |c| {
            try writer.writeAll("{\n");
            // Sorted keys: args, func, kind
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "args");
            try writer.writeAll(": ");
            try writeStringArray(writer, c.args);
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "func");
            try writer.writeAll(": ");
            try writeJsonString(writer, c.func);
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "call");
            try writer.writeByte('\n');
            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .method_call => |mc| {
            try writer.writeAll("{\n");
            // Sorted keys: args, kind, method, object
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "args");
            try writer.writeAll(": ");
            try writeStringArray(writer, mc.args);
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "method_call");
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "method");
            try writer.writeAll(": ");
            try writeJsonString(writer, mc.method);
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "object");
            try writer.writeAll(": ");
            try writeJsonString(writer, mc.object);
            try writer.writeByte('\n');
            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .@"if" => |if_e| {
            try writer.writeAll("{\n");
            // Sorted keys: cond, else, kind, then
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "cond");
            try writer.writeAll(": ");
            try writeJsonString(writer, if_e.cond);
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "else");
            try writer.writeAll(": ");
            try writeBindingsArray(writer, if_e.@"else", depth + 1);
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "if");
            try writer.writeAll(",\n");

            if (if_e.results.len > 0) {
                try writeIndent(writer, depth + 1);
                try writeJsonString(writer, "results");
                try writer.writeAll(": [\n");
                for (if_e.results, 0..) |name, ri| {
                    try writeIndent(writer, depth + 2);
                    try writeJsonString(writer, name);
                    if (ri + 1 < if_e.results.len) try writer.writeByte(',');
                    try writer.writeByte('\n');
                }
                try writeIndent(writer, depth + 1);
                try writer.writeAll("],\n");
            }

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "then");
            try writer.writeAll(": ");
            try writeBindingsArray(writer, if_e.then, depth + 1);
            try writer.writeByte('\n');

            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .loop => |lp| {
            try writer.writeAll("{\n");
            // Sorted keys: body, count, iterVar, kind, start, step
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "body");
            try writer.writeAll(": ");
            try writeBindingsArray(writer, lp.body, depth + 1);
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "count");
            try writer.writeAll(": ");
            try writer.print("{d}", .{lp.count});
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "iterVar");
            try writer.writeAll(": ");
            try writeJsonString(writer, lp.iter_var);
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "loop");
            try writer.writeAll(",\n");

            // Issue #121: iterator start value and step direction. `start` is an
            // int64 loop start, emitted as a bare JSON number — byte-identical
            // to the TypeScript ANF JSON, whose reviver collapses int64-range
            // `Nn` strings back to plain numbers.
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "start");
            try writer.writeAll(": ");
            try writer.print("{d}", .{lp.start});
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "step");
            try writer.writeAll(": ");
            try writer.print("{d}", .{lp.step});
            try writer.writeByte('\n');

            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .assert => |a| {
            try writer.writeAll("{\n");
            // Sorted keys: isAutoInjectedStateCheck (when true), kind, value
            // The marker is omitted entirely when false to keep the
            // checked-in fold-OFF goldens stable for developer asserts.
            if (a.is_auto_injected_state_check) {
                try writeIndent(writer, depth + 1);
                try writeJsonString(writer, "isAutoInjectedStateCheck");
                try writer.writeAll(": true,\n");
            }

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "assert");
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "value");
            try writer.writeAll(": ");
            try writeJsonString(writer, a.value);
            try writer.writeByte('\n');

            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .update_prop => |up| {
            try writer.writeAll("{\n");
            // Sorted keys: kind, name, value
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "update_prop");
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "name");
            try writer.writeAll(": ");
            try writeJsonString(writer, up.name);
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "value");
            try writer.writeAll(": ");
            try writeJsonString(writer, up.value);
            try writer.writeByte('\n');
            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .get_state_script => {
            try writer.writeAll("{\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "get_state_script");
            try writer.writeByte('\n');
            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .check_preimage => |cp| {
            try writer.writeAll("{\n");
            // Sorted keys: kind, preimage, sighashFlag (#123, only when non-default)
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "check_preimage");
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "preimage");
            try writer.writeAll(": ");
            try writeJsonString(writer, cp.preimage);
            if (cp.sighash_flag != 0) {
                try writer.writeAll(",\n");
                try writeIndent(writer, depth + 1);
                try writeJsonString(writer, "sighashFlag");
                try writer.print(": {d}", .{cp.sighash_flag});
            }
            try writer.writeByte('\n');
            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .deserialize_state => |ds| {
            try writer.writeAll("{\n");
            // Sorted keys: kind, preimage
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "deserialize_state");
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "preimage");
            try writer.writeAll(": ");
            try writeJsonString(writer, ds.preimage);
            try writer.writeByte('\n');
            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .add_output => |ao| {
            try writer.writeAll("{\n");
            // Sorted keys: kind, preimage, satoshis, stateValues
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "add_output");
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "preimage");
            try writer.writeAll(": ");
            try writeJsonString(writer, ao.preimage);
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "satoshis");
            try writer.writeAll(": ");
            try writeJsonString(writer, ao.satoshis);
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "stateValues");
            try writer.writeAll(": ");
            try writeStringArray(writer, ao.state_values);
            try writer.writeByte('\n');

            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .add_raw_output => |aro| {
            try writer.writeAll("{\n");
            // Sorted keys: kind, satoshis, scriptBytes
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "add_raw_output");
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "satoshis");
            try writer.writeAll(": ");
            try writeJsonString(writer, aro.satoshis);
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "scriptBytes");
            try writer.writeAll(": ");
            try writeJsonString(writer, aro.script_bytes);
            try writer.writeByte('\n');

            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .add_data_output => |ado| {
            try writer.writeAll("{\n");
            // Sorted keys: kind, satoshis, scriptBytes. Wire shape identical to
            // add_raw_output; distinguished only by position in the
            // continuation-hash concatenation.
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "add_data_output");
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "satoshis");
            try writer.writeAll(": ");
            try writeJsonString(writer, ado.satoshis);
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "scriptBytes");
            try writer.writeAll(": ");
            try writeJsonString(writer, ado.script_bytes);
            try writer.writeByte('\n');

            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .array_literal => |al| {
            try writer.writeAll("{\n");
            // Sorted keys: elements, kind
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "elements");
            try writer.writeAll(": ");
            try writeStringArray(writer, al.elements);
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "array_literal");
            try writer.writeByte('\n');
            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .raw_script => |rs| {
            try writer.writeAll("{\n");
            // Sorted keys: bytes, in_arity, kind, out_arity. The arities are
            // emitted unconditionally so in_arity 0 / out_arity 0 survive
            // round-trips (matches the Go reference compiler).
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "bytes");
            try writer.writeAll(": ");
            try writeJsonString(writer, rs.bytes);
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "in_arity");
            try writer.writeAll(": ");
            try writer.print("{d}", .{rs.in_arity});
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "raw_script");
            try writer.writeAll(",\n");

            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "out_arity");
            try writer.writeAll(": ");
            try writer.print("{d}", .{rs.out_arity});
            try writer.writeByte('\n');

            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
    }
}

/// `Number.MAX_SAFE_INTEGER` (2^53 - 1) — the largest magnitude a bare JSON
/// number survives. Every JSON consumer that decodes into a JS number (or into
/// Go's `interface{}`, which is `float64`) is an IEEE-754 double, so `i64` is
/// NOT the boundary: `9007199254740993` fits `i64` and still reads back as
/// `9007199254740992`.
const js_max_safe_integer: i128 = 9007199254740991;

fn writeConstValue(writer: anytype, value: types.ConstValue) !void {
    switch (value) {
        .integer => |i| {
            if (i > js_max_safe_integer or i < -js_max_safe_integer) {
                // Past the safe-integer boundary a bare JSON number is lossy —
                // emit the same canonical `"<n>n"` string the `big_integer`
                // arm below uses, which is also what TS / Go / Rust / Python /
                // Ruby / Java emit in this window.
                try writer.print("\"{d}n\"", .{i});
            } else {
                try writer.print("{d}", .{i});
            }
        },
        .big_integer => |s| {
            // Canonical JS BigInt encoding: quoted decimal string with the
            // trailing `n` discriminator. Matches the TS / Go / Python
            // emitters so the IR JSON is byte-identical across tiers for
            // oversize literals (e.g. the 256-bit secp256k1 group order in
            // schnorr-zkp).
            try writer.writeByte('"');
            try writer.writeAll(s);
            try writer.writeAll("n\"");
        },
        .boolean => |b| {
            if (b) {
                try writer.writeAll("true");
            } else {
                try writer.writeAll("false");
            }
        },
        .string => |s| try writeJsonString(writer, s),
    }
}

fn writeStringArray(writer: anytype, items: []const []const u8) !void {
    try writer.writeByte('[');
    for (items, 0..) |item, i| {
        if (i > 0) try writer.writeAll(", ");
        try writeJsonString(writer, item);
    }
    try writer.writeByte(']');
}

// ============================================================================
// Artifact Serialization
// ============================================================================

fn writeCanonicalArtifact(writer: anytype, artifact: types.Artifact, depth: usize) !void {
    try writer.writeAll("{\n");

    // Sorted keys: abi, asm_text, build_timestamp, compiler_version,
    // contract_name, script, version
    // (plus optional: code_separator_index, code_separator_indices,
    //  constructor_slots, source_map, state_fields)
    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "abi");
    try writer.writeAll(": ");
    try writeABI(writer, artifact.abi, depth + 1);
    try writer.writeAll(",\n");

    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "asm_text");
    try writer.writeAll(": ");
    try writeJsonString(writer, artifact.asm_text);
    try writer.writeAll(",\n");

    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "build_timestamp");
    try writer.writeAll(": ");
    try writeJsonString(writer, artifact.build_timestamp);
    try writer.writeAll(",\n");

    if (artifact.code_separator_index) |csi| {
        try writeIndent(writer, depth + 1);
        try writeJsonString(writer, "code_separator_index");
        try writer.writeAll(": ");
        try writer.print("{d}", .{csi});
        try writer.writeAll(",\n");
    }

    if (artifact.code_separator_indices) |indices| {
        try writeIndent(writer, depth + 1);
        try writeJsonString(writer, "code_separator_indices");
        try writer.writeAll(": [");
        for (indices, 0..) |idx, i| {
            if (i > 0) try writer.writeAll(", ");
            try writer.print("{d}", .{idx});
        }
        try writer.writeAll("],\n");
    }

    if (artifact.code_sep_index_slots) |slots| {
        try writeIndent(writer, depth + 1);
        try writeJsonString(writer, "code_sep_index_slots");
        try writer.writeAll(": [");
        for (slots, 0..) |slot, i| {
            if (i > 0) try writer.writeAll(", ");
            try writer.print("{{\"byte_offset\": {d}, \"code_sep_index\": {d}}}", .{ slot.byte_offset, slot.code_sep_index });
        }
        try writer.writeAll("],\n");
    }

    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "compiler_version");
    try writer.writeAll(": ");
    try writeJsonString(writer, artifact.compiler_version);
    try writer.writeAll(",\n");

    if (artifact.constructor_slots) |slots| {
        try writeIndent(writer, depth + 1);
        try writeJsonString(writer, "constructor_slots");
        try writer.writeAll(": ");
        try writeConstructorSlots(writer, slots, depth + 1);
        try writer.writeAll(",\n");
    }

    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "contract_name");
    try writer.writeAll(": ");
    try writeJsonString(writer, artifact.contract_name);
    try writer.writeAll(",\n");

    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "script");
    try writer.writeAll(": ");
    try writeJsonString(writer, artifact.script);
    try writer.writeAll(",\n");

    if (artifact.state_fields) |fields| {
        try writeIndent(writer, depth + 1);
        try writeJsonString(writer, "state_fields");
        try writer.writeAll(": ");
        try writeStateFields(writer, fields, depth + 1);
        try writer.writeAll(",\n");
    }

    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "version");
    try writer.writeAll(": ");
    try writeJsonString(writer, artifact.version);
    try writer.writeByte('\n');

    try writeIndent(writer, depth);
    try writer.writeByte('}');
}

fn writeABI(writer: anytype, abi: types.ABI, depth: usize) !void {
    try writer.writeAll("{\n");

    // Sorted keys: constructor, methods
    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "constructor");
    try writer.writeAll(": ");
    try writeABIConstructor(writer, abi.constructor, depth + 1);
    try writer.writeAll(",\n");

    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "methods");
    try writer.writeAll(": ");
    try writeABIMethods(writer, abi.methods, depth + 1);
    try writer.writeByte('\n');

    try writeIndent(writer, depth);
    try writer.writeByte('}');
}

fn writeABIConstructor(writer: anytype, ctor: types.ABIConstructor, depth: usize) !void {
    try writer.writeAll("{\n");

    try writeIndent(writer, depth + 1);
    try writeJsonString(writer, "params");
    try writer.writeAll(": ");
    try writeABIParams(writer, ctor.params, depth + 1);
    try writer.writeByte('\n');

    try writeIndent(writer, depth);
    try writer.writeByte('}');
}

fn writeABIMethods(writer: anytype, methods: []const types.ABIMethod, depth: usize) !void {
    if (methods.len == 0) {
        try writer.writeAll("[]");
        return;
    }

    try writer.writeAll("[\n");
    for (methods, 0..) |method, i| {
        try writeIndent(writer, depth + 1);
        try writer.writeAll("{\n");

        // Sorted keys: is_public, name, params
        try writeIndent(writer, depth + 2);
        try writeJsonString(writer, "is_public");
        try writer.writeAll(": ");
        if (method.is_public) {
            try writer.writeAll("true");
        } else {
            try writer.writeAll("false");
        }
        try writer.writeAll(",\n");

        try writeIndent(writer, depth + 2);
        try writeJsonString(writer, "name");
        try writer.writeAll(": ");
        try writeJsonString(writer, method.name);
        try writer.writeAll(",\n");

        try writeIndent(writer, depth + 2);
        try writeJsonString(writer, "params");
        try writer.writeAll(": ");
        try writeABIParams(writer, method.params, depth + 2);
        try writer.writeByte('\n');

        try writeIndent(writer, depth + 1);
        try writer.writeByte('}');
        if (i + 1 < methods.len) try writer.writeByte(',');
        try writer.writeByte('\n');
    }
    try writeIndent(writer, depth);
    try writer.writeByte(']');
}

fn writeABIParams(writer: anytype, params: []const types.ABIParam, depth: usize) !void {
    if (params.len == 0) {
        try writer.writeAll("[]");
        return;
    }

    try writer.writeAll("[\n");
    for (params, 0..) |param, i| {
        try writeIndent(writer, depth + 1);
        try writer.writeAll("{\n");

        // Sorted keys: name, type_name
        try writeIndent(writer, depth + 2);
        try writeJsonString(writer, "name");
        try writer.writeAll(": ");
        try writeJsonString(writer, param.name);
        try writer.writeAll(",\n");

        try writeIndent(writer, depth + 2);
        try writeJsonString(writer, "type_name");
        try writer.writeAll(": ");
        try writeJsonString(writer, param.type_name);
        try writer.writeByte('\n');

        try writeIndent(writer, depth + 1);
        try writer.writeByte('}');
        if (i + 1 < params.len) try writer.writeByte(',');
        try writer.writeByte('\n');
    }
    try writeIndent(writer, depth);
    try writer.writeByte(']');
}

fn writeConstructorSlots(writer: anytype, slots: []const types.ConstructorSlot, depth: usize) !void {
    if (slots.len == 0) {
        try writer.writeAll("[]");
        return;
    }

    try writer.writeAll("[\n");
    for (slots, 0..) |slot, i| {
        try writeIndent(writer, depth + 1);
        try writer.writeAll("{\n");

        // Sorted keys: byte_offset, param_index
        try writeIndent(writer, depth + 2);
        try writeJsonString(writer, "byte_offset");
        try writer.writeAll(": ");
        try writer.print("{d}", .{slot.byte_offset});
        try writer.writeAll(",\n");

        try writeIndent(writer, depth + 2);
        try writeJsonString(writer, "param_index");
        try writer.writeAll(": ");
        try writer.print("{d}", .{slot.param_index});
        try writer.writeByte('\n');

        try writeIndent(writer, depth + 1);
        try writer.writeByte('}');
        if (i + 1 < slots.len) try writer.writeByte(',');
        try writer.writeByte('\n');
    }
    try writeIndent(writer, depth);
    try writer.writeByte(']');
}

fn writeStateFields(writer: anytype, fields: []const types.StateField, depth: usize) !void {
    if (fields.len == 0) {
        try writer.writeAll("[]");
        return;
    }

    try writer.writeAll("[\n");
    for (fields, 0..) |field, i| {
        try writeIndent(writer, depth + 1);
        try writer.writeAll("{\n");

        // Sorted keys: index, name, type_name
        try writeIndent(writer, depth + 2);
        try writeJsonString(writer, "index");
        try writer.writeAll(": ");
        try writer.print("{d}", .{field.index});
        try writer.writeAll(",\n");

        try writeIndent(writer, depth + 2);
        try writeJsonString(writer, "name");
        try writer.writeAll(": ");
        try writeJsonString(writer, field.name);
        try writer.writeAll(",\n");

        try writeIndent(writer, depth + 2);
        try writeJsonString(writer, "type_name");
        try writer.writeAll(": ");
        try writeJsonString(writer, field.type_name);
        try writer.writeByte('\n');

        try writeIndent(writer, depth + 1);
        try writer.writeByte('}');
        if (i + 1 < fields.len) try writer.writeByte(',');
        try writer.writeByte('\n');
    }
    try writeIndent(writer, depth);
    try writer.writeByte(']');
}

// ============================================================================
// Low-level serialization helpers
// ============================================================================

fn writeIndent(writer: anytype, depth: usize) !void {
    for (0..depth) |_| {
        try writer.writeAll("  ");
    }
}

/// Write a JSON string value, escaping special characters.
/// Public so other modules (e.g. emit.zig) can reuse it.
pub fn writeJsonString(writer: anytype, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0x08 => try writer.writeAll("\\b"),
            0x0C => try writer.writeAll("\\f"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
    try writer.writeByte('"');
}

// ============================================================================
// Tests
// ============================================================================

test "parse basic P2PKH ANF IR" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json_source =
        \\{
        \\  "contractName": "P2PKH",
        \\  "methods": [
        \\    {
        \\      "body": [
        \\        {
        \\          "name": "t0",
        \\          "value": {
        \\            "kind": "load_prop",
        \\            "name": "pubKeyHash"
        \\          }
        \\        },
        \\        {
        \\          "name": "t1",
        \\          "value": {
        \\            "args": [
        \\              "t0"
        \\            ],
        \\            "func": "super",
        \\            "kind": "call"
        \\          }
        \\        },
        \\        {
        \\          "name": "t2",
        \\          "value": {
        \\            "kind": "load_prop",
        \\            "name": "pubKeyHash"
        \\          }
        \\        },
        \\        {
        \\          "name": "t3",
        \\          "value": {
        \\            "kind": "update_prop",
        \\            "name": "pubKeyHash",
        \\            "value": "t2"
        \\          }
        \\        }
        \\      ],
        \\      "isPublic": false,
        \\      "name": "constructor",
        \\      "params": [
        \\        {
        \\          "name": "pubKeyHash",
        \\          "type": "Addr"
        \\        }
        \\      ]
        \\    },
        \\    {
        \\      "body": [
        \\        {
        \\          "name": "t0",
        \\          "value": {
        \\            "kind": "load_param",
        \\            "name": "pubKey"
        \\          }
        \\        },
        \\        {
        \\          "name": "t1",
        \\          "value": {
        \\            "args": [
        \\              "t0"
        \\            ],
        \\            "func": "hash160",
        \\            "kind": "call"
        \\          }
        \\        },
        \\        {
        \\          "name": "t2",
        \\          "value": {
        \\            "kind": "load_prop",
        \\            "name": "pubKeyHash"
        \\          }
        \\        },
        \\        {
        \\          "name": "t3",
        \\          "value": {
        \\            "kind": "bin_op",
        \\            "left": "t1",
        \\            "op": "===",
        \\            "result_type": "bytes",
        \\            "right": "t2"
        \\          }
        \\        },
        \\        {
        \\          "name": "t4",
        \\          "value": {
        \\            "kind": "assert",
        \\            "value": "t3"
        \\          }
        \\        },
        \\        {
        \\          "name": "t5",
        \\          "value": {
        \\            "kind": "load_param",
        \\            "name": "sig"
        \\          }
        \\        },
        \\        {
        \\          "name": "t6",
        \\          "value": {
        \\            "kind": "load_param",
        \\            "name": "pubKey"
        \\          }
        \\        },
        \\        {
        \\          "name": "t7",
        \\          "value": {
        \\            "args": [
        \\              "t5",
        \\              "t6"
        \\            ],
        \\            "func": "checkSig",
        \\            "kind": "call"
        \\          }
        \\        },
        \\        {
        \\          "name": "t8",
        \\          "value": {
        \\            "kind": "assert",
        \\            "value": "t7"
        \\          }
        \\        }
        \\      ],
        \\      "isPublic": true,
        \\      "name": "unlock",
        \\      "params": [
        \\        {
        \\          "name": "sig",
        \\          "type": "Sig"
        \\        },
        \\        {
        \\          "name": "pubKey",
        \\          "type": "PubKey"
        \\        }
        \\      ]
        \\    }
        \\  ],
        \\  "properties": [
        \\    {
        \\      "name": "pubKeyHash",
        \\      "readonly": true,
        \\      "type": "Addr"
        \\    }
        \\  ]
        \\}
    ;

    const program = try parseANFProgram(allocator, json_source);

    // Verify contract name
    try std.testing.expectEqualStrings("P2PKH", program.contract_name);

    // Verify properties
    try std.testing.expectEqual(@as(usize, 1), program.properties.len);
    try std.testing.expectEqualStrings("pubKeyHash", program.properties[0].name);
    try std.testing.expectEqualStrings("Addr", program.properties[0].type_name);
    try std.testing.expect(program.properties[0].readonly);

    // Verify methods (constructor + unlock)
    try std.testing.expectEqual(@as(usize, 2), program.methods.len);

    // Constructor
    try std.testing.expectEqualStrings("constructor", program.methods[0].name);
    try std.testing.expect(!program.methods[0].is_public);
    try std.testing.expectEqual(@as(usize, 1), program.methods[0].params.len);
    try std.testing.expectEqualStrings("pubKeyHash", program.methods[0].params[0].name);
    try std.testing.expectEqualStrings("Addr", program.methods[0].params[0].type_name);
    try std.testing.expectEqual(@as(usize, 4), program.methods[0].body.len);

    // Unlock method
    const unlock = program.methods[1];
    try std.testing.expectEqualStrings("unlock", unlock.name);
    try std.testing.expect(unlock.is_public);
    try std.testing.expectEqual(@as(usize, 2), unlock.params.len);
    try std.testing.expectEqualStrings("sig", unlock.params[0].name);
    try std.testing.expectEqualStrings("pubKey", unlock.params[1].name);
    try std.testing.expectEqual(@as(usize, 9), unlock.body.len);

    // Verify load_param
    try std.testing.expectEqualStrings("t0", unlock.body[0].name);
    switch (unlock.body[0].value) {
        .load_param => |lp| try std.testing.expectEqualStrings("pubKey", lp.name),
        else => return error.TestUnexpectedResult,
    }

    // Verify call (hash160)
    try std.testing.expectEqualStrings("t1", unlock.body[1].name);
    switch (unlock.body[1].value) {
        .call => |c| {
            try std.testing.expectEqualStrings("hash160", c.func);
            try std.testing.expectEqual(@as(usize, 1), c.args.len);
            try std.testing.expectEqualStrings("t0", c.args[0]);
        },
        else => return error.TestUnexpectedResult,
    }

    // Verify load_prop
    try std.testing.expectEqualStrings("t2", unlock.body[2].name);
    switch (unlock.body[2].value) {
        .load_prop => |lp| try std.testing.expectEqualStrings("pubKeyHash", lp.name),
        else => return error.TestUnexpectedResult,
    }

    // Verify bin_op with result_type
    try std.testing.expectEqualStrings("t3", unlock.body[3].name);
    switch (unlock.body[3].value) {
        .bin_op => |bop| {
            try std.testing.expectEqualStrings("===", bop.op);
            try std.testing.expectEqualStrings("t1", bop.left);
            try std.testing.expectEqualStrings("t2", bop.right);
            try std.testing.expect(bop.result_type != null);
            try std.testing.expectEqualStrings("bytes", bop.result_type.?);
        },
        else => return error.TestUnexpectedResult,
    }

    // Verify assert
    try std.testing.expectEqualStrings("t4", unlock.body[4].name);
    switch (unlock.body[4].value) {
        .assert => |a| try std.testing.expectEqualStrings("t3", a.value),
        else => return error.TestUnexpectedResult,
    }

    // Verify checkSig call with 2 args
    try std.testing.expectEqualStrings("t7", unlock.body[7].name);
    switch (unlock.body[7].value) {
        .call => |c| {
            try std.testing.expectEqualStrings("checkSig", c.func);
            try std.testing.expectEqual(@as(usize, 2), c.args.len);
            try std.testing.expectEqualStrings("t5", c.args[0]);
            try std.testing.expectEqualStrings("t6", c.args[1]);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse if-else ANF IR" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json_source =
        \\{
        \\  "contractName": "IfElse",
        \\  "methods": [
        \\    {
        \\      "body": [
        \\        {
        \\          "name": "t0",
        \\          "value": {
        \\            "kind": "load_const",
        \\            "value": 0
        \\          }
        \\        },
        \\        {
        \\          "name": "t3",
        \\          "value": {
        \\            "cond": "t1",
        \\            "else": [
        \\              {
        \\                "name": "t2",
        \\                "value": {
        \\                  "kind": "load_const",
        \\                  "value": 99
        \\                }
        \\              }
        \\            ],
        \\            "kind": "if",
        \\            "then": [
        \\              {
        \\                "name": "t1",
        \\                "value": {
        \\                  "kind": "load_const",
        \\                  "value": 42
        \\                }
        \\              }
        \\            ]
        \\          }
        \\        }
        \\      ],
        \\      "isPublic": true,
        \\      "name": "check",
        \\      "params": []
        \\    }
        \\  ],
        \\  "properties": []
        \\}
    ;

    const program = try parseANFProgram(allocator, json_source);
    defer program.deinit(allocator);

    try std.testing.expectEqualStrings("IfElse", program.contract_name);
    try std.testing.expectEqual(@as(usize, 1), program.methods.len);

    const method = program.methods[0];
    try std.testing.expectEqual(@as(usize, 2), method.body.len);

    // First binding: load_const 0
    switch (method.body[0].value) {
        .load_const => |lc| switch (lc.value) {
            .integer => |v| try std.testing.expectEqual(@as(i128, 0), v),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    // Second binding: if expression
    switch (method.body[1].value) {
        .@"if" => |if_e| {
            try std.testing.expectEqualStrings("t1", if_e.cond);
            try std.testing.expectEqual(@as(usize, 1), if_e.then.len);
            try std.testing.expectEqual(@as(usize, 1), if_e.@"else".len);

            // then branch: load_const 42
            switch (if_e.then[0].value) {
                .load_const => |lc| switch (lc.value) {
                    .integer => |v| try std.testing.expectEqual(@as(i128, 42), v),
                    else => return error.TestUnexpectedResult,
                },
                else => return error.TestUnexpectedResult,
            }

            // else branch: load_const 99
            switch (if_e.@"else"[0].value) {
                .load_const => |lc| switch (lc.value) {
                    .integer => |v| try std.testing.expectEqual(@as(i128, 99), v),
                    else => return error.TestUnexpectedResult,
                },
                else => return error.TestUnexpectedResult,
            }
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse loop ANF IR" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json_source =
        \\{
        \\  "contractName": "Loop",
        \\  "methods": [
        \\    {
        \\      "body": [
        \\        {
        \\          "name": "t0",
        \\          "value": {
        \\            "body": [
        \\              {
        \\                "name": "t1",
        \\                "value": {
        \\                  "kind": "load_const",
        \\                  "value": 1
        \\                }
        \\              }
        \\            ],
        \\            "count": 5,
        \\            "iterVar": "i",
        \\            "kind": "loop"
        \\          }
        \\        }
        \\      ],
        \\      "isPublic": true,
        \\      "name": "run",
        \\      "params": []
        \\    }
        \\  ],
        \\  "properties": []
        \\}
    ;

    const program = try parseANFProgram(allocator, json_source);
    defer program.deinit(allocator);

    try std.testing.expectEqualStrings("Loop", program.contract_name);
    const method = program.methods[0];
    try std.testing.expectEqual(@as(usize, 1), method.body.len);

    switch (method.body[0].value) {
        .loop => |lp| {
            try std.testing.expectEqual(@as(u32, 5), lp.count);
            try std.testing.expectEqualStrings("i", lp.iter_var);
            try std.testing.expectEqual(@as(usize, 1), lp.body.len);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse unary_op ANF IR" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json_source =
        \\{
        \\  "contractName": "UnaryTest",
        \\  "methods": [
        \\    {
        \\      "body": [
        \\        {
        \\          "name": "t0",
        \\          "value": {
        \\            "kind": "unary_op",
        \\            "op": "!",
        \\            "operand": "flag"
        \\          }
        \\        }
        \\      ],
        \\      "isPublic": true,
        \\      "name": "test",
        \\      "params": [
        \\        {
        \\          "name": "flag",
        \\          "type": "boolean"
        \\        }
        \\      ]
        \\    }
        \\  ],
        \\  "properties": []
        \\}
    ;

    const program = try parseANFProgram(allocator, json_source);
    defer program.deinit(allocator);

    const method = program.methods[0];
    switch (method.body[0].value) {
        .unary_op => |uop| {
            try std.testing.expectEqualStrings("!", uop.op);
            try std.testing.expectEqualStrings("flag", uop.operand);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse load_const variants" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json_source =
        \\{
        \\  "contractName": "ConstTest",
        \\  "methods": [
        \\    {
        \\      "body": [
        \\        {
        \\          "name": "t0",
        \\          "value": {
        \\            "kind": "load_const",
        \\            "value": 42
        \\          }
        \\        },
        \\        {
        \\          "name": "t1",
        \\          "value": {
        \\            "kind": "load_const",
        \\            "value": true
        \\          }
        \\        },
        \\        {
        \\          "name": "t2",
        \\          "value": {
        \\            "kind": "load_const",
        \\            "value": "@ref:t0"
        \\          }
        \\        },
        \\        {
        \\          "name": "t3",
        \\          "value": {
        \\            "kind": "load_const",
        \\            "value": "1976a914"
        \\          }
        \\        },
        \\        {
        \\          "name": "t4",
        \\          "value": {
        \\            "kind": "load_const",
        \\            "value": "@this"
        \\          }
        \\        }
        \\      ],
        \\      "isPublic": true,
        \\      "name": "test",
        \\      "params": []
        \\    }
        \\  ],
        \\  "properties": []
        \\}
    ;

    const program = try parseANFProgram(allocator, json_source);
    defer program.deinit(allocator);

    const bindings = program.methods[0].body;

    // Integer constant
    switch (bindings[0].value) {
        .load_const => |lc| switch (lc.value) {
            .integer => |v| try std.testing.expectEqual(@as(i128, 42), v),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    // Boolean constant
    switch (bindings[1].value) {
        .load_const => |lc| switch (lc.value) {
            .boolean => |v| try std.testing.expect(v),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    // @ref: string
    switch (bindings[2].value) {
        .load_const => |lc| switch (lc.value) {
            .string => |s| try std.testing.expectEqualStrings("@ref:t0", s),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    // hex string literal
    switch (bindings[3].value) {
        .load_const => |lc| switch (lc.value) {
            .string => |s| try std.testing.expectEqualStrings("1976a914", s),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    // @this string
    switch (bindings[4].value) {
        .load_const => |lc| switch (lc.value) {
            .string => |s| try std.testing.expectEqualStrings("@this", s),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse stateful contract with check_preimage and get_state_script" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json_source =
        \\{
        \\  "contractName": "Counter",
        \\  "methods": [
        \\    {
        \\      "body": [
        \\        {
        \\          "name": "t0",
        \\          "value": {
        \\            "kind": "check_preimage",
        \\            "preimage": "txPre"
        \\          }
        \\        },
        \\        {
        \\          "name": "t1",
        \\          "value": {
        \\            "kind": "deserialize_state",
        \\            "preimage": "txPre"
        \\          }
        \\        },
        \\        {
        \\          "name": "t2",
        \\          "value": {
        \\            "kind": "get_state_script"
        \\          }
        \\        }
        \\      ],
        \\      "isPublic": true,
        \\      "name": "increment",
        \\      "params": [
        \\        {
        \\          "name": "txPre",
        \\          "type": "SigHashPreimage"
        \\        }
        \\      ]
        \\    }
        \\  ],
        \\  "properties": [
        \\    {
        \\      "name": "count",
        \\      "readonly": false,
        \\      "type": "bigint"
        \\    }
        \\  ]
        \\}
    ;

    const program = try parseANFProgram(allocator, json_source);
    defer program.deinit(allocator);

    const bindings = program.methods[0].body;
    try std.testing.expectEqual(@as(usize, 3), bindings.len);

    // check_preimage
    switch (bindings[0].value) {
        .check_preimage => |cp| try std.testing.expectEqualStrings("txPre", cp.preimage),
        else => return error.TestUnexpectedResult,
    }

    // deserialize_state
    switch (bindings[1].value) {
        .deserialize_state => |ds| try std.testing.expectEqualStrings("txPre", ds.preimage),
        else => return error.TestUnexpectedResult,
    }

    // get_state_script
    switch (bindings[2].value) {
        .get_state_script => {},
        else => return error.TestUnexpectedResult,
    }
}

// R-126: this fixture used to declare `"properties": []` while its add_output
// named two state values — the very mismatch `checkAddOutputArity` now refuses,
// sitting in the parser's own unit test. Two mutable properties were added to
// make the program well-formed; the assertions below are unchanged.
test "parse add_output ANF IR" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json_source =
        \\{
        \\  "contractName": "OutputTest",
        \\  "methods": [
        \\    {
        \\      "body": [
        \\        {
        \\          "name": "t0",
        \\          "value": {
        \\            "kind": "add_output",
        \\            "preimage": "",
        \\            "satoshis": "sat_ref",
        \\            "stateValues": ["v1", "v2"]
        \\          }
        \\        }
        \\      ],
        \\      "isPublic": true,
        \\      "name": "spend",
        \\      "params": []
        \\    }
        \\  ],
        \\  "properties": [
        \\    { "name": "a", "readonly": false, "type": "bigint" },
        \\    { "name": "b", "readonly": false, "type": "bigint" }
        \\  ]
        \\}
    ;

    const program = try parseANFProgram(allocator, json_source);
    defer program.deinit(allocator);

    switch (program.methods[0].body[0].value) {
        .add_output => |ao| {
            try std.testing.expectEqualStrings("sat_ref", ao.satoshis);
            try std.testing.expectEqual(@as(usize, 2), ao.state_values.len);
            try std.testing.expectEqualStrings("v1", ao.state_values[0]);
            try std.testing.expectEqualStrings("v2", ao.state_values[1]);
            try std.testing.expectEqualStrings("", ao.preimage);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse method_call ANF IR" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json_source =
        \\{
        \\  "contractName": "MethodCallTest",
        \\  "methods": [
        \\    {
        \\      "body": [
        \\        {
        \\          "name": "t0",
        \\          "value": {
        \\            "kind": "load_const",
        \\            "value": "@this"
        \\          }
        \\        },
        \\        {
        \\          "name": "t1",
        \\          "value": {
        \\            "args": ["a0", "a1"],
        \\            "kind": "method_call",
        \\            "method": "compute",
        \\            "object": "t0"
        \\          }
        \\        }
        \\      ],
        \\      "isPublic": true,
        \\      "name": "run",
        \\      "params": []
        \\    }
        \\  ],
        \\  "properties": []
        \\}
    ;

    const program = try parseANFProgram(allocator, json_source);
    defer program.deinit(allocator);

    switch (program.methods[0].body[1].value) {
        .method_call => |mc| {
            try std.testing.expectEqualStrings("t0", mc.object);
            try std.testing.expectEqualStrings("compute", mc.method);
            try std.testing.expectEqual(@as(usize, 2), mc.args.len);
            try std.testing.expectEqualStrings("a0", mc.args[0]);
            try std.testing.expectEqualStrings("a1", mc.args[1]);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse update_prop ANF IR" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json_source =
        \\{
        \\  "contractName": "PropTest",
        \\  "methods": [
        \\    {
        \\      "body": [
        \\        {
        \\          "name": "t0",
        \\          "value": {
        \\            "kind": "update_prop",
        \\            "name": "count",
        \\            "value": "t7"
        \\          }
        \\        }
        \\      ],
        \\      "isPublic": true,
        \\      "name": "inc",
        \\      "params": []
        \\    }
        \\  ],
        \\  "properties": []
        \\}
    ;

    const program = try parseANFProgram(allocator, json_source);
    defer program.deinit(allocator);

    switch (program.methods[0].body[0].value) {
        .update_prop => |up| {
            try std.testing.expectEqualStrings("count", up.name);
            try std.testing.expectEqualStrings("t7", up.value);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "serialize and round-trip basic P2PKH" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Build a minimal P2PKH program
    const program = types.ANFProgram{
        .contract_name = "P2PKH",
        .properties = @constCast(&[_]types.ANFProperty{
            .{ .name = "pubKeyHash", .type_name = "Addr", .readonly = true },
        }),
        .methods = @constCast(&[_]types.ANFMethod{
            .{
                .name = "unlock",
                .is_public = true,
                .params = @constCast(&[_]types.ANFParam{
                    .{ .name = "sig", .type_name = "Sig" },
                    .{ .name = "pubKey", .type_name = "PubKey" },
                }),
                .body = @constCast(&[_]types.ANFBinding{
                    .{ .name = "t0", .value = .{ .load_param = .{ .name = "pubKey" } } },
                    .{ .name = "t1", .value = .{ .call = .{ .func = "hash160", .args = @constCast(&[_][]const u8{"t0"}) } } },
                    .{ .name = "t2", .value = .{ .load_prop = .{ .name = "pubKeyHash" } } },
                    .{ .name = "t3", .value = .{ .assert = .{ .value = "t2" } } },
                }),
            },
        }),
    };

    const json = try serializeCanonicalJSON(allocator, program);
    defer allocator.free(json);

    // Parse it back
    const reparsed = try parseANFProgram(allocator, json);
    defer reparsed.deinit(allocator);

    try std.testing.expectEqualStrings("P2PKH", reparsed.contract_name);
    try std.testing.expectEqual(@as(usize, 1), reparsed.properties.len);
    try std.testing.expectEqual(@as(usize, 1), reparsed.methods.len);
    try std.testing.expectEqualStrings("unlock", reparsed.methods[0].name);
    try std.testing.expect(reparsed.methods[0].is_public);
    try std.testing.expectEqual(@as(usize, 4), reparsed.methods[0].body.len);
}
