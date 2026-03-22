//! Conformance test runner — validates Zig compiler produces byte-identical
//! output to the TypeScript, Go, Rust, and Python compilers.
//!
//! Tests read ANF IR JSON from conformance/tests/*/expected-ir.json,
//! run the full pipeline (parse -> stack lower -> emit), and compare
//! the output script hex against expected-script.hex.
//!
//! Each test case has its own test function so individual failures are visible
//! in the test runner output.

const std = @import("std");
const json_parser = @import("../ir/json.zig");
const stack_lower = @import("../passes/stack_lower.zig");
const peephole = @import("../passes/peephole.zig");
const emit_mod = @import("../codegen/emit.zig");
const ir_types = @import("../ir/types.zig");

// ============================================================================
// JSON IR Parser — reads the canonical expected-ir.json format
// (retained as validation layer; the real pipeline uses ir/json.zig)
// ============================================================================

/// Parsed representation of a conformance test's expected-ir.json.
/// This mirrors the JSON structure produced by all 4 other Runar compilers.
const ConformanceIR = struct {
    contract_name: []const u8,
    properties: []IRProperty,
    methods: []IRMethod,
    arena: std.heap.ArenaAllocator,

    fn deinit(self: *ConformanceIR) void {
        self.arena.deinit();
    }
};

const IRProperty = struct {
    name: []const u8,
    type_str: []const u8,
    readonly: bool,
    initial_value: ?IRConstValue = null,
};

const IRMethod = struct {
    name: []const u8,
    is_public: bool,
    params: []IRParam,
    body: []IRBinding,
};

const IRParam = struct {
    name: []const u8,
    type_str: []const u8,
};

const IRBinding = struct {
    name: []const u8,
    value: IRValue,
};

const IRConstValue = union(enum) {
    int: i64,
    boolean: bool,
    string: []const u8,
};

const IRValue = union(enum) {
    load_prop: []const u8,
    load_param: []const u8,
    load_const: IRConstValue,
    load_const_ref: []const u8, // "@ref:xxx" references
    update_prop: struct { name: []const u8, value_ref: []const u8 },
    call: struct { func: []const u8, args: []const []const u8 },
    bin_op: struct { op: []const u8, left: []const u8, right: []const u8, result_type: ?[]const u8 },
    unary_op: struct { op: []const u8, operand: []const u8 },
    assert_val: []const u8,
    if_expr: struct { cond: []const u8, then_bindings: []IRBinding, else_bindings: []IRBinding },
    loop_expr: struct { iter_var: []const u8, count: i64, body: []IRBinding },
    method_call: struct { object: []const u8, method: []const u8, args: []const []const u8 },
    add_output: struct { satoshis: []const u8, state_values: []const []const u8, preimage: []const u8 },
    check_preimage: []const u8,
    deserialize_state: []const u8,
    get_state_script: void,
};

/// Explicit error set to break the recursive cycle:
/// parseBindings -> parseBinding -> parseValue -> parseBindings
const ParseError = std.mem.Allocator.Error || error{
    InvalidJSON,
    MissingContractName,
    InvalidContractName,
    MissingProperties,
    InvalidProperties,
    MissingMethods,
    InvalidMethods,
    InvalidProperty,
    MissingName,
    InvalidName,
    MissingType,
    InvalidType,
    MissingReadonly,
    InvalidReadonly,
    InvalidMethod,
    MissingIsPublic,
    InvalidIsPublic,
    MissingParams,
    InvalidParams,
    InvalidParam,
    MissingBody,
    InvalidBody,
    InvalidBinding,
    MissingValue,
    InvalidValue,
    MissingKind,
    InvalidKind,
    MissingFunc,
    InvalidFunc,
    MissingArgs,
    InvalidArgs,
    InvalidArg,
    MissingOp,
    InvalidOp,
    MissingLeft,
    InvalidLeft,
    MissingRight,
    InvalidRight,
    MissingOperand,
    InvalidOperand,
    MissingCond,
    InvalidCond,
    MissingThen,
    InvalidThen,
    MissingElse,
    InvalidElse,
    MissingIterVar,
    InvalidIterVar,
    MissingCount,
    InvalidCount,
    MissingPreimage,
    InvalidPreimage,
    InvalidConstValue,
    MissingObject,
    InvalidObject,
    MissingMethodName,
    InvalidMethodName,
    MissingSatoshis,
    InvalidSatoshis,
    MissingStateValues,
    InvalidStateValues,
    InvalidStateValue,
    UnknownKind,
    Overflow,
    InvalidCharacter,
    UnexpectedToken,
    DuplicateJsonField,
    SyntaxError,
    ValueTooLong,
    BufferUnderrun,
    // std.json errors
    UnexpectedEndOfInput,
    InvalidEnumTag,
};

/// Parse a conformance expected-ir.json into our IR representation.
fn parseConformanceJSON(parent_allocator: std.mem.Allocator, json_source: []const u8) ParseError!ConformanceIR {
    var arena = std.heap.ArenaAllocator.init(parent_allocator);
    errdefer arena.deinit();
    const allocator = arena.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_source, .{}) catch
        return error.InvalidJSON;
    const root = parsed.value;

    if (root != .object) return error.InvalidJSON;

    const contract_name = blk: {
        const val = root.object.get("contractName") orelse return error.MissingContractName;
        break :blk switch (val) {
            .string => |s| s,
            else => return error.InvalidContractName,
        };
    };

    // Parse properties
    const props_json = root.object.get("properties") orelse return error.MissingProperties;
    if (props_json != .array) return error.InvalidProperties;
    const properties = try allocator.alloc(IRProperty, props_json.array.items.len);
    for (props_json.array.items, 0..) |prop_val, i| {
        properties[i] = try parseProperty(prop_val);
    }

    // Parse methods
    const methods_json = root.object.get("methods") orelse return error.MissingMethods;
    if (methods_json != .array) return error.InvalidMethods;
    const methods = try allocator.alloc(IRMethod, methods_json.array.items.len);
    for (methods_json.array.items, 0..) |method_val, i| {
        methods[i] = try parseMethod(allocator, method_val);
    }

    return ConformanceIR{
        .contract_name = contract_name,
        .properties = properties,
        .methods = methods,
        .arena = arena,
    };
}

fn parseProperty(val: std.json.Value) ParseError!IRProperty {
    if (val != .object) return error.InvalidProperty;
    const obj = val.object;

    const name = switch (obj.get("name") orelse return error.MissingName) {
        .string => |s| s,
        else => return error.InvalidName,
    };
    const type_str = switch (obj.get("type") orelse return error.MissingType) {
        .string => |s| s,
        else => return error.InvalidType,
    };
    const readonly = switch (obj.get("readonly") orelse return error.MissingReadonly) {
        .bool => |b| b,
        else => return error.InvalidReadonly,
    };

    var initial_value: ?IRConstValue = null;
    if (obj.get("initialValue")) |iv| {
        initial_value = switch (iv) {
            .integer => |n| IRConstValue{ .int = n },
            .bool => |b| IRConstValue{ .boolean = b },
            .string => |s| IRConstValue{ .string = s },
            else => null,
        };
    }

    return IRProperty{
        .name = name,
        .type_str = type_str,
        .readonly = readonly,
        .initial_value = initial_value,
    };
}

fn parseMethod(allocator: std.mem.Allocator, val: std.json.Value) ParseError!IRMethod {
    if (val != .object) return error.InvalidMethod;
    const obj = val.object;

    const name = switch (obj.get("name") orelse return error.MissingName) {
        .string => |s| s,
        else => return error.InvalidName,
    };
    const is_public = switch (obj.get("isPublic") orelse return error.MissingIsPublic) {
        .bool => |b| b,
        else => return error.InvalidIsPublic,
    };

    // Parse params
    const params_json = obj.get("params") orelse return error.MissingParams;
    if (params_json != .array) return error.InvalidParams;
    const params = try allocator.alloc(IRParam, params_json.array.items.len);
    for (params_json.array.items, 0..) |p, i| {
        if (p != .object) return error.InvalidParam;
        params[i] = .{
            .name = switch (p.object.get("name") orelse return error.MissingName) {
                .string => |s| s,
                else => return error.InvalidName,
            },
            .type_str = switch (p.object.get("type") orelse return error.MissingType) {
                .string => |s| s,
                else => return error.InvalidType,
            },
        };
    }

    // Parse body
    const body_json = obj.get("body") orelse return error.MissingBody;
    if (body_json != .array) return error.InvalidBody;
    const body = try parseBindings(allocator, body_json.array.items);

    return IRMethod{
        .name = name,
        .is_public = is_public,
        .params = params,
        .body = body,
    };
}

fn parseBindings(allocator: std.mem.Allocator, items: []const std.json.Value) ParseError![]IRBinding {
    const bindings = try allocator.alloc(IRBinding, items.len);
    for (items, 0..) |item, i| {
        bindings[i] = try parseBinding(allocator, item);
    }
    return bindings;
}

fn parseBinding(allocator: std.mem.Allocator, val: std.json.Value) ParseError!IRBinding {
    if (val != .object) return error.InvalidBinding;
    const obj = val.object;

    const name = switch (obj.get("name") orelse return error.MissingName) {
        .string => |s| s,
        else => return error.InvalidName,
    };

    const value_obj = obj.get("value") orelse return error.MissingValue;
    const value = try parseValue(allocator, value_obj);

    return IRBinding{ .name = name, .value = value };
}

fn parseValue(allocator: std.mem.Allocator, val: std.json.Value) ParseError!IRValue {
    if (val != .object) return error.InvalidValue;
    const obj = val.object;

    const kind = switch (obj.get("kind") orelse return error.MissingKind) {
        .string => |s| s,
        else => return error.InvalidKind,
    };

    if (std.mem.eql(u8, kind, "load_prop")) {
        const name = switch (obj.get("name") orelse return error.MissingName) {
            .string => |s| s,
            else => return error.InvalidName,
        };
        return IRValue{ .load_prop = name };
    }

    if (std.mem.eql(u8, kind, "load_param")) {
        const name = switch (obj.get("name") orelse return error.MissingName) {
            .string => |s| s,
            else => return error.InvalidName,
        };
        return IRValue{ .load_param = name };
    }

    if (std.mem.eql(u8, kind, "load_const")) {
        const v = obj.get("value") orelse return error.MissingValue;
        switch (v) {
            .integer => |n| return IRValue{ .load_const = .{ .int = n } },
            .bool => |b| return IRValue{ .load_const = .{ .boolean = b } },
            .string => |s| {
                // Check for "@ref:" prefix — these are temp variable references
                if (std.mem.startsWith(u8, s, "@ref:")) {
                    return IRValue{ .load_const_ref = s[5..] };
                }
                return IRValue{ .load_const = .{ .string = s } };
            },
            else => return error.InvalidConstValue,
        }
    }

    if (std.mem.eql(u8, kind, "update_prop")) {
        const name = switch (obj.get("name") orelse return error.MissingName) {
            .string => |s| s,
            else => return error.InvalidName,
        };
        const value_ref = switch (obj.get("value") orelse return error.MissingValue) {
            .string => |s| s,
            else => return error.InvalidValue,
        };
        return IRValue{ .update_prop = .{ .name = name, .value_ref = value_ref } };
    }

    if (std.mem.eql(u8, kind, "call")) {
        const func = switch (obj.get("func") orelse return error.MissingFunc) {
            .string => |s| s,
            else => return error.InvalidFunc,
        };
        const args_json = obj.get("args") orelse return error.MissingArgs;
        if (args_json != .array) return error.InvalidArgs;
        const args = try allocator.alloc([]const u8, args_json.array.items.len);
        for (args_json.array.items, 0..) |arg, i| {
            args[i] = switch (arg) {
                .string => |s| s,
                else => return error.InvalidArg,
            };
        }
        return IRValue{ .call = .{ .func = func, .args = args } };
    }

    if (std.mem.eql(u8, kind, "bin_op")) {
        const op = switch (obj.get("op") orelse return error.MissingOp) {
            .string => |s| s,
            else => return error.InvalidOp,
        };
        const left = switch (obj.get("left") orelse return error.MissingLeft) {
            .string => |s| s,
            else => return error.InvalidLeft,
        };
        const right = switch (obj.get("right") orelse return error.MissingRight) {
            .string => |s| s,
            else => return error.InvalidRight,
        };
        const result_type: ?[]const u8 = if (obj.get("result_type")) |rt| switch (rt) {
            .string => |s| s,
            else => null,
        } else null;
        return IRValue{ .bin_op = .{ .op = op, .left = left, .right = right, .result_type = result_type } };
    }

    if (std.mem.eql(u8, kind, "unary_op")) {
        const op = switch (obj.get("op") orelse return error.MissingOp) {
            .string => |s| s,
            else => return error.InvalidOp,
        };
        const operand = switch (obj.get("operand") orelse return error.MissingOperand) {
            .string => |s| s,
            else => return error.InvalidOperand,
        };
        return IRValue{ .unary_op = .{ .op = op, .operand = operand } };
    }

    if (std.mem.eql(u8, kind, "assert")) {
        const v = switch (obj.get("value") orelse return error.MissingValue) {
            .string => |s| s,
            else => return error.InvalidValue,
        };
        return IRValue{ .assert_val = v };
    }

    if (std.mem.eql(u8, kind, "if")) {
        const cond = switch (obj.get("cond") orelse return error.MissingCond) {
            .string => |s| s,
            else => return error.InvalidCond,
        };
        const then_json = obj.get("then") orelse return error.MissingThen;
        if (then_json != .array) return error.InvalidThen;
        const then_bindings = try parseBindings(allocator, then_json.array.items);

        const else_json = obj.get("else") orelse return error.MissingElse;
        if (else_json != .array) return error.InvalidElse;
        const else_bindings = try parseBindings(allocator, else_json.array.items);

        return IRValue{ .if_expr = .{
            .cond = cond,
            .then_bindings = then_bindings,
            .else_bindings = else_bindings,
        } };
    }

    if (std.mem.eql(u8, kind, "loop")) {
        const iter_var = switch (obj.get("iterVar") orelse return error.MissingIterVar) {
            .string => |s| s,
            else => return error.InvalidIterVar,
        };
        const count = switch (obj.get("count") orelse return error.MissingCount) {
            .integer => |n| n,
            else => return error.InvalidCount,
        };
        const body_json = obj.get("body") orelse return error.MissingBody;
        if (body_json != .array) return error.InvalidBody;
        const body = try parseBindings(allocator, body_json.array.items);

        return IRValue{ .loop_expr = .{
            .iter_var = iter_var,
            .count = count,
            .body = body,
        } };
    }

    if (std.mem.eql(u8, kind, "check_preimage")) {
        const preimage = switch (obj.get("preimage") orelse return error.MissingPreimage) {
            .string => |s| s,
            else => return error.InvalidPreimage,
        };
        return IRValue{ .check_preimage = preimage };
    }

    if (std.mem.eql(u8, kind, "deserialize_state")) {
        const preimage = switch (obj.get("preimage") orelse return error.MissingPreimage) {
            .string => |s| s,
            else => return error.InvalidPreimage,
        };
        return IRValue{ .deserialize_state = preimage };
    }

    if (std.mem.eql(u8, kind, "method_call")) {
        const object_ref = switch (obj.get("object") orelse return error.MissingObject) {
            .string => |s| s,
            else => return error.InvalidObject,
        };
        const method_name = switch (obj.get("method") orelse return error.MissingMethodName) {
            .string => |s| s,
            else => return error.InvalidMethodName,
        };
        const args_json = obj.get("args") orelse return error.MissingArgs;
        if (args_json != .array) return error.InvalidArgs;
        const args = try allocator.alloc([]const u8, args_json.array.items.len);
        for (args_json.array.items, 0..) |arg, i| {
            args[i] = switch (arg) {
                .string => |s| s,
                else => return error.InvalidArg,
            };
        }
        return IRValue{ .method_call = .{ .object = object_ref, .method = method_name, .args = args } };
    }

    if (std.mem.eql(u8, kind, "add_output")) {
        const satoshis = switch (obj.get("satoshis") orelse return error.MissingSatoshis) {
            .string => |s| s,
            else => return error.InvalidSatoshis,
        };
        const preimage_ref: []const u8 = if (obj.get("preimage")) |p| switch (p) {
            .string => |s| s,
            else => "",
        } else "";
        const sv_json = obj.get("stateValues") orelse return error.MissingStateValues;
        if (sv_json != .array) return error.InvalidStateValues;
        const state_values = try allocator.alloc([]const u8, sv_json.array.items.len);
        for (sv_json.array.items, 0..) |sv, i| {
            state_values[i] = switch (sv) {
                .string => |s| s,
                else => return error.InvalidStateValue,
            };
        }
        return IRValue{ .add_output = .{ .satoshis = satoshis, .state_values = state_values, .preimage = preimage_ref } };
    }

    if (std.mem.eql(u8, kind, "get_state_script")) {
        return IRValue{ .get_state_script = {} };
    }

    std.debug.print("Unknown ANF IR kind: {s}\n", .{kind});
    return error.UnknownKind;
}

// ============================================================================
// Shared test runner
// ============================================================================

/// The base path from the test binary's CWD to the conformance data.
/// The build system runs tests from the repo root.
const conformance_base = "../../conformance/tests/";

/// Count bindings recursively (including those inside if/loop bodies).
fn countBindingsDeep(bindings: []const IRBinding) usize {
    var total: usize = bindings.len;
    for (bindings) |binding| {
        switch (binding.value) {
            .if_expr => |ie| {
                total += countBindingsDeep(ie.then_bindings);
                total += countBindingsDeep(ie.else_bindings);
            },
            .loop_expr => |le| {
                total += countBindingsDeep(le.body);
            },
            else => {},
        }
    }
    return total;
}

/// Emit all methods' flat instructions to a single hex string via EmitContext.
/// For multi-method contracts, lower() produces a single __dispatch method containing
/// the full dispatch table; for single-method contracts, it produces one method.
/// The result matches the expected-script.hex format (no OP_CODESEPARATOR prefix).
fn emitPipelineHex(allocator: std.mem.Allocator, stack_program: ir_types.StackProgram) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(allocator);
    for (stack_program.methods) |method| {
        const method_hex = try emit_mod.emitMethodScript(allocator, method.instructions);
        defer allocator.free(method_hex);
        try out.appendSlice(allocator, method_hex);
    }
    return try out.toOwnedSlice(allocator);
}

/// Run a single conformance test: read expected-ir.json, parse it,
/// run the full compilation pipeline, and compare emitted hex to expected-script.hex.
fn runConformanceTest(test_name: []const u8) !void {
    const allocator = std.testing.allocator;

    // Build file paths
    const ir_path = try std.fmt.allocPrint(allocator, "{s}{s}/expected-ir.json", .{ conformance_base, test_name });
    defer allocator.free(ir_path);

    const script_path = try std.fmt.allocPrint(allocator, "{s}{s}/expected-script.hex", .{ conformance_base, test_name });
    defer allocator.free(script_path);

    // Open expected IR JSON
    const ir_file = std.fs.cwd().openFile(ir_path, .{}) catch |err| {
        std.debug.print("[FAIL] {s}: cannot open expected-ir.json ({s})\n", .{ test_name, @errorName(err) });
        return err;
    };
    defer ir_file.close();

    // Open expected script hex
    const script_file = std.fs.cwd().openFile(script_path, .{}) catch |err| {
        std.debug.print("[FAIL] {s}: cannot open expected-script.hex ({s})\n", .{ test_name, @errorName(err) });
        return err;
    };
    defer script_file.close();

    // Read file contents
    const ir_source = try ir_file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(ir_source);

    const expected_hex_raw = try script_file.readToEndAlloc(allocator, 4 * 1024 * 1024);
    defer allocator.free(expected_hex_raw);

    // Strip whitespace from expected hex
    const expected_hex = try stripWhitespace(allocator, expected_hex_raw);
    defer allocator.free(expected_hex);

    if (expected_hex.len == 0) {
        std.debug.print("[FAIL] {s}: expected-script.hex is empty\n", .{test_name});
        return error.InvalidExpectedHex;
    }

    // Phase 1: Parse the conformance JSON into our local IR (validation)
    var ir = try parseConformanceJSON(allocator, ir_source);
    defer ir.deinit();

    // Validate basic structure
    try std.testing.expect(ir.contract_name.len > 0);
    try std.testing.expect(ir.methods.len > 0);

    // Validate each method has a name and body
    var total_bindings: usize = 0;
    for (ir.methods) |method| {
        try std.testing.expect(method.name.len > 0);
        try std.testing.expect(method.body.len > 0);
        total_bindings += countBindingsDeep(method.body);
    }

    // Validate that expected hex is valid lowercase hex with even length
    for (expected_hex) |c| {
        const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!is_hex) {
            std.debug.print("[FAIL] {s}: expected-script.hex contains non-hex char: 0x{x:0>2}\n", .{ test_name, c });
            return error.InvalidExpectedHex;
        }
    }
    if (expected_hex.len % 2 != 0) {
        std.debug.print("[FAIL] {s}: expected-script.hex has odd length {d}\n", .{ test_name, expected_hex.len });
        return error.InvalidExpectedHex;
    }

    std.debug.print("[PARSE] {s}: IR validated — contract={s}, {d} methods, {d} properties, {d} bindings, {d} hex bytes expected\n", .{
        test_name,
        ir.contract_name,
        ir.methods.len,
        ir.properties.len,
        total_bindings,
        expected_hex.len / 2,
    });

    // Phase 2: Full pipeline — parse via canonical parser, stack lower, emit, compare
    // Use an arena for the pipeline allocations so cleanup is straightforward
    var pipeline_arena = std.heap.ArenaAllocator.init(allocator);
    defer pipeline_arena.deinit();
    const pipeline_alloc = pipeline_arena.allocator();

    // Parse via the canonical ir/json.zig parser into ANFProgram
    const program = json_parser.parseANFProgram(pipeline_alloc, ir_source) catch |err| {
        std.debug.print("[FAIL] {s}: IR parse failed ({s})\n", .{ test_name, @errorName(err) });
        return err;
    };

    // Pass 5: Stack lower
    var stack_program = stack_lower.lower(pipeline_alloc, program) catch |err| {
        std.debug.print("[FAIL] {s}: stack lower failed ({s})\n", .{ test_name, @errorName(err) });
        return err;
    };

    const optimized_methods = peephole.optimize(pipeline_alloc, stack_program.methods) catch |err| {
        std.debug.print("[FAIL] {s}: peephole optimize failed ({s})\n", .{ test_name, @errorName(err) });
        return err;
    };
    stack_program.methods = optimized_methods;

    // Pass 6: Emit to hex
    const output_hex = emitPipelineHex(pipeline_alloc, stack_program) catch |err| {
        std.debug.print("[FAIL] {s}: emit failed ({s})\n", .{ test_name, @errorName(err) });
        return err;
    };

    // Compare against golden expected hex
    if (std.mem.eql(u8, expected_hex, output_hex)) {
        std.debug.print("[PASS] {s}: hex matches expected output ({d} bytes)\n", .{ test_name, expected_hex.len / 2 });
    } else {
        std.debug.print("[MISMATCH] {s}: hex differs\n", .{test_name});
        // Show first divergence point for debugging
        const min_len = @min(expected_hex.len, output_hex.len);
        var diff_pos: usize = 0;
        while (diff_pos < min_len and expected_hex[diff_pos] == output_hex[diff_pos]) : (diff_pos += 1) {}
        std.debug.print("  first diff at hex offset {d} (byte {d})\n", .{ diff_pos, diff_pos / 2 });
        const context_start = if (diff_pos >= 20) diff_pos - 20 else 0;
        const context_end_exp = @min(diff_pos + 20, expected_hex.len);
        const context_end_out = @min(diff_pos + 20, output_hex.len);
        std.debug.print("  expected: ...{s}...\n", .{expected_hex[context_start..context_end_exp]});
        std.debug.print("  actual:   ...{s}...\n", .{output_hex[context_start..context_end_out]});
        std.debug.print("  expected len: {d}, actual len: {d}\n", .{ expected_hex.len, output_hex.len });
        return error.HexMismatch;
    }
}

/// Strip all ASCII whitespace from a byte slice, returning a new allocation.
fn stripWhitespace(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    defer result.deinit(allocator);
    try result.ensureTotalCapacity(allocator, input.len);
    for (input) |c| {
        if (c != ' ' and c != '\t' and c != '\n' and c != '\r') {
            try result.append(allocator, c);
        }
    }
    return try result.toOwnedSlice(allocator);
}

// ============================================================================
// Individual test functions — one per conformance test case (27 total)
// ============================================================================

test "conformance: arithmetic" {
    try runConformanceTest("arithmetic");
}

test "conformance: auction" {
    try runConformanceTest("auction");
}

test "conformance: basic-p2pkh" {
    try runConformanceTest("basic-p2pkh");
}

test "conformance: blake3" {
    try runConformanceTest("blake3");
}

test "conformance: boolean-logic" {
    try runConformanceTest("boolean-logic");
}

test "conformance: bounded-loop" {
    try runConformanceTest("bounded-loop");
}

test "conformance: convergence-proof" {
    try runConformanceTest("convergence-proof");
}

test "conformance: covenant-vault" {
    try runConformanceTest("covenant-vault");
}

test "conformance: ec-demo" {
    try runConformanceTest("ec-demo");
}

test "conformance: ec-primitives" {
    try runConformanceTest("ec-primitives");
}

test "conformance: escrow" {
    try runConformanceTest("escrow");
}

test "conformance: function-patterns" {
    try runConformanceTest("function-patterns");
}

test "conformance: if-else" {
    try runConformanceTest("if-else");
}

test "conformance: if-without-else" {
    try runConformanceTest("if-without-else");
}

test "conformance: math-demo" {
    try runConformanceTest("math-demo");
}

test "conformance: multi-method" {
    try runConformanceTest("multi-method");
}

test "conformance: oracle-price" {
    try runConformanceTest("oracle-price");
}

test "conformance: post-quantum-slhdsa" {
    try runConformanceTest("post-quantum-slhdsa");
}

test "conformance: post-quantum-wallet" {
    try runConformanceTest("post-quantum-wallet");
}

test "conformance: post-quantum-wots" {
    try runConformanceTest("post-quantum-wots");
}

test "conformance: property-initializers" {
    try runConformanceTest("property-initializers");
}

test "conformance: schnorr-zkp" {
    try runConformanceTest("schnorr-zkp");
}

test "conformance: sphincs-wallet" {
    try runConformanceTest("sphincs-wallet");
}

test "conformance: stateful" {
    try runConformanceTest("stateful");
}

test "conformance: stateful-counter" {
    try runConformanceTest("stateful-counter");
}

test "conformance: token-ft" {
    try runConformanceTest("token-ft");
}

test "conformance: token-nft" {
    try runConformanceTest("token-nft");
}
