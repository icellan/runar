//! JSON parser and serializer for Runar ANF IR artifacts.
//! Reads the canonical JSON format produced by other Runar compilers
//! and produces canonical JSON with sorted keys and 2-space indentation
//! for conformance testing.

const std = @import("std");
const types = @import("types.zig");

const ParseError = error{
    MissingField,
    InvalidKind,
    InvalidType,
    InvalidOperator,
    InvalidConstValue,
    UnexpectedValueType,
    MaxRecursionDepthExceeded,
};

const max_parse_depth: u32 = 256;

// ============================================================================
// Public API
// ============================================================================

/// Parse a JSON string into an ANFProgram.
pub fn parseANFProgram(allocator: std.mem.Allocator, json_source: []const u8) !types.ANFProgram {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_source, .{});
    defer parsed.deinit();

    const root = parsed.value;
    return try parseProgram(allocator, root);
}

/// Serialize ANF IR to canonical JSON with sorted keys and 2-space indentation.
/// Used for conformance testing — SHA-256 of this output must match other compilers.
pub fn serializeCanonicalJSON(allocator: std.mem.Allocator, program: types.ANFProgram) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try writeCanonicalProgram(buf.writer(allocator), program, 0);
    try buf.append(allocator, '\n');

    return buf.toOwnedSlice(allocator);
}

/// Serialize the final artifact to JSON.
pub fn serializeArtifact(allocator: std.mem.Allocator, artifact: types.Artifact) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try writeCanonicalArtifact(buf.writer(allocator), artifact, 0);
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

    return types.ANFProgram{
        .contract_name = try allocator.dupe(u8, contract_name),
        .properties = properties,
        .methods = try method_list.toOwnedSlice(allocator),
    };
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
                const int_val: i128 = @intFromFloat(f);
                const roundtrip: f64 = @floatFromInt(int_val);
                if (roundtrip != f) return ParseError.InvalidConstValue;
                break :blk @as(?types.ConstValue, .{ .integer = int_val });
            },
            .bool => |b| @as(?types.ConstValue, .{ .boolean = b }),
            .string => |s| @as(?types.ConstValue, .{ .string = try allocator.dupe(u8, s) }),
            else => return ParseError.InvalidConstValue,
        } else null;
        result[i] = .{
            .name = try allocator.dupe(u8, try getString(prop_obj, "name")),
            .type_name = try allocator.dupe(u8, type_str),
            .type_info = types.parseRunarType(type_str),
            .readonly = try getBool(prop_obj, "readonly"),
            .initial_value = initial_value,
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

const BindingError = ParseError || std.mem.Allocator.Error;

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
    deserialize_state, add_output, add_raw_output,
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
});

fn parseANFValue(allocator: std.mem.Allocator, obj: std.json.ObjectMap, depth: u32) BindingError!types.ANFValue {
    if (depth >= max_parse_depth) return ParseError.MaxRecursionDepthExceeded;

    const kind = try getString(obj, "kind");
    const tag = kind_map.get(kind) orelse return ParseError.InvalidKind;

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
        } },
        .deserialize_state => .{ .deserialize_state = .{
            .preimage = try allocator.dupe(u8, try getString(obj, "preimage")),
        } },
        .add_output => try parseAddOutput(allocator, obj),
        .add_raw_output => try parseAddRawOutput(allocator, obj),
    };
}

fn parseLoadConst(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !types.ANFValue {
    const val = obj.get("value") orelse return ParseError.MissingField;

    switch (val) {
        .integer => |i| return .{ .load_const = .{ .value = .{ .integer = i } } },
        .float => |f| {
            const int_val: i128 = @intFromFloat(f);
            const roundtrip: f64 = @floatFromInt(int_val);
            if (roundtrip != f) return ParseError.InvalidConstValue;
            return .{ .load_const = .{ .value = .{ .integer = int_val } } };
        },
        .bool => |b| return .{ .load_const = .{ .value = .{ .boolean = b } } },
        .string => |s| return .{ .load_const = .{ .value = .{ .string = try allocator.dupe(u8, s) } } },
        else => return ParseError.InvalidConstValue,
    }
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

    const if_expr = try allocator.create(types.ANFIf);
    if_expr.* = .{
        .cond = try allocator.dupe(u8, cond),
        .then = then_bindings,
        .@"else" = else_bindings,
    };

    return .{ .@"if" = if_expr };
}

fn parseLoop(allocator: std.mem.Allocator, obj: std.json.ObjectMap, depth: u32) BindingError!types.ANFValue {
    const count_val = obj.get("count") orelse return ParseError.MissingField;
    const count: u32 = switch (count_val) {
        .integer => |i| @intCast(i),
        .float => |f| @intFromFloat(f),
        else => return ParseError.UnexpectedValueType,
    };
    const iter_var = try getString(obj, "iterVar");
    const body_val = obj.get("body") orelse return ParseError.MissingField;
    const body_bindings = try parseBindings(allocator, body_val.array, depth + 1);

    const loop_node = try allocator.create(types.ANFLoop);
    loop_node.* = .{
        .count = count,
        .body = body_bindings,
        .iter_var = try allocator.dupe(u8, iter_var),
    };

    return .{ .loop = loop_node };
}

fn parseAssert(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !types.ANFValue {
    const val_ref = try getString(obj, "value");

    return .{ .assert = .{
        .value = try allocator.dupe(u8, val_ref),
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

        // Sorted keys: initialValue, name, readonly, type
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
            // Sorted keys: body, count, iterVar, kind
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
            try writer.writeByte('\n');

            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
        .assert => |a| {
            try writer.writeAll("{\n");
            // Sorted keys: kind, value
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
            // Sorted keys: kind, preimage
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "check_preimage");
            try writer.writeAll(",\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "preimage");
            try writer.writeAll(": ");
            try writeJsonString(writer, cp.preimage);
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
        // Legacy variants — write as generic object with kind
        else => {
            try writer.writeAll("{\n");
            try writeIndent(writer, depth + 1);
            try writeJsonString(writer, "kind");
            try writer.writeAll(": ");
            try writeJsonString(writer, "unknown");
            try writer.writeByte('\n');
            try writeIndent(writer, depth);
            try writer.writeByte('}');
        },
    }
}

fn writeConstValue(writer: anytype, value: types.ConstValue) !void {
    switch (value) {
        .integer => |i| try writer.print("{d}", .{i}),
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
        \\  "properties": []
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
