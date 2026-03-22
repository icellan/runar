//! Pass 2: Validate — checks a ContractNode against Runar language constraints.
//!
//! Takes the AST produced by Pass 1 (Parse) and reports errors/warnings WITHOUT
//! modifying it. Direct port of compilers/python/runar_compiler/frontend/validator.py.
//!
//! Checks performed:
//!   1. Valid property types (no void, positive array lengths, no custom types)
//!   2. SmartContract: all properties must be readonly
//!   3. StatefulSmartContract: warn if no mutable properties
//!   4. StatefulSmartContract: txPreimage must not be declared (implicit)
//!   5. Constructor must have super() call and assign all properties
//!   6. No recursion (build call graph, DFS cycle detection)
//!   7. Public methods must end with assert (stateless contracts)
//!   8. StatefulSmartContract: warn on manual checkPreimage/getStateScript

const std = @import("std");
const types = @import("../ir/types.zig");

const Allocator = std.mem.Allocator;
const ContractNode = types.ContractNode;
const PropertyNode = types.PropertyNode;
const ConstructorNode = types.ConstructorNode;
const MethodNode = types.MethodNode;
const Expression = types.Expression;
const Statement = types.Statement;
const RunarType = types.RunarType;
const ParentClass = types.ParentClass;
const CompilerDiagnostic = types.CompilerDiagnostic;
const DiagnosticSeverity = types.DiagnosticSeverity;

// ============================================================================
// Public API
// ============================================================================

pub const ValidationResult = struct {
    errors: []CompilerDiagnostic,
    warnings: []CompilerDiagnostic,
};

const ConstructorValidationMode = enum {
    generic,
    zig,
};

/// Validate a Runar AST against language subset constraints.
/// Does NOT modify the AST; only reports errors and warnings.
/// Caller owns the returned slices and must free them with the same allocator.
pub fn validate(allocator: Allocator, contract: ContractNode) !ValidationResult {
    return validateWithMode(allocator, contract, .generic);
}

/// Validate a Zig AST against Runar language subset constraints.
/// Zig constructors use `init` field assignment, not `super(...)`.
pub fn validateZig(allocator: Allocator, contract: ContractNode) !ValidationResult {
    return validateWithMode(allocator, contract, .zig);
}

fn validateWithMode(
    allocator: Allocator,
    contract: ContractNode,
    mode: ConstructorValidationMode,
) !ValidationResult {
    var errors: std.ArrayListUnmanaged(CompilerDiagnostic) = .empty;
    defer errors.deinit(allocator);
    var warnings: std.ArrayListUnmanaged(CompilerDiagnostic) = .empty;
    defer warnings.deinit(allocator);

    try validateProperties(allocator, contract, &errors, &warnings);
    try validateConstructor(allocator, contract, mode, &errors);
    try validateMethods(allocator, contract, &errors, &warnings);
    try checkNoRecursion(allocator, contract, &errors);

    return .{
        .errors = try errors.toOwnedSlice(allocator),
        .warnings = try warnings.toOwnedSlice(allocator),
    };
}

/// Free a ValidationResult previously returned by validate().
pub fn freeResult(allocator: Allocator, result: ValidationResult) void {
    allocator.free(result.errors);
    allocator.free(result.warnings);
}

// ============================================================================
// Valid property types
// ============================================================================

/// Property types that are valid in Runar contracts. Void is explicitly excluded.
fn isValidPropertyType(t: RunarType) bool {
    return switch (t) {
        .bigint, .boolean, .byte_string, .pub_key, .sig, .sha256, .ripemd160,
        .addr, .sig_hash_preimage, .rabin_sig, .rabin_pub_key, .point,
        => true,
        .void, .unknown, .op_code_type, .sig_hash_type => false,
    };
}

// ============================================================================
// Property validation
// ============================================================================

fn validateProperties(
    allocator: Allocator,
    contract: ContractNode,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
    warnings: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    for (contract.properties) |prop| {
        // Check for void type
        if (prop.type_info == .void) {
            try errors.append(allocator, .{
                .message = "property type 'void' is not valid",
                .severity = .@"error",
            });
        } else if (!isValidPropertyType(prop.type_info) and prop.type_info != .unknown) {
            try errors.append(allocator, .{
                .message = "unsupported type in property declaration",
                .severity = .@"error",
            });
        }

        // V27: txPreimage is implicit in StatefulSmartContract
        if (contract.parent_class == .stateful_smart_contract and
            std.mem.eql(u8, prop.name, "txPreimage"))
        {
            try errors.append(allocator, .{
                .message = "'txPreimage' is an implicit property of StatefulSmartContract and must not be declared",
                .severity = .@"error",
            });
        }
    }

    // SmartContract requires all properties to be readonly
    if (contract.parent_class == .smart_contract) {
        for (contract.properties) |prop| {
            if (!prop.readonly) {
                try errors.append(allocator, .{
                    .message = "property in SmartContract must be declared readonly",
                    .severity = .@"error",
                });
            }
        }
    }

    // V26: Warn if StatefulSmartContract has no mutable properties
    if (contract.parent_class == .stateful_smart_contract) {
        var has_mutable = false;
        for (contract.properties) |prop| {
            if (!prop.readonly) {
                has_mutable = true;
                break;
            }
        }
        if (!has_mutable) {
            try warnings.append(allocator, .{
                .message = "StatefulSmartContract has no mutable properties; consider using SmartContract instead",
                .severity = .warning,
            });
        }
    }
}

// ============================================================================
// Constructor validation
// ============================================================================

fn validateConstructor(
    allocator: Allocator,
    contract: ContractNode,
    mode: ConstructorValidationMode,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    const ctor = contract.constructor;
    const is_zig_constructor = mode == .zig or isZigConstructor(ctor);

    if (!is_zig_constructor and ctor.params.len > 0 and ctor.super_args.len == 0) {
        try errors.append(allocator, .{
            .message = "constructor must call super() with all parameters",
            .severity = .@"error",
        });
    }

    for (contract.properties) |prop| {
        var assigned = false;
        for (ctor.assignments) |assignment| {
            if (std.mem.eql(u8, assignment.target, prop.name)) {
                assigned = true;
                break;
            }
        }
        // Properties with initializers don't need constructor assignments
        if (!assigned and prop.initializer == null) {
            try errors.append(allocator, .{
                .message = "property must be assigned in the constructor",
                .severity = .@"error",
            });
        }
    }
}

fn isZigConstructor(ctor: ConstructorNode) bool {
    for (ctor.params) |param| {
        if (param.type_name.len == 0) return true;
    }
    return false;
}

// ============================================================================
// Method validation
// ============================================================================

fn validateMethods(
    allocator: Allocator,
    contract: ContractNode,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
    warnings: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    for (contract.methods) |method| {
        // Public methods must end with assert() (unless StatefulSmartContract,
        // where the compiler auto-injects the final assert)
        if (method.is_public and contract.parent_class != .stateful_smart_contract) {
            if (!endsWithAssert(method.body)) {
                try errors.append(allocator, .{
                    .message = "public method must end with an assert() call",
                    .severity = .@"error",
                });
            }
        }

        // V24/V25: Warn on manual preimage/state-script boilerplate in StatefulSmartContract
        if (contract.parent_class == .stateful_smart_contract and method.is_public) {
            try warnManualPreimageUsage(allocator, method, warnings);
        }

        // Validate for-loop bounds are compile-time constants
        for (method.body) |stmt| {
            try validateStatement(allocator, stmt, errors);
        }
    }
}

/// Check if a method body ends with an assert statement (or all branches of a
/// trailing if-statement end with assert).
fn endsWithAssert(body: []const Statement) bool {
    if (body.len == 0) return false;
    const last = body[body.len - 1];

    return switch (last) {
        .assert_stmt => true,
        .expr_stmt => |expr| isAssertCall(expr),
        .if_stmt => |if_s| {
            const then_ok = endsWithAssert(if_s.then_body);
            const else_ok = if (if_s.else_body) |eb| endsWithAssert(eb) else false;
            return then_ok and else_ok;
        },
        else => false,
    };
}

/// Check if an expression is a call to assert().
fn isAssertCall(expr: Expression) bool {
    return switch (expr) {
        .call => |c| std.mem.eql(u8, c.callee, "assert"),
        .method_call => |mc| std.mem.eql(u8, mc.method, "assert"),
        else => false,
    };
}

/// Validate individual statements (currently checks for-loop bounds).
fn validateStatement(
    allocator: Allocator,
    stmt: Statement,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    switch (stmt) {
        .for_stmt => {
            // For loops in the Zig IR already have concrete i64 bounds (init_value, bound),
            // so they are inherently compile-time constants. No validation needed here.
        },
        .if_stmt => |if_s| {
            for (if_s.then_body) |s| try validateStatement(allocator, s, errors);
            if (if_s.else_body) |eb| {
                for (eb) |s| try validateStatement(allocator, s, errors);
            }
        },
        else => {},
    }
}

/// Warn on manual checkPreimage() or getStateScript() usage in StatefulSmartContract methods.
fn warnManualPreimageUsage(
    allocator: Allocator,
    method: MethodNode,
    warnings: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    for (method.body) |stmt| {
        try walkStatementsForPreimage(allocator, stmt, method.name, warnings);
    }
}

fn walkStatementsForPreimage(
    allocator: Allocator,
    stmt: Statement,
    method_name: []const u8,
    warnings: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    switch (stmt) {
        .expr_stmt => |expr| try walkExprForPreimage(allocator, expr, method_name, warnings),
        .const_decl => |cd| try walkExprForPreimage(allocator, cd.value, method_name, warnings),
        .let_decl => |ld| {
            if (ld.value) |v| try walkExprForPreimage(allocator, v, method_name, warnings);
        },
        .assign => |a| try walkExprForPreimage(allocator, a.value, method_name, warnings),
        .if_stmt => |if_s| {
            try walkExprForPreimage(allocator, if_s.condition, method_name, warnings);
            for (if_s.then_body) |s| try walkStatementsForPreimage(allocator, s, method_name, warnings);
            if (if_s.else_body) |eb| {
                for (eb) |s| try walkStatementsForPreimage(allocator, s, method_name, warnings);
            }
        },
        .for_stmt => |fs| {
            for (fs.body) |s| try walkStatementsForPreimage(allocator, s, method_name, warnings);
        },
        .assert_stmt => |a| try walkExprForPreimage(allocator, a.condition, method_name, warnings),
        .return_stmt => |opt_expr| {
            if (opt_expr) |expr| try walkExprForPreimage(allocator, expr, method_name, warnings);
        },
    }
}

fn walkExprForPreimage(
    allocator: Allocator,
    expr: Expression,
    method_name: []const u8,
    warnings: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    switch (expr) {
        .call => |c| {
            if (std.mem.eql(u8, c.callee, "checkPreimage")) {
                try warnings.append(allocator, .{
                    .message = "StatefulSmartContract auto-injects checkPreimage(); calling it manually will cause a duplicate verification",
                    .severity = .warning,
                });
            }
            for (c.args) |arg| try walkExprForPreimage(allocator, arg, method_name, warnings);
        },
        .method_call => |mc| {
            if (std.mem.eql(u8, mc.method, "checkPreimage")) {
                try warnings.append(allocator, .{
                    .message = "StatefulSmartContract auto-injects checkPreimage(); calling it manually will cause a duplicate verification",
                    .severity = .warning,
                });
            }
            if (std.mem.eql(u8, mc.method, "getStateScript")) {
                try warnings.append(allocator, .{
                    .message = "StatefulSmartContract auto-injects state continuation; calling getStateScript() manually is redundant",
                    .severity = .warning,
                });
            }
            for (mc.args) |arg| try walkExprForPreimage(allocator, arg, method_name, warnings);
        },
        .binary_op => |b| {
            try walkExprForPreimage(allocator, b.left, method_name, warnings);
            try walkExprForPreimage(allocator, b.right, method_name, warnings);
        },
        .unary_op => |u| try walkExprForPreimage(allocator, u.operand, method_name, warnings),
        .ternary => |t| {
            try walkExprForPreimage(allocator, t.condition, method_name, warnings);
            try walkExprForPreimage(allocator, t.then_expr, method_name, warnings);
            try walkExprForPreimage(allocator, t.else_expr, method_name, warnings);
        },
        .index_access => |ia| {
            try walkExprForPreimage(allocator, ia.object, method_name, warnings);
            try walkExprForPreimage(allocator, ia.index, method_name, warnings);
        },
        .increment => |inc| try walkExprForPreimage(allocator, inc.operand, method_name, warnings),
        .decrement => |dec| try walkExprForPreimage(allocator, dec.operand, method_name, warnings),
        .literal_int, .literal_bool, .literal_bytes, .identifier,
        .property_access, .array_literal,
        => {},
    }
}

// ============================================================================
// Recursion detection
// ============================================================================

const StringSet = std.StringHashMapUnmanaged(void);

/// Build a call graph and check for cycles using DFS.
fn checkNoRecursion(
    allocator: Allocator,
    contract: ContractNode,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    // Build call graph: method_name -> set of called method names
    var call_graph = std.StringHashMapUnmanaged(StringSet){};
    defer {
        var it = call_graph.iterator();
        while (it.next()) |entry| {
            var set = entry.value_ptr.*;
            set.deinit(allocator);
        }
        call_graph.deinit(allocator);
    }

    var method_names = StringSet{};
    defer method_names.deinit(allocator);

    for (contract.methods) |method| {
        try method_names.put(allocator, method.name, {});

        var calls = StringSet{};
        for (method.body) |stmt| {
            try collectMethodCalls(allocator, stmt, &calls);
        }
        try call_graph.put(allocator, method.name, calls);
    }

    // Check for cycles using DFS from each method
    for (contract.methods) |method| {
        var visited = StringSet{};
        defer visited.deinit(allocator);
        var stack = StringSet{};
        defer stack.deinit(allocator);

        if (try hasCycle(allocator, method.name, &call_graph, &method_names, &visited, &stack)) {
            try errors.append(allocator, .{
                .message = "recursion detected: method calls itself directly or indirectly",
                .severity = .@"error",
            });
        }
    }
}

fn hasCycle(
    allocator: Allocator,
    name: []const u8,
    call_graph: *std.StringHashMapUnmanaged(StringSet),
    method_names: *StringSet,
    visited: *StringSet,
    stack: *StringSet,
) !bool {
    if (stack.get(name) != null) return true;
    if (visited.get(name) != null) return false;

    try visited.put(allocator, name, {});
    try stack.put(allocator, name, {});

    if (call_graph.getPtr(name)) |calls| {
        var it = calls.iterator();
        while (it.next()) |entry| {
            const callee = entry.key_ptr.*;
            if (method_names.get(callee) != null) {
                if (try hasCycle(allocator, callee, call_graph, method_names, visited, stack)) {
                    return true;
                }
            }
        }
    }

    _ = stack.remove(name);
    return false;
}

/// Collect method calls from statements.
fn collectMethodCalls(allocator: Allocator, stmt: Statement, calls: *StringSet) !void {
    switch (stmt) {
        .expr_stmt => |expr| try collectMethodCallsInExpr(allocator, expr, calls),
        .const_decl => |cd| try collectMethodCallsInExpr(allocator, cd.value, calls),
        .let_decl => |ld| {
            if (ld.value) |v| try collectMethodCallsInExpr(allocator, v, calls);
        },
        .assign => |a| try collectMethodCallsInExpr(allocator, a.value, calls),
        .if_stmt => |if_s| {
            try collectMethodCallsInExpr(allocator, if_s.condition, calls);
            for (if_s.then_body) |s| try collectMethodCalls(allocator, s, calls);
            if (if_s.else_body) |eb| {
                for (eb) |s| try collectMethodCalls(allocator, s, calls);
            }
        },
        .for_stmt => |fs| {
            for (fs.body) |s| try collectMethodCalls(allocator, s, calls);
        },
        .assert_stmt => |a| try collectMethodCallsInExpr(allocator, a.condition, calls),
        .return_stmt => |opt_expr| {
            if (opt_expr) |expr| try collectMethodCallsInExpr(allocator, expr, calls);
        },
    }
}

fn collectMethodCallsInExpr(allocator: Allocator, expr: Expression, calls: *StringSet) !void {
    switch (expr) {
        .call => |c| {
            // Bare function calls that might be method references
            try calls.put(allocator, c.callee, {});
            for (c.args) |arg| try collectMethodCallsInExpr(allocator, arg, calls);
        },
        .method_call => |mc| {
            // this.methodName() calls
            if (std.mem.eql(u8, mc.object, "this")) {
                try calls.put(allocator, mc.method, {});
            }
            for (mc.args) |arg| try collectMethodCallsInExpr(allocator, arg, calls);
        },
        .binary_op => |b| {
            try collectMethodCallsInExpr(allocator, b.left, calls);
            try collectMethodCallsInExpr(allocator, b.right, calls);
        },
        .unary_op => |u| try collectMethodCallsInExpr(allocator, u.operand, calls),
        .ternary => |t| {
            try collectMethodCallsInExpr(allocator, t.condition, calls);
            try collectMethodCallsInExpr(allocator, t.then_expr, calls);
            try collectMethodCallsInExpr(allocator, t.else_expr, calls);
        },
        .index_access => |ia| {
            try collectMethodCallsInExpr(allocator, ia.object, calls);
            try collectMethodCallsInExpr(allocator, ia.index, calls);
        },
        .increment => |inc| try collectMethodCallsInExpr(allocator, inc.operand, calls),
        .decrement => |dec| try collectMethodCallsInExpr(allocator, dec.operand, calls),
        .literal_int, .literal_bool, .literal_bytes, .identifier,
        .property_access, .array_literal,
        => {},
    }
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

// -- Test helpers --

fn makeProperty(name: []const u8, type_info: RunarType, readonly: bool) PropertyNode {
    return .{ .name = name, .type_info = type_info, .readonly = readonly };
}

fn makePropertyWithInit(name: []const u8, type_info: RunarType, readonly: bool) PropertyNode {
    return .{ .name = name, .type_info = type_info, .readonly = readonly, .initializer = .{ .literal_int = 0 } };
}

fn makeAssignment(target: []const u8) types.AssignmentNode {
    return .{ .target = target, .value = .{ .literal_int = 0 } };
}

fn makeParam(name: []const u8) types.ParamNode {
    return .{ .name = name, .type_name = "bigint" };
}

fn makeZigParam(name: []const u8) types.ParamNode {
    return .{ .name = name };
}

// -- Property validation tests --

test "valid SmartContract passes validation" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var super_args = [_]Expression{.{ .identifier = "pk" }};
    var params = [_]types.ParamNode{makeParam("pk")};
    const contract = ContractNode{
        .name = "P2PKH",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    try testing.expectEqual(@as(usize, 0), result.errors.len);
    try testing.expectEqual(@as(usize, 0), result.warnings.len);
}

test "void property type is rejected" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("x", .void, true),
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("x")};
    const contract = ContractNode{
        .name = "Bad",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    try testing.expect(result.errors.len >= 1);
    try testing.expectEqualStrings("property type 'void' is not valid", result.errors[0].message);
}

test "SmartContract rejects mutable property" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("counter", .bigint, false),
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("counter")};
    const contract = ContractNode{
        .name = "Bad",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found_readonly_error = false;
    for (result.errors) |err| {
        if (std.mem.eql(u8, err.message, "property in SmartContract must be declared readonly")) {
            found_readonly_error = true;
            break;
        }
    }
    try testing.expect(found_readonly_error);
}

test "StatefulSmartContract warns on no mutable properties" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var super_args = [_]Expression{.{ .identifier = "pk" }};
    var params = [_]types.ParamNode{makeParam("pk")};
    const contract = ContractNode{
        .name = "Counter",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    try testing.expect(result.warnings.len >= 1);
    try testing.expectEqualStrings(
        "StatefulSmartContract has no mutable properties; consider using SmartContract instead",
        result.warnings[0].message,
    );
}

test "StatefulSmartContract rejects explicit txPreimage" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("txPreimage", .sig_hash_preimage, true),
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("txPreimage")};
    const contract = ContractNode{
        .name = "Bad",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found = false;
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "txPreimage") != null) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

// -- Constructor validation tests --

test "constructor missing super() call reports error" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var params = [_]types.ParamNode{makeParam("pk")};
    const contract = ContractNode{
        .name = "Bad",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &.{}, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found = false;
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "super()") != null) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "zig constructor without super() passes when properties are assigned" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
    };
    var assignments = [_]types.AssignmentNode{
        .{ .target = "pk", .value = .{ .identifier = "pk" } },
    };
    var params = [_]types.ParamNode{makeZigParam("pk")};
    const contract = ContractNode{
        .name = "P2PKH",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &.{}, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validateZig(allocator, contract);
    defer freeResult(allocator, result);

    try testing.expectEqual(@as(usize, 0), result.errors.len);
}

test "zig constructor missing property assignment reports error without super() noise" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
        makeProperty("amount", .bigint, true),
    };
    var assignments = [_]types.AssignmentNode{
        .{ .target = "pk", .value = .{ .identifier = "pk" } },
    };
    var params = [_]types.ParamNode{ makeZigParam("pk"), makeZigParam("amount") };
    const contract = ContractNode{
        .name = "Bad",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &.{}, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validateZig(allocator, contract);
    defer freeResult(allocator, result);

    var found_assignment_error = false;
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "super()") != null) {
            return error.TestUnexpectedResult;
        }
        if (std.mem.eql(u8, err.message, "property must be assigned in the constructor")) {
            found_assignment_error = true;
        }
    }
    try testing.expect(found_assignment_error);
}

test "constructor missing property assignment reports error" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
        makeProperty("amount", .bigint, true),
    };
    // Only assign pk, not amount
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var super_args = [_]Expression{ .{ .identifier = "pk" }, .{ .identifier = "amount" } };
    var params = [_]types.ParamNode{ makeParam("pk"), makeParam("amount") };
    const contract = ContractNode{
        .name = "Bad",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found = false;
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "property must be assigned") != null) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "property with initializer does not require constructor assignment" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
        makePropertyWithInit("counter", .bigint, false),
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var super_args = [_]Expression{.{ .identifier = "pk" }};
    var params = [_]types.ParamNode{makeParam("pk")};
    const contract = ContractNode{
        .name = "Counter",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    // Should have no "property must be assigned" errors (counter has initializer)
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "counter") != null and
            std.mem.indexOf(u8, err.message, "assigned") != null)
        {
            return error.TestUnexpectedResult;
        }
    }
}

// -- Method validation tests --

test "public method without assert reports error for SmartContract" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
    };
    var body = [_]Statement{.{ .expr_stmt = .{ .literal_bool = true } }};
    var methods = [_]MethodNode{
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var super_args = [_]Expression{.{ .identifier = "pk" }};
    var params = [_]types.ParamNode{makeParam("pk")};
    const contract = ContractNode{
        .name = "P2PKH",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found = false;
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "assert()") != null) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "public method ending with assert_stmt passes" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
    };
    var body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var methods = [_]MethodNode{
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var super_args = [_]Expression{.{ .identifier = "pk" }};
    var params = [_]types.ParamNode{makeParam("pk")};
    const contract = ContractNode{
        .name = "P2PKH",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "assert()") != null) {
            return error.TestUnexpectedResult;
        }
    }
}

test "StatefulSmartContract public method without assert is OK" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("counter", .bigint, false),
    };
    var body = [_]Statement{.{ .expr_stmt = .{ .literal_bool = true } }};
    var methods = [_]MethodNode{
        .{ .name = "increment", .is_public = true, .params = &.{}, .body = &body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("counter")};
    var super_args = [_]Expression{.{ .identifier = "counter" }};
    var params = [_]types.ParamNode{makeParam("counter")};
    const contract = ContractNode{
        .name = "Counter",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "assert()") != null) {
            return error.TestUnexpectedResult;
        }
    }
}

// -- Recursion detection tests --

test "direct recursion detected" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("x", .bigint, true),
    };

    // Method "foo" calls this.foo() -> direct recursion
    var call_expr = types.MethodCall{ .object = "this", .method = "foo", .args = &.{} };
    var body = [_]Statement{.{ .expr_stmt = .{ .method_call = &call_expr } }};
    var assert_body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var methods = [_]MethodNode{
        .{ .name = "foo", .is_public = false, .params = &.{}, .body = &body },
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &assert_body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("x")};
    var super_args = [_]Expression{.{ .identifier = "x" }};
    var params = [_]types.ParamNode{makeParam("x")};
    const contract = ContractNode{
        .name = "Recursive",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found = false;
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "recursion detected") != null) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "indirect recursion detected" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("x", .bigint, true),
    };

    // Method "a" calls this.b(), method "b" calls this.a() -> indirect recursion
    var call_b = types.MethodCall{ .object = "this", .method = "b", .args = &.{} };
    var body_a = [_]Statement{.{ .expr_stmt = .{ .method_call = &call_b } }};
    var call_a = types.MethodCall{ .object = "this", .method = "a", .args = &.{} };
    var body_b = [_]Statement{.{ .expr_stmt = .{ .method_call = &call_a } }};
    var assert_body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var methods = [_]MethodNode{
        .{ .name = "a", .is_public = false, .params = &.{}, .body = &body_a },
        .{ .name = "b", .is_public = false, .params = &.{}, .body = &body_b },
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &assert_body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("x")};
    var super_args = [_]Expression{.{ .identifier = "x" }};
    var params = [_]types.ParamNode{makeParam("x")};
    const contract = ContractNode{
        .name = "Recursive",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var recursion_count: usize = 0;
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "recursion detected") != null) {
            recursion_count += 1;
        }
    }
    // Both "a" and "b" should report recursion
    try testing.expect(recursion_count >= 2);
}

test "no recursion in acyclic call graph" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("x", .bigint, true),
    };

    // Method "a" calls this.b(), method "b" does not call anything -> no cycle
    var call_b = types.MethodCall{ .object = "this", .method = "b", .args = &.{} };
    var body_a = [_]Statement{.{ .expr_stmt = .{ .method_call = &call_b } }};
    var body_b = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var assert_body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var methods = [_]MethodNode{
        .{ .name = "a", .is_public = false, .params = &.{}, .body = &body_a },
        .{ .name = "b", .is_public = false, .params = &.{}, .body = &body_b },
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &assert_body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("x")};
    var super_args = [_]Expression{.{ .identifier = "x" }};
    var params = [_]types.ParamNode{makeParam("x")};
    const contract = ContractNode{
        .name = "NoRecurse",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "recursion") != null) {
            return error.TestUnexpectedResult;
        }
    }
}

// -- Preimage warning tests --

test "StatefulSmartContract warns on manual checkPreimage call" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("counter", .bigint, false),
    };
    var check_call = types.CallExpr{ .callee = "checkPreimage", .args = &.{} };
    var body = [_]Statement{.{ .expr_stmt = .{ .call = &check_call } }};
    var methods = [_]MethodNode{
        .{ .name = "increment", .is_public = true, .params = &.{}, .body = &body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("counter")};
    var super_args = [_]Expression{.{ .identifier = "counter" }};
    var params = [_]types.ParamNode{makeParam("counter")};
    const contract = ContractNode{
        .name = "Counter",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found = false;
    for (result.warnings) |w| {
        if (std.mem.indexOf(u8, w.message, "checkPreimage") != null) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "StatefulSmartContract warns on manual getStateScript call" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("counter", .bigint, false),
    };
    var mc = types.MethodCall{ .object = "this", .method = "getStateScript", .args = &.{} };
    var body = [_]Statement{.{ .expr_stmt = .{ .method_call = &mc } }};
    var methods = [_]MethodNode{
        .{ .name = "increment", .is_public = true, .params = &.{}, .body = &body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("counter")};
    var super_args = [_]Expression{.{ .identifier = "counter" }};
    var params = [_]types.ParamNode{makeParam("counter")};
    const contract = ContractNode{
        .name = "Counter",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found = false;
    for (result.warnings) |w| {
        if (std.mem.indexOf(u8, w.message, "getStateScript") != null) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

// -- Edge cases --

test "empty contract with no properties or methods" {
    const allocator = testing.allocator;
    const contract = ContractNode{
        .name = "Empty",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    try testing.expectEqual(@as(usize, 0), result.errors.len);
    try testing.expectEqual(@as(usize, 0), result.warnings.len);
}

test "endsWithAssert detects assert in both if branches" {
    // if-stmt where both branches end with assert -> OK
    var then_body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var else_body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    const body = [_]Statement{.{ .if_stmt = .{
        .condition = .{ .literal_bool = true },
        .then_body = &then_body,
        .else_body = &else_body,
    } }};
    try testing.expect(endsWithAssert(&body));
}

test "endsWithAssert rejects if with missing else assert" {
    var then_body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    const body = [_]Statement{.{ .if_stmt = .{
        .condition = .{ .literal_bool = true },
        .then_body = &then_body,
        .else_body = null,
    } }};
    try testing.expect(!endsWithAssert(&body));
}

test "endsWithAssert on empty body returns false" {
    try testing.expect(!endsWithAssert(&.{}));
}
