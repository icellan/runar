//! Pass 3: Type Check — verifies type consistency of a parsed Runar AST.
//!
//! Direct port of `compilers/python/runar_compiler/frontend/typecheck.py`.
//!
//! Checks performed:
//!   1. Property type consistency
//!   2. Constructor param types match property types
//!   3. Method param types are valid Runar types
//!   4. Expression type inference (recursive)
//!   5. Binary operator type rules (arithmetic on bigint, comparison, etc.)
//!   6. Builtin function call validation against 60+ signatures
//!   7. Affine type tracking (Sig and SigHashPreimage used at most once)

const std = @import("std");
const types = @import("../ir/types.zig");

const Allocator = std.mem.Allocator;
const ContractNode = types.ContractNode;
const MethodNode = types.MethodNode;
const ConstructorNode = types.ConstructorNode;
const Expression = types.Expression;
const Statement = types.Statement;
const BinOperator = types.BinOperator;
const UnaryOperator = types.UnaryOperator;
const RunarType = types.RunarType;

const log = std.log.scoped(.typecheck);

// ============================================================================
// Public API
// ============================================================================

pub const TypeCheckResult = struct {
    contract: ContractNode,
    errors: []const []const u8,

    pub fn deinit(self: *const TypeCheckResult, allocator: Allocator) void {
        for (self.errors) |msg| allocator.free(msg);
        if (self.errors.len > 0) allocator.free(self.errors);
    }
};

/// Type-check a Runar AST. Returns the same AST plus any errors.
pub fn typeCheck(allocator: Allocator, contract: ContractNode) !TypeCheckResult {
    var checker = try TypeChecker.init(allocator, contract);
    defer checker.deinit();

    checker.checkConstructor();
    for (contract.methods) |method| {
        checker.checkMethod(method);
    }

    const errors = try checker.errors.toOwnedSlice(allocator);
    return .{ .contract = contract, .errors = errors };
}

// ============================================================================
// Built-in function signatures
// ============================================================================

const FuncSig = struct {
    params: []const RunarType,
    return_type: RunarType,
};

/// Compile-time helper to build a FuncSig from type arrays.
fn sig(comptime params: []const RunarType, comptime ret: RunarType) FuncSig {
    return .{ .params = params, .return_type = ret };
}

const builtin_functions = std.StaticStringMap(FuncSig).initComptime(.{
    // Hash functions
    .{ "sha256", sig(&.{.byte_string}, .sha256) },
    .{ "ripemd160", sig(&.{.byte_string}, .ripemd160) },
    .{ "hash160", sig(&.{.byte_string}, .ripemd160) },
    .{ "hash256", sig(&.{.byte_string}, .sha256) },
    // Signature verification
    .{ "checkSig", sig(&.{ .sig, .pub_key }, .boolean) },
    .{ "checkMultiSig", sig(&.{}, .boolean) }, // variadic, special-cased
    .{ "checkPreimage", sig(&.{.sig_hash_preimage}, .boolean) },
    // Assertion
    .{ "assert", sig(&.{.boolean}, .void) }, // special-cased: 1-2 args
    // Byte operations
    .{ "len", sig(&.{.byte_string}, .bigint) },
    .{ "cat", sig(&.{ .byte_string, .byte_string }, .byte_string) },
    .{ "substr", sig(&.{ .byte_string, .bigint, .bigint }, .byte_string) },
    .{ "num2bin", sig(&.{ .bigint, .bigint }, .byte_string) },
    .{ "bin2num", sig(&.{.byte_string}, .bigint) },
    .{ "reverseBytes", sig(&.{.byte_string}, .byte_string) },
    .{ "left", sig(&.{ .byte_string, .bigint }, .byte_string) },
    .{ "right", sig(&.{ .byte_string, .bigint }, .byte_string) },
    .{ "int2str", sig(&.{ .bigint, .bigint }, .byte_string) },
    .{ "toByteString", sig(&.{.byte_string}, .byte_string) },
    // Rabin / WOTS / SLH-DSA
    .{ "verifyRabinSig", sig(&.{ .byte_string, .rabin_sig, .byte_string, .rabin_pub_key }, .boolean) },
    .{ "verifyWOTS", sig(&.{ .byte_string, .byte_string, .byte_string }, .boolean) },
    .{ "verifySLHDSA_SHA2_128s", sig(&.{ .byte_string, .byte_string, .byte_string }, .boolean) },
    .{ "verifySLHDSA_SHA2_128f", sig(&.{ .byte_string, .byte_string, .byte_string }, .boolean) },
    .{ "verifySLHDSA_SHA2_192s", sig(&.{ .byte_string, .byte_string, .byte_string }, .boolean) },
    .{ "verifySLHDSA_SHA2_192f", sig(&.{ .byte_string, .byte_string, .byte_string }, .boolean) },
    .{ "verifySLHDSA_SHA2_256s", sig(&.{ .byte_string, .byte_string, .byte_string }, .boolean) },
    .{ "verifySLHDSA_SHA2_256f", sig(&.{ .byte_string, .byte_string, .byte_string }, .boolean) },
    // EC operations
    .{ "ecAdd", sig(&.{ .point, .point }, .point) },
    .{ "ecMul", sig(&.{ .point, .bigint }, .point) },
    .{ "ecMulGen", sig(&.{.bigint}, .point) },
    .{ "ecNegate", sig(&.{.point}, .point) },
    .{ "ecOnCurve", sig(&.{.point}, .boolean) },
    .{ "ecModReduce", sig(&.{ .bigint, .bigint }, .bigint) },
    .{ "ecEncodeCompressed", sig(&.{.point}, .byte_string) },
    .{ "ecMakePoint", sig(&.{ .bigint, .bigint }, .point) },
    .{ "ecPointX", sig(&.{.point}, .bigint) },
    .{ "ecPointY", sig(&.{.point}, .bigint) },
    // SHA-256 / Blake3 compression
    .{ "sha256Compress", sig(&.{ .byte_string, .byte_string }, .byte_string) },
    .{ "sha256Finalize", sig(&.{ .byte_string, .byte_string, .bigint }, .byte_string) },
    .{ "blake3Compress", sig(&.{ .byte_string, .byte_string }, .byte_string) },
    .{ "blake3Hash", sig(&.{.byte_string}, .byte_string) },
    // Math
    .{ "abs", sig(&.{.bigint}, .bigint) },
    .{ "min", sig(&.{ .bigint, .bigint }, .bigint) },
    .{ "max", sig(&.{ .bigint, .bigint }, .bigint) },
    .{ "within", sig(&.{ .bigint, .bigint, .bigint }, .boolean) },
    .{ "safediv", sig(&.{ .bigint, .bigint }, .bigint) },
    .{ "safemod", sig(&.{ .bigint, .bigint }, .bigint) },
    .{ "clamp", sig(&.{ .bigint, .bigint, .bigint }, .bigint) },
    .{ "sign", sig(&.{.bigint}, .bigint) },
    .{ "pow", sig(&.{ .bigint, .bigint }, .bigint) },
    .{ "mulDiv", sig(&.{ .bigint, .bigint, .bigint }, .bigint) },
    .{ "percentOf", sig(&.{ .bigint, .bigint }, .bigint) },
    .{ "sqrt", sig(&.{.bigint}, .bigint) },
    .{ "gcd", sig(&.{ .bigint, .bigint }, .bigint) },
    .{ "divmod", sig(&.{ .bigint, .bigint }, .bigint) },
    .{ "log2", sig(&.{.bigint}, .bigint) },
    .{ "bool", sig(&.{.bigint}, .boolean) },
    // Exit / pack / unpack
    .{ "exit", sig(&.{.boolean}, .void) },
    .{ "pack", sig(&.{.bigint}, .byte_string) },
    .{ "unpack", sig(&.{.byte_string}, .bigint) },
    // SigHashPreimage extractors
    .{ "extractVersion", sig(&.{.sig_hash_preimage}, .bigint) },
    .{ "extractHashPrevouts", sig(&.{.sig_hash_preimage}, .sha256) },
    .{ "extractHashSequence", sig(&.{.sig_hash_preimage}, .sha256) },
    .{ "extractOutpoint", sig(&.{.sig_hash_preimage}, .byte_string) },
    .{ "extractInputIndex", sig(&.{.sig_hash_preimage}, .bigint) },
    .{ "extractScriptCode", sig(&.{.sig_hash_preimage}, .byte_string) },
    .{ "extractAmount", sig(&.{.sig_hash_preimage}, .bigint) },
    .{ "extractSequence", sig(&.{.sig_hash_preimage}, .bigint) },
    .{ "extractOutputHash", sig(&.{.sig_hash_preimage}, .sha256) },
    .{ "extractOutputs", sig(&.{.sig_hash_preimage}, .sha256) },
    .{ "extractLocktime", sig(&.{.sig_hash_preimage}, .bigint) },
    .{ "extractSigHashType", sig(&.{.sig_hash_preimage}, .bigint) },
    .{ "buildChangeOutput", sig(&.{ .byte_string, .bigint }, .byte_string) },
});

// ============================================================================
// Subtyping
// ============================================================================

/// ByteString-family types: all are subtypes of ByteString.
fn isByteFamily(t: RunarType) bool {
    return switch (t) {
        .byte_string, .pub_key, .sig, .sha256, .ripemd160, .addr, .sig_hash_preimage, .point => true,
        else => false,
    };
}

/// BigInt-family types: all are subtypes of bigint.
fn isBigintFamily(t: RunarType) bool {
    return switch (t) {
        .bigint, .rabin_sig, .rabin_pub_key => true,
        else => false,
    };
}

/// Returns true if `actual` is a subtype of `expected`.
fn isSubtype(actual: RunarType, expected: RunarType) bool {
    if (actual == expected) return true;
    if (actual == .unknown) return true;
    if (expected == .unknown) return true;
    if (expected == .byte_string and isByteFamily(actual)) return true;
    if (expected == .bigint and isBigintFamily(actual)) return true;
    return false;
}

// ============================================================================
// Type environment (scoped symbol table)
// ============================================================================

const TypeEnv = struct {
    scopes: std.ArrayListUnmanaged(Scope) = .empty,
    allocator: Allocator,

    const Scope = std.StringHashMapUnmanaged(RunarType);

    fn init(allocator: Allocator) !TypeEnv {
        var env = TypeEnv{ .allocator = allocator };
        try env.pushScope();
        return env;
    }

    fn deinit(self: *TypeEnv) void {
        for (self.scopes.items) |*scope| scope.deinit(self.allocator);
        self.scopes.deinit(self.allocator);
    }

    fn pushScope(self: *TypeEnv) !void {
        try self.scopes.append(self.allocator, .empty);
    }

    fn popScope(self: *TypeEnv) void {
        if (self.scopes.items.len > 0) {
            var scope = self.scopes.items[self.scopes.items.len - 1];
            self.scopes.items.len -= 1;
            scope.deinit(self.allocator);
        }
    }

    fn define(self: *TypeEnv, name: []const u8, typ: RunarType) void {
        const len = self.scopes.items.len;
        if (len == 0) return;
        self.scopes.items[len - 1].put(self.allocator, name, typ) catch {};
    }

    fn lookup(self: *const TypeEnv, name: []const u8) ?RunarType {
        var i = self.scopes.items.len;
        while (i > 0) {
            i -= 1;
            if (self.scopes.items[i].get(name)) |t| return t;
        }
        return null;
    }
};

// ============================================================================
// Affine types
// ============================================================================

fn isAffineType(t: RunarType) bool {
    return t == .sig or t == .sig_hash_preimage;
}

/// Functions that consume affine values, mapped to the parameter indices that get consumed.
fn consumedIndices(func_name: []const u8) ?[]const u8 {
    const map = std.StaticStringMap([]const u8).initComptime(.{
        .{ "checkSig", &[_]u8{0} },
        .{ "checkMultiSig", &[_]u8{0} },
        .{ "checkPreimage", &[_]u8{0} },
    });
    return map.get(func_name);
}

// ============================================================================
// Type checker
// ============================================================================

const TypeChecker = struct {
    allocator: Allocator,
    contract: ContractNode,
    errors: std.ArrayListUnmanaged([]const u8),
    prop_types: std.StringHashMapUnmanaged(RunarType),
    method_sigs: std.StringHashMapUnmanaged(FuncSig),
    consumed_values: std.StringHashMapUnmanaged(bool),
    stateful_ctx_params: std.StringHashMapUnmanaged(void),

    fn init(allocator: Allocator, contract: ContractNode) !TypeChecker {
        var self = TypeChecker{
            .allocator = allocator,
            .contract = contract,
            .errors = .empty,
            .prop_types = .empty,
            .method_sigs = .empty,
            .consumed_values = .empty,
            .stateful_ctx_params = .empty,
        };

        // Register property types
        for (contract.properties) |prop| {
            try self.prop_types.put(allocator, prop.name, prop.type_info);
        }

        // StatefulSmartContract gets implicit txPreimage property
        if (contract.parent_class == .stateful_smart_contract) {
            try self.prop_types.put(allocator, "txPreimage", .sig_hash_preimage);
        }

        // Register method signatures
        for (contract.methods) |method| {
            const params = try allocator.alloc(RunarType, method.params.len);
            for (method.params, 0..) |p, i| params[i] = p.type_info;
            const ret: RunarType = if (method.is_public) .void else inferMethodReturnType(method);
            try self.method_sigs.put(allocator, method.name, .{ .params = params, .return_type = ret });
        }

        return self;
    }

    fn deinit(self: *TypeChecker) void {
        // Free method sig param slices we allocated
        var it = self.method_sigs.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.params.len > 0) self.allocator.free(entry.value_ptr.params);
        }
        self.method_sigs.deinit(self.allocator);
        self.prop_types.deinit(self.allocator);
        self.consumed_values.deinit(self.allocator);
        self.stateful_ctx_params.deinit(self.allocator);
        // Note: self.errors ownership transfers to caller via toOwnedSlice
    }

    fn addError(self: *TypeChecker, comptime fmt: []const u8, args: anytype) void {
        const msg = std.fmt.allocPrint(self.allocator, fmt, args) catch return;
        self.errors.append(self.allocator, msg) catch {
            self.allocator.free(msg);
        };
    }

    // ------------------------------------------------------------------
    // Top-level checks
    // ------------------------------------------------------------------

    fn checkConstructor(self: *TypeChecker) void {
        var env = TypeEnv.init(self.allocator) catch return;
        defer env.deinit();

        self.consumed_values.clearRetainingCapacity();
        self.stateful_ctx_params.clearRetainingCapacity();

        const ctor = self.contract.constructor;
        for (ctor.params) |param| env.define(param.name, param.type_info);
        for (self.contract.properties) |prop| env.define(prop.name, prop.type_info);

        // Check constructor body (assignments)
        for (ctor.assignments) |assign| {
            _ = self.inferExprType(assign.value, &env);
        }
    }

    fn checkMethod(self: *TypeChecker, method: MethodNode) void {
        var env = TypeEnv.init(self.allocator) catch return;
        defer env.deinit();

        self.consumed_values.clearRetainingCapacity();
        self.stateful_ctx_params.clearRetainingCapacity();

        for (method.params) |param| {
            env.define(param.name, param.type_info);
            if (std.mem.eql(u8, param.type_name, "StatefulContext")) {
                self.stateful_ctx_params.put(self.allocator, param.name, {}) catch {};
            }
        }

        self.checkStatements(method.body, &env);
    }

    fn checkStatements(self: *TypeChecker, stmts: []const Statement, env: *TypeEnv) void {
        for (stmts) |stmt| self.checkStatement(stmt, env);
    }

    fn checkStatement(self: *TypeChecker, stmt: Statement, env: *TypeEnv) void {
        switch (stmt) {
            .const_decl => |decl| {
                const init_type = self.inferExprType(decl.value, env);
                if (decl.type_info) |declared| {
                    if (!isSubtype(init_type, declared)) {
                        self.addError("type '{s}' is not assignable to type '{s}'", .{
                            types.runarTypeToString(init_type),
                            types.runarTypeToString(declared),
                        });
                    }
                    env.define(decl.name, declared);
                } else {
                    env.define(decl.name, init_type);
                }
            },
            .let_decl => |decl| {
                if (decl.value) |val| {
                    const init_type = self.inferExprType(val, env);
                    if (decl.type_info) |declared| {
                        if (!isSubtype(init_type, declared)) {
                            self.addError("type '{s}' is not assignable to type '{s}'", .{
                                types.runarTypeToString(init_type),
                                types.runarTypeToString(declared),
                            });
                        }
                        env.define(decl.name, declared);
                    } else {
                        env.define(decl.name, init_type);
                    }
                } else {
                    env.define(decl.name, decl.type_info orelse .unknown);
                }
            },
            .assign => |assign| {
                const target_type = if (self.prop_types.get(assign.target)) |t| t else (env.lookup(assign.target) orelse .unknown);
                const value_type = self.inferExprType(assign.value, env);
                if (!isSubtype(value_type, target_type)) {
                    self.addError("type '{s}' is not assignable to type '{s}'", .{
                        types.runarTypeToString(value_type),
                        types.runarTypeToString(target_type),
                    });
                }
            },
            .if_stmt => |if_s| {
                const cond_type = self.inferExprType(if_s.condition, env);
                if (cond_type != .boolean) {
                    self.addError("if condition must be boolean, got '{s}'", .{types.runarTypeToString(cond_type)});
                }
                env.pushScope() catch return;
                self.checkStatements(if_s.then_body, env);
                env.popScope();
                if (if_s.else_body) |else_body| {
                    env.pushScope() catch return;
                    self.checkStatements(else_body, env);
                    env.popScope();
                }
            },
            .for_stmt => |for_s| {
                env.pushScope() catch return;
                env.define(for_s.var_name, .bigint);
                self.checkStatements(for_s.body, env);
                env.popScope();
            },
            .expr_stmt => |expr| {
                _ = self.inferExprType(expr, env);
            },
            .assert_stmt => |assert_s| {
                const cond_type = self.inferExprType(assert_s.condition, env);
                if (cond_type != .boolean and cond_type != .unknown) {
                    self.addError("assert() condition must be boolean, got '{s}'", .{types.runarTypeToString(cond_type)});
                }
            },
            .return_stmt => |maybe_expr| {
                if (maybe_expr) |expr| {
                    _ = self.inferExprType(expr, env);
                }
            },
        }
    }

    // ------------------------------------------------------------------
    // Type inference
    // ------------------------------------------------------------------

    fn inferExprType(self: *TypeChecker, expr: Expression, env: *TypeEnv) RunarType {
        return switch (expr) {
            .literal_int => .bigint,
            .literal_bool => .boolean,
            .literal_bytes => .byte_string,
            .identifier => |name| {
                if (std.mem.eql(u8, name, "this") or std.mem.eql(u8, name, "self")) return .unknown; // sentinel
                if (std.mem.eql(u8, name, "super")) return .unknown;
                if (env.lookup(name)) |t| return t;
                if (self.prop_types.get(name)) |t| return t;
                if (builtin_functions.get(name) != null) return .unknown; // builtin ref
                return .unknown;
            },
            .property_access => |pa| {
                if (std.mem.eql(u8, pa.object, "this") or std.mem.eql(u8, pa.object, "self")) {
                    if (self.prop_types.get(pa.property)) |t| return t;
                    if (self.method_sigs.get(pa.property) != null) return .unknown;
                    if (std.mem.eql(u8, pa.property, "getStateScript")) return .unknown;
                    return .unknown;
                }
                if (self.stateful_ctx_params.get(pa.object) != null and std.mem.eql(u8, pa.property, "txPreimage")) {
                    return .sig_hash_preimage;
                }
                if (std.mem.eql(u8, pa.object, "SigHash")) return .bigint;
                return .unknown;
            },
            .binary_op => |bin| self.checkBinaryExpr(bin, env),
            .unary_op => |un| self.checkUnaryExpr(un, env),
            .call => |call| self.checkCallExpr(call, env),
            .method_call => |mc| self.checkMethodCallExpr(mc, env),
            .ternary => |tern| {
                const cond_type = self.inferExprType(tern.condition, env);
                if (cond_type != .boolean) {
                    self.addError("ternary condition must be boolean, got '{s}'", .{types.runarTypeToString(cond_type)});
                }
                const cons_type = self.inferExprType(tern.then_expr, env);
                const alt_type = self.inferExprType(tern.else_expr, env);
                if (cons_type != alt_type) {
                    if (isSubtype(alt_type, cons_type)) return cons_type;
                    if (isSubtype(cons_type, alt_type)) return alt_type;
                }
                return cons_type;
            },
            .index_access => |ia| {
                const obj_type = self.inferExprType(ia.object, env);
                const idx_type = self.inferExprType(ia.index, env);
                if (!isBigintFamily(idx_type)) {
                    self.addError("array index must be bigint, got '{s}'", .{types.runarTypeToString(idx_type)});
                }
                _ = obj_type;
                return .unknown;
            },
            .increment => |inc| {
                const operand_type = self.inferExprType(inc.operand, env);
                if (!isBigintFamily(operand_type)) {
                    self.addError("++ operator requires bigint, got '{s}'", .{types.runarTypeToString(operand_type)});
                }
                return .bigint;
            },
            .decrement => |dec| {
                const operand_type = self.inferExprType(dec.operand, env);
                if (!isBigintFamily(operand_type)) {
                    self.addError("-- operator requires bigint, got '{s}'", .{types.runarTypeToString(operand_type)});
                }
                return .bigint;
            },
            .array_literal => |elems| {
                for (elems) |elem| _ = self.inferExprType(elem, env);
                return .unknown;
            },
        };
    }

    // ------------------------------------------------------------------
    // Binary expression type checking
    // ------------------------------------------------------------------

    fn checkBinaryExpr(self: *TypeChecker, bin: *const types.BinaryOp, env: *TypeEnv) RunarType {
        const left_type = self.inferExprType(bin.left, env);
        const right_type = self.inferExprType(bin.right, env);

        switch (bin.op) {
            // ByteString concatenation: ByteString + ByteString -> ByteString
            .add => {
                if (isByteFamily(left_type) and isByteFamily(right_type)) return .byte_string;
                if (!isBigintFamily(left_type))
                    self.addError("left operand of '+' must be bigint, got '{s}'", .{types.runarTypeToString(left_type)});
                if (!isBigintFamily(right_type))
                    self.addError("right operand of '+' must be bigint, got '{s}'", .{types.runarTypeToString(right_type)});
                return .bigint;
            },
            // Arithmetic
            .sub, .mul, .div, .mod => {
                const op_str = bin.op.toTsString();
                if (!isBigintFamily(left_type))
                    self.addError("left operand of '{s}' must be bigint, got '{s}'", .{ op_str, types.runarTypeToString(left_type) });
                if (!isBigintFamily(right_type))
                    self.addError("right operand of '{s}' must be bigint, got '{s}'", .{ op_str, types.runarTypeToString(right_type) });
                return .bigint;
            },
            // Comparison
            .lt, .lte, .gt, .gte => {
                const op_str = bin.op.toTsString();
                if (!isBigintFamily(left_type))
                    self.addError("left operand of '{s}' must be bigint, got '{s}'", .{ op_str, types.runarTypeToString(left_type) });
                if (!isBigintFamily(right_type))
                    self.addError("right operand of '{s}' must be bigint, got '{s}'", .{ op_str, types.runarTypeToString(right_type) });
                return .boolean;
            },
            // Equality
            .eq, .neq => {
                const compatible = isSubtype(left_type, right_type) or
                    isSubtype(right_type, left_type) or
                    (isByteFamily(left_type) and isByteFamily(right_type)) or
                    (isBigintFamily(left_type) and isBigintFamily(right_type));
                if (!compatible and left_type != .unknown and right_type != .unknown) {
                    self.addError("cannot compare '{s}' and '{s}' with '{s}'", .{
                        types.runarTypeToString(left_type),
                        types.runarTypeToString(right_type),
                        bin.op.toTsString(),
                    });
                }
                return .boolean;
            },
            // Logical
            .and_op, .or_op => {
                const op_str = bin.op.toTsString();
                if (left_type != .boolean and left_type != .unknown)
                    self.addError("left operand of '{s}' must be boolean, got '{s}'", .{ op_str, types.runarTypeToString(left_type) });
                if (right_type != .boolean and right_type != .unknown)
                    self.addError("right operand of '{s}' must be boolean, got '{s}'", .{ op_str, types.runarTypeToString(right_type) });
                return .boolean;
            },
            // Shifts
            .lshift, .rshift => {
                const op_str = bin.op.toTsString();
                if (!isBigintFamily(left_type))
                    self.addError("left operand of '{s}' must be bigint, got '{s}'", .{ op_str, types.runarTypeToString(left_type) });
                if (!isBigintFamily(right_type))
                    self.addError("right operand of '{s}' must be bigint, got '{s}'", .{ op_str, types.runarTypeToString(right_type) });
                return .bigint;
            },
            // Bitwise: bigint x bigint -> bigint, or ByteString x ByteString -> ByteString
            .bitand, .bitor, .bitxor => {
                if (isByteFamily(left_type) and isByteFamily(right_type)) return .byte_string;
                const op_str = bin.op.toTsString();
                if (!isBigintFamily(left_type))
                    self.addError("left operand of '{s}' must be bigint or ByteString, got '{s}'", .{ op_str, types.runarTypeToString(left_type) });
                if (!isBigintFamily(right_type))
                    self.addError("right operand of '{s}' must be bigint or ByteString, got '{s}'", .{ op_str, types.runarTypeToString(right_type) });
                return .bigint;
            },
        }
    }

    // ------------------------------------------------------------------
    // Unary expression type checking
    // ------------------------------------------------------------------

    fn checkUnaryExpr(self: *TypeChecker, un: *const types.UnaryOp, env: *TypeEnv) RunarType {
        const operand_type = self.inferExprType(un.operand, env);

        return switch (un.op) {
            .not => {
                if (operand_type != .boolean and operand_type != .unknown) {
                    self.addError("operand of '!' must be boolean, got '{s}'", .{types.runarTypeToString(operand_type)});
                }
                return .boolean;
            },
            .negate => {
                if (!isBigintFamily(operand_type)) {
                    self.addError("operand of unary '-' must be bigint, got '{s}'", .{types.runarTypeToString(operand_type)});
                }
                return .bigint;
            },
            .bitnot => {
                if (isByteFamily(operand_type)) return .byte_string;
                if (!isBigintFamily(operand_type)) {
                    self.addError("operand of '~' must be bigint or ByteString, got '{s}'", .{types.runarTypeToString(operand_type)});
                }
                return .bigint;
            },
        };
    }

    // ------------------------------------------------------------------
    // Call expression type checking (direct calls)
    // ------------------------------------------------------------------

    fn checkCallExpr(self: *TypeChecker, call: *const types.CallExpr, env: *TypeEnv) RunarType {
        const name = call.callee;

        // super() call
        if (std.mem.eql(u8, name, "super")) {
            for (call.args) |arg| _ = self.inferExprType(arg, env);
            return .void;
        }

        // Builtin function
        if (builtin_functions.get(name)) |func_sig| {
            return self.checkCallArgs(name, func_sig, call.args, env);
        }

        // Known contract method
        if (self.method_sigs.get(name)) |method_sig| {
            return self.checkCallArgs(name, method_sig, call.args, env);
        }

        // Local variable (callable)
        if (env.lookup(name) != null) {
            for (call.args) |arg| _ = self.inferExprType(arg, env);
            return .unknown;
        }

        self.addError("unknown function '{s}' -- only Runar built-in functions and contract methods are allowed", .{name});
        for (call.args) |arg| _ = self.inferExprType(arg, env);
        return .unknown;
    }

    // ------------------------------------------------------------------
    // Method call expression type checking (this.method() etc.)
    // ------------------------------------------------------------------

    fn checkMethodCallExpr(self: *TypeChecker, mc: *const types.MethodCall, env: *TypeEnv) RunarType {
        const is_this = std.mem.eql(u8, mc.object, "this") or std.mem.eql(u8, mc.object, "self");
        const is_stateful_ctx = self.stateful_ctx_params.get(mc.object) != null;

        if (is_this or is_stateful_ctx) {
            if (std.mem.eql(u8, mc.method, "getStateScript")) return .byte_string;
            if (std.mem.eql(u8, mc.method, "addOutput")) {
                if (self.contract.parent_class != .stateful_smart_contract) {
                    self.addError("addOutput() is only available in StatefulSmartContract, not SmartContract", .{});
                }
                for (mc.args) |arg| _ = self.inferExprType(arg, env);
                return .void;
            }
            if (std.mem.eql(u8, mc.method, "addRawOutput")) {
                if (self.contract.parent_class != .stateful_smart_contract) {
                    self.addError("addRawOutput() is only available in StatefulSmartContract, not SmartContract", .{});
                }
                for (mc.args) |arg| _ = self.inferExprType(arg, env);
                return .void;
            }
            if (self.method_sigs.get(mc.method)) |method_sig| {
                return self.checkCallArgs(mc.method, method_sig, mc.args, env);
            }
            self.addError("unknown method '{s}.{s}' -- only Runar built-in methods and contract methods are allowed", .{ mc.object, mc.method });
            for (mc.args) |arg| _ = self.inferExprType(arg, env);
            return .unknown;
        }

        // Not this.method — reject
        self.addError("unknown function '{s}.{s}' -- only Runar built-in functions and contract methods are allowed", .{ mc.object, mc.method });
        for (mc.args) |arg| _ = self.inferExprType(arg, env);
        return .unknown;
    }

    // ------------------------------------------------------------------
    // Argument checking
    // ------------------------------------------------------------------

    fn checkCallArgs(self: *TypeChecker, func_name: []const u8, func_sig: FuncSig, args: []const Expression, env: *TypeEnv) RunarType {
        // assert: 1-2 args special case
        if (std.mem.eql(u8, func_name, "assert")) {
            if (args.len < 1 or args.len > 2) {
                self.addError("assert() expects 1 or 2 arguments, got {d}", .{args.len});
            }
            if (args.len >= 1) {
                const cond_type = self.inferExprType(args[0], env);
                if (cond_type != .boolean and cond_type != .unknown) {
                    self.addError("assert() condition must be boolean, got '{s}'", .{types.runarTypeToString(cond_type)});
                }
            }
            if (args.len >= 2) _ = self.inferExprType(args[1], env);
            return func_sig.return_type;
        }

        // checkMultiSig: variadic special case
        if (std.mem.eql(u8, func_name, "checkMultiSig")) {
            for (args) |arg| _ = self.inferExprType(arg, env);
            self.checkAffineConsumption(func_name, args, env);
            return func_sig.return_type;
        }

        // Standard arity check
        if (args.len != func_sig.params.len) {
            self.addError("{s}() expects {d} argument(s), got {d}", .{ func_name, func_sig.params.len, args.len });
        }

        const count = @min(args.len, func_sig.params.len);
        for (0..count) |i| {
            const arg_type = self.inferExprType(args[i], env);
            const expected = func_sig.params[i];
            if (!isSubtype(arg_type, expected) and arg_type != .unknown) {
                self.addError("argument {d} of {s}(): expected '{s}', got '{s}'", .{
                    i + 1,
                    func_name,
                    types.runarTypeToString(expected),
                    types.runarTypeToString(arg_type),
                });
            }
        }

        // Type-check extra args beyond expected arity
        for (count..args.len) |i| _ = self.inferExprType(args[i], env);

        self.checkAffineConsumption(func_name, args, env);
        return func_sig.return_type;
    }

    // ------------------------------------------------------------------
    // Affine consumption
    // ------------------------------------------------------------------

    fn checkAffineConsumption(self: *TypeChecker, func_name: []const u8, args: []const Expression, env: *TypeEnv) void {
        const indices = consumedIndices(func_name) orelse return;

        for (indices) |param_index| {
            if (param_index >= args.len) continue;

            const arg = args[param_index];
            const arg_name = switch (arg) {
                .identifier => |name| name,
                else => continue,
            };

            const arg_type = env.lookup(arg_name) orelse continue;
            if (!isAffineType(arg_type)) continue;

            if (self.consumed_values.get(arg_name)) |consumed| {
                if (consumed) {
                    self.addError("affine value '{s}' has already been consumed", .{arg_name});
                    continue;
                }
            }
            self.consumed_values.put(self.allocator, arg_name, true) catch {};
        }
    }
};

// ============================================================================
// Private method return type inference (pre-pass, no type env needed)
// ============================================================================

fn inferMethodReturnType(method: MethodNode) RunarType {
    const return_types = collectReturnTypes(method.body);
    if (return_types.len == 0) return .void;

    const first = return_types[0];
    var all_same = true;
    for (return_types[1..]) |t| {
        if (t != first) {
            all_same = false;
            break;
        }
    }
    if (all_same) return first;

    // Check if all in bigint family
    var all_bigint = true;
    for (return_types) |t| {
        if (!isBigintFamily(t)) {
            all_bigint = false;
            break;
        }
    }
    if (all_bigint) return .bigint;

    // Check if all in ByteString family
    var all_bytes = true;
    for (return_types) |t| {
        if (!isByteFamily(t)) {
            all_bytes = false;
            break;
        }
    }
    if (all_bytes) return .byte_string;

    // Check if all boolean
    var all_bool = true;
    for (return_types) |t| {
        if (t != .boolean) {
            all_bool = false;
            break;
        }
    }
    if (all_bool) return .boolean;

    return first;
}

/// Stack-allocated bounded buffer for return types (avoids allocation).
const MAX_RETURN_TYPES = 64;
const ReturnTypeBuf = struct {
    items: [MAX_RETURN_TYPES]RunarType = undefined,
    len: usize = 0,

    fn append(self: *ReturnTypeBuf, t: RunarType) void {
        if (self.len < MAX_RETURN_TYPES) {
            self.items[self.len] = t;
            self.len += 1;
        }
    }

    fn slice(self: *const ReturnTypeBuf) []const RunarType {
        return self.items[0..self.len];
    }
};

fn collectReturnTypes(stmts: []const Statement) []const RunarType {
    const S = struct {
        var buf: ReturnTypeBuf = .{};
    };
    S.buf = .{};
    collectReturnTypesInto(stmts, &S.buf);
    return S.buf.slice();
}

fn collectReturnTypesInto(stmts: []const Statement, buf: *ReturnTypeBuf) void {
    for (stmts) |stmt| {
        switch (stmt) {
            .return_stmt => |maybe_expr| {
                if (maybe_expr) |expr| buf.append(inferExprTypeStatic(expr));
            },
            .if_stmt => |if_s| {
                collectReturnTypesInto(if_s.then_body, buf);
                if (if_s.else_body) |else_body| collectReturnTypesInto(else_body, buf);
            },
            .for_stmt => |for_s| collectReturnTypesInto(for_s.body, buf),
            else => {},
        }
    }
}

/// Lightweight expression type inference without a type environment.
/// Used for inferring return types of private methods before the full type-check pass.
fn inferExprTypeStatic(expr: Expression) RunarType {
    return switch (expr) {
        .literal_int => .bigint,
        .literal_bool => .boolean,
        .literal_bytes => .byte_string,
        .identifier => .unknown,
        .binary_op => |bin| {
            return switch (bin.op) {
                .add, .sub, .mul, .div, .mod, .bitand, .bitor, .bitxor, .lshift, .rshift => .bigint,
                .eq, .neq, .lt, .lte, .gt, .gte, .and_op, .or_op => .boolean,
            };
        },
        .unary_op => |un| {
            return switch (un.op) {
                .not => .boolean,
                .negate, .bitnot => .bigint,
            };
        },
        .call => |call| {
            if (builtin_functions.get(call.callee)) |func_sig| return func_sig.return_type;
            return .unknown;
        },
        .method_call => |mc| {
            if (builtin_functions.get(mc.method)) |func_sig| return func_sig.return_type;
            return .unknown;
        },
        .ternary => |tern| {
            const cons_type = inferExprTypeStatic(tern.then_expr);
            if (cons_type != .unknown) return cons_type;
            return inferExprTypeStatic(tern.else_expr);
        },
        .increment, .decrement => .bigint,
        .property_access => .unknown,
        .index_access => .unknown,
        .array_literal => .unknown,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "isSubtype: same type" {
    try std.testing.expect(isSubtype(.bigint, .bigint));
    try std.testing.expect(isSubtype(.boolean, .boolean));
    try std.testing.expect(isSubtype(.byte_string, .byte_string));
}

test "isSubtype: unknown is compatible with anything" {
    try std.testing.expect(isSubtype(.unknown, .bigint));
    try std.testing.expect(isSubtype(.bigint, .unknown));
    try std.testing.expect(isSubtype(.unknown, .unknown));
}

test "isSubtype: ByteString family" {
    try std.testing.expect(isSubtype(.pub_key, .byte_string));
    try std.testing.expect(isSubtype(.sig, .byte_string));
    try std.testing.expect(isSubtype(.sha256, .byte_string));
    try std.testing.expect(isSubtype(.ripemd160, .byte_string));
    try std.testing.expect(isSubtype(.addr, .byte_string));
    try std.testing.expect(isSubtype(.sig_hash_preimage, .byte_string));
    try std.testing.expect(isSubtype(.point, .byte_string));
    try std.testing.expect(!isSubtype(.bigint, .byte_string));
    try std.testing.expect(!isSubtype(.boolean, .byte_string));
}

test "isSubtype: bigint family" {
    try std.testing.expect(isSubtype(.rabin_sig, .bigint));
    try std.testing.expect(isSubtype(.rabin_pub_key, .bigint));
    try std.testing.expect(!isSubtype(.byte_string, .bigint));
    try std.testing.expect(!isSubtype(.boolean, .bigint));
}

test "isSubtype: not assignable across families" {
    try std.testing.expect(!isSubtype(.bigint, .boolean));
    try std.testing.expect(!isSubtype(.boolean, .bigint));
    try std.testing.expect(!isSubtype(.byte_string, .boolean));
    try std.testing.expect(!isSubtype(.pub_key, .bigint));
}

test "TypeEnv: define and lookup" {
    const allocator = std.testing.allocator;
    var env = try TypeEnv.init(allocator);
    defer env.deinit();

    env.define("x", .bigint);
    env.define("y", .boolean);
    try std.testing.expectEqual(.bigint, env.lookup("x").?);
    try std.testing.expectEqual(.boolean, env.lookup("y").?);
    try std.testing.expectEqual(null, env.lookup("z"));
}

test "TypeEnv: scoped shadowing" {
    const allocator = std.testing.allocator;
    var env = try TypeEnv.init(allocator);
    defer env.deinit();

    env.define("x", .bigint);
    try env.pushScope();
    env.define("x", .boolean);
    try std.testing.expectEqual(.boolean, env.lookup("x").?);
    env.popScope();
    try std.testing.expectEqual(.bigint, env.lookup("x").?);
}

test "builtin_functions: sha256 signature" {
    const func_sig = builtin_functions.get("sha256").?;
    try std.testing.expectEqual(1, func_sig.params.len);
    try std.testing.expectEqual(.byte_string, func_sig.params[0]);
    try std.testing.expectEqual(.sha256, func_sig.return_type);
}

test "builtin_functions: checkSig signature" {
    const func_sig = builtin_functions.get("checkSig").?;
    try std.testing.expectEqual(2, func_sig.params.len);
    try std.testing.expectEqual(.sig, func_sig.params[0]);
    try std.testing.expectEqual(.pub_key, func_sig.params[1]);
    try std.testing.expectEqual(.boolean, func_sig.return_type);
}

test "builtin_functions: all 60+ entries present" {
    const expected = [_][]const u8{
        "sha256",          "ripemd160",         "hash160",
        "hash256",         "checkSig",          "checkMultiSig",
        "checkPreimage",   "assert",            "len",
        "cat",             "substr",            "num2bin",
        "bin2num",         "reverseBytes",      "left",
        "right",           "int2str",           "toByteString",
        "verifyRabinSig",  "verifyWOTS",        "verifySLHDSA_SHA2_128s",
        "verifySLHDSA_SHA2_128f",               "verifySLHDSA_SHA2_192s",
        "verifySLHDSA_SHA2_192f",               "verifySLHDSA_SHA2_256s",
        "verifySLHDSA_SHA2_256f",               "ecAdd",
        "ecMul",           "ecMulGen",          "ecNegate",
        "ecOnCurve",       "ecModReduce",       "ecEncodeCompressed",
        "ecMakePoint",     "ecPointX",          "ecPointY",
        "sha256Compress",  "sha256Finalize",    "blake3Compress",
        "blake3Hash",      "abs",               "min",
        "max",             "within",            "safediv",
        "safemod",         "clamp",             "sign",
        "pow",             "mulDiv",            "percentOf",
        "sqrt",            "gcd",               "divmod",
        "log2",            "bool",              "exit",
        "pack",            "unpack",            "extractVersion",
        "extractHashPrevouts",                  "extractHashSequence",
        "extractOutpoint", "extractInputIndex", "extractScriptCode",
        "extractAmount",   "extractSequence",   "extractOutputHash",
        "extractOutputs",  "extractLocktime",   "extractSigHashType",
    };
    for (expected) |name| {
        try std.testing.expect(builtin_functions.get(name) != null);
    }
}

test "typeCheck: empty contract passes" {
    const allocator = std.testing.allocator;
    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(0, result.errors.len);
}

test "typeCheck: valid bigint arithmetic" {
    const allocator = std.testing.allocator;

    // Build: const x: bigint = 1 + 2;
    const bin = try allocator.create(types.BinaryOp);
    defer allocator.destroy(bin);
    bin.* = .{ .op = .add, .left = .{ .literal_int = 1 }, .right = .{ .literal_int = 2 } };

    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .const_decl = .{ .name = "x", .type_info = .bigint, .value = .{ .binary_op = bin } } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = &.{}, .body = stmts };

    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(0, result.errors.len);
}

test "typeCheck: type mismatch in variable declaration" {
    const allocator = std.testing.allocator;

    // Build: const x: boolean = 42;  (bigint assigned to boolean)
    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .const_decl = .{ .name = "x", .type_info = .boolean, .value = .{ .literal_int = 42 } } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = &.{}, .body = stmts };

    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(1, result.errors.len);
    try std.testing.expect(std.mem.indexOf(u8, result.errors[0], "not assignable") != null);
}

test "typeCheck: if condition must be boolean" {
    const allocator = std.testing.allocator;

    // Build: if (42) { }
    const then_body = try allocator.alloc(Statement, 0);
    defer allocator.free(then_body);

    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .if_stmt = .{ .condition = .{ .literal_int = 42 }, .then_body = then_body } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = &.{}, .body = stmts };

    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(1, result.errors.len);
    try std.testing.expect(std.mem.indexOf(u8, result.errors[0], "if condition must be boolean") != null);
}

test "typeCheck: unknown function error" {
    const allocator = std.testing.allocator;

    // Build: Math.floor(x)  -> as a direct call to "Math.floor"
    const call = try allocator.create(types.CallExpr);
    defer allocator.destroy(call);
    const args = try allocator.alloc(Expression, 1);
    defer allocator.free(args);
    args[0] = .{ .literal_int = 1 };
    call.* = .{ .callee = "floor", .args = args };

    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .expr_stmt = .{ .call = call } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = &.{}, .body = stmts };

    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(1, result.errors.len);
    try std.testing.expect(std.mem.indexOf(u8, result.errors[0], "unknown function") != null);
}

test "typeCheck: valid builtin call sha256" {
    const allocator = std.testing.allocator;

    // Build: const h = sha256(b"cafe");
    const call = try allocator.create(types.CallExpr);
    defer allocator.destroy(call);
    const args = try allocator.alloc(Expression, 1);
    defer allocator.free(args);
    args[0] = .{ .literal_bytes = "cafe" };
    call.* = .{ .callee = "sha256", .args = args };

    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .const_decl = .{ .name = "h", .type_info = .sha256, .value = .{ .call = call } } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = &.{}, .body = stmts };

    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(0, result.errors.len);
}

test "typeCheck: wrong arg type for builtin" {
    const allocator = std.testing.allocator;

    // Build: sha256(42) — int instead of ByteString
    const call = try allocator.create(types.CallExpr);
    defer allocator.destroy(call);
    const args = try allocator.alloc(Expression, 1);
    defer allocator.free(args);
    args[0] = .{ .literal_int = 42 };
    call.* = .{ .callee = "sha256", .args = args };

    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .expr_stmt = .{ .call = call } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = &.{}, .body = stmts };

    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(1, result.errors.len);
    try std.testing.expect(std.mem.indexOf(u8, result.errors[0], "expected 'ByteString'") != null);
}

test "typeCheck: wrong arity for builtin" {
    const allocator = std.testing.allocator;

    // Build: sha256(b"a", b"b") — 2 args instead of 1
    const call = try allocator.create(types.CallExpr);
    defer allocator.destroy(call);
    const args = try allocator.alloc(Expression, 2);
    defer allocator.free(args);
    args[0] = .{ .literal_bytes = "a" };
    args[1] = .{ .literal_bytes = "b" };
    call.* = .{ .callee = "sha256", .args = args };

    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .expr_stmt = .{ .call = call } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = &.{}, .body = stmts };

    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(1, result.errors.len);
    try std.testing.expect(std.mem.indexOf(u8, result.errors[0], "expects 1 argument") != null);
}

test "typeCheck: affine value consumed twice" {
    const allocator = std.testing.allocator;

    // Build a method that calls checkSig(mySig, pk) twice with the same Sig
    const params = try allocator.alloc(types.ParamNode, 2);
    defer allocator.free(params);
    params[0] = .{ .name = "mySig", .type_info = .sig, .type_name = "Sig" };
    params[1] = .{ .name = "pk", .type_info = .pub_key, .type_name = "PubKey" };

    const call1 = try allocator.create(types.CallExpr);
    defer allocator.destroy(call1);
    const args1 = try allocator.alloc(Expression, 2);
    defer allocator.free(args1);
    args1[0] = .{ .identifier = "mySig" };
    args1[1] = .{ .identifier = "pk" };
    call1.* = .{ .callee = "checkSig", .args = args1 };

    const call2 = try allocator.create(types.CallExpr);
    defer allocator.destroy(call2);
    const args2 = try allocator.alloc(Expression, 2);
    defer allocator.free(args2);
    args2[0] = .{ .identifier = "mySig" };
    args2[1] = .{ .identifier = "pk" };
    call2.* = .{ .callee = "checkSig", .args = args2 };

    const stmts = try allocator.alloc(Statement, 2);
    defer allocator.free(stmts);
    stmts[0] = .{ .expr_stmt = .{ .call = call1 } };
    stmts[1] = .{ .expr_stmt = .{ .call = call2 } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = params, .body = stmts };

    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(1, result.errors.len);
    try std.testing.expect(std.mem.indexOf(u8, result.errors[0], "affine value 'mySig' has already been consumed") != null);
}

test "typeCheck: affine value single use is fine" {
    const allocator = std.testing.allocator;

    const params = try allocator.alloc(types.ParamNode, 2);
    defer allocator.free(params);
    params[0] = .{ .name = "mySig", .type_info = .sig, .type_name = "Sig" };
    params[1] = .{ .name = "pk", .type_info = .pub_key, .type_name = "PubKey" };

    const call = try allocator.create(types.CallExpr);
    defer allocator.destroy(call);
    const args = try allocator.alloc(Expression, 2);
    defer allocator.free(args);
    args[0] = .{ .identifier = "mySig" };
    args[1] = .{ .identifier = "pk" };
    call.* = .{ .callee = "checkSig", .args = args };

    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .expr_stmt = .{ .call = call } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = params, .body = stmts };

    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(0, result.errors.len);
}

test "typeCheck: logical operator requires boolean" {
    const allocator = std.testing.allocator;

    // Build: 1 && true  — left is bigint, should error
    const bin = try allocator.create(types.BinaryOp);
    defer allocator.destroy(bin);
    bin.* = .{ .op = .and_op, .left = .{ .literal_int = 1 }, .right = .{ .literal_bool = true } };

    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .expr_stmt = .{ .binary_op = bin } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = &.{}, .body = stmts };

    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(1, result.errors.len);
    try std.testing.expect(std.mem.indexOf(u8, result.errors[0], "must be boolean") != null);
}

test "typeCheck: unary not requires boolean" {
    const allocator = std.testing.allocator;

    // Build: !42 — operand is bigint
    const un = try allocator.create(types.UnaryOp);
    defer allocator.destroy(un);
    un.* = .{ .op = .not, .operand = .{ .literal_int = 42 } };

    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .expr_stmt = .{ .unary_op = un } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = &.{}, .body = stmts };

    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(1, result.errors.len);
    try std.testing.expect(std.mem.indexOf(u8, result.errors[0], "operand of '!' must be boolean") != null);
}

test "typeCheck: property access from this" {
    const allocator = std.testing.allocator;

    // Build a contract with a property and a method accessing this.counter
    const props = try allocator.alloc(types.PropertyNode, 1);
    defer allocator.free(props);
    props[0] = .{ .name = "counter", .type_info = .bigint, .readonly = false };

    // Build: const x: bigint = this.counter;
    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .const_decl = .{
        .name = "x",
        .type_info = .bigint,
        .value = .{ .property_access = .{ .object = "this", .property = "counter" } },
    } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "increment", .is_public = true, .params = &.{}, .body = stmts };

    const contract = ContractNode{
        .name = "Counter",
        .parent_class = .smart_contract,
        .properties = props,
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(0, result.errors.len);
}

test "typeCheck: stateful contract has txPreimage" {
    const allocator = std.testing.allocator;

    // Build: const pre: SigHashPreimage = this.txPreimage;
    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .const_decl = .{
        .name = "pre",
        .type_info = .sig_hash_preimage,
        .value = .{ .property_access = .{ .object = "this", .property = "txPreimage" } },
    } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = &.{}, .body = stmts };

    const contract = ContractNode{
        .name = "Stateful",
        .parent_class = .stateful_smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(0, result.errors.len);
}

test "typeCheck: comparison operator types" {
    const allocator = std.testing.allocator;

    // Build: true < 1 — left is boolean, should error
    const bin = try allocator.create(types.BinaryOp);
    defer allocator.destroy(bin);
    bin.* = .{ .op = .lt, .left = .{ .literal_bool = true }, .right = .{ .literal_int = 1 } };

    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .expr_stmt = .{ .binary_op = bin } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = &.{}, .body = stmts };

    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(1, result.errors.len);
    try std.testing.expect(std.mem.indexOf(u8, result.errors[0], "must be bigint") != null);
}

test "typeCheck: method call this.getStateScript" {
    const allocator = std.testing.allocator;

    const mc = try allocator.create(types.MethodCall);
    defer allocator.destroy(mc);
    mc.* = .{ .object = "this", .method = "getStateScript", .args = &.{} };

    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .const_decl = .{
        .name = "script",
        .type_info = .byte_string,
        .value = .{ .method_call = mc },
    } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = &.{}, .body = stmts };

    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .stateful_smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(0, result.errors.len);
}

test "typeCheck: assert special case with 2 args" {
    const allocator = std.testing.allocator;

    // Build: assert(true, "msg")
    const call = try allocator.create(types.CallExpr);
    defer allocator.destroy(call);
    const args = try allocator.alloc(Expression, 2);
    defer allocator.free(args);
    args[0] = .{ .literal_bool = true };
    args[1] = .{ .literal_bytes = "error message" };
    call.* = .{ .callee = "assert", .args = args };

    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .expr_stmt = .{ .call = call } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = &.{}, .body = stmts };

    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(0, result.errors.len);
}

test "typeCheck: equality across ByteString subtypes is fine" {
    const allocator = std.testing.allocator;

    // Build: sha256Result === ripemd160Result (both ByteString family)
    const params = try allocator.alloc(types.ParamNode, 2);
    defer allocator.free(params);
    params[0] = .{ .name = "a", .type_info = .sha256, .type_name = "Sha256" };
    params[1] = .{ .name = "b", .type_info = .ripemd160, .type_name = "Ripemd160" };

    const bin = try allocator.create(types.BinaryOp);
    defer allocator.destroy(bin);
    bin.* = .{ .op = .eq, .left = .{ .identifier = "a" }, .right = .{ .identifier = "b" } };

    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .expr_stmt = .{ .binary_op = bin } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = params, .body = stmts };

    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(0, result.errors.len);
}

test "typeCheck: incompatible equality comparison" {
    const allocator = std.testing.allocator;

    // Build: 42 === true  (bigint vs boolean — not compatible)
    const bin = try allocator.create(types.BinaryOp);
    defer allocator.destroy(bin);
    bin.* = .{ .op = .eq, .left = .{ .literal_int = 42 }, .right = .{ .literal_bool = true } };

    const stmts = try allocator.alloc(Statement, 1);
    defer allocator.free(stmts);
    stmts[0] = .{ .expr_stmt = .{ .binary_op = bin } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = &.{}, .body = stmts };

    const contract = ContractNode{
        .name = "TestContract",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = methods,
    };
    const result = try typeCheck(allocator, contract);
    defer result.deinit(allocator);
    try std.testing.expectEqual(1, result.errors.len);
    try std.testing.expect(std.mem.indexOf(u8, result.errors[0], "cannot compare") != null);
}

test "inferExprTypeStatic: literal types" {
    try std.testing.expectEqual(.bigint, inferExprTypeStatic(.{ .literal_int = 42 }));
    try std.testing.expectEqual(.boolean, inferExprTypeStatic(.{ .literal_bool = true }));
    try std.testing.expectEqual(.byte_string, inferExprTypeStatic(.{ .literal_bytes = "ff" }));
}

test "inferExprTypeStatic: binary ops" {
    const allocator = std.testing.allocator;
    const bin = try allocator.create(types.BinaryOp);
    defer allocator.destroy(bin);

    bin.* = .{ .op = .add, .left = .{ .literal_int = 1 }, .right = .{ .literal_int = 2 } };
    try std.testing.expectEqual(.bigint, inferExprTypeStatic(.{ .binary_op = bin }));

    bin.* = .{ .op = .eq, .left = .{ .literal_int = 1 }, .right = .{ .literal_int = 2 } };
    try std.testing.expectEqual(.boolean, inferExprTypeStatic(.{ .binary_op = bin }));
}

test "isAffineType: Sig and SigHashPreimage" {
    try std.testing.expect(isAffineType(.sig));
    try std.testing.expect(isAffineType(.sig_hash_preimage));
    try std.testing.expect(!isAffineType(.bigint));
    try std.testing.expect(!isAffineType(.pub_key));
    try std.testing.expect(!isAffineType(.boolean));
}

test "isByteFamily: comprehensive" {
    try std.testing.expect(isByteFamily(.byte_string));
    try std.testing.expect(isByteFamily(.pub_key));
    try std.testing.expect(isByteFamily(.sig));
    try std.testing.expect(isByteFamily(.sha256));
    try std.testing.expect(isByteFamily(.ripemd160));
    try std.testing.expect(isByteFamily(.addr));
    try std.testing.expect(isByteFamily(.sig_hash_preimage));
    try std.testing.expect(isByteFamily(.point));
    try std.testing.expect(!isByteFamily(.bigint));
    try std.testing.expect(!isByteFamily(.boolean));
}

test "isBigintFamily: comprehensive" {
    try std.testing.expect(isBigintFamily(.bigint));
    try std.testing.expect(isBigintFamily(.rabin_sig));
    try std.testing.expect(isBigintFamily(.rabin_pub_key));
    try std.testing.expect(!isBigintFamily(.byte_string));
    try std.testing.expect(!isBigintFamily(.boolean));
    try std.testing.expect(!isBigintFamily(.pub_key));
}
