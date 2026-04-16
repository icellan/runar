//! Pass 4: ANF Lower -- transforms a ContractNode (AST) into an ANFProgram (IR).
//!
//! Every subexpression becomes a named temporary binding (t0, t1, t2...).
//! This is A-Normal Form: all intermediate values are explicitly named.
//!
//! Example:
//!   hash160(pubKey) === this.pubKeyHash
//! becomes:
//!   t0 = load_param("pubKey")
//!   t1 = call("hash160", [t0])
//!   t2 = load_prop("pubKeyHash")
//!   t3 = bin_op("===", t1, t2, result_type="bytes")
//!
//! Stateful contracts get automatic preimage checking, state deserialization,
//! and output hash verification injected into public methods.

const std = @import("std");
const types = @import("../ir/types.zig");

const Allocator = std.mem.Allocator;

// IR types used throughout
const ANFProgram = types.ANFProgram;
const ANFProperty = types.ANFProperty;
const ANFMethod = types.ANFMethod;
const ANFBinding = types.ANFBinding;
const ANFValue = types.ANFValue;
const ParamNode = types.ParamNode;
const ContractNode = types.ContractNode;
const ConstructorNode = types.ConstructorNode;
const MethodNode = types.MethodNode;
const PropertyNode = types.PropertyNode;
const Expression = types.Expression;
const Statement = types.Statement;
const ConstValue = types.ConstValue;
const RunarType = types.RunarType;
const BinOperator = types.BinOperator;
const UnaryOperator = types.UnaryOperator;
const ParentClass = types.ParentClass;

// ============================================================================
// Public API
// ============================================================================

pub const LowerError = error{
    OutOfMemory,
    UnsupportedExpression,
    UnsupportedStatement,
};

/// Lower a type-checked ContractNode AST into an ANFProgram IR.
pub fn lowerToANF(allocator: Allocator, contract: ContractNode) LowerError!ANFProgram {
    const properties = try lowerProperties(allocator, contract);
    const methods = try lowerMethods(allocator, contract);

    // Post-pass: lift update_prop from if-else branches into flat conditionals.
    // This prevents phantom stack entries in stack lowering for patterns like
    // position dispatch (different properties updated in different branches).
    // Mirrors the TS reference compiler's liftBranchUpdateProps
    // (packages/runar-compiler/src/passes/04-anf-lower.ts).
    for (methods) |*m| {
        const old_bindings = m.bindings;
        const lifted = try liftBranchUpdateProps(allocator, old_bindings);
        // Release the outer slice from `lowerMethods`. Inner ANFBinding entries
        // that survived (those that did not match the lift pattern) are
        // copied by value into `lifted`, so the strings/sub-slices they
        // reference remain valid and are NOT freed here.
        if (old_bindings.len > 0) allocator.free(old_bindings);
        m.bindings = lifted;
        m.body = lifted;
    }

    return ANFProgram{
        .contract_name = contract.name,
        .parent_class = contract.parent_class,
        .properties = properties,
        .methods = methods,
    };
}

// ============================================================================
// Byte-type detection
// ============================================================================

fn isByteType(t: RunarType) bool {
    return switch (t) {
        .byte_string, .pub_key, .sig, .sha256, .ripemd160, .addr,
        .sig_hash_preimage, .rabin_sig, .rabin_pub_key, .point,
        .p256_point, .p384_point => true,
        else => false,
    };
}

fn isByteReturningFunction(name: []const u8) bool {
    const funcs = std.StaticStringMap(void).initComptime(.{
        .{ "sha256", {} },       .{ "ripemd160", {} },    .{ "hash160", {} },
        .{ "hash256", {} },      .{ "cat", {} },          .{ "substr", {} },
        .{ "num2bin", {} },      .{ "reverseBytes", {} }, .{ "left", {} },
        .{ "right", {} },        .{ "int2str", {} },      .{ "toByteString", {} },
        .{ "pack", {} },         .{ "ecAdd", {} },        .{ "ecMul", {} },
        .{ "ecMulGen", {} },     .{ "ecNegate", {} },     .{ "ecMakePoint", {} },
        .{ "ecEncodeCompressed", {} },
        .{ "blake3Compress", {} }, .{ "blake3Hash", {} },
        .{ "p256Add", {} },      .{ "p256Mul", {} },      .{ "p256MulGen", {} },
        .{ "p256Negate", {} },   .{ "p256EncodeCompressed", {} },
        .{ "p384Add", {} },      .{ "p384Mul", {} },      .{ "p384MulGen", {} },
        .{ "p384Negate", {} },   .{ "p384EncodeCompressed", {} },
    });
    return funcs.get(name) != null;
}

/// Check if an expression is known to produce byte-typed values.
fn isByteTypedExpr(expr: Expression, ctx: *const LowerCtx) bool {
    switch (expr) {
        .literal_bytes => return true,
        .identifier => |name| {
            // Check property types
            for (ctx.contract.properties) |p| {
                if (std.mem.eql(u8, p.name, name) and isByteType(p.type_info)) return true;
            }
            // Check local byte vars
            if (ctx.local_byte_vars.get(name) != null) return true;
            // Mirror TS reference: getParamType walks ALL methods' params
            // (and the constructor) and returns the first match by name.
            // This means a param name shared across methods inherits the
            // type from whichever method declared it first in source order.
            // See packages/runar-compiler/src/passes/04-anf-lower.ts getParamType.
            for (ctx.contract.constructor.params) |p| {
                if (std.mem.eql(u8, p.name, name)) {
                    return isByteType(p.type_info);
                }
            }
            for (ctx.contract.methods) |m| {
                for (m.params) |p| {
                    if (std.mem.eql(u8, p.name, name)) {
                        return isByteType(p.type_info);
                    }
                }
            }
            return false;
        },
        .property_access => |pa| {
            for (ctx.contract.properties) |p| {
                if (std.mem.eql(u8, p.name, pa.property) and isByteType(p.type_info)) return true;
            }
            return false;
        },
        .call => |c| {
            if (isByteReturningFunction(c.callee)) return true;
            if (c.callee.len >= 7 and std.mem.startsWith(u8, c.callee, "extract")) return true;
            return false;
        },
        .method_call => |mc| {
            if (std.mem.eql(u8, mc.object, "this") or std.mem.eql(u8, mc.object, "self")) {
                for (ctx.contract.properties) |p| {
                    if (std.mem.eql(u8, p.name, mc.method) and isByteType(p.type_info)) return true;
                }
            }
            return false;
        },
        else => return false,
    }
}

// ============================================================================
// Properties
// ============================================================================

fn lowerProperties(allocator: Allocator, contract: ContractNode) LowerError![]ANFProperty {
    if (contract.properties.len == 0) return &.{};

    var result: std.ArrayListUnmanaged(ANFProperty) = .empty;
    for (contract.properties) |prop| {
        var anf_prop = ANFProperty{
            .name = prop.name,
            .type_name = types.runarTypeToString(prop.type_info),
            .type_info = prop.type_info,
            .readonly = prop.readonly,
            .synthetic_array_chain = prop.synthetic_array_chain,
        };
        // Only emit initialValue for properties that have defaults AND are NOT
        // constructor params. This matches the TS compiler: properties with
        // initializers are excluded from auto-generated constructors.
        if (prop.initializer) |init_expr| {
            const is_ctor_param = for (contract.constructor.params) |p| {
                if (std.mem.eql(u8, p.name, prop.name)) break true;
            } else false;
            if (!is_ctor_param) {
                anf_prop.initial_value = extractLiteralValue(init_expr);
            }
        }
        try result.append(allocator, anf_prop);
    }
    return try result.toOwnedSlice(allocator);
}

fn extractLiteralValue(expr: Expression) ?ConstValue {
    switch (expr) {
        .literal_int => |v| return .{ .integer = v },
        .literal_bool => |v| return .{ .boolean = v },
        .literal_bytes => |v| return .{ .string = v },
        .unary_op => |uop| {
            if (uop.op == .negate) {
                switch (uop.operand) {
                    .literal_int => |v| return .{ .integer = -v },
                    else => {},
                }
            }
        },
        else => {},
    }
    return null;
}

// ============================================================================
// Methods
// ============================================================================

fn lowerMethods(allocator: Allocator, contract: ContractNode) LowerError![]ANFMethod {
    var result: std.ArrayListUnmanaged(ANFMethod) = .empty;

    // Lower constructor — do NOT register constructor params with addParam;
    // the TS/Go/Rust/Python compilers treat constructor param names as property
    // references (load_prop) rather than parameter references (load_param).
    {
        var ctor_ctx = LowerCtx.init(allocator, contract);
        defer ctor_ctx.deinit();
        for (contract.constructor.params) |param| {
            if (isByteType(param.type_info)) ctor_ctx.markByteTyped(param.name);
        }
        try lowerConstructorBody(&ctor_ctx, contract.constructor);
        const bindings = try ctor_ctx.bindings.toOwnedSlice(allocator);
        try result.append(allocator, ANFMethod{
            .name = "constructor",
            .is_public = false,
            .params = contract.constructor.params,
            .bindings = bindings,
            .body = bindings,
        });
    }

    // Lower each method
    for (contract.methods) |method| {
        var method_ctx = LowerCtx.init(allocator, contract);
        defer method_ctx.deinit();
        // Use the method's source location as default for all bindings in the method.
        method_ctx.current_source_loc = method.source_loc;
        for (method.params) |param| {
            method_ctx.addParam(param.name);
            if (isByteType(param.type_info)) method_ctx.markByteTyped(param.name);
        }

        if (contract.parent_class == .stateful_smart_contract and method.is_public) {
            try lowerStatefulPublicMethod(allocator, &method_ctx, method, contract);
        } else {
            try lowerStatements(&method_ctx, method.body);
            const bindings = try method_ctx.bindings.toOwnedSlice(allocator);
            try result.append(allocator, ANFMethod{
                .name = method.name,
                .is_public = method.is_public,
                .params = method.params,
                .bindings = bindings,
                .body = bindings,
            });
        }

        if (contract.parent_class == .stateful_smart_contract and method.is_public) {
            // Build augmented params
            const needs_change_output = methodMutatesState(method, contract) or methodHasAddOutput(method);
            const needs_new_amount = methodMutatesState(method, contract) and !methodHasAddOutput(method);

            var aug_params: std.ArrayListUnmanaged(ParamNode) = .empty;
            for (method.params) |param| {
                if (!std.mem.eql(u8, param.type_name, "StatefulContext")) {
                    try aug_params.append(allocator, param);
                }
            }
            if (needs_change_output) {
                try aug_params.append(allocator, .{ .name = "_changePKH", .type_info = .ripemd160, .type_name = "Ripemd160" });
                try aug_params.append(allocator, .{ .name = "_changeAmount", .type_info = .bigint, .type_name = "bigint" });
            }
            if (needs_new_amount) {
                try aug_params.append(allocator, .{ .name = "_newAmount", .type_info = .bigint, .type_name = "bigint" });
            }
            try aug_params.append(allocator, .{ .name = "txPreimage", .type_info = .sig_hash_preimage, .type_name = "SigHashPreimage" });

            const bindings = try method_ctx.bindings.toOwnedSlice(allocator);
            try result.append(allocator, ANFMethod{
                .name = method.name,
                .is_public = true,
                .params = try aug_params.toOwnedSlice(allocator),
                .bindings = bindings,
                .body = bindings,
            });
        }
    }

    return try result.toOwnedSlice(allocator);
}

fn lowerConstructorBody(ctx: *LowerCtx, ctor: ConstructorNode) LowerError!void {
    // Always lower super() call — even with zero args, the call must appear in the
    // constructor body to match the TypeScript reference compiler output.
    var arg_refs: std.ArrayListUnmanaged([]const u8) = .empty;
    for (ctor.super_args) |arg| {
        const ref = try lowerExprToRef(ctx, arg);
        try arg_refs.append(ctx.allocator, ref);
    }
    _ = try ctx.emit(.{ .call = .{
        .func = "super",
        .args = try arg_refs.toOwnedSlice(ctx.allocator),
    } });

    // Lower constructor assignments: this.x = param
    for (ctor.assignments) |assign| {
        const value_ref = try lowerExprToRef(ctx, assign.value);
        _ = try ctx.emit(.{ .update_prop = .{
            .name = assign.target,
            .value = value_ref,
        } });
    }
}

fn lowerStatefulPublicMethod(
    allocator: Allocator,
    ctx: *LowerCtx,
    method: MethodNode,
    contract: ContractNode,
) LowerError!void {
    const needs_change_output = methodMutatesState(method, contract) or methodHasAddOutput(method);
    const needs_new_amount = methodMutatesState(method, contract) and !methodHasAddOutput(method);

    // Register implicit parameters
    if (needs_change_output) {
        ctx.addParam("_changePKH");
        ctx.addParam("_changeAmount");
        ctx.markByteTyped("_changePKH");
    }
    if (needs_new_amount) {
        ctx.addParam("_newAmount");
    }
    ctx.addParam("txPreimage");
    ctx.markByteTyped("txPreimage");

    // Inject checkPreimage(txPreimage)
    const preimage_ref = try ctx.emit(.{ .load_param = .{ .name = "txPreimage" } });
    const check_result = try ctx.emit(.{ .check_preimage = .{ .preimage = preimage_ref } });
    _ = try ctx.emit(.{ .assert = .{ .value = check_result } });

    // Deserialize state if there are mutable properties
    const has_mutable_state = for (contract.properties) |p| {
        if (!p.readonly) break true;
    } else false;

    if (has_mutable_state) {
        const preimage_ref3 = try ctx.emit(.{ .load_param = .{ .name = "txPreimage" } });
        _ = try ctx.emit(.{ .deserialize_state = .{ .preimage = preimage_ref3 } });
    }

    // Lower the developer's method body
    try lowerStatements(ctx, method.body);

    // Determine state continuation type
    const add_output_refs = ctx.getAddOutputRefs();
    _ = allocator;

    if (add_output_refs.len > 0 or methodMutatesState(method, contract)) {
        // Build P2PKH change output
        const change_pkh_ref = try ctx.emit(.{ .load_param = .{ .name = "_changePKH" } });
        const change_amount_ref = try ctx.emit(.{ .load_param = .{ .name = "_changeAmount" } });
        const change_output_ref = try ctx.emit(.{ .call = .{
            .func = "buildChangeOutput",
            .args = try ctx.allocSlice(&.{ change_pkh_ref, change_amount_ref }),
        } });

        if (add_output_refs.len > 0) {
            // Multi-output: concat all outputs + change, hash, verify
            var accumulated: []const u8 = add_output_refs[0];
            for (add_output_refs[1..]) |aor| {
                accumulated = try ctx.emit(.{ .call = .{
                    .func = "cat",
                    .args = try ctx.allocSlice(&.{ accumulated, aor }),
                } });
            }
            accumulated = try ctx.emit(.{ .call = .{
                .func = "cat",
                .args = try ctx.allocSlice(&.{ accumulated, change_output_ref }),
            } });
            const hash_ref = try ctx.emit(.{ .call = .{
                .func = "hash256",
                .args = try ctx.allocSlice(&.{accumulated}),
            } });
            const preimage_ref2 = try ctx.emit(.{ .load_param = .{ .name = "txPreimage" } });
            const output_hash_ref = try ctx.emit(.{ .call = .{
                .func = "extractOutputHash",
                .args = try ctx.allocSlice(&.{preimage_ref2}),
            } });
            const eq_ref = try ctx.emit(.{ .bin_op = .{
                .op = "===",
                .left = hash_ref,
                .right = output_hash_ref,
                .result_type = "bytes",
            } });
            _ = try ctx.emit(.{ .assert = .{ .value = eq_ref } });
        } else {
            // Single-output continuation
            const state_script_ref = try ctx.emit(.{ .get_state_script = {} });
            const preimage_ref2 = try ctx.emit(.{ .load_param = .{ .name = "txPreimage" } });
            const new_amount_ref = try ctx.emit(.{ .load_param = .{ .name = "_newAmount" } });
            const contract_output_ref = try ctx.emit(.{ .call = .{
                .func = "computeStateOutput",
                .args = try ctx.allocSlice(&.{ preimage_ref2, state_script_ref, new_amount_ref }),
            } });
            const all_outputs = try ctx.emit(.{ .call = .{
                .func = "cat",
                .args = try ctx.allocSlice(&.{ contract_output_ref, change_output_ref }),
            } });
            const hash_ref = try ctx.emit(.{ .call = .{
                .func = "hash256",
                .args = try ctx.allocSlice(&.{all_outputs}),
            } });
            const preimage_ref4 = try ctx.emit(.{ .load_param = .{ .name = "txPreimage" } });
            const output_hash_ref = try ctx.emit(.{ .call = .{
                .func = "extractOutputHash",
                .args = try ctx.allocSlice(&.{preimage_ref4}),
            } });
            const eq_ref = try ctx.emit(.{ .bin_op = .{
                .op = "===",
                .left = hash_ref,
                .right = output_hash_ref,
                .result_type = "bytes",
            } });
            _ = try ctx.emit(.{ .assert = .{ .value = eq_ref } });
        }
    }
}

// ============================================================================
// LowerCtx -- manages temp variable generation and binding emission
// ============================================================================

const LowerCtx = struct {
    allocator: Allocator,
    contract: ContractNode,
    bindings: std.ArrayListUnmanaged(ANFBinding),
    counter: u32,
    local_names: std.StringHashMapUnmanaged(void),
    param_names: std.StringHashMapUnmanaged(void),
    local_aliases: std.StringHashMapUnmanaged([]const u8),
    local_byte_vars: std.StringHashMapUnmanaged(void),
    add_output_refs: std.ArrayListUnmanaged([]const u8),
    /// Current source location — set before lowering each statement, stamped on bindings.
    current_source_loc: ?types.SourceLocation = null,

    fn init(allocator: Allocator, contract: ContractNode) LowerCtx {
        return .{
            .allocator = allocator,
            .contract = contract,
            .bindings = .empty,
            .counter = 0,
            .local_names = .empty,
            .param_names = .empty,
            .local_aliases = .empty,
            .local_byte_vars = .empty,
            .add_output_refs = .empty,
        };
    }

    fn freshTemp(self: *LowerCtx) ![]const u8 {
        const name = try std.fmt.allocPrint(self.allocator, "t{d}", .{self.counter});
        self.counter += 1;
        return name;
    }

    fn emit(self: *LowerCtx, value: ANFValue) LowerError![]const u8 {
        const name = try self.freshTemp();
        try self.bindings.append(self.allocator, ANFBinding{ .name = name, .value = value, .source_loc = self.current_source_loc });
        return name;
    }

    fn emitNamed(self: *LowerCtx, name: []const u8, value: ANFValue) LowerError!void {
        try self.bindings.append(self.allocator, ANFBinding{ .name = name, .value = value, .source_loc = self.current_source_loc });
    }

    fn addLocal(self: *LowerCtx, name: []const u8) void {
        self.local_names.put(self.allocator, name, {}) catch {};
    }

    fn isLocal(self: *const LowerCtx, name: []const u8) bool {
        return self.local_names.get(name) != null;
    }

    fn addParam(self: *LowerCtx, name: []const u8) void {
        self.param_names.put(self.allocator, name, {}) catch {};
    }

    fn markByteTyped(self: *LowerCtx, name: []const u8) void {
        self.local_byte_vars.put(self.allocator, name, {}) catch {};
    }

    fn isParam(self: *const LowerCtx, name: []const u8) bool {
        return self.param_names.get(name) != null;
    }

    fn setLocalAlias(self: *LowerCtx, local_name: []const u8, binding_name: []const u8) void {
        self.local_aliases.put(self.allocator, local_name, binding_name) catch {};
    }

    fn getLocalAlias(self: *const LowerCtx, local_name: []const u8) ?[]const u8 {
        return self.local_aliases.get(local_name);
    }

    fn addOutputRef(self: *LowerCtx, ref: []const u8) void {
        self.add_output_refs.append(self.allocator, ref) catch {};
    }

    fn getAddOutputRefs(self: *const LowerCtx) []const []const u8 {
        return self.add_output_refs.items;
    }

    fn isProperty(self: *const LowerCtx, name: []const u8) bool {
        for (self.contract.properties) |p| {
            if (std.mem.eql(u8, p.name, name)) return true;
        }
        return false;
    }

    fn subContext(self: *LowerCtx) LowerCtx {
        var sub = LowerCtx.init(self.allocator, self.contract);
        sub.counter = self.counter;
        // Copy local names
        var local_it = self.local_names.iterator();
        while (local_it.next()) |entry| {
            sub.local_names.put(self.allocator, entry.key_ptr.*, {}) catch {};
        }
        // Copy param names
        var param_it = self.param_names.iterator();
        while (param_it.next()) |entry| {
            sub.param_names.put(self.allocator, entry.key_ptr.*, {}) catch {};
        }
        // Copy local aliases
        var alias_it = self.local_aliases.iterator();
        while (alias_it.next()) |entry| {
            sub.local_aliases.put(self.allocator, entry.key_ptr.*, entry.value_ptr.*) catch {};
        }
        // Copy local byte vars
        var byte_it = self.local_byte_vars.iterator();
        while (byte_it.next()) |entry| {
            sub.local_byte_vars.put(self.allocator, entry.key_ptr.*, {}) catch {};
        }
        return sub;
    }

    fn syncCounter(self: *LowerCtx, sub: *const LowerCtx) void {
        if (sub.counter > self.counter) {
            self.counter = sub.counter;
        }
    }

    fn deinit(self: *LowerCtx) void {
        self.local_names.deinit(self.allocator);
        self.param_names.deinit(self.allocator);
        self.local_aliases.deinit(self.allocator);
        self.local_byte_vars.deinit(self.allocator);
        self.add_output_refs.deinit(self.allocator);
    }

    /// Allocate a slice of string refs on the arena allocator.
    fn allocSlice(self: *LowerCtx, items: []const []const u8) LowerError![]const []const u8 {
        const result = try self.allocator.alloc([]const u8, items.len);
        @memcpy(result, items);
        return result;
    }
};

// ============================================================================
// Statement lowering
// ============================================================================

fn lowerStatements(ctx: *LowerCtx, stmts: []const Statement) LowerError!void {
    for (stmts, 0..) |stmt, i| {
        // Early-return nesting: if a then-block ends with return and there's no else-branch,
        // remaining statements become the else-branch.
        if (stmt == .if_stmt) {
            const if_s = stmt.if_stmt;
            if (if_s.else_body == null and (i + 1 < stmts.len) and branchEndsWithReturn(if_s.then_body)) {
                const remaining = stmts[i + 1 ..];
                try lowerIfStatementWithElse(ctx, if_s.condition, if_s.then_body, remaining);
                return;
            }
        }
        try lowerStatement(ctx, stmt);
    }
}

fn lowerStatement(ctx: *LowerCtx, stmt: Statement) LowerError!void {
    // Extract source_loc from the statement variant and set it on the context.
    // All bindings emitted while processing this statement will inherit it.
    const prev_loc = ctx.current_source_loc;
    defer ctx.current_source_loc = prev_loc;
    ctx.current_source_loc = switch (stmt) {
        .const_decl => |d| d.source_loc,
        .let_decl => |d| d.source_loc,
        .assign => |a| a.source_loc,
        .if_stmt => |i| i.source_loc,
        .for_stmt => |f| f.source_loc,
        .assert_stmt => |a| a.source_loc,
        .expr_stmt, .return_stmt => null,
    } orelse ctx.current_source_loc;

    switch (stmt) {
        .const_decl => |decl| {
            const value_ref = try lowerExprToRef(ctx, decl.value);
            ctx.addLocal(decl.name);
            if (isByteTypedExpr(decl.value, ctx)) {
                ctx.local_byte_vars.put(ctx.allocator, decl.name, {}) catch {};
            }
            try ctx.emitNamed(decl.name, makeLoadConstString(ctx.allocator, try refString(ctx.allocator, value_ref)));
        },
        .let_decl => |decl| {
            if (decl.value) |val| {
                const value_ref = try lowerExprToRef(ctx, val);
                ctx.addLocal(decl.name);
                if (isByteTypedExpr(val, ctx)) {
                    ctx.local_byte_vars.put(ctx.allocator, decl.name, {}) catch {};
                }
                try ctx.emitNamed(decl.name, makeLoadConstString(ctx.allocator, try refString(ctx.allocator, value_ref)));
            } else {
                ctx.addLocal(decl.name);
                _ = try ctx.emit(makeLoadConstInt(0));
            }
        },
        .assign => |assign| {
            // Skip Zig discard assignments: _ = self; _ = expr;
            if (std.mem.eql(u8, assign.target, "_")) return;
            const value_ref = try lowerExprToRef(ctx, assign.value);
            // Check if target is a property
            if (ctx.isProperty(assign.target)) {
                _ = try ctx.emit(.{ .update_prop = .{
                    .name = assign.target,
                    .value = value_ref,
                } });
            } else if (ctx.isLocal(assign.target)) {
                try ctx.emitNamed(assign.target, makeLoadConstString(ctx.allocator, try refString(ctx.allocator, value_ref)));
            } else {
                _ = try lowerExprToRef(ctx, .{ .identifier = assign.target });
            }
        },
        .if_stmt => |if_s| {
            try lowerIfStatementFull(ctx, if_s.condition, if_s.then_body, if_s.else_body);
        },
        .for_stmt => |for_s| {
            try lowerForStatement(ctx, for_s);
        },
        .expr_stmt => |expr| {
            _ = try lowerExprToRef(ctx, expr);
        },
        .assert_stmt => |assert_s| {
            const cond_ref = try lowerExprToRef(ctx, assert_s.condition);
            _ = try ctx.emit(.{ .assert = .{ .value = cond_ref } });
        },
        .return_stmt => |maybe_expr| {
            if (maybe_expr) |expr| {
                const ref = try lowerExprToRef(ctx, expr);
                // If the returned ref is not the last emitted binding, emit explicit load
                if (ctx.bindings.items.len > 0 and !std.mem.eql(u8, ctx.bindings.items[ctx.bindings.items.len - 1].name, ref)) {
                    _ = try ctx.emit(makeLoadConstString(ctx.allocator, try refString(ctx.allocator, ref)));
                }
            }
        },
    }
}

fn lowerIfStatementFull(ctx: *LowerCtx, condition: Expression, then_body: []const Statement, else_body: ?[]const Statement) LowerError!void {
    const cond_ref = try lowerExprToRef(ctx, condition);

    // Lower then-block
    var then_ctx = ctx.subContext();
    try lowerStatements(&then_ctx, then_body);
    ctx.syncCounter(&then_ctx);

    // Lower else-block
    var else_ctx = ctx.subContext();
    if (else_body) |eb| {
        try lowerStatements(&else_ctx, eb);
    }
    ctx.syncCounter(&else_ctx);

    // Propagate addOutput refs
    const then_has_outputs = then_ctx.getAddOutputRefs().len > 0;
    const else_has_outputs = else_ctx.getAddOutputRefs().len > 0;

    const if_val = try ctx.allocator.create(types.ANFIf);
    if_val.* = .{
        .cond = cond_ref,
        .then = try then_ctx.bindings.toOwnedSlice(ctx.allocator),
        .@"else" = try else_ctx.bindings.toOwnedSlice(ctx.allocator),
    };
    const if_name = try ctx.emit(.{ .@"if" = if_val });

    if (then_has_outputs or else_has_outputs) {
        ctx.addOutputRef(if_name);
    }

    // Alias detection: if both branches end by reassigning same local variable
    if (if_val.then.len > 0 and if_val.@"else".len > 0) {
        const then_last = if_val.then[if_val.then.len - 1];
        const else_last = if_val.@"else"[if_val.@"else".len - 1];
        if (std.mem.eql(u8, then_last.name, else_last.name) and ctx.isLocal(then_last.name)) {
            ctx.setLocalAlias(then_last.name, if_name);
        }
    }
}

fn lowerIfStatementWithElse(ctx: *LowerCtx, condition: Expression, then_body: []const Statement, else_body: []const Statement) LowerError!void {
    try lowerIfStatementFull(ctx, condition, then_body, else_body);
}

fn lowerForStatement(ctx: *LowerCtx, for_s: types.ForStmt) LowerError!void {
    const count: u32 = blk: {
        const diff = for_s.bound - for_s.init_value;
        if (diff < 0) break :blk 0;
        break :blk @intCast(diff);
    };

    // Lower body
    var body_ctx = ctx.subContext();
    try lowerStatements(&body_ctx, for_s.body);
    ctx.syncCounter(&body_ctx);

    const loop_val = try ctx.allocator.create(types.ANFLoop);
    loop_val.* = .{
        .count = count,
        .body = try body_ctx.bindings.toOwnedSlice(ctx.allocator),
        .iter_var = for_s.var_name,
    };
    _ = try ctx.emit(.{ .loop = loop_val });
}

// ============================================================================
// Expression lowering (the core ANF conversion)
// ============================================================================

fn lowerExprToRef(ctx: *LowerCtx, expr: Expression) LowerError![]const u8 {
    switch (expr) {
        .literal_int => |v| {
            return try ctx.emit(makeLoadConstInt(v));
        },
        .literal_bool => |v| {
            return try ctx.emit(makeLoadConstBool(v));
        },
        .literal_bytes => |v| {
            return try ctx.emit(makeLoadConstString(ctx.allocator, v));
        },
        .identifier => |name| {
            return try lowerIdentifier(ctx, name);
        },
        .property_access => |pa| {
            // this.txPreimage in StatefulSmartContract -> load_param
            if (ctx.isParam(pa.property)) {
                return try ctx.emit(.{ .load_param = .{ .name = pa.property } });
            }
            if (isStatefulContextParam(ctx, pa.object) and std.mem.eql(u8, pa.property, "txPreimage")) {
                return try ctx.emit(.{ .load_param = .{ .name = "txPreimage" } });
            }
            // this.x -> load_prop
            return try ctx.emit(.{ .load_prop = .{ .name = pa.property } });
        },
        .binary_op => |bop| {
            const left_ref = try lowerExprToRef(ctx, bop.left);
            const right_ref = try lowerExprToRef(ctx, bop.right);

            var result_type: ?[]const u8 = null;
            const op_str = bop.op.toTsString();

            // For ===, !==, annotate byte-typed operands
            if (bop.op == .eq or bop.op == .neq) {
                if (isByteTypedExpr(bop.left, ctx) or isByteTypedExpr(bop.right, ctx)) {
                    result_type = "bytes";
                }
            }
            // For +, annotate byte-typed operands (OP_CAT)
            if (bop.op == .add) {
                if (isByteTypedExpr(bop.left, ctx) or isByteTypedExpr(bop.right, ctx)) {
                    result_type = "bytes";
                }
            }
            // For &, |, ^, annotate byte-typed operands
            if (bop.op == .bitand or bop.op == .bitor or bop.op == .bitxor) {
                if (isByteTypedExpr(bop.left, ctx) or isByteTypedExpr(bop.right, ctx)) {
                    result_type = "bytes";
                }
            }

            return try ctx.emit(.{ .bin_op = .{
                .op = op_str,
                .left = left_ref,
                .right = right_ref,
                .result_type = result_type,
            } });
        },
        .unary_op => |uop| {
            const operand_ref = try lowerExprToRef(ctx, uop.operand);
            var result_type: ?[]const u8 = null;
            if (uop.op == .bitnot and isByteTypedExpr(uop.operand, ctx)) {
                result_type = "bytes";
            }
            return try ctx.emit(.{ .unary_op = .{
                .op = uop.op.toTsString(),
                .operand = operand_ref,
                .result_type = result_type,
            } });
        },
        .call => |c| {
            return try lowerCallExpr(ctx, c);
        },
        .method_call => |mc| {
            return try lowerMethodCallExpr(ctx, mc);
        },
        .ternary => |t| {
            return try lowerTernaryExpr(ctx, t);
        },
        .index_access => |ia| {
            const obj_ref = try lowerExprToRef(ctx, ia.object);
            const idx_ref = try lowerExprToRef(ctx, ia.index);
            return try ctx.emit(.{ .call = .{
                .func = "__array_access",
                .args = try ctx.allocSlice(&.{ obj_ref, idx_ref }),
            } });
        },
        .increment => |inc| {
            return try lowerIncrementExpr(ctx, inc);
        },
        .decrement => |dec| {
            return try lowerDecrementExpr(ctx, dec);
        },
        .array_literal => |elems| {
            var refs: std.ArrayListUnmanaged([]const u8) = .empty;
            for (elems) |elem| {
                const ref = try lowerExprToRef(ctx, elem);
                try refs.append(ctx.allocator, ref);
            }
            return try ctx.emit(.{ .array_literal = .{
                .elements = try refs.toOwnedSlice(ctx.allocator),
            } });
        },
    }
}

fn lowerIdentifier(ctx: *LowerCtx, name: []const u8) LowerError![]const u8 {
    // 'this' and 'self' are not first-class runtime values in ANF.
    if (std.mem.eql(u8, name, "this") or std.mem.eql(u8, name, "self")) {
        return try ctx.emit(makeLoadConstString(ctx.allocator, "@this"));
    }

    // Check if it's a registered parameter
    if (ctx.isParam(name)) {
        return try ctx.emit(.{ .load_param = .{ .name = name } });
    }

    // Check if it's a local variable
    if (ctx.isLocal(name)) {
        if (ctx.getLocalAlias(name)) |alias| {
            return alias;
        }
        return name;
    }

    // Check if it's a contract property
    if (ctx.isProperty(name)) {
        return try ctx.emit(.{ .load_prop = .{ .name = name } });
    }

    // Default: treat as parameter
    return try ctx.emit(.{ .load_param = .{ .name = name } });
}

fn isStatefulContextParam(ctx: *const LowerCtx, name: []const u8) bool {
    for (ctx.contract.methods) |method| {
        for (method.params) |param| {
            if (std.mem.eql(u8, param.name, name) and std.mem.eql(u8, param.type_name, "StatefulContext")) {
                return true;
            }
        }
    }
    return false;
}

fn lowerCallExpr(ctx: *LowerCtx, c: *const types.CallExpr) LowerError![]const u8 {
    // super() call
    if (std.mem.eql(u8, c.callee, "super")) {
        const arg_refs = try lowerArgs(ctx, c.args);
        return try ctx.emit(.{ .call = .{
            .func = "super",
            .args = arg_refs,
        } });
    }

    // assert(expr)
    if (std.mem.eql(u8, c.callee, "assert")) {
        if (c.args.len >= 1) {
            const value_ref = try lowerExprToRef(ctx, c.args[0]);
            return try ctx.emit(.{ .assert = .{ .value = value_ref } });
        }
        const false_ref = try ctx.emit(makeLoadConstBool(false));
        return try ctx.emit(.{ .assert = .{ .value = false_ref } });
    }

    // checkPreimage(preimage)
    if (std.mem.eql(u8, c.callee, "checkPreimage")) {
        if (c.args.len >= 1) {
            const preimage_ref = try lowerExprToRef(ctx, c.args[0]);
            return try ctx.emit(.{ .check_preimage = .{ .preimage = preimage_ref } });
        }
    }

    // Check if callee is a contract method (private helper) — emit method_call with @this
    for (ctx.contract.methods) |method| {
        if (std.mem.eql(u8, method.name, c.callee)) {
            const arg_refs = try lowerArgs(ctx, c.args);
            const this_ref = try ctx.emit(makeLoadConstString(ctx.allocator, "@this"));
            return try ctx.emit(.{ .method_call = .{
                .object = this_ref,
                .method = c.callee,
                .args = arg_refs,
            } });
        }
    }

    // Direct function call: sha256(x), checkSig(sig, pk), etc.
    const arg_refs = try lowerArgs(ctx, c.args);
    return try ctx.emit(.{ .call = .{
        .func = c.callee,
        .args = arg_refs,
    } });
}

fn lowerMethodCallExpr(ctx: *LowerCtx, mc: *const types.MethodCall) LowerError![]const u8 {
    const is_self = std.mem.eql(u8, mc.object, "this") or std.mem.eql(u8, mc.object, "self");
    const is_stateful_ctx = isStatefulContextParam(ctx, mc.object);

    // this.addOutput(satoshis, val1, val2, ...)
    if ((is_self or is_stateful_ctx) and std.mem.eql(u8, mc.method, "addOutput")) {
        const arg_refs = try lowerAddOutputArgs(ctx, mc.args);
        if (arg_refs.len > 0) {
            const ref = try ctx.emit(.{ .add_output = .{
                .satoshis = arg_refs[0],
                .state_values = if (arg_refs.len > 1) arg_refs[1..] else &.{},
                .preimage = "",
            } });
            ctx.addOutputRef(ref);
            return ref;
        }
    }

    // this.addRawOutput(satoshis, scriptBytes)
    if ((is_self or is_stateful_ctx) and std.mem.eql(u8, mc.method, "addRawOutput")) {
        const arg_refs = try lowerArgs(ctx, mc.args);
        if (arg_refs.len >= 2) {
            const ref = try ctx.emit(.{ .add_raw_output = .{
                .satoshis = arg_refs[0],
                .script_bytes = arg_refs[1],
            } });
            ctx.addOutputRef(ref);
            return ref;
        }
    }

    // this.getStateScript()
    if ((is_self or is_stateful_ctx) and std.mem.eql(u8, mc.method, "getStateScript")) {
        return try ctx.emit(.{ .get_state_script = {} });
    }

    // SigHash enum members
    if (std.mem.eql(u8, mc.object, "SigHash")) {
        const sig_hash_map = std.StaticStringMap(i64).initComptime(.{
            .{ "ALL", 0x01 },         .{ "NONE", 0x02 },
            .{ "SINGLE", 0x03 },      .{ "FORKID", 0x40 },
            .{ "ANYONECANPAY", 0x80 },
        });
        if (sig_hash_map.get(mc.method)) |val| {
            return try ctx.emit(makeLoadConstInt(val));
        }
    }

    // this.method(...) -> method_call
    if (is_self) {
        const arg_refs = try lowerArgs(ctx, mc.args);
        const this_ref = try ctx.emit(makeLoadConstString(ctx.allocator, "@this"));
        return try ctx.emit(.{ .method_call = .{
            .object = this_ref,
            .method = mc.method,
            .args = arg_refs,
        } });
    }

    // General member access or method call
    const arg_refs = try lowerArgs(ctx, mc.args);
    const obj_ref = try lowerExprToRef(ctx, .{ .identifier = mc.object });
    return try ctx.emit(.{ .method_call = .{
        .object = obj_ref,
        .method = mc.method,
        .args = arg_refs,
    } });
}

fn lowerTernaryExpr(ctx: *LowerCtx, t: *const types.Ternary) LowerError![]const u8 {
    const cond_ref = try lowerExprToRef(ctx, t.condition);

    var then_ctx = ctx.subContext();
    _ = try lowerExprToRef(&then_ctx, t.then_expr);
    ctx.syncCounter(&then_ctx);

    var else_ctx = ctx.subContext();
    _ = try lowerExprToRef(&else_ctx, t.else_expr);
    ctx.syncCounter(&else_ctx);

    const if_val = try ctx.allocator.create(types.ANFIf);
    if_val.* = .{
        .cond = cond_ref,
        .then = try then_ctx.bindings.toOwnedSlice(ctx.allocator),
        .@"else" = try else_ctx.bindings.toOwnedSlice(ctx.allocator),
    };
    return try ctx.emit(.{ .@"if" = if_val });
}

fn lowerAddOutputArgs(ctx: *LowerCtx, args: []const Expression) LowerError![]const []const u8 {
    if (args.len == 2) {
        switch (args[1]) {
            .array_literal => |elems| {
                var refs: std.ArrayListUnmanaged([]const u8) = .empty;
                try refs.append(ctx.allocator, try lowerExprToRef(ctx, args[0]));
                for (elems) |elem| {
                    try refs.append(ctx.allocator, try lowerExprToRef(ctx, elem));
                }
                return try refs.toOwnedSlice(ctx.allocator);
            },
            else => {},
        }
    }
    return try lowerArgs(ctx, args);
}

fn lowerIncrementExpr(ctx: *LowerCtx, inc: *const types.IncrementExpr) LowerError![]const u8 {
    const operand_ref = try lowerExprToRef(ctx, inc.operand);
    const one_ref = try ctx.emit(makeLoadConstInt(1));
    const result = try ctx.emit(.{ .bin_op = .{
        .op = "+",
        .left = operand_ref,
        .right = one_ref,
    } });

    // If operand is a named variable, update it
    switch (inc.operand) {
        .identifier => |name| {
            try ctx.emitNamed(name, makeLoadConstString(ctx.allocator, try refString(ctx.allocator, result)));
        },
        .property_access => |pa| {
            if (isReadonlyProperty(ctx.contract.properties, pa.property)) {
                return error.UnsupportedExpression; // cannot increment readonly property
            }
            _ = try ctx.emit(.{ .update_prop = .{
                .name = pa.property,
                .value = result,
            } });
        },
        else => {},
    }

    if (inc.prefix) return result;
    return operand_ref;
}

fn lowerDecrementExpr(ctx: *LowerCtx, dec: *const types.DecrementExpr) LowerError![]const u8 {
    const operand_ref = try lowerExprToRef(ctx, dec.operand);
    const one_ref = try ctx.emit(makeLoadConstInt(1));
    const result = try ctx.emit(.{ .bin_op = .{
        .op = "-",
        .left = operand_ref,
        .right = one_ref,
    } });

    // If operand is a named variable, update it
    switch (dec.operand) {
        .identifier => |name| {
            try ctx.emitNamed(name, makeLoadConstString(ctx.allocator, try refString(ctx.allocator, result)));
        },
        .property_access => |pa| {
            if (isReadonlyProperty(ctx.contract.properties, pa.property)) {
                return error.UnsupportedExpression; // cannot decrement readonly property
            }
            _ = try ctx.emit(.{ .update_prop = .{
                .name = pa.property,
                .value = result,
            } });
        },
        else => {},
    }

    if (dec.prefix) return result;
    return operand_ref;
}

fn lowerArgs(ctx: *LowerCtx, args: []const Expression) LowerError![]const []const u8 {
    if (args.len == 0) return &.{};
    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    for (args) |arg| {
        const ref = try lowerExprToRef(ctx, arg);
        try result.append(ctx.allocator, ref);
    }
    return try result.toOwnedSlice(ctx.allocator);
}

// ============================================================================
// ANFValue constructors
// ============================================================================

fn makeLoadConstInt(val: i64) ANFValue {
    return .{ .load_const = .{ .value = .{ .integer = val } } };
}

fn makeLoadConstBool(val: bool) ANFValue {
    return .{ .load_const = .{ .value = .{ .boolean = val } } };
}

fn makeLoadConstString(allocator: Allocator, val: []const u8) ANFValue {
    _ = allocator;
    return .{ .load_const = .{ .value = .{ .string = val } } };
}

/// Create an "@ref:NAME" string for local variable aliasing.
fn refString(allocator: Allocator, name: []const u8) LowerError![]const u8 {
    return try std.fmt.allocPrint(allocator, "@ref:{s}", .{name});
}

// ============================================================================
// Property helpers
// ============================================================================

fn isReadonlyProperty(properties: []const PropertyNode, name: []const u8) bool {
    for (properties) |p| {
        if (std.mem.eql(u8, p.name, name)) return p.readonly;
    }
    return false;
}

// ============================================================================
// State mutation analysis
// ============================================================================

fn methodMutatesState(method: MethodNode, contract: ContractNode) bool {
    // Collect mutable property names
    var has_mutable = false;
    for (contract.properties) |p| {
        if (!p.readonly) {
            has_mutable = true;
            break;
        }
    }
    if (!has_mutable) return false;

    return bodyMutatesState(method.body, contract);
}

fn bodyMutatesState(stmts: []const Statement, contract: ContractNode) bool {
    for (stmts) |stmt| {
        if (stmtMutatesState(stmt, contract)) return true;
    }
    return false;
}

fn stmtMutatesState(stmt: Statement, contract: ContractNode) bool {
    switch (stmt) {
        .assign => |assign| {
            // Check if target is a mutable property
            for (contract.properties) |p| {
                if (!p.readonly and std.mem.eql(u8, p.name, assign.target)) return true;
            }
            return false;
        },
        .expr_stmt => |expr| return exprMutatesState(expr, contract),
        .if_stmt => |if_s| {
            if (bodyMutatesState(if_s.then_body, contract)) return true;
            if (if_s.else_body) |eb| {
                if (bodyMutatesState(eb, contract)) return true;
            }
            return false;
        },
        .for_stmt => |for_s| return bodyMutatesState(for_s.body, contract),
        else => return false,
    }
}

fn exprMutatesState(expr: Expression, contract: ContractNode) bool {
    switch (expr) {
        .increment => |inc| {
            switch (inc.operand) {
                .property_access => |pa| {
                    for (contract.properties) |p| {
                        if (!p.readonly and std.mem.eql(u8, p.name, pa.property)) return true;
                    }
                },
                else => {},
            }
        },
        .decrement => |dec| {
            switch (dec.operand) {
                .property_access => |pa| {
                    for (contract.properties) |p| {
                        if (!p.readonly and std.mem.eql(u8, p.name, pa.property)) return true;
                    }
                },
                else => {},
            }
        },
        else => {},
    }
    return false;
}

// ============================================================================
// addOutput detection
// ============================================================================

fn methodHasAddOutput(method: MethodNode) bool {
    return bodyHasAddOutput(method.body, method.params);
}

fn bodyHasAddOutput(stmts: []const Statement, params: []const ParamNode) bool {
    for (stmts) |stmt| {
        if (stmtHasAddOutput(stmt, params)) return true;
    }
    return false;
}

fn stmtHasAddOutput(stmt: Statement, params: []const ParamNode) bool {
    switch (stmt) {
        .expr_stmt => |expr| return exprHasAddOutput(expr, params),
        .if_stmt => |if_s| {
            if (bodyHasAddOutput(if_s.then_body, params)) return true;
            if (if_s.else_body) |eb| {
                if (bodyHasAddOutput(eb, params)) return true;
            }
            return false;
        },
        .for_stmt => |for_s| return bodyHasAddOutput(for_s.body, params),
        else => return false,
    }
}

fn exprHasAddOutput(expr: Expression, params: []const ParamNode) bool {
    switch (expr) {
        .method_call => |mc| {
            if (std.mem.eql(u8, mc.object, "this") or std.mem.eql(u8, mc.object, "self") or paramIsStatefulContext(params, mc.object)) {
                if (std.mem.eql(u8, mc.method, "addOutput") or std.mem.eql(u8, mc.method, "addRawOutput")) {
                    return true;
                }
            }
        },
        else => {},
    }
    return false;
}

fn paramIsStatefulContext(params: []const ParamNode, name: []const u8) bool {
    for (params) |param| {
        if (std.mem.eql(u8, param.name, name) and std.mem.eql(u8, param.type_name, "StatefulContext")) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Helpers
// ============================================================================

fn branchEndsWithReturn(stmts: []const Statement) bool {
    if (stmts.len == 0) return false;
    const last = stmts[stmts.len - 1];
    switch (last) {
        .return_stmt => return true,
        .if_stmt => |if_s| {
            if (if_s.else_body) |eb| {
                return branchEndsWithReturn(if_s.then_body) and branchEndsWithReturn(eb);
            }
            return false;
        },
        else => return false,
    }
}

// ============================================================================
// liftBranchUpdateProps — flatten if-else chains that write properties
// ============================================================================
//
// Mirrors the TypeScript reference compiler's liftBranchUpdateProps
// (packages/runar-compiler/src/passes/04-anf-lower.ts) and Go/Rust/Ruby ports.
//
// Transforms if-else chains where each branch ends with update_prop into
// flat conditional assignments. This is critical for stateful contracts
// because Bitcoin Script requires ALL state fields to be explicitly on the
// stack after method execution — nested update_props leave phantom stack
// entries in stack lowering.
//
// Before:
//   if (pos === 0) { this.c0 = turn; }
//   else if (pos === 1) { this.c1 = turn; }
//   else { assert(false); }
//
// After:
//   this.c0 = (pos === 0)           ? turn : this.c0;
//   this.c1 = (!cond0 && pos === 1) ? turn : this.c1;

const UpdateBranch = struct {
    cond_setup_bindings: []const ANFBinding,
    cond_ref: ?[]const u8, // null for final else
    prop_name: []const u8,
    value_bindings: []const ANFBinding,
    value_ref: []const u8,
};

/// Find the max temp index (e.g. "t47" → 47) in a binding tree.
fn maxTempIndex(bindings: []const ANFBinding) i64 {
    var max: i64 = -1;
    for (bindings) |b| {
        if (b.name.len > 1 and b.name[0] == 't') {
            var n: i64 = 0;
            var valid = true;
            for (b.name[1..]) |ch| {
                if (ch >= '0' and ch <= '9') {
                    n = n * 10 + (ch - '0');
                } else {
                    valid = false;
                    break;
                }
            }
            if (valid and n > max) max = n;
        }
        switch (b.value) {
            .@"if" => |ifv| {
                const t = maxTempIndex(ifv.then);
                if (t > max) max = t;
                const e = maxTempIndex(ifv.@"else");
                if (e > max) max = e;
            },
            .loop => |lp| {
                const t = maxTempIndex(lp.body);
                if (t > max) max = t;
            },
            else => {},
        }
    }
    return max;
}

/// Check if a binding value is side-effect-free (safe to hoist).
fn isSideEffectFree(v: ANFValue) bool {
    return switch (v) {
        .load_prop, .load_param, .load_const, .bin_op, .unary_op => true,
        else => false,
    };
}

fn allBindingsSideEffectFree(bindings: []const ANFBinding) bool {
    for (bindings) |b| {
        if (!isSideEffectFree(b.value)) return false;
    }
    return true;
}

/// Extract the update_prop target from a branch's last binding.
/// Returns null if the branch doesn't end with a simple update_prop.
const BranchUpdate = struct {
    prop_name: []const u8,
    value_bindings: []const ANFBinding,
    value_ref: []const u8,
};

fn extractBranchUpdate(bindings: []const ANFBinding) ?BranchUpdate {
    if (bindings.len == 0) return null;
    const last = bindings[bindings.len - 1];
    switch (last.value) {
        .update_prop => |up| {
            const value_bindings = bindings[0 .. bindings.len - 1];
            if (!allBindingsSideEffectFree(value_bindings)) return null;
            return .{
                .prop_name = up.name,
                .value_bindings = value_bindings,
                .value_ref = up.value,
            };
        },
        else => return null,
    }
}

/// Check if an else branch is just `assert(false)` — unreachable dead code.
fn isAssertFalseElse(bindings: []const ANFBinding) bool {
    if (bindings.len == 0) return false;
    const last = bindings[bindings.len - 1];
    const assert_ref = switch (last.value) {
        .assert => |a| a.value,
        else => return false,
    };
    for (bindings) |b| {
        if (std.mem.eql(u8, b.name, assert_ref)) {
            switch (b.value) {
                .load_const => |lc| switch (lc.value) {
                    .boolean => |bv| return !bv,
                    else => return false,
                },
                else => return false,
            }
        }
    }
    return false;
}

/// Recursively collect update branches from a nested if-else chain.
/// Returns null if the chain cannot be flattened.
fn collectUpdateBranches(
    allocator: Allocator,
    if_cond: []const u8,
    then_bindings: []const ANFBinding,
    else_bindings: []const ANFBinding,
) LowerError!?[]UpdateBranch {
    const then_update = extractBranchUpdate(then_bindings) orelse return null;

    var branches: std.ArrayListUnmanaged(UpdateBranch) = .empty;
    try branches.append(allocator, .{
        .cond_setup_bindings = &.{},
        .cond_ref = if_cond,
        .prop_name = then_update.prop_name,
        .value_bindings = then_update.value_bindings,
        .value_ref = then_update.value_ref,
    });

    if (else_bindings.len == 0) {
        branches.deinit(allocator);
        return null;
    }

    // Check if else is another if (else-if chain)
    const last_else = else_bindings[else_bindings.len - 1];
    switch (last_else.value) {
        .@"if" => |inner_if| {
            const cond_setup = else_bindings[0 .. else_bindings.len - 1];
            if (!allBindingsSideEffectFree(cond_setup)) {
                branches.deinit(allocator);
                return null;
            }

            const inner_maybe = try collectUpdateBranches(
                allocator,
                inner_if.cond,
                inner_if.then,
                inner_if.@"else",
            );
            const inner = inner_maybe orelse {
                branches.deinit(allocator);
                return null;
            };

            // Prepend condition setup to first inner branch
            const merged = try allocator.alloc(ANFBinding, cond_setup.len + inner[0].cond_setup_bindings.len);
            @memcpy(merged[0..cond_setup.len], cond_setup);
            @memcpy(merged[cond_setup.len..], inner[0].cond_setup_bindings);
            inner[0].cond_setup_bindings = merged;

            try branches.appendSlice(allocator, inner);
            return try branches.toOwnedSlice(allocator);
        },
        else => {},
    }

    // Otherwise, else branch should end with update_prop (final else)
    if (extractBranchUpdate(else_bindings)) |eu| {
        try branches.append(allocator, .{
            .cond_setup_bindings = &.{},
            .cond_ref = null,
            .prop_name = eu.prop_name,
            .value_bindings = eu.value_bindings,
            .value_ref = eu.value_ref,
        });
        return try branches.toOwnedSlice(allocator);
    }

    // Handle unreachable else: assert(false)
    if (isAssertFalseElse(else_bindings)) {
        return try branches.toOwnedSlice(allocator);
    }

    branches.deinit(allocator);
    return null;
}

/// Remap temp references in an ANF value according to a name mapping.
fn remapValueRefs(
    allocator: Allocator,
    value: ANFValue,
    name_map: *const std.StringHashMapUnmanaged([]const u8),
) LowerError!ANFValue {
    const r = struct {
        fn f(nm: *const std.StringHashMapUnmanaged([]const u8), s: []const u8) []const u8 {
            if (nm.get(s)) |mapped| return mapped;
            return s;
        }
    }.f;

    switch (value) {
        .load_param, .load_prop, .get_state_script => return value,
        .load_const => |lc| {
            switch (lc.value) {
                .string => |s| {
                    if (s.len > 5 and std.mem.startsWith(u8, s, "@ref:")) {
                        const target = s[5..];
                        if (name_map.get(target)) |mapped| {
                            const new_s = try std.fmt.allocPrint(allocator, "@ref:{s}", .{mapped});
                            return .{ .load_const = .{ .value = .{ .string = new_s } } };
                        }
                    }
                },
                else => {},
            }
            return value;
        },
        .bin_op => |bop| {
            return .{ .bin_op = .{
                .op = bop.op,
                .left = r(name_map, bop.left),
                .right = r(name_map, bop.right),
                .result_type = bop.result_type,
            } };
        },
        .unary_op => |uop| {
            return .{ .unary_op = .{
                .op = uop.op,
                .operand = r(name_map, uop.operand),
                .result_type = uop.result_type,
            } };
        },
        .call => |c| {
            const new_args = try allocator.alloc([]const u8, c.args.len);
            for (c.args, 0..) |a, i| new_args[i] = r(name_map, a);
            return .{ .call = .{ .func = c.func, .args = new_args } };
        },
        .method_call => |mc| {
            const new_args = try allocator.alloc([]const u8, mc.args.len);
            for (mc.args, 0..) |a, i| new_args[i] = r(name_map, a);
            return .{ .method_call = .{
                .object = r(name_map, mc.object),
                .method = mc.method,
                .args = new_args,
            } };
        },
        .assert => |a| {
            return .{ .assert = .{ .value = r(name_map, a.value) } };
        },
        .update_prop => |up| {
            return .{ .update_prop = .{ .name = up.name, .value = r(name_map, up.value) } };
        },
        .check_preimage => |cp| {
            return .{ .check_preimage = .{ .preimage = r(name_map, cp.preimage) } };
        },
        .deserialize_state => |ds| {
            return .{ .deserialize_state = .{ .preimage = r(name_map, ds.preimage) } };
        },
        .add_output => |ao| {
            const new_sv = try allocator.alloc([]const u8, ao.state_values.len);
            for (ao.state_values, 0..) |s, i| new_sv[i] = r(name_map, s);
            const new_sr = try allocator.alloc([]const u8, ao.state_refs.len);
            for (ao.state_refs, 0..) |s, i| new_sr[i] = r(name_map, s);
            return .{ .add_output = .{
                .satoshis = r(name_map, ao.satoshis),
                .state_values = new_sv,
                .preimage = if (ao.preimage.len > 0) r(name_map, ao.preimage) else ao.preimage,
                .state_refs = new_sr,
            } };
        },
        .add_raw_output => |aro| {
            return .{ .add_raw_output = .{
                .satoshis = r(name_map, aro.satoshis),
                .script_bytes = if (aro.script_bytes.len > 0) r(name_map, aro.script_bytes) else aro.script_bytes,
            } };
        },
        .@"if" => |ifv| {
            const new_if = try allocator.create(types.ANFIf);
            new_if.* = .{
                .cond = r(name_map, ifv.cond),
                .then = ifv.then,
                .@"else" = ifv.@"else",
            };
            return .{ .@"if" = new_if };
        },
        else => return value,
    }
}

/// Transform if-bindings whose branches all end with update_prop into
/// flat conditional assignments.
fn liftBranchUpdateProps(
    allocator: Allocator,
    bindings: []const ANFBinding,
) LowerError![]ANFBinding {
    var next_idx: i64 = maxTempIndex(bindings) + 1;
    const FreshCtx = struct {
        allocator: Allocator,
        next_idx: *i64,
        fn fresh(self: @This()) LowerError![]const u8 {
            const name = try std.fmt.allocPrint(self.allocator, "t{d}", .{self.next_idx.*});
            self.next_idx.* += 1;
            return name;
        }
    };
    const fctx = FreshCtx{ .allocator = allocator, .next_idx = &next_idx };

    var result: std.ArrayListUnmanaged(ANFBinding) = .empty;

    for (bindings) |binding| {
        const if_val = switch (binding.value) {
            .@"if" => |v| v,
            else => {
                try result.append(allocator, binding);
                continue;
            },
        };

        const branches_maybe = try collectUpdateBranches(
            allocator,
            if_val.cond,
            if_val.then,
            if_val.@"else",
        );
        const branches = branches_maybe orelse {
            try result.append(allocator, binding);
            continue;
        };
        if (branches.len < 2) {
            try result.append(allocator, binding);
            continue;
        }

        // --- Transform: flatten into conditional assignments ---

        // 1. Hoist condition setup bindings with fresh names.
        var name_map: std.StringHashMapUnmanaged([]const u8) = .empty;
        defer name_map.deinit(allocator);

        var cond_refs: std.ArrayListUnmanaged(?[]const u8) = .empty;
        defer cond_refs.deinit(allocator);

        for (branches) |branch| {
            for (branch.cond_setup_bindings) |csb| {
                const new_name = try fctx.fresh();
                try name_map.put(allocator, csb.name, new_name);
                const remapped = try remapValueRefs(allocator, csb.value, &name_map);
                try result.append(allocator, .{
                    .name = new_name,
                    .value = remapped,
                });
            }
            if (branch.cond_ref) |cr| {
                const mapped: []const u8 = if (name_map.get(cr)) |m| m else cr;
                try cond_refs.append(allocator, mapped);
            } else {
                try cond_refs.append(allocator, null);
            }
        }

        // 2. Compute effective condition for each branch.
        var effective_conds: std.ArrayListUnmanaged([]const u8) = .empty;
        defer effective_conds.deinit(allocator);

        var negated_conds: std.ArrayListUnmanaged([]const u8) = .empty;
        defer negated_conds.deinit(allocator);

        for (branches, 0..) |_, i| {
            if (i == 0) {
                try effective_conds.append(allocator, cond_refs.items[0].?);
                continue;
            }

            // Negate any prior conditions not yet negated.
            var j: usize = negated_conds.items.len;
            while (j < i) : (j += 1) {
                const cr = cond_refs.items[j] orelse continue;
                const neg_name = try fctx.fresh();
                try result.append(allocator, .{
                    .name = neg_name,
                    .value = .{ .unary_op = .{ .op = "!", .operand = cr } },
                });
                try negated_conds.append(allocator, neg_name);
            }

            // AND all negated conditions together.
            var and_ref: []const u8 = negated_conds.items[0];
            const limit = if (negated_conds.items.len < i) negated_conds.items.len else i;
            var k: usize = 1;
            while (k < limit) : (k += 1) {
                const and_name = try fctx.fresh();
                try result.append(allocator, .{
                    .name = and_name,
                    .value = .{ .bin_op = .{
                        .op = "&&",
                        .left = and_ref,
                        .right = negated_conds.items[k],
                        .result_type = null,
                    } },
                });
                and_ref = and_name;
            }

            if (cond_refs.items[i]) |cr| {
                // Middle branch: AND with own condition.
                const final_name = try fctx.fresh();
                try result.append(allocator, .{
                    .name = final_name,
                    .value = .{ .bin_op = .{
                        .op = "&&",
                        .left = and_ref,
                        .right = cr,
                        .result_type = null,
                    } },
                });
                try effective_conds.append(allocator, final_name);
            } else {
                // Final else: just the AND of negations.
                try effective_conds.append(allocator, and_ref);
            }
        }

        // 3. For each branch, emit: load_old, conditional if-expression, update_prop.
        for (branches, 0..) |branch, i| {
            // Load old property value.
            const old_prop_ref = try fctx.fresh();
            try result.append(allocator, .{
                .name = old_prop_ref,
                .value = .{ .load_prop = .{ .name = branch.prop_name } },
            });

            // Remap value bindings for the then-branch.
            var branch_map: std.StringHashMapUnmanaged([]const u8) = .empty;
            defer branch_map.deinit(allocator);
            var map_it = name_map.iterator();
            while (map_it.next()) |entry| {
                try branch_map.put(allocator, entry.key_ptr.*, entry.value_ptr.*);
            }

            var then_bindings: std.ArrayListUnmanaged(ANFBinding) = .empty;
            for (branch.value_bindings) |vb| {
                const new_name = try fctx.fresh();
                try branch_map.put(allocator, vb.name, new_name);
                const remapped = try remapValueRefs(allocator, vb.value, &branch_map);
                try then_bindings.append(allocator, .{
                    .name = new_name,
                    .value = remapped,
                });
            }

            // Else branch: keep old property value.
            const keep_name = try fctx.fresh();
            var else_bindings_list: std.ArrayListUnmanaged(ANFBinding) = .empty;
            try else_bindings_list.append(allocator, .{
                .name = keep_name,
                .value = .{ .load_const = .{ .value = .{
                    .string = try std.fmt.allocPrint(allocator, "@ref:{s}", .{old_prop_ref}),
                } } },
            });

            // Emit conditional if-expression.
            const cond_if_ref = try fctx.fresh();
            const new_if = try allocator.create(types.ANFIf);
            new_if.* = .{
                .cond = effective_conds.items[i],
                .then = try then_bindings.toOwnedSlice(allocator),
                .@"else" = try else_bindings_list.toOwnedSlice(allocator),
            };
            try result.append(allocator, .{
                .name = cond_if_ref,
                .value = .{ .@"if" = new_if },
            });

            // Emit update_prop.
            const update_name = try fctx.fresh();
            try result.append(allocator, .{
                .name = update_name,
                .value = .{ .update_prop = .{
                    .name = branch.prop_name,
                    .value = cond_if_ref,
                } },
            });
        }
    }

    return try result.toOwnedSlice(allocator);
}

// ============================================================================
// Tests
// ============================================================================

test "fresh temp names are sequential" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, .{
        .name = "Test",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });

    const t0 = try ctx.freshTemp();
    defer allocator.free(t0);
    const t1 = try ctx.freshTemp();
    defer allocator.free(t1);
    const t2 = try ctx.freshTemp();
    defer allocator.free(t2);

    try std.testing.expectEqualStrings("t0", t0);
    try std.testing.expectEqualStrings("t1", t1);
    try std.testing.expectEqualStrings("t2", t2);
    try std.testing.expectEqual(@as(u32, 3), ctx.counter);
}

test "emit produces binding with correct name" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, .{
        .name = "Test",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });

    const ref = try ctx.emit(makeLoadConstInt(42));
    defer allocator.free(ref);
    defer ctx.bindings.deinit(allocator);

    try std.testing.expectEqualStrings("t0", ref);
    try std.testing.expectEqual(@as(usize, 1), ctx.bindings.items.len);
    try std.testing.expectEqualStrings("t0", ctx.bindings.items[0].name);
}

test "lower literal int expression" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, .{
        .name = "Test",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });
    defer ctx.bindings.deinit(allocator);

    const ref = try lowerExprToRef(&ctx, .{ .literal_int = 99 });
    defer allocator.free(ref);

    try std.testing.expectEqualStrings("t0", ref);
    try std.testing.expectEqual(@as(usize, 1), ctx.bindings.items.len);

    // Verify it's a load_const integer
    switch (ctx.bindings.items[0].value) {
        .load_const => |lc| {
            switch (lc.value) {
                .integer => |v| try std.testing.expectEqual(@as(i128, 99), v),
                else => return error.TestExpectedEqual,
            }
        },
        else => return error.TestExpectedEqual,
    }
}

test "lower binary expression flattens subexpressions" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, .{
        .name = "Test",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });
    defer {
        for (ctx.bindings.items) |b| {
            switch (b.value) {
                .load_const, .bin_op => {},
                else => {},
            }
            allocator.free(b.name);
        }
        ctx.bindings.deinit(allocator);
    }

    // 1 + 2 should produce: t0 = load_const(1), t1 = load_const(2), t2 = bin_op(+, t0, t1)
    const bop = try allocator.create(types.BinaryOp);
    defer allocator.destroy(bop);
    bop.* = .{
        .op = .add,
        .left = .{ .literal_int = 1 },
        .right = .{ .literal_int = 2 },
    };

    const ref = try lowerExprToRef(&ctx, .{ .binary_op = bop });
    _ = ref;

    try std.testing.expectEqual(@as(usize, 3), ctx.bindings.items.len);
    try std.testing.expectEqualStrings("t0", ctx.bindings.items[0].name);
    try std.testing.expectEqualStrings("t1", ctx.bindings.items[1].name);
    try std.testing.expectEqualStrings("t2", ctx.bindings.items[2].name);

    // Verify the bin_op references t0 and t1
    switch (ctx.bindings.items[2].value) {
        .bin_op => |op| {
            try std.testing.expectEqualStrings("+", op.op);
            try std.testing.expectEqualStrings("t0", op.left);
            try std.testing.expectEqualStrings("t1", op.right);
        },
        else => return error.TestExpectedEqual,
    }
}

test "lower identifier as parameter" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, .{
        .name = "Test",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });
    defer {
        for (ctx.bindings.items) |b| allocator.free(b.name);
        ctx.bindings.deinit(allocator);
    }

    // An unknown identifier is treated as a parameter
    const ref = try lowerExprToRef(&ctx, .{ .identifier = "pubKey" });
    _ = ref;

    try std.testing.expectEqual(@as(usize, 1), ctx.bindings.items.len);
    switch (ctx.bindings.items[0].value) {
        .load_param => |lp| try std.testing.expectEqualStrings("pubKey", lp.name),
        else => return error.TestExpectedEqual,
    }
}

test "lower property access" {
    const allocator = std.testing.allocator;

    const props = try allocator.alloc(PropertyNode, 1);
    defer allocator.free(props);
    props[0] = .{ .name = "pubKeyHash", .type_info = .ripemd160, .readonly = true };

    var ctx = LowerCtx.init(allocator, .{
        .name = "P2PKH",
        .parent_class = .smart_contract,
        .properties = props,
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });
    defer {
        for (ctx.bindings.items) |b| allocator.free(b.name);
        ctx.bindings.deinit(allocator);
    }

    // this.pubKeyHash -> load_prop
    const ref = try lowerExprToRef(&ctx, .{ .property_access = .{ .object = "this", .property = "pubKeyHash" } });
    _ = ref;

    try std.testing.expectEqual(@as(usize, 1), ctx.bindings.items.len);
    switch (ctx.bindings.items[0].value) {
        .load_prop => |lp| try std.testing.expectEqualStrings("pubKeyHash", lp.name),
        else => return error.TestExpectedEqual,
    }
}

test "lower assert expression" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, .{
        .name = "Test",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });
    defer {
        for (ctx.bindings.items) |b| allocator.free(b.name);
        ctx.bindings.deinit(allocator);
    }

    // assert(true) -> t0 = load_const(true), t1 = assert(t0)
    const assert_args = try allocator.alloc(Expression, 1);
    defer allocator.free(assert_args);
    assert_args[0] = .{ .literal_bool = true };

    const call = try allocator.create(types.CallExpr);
    defer allocator.destroy(call);
    call.* = .{ .callee = "assert", .args = assert_args };

    const ref = try lowerExprToRef(&ctx, .{ .call = call });
    _ = ref;

    try std.testing.expectEqual(@as(usize, 2), ctx.bindings.items.len);
    // First binding: load_const(true)
    switch (ctx.bindings.items[0].value) {
        .load_const => |lc| {
            switch (lc.value) {
                .boolean => |v| try std.testing.expect(v),
                else => return error.TestExpectedEqual,
            }
        },
        else => return error.TestExpectedEqual,
    }
    // Second binding: assert(t0)
    switch (ctx.bindings.items[1].value) {
        .assert => |a| try std.testing.expectEqualStrings("t0", a.value),
        else => return error.TestExpectedEqual,
    }
}

test "P2PKH contract full lowering" {
    const allocator = std.testing.allocator;

    // Build a P2PKH contract AST:
    //   contract P2PKH extends SmartContract {
    //     readonly pubKeyHash: Addr;
    //     constructor(pubKeyHash: Addr) { super(pubKeyHash); }
    //     public unlock(sig: Sig, pubKey: PubKey) {
    //       assert(hash160(pubKey) === this.pubKeyHash);
    //       assert(checkSig(sig, pubKey));
    //     }
    //   }

    // Properties
    const props = try allocator.alloc(PropertyNode, 1);
    defer allocator.free(props);
    props[0] = .{ .name = "pubKeyHash", .type_info = .ripemd160, .readonly = true };

    // Constructor
    const ctor_params = try allocator.alloc(ParamNode, 1);
    defer allocator.free(ctor_params);
    ctor_params[0] = .{ .name = "pubKeyHash", .type_info = .ripemd160, .type_name = "Addr" };

    const ctor_assignments = try allocator.alloc(types.AssignmentNode, 1);
    defer allocator.free(ctor_assignments);
    ctor_assignments[0] = .{ .target = "pubKeyHash", .value = .{ .identifier = "pubKeyHash" } };

    // Method body: two assert statements
    // Statement 1: assert(hash160(pubKey) === this.pubKeyHash)
    const hash_args = try allocator.alloc(Expression, 1);
    defer allocator.free(hash_args);
    hash_args[0] = .{ .identifier = "pubKey" };
    const hash_call = try allocator.create(types.CallExpr);
    defer allocator.destroy(hash_call);
    hash_call.* = .{ .callee = "hash160", .args = hash_args };

    const eq_op = try allocator.create(types.BinaryOp);
    defer allocator.destroy(eq_op);
    eq_op.* = .{
        .op = .eq,
        .left = .{ .call = hash_call },
        .right = .{ .property_access = .{ .object = "this", .property = "pubKeyHash" } },
    };

    const assert1_args = try allocator.alloc(Expression, 1);
    defer allocator.free(assert1_args);
    assert1_args[0] = .{ .binary_op = eq_op };
    const assert1_call = try allocator.create(types.CallExpr);
    defer allocator.destroy(assert1_call);
    assert1_call.* = .{ .callee = "assert", .args = assert1_args };

    // Statement 2: assert(checkSig(sig, pubKey))
    const check_args = try allocator.alloc(Expression, 2);
    defer allocator.free(check_args);
    check_args[0] = .{ .identifier = "sig" };
    check_args[1] = .{ .identifier = "pubKey" };
    const check_call = try allocator.create(types.CallExpr);
    defer allocator.destroy(check_call);
    check_call.* = .{ .callee = "checkSig", .args = check_args };

    const assert2_args = try allocator.alloc(Expression, 1);
    defer allocator.free(assert2_args);
    assert2_args[0] = .{ .call = check_call };
    const assert2_call = try allocator.create(types.CallExpr);
    defer allocator.destroy(assert2_call);
    assert2_call.* = .{ .callee = "assert", .args = assert2_args };

    // Build method body as statement slice
    const body = try allocator.alloc(Statement, 2);
    defer allocator.free(body);
    body[0] = .{ .expr_stmt = .{ .call = assert1_call } };
    body[1] = .{ .expr_stmt = .{ .call = assert2_call } };

    // Method params
    const method_params = try allocator.alloc(ParamNode, 2);
    defer allocator.free(method_params);
    method_params[0] = .{ .name = "sig", .type_info = .sig, .type_name = "Sig" };
    method_params[1] = .{ .name = "pubKey", .type_info = .pub_key, .type_name = "PubKey" };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = method_params, .body = body };

    const contract = ContractNode{
        .name = "P2PKH",
        .parent_class = .smart_contract,
        .properties = props,
        .constructor = .{ .params = ctor_params, .super_args = &.{}, .assignments = ctor_assignments },
        .methods = methods,
    };

    const program = try lowerToANF(allocator, contract);

    // Free all allocated temp names and nested structures
    defer {
        for (program.methods) |m| {
            for (m.bindings) |b| {
                // Free temp names (t0, t1, ...) and @ref: strings
                if (b.name.len >= 2 and b.name[0] == 't') {
                    allocator.free(b.name);
                }
                // Free nested allocations in values
                switch (b.value) {
                    .load_const => |lc| {
                        switch (lc.value) {
                            .string => |s| {
                                if (s.len > 5 and std.mem.startsWith(u8, s, "@ref:")) {
                                    allocator.free(s);
                                }
                            },
                            else => {},
                        }
                    },
                    .call => |c| {
                        if (c.args.len > 0) allocator.free(c.args);
                    },
                    else => {},
                }
            }
            if (m.bindings.len > 0) allocator.free(m.bindings);
        }
        allocator.free(program.methods);
        allocator.free(program.properties);
    }

    // Validate structure
    try std.testing.expectEqualStrings("P2PKH", program.contract_name);
    try std.testing.expectEqual(@as(usize, 1), program.properties.len);
    try std.testing.expectEqualStrings("pubKeyHash", program.properties[0].name);
    try std.testing.expect(program.properties[0].readonly);

    // Should have 2 methods: constructor + unlock
    try std.testing.expectEqual(@as(usize, 2), program.methods.len);
    try std.testing.expectEqualStrings("constructor", program.methods[0].name);
    try std.testing.expectEqualStrings("unlock", program.methods[1].name);
    try std.testing.expect(program.methods[1].is_public);

    // Constructor should have 1 assignment binding (update_prop)
    const ctor_bindings = program.methods[0].bindings;
    try std.testing.expect(ctor_bindings.len >= 1);

    // Unlock method body should have bindings for the P2PKH logic:
    //   t0 = load_param("pubKey")
    //   t1 = call("hash160", [t0])
    //   t2 = load_prop("pubKeyHash")
    //   t3 = bin_op("===", t1, t2, result_type="bytes")
    //   t4 = assert(t3)
    //   t5 = load_param("sig")
    //   t6 = load_param("pubKey")
    //   t7 = call("checkSig", [t5, t6])
    //   t8 = assert(t7)
    const unlock_bindings = program.methods[1].bindings;
    try std.testing.expect(unlock_bindings.len >= 9);

    // Verify first binding is load_param("pubKey")
    switch (unlock_bindings[0].value) {
        .load_param => |lp| try std.testing.expectEqualStrings("pubKey", lp.name),
        else => return error.TestExpectedEqual,
    }

    // Verify second binding is call("hash160", ...)
    switch (unlock_bindings[1].value) {
        .call => |c| try std.testing.expectEqualStrings("hash160", c.func),
        else => return error.TestExpectedEqual,
    }

    // Verify third binding is load_prop("pubKeyHash")
    switch (unlock_bindings[2].value) {
        .load_prop => |lp| try std.testing.expectEqualStrings("pubKeyHash", lp.name),
        else => return error.TestExpectedEqual,
    }

    // Verify fourth binding is bin_op("===", ...) with bytes result type
    switch (unlock_bindings[3].value) {
        .bin_op => |op| {
            try std.testing.expectEqualStrings("===", op.op);
            try std.testing.expectEqualStrings("t1", op.left);
            try std.testing.expectEqualStrings("t2", op.right);
            if (op.result_type) |rt| {
                try std.testing.expectEqualStrings("bytes", rt);
            } else {
                return error.TestExpectedEqual;
            }
        },
        else => return error.TestExpectedEqual,
    }

    // Verify fifth binding is assert
    switch (unlock_bindings[4].value) {
        .assert => |a| try std.testing.expectEqualStrings("t3", a.value),
        else => return error.TestExpectedEqual,
    }
}

test "sub_context shares counter" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, .{
        .name = "Test",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });

    // Emit a few temps
    const t0 = try ctx.freshTemp();
    defer allocator.free(t0);
    const t1 = try ctx.freshTemp();
    defer allocator.free(t1);

    try std.testing.expectEqual(@as(u32, 2), ctx.counter);

    // Sub-context starts where parent left off
    var sub = ctx.subContext();
    const t2 = try sub.freshTemp();
    defer allocator.free(t2);

    try std.testing.expectEqualStrings("t2", t2);
    try std.testing.expectEqual(@as(u32, 3), sub.counter);

    // Sync back
    ctx.syncCounter(&sub);
    try std.testing.expectEqual(@as(u32, 3), ctx.counter);
}

test "extractLiteralValue handles all literal types" {
    // Integer
    const int_val = extractLiteralValue(.{ .literal_int = 42 });
    try std.testing.expect(int_val != null);
    switch (int_val.?) {
        .integer => |v| try std.testing.expectEqual(@as(i128, 42), v),
        else => return error.TestExpectedEqual,
    }

    // Boolean
    const bool_val = extractLiteralValue(.{ .literal_bool = true });
    try std.testing.expect(bool_val != null);
    switch (bool_val.?) {
        .boolean => |v| try std.testing.expect(v),
        else => return error.TestExpectedEqual,
    }

    // Bytes
    const bytes_val = extractLiteralValue(.{ .literal_bytes = "deadbeef" });
    try std.testing.expect(bytes_val != null);
    switch (bytes_val.?) {
        .string => |v| try std.testing.expectEqualStrings("deadbeef", v),
        else => return error.TestExpectedEqual,
    }

    // Unsupported
    const none_val = extractLiteralValue(.{ .identifier = "x" });
    try std.testing.expect(none_val == null);
}

test "isByteReturningFunction" {
    try std.testing.expect(isByteReturningFunction("sha256"));
    try std.testing.expect(isByteReturningFunction("hash160"));
    try std.testing.expect(isByteReturningFunction("ripemd160"));
    try std.testing.expect(isByteReturningFunction("cat"));
    try std.testing.expect(!isByteReturningFunction("checkSig"));
    try std.testing.expect(!isByteReturningFunction("add"));
}

test "isByteType" {
    try std.testing.expect(isByteType(.byte_string));
    try std.testing.expect(isByteType(.pub_key));
    try std.testing.expect(isByteType(.sig));
    try std.testing.expect(isByteType(.ripemd160));
    try std.testing.expect(!isByteType(.bigint));
    try std.testing.expect(!isByteType(.boolean));
}

test "branchEndsWithReturn" {
    // Empty body
    try std.testing.expect(!branchEndsWithReturn(&.{}));

    // Body ending with return
    const stmts_ret = [_]Statement{.{ .return_stmt = .{ .literal_int = 1 } }};
    try std.testing.expect(branchEndsWithReturn(&stmts_ret));

    // Body ending with non-return
    const stmts_no_ret = [_]Statement{.{ .expr_stmt = .{ .literal_int = 1 } }};
    try std.testing.expect(!branchEndsWithReturn(&stmts_no_ret));
}

test "lower properties with initial values" {
    const allocator = std.testing.allocator;

    const props = try allocator.alloc(PropertyNode, 2);
    defer allocator.free(props);
    props[0] = .{ .name = "counter", .type_info = .bigint, .readonly = false, .initializer = .{ .literal_int = 0 } };
    props[1] = .{ .name = "owner", .type_info = .ripemd160, .readonly = true };

    const result = try lowerProperties(allocator, .{
        .name = "Test",
        .parent_class = .stateful_smart_contract,
        .properties = props,
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("counter", result[0].name);
    try std.testing.expect(!result[0].readonly);
    try std.testing.expect(result[0].initial_value != null);
    switch (result[0].initial_value.?) {
        .integer => |v| try std.testing.expectEqual(@as(i128, 0), v),
        else => return error.TestExpectedEqual,
    }
    try std.testing.expectEqualStrings("owner", result[1].name);
    try std.testing.expect(result[1].readonly);
    try std.testing.expect(result[1].initial_value == null);
}
