//! Pass 3b: Expand fixed-size array properties into scalar sibling fields.
//!
//! Zig port of `packages/runar-compiler/src/passes/03b-expand-fixed-arrays.ts`.
//! Runs after typecheck and before ANF lowering. Takes a ContractNode whose
//! properties may contain `FixedArray<T, N>` declarations (represented in the
//! Zig AST as `type_info == .fixed_array` with `fixed_array_length` and
//! `fixed_array_element` populated) and rewrites it so that every downstream
//! pass sees an equivalent contract with N scalar siblings `<name>__0 ..
//! <name>__{N-1}` and all `this.<name>[i]` reads/writes replaced by direct
//! member access (literal index) or if/else dispatch (runtime index).
//!
//! Matches the TypeScript reference pass semantically:
//!   - Literal index: rewrite to direct `<name>__K` property access
//!     (out-of-range literal is a compile error)
//!   - Runtime read in expression context: nested ternary chain, terminal is
//!     the last slot (no bounds check)
//!   - Runtime read in statement context (const x = this.arr[i] or target =
//!     this.arr[i]): statement-form fallback+if-chain
//!   - Runtime write: if/else chain with assert(false) final else
//!   - Nested literal chain: resolved via `tryResolveLiteralIndexChain`
//!   - Nested runtime: compile error
//!
//! Allocation rule: all synthetic AST nodes (statements, expressions,
//! synthetic_array_chain slices) are allocated from the pass's `allocator`,
//! which the caller provides. For the main compile pipeline this is the same
//! arena that owns the AST, so lifetimes are trivially correct.

const std = @import("std");
const types = @import("../ir/types.zig");

const Allocator = std.mem.Allocator;

const ContractNode = types.ContractNode;
const PropertyNode = types.PropertyNode;
const SyntheticArrayLevel = types.SyntheticArrayLevel;
const ConstructorNode = types.ConstructorNode;
const MethodNode = types.MethodNode;
const Statement = types.Statement;
const Expression = types.Expression;
const ConstDecl = types.ConstDecl;
const LetDecl = types.LetDecl;
const Assign = types.Assign;
const IfStmt = types.IfStmt;
const AssertStmt = types.AssertStmt;
const BinaryOp = types.BinaryOp;
const UnaryOp = types.UnaryOp;
const CallExpr = types.CallExpr;
const MethodCall = types.MethodCall;
const Ternary = types.Ternary;
const IndexAccess = types.IndexAccess;
const IncrementExpr = types.IncrementExpr;
const DecrementExpr = types.DecrementExpr;
const PropertyAccess = types.PropertyAccess;
const RunarType = types.RunarType;
const BinOperator = types.BinOperator;
const CompilerDiagnostic = types.CompilerDiagnostic;

pub const ExpandError = error{OutOfMemory};

pub const Result = struct {
    contract: ContractNode,
    errors: []CompilerDiagnostic,
};

/// Expand fixed-array properties in `contract` into scalar siblings, rewriting
/// every `this.<name>[i]` read/write into literal-index or runtime-dispatch
/// form. Pure AST→AST. All synthetic nodes are allocated with `allocator`.
pub fn expand(allocator: Allocator, contract: ContractNode) ExpandError!Result {
    // Early out: no fixed-array properties at all.
    var has_any = false;
    for (contract.properties) |p| {
        if (p.type_info == .fixed_array and p.fixed_array_length > 0) {
            has_any = true;
            break;
        }
    }
    if (!has_any) {
        return .{ .contract = contract, .errors = &.{} };
    }

    var ctx = Ctx{
        .allocator = allocator,
        .errors = .empty,
        .array_map = .empty,
        .synthetic_arrays = .empty,
        .temp_counter = 0,
    };
    defer ctx.array_map.deinit(allocator);
    defer ctx.synthetic_arrays.deinit(allocator);

    try ctx.collectArrays(contract);
    if (ctx.errors.items.len > 0) {
        return .{ .contract = contract, .errors = try ctx.errors.toOwnedSlice(allocator) };
    }

    const new_props = try ctx.rewriteProperties(contract);
    if (ctx.errors.items.len > 0) {
        return .{ .contract = contract, .errors = try ctx.errors.toOwnedSlice(allocator) };
    }

    const new_ctor = try ctx.rewriteConstructor(contract.constructor);
    const new_methods = try allocator.alloc(MethodNode, contract.methods.len);
    for (contract.methods, 0..) |m, i| {
        new_methods[i] = try ctx.rewriteMethod(m);
    }

    if (ctx.errors.items.len > 0) {
        return .{ .contract = contract, .errors = try ctx.errors.toOwnedSlice(allocator) };
    }

    const out = ContractNode{
        .name = contract.name,
        .parent_class = contract.parent_class,
        .properties = new_props,
        .constructor = new_ctor,
        .methods = new_methods,
    };
    return .{ .contract = out, .errors = &.{} };
}

// ============================================================================
// Context & metadata
// ============================================================================

const ArrayMeta = struct {
    root_name: []const u8,
    length: u32,
    element: RunarType,
    slot_names: []const []const u8,
    slot_is_array: bool,
    /// Nested element length (non-zero only for FixedArray<FixedArray<T, M>, N>).
    nested_length: u32,
    /// For nested arrays, per-slot sub-meta keyed by slot name.
    nested: ?std.StringHashMapUnmanaged(*ArrayMeta) = null,
};

const Ctx = struct {
    allocator: Allocator,
    errors: std.ArrayListUnmanaged(CompilerDiagnostic),
    array_map: std.StringHashMapUnmanaged(*ArrayMeta),
    synthetic_arrays: std.StringHashMapUnmanaged(*ArrayMeta),
    temp_counter: u32,

    fn pushError(self: *Ctx, msg: []const u8) !void {
        const dup = try self.allocator.dupe(u8, msg);
        try self.errors.append(self.allocator, .{ .message = dup });
    }

    fn pushErrorFmt(self: *Ctx, comptime fmt: []const u8, args: anytype) !void {
        const msg = try std.fmt.allocPrint(self.allocator, fmt, args);
        try self.errors.append(self.allocator, .{ .message = msg });
    }

    fn freshName(self: *Ctx, comptime tag: []const u8) ![]const u8 {
        const n = self.temp_counter;
        self.temp_counter += 1;
        return try std.fmt.allocPrint(self.allocator, "__{s}_{d}", .{ tag, n });
    }

    // ------------------------------------------------------------------
    // Collect phase
    // ------------------------------------------------------------------

    fn collectArrays(self: *Ctx, contract: ContractNode) !void {
        for (contract.properties) |prop| {
            if (prop.type_info != .fixed_array) continue;
            if (prop.fixed_array_length == 0) continue;
            const meta = try self.buildMetaFromProp(prop);
            if (meta) |m| {
                try self.array_map.put(self.allocator, prop.name, m);
            }
        }
    }

    fn buildMetaFromProp(self: *Ctx, prop: PropertyNode) !?*ArrayMeta {
        if (prop.fixed_array_element == .void) {
            try self.pushErrorFmt(
                "FixedArray element type cannot be 'void' (property '{s}')",
                .{prop.name},
            );
            return null;
        }
        if (prop.fixed_array_length == 0) {
            try self.pushErrorFmt(
                "FixedArray length must be a positive integer (property '{s}')",
                .{prop.name},
            );
            return null;
        }
        return try self.buildMeta(
            prop.name,
            prop.fixed_array_length,
            prop.fixed_array_element,
            prop.fixed_array_nested_length,
        );
    }

    fn buildMeta(
        self: *Ctx,
        root_name: []const u8,
        length: u32,
        element: RunarType,
        nested_length: u32,
    ) !*ArrayMeta {
        const meta = try self.allocator.create(ArrayMeta);
        var slot_names = try self.allocator.alloc([]const u8, length);
        for (0..length) |i| {
            slot_names[i] = try std.fmt.allocPrint(self.allocator, "{s}__{d}", .{ root_name, i });
        }

        const slot_is_array = (element == .fixed_array) and nested_length > 0;
        meta.* = .{
            .root_name = root_name,
            .length = length,
            .element = element,
            .slot_names = slot_names,
            .slot_is_array = slot_is_array,
            .nested_length = nested_length,
            .nested = null,
        };

        if (slot_is_array) {
            var nested_map: std.StringHashMapUnmanaged(*ArrayMeta) = .empty;
            for (slot_names) |slot| {
                // Nested FixedArray: we only support one level of nesting via the
                // parser-level fixed_array_nested_length. Deeper nesting isn't
                // captured at parse time in the current Zig AST; report cleanly
                // if the element is still .fixed_array without a known length.
                const sub = try self.buildMeta(slot, nested_length, .bigint, 0);
                try nested_map.put(self.allocator, slot, sub);
                try self.synthetic_arrays.put(self.allocator, slot, sub);
            }
            meta.nested = nested_map;
        }
        return meta;
    }

    // ------------------------------------------------------------------
    // Property rewrite (initializer distribution)
    // ------------------------------------------------------------------

    fn rewriteProperties(self: *Ctx, contract: ContractNode) ![]PropertyNode {
        var out: std.ArrayListUnmanaged(PropertyNode) = .empty;
        for (contract.properties) |prop| {
            if (prop.type_info != .fixed_array) {
                try out.append(self.allocator, prop);
                continue;
            }
            const meta = self.array_map.get(prop.name) orelse continue;

            // Distribute array literal initializer if present.
            const init_elements = try self.extractArrayLiteral(prop, meta);
            try self.expandMeta(&out, meta, prop.readonly, init_elements, &.{});
        }
        return try out.toOwnedSlice(self.allocator);
    }

    fn extractArrayLiteral(self: *Ctx, prop: PropertyNode, meta: *ArrayMeta) !?[]const Expression {
        if (prop.initializer == null) return null;
        const init_expr = prop.initializer.?;
        switch (init_expr) {
            .array_literal => |elems| {
                if (elems.len != meta.length) {
                    try self.pushErrorFmt(
                        "Initializer length {d} does not match FixedArray length {d} for property '{s}'",
                        .{ elems.len, meta.length, prop.name },
                    );
                    return null;
                }
                return elems;
            },
            else => {
                try self.pushErrorFmt(
                    "Property '{s}' of type FixedArray must use an array literal initializer",
                    .{prop.name},
                );
                return null;
            },
        }
    }

    fn expandMeta(
        self: *Ctx,
        out: *std.ArrayListUnmanaged(PropertyNode),
        meta: *ArrayMeta,
        readonly: bool,
        initializer: ?[]const Expression,
        parent_chain: []const SyntheticArrayLevel,
    ) !void {
        for (meta.slot_names, 0..) |slot, i| {
            const slot_init: ?Expression = if (initializer) |elems| elems[i] else null;

            // Build the chain for this level.
            const chain = try self.allocator.alloc(SyntheticArrayLevel, parent_chain.len + 1);
            @memcpy(chain[0..parent_chain.len], parent_chain);
            chain[parent_chain.len] = .{
                .base = meta.root_name,
                .index = @intCast(i),
                .length = meta.length,
            };

            if (meta.slot_is_array) {
                const sub = meta.nested.?.get(slot).?;
                var sub_init: ?[]const Expression = null;
                if (slot_init) |si| switch (si) {
                    .array_literal => |inner| {
                        if (inner.len != sub.length) {
                            try self.pushErrorFmt(
                                "Nested FixedArray initializer length {d} does not match expected length {d}",
                                .{ inner.len, sub.length },
                            );
                        } else {
                            sub_init = inner;
                        }
                    },
                    else => {
                        try self.pushError("Nested FixedArray element must be an array literal");
                    },
                };
                try self.expandMeta(out, sub, readonly, sub_init, chain);
            } else {
                try out.append(self.allocator, PropertyNode{
                    .name = slot,
                    .type_info = meta.element,
                    .readonly = readonly,
                    .initializer = slot_init,
                    .fixed_array_length = 0,
                    .fixed_array_element = .unknown,
                    .fixed_array_nested_length = 0,
                    .synthetic_array_chain = chain,
                });
            }
        }
    }

    // ------------------------------------------------------------------
    // Method / body rewrite
    // ------------------------------------------------------------------

    fn rewriteConstructor(self: *Ctx, ctor: ConstructorNode) !ConstructorNode {
        // Constructor body is a simple list of assignments. We rewrite the
        // values (in case they involve index accesses, unlikely but cheap)
        // and leave the targets alone. FixedArray properties never appear as
        // constructor assignment targets because they're initializer-only.
        var new_assigns = try self.allocator.alloc(types.AssignmentNode, ctor.assignments.len);
        for (ctor.assignments, 0..) |a, i| {
            new_assigns[i] = .{
                .target = a.target,
                .value = try self.rewriteExpressionSimple(a.value),
            };
        }
        var new_super = try self.allocator.alloc(Expression, ctor.super_args.len);
        for (ctor.super_args, 0..) |sa, i| new_super[i] = try self.rewriteExpressionSimple(sa);
        return .{
            .params = ctor.params,
            .super_args = new_super,
            .assignments = new_assigns,
        };
    }

    fn rewriteMethod(self: *Ctx, method: MethodNode) !MethodNode {
        const new_body = try self.rewriteStatements(method.body);
        return .{
            .name = method.name,
            .is_public = method.is_public,
            .params = method.params,
            .body = new_body,
            .source_loc = method.source_loc,
        };
    }

    fn rewriteStatements(self: *Ctx, stmts: []const Statement) ExpandError![]Statement {
        var out: std.ArrayListUnmanaged(Statement) = .empty;
        for (stmts) |stmt| try self.rewriteStatementInto(&out, stmt);
        return try out.toOwnedSlice(self.allocator);
    }

    fn rewriteStatementInto(self: *Ctx, out: *std.ArrayListUnmanaged(Statement), stmt: Statement) ExpandError!void {
        switch (stmt) {
            .const_decl => |d| {
                if (try self.tryRewriteReadAsStatements(out, d.value, .{ .identifier = d.name }, true, d.type_info)) {
                    return;
                }
                var prelude: std.ArrayListUnmanaged(Statement) = .empty;
                const new_val = try self.rewriteExpression(&prelude, d.value);
                try out.appendSlice(self.allocator, prelude.items);
                try out.append(self.allocator, .{ .const_decl = .{
                    .name = d.name,
                    .type_info = d.type_info,
                    .value = new_val,
                    .source_loc = d.source_loc,
                } });
            },
            .let_decl => |d| {
                if (d.value) |v| {
                    if (try self.tryRewriteReadAsStatements(out, v, .{ .identifier = d.name }, true, d.type_info)) {
                        return;
                    }
                    var prelude: std.ArrayListUnmanaged(Statement) = .empty;
                    const new_val = try self.rewriteExpression(&prelude, v);
                    try out.appendSlice(self.allocator, prelude.items);
                    try out.append(self.allocator, .{ .let_decl = .{
                        .name = d.name,
                        .type_info = d.type_info,
                        .value = new_val,
                        .source_loc = d.source_loc,
                    } });
                } else {
                    try out.append(self.allocator, stmt);
                }
            },
            .assign => |a| {
                try self.rewriteAssign(out, a);
            },
            .if_stmt => |ifs| {
                var prelude: std.ArrayListUnmanaged(Statement) = .empty;
                const new_cond = try self.rewriteExpression(&prelude, ifs.condition);
                try out.appendSlice(self.allocator, prelude.items);
                const new_then = try self.rewriteStatements(ifs.then_body);
                const new_else: ?[]Statement = if (ifs.else_body) |eb| try self.rewriteStatements(eb) else null;
                try out.append(self.allocator, .{ .if_stmt = .{
                    .condition = new_cond,
                    .then_body = new_then,
                    .else_body = new_else,
                    .source_loc = ifs.source_loc,
                } });
            },
            .for_stmt => |fs| {
                const new_body = try self.rewriteStatements(fs.body);
                try out.append(self.allocator, .{ .for_stmt = .{
                    .var_name = fs.var_name,
                    .init_value = fs.init_value,
                    .bound = fs.bound,
                    .body = new_body,
                    .source_loc = fs.source_loc,
                } });
            },
            .expr_stmt => |e| {
                var prelude: std.ArrayListUnmanaged(Statement) = .empty;
                const new_e = try self.rewriteExpression(&prelude, e);
                try out.appendSlice(self.allocator, prelude.items);
                try out.append(self.allocator, .{ .expr_stmt = new_e });
            },
            .assert_stmt => |a| {
                var prelude: std.ArrayListUnmanaged(Statement) = .empty;
                const new_cond = try self.rewriteExpression(&prelude, a.condition);
                try out.appendSlice(self.allocator, prelude.items);
                try out.append(self.allocator, .{ .assert_stmt = .{
                    .condition = new_cond,
                    .message = a.message,
                    .source_loc = a.source_loc,
                } });
            },
            .return_stmt => |maybe| {
                if (maybe) |e| {
                    var prelude: std.ArrayListUnmanaged(Statement) = .empty;
                    const new_e = try self.rewriteExpression(&prelude, e);
                    try out.appendSlice(self.allocator, prelude.items);
                    try out.append(self.allocator, .{ .return_stmt = new_e });
                } else {
                    try out.append(self.allocator, stmt);
                }
            },
        }
    }

    fn rewriteAssign(
        self: *Ctx,
        out: *std.ArrayListUnmanaged(Statement),
        a: Assign,
    ) !void {
        // Case 1: index-target assignment — `this.arr[idx] = value`.
        if (a.index_target) |ia_ptr| {
            try self.rewriteIndexAssign(out, ia_ptr.*, a.value, a.source_loc);
            return;
        }

        // Case 2: whole-array reassignment. Not allowed outside initializers.
        if (self.array_map.contains(a.target)) {
            try self.pushErrorFmt(
                "cannot reassign entire FixedArray property '{s}' (only element writes are supported)",
                .{a.target},
            );
            return;
        }

        // Case 3: plain property or local assignment. Rewrite RHS and keep.
        var prelude: std.ArrayListUnmanaged(Statement) = .empty;
        const new_val = try self.rewriteExpression(&prelude, a.value);
        try out.appendSlice(self.allocator, prelude.items);
        try out.append(self.allocator, .{ .assign = .{
            .target = a.target,
            .value = new_val,
            .source_loc = a.source_loc,
        } });
    }

    fn rewriteIndexAssign(
        self: *Ctx,
        out: *std.ArrayListUnmanaged(Statement),
        ia: IndexAccess,
        value: Expression,
        source_loc: ?types.SourceLocation,
    ) !void {
        // Try the nested literal chain first — writes `this.grid[0][1] = v`
        // resolve to a single `grid__0__1 = v` assignment.
        const chain = try self.tryResolveLiteralIndexChain(ia);
        switch (chain) {
            .ok => |name| {
                var prelude: std.ArrayListUnmanaged(Statement) = .empty;
                const new_val = try self.rewriteExpression(&prelude, value);
                try out.appendSlice(self.allocator, prelude.items);
                try out.append(self.allocator, .{ .assign = .{
                    .target = name,
                    .value = new_val,
                    .source_loc = source_loc,
                } });
                return;
            },
            .out_of_range => return,
            .not_applicable => {},
        }

        const base_name = self.tryResolveArrayBase(ia.object) orelse {
            // Not a fixed-array property — leave untouched. This shouldn't
            // happen in practice because the parser only emits index_target
            // for `this.x[...]` shapes, but be defensive.
            return;
        };
        const meta = self.array_map.get(base_name) orelse self.synthetic_arrays.get(base_name).?;

        var prelude: std.ArrayListUnmanaged(Statement) = .empty;
        const new_val = try self.rewriteExpression(&prelude, value);
        const new_idx = try self.rewriteExpression(&prelude, ia.index);

        // Literal index — direct assignment.
        if (asLiteralIndex(new_idx)) |lit| {
            if (lit < 0 or lit >= meta.length) {
                try self.pushErrorFmt(
                    "Index {d} is out of range for FixedArray of length {d}",
                    .{ lit, meta.length },
                );
                return;
            }
            if (meta.slot_is_array) {
                try self.pushError("Cannot assign to a nested FixedArray sub-array as a whole");
                return;
            }
            try out.appendSlice(self.allocator, prelude.items);
            try out.append(self.allocator, .{ .assign = .{
                .target = meta.slot_names[@intCast(lit)],
                .value = new_val,
                .source_loc = source_loc,
            } });
            return;
        }

        if (meta.slot_is_array) {
            try self.pushError("Runtime index assignment on a nested FixedArray is not supported");
            return;
        }

        // Runtime index — dispatch if-chain with assert(false) terminator.
        const idx_ref = try self.hoistIfImpure(&prelude, new_idx, "idx");
        const val_ref = try self.hoistIfImpure(&prelude, new_val, "val");
        try out.appendSlice(self.allocator, prelude.items);
        const dispatch = try self.buildWriteDispatchIf(meta, idx_ref, val_ref);
        try out.append(self.allocator, dispatch);
    }

    // ------------------------------------------------------------------
    // Expression rewrite
    // ------------------------------------------------------------------

    /// Simpler form used outside of statement contexts — no statement-form
    /// hoisting. Mostly used for constructor args and super-call args.
    fn rewriteExpressionSimple(self: *Ctx, expr: Expression) ExpandError!Expression {
        var prelude: std.ArrayListUnmanaged(Statement) = .empty;
        return try self.rewriteExpression(&prelude, expr);
    }

    fn rewriteExpression(
        self: *Ctx,
        prelude: *std.ArrayListUnmanaged(Statement),
        expr: Expression,
    ) ExpandError!Expression {
        switch (expr) {
            .index_access => |ia| return try self.rewriteIndexAccess(prelude, ia.*),
            .binary_op => |bo| {
                // parse_ts models `x = y` as an expression-level BinaryOp with op == eq?
                // No — TS parser translates assignments to statement-level Assign.
                // So we only need to recurse.
                const new_bo = try self.allocator.create(BinaryOp);
                new_bo.* = .{
                    .op = bo.op,
                    .left = try self.rewriteExpression(prelude, bo.left),
                    .right = try self.rewriteExpression(prelude, bo.right),
                };
                return .{ .binary_op = new_bo };
            },
            .unary_op => |uo| {
                const new_uo = try self.allocator.create(UnaryOp);
                new_uo.* = .{
                    .op = uo.op,
                    .operand = try self.rewriteExpression(prelude, uo.operand),
                };
                return .{ .unary_op = new_uo };
            },
            .call => |ce| {
                var new_args = try self.allocator.alloc(Expression, ce.args.len);
                for (ce.args, 0..) |arg, i| new_args[i] = try self.rewriteExpression(prelude, arg);
                const new_call = try self.allocator.create(CallExpr);
                new_call.* = .{ .callee = ce.callee, .args = new_args };
                return .{ .call = new_call };
            },
            .method_call => |mc| {
                var new_args = try self.allocator.alloc(Expression, mc.args.len);
                for (mc.args, 0..) |arg, i| new_args[i] = try self.rewriteExpression(prelude, arg);
                const new_mc = try self.allocator.create(MethodCall);
                new_mc.* = .{ .object = mc.object, .method = mc.method, .args = new_args };
                return .{ .method_call = new_mc };
            },
            .ternary => |t| {
                const new_t = try self.allocator.create(Ternary);
                new_t.* = .{
                    .condition = try self.rewriteExpression(prelude, t.condition),
                    .then_expr = try self.rewriteExpression(prelude, t.then_expr),
                    .else_expr = try self.rewriteExpression(prelude, t.else_expr),
                };
                return .{ .ternary = new_t };
            },
            .array_literal => |elems| {
                var new_elems = try self.allocator.alloc(Expression, elems.len);
                for (elems, 0..) |e, i| new_elems[i] = try self.rewriteExpression(prelude, e);
                return .{ .array_literal = new_elems };
            },
            .increment => |iv| {
                const new_iv = try self.allocator.create(IncrementExpr);
                new_iv.* = .{ .operand = try self.rewriteExpression(prelude, iv.operand), .prefix = iv.prefix };
                return .{ .increment = new_iv };
            },
            .decrement => |dv| {
                const new_dv = try self.allocator.create(DecrementExpr);
                new_dv.* = .{ .operand = try self.rewriteExpression(prelude, dv.operand), .prefix = dv.prefix };
                return .{ .decrement = new_dv };
            },
            else => return expr,
        }
    }

    /// Rewrite `this.<arr>[idx]` as a read. If the object is not a known array
    /// property, recurse into sub-expressions unchanged.
    fn rewriteIndexAccess(
        self: *Ctx,
        prelude: *std.ArrayListUnmanaged(Statement),
        ia: IndexAccess,
    ) ExpandError!Expression {
        // Try to resolve a fully-literal chain like `this.grid[0][1]` to
        // the flat synthetic leaf name `grid__0__1`.
        const literal_chain = try self.tryResolveLiteralIndexChain(ia);
        switch (literal_chain) {
            .ok => |name| return .{ .property_access = .{ .object = "this", .property = name } },
            .out_of_range => return .{ .literal_int = 0 },
            .not_applicable => {},
        }

        // Single-level base.
        const base_name = self.tryResolveArrayBase(ia.object);
        if (base_name == null) {
            // Not a fixed-array property; recurse.
            const new_obj = try self.rewriteExpression(prelude, ia.object);
            const new_idx = try self.rewriteExpression(prelude, ia.index);
            const new_ia = try self.allocator.create(IndexAccess);
            new_ia.* = .{ .object = new_obj, .index = new_idx };
            return .{ .index_access = new_ia };
        }

        const meta = self.array_map.get(base_name.?) orelse self.synthetic_arrays.get(base_name.?).?;

        if (asLiteralIndex(ia.index)) |lit| {
            if (lit < 0 or lit >= meta.length) {
                try self.pushErrorFmt(
                    "Index {d} is out of range for FixedArray of length {d}",
                    .{ lit, meta.length },
                );
                return .{ .literal_int = 0 };
            }
            return .{ .property_access = .{ .object = "this", .property = meta.slot_names[@intCast(lit)] } };
        }

        // Runtime index — nested arrays not supported here.
        if (meta.slot_is_array) {
            try self.pushError("Runtime index access on a nested FixedArray is not supported");
            return .{ .literal_int = 0 };
        }

        const rewritten_idx = try self.rewriteExpression(prelude, ia.index);
        const idx_ref = try self.hoistIfImpure(prelude, rewritten_idx, "idx");
        return try self.buildReadDispatchTernary(meta, idx_ref);
    }

    /// Statement-form dispatch for `const v = this.board[i]` and `v = this.board[i]`.
    /// Emits prelude + a `let v = board__{N-1}` fallback + if-chain into `out`.
    /// Returns true if the rewrite applied; false if the caller should fall
    /// back to the expression form.
    fn tryRewriteReadAsStatements(
        self: *Ctx,
        out: *std.ArrayListUnmanaged(Statement),
        init_expr: Expression,
        target: Expression,
        is_decl: bool,
        decl_type: ?RunarType,
    ) !bool {
        if (init_expr != .index_access) return false;
        const ia = init_expr.index_access.*;
        const base_name = self.tryResolveArrayBase(ia.object) orelse return false;
        const meta = self.array_map.get(base_name) orelse self.synthetic_arrays.get(base_name) orelse return false;
        if (asLiteralIndex(ia.index) != null) return false;
        if (meta.slot_is_array) return false;

        var prelude: std.ArrayListUnmanaged(Statement) = .empty;
        const rewritten_idx = try self.rewriteExpression(&prelude, ia.index);
        const idx_ref = try self.hoistIfImpure(&prelude, rewritten_idx, "idx");

        try out.appendSlice(self.allocator, prelude.items);

        const n = meta.length;
        const fallback = Expression{ .property_access = .{ .object = "this", .property = meta.slot_names[n - 1] } };

        // Emit the fallback declaration / assignment.
        switch (target) {
            .identifier => |tname| {
                if (is_decl) {
                    // `let v = board__{N-1}` — Zig Assign can't take a property_access
                    // target, and let_decl is the declaration shape. The binding must
                    // be mutable for subsequent dispatch assignments to be legal.
                    try out.append(self.allocator, .{ .let_decl = .{
                        .name = tname,
                        .type_info = decl_type,
                        .value = fallback,
                    } });
                } else {
                    try out.append(self.allocator, .{ .assign = .{ .target = tname, .value = fallback } });
                }
            },
            .property_access => {
                // property-target statement-form is not representable as a
                // Zig Assign (which is name-only). Fall back to expression form.
                return false;
            },
            else => return false,
        }

        // Build a tail-recursive if-chain for i = N-2 down to 0.
        if (n >= 2) {
            var i: usize = n - 1;
            var tail_else: ?[]Statement = null;
            while (i > 0) {
                i -= 1;
                const slot = meta.slot_names[i];
                const cond = try self.makeIdxEq(idx_ref, @intCast(i));
                const assign_stmt = try self.makeTargetAssign(target, .{ .property_access = .{ .object = "this", .property = slot } });
                const then_body = try self.allocator.alloc(Statement, 1);
                then_body[0] = assign_stmt;
                const if_stmt = types.IfStmt{
                    .condition = cond,
                    .then_body = then_body,
                    .else_body = tail_else,
                };
                const wrapped = try self.allocator.alloc(Statement, 1);
                wrapped[0] = .{ .if_stmt = if_stmt };
                tail_else = wrapped;
            }
            if (tail_else) |te| try out.appendSlice(self.allocator, te);
        }

        return true;
    }

    fn makeIdxEq(self: *Ctx, idx_ref: Expression, lit: i64) !Expression {
        const bo = try self.allocator.create(BinaryOp);
        bo.* = .{ .op = .eq, .left = try self.cloneExpr(idx_ref), .right = .{ .literal_int = lit } };
        return .{ .binary_op = bo };
    }

    fn makeTargetAssign(self: *Ctx, target: Expression, value: Expression) !Statement {
        switch (target) {
            .identifier => |name| return .{ .assign = .{ .target = name, .value = value } },
            .property_access => |pa| return .{ .assign = .{ .target = pa.property, .value = value } },
            else => {
                try self.pushError("unsupported assignment target in FixedArray rewrite");
                return .{ .expr_stmt = .{ .literal_int = 0 } };
            },
        }
    }

    fn buildReadDispatchTernary(
        self: *Ctx,
        meta: *ArrayMeta,
        idx_ref: Expression,
    ) ExpandError!Expression {
        // Tail: last slot.
        var chain: Expression = .{ .property_access = .{ .object = "this", .property = meta.slot_names[meta.length - 1] } };
        if (meta.length < 2) return chain;
        var i: usize = meta.length - 1;
        while (i > 0) {
            i -= 1;
            const slot = meta.slot_names[i];
            const cond = try self.makeIdxEq(idx_ref, @intCast(i));
            const branch: Expression = .{ .property_access = .{ .object = "this", .property = slot } };
            const t = try self.allocator.create(Ternary);
            t.* = .{
                .condition = cond,
                .then_expr = branch,
                .else_expr = chain,
            };
            chain = .{ .ternary = t };
        }
        return chain;
    }

    /// Rewrite `this.board[expr] = v` into a cascaded if/else chain with a
    /// final `assert(false)`. The parser places these writes in a context we
    /// must recognise — in the Zig AST they appear as an `expr_stmt`
    /// containing a BinaryOp? Or via a dedicated Assign? Look at parse_ts
    /// behaviour for the exact shape.
    fn buildWriteDispatchIf(
        self: *Ctx,
        meta: *ArrayMeta,
        idx_ref: Expression,
        val_ref: Expression,
    ) !Statement {
        // Build from tail toward head.
        const assert_false_stmt = Statement{ .assert_stmt = .{
            .condition = .{ .literal_bool = false },
            .message = null,
        } };
        var tail = try self.allocator.alloc(Statement, 1);
        tail[0] = assert_false_stmt;
        var i: usize = meta.length;
        while (i > 0) {
            i -= 1;
            const slot = meta.slot_names[i];
            const cond = try self.makeIdxEq(idx_ref, @intCast(i));
            const branch_assign = Statement{ .assign = .{
                .target = slot,
                .value = try self.cloneExpr(val_ref),
            } };
            const then_body = try self.allocator.alloc(Statement, 1);
            then_body[0] = branch_assign;
            const if_stmt = types.IfStmt{
                .condition = cond,
                .then_body = then_body,
                .else_body = tail,
            };
            const wrapped = try self.allocator.alloc(Statement, 1);
            wrapped[0] = .{ .if_stmt = if_stmt };
            tail = wrapped;
        }
        return tail[0];
    }

    // ------------------------------------------------------------------
    // Chain resolution (nested literal index chains)
    // ------------------------------------------------------------------

    const ChainResult = union(enum) {
        ok: []const u8,
        out_of_range,
        not_applicable,
    };

    fn tryResolveLiteralIndexChain(self: *Ctx, ia: IndexAccess) !ChainResult {
        // Walk inward, collecting literal indices innermost first.
        var literals: std.ArrayListUnmanaged(i64) = .empty;
        defer literals.deinit(self.allocator);

        var cursor: Expression = .{ .index_access = blk: {
            const p = try self.allocator.create(IndexAccess);
            p.* = ia;
            break :blk p;
        } };
        while (cursor == .index_access) {
            const inner = cursor.index_access.*;
            const lit = asLiteralIndex(inner.index) orelse return .not_applicable;
            try literals.append(self.allocator, lit);
            cursor = inner.object;
        }
        if (cursor != .property_access) return .not_applicable;
        const pa = cursor.property_access;
        if (!std.mem.eql(u8, pa.object, "this")) return .not_applicable;
        const root_meta = self.array_map.get(pa.property) orelse return .not_applicable;

        // Reverse to outermost-first.
        std.mem.reverse(i64, literals.items);

        var meta: *ArrayMeta = root_meta;
        var level: usize = 0;
        while (level < literals.items.len) : (level += 1) {
            const idx = literals.items[level];
            if (idx < 0 or idx >= meta.length) {
                try self.pushErrorFmt(
                    "Index {d} is out of range for FixedArray of length {d}",
                    .{ idx, meta.length },
                );
                return .out_of_range;
            }
            const slot = meta.slot_names[@intCast(idx)];
            if (level == literals.items.len - 1) {
                if (meta.slot_is_array) return .not_applicable;
                return .{ .ok = slot };
            }
            if (!meta.slot_is_array) return .not_applicable;
            meta = meta.nested.?.get(slot).?;
        }
        return .not_applicable;
    }

    fn tryResolveArrayBase(self: *Ctx, obj: Expression) ?[]const u8 {
        if (obj == .property_access) {
            const pa = obj.property_access;
            if (self.array_map.contains(pa.property)) return pa.property;
            if (self.synthetic_arrays.contains(pa.property)) return pa.property;
        }
        return null;
    }

    fn hoistIfImpure(
        self: *Ctx,
        prelude: *std.ArrayListUnmanaged(Statement),
        expr: Expression,
        comptime tag: []const u8,
    ) !Expression {
        if (isPureReference(expr)) return expr;
        const name = try self.freshName(tag);
        try prelude.append(self.allocator, .{ .const_decl = .{
            .name = name,
            .type_info = null,
            .value = expr,
        } });
        return .{ .identifier = name };
    }

    fn cloneExpr(self: *Ctx, expr: Expression) ExpandError!Expression {
        switch (expr) {
            .literal_int, .literal_bool, .literal_bytes, .identifier, .property_access => return expr,
            .binary_op => |bo| {
                const new_bo = try self.allocator.create(BinaryOp);
                new_bo.* = .{
                    .op = bo.op,
                    .left = try self.cloneExpr(bo.left),
                    .right = try self.cloneExpr(bo.right),
                };
                return .{ .binary_op = new_bo };
            },
            .unary_op => |uo| {
                const new_uo = try self.allocator.create(UnaryOp);
                new_uo.* = .{ .op = uo.op, .operand = try self.cloneExpr(uo.operand) };
                return .{ .unary_op = new_uo };
            },
            .call => |ce| {
                var new_args = try self.allocator.alloc(Expression, ce.args.len);
                for (ce.args, 0..) |a, i| new_args[i] = try self.cloneExpr(a);
                const new_call = try self.allocator.create(CallExpr);
                new_call.* = .{ .callee = ce.callee, .args = new_args };
                return .{ .call = new_call };
            },
            .method_call => |mc| {
                var new_args = try self.allocator.alloc(Expression, mc.args.len);
                for (mc.args, 0..) |a, i| new_args[i] = try self.cloneExpr(a);
                const new_mc = try self.allocator.create(MethodCall);
                new_mc.* = .{ .object = mc.object, .method = mc.method, .args = new_args };
                return .{ .method_call = new_mc };
            },
            .ternary => |t| {
                const new_t = try self.allocator.create(Ternary);
                new_t.* = .{
                    .condition = try self.cloneExpr(t.condition),
                    .then_expr = try self.cloneExpr(t.then_expr),
                    .else_expr = try self.cloneExpr(t.else_expr),
                };
                return .{ .ternary = new_t };
            },
            .index_access => |ia| {
                const new_ia = try self.allocator.create(IndexAccess);
                new_ia.* = .{
                    .object = try self.cloneExpr(ia.object),
                    .index = try self.cloneExpr(ia.index),
                };
                return .{ .index_access = new_ia };
            },
            .increment => |iv| {
                const new_iv = try self.allocator.create(IncrementExpr);
                new_iv.* = .{ .operand = try self.cloneExpr(iv.operand), .prefix = iv.prefix };
                return .{ .increment = new_iv };
            },
            .decrement => |dv| {
                const new_dv = try self.allocator.create(DecrementExpr);
                new_dv.* = .{ .operand = try self.cloneExpr(dv.operand), .prefix = dv.prefix };
                return .{ .decrement = new_dv };
            },
            .array_literal => |elems| {
                var new_elems = try self.allocator.alloc(Expression, elems.len);
                for (elems, 0..) |e, i| new_elems[i] = try self.cloneExpr(e);
                return .{ .array_literal = new_elems };
            },
        }
    }
};

// ============================================================================
// Stateless helpers
// ============================================================================

fn asLiteralIndex(expr: Expression) ?i64 {
    switch (expr) {
        .literal_int => |v| return v,
        .unary_op => |uo| {
            if (uo.op == .negate and uo.operand == .literal_int) return -uo.operand.literal_int;
        },
        else => {},
    }
    return null;
}

fn isPureReference(expr: Expression) bool {
    return switch (expr) {
        .literal_int, .literal_bool, .literal_bytes, .identifier, .property_access => true,
        .unary_op => |uo| uo.op == .negate and uo.operand == .literal_int,
        else => false,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "expand no-op when no fixed arrays" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var props = [_]PropertyNode{
        .{ .name = "count", .type_info = .bigint, .readonly = false },
    };
    const ctor = ConstructorNode{ .params = &.{}, .super_args = &.{}, .assignments = &.{} };
    const contract = ContractNode{
        .name = "Test",
        .parent_class = .stateful_smart_contract,
        .properties = &props,
        .constructor = ctor,
        .methods = &.{},
    };
    const result = try expand(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), result.errors.len);
    try std.testing.expectEqual(@as(usize, 1), result.contract.properties.len);
}

test "expand flat FixedArray<bigint, 3>" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var props = [_]PropertyNode{
        .{
            .name = "board",
            .type_info = .fixed_array,
            .readonly = false,
            .fixed_array_length = 3,
            .fixed_array_element = .bigint,
        },
    };
    const ctor = ConstructorNode{ .params = &.{}, .super_args = &.{}, .assignments = &.{} };
    const contract = ContractNode{
        .name = "T",
        .parent_class = .stateful_smart_contract,
        .properties = &props,
        .constructor = ctor,
        .methods = &.{},
    };
    const result = try expand(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), result.errors.len);
    try std.testing.expectEqual(@as(usize, 3), result.contract.properties.len);
    try std.testing.expectEqualStrings("board__0", result.contract.properties[0].name);
    try std.testing.expectEqualStrings("board__1", result.contract.properties[1].name);
    try std.testing.expectEqualStrings("board__2", result.contract.properties[2].name);
    try std.testing.expect(result.contract.properties[0].synthetic_array_chain != null);
    try std.testing.expectEqual(@as(usize, 1), result.contract.properties[0].synthetic_array_chain.?.len);
    try std.testing.expectEqual(@as(u32, 0), result.contract.properties[0].synthetic_array_chain.?[0].index);
    try std.testing.expectEqual(@as(u32, 3), result.contract.properties[0].synthetic_array_chain.?[0].length);
}

test "expand FixedArray<void, N> is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var props = [_]PropertyNode{
        .{
            .name = "x",
            .type_info = .fixed_array,
            .readonly = false,
            .fixed_array_length = 3,
            .fixed_array_element = .void,
        },
    };
    const ctor = ConstructorNode{ .params = &.{}, .super_args = &.{}, .assignments = &.{} };
    const contract = ContractNode{
        .name = "T",
        .parent_class = .stateful_smart_contract,
        .properties = &props,
        .constructor = ctor,
        .methods = &.{},
    };
    const result = try expand(alloc, contract);
    try std.testing.expect(result.errors.len > 0);
}

test "expand literal initializer distributes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const elems = try alloc.alloc(Expression, 3);
    elems[0] = .{ .literal_int = 10 };
    elems[1] = .{ .literal_int = 20 };
    elems[2] = .{ .literal_int = 30 };

    var props = [_]PropertyNode{
        .{
            .name = "scores",
            .type_info = .fixed_array,
            .readonly = false,
            .initializer = .{ .array_literal = elems },
            .fixed_array_length = 3,
            .fixed_array_element = .bigint,
        },
    };
    const ctor = ConstructorNode{ .params = &.{}, .super_args = &.{}, .assignments = &.{} };
    const contract = ContractNode{
        .name = "T",
        .parent_class = .stateful_smart_contract,
        .properties = &props,
        .constructor = ctor,
        .methods = &.{},
    };
    const result = try expand(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), result.errors.len);
    try std.testing.expectEqual(@as(usize, 3), result.contract.properties.len);
    try std.testing.expectEqual(@as(i64, 10), result.contract.properties[0].initializer.?.literal_int);
    try std.testing.expectEqual(@as(i64, 20), result.contract.properties[1].initializer.?.literal_int);
    try std.testing.expectEqual(@as(i64, 30), result.contract.properties[2].initializer.?.literal_int);
}
