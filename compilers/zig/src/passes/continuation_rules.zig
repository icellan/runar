//! #199 (warning) and D18 (error): where a StatefulSmartContract's satoshis
//! can go. Port of packages/runar-compiler/src/passes/continuation-rules.ts
//! (see its header for the full rationale). Both rules read the transitive
//! continuation predicates anf_lower.zig injects the continuation from
//! (`methodMutatesState`, `methodHasAddOutput` = addOutput OR addRawOutput,
//! `methodHasAddDataOutput`). anf_lower.zig is wire-format gated, so the one
//! new predicate -- calls addOutput itself -- lives here, mirroring
//! anf_lower's `exprHasIntrinsicCallRec` callee matching exactly (a
//! method_call on `this` / `self` / a StatefulContext parameter; bareword and
//! receiver calls to a private helper are followed, each helper once, within
//! MAX_CALL_DEPTH hops, breadth first).

const std = @import("std");
const types = @import("../ir/types.zig");
const anf_lower = @import("anf_lower.zig");
const input_limits = @import("../frontend/input_limits.zig");

const Allocator = std.mem.Allocator;
const ContractNode = types.ContractNode;
const MethodNode = types.MethodNode;
const ParamNode = types.ParamNode;
const Expression = types.Expression;
const Statement = types.Statement;
const CompilerDiagnostic = types.CompilerDiagnostic;

/// #199: the shared warning text (contract name twice).
pub const RELEASE_TRAP_FMT =
    "contract '{s}' has no terminal method and no public method that calls " ++
    "addOutput/addRawOutput; its satoshis can never leave instances of '{s}'";

/// D18: the shared error text (method name).
pub const DROPPED_CONTINUATION_FMT =
    "method '{s}' writes contract state but emits no state continuation: it calls " ++
    "addRawOutput() without addOutput(), and a method that declares its own outputs gets no " ++
    "auto-injected continuation, so the state write would be lost and the contract's satoshis " ++
    "would leave with the spend. Add this.addOutput(satoshis, ...) to carry the new state, or " ++
    "stop writing state in a method meant to end the contract";

const MAX_DEPTH: u32 = @intCast(input_limits.MAX_CALL_DEPTH);

const Pending = struct { stmts: []const Statement, params: []const ParamNode, depth: u32 };

const Walk = struct {
    allocator: Allocator,
    contract: ContractNode,
    depth: u32 = 0,
    pending: std.ArrayListUnmanaged(Pending) = .empty,
    visited: std.StringHashMapUnmanaged(void) = .empty,

    fn enqueue(w: *Walk, name: []const u8) void {
        if (w.depth + 1 > MAX_DEPTH) return;
        for (w.contract.methods) |m| {
            if (m.is_public or !std.mem.eql(u8, m.name, name)) continue;
            const gop = w.visited.getOrPut(w.allocator, m.name) catch @panic("out of memory");
            if (gop.found_existing) return;
            w.pending.append(w.allocator, .{ .stmts = m.body, .params = m.params, .depth = w.depth + 1 }) catch @panic("out of memory");
            return;
        }
    }

    fn body(w: *Walk, stmts: []const Statement, params: []const ParamNode) bool {
        for (stmts) |s| if (w.stmt(s, params)) return true;
        return false;
    }

    fn stmt(w: *Walk, s: Statement, params: []const ParamNode) bool {
        return switch (s) {
            .expr_stmt => |e| w.expr(e.expr, params),
            .const_decl => |cd| w.expr(cd.value, params),
            .let_decl => |ld| if (ld.value) |v| w.expr(v, params) else false,
            .assign => |as_| w.expr(as_.value, params),
            .assert_stmt => |as_s| w.expr(as_s.condition, params),
            .if_stmt => |if_s| w.expr(if_s.condition, params) or w.body(if_s.then_body, params) or
                (if (if_s.else_body) |eb| w.body(eb, params) else false),
            .for_stmt => |for_s| w.body(for_s.body, params),
            .return_stmt => |r| if (r.value) |v| w.expr(v, params) else false,
        };
    }

    fn expr(w: *Walk, e: Expression, params: []const ParamNode) bool {
        switch (e) {
            .method_call => |mc| {
                if (std.mem.eql(u8, mc.object, "this") or std.mem.eql(u8, mc.object, "self") or isStatefulContext(params, mc.object)) {
                    if (std.mem.eql(u8, mc.method, "addOutput")) return true;
                    w.enqueue(mc.method);
                }
                for (mc.args) |arg| if (w.expr(arg, params)) return true;
            },
            .call => |call| {
                w.enqueue(call.callee);
                for (call.args) |arg| if (w.expr(arg, params)) return true;
            },
            .binary_op => |bin| return w.expr(bin.left, params) or w.expr(bin.right, params),
            .unary_op => |un| return w.expr(un.operand, params),
            .ternary => |t| return w.expr(t.condition, params) or w.expr(t.then_expr, params) or w.expr(t.else_expr, params),
            .index_access => |idx| return w.expr(idx.object, params) or w.expr(idx.index, params),
            .array_literal => |elems| {
                for (elems) |el| if (w.expr(el, params)) return true;
            },
            else => {},
        }
        return false;
    }
};

fn isStatefulContext(params: []const ParamNode, name: []const u8) bool {
    for (params) |p| {
        if (std.mem.eql(u8, p.name, name) and std.mem.eql(u8, p.type_name, "StatefulContext")) return true;
    }
    return false;
}

/// Calls this.addOutput(...) itself, directly or through a private helper.
pub fn methodCallsAddOutput(method: MethodNode, contract: ContractNode) bool {
    var fallback = std.heap.stackFallback(4096, std.heap.page_allocator);
    var w: Walk = .{ .allocator = fallback.get(), .contract = contract };
    defer {
        w.pending.deinit(w.allocator);
        w.visited.deinit(w.allocator);
    }
    w.pending.append(w.allocator, .{ .stmts = method.body, .params = method.params, .depth = 0 }) catch @panic("out of memory");
    var next: usize = 0;
    while (next < w.pending.items.len) : (next += 1) {
        const p = w.pending.items[next];
        w.depth = p.depth;
        if (w.body(p.stmts, p.params)) return true;
    }
    return false;
}

/// `this.p[i]...` rooted at a mutable property `p` (at least one index_access).
fn isMutableElement(target: Expression, contract: ContractNode) bool {
    if (target != .index_access) return false;
    var node = target;
    while (node == .index_access) node = node.index_access.object;
    if (node != .property_access) return false;
    for (contract.properties) |p| {
        if (!p.readonly and std.mem.eql(u8, p.name, node.property_access.property)) return true;
    }
    return false;
}

/// Element-increment walk. Same descent and private-helper following as
/// anf_lower's `methodMutatesState` (bareword and any-receiver method calls to
/// a private helper, each helper once, within MAX_CALL_DEPTH hops, breadth
/// first; ++/-- not descended into).
const ElementWalk = struct {
    allocator: Allocator,
    contract: ContractNode,
    depth: u32 = 0,
    pending: std.ArrayListUnmanaged(Pending) = .empty,
    visited: std.StringHashMapUnmanaged(void) = .empty,

    fn enqueue(w: *ElementWalk, name: []const u8) void {
        if (w.depth + 1 > MAX_DEPTH) return;
        for (w.contract.methods) |m| {
            if (m.is_public or !std.mem.eql(u8, m.name, name)) continue;
            const gop = w.visited.getOrPut(w.allocator, m.name) catch @panic("out of memory");
            if (gop.found_existing) return;
            w.pending.append(w.allocator, .{ .stmts = m.body, .params = m.params, .depth = w.depth + 1 }) catch @panic("out of memory");
            return;
        }
    }

    fn body(w: *ElementWalk, stmts: []const Statement) bool {
        for (stmts) |s| if (w.stmt(s)) return true;
        return false;
    }

    fn stmt(w: *ElementWalk, s: Statement) bool {
        return switch (s) {
            .expr_stmt => |e| w.expr(e.expr),
            .const_decl => |cd| w.expr(cd.value),
            .let_decl => |ld| if (ld.value) |v| w.expr(v) else false,
            .assign => |as_| w.expr(as_.value),
            .assert_stmt => |as_s| w.expr(as_s.condition),
            .if_stmt => |if_s| w.expr(if_s.condition) or w.body(if_s.then_body) or
                (if (if_s.else_body) |eb| w.body(eb) else false),
            .for_stmt => |for_s| w.body(for_s.body),
            .return_stmt => |r| if (r.value) |v| w.expr(v) else false,
        };
    }

    fn expr(w: *ElementWalk, e: Expression) bool {
        switch (e) {
            .increment => |inc| return isMutableElement(inc.operand, w.contract),
            .decrement => |dec| return isMutableElement(dec.operand, w.contract),
            .call => |call| {
                w.enqueue(call.callee);
                for (call.args) |arg| if (w.expr(arg)) return true;
            },
            .method_call => |mc| {
                w.enqueue(mc.method);
                for (mc.args) |arg| if (w.expr(arg)) return true;
            },
            .binary_op => |bin| return w.expr(bin.left) or w.expr(bin.right),
            .unary_op => |un| return w.expr(un.operand),
            .ternary => |t| return w.expr(t.condition) or w.expr(t.then_expr) or w.expr(t.else_expr),
            .index_access => |idx| return w.expr(idx.object) or w.expr(idx.index),
            .array_literal => |elems| {
                for (elems) |el| if (w.expr(el)) return true;
            },
            else => {},
        }
        return false;
    }
};

/// `this.arr[i]++` / `this.arr[i]--` on a mutable property, directly or
/// through a private helper. Both rules run before FixedArray expansion, where
/// such an increment's operand is still an index_access that anf_lower's
/// `methodMutatesState` (built for the expanded contract) does not count.
/// Element ASSIGNMENTS need no help: their `Assign.target` is already the
/// base property name with `target_is_property` set, which that walk counts.
fn incrementsMutableElement(method: MethodNode, contract: ContractNode) bool {
    var fallback = std.heap.stackFallback(4096, std.heap.page_allocator);
    var w: ElementWalk = .{ .allocator = fallback.get(), .contract = contract };
    defer {
        w.pending.deinit(w.allocator);
        w.visited.deinit(w.allocator);
    }
    w.pending.append(w.allocator, .{ .stmts = method.body, .params = method.params, .depth = 0 }) catch @panic("out of memory");
    var next: usize = 0;
    while (next < w.pending.items.len) : (next += 1) {
        const p = w.pending.items[next];
        w.depth = p.depth;
        if (w.body(p.stmts)) return true;
    }
    return false;
}

/// methodMutatesState as the two rules need it on the unexpanded contract.
pub fn mutatesState(method: MethodNode, contract: ContractNode) bool {
    return anf_lower.methodMutatesState(method, contract) or incrementsMutableElement(method, contract);
}

/// D18: the method writes state and only raw outputs replace its continuation.
pub fn dropsContinuation(method: MethodNode, contract: ContractNode) bool {
    return mutatesState(method, contract) and
        anf_lower.methodHasAddOutput(method, contract) and
        !methodCallsAddOutput(method, contract);
}

/// #199: the contract-level warning, when it applies (stateful contracts only).
/// Contract-level: no source location. The message is allocated.
pub fn releaseTrapWarning(allocator: Allocator, contract: ContractNode) !?CompilerDiagnostic {
    if (contract.parent_class != .stateful_smart_contract) return null;
    var publics: usize = 0;
    for (contract.methods) |m| {
        if (!m.is_public) continue;
        publics += 1;
        const state_out = anf_lower.methodHasAddOutput(m, contract);
        // Not terminal (needsChange) and no declared state/raw output.
        const needs_change = mutatesState(m, contract) or state_out or
            anf_lower.methodHasAddDataOutput(m, contract);
        if (!needs_change or state_out) return null;
    }
    if (publics == 0) return null;
    const msg = try std.fmt.allocPrint(allocator, RELEASE_TRAP_FMT, .{ contract.name, contract.name });
    return .{ .message = msg, .owned_message = true, .severity = .warning };
}
