//! #199 (warning) and D18 (error): where a StatefulSmartContract's satoshis
//! can go. Port of packages/runar-compiler/src/passes/continuation-rules.ts
//! (see its header for the full rationale). Both rules read the transitive
//! continuation predicates anf_lower.zig injects the continuation from
//! (`methodMutatesState`, `methodHasAddOutput` = addOutput OR addRawOutput,
//! `methodHasAddDataOutput`). anf_lower.zig is wire-format gated, so D18's
//! per-path analysis (`Paths` below) lives here. Its addOutput match mirrors
//! anf_lower's `exprHasIntrinsicCallRec` (a method_call on `this` / `self` /
//! a StatefulContext parameter); private helpers resolve by name, bareword or
//! any receiver, as `methodMutatesState` follows them.

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
    "method '{s}' writes contract state on a path that reaches no addOutput(): a method " ++
    "that declares its own outputs (addOutput/addRawOutput) gets no auto-injected continuation, " ++
    "so on that path the state write would be lost and the contract's satoshis would leave with " ++
    "the spend. Add this.addOutput(satoshis, ...) on every path that writes state, or stop " ++
    "writing state on a path meant to end the contract";

const MAX_DEPTH: u32 = @intCast(input_limits.MAX_CALL_DEPTH);

const Pending = struct { stmts: []const Statement, params: []const ParamNode, depth: u32 };

fn isStatefulContext(params: []const ParamNode, name: []const u8) bool {
    for (params) |p| {
        if (std.mem.eql(u8, p.name, name) and std.mem.eql(u8, p.type_name, "StatefulContext")) return true;
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

// ---------------------------------------------------------------------------
// D18, per path
// ---------------------------------------------------------------------------
//
// A path state is two bits, W (state written) and A (addOutput reached); a
// set of the four possible states is a u4 mask (bit x set iff state x is
// live). Every call in an expression runs; `if` unions its arms; a loop
// unions skipping it; a private helper call composes the caller's states
// with the helper's exit states (fallthrough + return).

pub const W: u2 = 1;
pub const A: u2 = 2;
/// The single fresh path {0}.
pub const ZERO: u4 = 1;

/// Every live state `x` becomes `x | bits`.
pub fn orAll(states: u4, bits: u2) u4 {
    var out: u4 = 0;
    for (0..4) |x| {
        if ((states >> @intCast(x)) & 1 != 0) out |= @as(u4, 1) << (@as(u2, @intCast(x)) | bits);
    }
    return out;
}

/// {x | y : x in states, y in exits}.
pub fn compose(states: u4, exits: u4) u4 {
    var out: u4 = 0;
    for (0..4) |y| {
        if ((exits >> @intCast(y)) & 1 != 0) out |= orAll(states, @intCast(y));
    }
    return out;
}

/// Some path wrote state (W) and reached no addOutput (not A): state 1.
pub fn droppedState(states: u4) bool {
    return states & (@as(u4, 1) << W) != 0;
}

const Flow = struct { live: u4, returned: u4 };

const Paths = struct {
    allocator: Allocator,
    contract: ContractNode,
    exits: std.StringHashMapUnmanaged(u4) = .empty,
    /// Set while collecting the helpers a body calls whose exits are unknown.
    missing: ?*std.ArrayListUnmanaged(MethodNode) = null,

    fn lookupPrivate(p: *Paths, name: []const u8) ?MethodNode {
        for (p.contract.methods) |m| {
            if (!m.is_public and std.mem.eql(u8, m.name, name)) return m;
        }
        return null;
    }

    fn isMutable(p: *Paths, name: []const u8) bool {
        for (p.contract.properties) |prop| {
            if (!prop.readonly and std.mem.eql(u8, prop.name, name)) return true;
        }
        return false;
    }

    /// `this.p` or `this.p[i]...` on a mutable property `p`.
    fn writesMutable(p: *Paths, target: Expression) bool {
        var node = target;
        while (node == .index_access) node = node.index_access.object;
        return node == .property_access and p.isMutable(node.property_access.property);
    }

    /// Exit states (fallthrough and return) of a body entered with a fresh path.
    fn bodyExits(p: *Paths, body: []const Statement, params: []const ParamNode) u4 {
        const f = p.stmts(body, params, ZERO);
        return f.live | f.returned;
    }

    fn stmts(p: *Paths, list: []const Statement, params: []const ParamNode, states: u4) Flow {
        var live = states;
        var returned: u4 = 0;
        for (list) |st| {
            if (live == 0) break;
            const f = p.stmt(st, params, live);
            returned |= f.returned;
            live = f.live;
        }
        return .{ .live = live, .returned = returned };
    }

    fn stmt(p: *Paths, st: Statement, params: []const ParamNode, states: u4) Flow {
        switch (st) {
            .assign => |as_| {
                var s = states;
                // `target` is the bare base name; an element write keeps its
                // index chain in `index_target`.
                if (as_.index_target) |it| s = p.expr(it.index, params, p.expr(it.object, params, s));
                s = p.expr(as_.value, params, s);
                if (as_.target_is_property and p.isMutable(as_.target)) s = orAll(s, W);
                return .{ .live = s, .returned = 0 };
            },
            .expr_stmt => |e| return .{ .live = p.expr(e.expr, params, states), .returned = 0 },
            .const_decl => |cd| return .{ .live = p.expr(cd.value, params, states), .returned = 0 },
            .let_decl => |ld| return .{ .live = if (ld.value) |v| p.expr(v, params, states) else states, .returned = 0 },
            .assert_stmt => |as_s| return .{ .live = p.expr(as_s.condition, params, states), .returned = 0 },
            .return_stmt => |r| return .{ .live = 0, .returned = if (r.value) |v| p.expr(v, params, states) else states },
            .if_stmt => |if_s| {
                const c = p.expr(if_s.condition, params, states);
                const t = p.stmts(if_s.then_body, params, c);
                const e: Flow = if (if_s.else_body) |eb| p.stmts(eb, params, c) else .{ .live = c, .returned = 0 };
                return .{ .live = t.live | e.live, .returned = t.returned | e.returned };
            },
            // The header's init / bound are integers: nothing to walk there.
            .for_stmt => |for_s| {
                const b = p.stmts(for_s.body, params, states);
                const u: Flow = if (for_s.update) |up| p.stmt(up.*, params, b.live) else .{ .live = b.live, .returned = 0 };
                return .{ .live = states | u.live, .returned = b.returned | u.returned };
            },
        }
    }

    fn helper(p: *Paths, m: MethodNode, states: u4) u4 {
        const ex = p.exits.get(m.name) orelse blk: {
            if (p.missing) |list| list.append(p.allocator, m) catch @panic("out of memory");
            break :blk ZERO;
        };
        return compose(states, ex);
    }

    fn expr(p: *Paths, e: Expression, params: []const ParamNode, states: u4) u4 {
        switch (e) {
            .increment => |inc| {
                const s = p.expr(inc.operand, params, states);
                return if (p.writesMutable(inc.operand)) orAll(s, W) else s;
            },
            .decrement => |dec| {
                const s = p.expr(dec.operand, params, states);
                return if (p.writesMutable(dec.operand)) orAll(s, W) else s;
            },
            .call => |call| {
                var s = states;
                for (call.args) |arg| s = p.expr(arg, params, s);
                if (p.lookupPrivate(call.callee)) |m| return p.helper(m, s);
                return s;
            },
            .method_call => |mc| {
                var s = states;
                for (mc.args) |arg| s = p.expr(arg, params, s);
                if (std.mem.eql(u8, mc.method, "addOutput") and
                    (std.mem.eql(u8, mc.object, "this") or std.mem.eql(u8, mc.object, "self") or isStatefulContext(params, mc.object)))
                {
                    return orAll(s, A);
                }
                if (p.lookupPrivate(mc.method)) |m| return p.helper(m, s);
                return s;
            },
            .binary_op => |bin| return p.expr(bin.right, params, p.expr(bin.left, params, states)),
            .unary_op => |un| return p.expr(un.operand, params, states),
            .ternary => |t| {
                const c = p.expr(t.condition, params, states);
                return p.expr(t.then_expr, params, c) | p.expr(t.else_expr, params, c);
            },
            .index_access => |idx| return p.expr(idx.index, params, p.expr(idx.object, params, states)),
            .array_literal => |elems| {
                var s = states;
                for (elems) |el| s = p.expr(el, params, s);
                return s;
            },
            else => return states,
        }
    }

    /// The private helpers `body` calls whose exits are not computed yet.
    fn unresolved(p: *Paths, body: []const Statement, params: []const ParamNode) []const MethodNode {
        var list: std.ArrayListUnmanaged(MethodNode) = .empty;
        p.missing = &list;
        defer p.missing = null;
        _ = p.bodyExits(body, params);
        return list.items;
    }

    /// Compute the exits of every helper reachable from `body`, bottom-up by an
    /// explicit post-order over the call graph (N-264: no host recursion across
    /// helper chains). A helper on the open path (a cycle; the validator refuses
    /// recursion) stays unresolved and contributes {0}.
    fn prepare(p: *Paths, body: []const Statement, params: []const ParamNode) void {
        const Frame = struct { helper: ?MethodNode, body: []const Statement, params: []const ParamNode };
        var open: std.StringHashMapUnmanaged(void) = .empty;
        var stack: std.ArrayListUnmanaged(Frame) = .empty;
        stack.append(p.allocator, .{ .helper = null, .body = body, .params = params }) catch @panic("out of memory");
        while (stack.items.len > 0) {
            const top = stack.items[stack.items.len - 1];
            var next: ?MethodNode = null;
            for (p.unresolved(top.body, top.params)) |m| {
                if (!open.contains(m.name)) {
                    next = m;
                    break;
                }
            }
            if (next) |m| {
                open.put(p.allocator, m.name, {}) catch @panic("out of memory");
                stack.append(p.allocator, .{ .helper = m, .body = m.body, .params = m.params }) catch @panic("out of memory");
            } else {
                _ = stack.pop();
                if (top.helper) |h| {
                    p.exits.put(p.allocator, h.name, p.bodyExits(h.body, h.params)) catch @panic("out of memory");
                    _ = open.remove(h.name);
                }
            }
        }
    }
};

/// D18, per path: the method declares a state output somewhere (any
/// addOutput / addRawOutput, so it gets no auto-continuation) and some path
/// through it writes state without reaching an addOutput.
pub fn dropsContinuation(method: MethodNode, contract: ContractNode) bool {
    if (!anf_lower.methodHasAddOutput(method, contract)) return false;
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var p: Paths = .{ .allocator = arena.allocator(), .contract = contract };
    p.prepare(method.body, method.params);
    return droppedState(p.bodyExits(method.body, method.params));
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
