//! D25 — bind every state continuation to the input that made it.
//!
//! SECURITY CORE (fund safety). Port of
//! packages/runar-compiler/src/passes/continuation-binding.ts (the TypeScript
//! reference): same classification, same hidden field name, same diagnostics.
//!
//! Before D25 every stateful covenant checked `hash256(continuation || change)
//! == hashOutputs` over the WHOLE output list, and the BIP-143 preimage carries
//! no input position, so two UTXOs of one contract spent in one transaction
//! that reach the same post-state were BOTH satisfied by ONE continuation
//! output: the second input's value left as the spender's change.
//!
//! The binding is a property of the CONTRACT, classified once:
//!
//!   single    every continuation-producing public method is mutate-only (no
//!             addOutput / addRawOutput / addDataOutput) and reads nothing
//!             SINGLE zeroes or redefines: those methods default to
//!             SIGHASH_SINGLE|FORKID (ALL|ANYONECANPAY|FORKID becomes
//!             SINGLE|ANYONECANPAY|FORKID); an explicit `@sighash ALL|FORKID`
//!             is refused.
//!   bind      at least one auto-continuation method, but not `single`: a
//!             hidden last state field `_spentOutpointHash =
//!             sha256(extractOutpoint(txPreimage))` is written by every
//!             continuation (anf_lower.zig).
//!   explicit  every continuation method sizes its own outputs: unchanged
//!             bytes, a warning on an unsigned `addOutput(extractAmount(...))`.
//!   none      stateless, or no public method produces a continuation.

const std = @import("std");
const types = @import("../ir/types.zig");
const sighash_directive = @import("../frontend/sighash_directive.zig");
const anf_lower = @import("anf_lower.zig");
const continuation_rules = @import("continuation_rules.zig");

const Allocator = std.mem.Allocator;
const ContractNode = types.ContractNode;
const MethodNode = types.MethodNode;
const PropertyNode = types.PropertyNode;
const Statement = types.Statement;
const Expression = types.Expression;
const SourceLocation = types.SourceLocation;
const CompilerDiagnostic = types.CompilerDiagnostic;

const BASE_ALL = sighash_directive.BASE_ALL;
const BASE_SINGLE = sighash_directive.BASE_SINGLE;
const BASE_TYPE_MASK = sighash_directive.BASE_TYPE_MASK;
const FLAG_ANYONECANPAY = sighash_directive.FLAG_ANYONECANPAY;
const FLAG_FORKID = sighash_directive.FLAG_FORKID;

/// The hidden state field of a `bind` contract (reserved; last mutable property).
pub const TWIN_BINDING_FIELD = "_spentOutpointHash";

/// SIGHASH_SINGLE|FORKID.
pub const SIGHASH_SINGLE_FORKID: i32 = BASE_SINGLE | FLAG_FORKID;

pub const ContinuationClass = enum { none, single, bind, explicit };

/// Builtins whose meaning SINGLE zeroes or redefines (a mutate-only method
/// reading one keeps ALL).
const SINGLE_INCOMPATIBLE_READS = [_][]const u8{
    "extractHashSequence",
    "extractOutputHash",
    "extractOutputs",
    "extractSigHashType",
    "requireOutputP2PKH",
};

/// D25: the shared error text for an explicit ALL sibling in a `single` contract.
pub const EXPLICIT_ALL_SIBLING_FMT =
    "method '{s}': @sighash ALL|FORKID on a state-continuation method of a contract whose " ++
    "continuation methods are all mutate-only reopens twin-input theft: such a contract commits each " ++
    "continuation under SIGHASH_SINGLE (one output per input), and one ALL method lets its input reuse " ++
    "a sibling's output while its own value leaves as change. Remove the directive (the default is " ++
    "SINGLE|FORKID) or write @sighash SINGLE|FORKID";

/// D25: the shared warning text for an unsigned value-conserving addOutput (D12 C1).
pub const UNSIGNED_ADD_OUTPUT_FMT =
    "method '{s}' re-creates the contract with addOutput(extractAmount(...), ...) and checks no " ++
    "signature: two UTXOs of this contract spent in one transaction that reach the same state are both " ++
    "satisfied by ONE such output, and the other input's value leaves as anyone's change (twin-input " ++
    "aliasing). A method that sizes its own outputs is not bound to its input; require a signature, or " ++
    "let the compiler size the continuation (write state instead of calling addOutput)";

fn privateMethod(contract: ContractNode, name: []const u8) ?MethodNode {
    for (contract.methods) |m| {
        if (!m.is_public and std.mem.eql(u8, m.name, name)) return m;
    }
    return null;
}

/// Every call name reachable from a body, through private helpers
/// (cycle-guarded): a `.call`'s callee and a `.method_call`'s method, the
/// spellings the reference's `calleeName` reads.
const CallNames = struct {
    contract: ContractNode,
    names: std.StringHashMapUnmanaged(void) = .empty,
    visiting: std.StringHashMapUnmanaged(void) = .empty,
    a: Allocator,

    fn deinit(self: *CallNames) void {
        self.names.deinit(self.a);
        self.visiting.deinit(self.a);
    }

    fn name(self: *CallNames, n: []const u8) Allocator.Error!void {
        try self.names.put(self.a, n, {});
        if (privateMethod(self.contract, n)) |t| {
            if (!self.visiting.contains(n)) {
                try self.visiting.put(self.a, n, {});
                try self.stmts(t.body);
                _ = self.visiting.remove(n);
            }
        }
    }

    fn stmts(self: *CallNames, ss: []const Statement) Allocator.Error!void {
        for (ss) |s| try self.stmt(s);
    }

    fn stmt(self: *CallNames, s: Statement) Allocator.Error!void {
        switch (s) {
            .assign => |as_| {
                if (as_.index_target) |it| {
                    try self.expr(it.object);
                    try self.expr(it.index);
                }
                try self.expr(as_.value);
            },
            .expr_stmt => |es| try self.expr(es.expr),
            // The canonical AST has no assert node: the reference sees an
            // expression-statement calling `assert` and walks its argument.
            .assert_stmt => |as_s| {
                try self.names.put(self.a, "assert", {});
                try self.expr(as_s.condition);
            },
            .if_stmt => |if_s| {
                try self.expr(if_s.condition);
                try self.stmts(if_s.then_body);
                if (if_s.else_body) |eb| try self.stmts(eb);
            },
            .for_stmt => |f| {
                if (f.update) |u| try self.stmt(u.*);
                try self.stmts(f.body);
            },
            .return_stmt => |r| if (r.value) |v| try self.expr(v),
            .const_decl => |cd| try self.expr(cd.value),
            .let_decl => |ld| if (ld.value) |v| try self.expr(v),
        }
    }

    fn expr(self: *CallNames, e: Expression) Allocator.Error!void {
        switch (e) {
            .call => |c| {
                try self.name(c.callee);
                for (c.args) |x| try self.expr(x);
            },
            .method_call => |mc| {
                try self.name(mc.method);
                for (mc.args) |x| try self.expr(x);
            },
            .binary_op => |b| {
                try self.expr(b.left);
                try self.expr(b.right);
            },
            .unary_op => |u| try self.expr(u.operand),
            .ternary => |t| {
                try self.expr(t.condition);
                try self.expr(t.then_expr);
                try self.expr(t.else_expr);
            },
            .index_access => |ia| {
                try self.expr(ia.object);
                try self.expr(ia.index);
            },
            .array_literal => |els| for (els) |x| try self.expr(x),
            else => {},
        }
    }
};

fn reachableCallNames(a: Allocator, contract: ContractNode, body: []const Statement) Allocator.Error!CallNames {
    var cn: CallNames = .{ .contract = contract, .a = a };
    errdefer cn.deinit();
    try cn.stmts(body);
    return cn;
}

fn isSignatureCheck(n: []const u8) bool {
    return std.mem.eql(u8, n, "checkSig") or std.mem.eql(u8, n, "checkMultiSig") or std.mem.startsWith(u8, n, "verify");
}

fn isSingleIncompatibleRead(n: []const u8) bool {
    for (SINGLE_INCOMPATIBLE_READS) |r| {
        if (std.mem.eql(u8, n, r)) return true;
    }
    return false;
}

/// Whether a public method produces a state continuation (the reference's
/// `continuationShape(effects).needsChange`), and whether it sizes its own
/// outputs (`hasStateOutput`).
const Effects = struct { needs_change: bool, has_state_output: bool, has_data_output: bool };

fn effectsOf(m: MethodNode, contract: ContractNode) Effects {
    const state = anf_lower.methodHasAddOutput(m, contract);
    const data = anf_lower.methodHasAddDataOutput(m, contract);
    const mutates = continuation_rules.mutatesState(m, contract) or nestedElementWrite(contract, m.body);
    return .{ .needs_change = mutates or state or data, .has_state_output = state, .has_data_output = data };
}

/// `this.grid[i][j] = v` on a mutable property, directly or through a private
/// helper. Classification runs before FixedArray expansion, where a nested
/// element write's `Assign.target` is not the base property name (the parsers
/// only name the base for a single-level `this.arr[i]`), so
/// `continuation_rules.mutatesState` misses it; the reference's side-effect
/// summary counts it (writesMutableProperty walks the index chain).
fn nestedElementWrite(contract: ContractNode, body: []const Statement) bool {
    var w: ElementWrite = .{ .contract = contract };
    return w.stmts(body);
}

const ElementWrite = struct {
    contract: ContractNode,
    depth: u32 = 0,

    fn rootIsMutable(self: *ElementWrite, ia: *const types.IndexAccess) bool {
        var obj = ia.object;
        while (obj == .index_access) obj = obj.index_access.object;
        const name = switch (obj) {
            .property_access => |pa| pa.property,
            .identifier => |id| id,
            else => return false,
        };
        for (self.contract.properties) |p| {
            if (!p.readonly and std.mem.eql(u8, p.name, name)) return true;
        }
        return false;
    }

    fn stmts(self: *ElementWrite, ss: []const Statement) bool {
        for (ss) |s| if (self.stmt(s)) return true;
        return false;
    }

    fn stmt(self: *ElementWrite, s: Statement) bool {
        return switch (s) {
            .assign => |as_| (as_.target_is_property and as_.index_target != null and self.rootIsMutable(as_.index_target.?)) or self.expr(as_.value),
            .expr_stmt => |es| self.expr(es.expr),
            .assert_stmt => |as_s| self.expr(as_s.condition),
            .if_stmt => |if_s| self.expr(if_s.condition) or self.stmts(if_s.then_body) or
                (if (if_s.else_body) |eb| self.stmts(eb) else false),
            .for_stmt => |f| self.stmts(f.body),
            .return_stmt => |r| if (r.value) |v| self.expr(v) else false,
            .const_decl => |cd| self.expr(cd.value),
            .let_decl => |ld| if (ld.value) |v| self.expr(v) else false,
        };
    }

    fn callee(self: *ElementWrite, name: []const u8) bool {
        // Private helpers form an acyclic graph bounded by MAX_CALL_DEPTH
        // (validate.zig refuses recursion before this runs); the depth guard
        // is belt and braces.
        if (self.depth > 256) return false;
        const t = privateMethod(self.contract, name) orelse return false;
        self.depth += 1;
        defer self.depth -= 1;
        return self.stmts(t.body);
    }

    fn expr(self: *ElementWrite, e: Expression) bool {
        switch (e) {
            .call => |c| {
                if (self.callee(c.callee)) return true;
                for (c.args) |x| if (self.expr(x)) return true;
            },
            .method_call => |mc| {
                if (self.callee(mc.method)) return true;
                for (mc.args) |x| if (self.expr(x)) return true;
            },
            .binary_op => |b| return self.expr(b.left) or self.expr(b.right),
            .unary_op => |u| return self.expr(u.operand),
            .ternary => |t| return self.expr(t.condition) or self.expr(t.then_expr) or self.expr(t.else_expr),
            else => {},
        }
        return false;
    }
};

/// The contract's D25 class.
pub fn continuationClass(a: Allocator, contract: ContractNode) Allocator.Error!ContinuationClass {
    if (contract.parent_class != .stateful_smart_contract) return .none;
    var any_continuation = false;
    var any_auto = false;
    var all_single_eligible = true;
    for (contract.methods) |m| {
        if (!m.is_public) continue;
        const fx = effectsOf(m, contract);
        if (!fx.needs_change) continue;
        any_continuation = true;
        if (!fx.has_state_output) any_auto = true;
        const base = if (m.sighash_type) |mode| mode & BASE_TYPE_MASK else BASE_ALL;
        const mode_ok = base == BASE_ALL or base == BASE_SINGLE;
        var reads_ok = true;
        {
            var cn = try reachableCallNames(a, contract, m.body);
            defer cn.deinit();
            var it = cn.names.keyIterator();
            while (it.next()) |k| {
                if (isSingleIncompatibleRead(k.*)) reads_ok = false;
            }
        }
        if (fx.has_state_output or fx.has_data_output or !mode_ok or !reads_ok) all_single_eligible = false;
    }
    if (!any_continuation) return .none;
    if (!any_auto) return .explicit;
    return if (all_single_eligible) .single else .bind;
}

/// D25 resolution, run by validate.zig right before the `@sighash` field
/// checks so every later pass (sighash validation, typecheck guards, ANF
/// lowering, the ABI) sees the effective mode. In a `single` contract it sets
/// each continuation method's `sighash_type` (written through
/// `contract.methods`); it refuses an explicit pure-ALL directive there; in an
/// `explicit` contract it warns about unsigned value-conserving addOutput
/// methods. Idempotent. Messages are allocator-owned (`owned_message`).
pub fn resolve(a: Allocator, contract: ContractNode, out: *std.ArrayListUnmanaged(CompilerDiagnostic)) !void {
    const cls = try continuationClass(a, contract);
    switch (cls) {
        .single => for (contract.methods) |*m| {
            if (!m.is_public or !effectsOf(m.*, contract).needs_change) continue;
            if (m.sighash_type) |mode| {
                if ((mode & BASE_TYPE_MASK) == BASE_ALL) {
                    if ((mode & FLAG_ANYONECANPAY) != 0) {
                        m.sighash_type = (mode & ~BASE_TYPE_MASK) | BASE_SINGLE;
                    } else {
                        const msg = try std.fmt.allocPrint(a, EXPLICIT_ALL_SIBLING_FMT, .{m.name});
                        try out.append(a, .{ .message = msg, .location = m.source_loc, .severity = .@"error", .owned_message = true });
                    }
                }
            } else {
                m.sighash_type = SIGHASH_SINGLE_FORKID;
            }
        },
        .explicit => for (contract.methods) |m| {
            if (!m.is_public or !effectsOf(m, contract).needs_change) continue;
            if (m.sighash_type) |mode| {
                if ((mode & BASE_TYPE_MASK) != BASE_ALL) continue;
            }
            if (try unsignedValueConservingAddOutput(a, contract, m)) {
                const msg = try std.fmt.allocPrint(a, UNSIGNED_ADD_OUTPUT_FMT, .{m.name});
                try out.append(a, .{ .message = msg, .location = m.source_loc, .severity = .warning, .owned_message = true });
            }
        },
        .none, .bind => {},
    }
}

/// D12 C1: whether a method that verifies no signature calls `addOutput`
/// whose satoshis argument reads `extractAmount` (directly, or through a
/// local initialised from it). Mirrors `unsignedValueConservingAddOutput`.
fn unsignedValueConservingAddOutput(a: Allocator, contract: ContractNode, m: MethodNode) Allocator.Error!bool {
    {
        var cn = try reachableCallNames(a, contract, m.body);
        defer cn.deinit();
        var it = cn.names.keyIterator();
        while (it.next()) |k| {
            if (isSignatureCheck(k.*)) return false;
        }
    }
    var w: AmountWalk = .{ .a = a, .contract = contract };
    defer {
        w.amount_locals.deinit(a);
        w.visiting.deinit(a);
    }
    try w.stmts(m.body);
    return w.found;
}

const AmountWalk = struct {
    a: Allocator,
    contract: ContractNode,
    amount_locals: std.StringHashMapUnmanaged(void) = .empty,
    visiting: std.StringHashMapUnmanaged(void) = .empty,
    found: bool = false,

    fn readsAmount(self: *AmountWalk, e: Expression) bool {
        return switch (e) {
            .call => |c| blk: {
                if (std.mem.eql(u8, c.callee, "extractAmount")) break :blk true;
                for (c.args) |x| if (self.readsAmount(x)) break :blk true;
                break :blk false;
            },
            .method_call => |mc| blk: {
                if (std.mem.eql(u8, mc.method, "extractAmount")) break :blk true;
                for (mc.args) |x| if (self.readsAmount(x)) break :blk true;
                break :blk false;
            },
            .identifier => |n| self.amount_locals.contains(n),
            .binary_op => |b| self.readsAmount(b.left) or self.readsAmount(b.right),
            .unary_op => |u| self.readsAmount(u.operand),
            .ternary => |t| self.readsAmount(t.condition) or self.readsAmount(t.then_expr) or self.readsAmount(t.else_expr),
            else => false,
        };
    }

    fn stmts(self: *AmountWalk, ss: []const Statement) Allocator.Error!void {
        for (ss) |s| try self.stmt(s);
    }

    fn local(self: *AmountWalk, name: []const u8, init: Expression) Allocator.Error!void {
        if (self.readsAmount(init)) try self.amount_locals.put(self.a, name, {});
        try self.expr(init);
    }

    fn stmt(self: *AmountWalk, s: Statement) Allocator.Error!void {
        switch (s) {
            .const_decl => |cd| try self.local(cd.name, cd.value),
            .let_decl => |ld| if (ld.value) |v| try self.local(ld.name, v),
            .assign => |as_| try self.expr(as_.value),
            .expr_stmt => |es| try self.expr(es.expr),
            // `assert(c)` is an expression-statement call in the reference,
            // whose argument the walk visits.
            .assert_stmt => |as_s| try self.expr(as_s.condition),
            .if_stmt => |if_s| {
                try self.expr(if_s.condition);
                try self.stmts(if_s.then_body);
                if (if_s.else_body) |eb| try self.stmts(eb);
            },
            .for_stmt => |f| try self.stmts(f.body),
            .return_stmt => |r| if (r.value) |v| try self.expr(v),
        }
    }

    /// Only a call is inspected (as in the reference): its name, the private
    /// helper it reaches, and its arguments.
    fn expr(self: *AmountWalk, e: Expression) Allocator.Error!void {
        const n: []const u8, const args: []Expression = switch (e) {
            .call => |c| .{ c.callee, c.args },
            .method_call => |mc| .{ mc.method, mc.args },
            else => return,
        };
        if (std.mem.eql(u8, n, "addOutput") and args.len > 0 and self.readsAmount(args[0])) self.found = true;
        if (privateMethod(self.contract, n)) |t| {
            if (!self.visiting.contains(t.name)) {
                try self.visiting.put(self.a, t.name, {});
                try self.stmts(t.body);
                _ = self.visiting.remove(t.name);
            }
        }
        for (args) |x| try self.expr(x);
    }
};

/// D25 injection, run after typecheck (before fixed-array expansion): a `bind`
/// contract gains the hidden `_spentOutpointHash: Sha256 = 0x00..00` as its
/// LAST property. ANF lowering then writes it in every auto-continuation and
/// appends it to every addOutput. The zero initializer keeps it out of the
/// constructor ABI. Any other class is returned unchanged.
pub fn inject(a: Allocator, contract: ContractNode) Allocator.Error!ContractNode {
    if (try continuationClass(a, contract) != .bind) return contract;
    for (contract.properties) |p| {
        if (std.mem.eql(u8, p.name, TWIN_BINDING_FIELD)) return contract;
    }
    const props = try a.alloc(PropertyNode, contract.properties.len + 1);
    @memcpy(props[0..contract.properties.len], contract.properties);
    props[contract.properties.len] = .{
        .name = TWIN_BINDING_FIELD,
        .type_info = .sha256,
        .type_name = "Sha256",
        .readonly = false,
        .initializer = .{ .literal_bytes = .{ .value = "00" ** 32 } },
        .source_loc = contract.constructor.super_loc,
    };
    var out = contract;
    out.properties = props;
    return out;
}

/// Whether a (post-injection) contract carries the hidden field.
pub fn bindsOutpoint(contract: ContractNode) bool {
    for (contract.properties) |p| {
        if (std.mem.eql(u8, p.name, TWIN_BINDING_FIELD)) return true;
    }
    return false;
}
