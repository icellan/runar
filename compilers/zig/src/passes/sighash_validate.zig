//! Field-usage validation for per-method `@sighash` modes (issue #123).
//!
//! SECURITY CORE. A relaxed sighash flag ZEROES specific BIP-143 preimage
//! fields; a covenant that still reads one of those fields (or binds an output
//! the flag no longer commits to) is exploitable — the attacker gets a free hand
//! over exactly the part of the transaction the covenant believed it had pinned.
//! This pass rejects, at compile time, every field read / output binding that
//! becomes unsound under the method's declared mode.
//!
//! Faithful port of packages/runar-compiler/src/passes/sighash-validate.ts and
//! its Go peer (compilers/go/frontend/sighash_validate.go), including the
//! security-audit fixes from commit e88f202c (F1 mutate-only SINGLE reject +
//! explicit-single warning, F3 transitive walk, F4 requireOutputP2PKH-under-
//! SINGLE reject).
//!
//! BIP-143 field availability by sighash type (✓ committed, ✗ ZEROED):
//!
//!   field                 ALL    NONE   SINGLE   +ANYONECANPAY
//!   ---------------------------------------------------------
//!   hashPrevouts           ✓      ✓      ✓         ✗
//!   hashSequence           ✓      ✗      ✗         ✗
//!   hashOutputs            ✓      ✗      same-idx   (per base)
//!
//! Note on F3 for-loop headers: the Zig `.runar.ts` parser collapses a
//! for-loop's init/condition to a compile-time-constant bound at parse time and
//! rejects a runtime bound outright (a forbidden read hidden in a loop condition
//! is therefore rejected before this pass runs). We still walk the loop BODY and
//! assignment index expressions.

const std = @import("std");
const types = @import("../ir/types.zig");
const sighash_directive = @import("../frontend/sighash_directive.zig");

const ContractNode = types.ContractNode;
const MethodNode = types.MethodNode;
const Statement = types.Statement;
const Expression = types.Expression;
const CompilerDiagnostic = types.CompilerDiagnostic;

const MAX_DEPTH: u32 = 32;

const Scan = struct {
    hash_prevouts_reads: usize = 0,
    hash_sequence_reads: usize = 0,
    hash_outputs_reads: usize = 0,
    prevout_script_reads: usize = 0,
    output_asserts: usize = 0,
    state_output_count: usize = 0,
    data_output_count: usize = 0,
    mutates_state: bool = false,
};

/// Validate every public method's `@sighash` field usage. Appends diagnostics
/// (errors + warnings, each carrying its own severity) into `out`. Methods with
/// no directive (default ALL|FORKID) are never flagged.
pub fn validateSighashUsage(
    allocator: std.mem.Allocator,
    contract: ContractNode,
    out: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    const is_stateful = contract.parent_class == .stateful_smart_contract;

    for (contract.methods) |method| {
        if (!method.is_public) continue;
        const mode = method.sighash_type orelse continue; // default -> allow all

        const base = mode & sighash_directive.BASE_TYPE_MASK;
        const acp = (mode & sighash_directive.FLAG_ANYONECANPAY) != 0;
        const label = try sighash_directive.describe(allocator, mode);
        // `label` is owned; keep it alive for all messages built below by
        // duplicating into each message via allocPrint (label freed at end).
        defer allocator.free(label);
        const loc = method.source_loc;

        var scan = Scan{};
        var visiting = std.StringHashMap(void).init(allocator);
        defer visiting.deinit();
        try scanMethod(contract, method, &scan, &visiting, 0);

        const needs_continuation = is_stateful and
            (scan.mutates_state or scan.state_output_count > 0 or scan.data_output_count > 0);

        // ---- ANYONECANPAY: only THIS input is signed ---------------------
        if (acp) {
            if (scan.hash_prevouts_reads > 0) {
                try err(allocator, out, loc, "@sighash {s}: reads hashPrevouts (extractHashPrevouts), which is zeroed under ANYONECANPAY (only this input is signed) — the covenant cannot constrain the input set, so any check on it is trivially bypassable. Remove ANYONECANPAY or drop the read.", .{label});
            }
            if (scan.prevout_script_reads > 0) {
                try err(allocator, out, loc, "@sighash {s}: binds a companion input's prevout script (extractPrevOutputScript), but ANYONECANPAY zeroes hashPrevouts so the input set is unconstrained — an attacker can substitute inputs freely. Companion-input covenants require the full prevout set committed (drop ANYONECANPAY).", .{label});
            }
        }

        // ---- hashSequence committed only under pure ALL (no ACP) ---------
        const hash_sequence_sound = base == sighash_directive.BASE_ALL and !acp;
        if (!hash_sequence_sound and scan.hash_sequence_reads > 0) {
            try err(allocator, out, loc, "@sighash {s}: reads hashSequence (extractHashSequence), which is zeroed under any mode other than SIGHASH_ALL (NONE / SINGLE / ANYONECANPAY all clear it) — the read yields attacker-chosen zeros. Use SIGHASH_ALL or drop the read.", .{label});
        }

        // ---- NONE commits to NO outputs ----------------------------------
        if (base == sighash_directive.BASE_NONE) {
            if (needs_continuation) {
                try err(allocator, out, loc, "@sighash {s}: this stateful method binds a state-continuation output via hashOutputs, but NONE commits to NO outputs (hashOutputs is zeroed) — the continuation is unenforceable, so the next-state covenant is meaningless and the spend is unsound. A continuation covenant cannot use NONE.", .{label});
            }
            if (scan.hash_outputs_reads > 0) {
                try err(allocator, out, loc, "@sighash {s}: reads hashOutputs (extractOutputHash/extractOutputs), which is zeroed under NONE — the read yields attacker-chosen zeros. Drop the output read or use ALL/SINGLE.", .{label});
            }
            if (scan.output_asserts > 0) {
                try err(allocator, out, loc, "@sighash {s}: asserts an output (requireOutputP2PKH), but NONE commits to no outputs — the assertion cannot be enforced. Use ALL/SINGLE.", .{label});
            }
            if (scan.state_output_count + scan.data_output_count > 0) {
                try err(allocator, out, loc, "@sighash {s}: this method emits {d} output(s) (addOutput/addRawOutput/addDataOutput), but NONE commits to no outputs — those outputs are unenforceable. Use ALL/SINGLE.", .{ label, scan.state_output_count + scan.data_output_count });
            }
        }

        // ---- SINGLE commits ONLY to the same-index output ----------------
        if (base == sighash_directive.BASE_SINGLE) {
            // F4: a fixed-index output assertion cannot be proven to land at
            // THIS input's index, the only output SINGLE commits to.
            if (scan.output_asserts > 0) {
                try err(allocator, out, loc, "@sighash {s}: 'requireOutputP2PKH' asserts an output at a fixed index, but SINGLE commits ONLY to the output at THIS input's index — the asserted index cannot be statically proven equal to the input index, so the assertion may bind an uncommitted (attacker-controllable) output or silently brick the spend. Use ALL.", .{label});
            }

            // F1: a stateful mutate-only (or data-only) method has NO explicit
            // output intrinsic, so the compiler auto-injects a single
            // state-continuation output whose value is the caller-chosen
            // _newAmount. Under SINGLE, BIP-143 commits ONLY to the output at
            // THIS input's index and does NOT pin its value -> value-skimmable.
            const is_mutate_only_auto_continuation = needs_continuation and
                scan.state_output_count == 0 and scan.data_output_count == 0;

            var state_outputs: usize = 0;
            if (scan.state_output_count > 0) {
                state_outputs = scan.state_output_count;
            } else if (needs_continuation) {
                state_outputs = 1;
            }
            const committed = state_outputs + scan.data_output_count;

            if (is_mutate_only_auto_continuation) {
                try err(allocator, out, loc, "@sighash {s}: this stateful method's state continuation is sized by the caller-chosen _newAmount, but SINGLE commits ONLY to the same-index output WITHOUT pinning its value — a spender can set _newAmount to dust, drive the change output to zero, and append a draining output while the covenant + OP_PUSH_TX binding still validate (value skim); a mutate-only SINGLE continuation is unsound. Use ALL, or emit an explicit addOutput/addRawOutput that carries the full protected value at this input's index.", .{label});
            } else if (committed > 1) {
                try err(allocator, out, loc, "@sighash {s}: SINGLE commits ONLY to the output at this input's index, but this method binds {d} outputs ({d} addOutput + {d} addDataOutput). Outputs beyond the same-index one are uncommitted and attacker-controllable. A SINGLE covenant must bind exactly one same-index output.", .{ label, committed, scan.state_output_count, scan.data_output_count });
            } else if (committed == 1) {
                try warn(allocator, out, loc, "@sighash {s}: SINGLE commits ONLY to the output at this input's index. This method binds exactly one output there, which is sound ONLY if that output carries the FULL protected value — SINGLE does not pin the amount, so a short-changed same-index output cannot be caught at compile time. Ensure the caller places the fully-valued output at this input's index.", .{label});
            }
        }
    }
}

fn err(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(CompilerDiagnostic), loc: ?types.SourceLocation, comptime fmt: []const u8, args: anytype) !void {
    const msg = try std.fmt.allocPrint(allocator, fmt, args);
    try out.append(allocator, .{ .message = msg, .location = loc, .severity = .@"error" });
}

fn warn(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(CompilerDiagnostic), loc: ?types.SourceLocation, comptime fmt: []const u8, args: anytype) !void {
    const msg = try std.fmt.allocPrint(allocator, fmt, args);
    try out.append(allocator, .{ .message = msg, .location = loc, .severity = .warning });
}

// ---------------------------------------------------------------------------
// Method scan — walks a method body transitively through private helpers,
// covering assignment targets/index expressions and loop bodies.
// ---------------------------------------------------------------------------

fn lookupPrivate(contract: ContractNode, name: []const u8) ?MethodNode {
    for (contract.methods) |m| {
        if (!m.is_public and std.mem.eql(u8, m.name, name)) return m;
    }
    return null;
}

fn isMutableProp(contract: ContractNode, name: []const u8) bool {
    for (contract.properties) |p| {
        if (!p.readonly and std.mem.eql(u8, p.name, name)) return true;
    }
    return false;
}

fn scanMethod(contract: ContractNode, method: MethodNode, scan: *Scan, visiting: *std.StringHashMap(void), depth: u32) std.mem.Allocator.Error!void {
    if (depth > MAX_DEPTH) return;
    try scanBody(contract, method.body, scan, visiting, depth);
}

fn scanBody(contract: ContractNode, stmts: []const Statement, scan: *Scan, visiting: *std.StringHashMap(void), depth: u32) std.mem.Allocator.Error!void {
    for (stmts) |s| try scanStmt(contract, s, scan, visiting, depth);
}

fn scanStmt(contract: ContractNode, stmt: Statement, scan: *Scan, visiting: *std.StringHashMap(void), depth: u32) std.mem.Allocator.Error!void {
    switch (stmt) {
        .assign => |a| {
            if (isMutableProp(contract, a.target)) scan.mutates_state = true;
            // F3: an index-access LHS can hide a forbidden read in its index.
            if (a.index_target) |it| {
                try scanExpr(contract, it.object, scan, visiting, depth);
                try scanExpr(contract, it.index, scan, visiting, depth);
            }
            try scanExpr(contract, a.value, scan, visiting, depth);
        },
        .expr_stmt => |e| try scanExpr(contract, e.expr, scan, visiting, depth),
        .const_decl => |d| try scanExpr(contract, d.value, scan, visiting, depth),
        .let_decl => |d| {
            if (d.value) |v| try scanExpr(contract, v, scan, visiting, depth);
        },
        .if_stmt => |i| {
            try scanExpr(contract, i.condition, scan, visiting, depth);
            try scanBody(contract, i.then_body, scan, visiting, depth);
            if (i.else_body) |eb| try scanBody(contract, eb, scan, visiting, depth);
        },
        .for_stmt => |f| try scanBody(contract, f.body, scan, visiting, depth),
        .return_stmt => |maybe_r| {
            const maybe = maybe_r.value;
            if (maybe) |e| try scanExpr(contract, e, scan, visiting, depth);
        },
        .assert_stmt => |as| try scanExpr(contract, as.condition, scan, visiting, depth),
    }
}

fn scanExpr(contract: ContractNode, expr: Expression, scan: *Scan, visiting: *std.StringHashMap(void), depth: u32) (std.mem.Allocator.Error)!void {
    switch (expr) {
        .call => |c| {
            try countCallee(contract, c.callee, scan, visiting, depth);
            for (c.args) |arg| try scanExpr(contract, arg, scan, visiting, depth);
        },
        .method_call => |mc| {
            // this.helper() / self.helper() — recurse into the private helper.
            try countCallee(contract, mc.method, scan, visiting, depth);
            for (mc.args) |arg| try scanExpr(contract, arg, scan, visiting, depth);
        },
        .binary_op => |b| {
            try scanExpr(contract, b.left, scan, visiting, depth);
            try scanExpr(contract, b.right, scan, visiting, depth);
        },
        .unary_op => |u| try scanExpr(contract, u.operand, scan, visiting, depth),
        .ternary => |t| {
            try scanExpr(contract, t.condition, scan, visiting, depth);
            try scanExpr(contract, t.then_expr, scan, visiting, depth);
            try scanExpr(contract, t.else_expr, scan, visiting, depth);
        },
        .index_access => |ia| {
            try scanExpr(contract, ia.object, scan, visiting, depth);
            try scanExpr(contract, ia.index, scan, visiting, depth);
        },
        .increment => |inc| {
            if (inc.operand == .property_access and isMutableProp(contract, inc.operand.property_access.property)) scan.mutates_state = true;
            try scanExpr(contract, inc.operand, scan, visiting, depth);
        },
        .decrement => |dec| {
            if (dec.operand == .property_access and isMutableProp(contract, dec.operand.property_access.property)) scan.mutates_state = true;
            try scanExpr(contract, dec.operand, scan, visiting, depth);
        },
        .array_literal => |els| {
            for (els) |el| try scanExpr(contract, el, scan, visiting, depth);
        },
        else => {},
    }
}

/// Classify a callee name against the flagged builtin/intrinsic sets, and
/// recurse (cycle-guarded) into a private helper of that name.
fn countCallee(contract: ContractNode, name: []const u8, scan: *Scan, visiting: *std.StringHashMap(void), depth: u32) std.mem.Allocator.Error!void {
    if (std.mem.eql(u8, name, "extractHashPrevouts")) scan.hash_prevouts_reads += 1;
    if (std.mem.eql(u8, name, "extractHashSequence")) scan.hash_sequence_reads += 1;
    if (std.mem.eql(u8, name, "extractOutputHash") or std.mem.eql(u8, name, "extractOutputs")) scan.hash_outputs_reads += 1;
    if (std.mem.eql(u8, name, "extractPrevOutputScript")) scan.prevout_script_reads += 1;
    if (std.mem.eql(u8, name, "requireOutputP2PKH")) scan.output_asserts += 1;
    if (std.mem.eql(u8, name, "addOutput") or std.mem.eql(u8, name, "addRawOutput")) scan.state_output_count += 1;
    if (std.mem.eql(u8, name, "addDataOutput")) scan.data_output_count += 1;

    if (lookupPrivate(contract, name)) |target| {
        if (!visiting.contains(name)) {
            try visiting.put(name, {});
            try scanBody(contract, target.body, scan, visiting, depth + 1);
            _ = visiting.remove(name);
        }
    }
}
