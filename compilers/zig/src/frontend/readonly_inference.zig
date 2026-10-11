//! Readonly *inference* for the `.runar.zig` surface parser.
//!
//! The Zig surface has no `readonly` keyword, so a stateful contract's
//! mutable fields are identified by three rules, in priority order:
//!
//!   1. `runar.Readonly(T)` on the field            -> readonly (explicit)
//!   2. a field default (`count: i64 = 0`)          -> mutable
//!   3. an assignment to the field in a method body -> mutable   <-- here
//!
//! `parse_zig.zig` implements rules 1 and 2 inline; this module implements
//! rule 3, which had no implementation. Without it a stateful contract whose
//! mutable field carries no default was inferred fully-readonly, the compiler
//! warned "StatefulSmartContract has no mutable properties", and the emitted
//! script silently dropped its state continuation -- while Go/Rust/TS
//! compiled the same source correctly.
//!
//! Reference implementation: `collectZigMutatedProperties` /
//! `collectZigMutatedInExpr` in `compilers/go/frontend/parser_zig.go`, which
//! the Go tier applies to the same `.runar.zig` surface.
//!
//! `applyMutationInference` is additive and idempotent: it only ever demotes
//! a `readonly` flag from true to false, and only for a stateful contract's
//! non-explicit, non-defaulted, assigned fields. Every other flag the parser
//! set is left alone.

const std = @import("std");
const types = @import("../ir/types.zig");

const Allocator = std.mem.Allocator;
const Expression = types.Expression;
const Statement = types.Statement;
const MethodNode = types.MethodNode;
const ParentClass = types.ParentClass;
const PropertyNode = types.PropertyNode;

const NameSet = std.StringHashMapUnmanaged(void);

/// Demote `readonly` for stateful properties that are assigned somewhere in a
/// method body.
///
/// Call AFTER the parser has applied rules 1 and 2:
///   - `parent_class`      selects the contract kind; stateless contracts are
///                         left untouched (all their fields are readonly).
///   - `properties`        the parsed fields, with `readonly` already set from
///                         the explicit-`Readonly` / has-default rules.
///   - `methods`           every method body to scan (public and private).
///   - `explicit_readonly` names annotated `runar.Readonly(T)`. These outrank
///                         inference: an explicit annotation stays readonly
///                         even if a method assigns the field, so a typo can
///                         never silently turn an immutable field into state
///                         (the validator is what reports the bad write).
pub fn applyMutationInference(
    allocator: Allocator,
    parent_class: ParentClass,
    properties: []PropertyNode,
    methods: []const MethodNode,
    explicit_readonly: []const []const u8,
) void {
    // Stateless contracts carry no state continuation -- every field is
    // readonly and an assignment is a validator error, not a mutability
    // signal.
    if (parent_class != .stateful_smart_contract) return;

    var mutated: NameSet = .empty;
    defer mutated.deinit(allocator);

    for (methods) |m| collectInBody(allocator, m.body, &mutated);

    for (properties) |*prop| {
        if (!prop.readonly) continue; // already mutable (rule 2)
        if (isExplicitReadonly(explicit_readonly, prop.name)) continue; // rule 1
        if (mutated.contains(prop.name)) prop.readonly = false; // rule 3
    }
}

fn isExplicitReadonly(explicit_readonly: []const []const u8, name: []const u8) bool {
    for (explicit_readonly) |fname| {
        if (std.mem.eql(u8, fname, name)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Statement / expression walk
// ---------------------------------------------------------------------------

fn collectInBody(allocator: Allocator, body: []const Statement, out: *NameSet) void {
    for (body) |stmt| collectInStmt(allocator, stmt, out);
}

fn collectInStmt(allocator: Allocator, stmt: Statement, out: *NameSet) void {
    switch (stmt) {
        // The Zig AST flattens an assignment target to a bare name:
        // `self.count = ...` and a local `count = ...` both land here as
        // `target = "count"` -- `target` alone cannot tell them apart.
        // `target_is_property` is the parser's authoritative answer (set via
        // `types.targetIsProperty` in `parse_zig.zig`), so only record the
        // name when it is actually a property write; otherwise a local that
        // shadows a property name would wrongly flip that property mutable.
        // This mirrors the Go reference (`collectZigMutatedProperties` in
        // `compilers/go/frontend/parser_zig.go`, which only records a target
        // that type-asserts to `PropertyAccessExpr`) and `validate.zig`'s
        // `checkReadonlyWrites`, which gates on the same flag for the same
        // reason. Compound forms (`self.x += 1`) are already normalised by
        // the parser into this same node with a synthesised binary RHS.
        .assign => |a| {
            if (a.target_is_property) out.put(allocator, a.target, {}) catch {};
            collectInExpr(allocator, a.value, out);
        },
        .const_decl => |d| collectInExpr(allocator, d.value, out),
        .let_decl => |d| if (d.value) |v| collectInExpr(allocator, v, out),
        .expr_stmt => |e| collectInExpr(allocator, e.expr, out),
        .assert_stmt => |a| collectInExpr(allocator, a.condition, out),
        .return_stmt => |maybe| if (maybe) |v| collectInExpr(allocator, v, out),
        .if_stmt => |s| {
            collectInExpr(allocator, s.condition, out);
            collectInBody(allocator, s.then_body, out);
            if (s.else_body) |eb| collectInBody(allocator, eb, out);
        },
        .for_stmt => |s| collectInBody(allocator, s.body, out),
    }
}

fn collectInExpr(allocator: Allocator, expr: Expression, out: *NameSet) void {
    switch (expr) {
        .increment => |i| {
            recordIfProperty(allocator, i.operand, out);
            collectInExpr(allocator, i.operand, out);
        },
        .decrement => |d| {
            recordIfProperty(allocator, d.operand, out);
            collectInExpr(allocator, d.operand, out);
        },
        .binary_op => |b| {
            collectInExpr(allocator, b.left, out);
            collectInExpr(allocator, b.right, out);
        },
        .unary_op => |u| collectInExpr(allocator, u.operand, out),
        .call => |c| for (c.args) |a| collectInExpr(allocator, a, out),
        .method_call => |m| for (m.args) |a| collectInExpr(allocator, a, out),
        .ternary => |t| {
            collectInExpr(allocator, t.condition, out);
            collectInExpr(allocator, t.then_expr, out);
            collectInExpr(allocator, t.else_expr, out);
        },
        .index_access => |ia| {
            collectInExpr(allocator, ia.object, out);
            collectInExpr(allocator, ia.index, out);
        },
        .array_literal => |elems| for (elems) |e| collectInExpr(allocator, e, out),
        .literal_int, .literal_bool, .literal_bytes, .literal_bigint,
        .identifier, .property_access => {},
    }
}

fn recordIfProperty(allocator: Allocator, operand: Expression, out: *NameSet) void {
    switch (operand) {
        .property_access => |pa| out.put(allocator, pa.property, {}) catch {},
        .identifier => |id| out.put(allocator, id, {}) catch {},
        else => {},
    }
}
