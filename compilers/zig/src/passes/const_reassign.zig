//! N-342 -- a `const` local on the `.runar.ts` surface cannot be reassigned.
//!
//! spec/grammar.md section 9: "`const` variables cannot be reassigned." The
//! parser recorded the declaration kind and nothing ever read it, so
//! `const s = 1n; s = s + x;` compiled. Refused, with one sentence in all seven
//! tiers: `x = e` (and the compound forms the parser desugars to it), `x++` /
//! `++x` / `x--` / `--x`, and a `const` for-initializer, which the loop's own
//! `i++` then advances (that last one is checked by `parse_ts.zig`'s
//! `parseForStmt`, which still sees the keyword). Element writes (`x[0] = e`)
//! are not touched. Scoping follows blocks. Runs on the `.runar.ts` parse
//! result only.

const std = @import("std");
const types = @import("../ir/types.zig");
const lex_diag = @import("lex_diag.zig");

const Allocator = std.mem.Allocator;
const Statement = types.Statement;

/// The one sentence every tier emits for reassigning const `name`.
pub const MESSAGE_FMT = "Cannot assign to '{s}' because it is a constant.";

const Binding = struct { name: []const u8, mutable: bool };

const Walker = struct {
    allocator: Allocator,
    file: []const u8,
    scope: std.ArrayListUnmanaged(Binding) = .empty,
    errors: std.ArrayListUnmanaged([]const u8) = .empty,

    fn isConst(self: *const Walker, name: []const u8) bool {
        var i = self.scope.items.len;
        while (i > 0) {
            i -= 1;
            if (std.mem.eql(u8, self.scope.items[i].name, name)) return !self.scope.items[i].mutable;
        }
        return false;
    }

    fn report(self: *Walker, name: []const u8, loc: ?types.SourceLocation) void {
        const line: u32 = if (loc) |l| l.line else 1;
        const col: u32 = if (loc) |l| l.column else 1;
        const msg = std.fmt.allocPrint(self.allocator, MESSAGE_FMT, .{name}) catch return;
        const f = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file, line, lex_diag.diagCol(col), msg }) catch return;
        self.allocator.free(msg);
        self.errors.append(self.allocator, f) catch {};
    }

    fn checkExpr(self: *Walker, e: types.Expression, loc: ?types.SourceLocation) void {
        const operand: types.Expression = switch (e) {
            .increment => |x| x.operand,
            .decrement => |x| x.operand,
            else => return,
        };
        switch (operand) {
            .identifier => |name| if (self.isConst(name)) self.report(name, loc),
            else => {},
        }
    }

    fn checkSimple(self: *Walker, stmt: Statement) void {
        switch (stmt) {
            .assign => |a| {
                if (!a.target_is_property and a.index_target == null and self.isConst(a.target)) {
                    self.report(a.target, a.source_loc);
                }
            },
            .expr_stmt => |s| self.checkExpr(s.expr, s.source_loc),
            else => {},
        }
    }

    fn walk(self: *Walker, stmts: []const Statement) void {
        const mark = self.scope.items.len;
        for (stmts) |stmt| {
            switch (stmt) {
                .const_decl => |d| self.scope.append(self.allocator, .{ .name = d.name, .mutable = false }) catch {},
                .let_decl => |d| self.scope.append(self.allocator, .{ .name = d.name, .mutable = true }) catch {},
                .if_stmt => |s| {
                    self.walk(s.then_body);
                    if (s.else_body) |eb| self.walk(eb);
                },
                .for_stmt => |s| {
                    const loop_mark = self.scope.items.len;
                    self.scope.append(self.allocator, .{ .name = s.var_name, .mutable = true }) catch {};
                    if (s.update) |u| self.checkSimple(u.*);
                    self.walk(s.body);
                    self.scope.shrinkRetainingCapacity(loop_mark);
                },
                else => self.checkSimple(stmt),
            }
        }
        self.scope.shrinkRetainingCapacity(mark);
    }
};

/// A diagnostic ("file:line:col: message") for every reassigned `const` local
/// in `contract`, followed by `existing`.
pub fn check(allocator: Allocator, file: []const u8, contract: types.ContractNode, existing: [][]const u8) [][]const u8 {
    var w = Walker{ .allocator = allocator, .file = file };
    w.walk(contract.constructor.body);
    for (contract.methods) |m| w.walk(m.body);
    if (w.errors.items.len == 0) return existing;
    var all: std.ArrayListUnmanaged([]const u8) = .empty;
    all.appendSlice(allocator, existing) catch return existing;
    all.appendSlice(allocator, w.errors.items) catch return existing;
    return all.items;
}
