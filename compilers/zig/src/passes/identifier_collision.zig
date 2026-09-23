//! F-017 — the identifier-collision rule.
//!
//! Five surfaces rename identifiers on the way into the AST: `.runar.py`,
//! `.runar.rb`, `.runar.rs`, `.runar.move` (snake_case -> camelCase) and
//! `.runar.go` (PascalCase -> camelCase). None of those mappings is injective:
//! `tmp` and `tmp_`, `a_b` and `aB`, `_tmp` and `tmp` (.py/.rb), `Tmp` and
//! `tmp` (.go) each land on one Rúnar name. Before this rule both spellings
//! were bound to ONE variable, so `tmp = n + 1; tmp_ = n + 2;
//! assert_(tmp == tmp_)` — always false in the source language — compiled to
//! a self-comparison that always passes.
//!
//! While parsing one contract, the surface parser records (source spelling,
//! Rúnar name) for every identifier it DECLARES: properties / struct fields,
//! method names (not the constructor), parameters (not receivers), locals at
//! every declaration or bare-name assignment target, and loop variables. If
//! two recorded pairs share a Rúnar name but differ in spelling, the contract
//! is refused with exactly one error whose text is identical in all seven
//! tiers. Mirrors `identifierCollisionMessage` in
//! packages/runar-compiler/src/passes/snake-to-camel.ts.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Decl = struct { raw: []const u8, name: []const u8 };

/// The (source spelling, Rúnar name) pairs declared by one contract.
pub const DeclaredIdents = struct {
    items: std.ArrayListUnmanaged(Decl) = .empty,

    /// Record one declared identifier and return its Rúnar name.
    pub fn declare(self: *DeclaredIdents, allocator: Allocator, raw: []const u8, name: []const u8) []const u8 {
        self.items.append(allocator, .{ .raw = raw, .name = name }) catch {};
        return name;
    }

    /// The single F-017 error message, or null.
    pub fn message(self: *const DeclaredIdents, allocator: Allocator) ?[]const u8 {
        return identifierCollisionMessage(allocator, self.items.items);
    }
};

fn less(a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

/// The collision with the smallest Rúnar name and, for it, the two smallest
/// source spellings (byte order), so the report does not depend on
/// declaration order. Null when every name has one spelling.
pub fn identifierCollisionMessage(allocator: Allocator, decls: []const Decl) ?[]const u8 {
    var best: ?[]const u8 = null;
    for (decls, 0..) |d, i| {
        for (decls[i + 1 ..]) |e| {
            if (std.mem.eql(u8, d.name, e.name) and !std.mem.eql(u8, d.raw, e.raw)) {
                if (best == null or less(d.name, best.?)) best = d.name;
            }
        }
    }
    const name = best orelse return null;
    var a: ?[]const u8 = null;
    for (decls) |d| {
        if (std.mem.eql(u8, d.name, name) and (a == null or less(d.raw, a.?))) a = d.raw;
    }
    var b: ?[]const u8 = null;
    for (decls) |d| {
        if (std.mem.eql(u8, d.name, name) and !std.mem.eql(u8, d.raw, a.?) and (b == null or less(d.raw, b.?))) b = d.raw;
    }
    return std.fmt.allocPrint(
        allocator,
        "identifier collision: '{s}' and '{s}' both convert to '{s}'; rename one of them",
        .{ a.?, b.?, name },
    ) catch null;
}

test "identifierCollisionMessage picks the smallest name, then its two smallest spellings" {
    const a = std.testing.allocator;
    const decls = [_]Decl{
        .{ .raw = "z_", .name = "z" },    .{ .raw = "z", .name = "z" },
        .{ .raw = "b__c", .name = "bC" }, .{ .raw = "b_c", .name = "bC" },
        .{ .raw = "bC", .name = "bC" },
    };
    const m = identifierCollisionMessage(a, &decls).?;
    defer a.free(m);
    try std.testing.expectEqualStrings("identifier collision: 'bC' and 'b__c' both convert to 'bC'; rename one of them", m);
    const same = [_]Decl{ .{ .raw = "tmp", .name = "tmp" }, .{ .raw = "tmp", .name = "tmp" }, .{ .raw = "sum_", .name = "sum" } };
    try std.testing.expect(identifierCollisionMessage(a, &same) == null);
}
