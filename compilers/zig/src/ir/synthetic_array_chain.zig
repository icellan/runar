//! N-096 — the `syntheticArrayChain` validity rule for `--ir` input. Port of
//! `packages/runar-compiler/src/ir/synthetic-array-chain.ts`: same rule, same
//! order, same words (`conformance/negatives/ir-synthetic-array-chain.test.ts`).
//!
//!   1. at most `max_depth` levels (the regrouper's 1024 passes are the only
//!      nesting bound the pipeline has);
//!   2. every level has 0 <= index < length;
//!   3. level k's base is level k-1's `<base>__<index>`, and the property is
//!      named `<innermost base>__<innermost index>`;
//!   4. the leaves sharing a root are exactly one expansion: contiguous,
//!      row-major from element 0, one type and one list of level lengths, and
//!      complete.
//!
//! Before the rule this tier dropped the F-105 probe's 1100-level property
//! from the ABI and compiled. The message travels on required_fields' thread-
//! local diagnostic channel, like every other rule whose words are shared.

const std = @import("std");
const types = @import("types.zig");
const required_fields = @import("required_fields.zig");

pub const Error = error{ SyntheticArrayChainMalformed, OutOfMemory };

/// The deepest chain the regrouper's 1024-pass cap can consume.
pub const max_depth: usize = 1023;

const prefix = "IR validation: malformed syntheticArrayChain on property '{s}': ";

const Family = struct {
    root: []const u8,
    type_name: []const u8,
    lengths: []u32,
    tuple: []u32,
    last: []const u8,

    fn complete(self: Family) bool {
        for (self.tuple, self.lengths) |i, l| {
            if (i + 1 != l) return false;
        }
        return true;
    }

    fn next(self: Family, allocator: std.mem.Allocator) ![]u32 {
        const t = try allocator.dupe(u32, self.tuple);
        var k = t.len;
        while (k > 0) {
            k -= 1;
            if (t[k] + 1 < self.lengths[k]) {
                t[k] += 1;
                return t;
            }
            t[k] = 0;
        }
        return t;
    }
};

fn leafName(allocator: std.mem.Allocator, root: []const u8, tuple: []const u32) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    try out.appendSlice(allocator, root);
    for (tuple) |i| {
        const part = try std.fmt.allocPrint(allocator, "__{d}", .{i});
        try out.appendSlice(allocator, part);
    }
    return out.toOwnedSlice(allocator);
}

fn lengthList(allocator: std.mem.Allocator, lengths: []const u32) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    for (lengths, 0..) |l, k| {
        if (k > 0) try out.appendSlice(allocator, ", ");
        const part = try std.fmt.allocPrint(allocator, "{d}", .{l});
        try out.appendSlice(allocator, part);
    }
    return out.toOwnedSlice(allocator);
}

fn refuseExpects(allocator: std.mem.Allocator, prop: []const u8, root: []const u8, type_name: []const u8, lengths: []const u32, tuple: []const u32) Error {
    const leaf = try leafName(allocator, root, tuple);
    const ls = try lengthList(allocator, lengths);
    required_fields.setDiag(prefix ++ "'{s}' expects its element '{s}' here (type {s}, level lengths [{s}])", .{ prop, root, leaf, type_name, ls });
    return error.SyntheticArrayChainMalformed;
}

fn checkLevels(allocator: std.mem.Allocator, name: []const u8, chain: []const types.SyntheticArrayLevel) Error!void {
    if (chain.len > max_depth) {
        required_fields.setDiag(prefix ++ "{d} levels exceed the limit of {d}", .{ name, chain.len, max_depth });
        return error.SyntheticArrayChainMalformed;
    }
    for (chain, 0..) |lvl, k| {
        if (!(lvl.index < lvl.length)) {
            required_fields.setDiag(prefix ++ "level {d} has index {d} and length {d}; expand-fixed-arrays writes 0 <= index < length", .{ name, k, lvl.index, lvl.length });
            return error.SyntheticArrayChainMalformed;
        }
        if (k > 0) {
            const prev = chain[k - 1];
            const want = try std.fmt.allocPrint(allocator, "{s}__{d}", .{ prev.base, prev.index });
            if (!std.mem.eql(u8, lvl.base, want)) {
                required_fields.setDiag(prefix ++ "level {d} has base '{s}'; expand-fixed-arrays writes '{s}'", .{ name, k, lvl.base, want });
                return error.SyntheticArrayChainMalformed;
            }
        }
    }
    const inner = chain[chain.len - 1];
    const want = try std.fmt.allocPrint(allocator, "{s}__{d}", .{ inner.base, inner.index });
    if (!std.mem.eql(u8, name, want)) {
        required_fields.setDiag(prefix ++ "its innermost level is element {d} of '{s}'; expand-fixed-arrays names that property '{s}'", .{ name, inner.index, inner.base, want });
        return error.SyntheticArrayChainMalformed;
    }
}

fn closeFamily(allocator: std.mem.Allocator, f: Family) Error!void {
    if (f.complete()) return;
    const leaf = try leafName(allocator, f.root, try f.next(allocator));
    required_fields.setDiag(prefix ++ "'{s}' ends here, before its element '{s}'", .{ f.last, f.root, leaf });
    return error.SyntheticArrayChainMalformed;
}

/// Sets the shared diagnostic and returns SyntheticArrayChainMalformed for
/// the first chain the rule refuses. Scratch memory lives in a private arena
/// (setDiag copies the message), so nothing outlives the call.
pub fn check(backing: std.mem.Allocator, props: []const types.ANFProperty) Error!void {
    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    const allocator = arena.allocator();
    var open: ?Family = null;
    var seen = std.StringHashMapUnmanaged(void){};

    for (props) |prop| {
        const chain: []const types.SyntheticArrayLevel = prop.synthetic_array_chain orelse &.{};
        if (open) |f| {
            if (chain.len == 0 or !std.mem.eql(u8, chain[0].base, f.root)) {
                try closeFamily(allocator, f);
                open = null;
            }
        }
        if (chain.len == 0) continue;

        try checkLevels(allocator, prop.name, chain);
        const tuple = try allocator.alloc(u32, chain.len);
        const lengths = try allocator.alloc(u32, chain.len);
        for (chain, 0..) |lvl, k| {
            tuple[k] = lvl.index;
            lengths[k] = lvl.length;
        }

        if (open) |*f| {
            if (f.complete()) {
                required_fields.setDiag(prefix ++ "'{s}' already ended before this property", .{ prop.name, f.root });
                return error.SyntheticArrayChainMalformed;
            }
            const want = try f.next(allocator);
            if (!std.mem.eql(u8, prop.type_name, f.type_name) or !std.mem.eql(u32, lengths, f.lengths) or !std.mem.eql(u32, tuple, want)) {
                return refuseExpects(allocator, prop.name, f.root, f.type_name, f.lengths, want);
            }
            f.tuple = want;
            f.last = prop.name;
            continue;
        }

        const root = chain[0].base;
        if (seen.contains(root)) {
            required_fields.setDiag(prefix ++ "'{s}' already ended before this property", .{ prop.name, root });
            return error.SyntheticArrayChainMalformed;
        }
        const start = try allocator.alloc(u32, chain.len);
        @memset(start, 0);
        if (!std.mem.eql(u32, tuple, start)) {
            return refuseExpects(allocator, prop.name, root, prop.type_name, lengths, start);
        }
        try seen.put(allocator, root, {});
        open = .{ .root = root, .type_name = prop.type_name, .lengths = lengths, .tuple = tuple, .last = prop.name };
    }
    if (open) |f| try closeFamily(allocator, f);
}
