const std = @import("std");
const types = @import("sdk_types.zig");

// ---------------------------------------------------------------------------
// generateZig — produce a typed Zig wrapper from a compiled RunarArtifact
// ---------------------------------------------------------------------------
//
// Mirrors the TS/Go codegen output shape: one struct representing the contract
// (holding constructor-arg fields) plus one public method per ABI entry point.

/// Map a Rúnar ABI type to a Zig type. Unknown types fall back to `[]const u8`
/// (hex-encoded), matching the Go mapping.
fn mapTypeToZig(abi_type: []const u8) []const u8 {
    if (std.mem.eql(u8, abi_type, "bigint")) return "i64";
    if (std.mem.eql(u8, abi_type, "boolean")) return "bool";
    if (std.mem.eql(u8, abi_type, "Sig")) return "[]const u8";
    if (std.mem.eql(u8, abi_type, "PubKey")) return "[]const u8";
    if (std.mem.eql(u8, abi_type, "Addr")) return "[]const u8";
    if (std.mem.eql(u8, abi_type, "ByteString")) return "[]const u8";
    if (std.mem.eql(u8, abi_type, "Ripemd160")) return "[]const u8";
    if (std.mem.eql(u8, abi_type, "Sha256")) return "[]const u8";
    if (std.mem.eql(u8, abi_type, "Point")) return "[]const u8";
    if (std.mem.eql(u8, abi_type, "SigHashPreimage")) return "[]const u8";
    return "[]const u8";
}

/// generateZig produces a Zig source file string that wraps the artifact's
/// contract API with typed struct + per-method helpers. Caller owns result.
pub fn generateZig(allocator: std.mem.Allocator, artifact: *const types.RunarArtifact) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    const name = if (artifact.contract_name.len > 0) artifact.contract_name else "Contract";

    try appendFmt(&out, allocator, "// GENERATED — do not edit by hand.\n", .{});
    try appendFmt(&out, allocator, "// Wrapper for Rúnar contract `{s}`.\n", .{name});
    try appendFmt(&out, allocator, "const std = @import(\"std\");\n\n", .{});

    // Constructor-args struct.
    try appendFmt(&out, allocator, "pub const {s}Args = struct {{\n", .{name});
    for (artifact.abi.constructor.params) |p| {
        try appendFmt(&out, allocator, "    {s}: {s},\n", .{ p.name, mapTypeToZig(p.type_name) });
    }
    try appendFmt(&out, allocator, "}};\n\n", .{});

    // Wrapper struct.
    try appendFmt(&out, allocator, "pub const {s} = struct {{\n", .{name});
    try appendFmt(&out, allocator, "    args: {s}Args,\n\n", .{name});
    try appendFmt(&out, allocator, "    pub fn init(args: {s}Args) {s} {{\n", .{ name, name });
    try appendFmt(&out, allocator, "        return .{{ .args = args }};\n", .{});
    try appendFmt(&out, allocator, "    }}\n\n", .{});

    for (artifact.abi.methods) |m| {
        if (!m.is_public) continue;
        try appendFmt(&out, allocator, "    /// ABI method `{s}`.\n", .{m.name});
        try appendFmt(&out, allocator, "    pub fn {s}(self: *{s}", .{ m.name, name });
        for (m.params) |p| {
            try appendFmt(&out, allocator, ", {s}: {s}", .{ p.name, mapTypeToZig(p.type_name) });
        }
        try appendFmt(&out, allocator, ") void {{\n", .{});
        try appendFmt(&out, allocator, "        _ = self;\n", .{});
        for (m.params) |p| {
            try appendFmt(&out, allocator, "        _ = {s};\n", .{p.name});
        }
        try appendFmt(&out, allocator, "    }}\n\n", .{});
    }

    try appendFmt(&out, allocator, "}};\n", .{});

    return out.toOwnedSlice(allocator);
}

fn appendFmt(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    const piece = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(piece);
    try out.appendSlice(allocator, piece);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "generateZig emits wrapper struct for a stateful counter" {
    const allocator = std.testing.allocator;

    // Build a synthetic artifact shaped like a stateful-counter compiled output.
    var methods = try allocator.alloc(types.ABIMethod, 2);
    defer allocator.free(methods);
    methods[0] = .{
        .name = try allocator.dupe(u8, "increment"),
        .params = &.{},
        .is_public = true,
    };
    methods[1] = .{
        .name = try allocator.dupe(u8, "decrement"),
        .params = &.{},
        .is_public = true,
    };
    defer {
        allocator.free(methods[0].name);
        allocator.free(methods[1].name);
    }

    var ctor_params = try allocator.alloc(types.ABIParam, 1);
    defer allocator.free(ctor_params);
    ctor_params[0] = .{
        .name = try allocator.dupe(u8, "count"),
        .type_name = try allocator.dupe(u8, "bigint"),
    };
    defer {
        allocator.free(ctor_params[0].name);
        allocator.free(ctor_params[0].type_name);
    }

    const artifact = types.RunarArtifact{
        .allocator = allocator,
        .contract_name = "Counter",
        .abi = .{
            .constructor = .{ .params = ctor_params },
            .methods = methods,
        },
    };

    const src = try generateZig(allocator, &artifact);
    defer allocator.free(src);

    // Known substrings that must appear in the generated wrapper.
    try std.testing.expect(std.mem.indexOf(u8, src, "pub const CounterArgs = struct") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "count: i64") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub const Counter = struct") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub fn increment(self: *Counter") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pub fn decrement(self: *Counter") != null);
}

test "generateZig maps common ABI types" {
    const allocator = std.testing.allocator;

    var ctor_params = try allocator.alloc(types.ABIParam, 4);
    defer allocator.free(ctor_params);
    ctor_params[0] = .{ .name = try allocator.dupe(u8, "sig"), .type_name = try allocator.dupe(u8, "Sig") };
    ctor_params[1] = .{ .name = try allocator.dupe(u8, "pk"), .type_name = try allocator.dupe(u8, "PubKey") };
    ctor_params[2] = .{ .name = try allocator.dupe(u8, "flag"), .type_name = try allocator.dupe(u8, "boolean") };
    ctor_params[3] = .{ .name = try allocator.dupe(u8, "n"), .type_name = try allocator.dupe(u8, "bigint") };
    defer {
        for (ctor_params) |*p| {
            allocator.free(p.name);
            allocator.free(p.type_name);
        }
    }

    const artifact = types.RunarArtifact{
        .allocator = allocator,
        .contract_name = "X",
        .abi = .{
            .constructor = .{ .params = ctor_params },
            .methods = &.{},
        },
    };

    const src = try generateZig(allocator, &artifact);
    defer allocator.free(src);

    try std.testing.expect(std.mem.indexOf(u8, src, "sig: []const u8") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "pk: []const u8") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "flag: bool") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "n: i64") != null);
}
