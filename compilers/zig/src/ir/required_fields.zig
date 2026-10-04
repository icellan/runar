//! N-069 — presence and JSON type of the ANF IR's required fields.
//!
//! Checked on the generic `std.json.Value` document BEFORE `json.zig` reads it.
//! That reader treated a missing `body` as an empty method (so `--ir` exited 0
//! printing `51`, a bare OP_TRUE, for a P2PK contract whose body was left out)
//! and read `.array` / `.object` off the union unconditionally, so a wrongly
//! typed `body` or `params` aborted the process with "access of union field
//! 'array' while field 'string' is active".
//!
//! The required set is `anf-ir.schema.json`'s `required` keys, minus the ones
//! every loader defaults for older payloads (loop start/step, add_output
//! preimage). The diagnostics are shared verbatim with the other six tiers
//! (Java's F-084 loader is the origin), pinned by
//! `conformance/negatives/ir-required-fields.test.ts`:
//!
//!   IR validation: required field <path> is missing
//!   IR validation: <path> must be <a type>, got <json type>
//!
//! Zig's IR errors are an enum with no payload, so the message is left in a
//! thread-local buffer that `main.zig` prints next to the error name.

const std = @import("std");

pub const Error = error{ IRRequiredFieldMissing, IRFieldWrongType };

threadlocal var diag_buf: [1024]u8 = undefined;
threadlocal var diag_len: usize = 0;

/// The message for the last `Error` this thread returned, if any.
pub fn lastDiagnostic() ?[]const u8 {
    if (diag_len == 0) return null;
    return diag_buf[0..diag_len];
}

/// Also used by json.zig for its N-071 terminal-assert rule, whose message
/// travels on the same channel.
pub fn setDiag(comptime fmt: []const u8, args: anytype) void {
    const s = std.fmt.bufPrint(&diag_buf, fmt, args) catch diag_buf[0..0];
    diag_len = s.len;
}

const CheckError = Error || std.mem.Allocator.Error;
const Obj = std.json.ObjectMap;

fn jsonType(v: ?std.json.Value) []const u8 {
    const val = v orelse return "null";
    return switch (val) {
        .null => "null",
        .bool => "boolean",
        .integer, .float, .number_string => "number",
        .string => "string",
        .array => "array",
        .object => "object",
    };
}

const Walker = struct {
    a: std.mem.Allocator,

    fn fieldPath(self: Walker, path: []const u8, key: []const u8) CheckError![]const u8 {
        if (path.len == 0) return key;
        return std.fmt.allocPrint(self.a, "{s}.{s}", .{ path, key });
    }

    fn malformed(path: []const u8, expected: []const u8, got: ?std.json.Value) Error {
        setDiag("IR validation: {s} must be {s}, got {s}", .{ path, expected, jsonType(got) });
        return Error.IRFieldWrongType;
    }

    /// Absence and a JSON null are both "missing".
    fn req(self: Walker, obj: Obj, key: []const u8, path: []const u8) CheckError!std.json.Value {
        const v = obj.get(key) orelse .null;
        if (v == .null) {
            setDiag("IR validation: required field {s} is missing", .{try self.fieldPath(path, key)});
            return Error.IRRequiredFieldMissing;
        }
        return v;
    }

    fn reqStr(self: Walker, obj: Obj, path: []const u8, keys: []const []const u8) CheckError!void {
        for (keys) |key| {
            const v = try self.req(obj, key, path);
            if (v != .string) return malformed(try self.fieldPath(path, key), "a string", v);
        }
    }

    fn reqBool(self: Walker, obj: Obj, key: []const u8, path: []const u8) CheckError!void {
        const v = try self.req(obj, key, path);
        if (v != .bool) return malformed(try self.fieldPath(path, key), "a boolean", v);
    }

    fn reqList(self: Walker, obj: Obj, key: []const u8, path: []const u8) CheckError!std.json.Array {
        const v = try self.req(obj, key, path);
        return switch (v) {
            .array => |arr| arr,
            else => malformed(try self.fieldPath(path, key), "an array", v),
        };
    }

    fn asObj(v: ?std.json.Value, path: []const u8) CheckError!Obj {
        if (v) |val| switch (val) {
            .object => |o| return o,
            else => {},
        };
        return malformed(path, "an object", v);
    }

    fn reqStrList(self: Walker, obj: Obj, key: []const u8, path: []const u8) CheckError!void {
        const lp = try self.fieldPath(path, key);
        for ((try self.reqList(obj, key, path)).items, 0..) |e, i| {
            if (e != .string) {
                return malformed(try std.fmt.allocPrint(self.a, "{s}[{d}]", .{ lp, i }), "a string", e);
            }
        }
    }

    fn checkBindings(self: Walker, obj: Obj, key: []const u8, path: []const u8) CheckError!void {
        const lp = try self.fieldPath(path, key);
        for ((try self.reqList(obj, key, path)).items, 0..) |b, i| {
            const bp = try std.fmt.allocPrint(self.a, "{s}[{d}]", .{ lp, i });
            const binding = try asObj(b, bp);
            try self.reqStr(binding, bp, &.{"name"});
            const vp = try std.fmt.allocPrint(self.a, "{s}.value", .{bp});
            try self.checkValue(try asObj(binding.get("value"), vp), vp);
        }
    }

    fn checkValue(self: Walker, v: Obj, path: []const u8) CheckError!void {
        try self.reqStr(v, path, &.{"kind"});
        const kind = v.get("kind").?.string;
        const eq = std.mem.eql;
        if (eq(u8, kind, "load_param") or eq(u8, kind, "load_prop")) {
            try self.reqStr(v, path, &.{"name"});
        } else if (eq(u8, kind, "bin_op")) {
            try self.reqStr(v, path, &.{ "op", "left", "right" });
        } else if (eq(u8, kind, "unary_op")) {
            try self.reqStr(v, path, &.{ "op", "operand" });
        } else if (eq(u8, kind, "call")) {
            try self.reqStr(v, path, &.{"func"});
            try self.reqStrList(v, "args", path);
        } else if (eq(u8, kind, "method_call")) {
            try self.reqStr(v, path, &.{ "object", "method" });
            try self.reqStrList(v, "args", path);
        } else if (eq(u8, kind, "if")) {
            try self.reqStr(v, path, &.{"cond"});
            try self.checkBindings(v, "then", path);
            try self.checkBindings(v, "else", path);
            if (v.contains("results")) try self.reqStrList(v, "results", path);
        } else if (eq(u8, kind, "loop")) {
            try self.checkBindings(v, "body", path);
            try self.reqStr(v, path, &.{"iterVar"});
        } else if (eq(u8, kind, "assert")) {
            try self.reqStr(v, path, &.{"value"});
        } else if (eq(u8, kind, "update_prop")) {
            try self.reqStr(v, path, &.{ "name", "value" });
        } else if (eq(u8, kind, "check_preimage") or eq(u8, kind, "deserialize_state")) {
            try self.reqStr(v, path, &.{"preimage"});
        } else if (eq(u8, kind, "add_output")) {
            try self.reqStr(v, path, &.{"satoshis"});
            try self.reqStrList(v, "stateValues", path);
        } else if (eq(u8, kind, "add_raw_output") or eq(u8, kind, "add_data_output")) {
            try self.reqStr(v, path, &.{ "satoshis", "scriptBytes" });
        } else if (eq(u8, kind, "array_literal")) {
            try self.reqStrList(v, "elements", path);
        }
        // load_const, get_state_script, raw_script: value-level rules check
        // their fields. Unknown kinds are refused by json.zig.
    }
};

/// F-038 / F-065: the two OPTIONAL keys the artifact copies into the fields the
/// SDK signs by. Absent (or null) is legal — IR written before they existed —
/// but a present value must be one the source path can produce: an unknown
/// parentClass or a FORKID-less sigHashType would otherwise reach the artifact
/// and steer the SDK into a spend the script rejects. Shared verbatim with the
/// other six tiers (packages/runar-compiler/src/ir/anf-required-fields.ts).
const PARENT_CLASSES = [_][]const u8{ "SmartContract", "StatefulSmartContract", "UnsafeSmartContract" };
const SIGHASH_TYPES = [_]i64{ 0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3 };

fn optParentClass(obj: Obj) Error!void {
    const v = obj.get("parentClass") orelse return;
    switch (v) {
        .null => return,
        .string => |s| {
            for (PARENT_CLASSES) |pc| if (std.mem.eql(u8, s, pc)) return;
            setDiag("IR validation: parentClass must be one of SmartContract, StatefulSmartContract, UnsafeSmartContract, got {s}", .{s});
            return Error.IRFieldWrongType;
        },
        else => return Walker.malformed("parentClass", "a string", v),
    }
}

fn optSigHashType(obj: Obj, path: []const u8) Error!void {
    const v = obj.get("sigHashType") orelse return;
    switch (v) {
        .null => return,
        .integer => |n| {
            for (SIGHASH_TYPES) |t| if (n == t) return;
            setDiag("IR validation: {s}.sigHashType must be one of 65, 66, 67, 193, 194, 195, got {d}", .{ path, n });
            return Error.IRFieldWrongType;
        },
        // An integer too large for i64 arrives as its digit string.
        .number_string => |digits| {
            setDiag("IR validation: {s}.sigHashType must be one of 65, 66, 67, 193, 194, 195, got {s}", .{ path, digits });
            return Error.IRFieldWrongType;
        },
        else => {
            setDiag("IR validation: {s}.sigHashType must be an integer, got {s}", .{ path, jsonType(v) });
            return Error.IRFieldWrongType;
        },
    }
}

/// Return the first required field that is missing or of the wrong JSON type;
/// its message is then available from `lastDiagnostic()`.
pub fn assertRequiredIrFields(allocator: std.mem.Allocator, root: std.json.Value) CheckError!void {
    diag_len = 0;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const w = Walker{ .a = arena.allocator() };

    const program = try Walker.asObj(root, "the IR document");
    try w.reqStr(program, "", &.{"contractName"});
    try optParentClass(program);
    for ((try w.reqList(program, "properties", "")).items, 0..) |p, i| {
        const pp = try std.fmt.allocPrint(w.a, "properties[{d}]", .{i});
        const prop = try Walker.asObj(p, pp);
        try w.reqStr(prop, pp, &.{ "name", "type" });
        try w.reqBool(prop, "readonly", pp);
    }
    for ((try w.reqList(program, "methods", "")).items, 0..) |m, i| {
        const mp = try std.fmt.allocPrint(w.a, "methods[{d}]", .{i});
        const method = try Walker.asObj(m, mp);
        try w.reqStr(method, mp, &.{"name"});
        try w.reqBool(method, "isPublic", mp);
        try optSigHashType(method, mp);
        for ((try w.reqList(method, "params", mp)).items, 0..) |p, j| {
            const pp = try std.fmt.allocPrint(w.a, "{s}.params[{d}]", .{ mp, j });
            try w.reqStr(try Walker.asObj(p, pp), pp, &.{ "name", "type" });
        }
        try w.checkBindings(method, "body", mp);
    }
}
