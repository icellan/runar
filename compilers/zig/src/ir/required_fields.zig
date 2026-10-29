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

pub const Error = error{ IRRequiredFieldMissing, IRFieldWrongType, IRIdentifierInvalid };

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

/// N-059 / F-102 (F-068 in Go): a `check_preimage` binding's optional
/// `sighashFlag`, at every nesting depth. Codegen appends `sighashFlag & 0xff`
/// to the OP_PUSH_TX binding, so an out-of-set value was truncated to a byte no
/// BSV spend can satisfy (999999 -> 0x3F, FORKID clear). Absent (or null), and
/// for Zig's reader an explicit 0, meant the default ALL|FORKID; an explicit 0
/// is now refused like every other out-of-set value. In a public method the
/// flag must also equal the method's `sigHashType` (default 0x41): the artifact
/// tells the SDK to sign under `sigHashType`, the script derives its sighash
/// under the flag, and a divergence is unspendable. Both diagnostics are shared
/// verbatim with the other six tiers.
const SIGHASH_DEFAULT: i64 = 0x41;
const BAD_FLAG_FMT = "IR validation: method {s} binding {s} check_preimage has sighashFlag {s}; sighashFlag must be one of {{0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3}} (ALL/NONE/SINGLE with FORKID, optionally ANYONECANPAY). Any other value is truncated to a sighash byte no BSV spend can satisfy.";

fn checkSighashFlags(w: Walker, obj: Obj, key: []const u8, path: []const u8, method: []const u8, is_public: bool, declared: i64) CheckError!void {
    const eq = std.mem.eql;
    const lp = try w.fieldPath(path, key);
    const list = switch (obj.get(key) orelse return) {
        .array => |arr| arr,
        else => return,
    };
    for (list.items, 0..) |b, i| {
        const vp = try std.fmt.allocPrint(w.a, "{s}[{d}].value", .{ lp, i });
        const binding = switch (b) {
            .object => |o| o,
            else => continue,
        };
        const v = switch (binding.get("value") orelse continue) {
            .object => |o| o,
            else => continue,
        };
        const name = switch (binding.get("name") orelse .null) {
            .string => |s| s,
            else => "",
        };
        const kind = switch (v.get("kind") orelse .null) {
            .string => |s| s,
            else => "",
        };
        if (eq(u8, kind, "if")) {
            try checkSighashFlags(w, v, "then", vp, method, is_public, declared);
            try checkSighashFlags(w, v, "else", vp, method, is_public, declared);
        } else if (eq(u8, kind, "loop")) {
            try checkSighashFlags(w, v, "body", vp, method, is_public, declared);
        } else if (eq(u8, kind, "check_preimage")) {
            var flag: i64 = SIGHASH_DEFAULT;
            const raw = v.get("sighashFlag") orelse .null;
            switch (raw) {
                .null => {},
                .integer => |n| {
                    var ok = false;
                    for (SIGHASH_TYPES) |t| if (n == t) {
                        ok = true;
                    };
                    if (!ok) {
                        setDiag(BAD_FLAG_FMT, .{ method, name, try std.fmt.allocPrint(w.a, "{d}", .{n}) });
                        return Error.IRFieldWrongType;
                    }
                    flag = n;
                },
                // An integer too large for i64 arrives as its digit string.
                .number_string => |digits| {
                    setDiag(BAD_FLAG_FMT, .{ method, name, digits });
                    return Error.IRFieldWrongType;
                },
                .float => |x| {
                    var ok = false;
                    for (SIGHASH_TYPES) |t| if (x == @as(f64, @floatFromInt(t))) {
                        ok = true;
                    };
                    if (!ok) {
                        setDiag(BAD_FLAG_FMT, .{ method, name, try std.fmt.allocPrint(w.a, "{d}", .{x}) });
                        return Error.IRFieldWrongType;
                    }
                    flag = @intFromFloat(x);
                },
                else => return Walker.malformed(try w.fieldPath(vp, "sighashFlag"), "an integer", raw),
            }
            if (is_public and flag != declared) {
                setDiag("IR validation: method {s} binding {s} check_preimage has sighashFlag {d} but the method declares sigHashType {d}; a public method's check_preimage must bind the sighash type its ABI declares, or the SDK signs a preimage the script rejects.", .{ method, name, flag, declared });
                return Error.IRFieldWrongType;
            }
        }
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
        const declared: i64 = switch (method.get("sigHashType") orelse .null) {
            .integer => |n| n,
            else => SIGHASH_DEFAULT,
        };
        try checkSighashFlags(w, method, "body", mp, method.get("name").?.string, method.get("isPublic").?.bool, declared);
    }
    try assertIrIdentifiers(w, program);
}

/// N-207: the declared identifiers are non-empty, and a method's parameter
/// names are distinct. Runs after the type walk above, so every field read
/// here is a string. "" is a string, so N-069 alone let an empty name through;
/// and duplicate param names alias ONE stack slot (every load_param resolves
/// to the last declared one, so assert(p0 === p1) over two params of the same
/// name compiled to an always-true script). Shared verbatim with the other six
/// tiers, pinned by conformance/negatives/ir-identifiers.test.ts:
///
///   IR validation: <path> must be a non-empty string
///   IR validation: <path>.name '<name>' duplicates <earlier path>.name
fn nonEmpty(w: Walker, obj: Obj, path: []const u8, keys: []const []const u8) CheckError!void {
    for (keys) |key| {
        if (obj.get(key).?.string.len == 0) {
            setDiag("IR validation: {s} must be a non-empty string", .{try w.fieldPath(path, key)});
            return Error.IRIdentifierInvalid;
        }
    }
}

/// N-408: a binding's name is non-empty at every nesting level (a method
/// body, an `if` arm, a `loop` body), named by the path `checkBindings`
/// walks: methods[0].body[1].value.then[0].name
fn nonEmptyBindingNames(w: Walker, obj: Obj, key: []const u8, path: []const u8) CheckError!void {
    const lp = try w.fieldPath(path, key);
    for (obj.get(key).?.array.items, 0..) |b, i| {
        const bp = try std.fmt.allocPrint(w.a, "{s}[{d}]", .{ lp, i });
        try nonEmpty(w, b.object, bp, &.{"name"});
        const value = b.object.get("value").?.object;
        const vp = try std.fmt.allocPrint(w.a, "{s}.value", .{bp});
        try nonEmpty(w, value, vp, &.{"kind"});
        const kind = value.get("kind").?.string;
        if (std.mem.eql(u8, kind, "if")) {
            try nonEmptyBindingNames(w, value, "then", vp);
            try nonEmptyBindingNames(w, value, "else", vp);
        } else if (std.mem.eql(u8, kind, "loop")) {
            try nonEmptyBindingNames(w, value, "body", vp);
        }
    }
}

fn assertIrIdentifiers(w: Walker, program: Obj) CheckError!void {
    try nonEmpty(w, program, "", &.{"contractName"});
    for (program.get("properties").?.array.items, 0..) |p, i| {
        const pp = try std.fmt.allocPrint(w.a, "properties[{d}]", .{i});
        try nonEmpty(w, p.object, pp, &.{ "name", "type" });
    }
    for (program.get("methods").?.array.items, 0..) |m, i| {
        const mp = try std.fmt.allocPrint(w.a, "methods[{d}]", .{i});
        try nonEmpty(w, m.object, mp, &.{"name"});
        const params = m.object.get("params").?.array.items;
        for (params, 0..) |p, j| {
            const pp = try std.fmt.allocPrint(w.a, "{s}.params[{d}]", .{ mp, j });
            try nonEmpty(w, p.object, pp, &.{ "name", "type" });
            const name = p.object.get("name").?.string;
            for (params[0..j], 0..) |earlier, k| {
                if (std.mem.eql(u8, earlier.object.get("name").?.string, name)) {
                    setDiag("IR validation: {s}.name '{s}' duplicates {s}.params[{d}].name", .{ pp, name, mp, k });
                    return Error.IRIdentifierInvalid;
                }
            }
        }
        try nonEmptyBindingNames(w, m.object, "body", mp);
    }
}
