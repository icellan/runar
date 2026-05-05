//! ANF interpreter parity driver — Zig SDK.
//!
//! See ../PROTOCOL.md for the input/output spec. Reads a single JSON input
//! file from argv[1], invokes the Zig SDK's
//! `computeNewStateAndDataOutputs` ANF interpreter entry point, and prints a
//! single JSON output object on stdout. Exits 0 on success, non-zero on any
//! error. Errors are written to stderr; stdout is touched only after a
//! successful run.

const std = @import("std");
const runar = @import("runar");

const ANFValue = runar.sdk_anf_interpreter.ANFValue;
const ANFProgram = runar.sdk_anf_interpreter.ANFProgram;
const NewStateResult = runar.sdk_anf_interpreter.NewStateResult;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer args_list.deinit(allocator);
    var args_iter = std.process.Args.Iterator.init(init.minimal.args);
    while (args_iter.next()) |arg| {
        try args_list.append(allocator, arg);
    }
    const args = args_list.items;

    // Parse flags: optional --mode=strict (or --mode=lenient, the default).
    // Anything else is the positional input file. argv[0] is the program name.
    var strict = false;
    var input_path: ?[]const u8 = null;
    if (args.len < 2) {
        std.debug.print("usage: runar-anf-driver-zig [--mode=strict] <input-json-file>\n", .{});
        std.process.exit(1);
    }
    for (args[1..]) |a| {
        if (std.mem.eql(u8, a, "--mode=strict")) {
            strict = true;
        } else if (std.mem.eql(u8, a, "--mode=lenient")) {
            strict = false;
        } else if (std.mem.startsWith(u8, a, "--")) {
            std.debug.print("unknown flag: {s}\n", .{a});
            std.process.exit(2);
        } else {
            if (input_path != null) {
                std.debug.print("usage: runar-anf-driver-zig [--mode=strict] <input-json-file>\n", .{});
                std.process.exit(1);
            }
            input_path = a;
        }
    }
    if (input_path == null) {
        std.debug.print("usage: runar-anf-driver-zig [--mode=strict] <input-json-file>\n", .{});
        std.process.exit(1);
    }
    runDriver(allocator, io, input_path.?, strict) catch |err| {
        std.debug.print("driver error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn runDriver(allocator: std.mem.Allocator, io: std.Io, input_path: []const u8, strict: bool) !void {
    // Load the input JSON.
    const input_data = try std.Io.Dir.cwd().readFileAlloc(io, input_path, allocator, .limited(16 * 1024 * 1024));
    defer allocator.free(input_data);

    var parsed_input = try std.json.parseFromSlice(std.json.Value, allocator, input_data, .{});
    defer parsed_input.deinit();
    if (parsed_input.value != .object) return error.InvalidInput;
    const input_root = parsed_input.value.object;

    // method name
    const method_name = blk: {
        const v = input_root.get("methodName") orelse return error.MissingMethodName;
        if (v != .string) return error.InvalidMethodName;
        break :blk v.string;
    };

    // Resolve ANF path. Prefer `anfPath`, fall back to `case`
    // (-> conformance/tests/<case>/expected-ir.json), matching the python +
    // ruby drivers' behaviour.
    const anf_path = try resolveAnfPath(allocator, io, input_root, input_path);
    defer allocator.free(anf_path);

    // Load + parse ANF program.
    const anf_data = try std.Io.Dir.cwd().readFileAlloc(io, anf_path, allocator, .limited(64 * 1024 * 1024));
    defer allocator.free(anf_data);

    var anf = try runar.sdk_anf_interpreter.parseANFFromJson(allocator, anf_data);
    // Note: parseANFFromJson allocates everything (deeply) using `allocator`
    // and returns the program by value. There is no public deinit; the
    // process exits once we are done so we intentionally leak. The Zig
    // GeneralPurposeAllocator surfaces this on debug builds, but we ship
    // ReleaseSafe — and the leak is bounded by a single ANF.
    _ = &anf;

    // Decode currentState, args, constructorArgs into ANFValue containers.
    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    if (input_root.get("currentState")) |cs_val| {
        try populateMap(allocator, &current_state, cs_val);
    }

    var arg_map = std.StringHashMap(ANFValue).init(allocator);
    defer arg_map.deinit();
    if (input_root.get("args")) |a_val| {
        try populateMap(allocator, &arg_map, a_val);
    }

    var ctor_args: std.ArrayListUnmanaged(ANFValue) = .empty;
    defer ctor_args.deinit(allocator);
    if (input_root.get("constructorArgs")) |c_val| {
        if (c_val == .array) {
            for (c_val.array.items) |item| {
                try ctor_args.append(allocator, try jsonValueToANFValue(allocator, item));
            }
        }
    }

    // Run the interpreter — strict or lenient. In strict mode, an
    // AssertionFailure populates `failure_info` (method + binding name) so
    // we can emit the cross-tier `{error, methodName, bindingName}` envelope.
    const result: NewStateResult = blk: {
        if (strict) {
            var failure_info: runar.sdk_anf_interpreter.AssertionFailureInfo = .{};
            const r = runar.sdk_anf_interpreter.executeStrictWithFailureInfo(
                allocator,
                &anf,
                method_name,
                current_state,
                arg_map,
                ctor_args.items,
                &failure_info,
            ) catch |err| switch (err) {
                error.AssertionFailure => {
                    var fail_buf: [1024]u8 = undefined;
                    var fail_w = std.Io.File.stdout().writer(io, &fail_buf);
                    try fail_w.interface.writeAll("{\"error\":\"AssertionFailureError\",\"methodName\":");
                    try writeJsonString(&fail_w.interface, failure_info.method_name);
                    try fail_w.interface.writeAll(",\"bindingName\":");
                    try writeJsonString(&fail_w.interface, failure_info.binding_name);
                    try fail_w.interface.writeAll("}\n");
                    try fail_w.interface.flush();
                    return;
                },
                else => |e| return e,
            };
            break :blk r;
        }
        break :blk try runar.sdk_anf_interpreter.computeNewStateAndDataOutputs(
            allocator,
            &anf,
            method_name,
            current_state,
            arg_map,
            ctor_args.items,
        );
    };
    defer {
        // Clean up data-output script slices (state map is freed below).
        for (result.data_outputs) |d| allocator.free(d.script);
        allocator.free(result.data_outputs);
    }

    // Emit JSON to stdout.
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    try writeOutputJson(&w.interface, result);
    try w.interface.writeAll("\n");
    try w.interface.flush();

    // Free the result state map last so we don't touch it after writing.
    var rs = result.state;
    // Free duped bytes that came from state_delta (those entries were
    // explicitly duped into our allocator by computeNewStateAndDataOutputs).
    // Pass-through values from currentState share lifetime with the input
    // ANFValue allocations, which are owned by `arg_map` / `current_state`'s
    // underlying buffers — leaking them is fine at process exit.
    rs.deinit();
}

/// Resolve the path to the ANF IR for a given input record. Mirrors the
/// behaviour of drivers/ruby/driver.rb and drivers/python/driver.py: prefer
/// the protocol-spec `anfPath` field; fall back to the shorter `case` form
/// (the test name under `conformance/tests/<case>/expected-ir.json`) used by
/// the inputs checked into this repo. Returned slice is owned by the caller.
fn resolveAnfPath(
    allocator: std.mem.Allocator,
    io: std.Io,
    input_root: std.json.ObjectMap,
    input_file_path: []const u8,
) ![]u8 {
    if (input_root.get("anfPath")) |v| {
        if (v == .string and v.string.len > 0) {
            return try allocator.dupe(u8, v.string);
        }
    }

    const case_val = input_root.get("case") orelse return error.MissingAnfPathOrCase;
    if (case_val != .string) return error.InvalidCaseField;
    const case_name = case_val.string;

    // Resolve the input file's directory to an absolute path so we can walk
    // ancestors looking for "conformance".
    const input_dir = std.fs.path.dirname(input_file_path) orelse ".";
    const abs_input_dir: []const u8 = if (std.fs.path.isAbsolute(input_dir))
        try allocator.dupe(u8, input_dir)
    else blk: {
        const cwd_path = try std.process.currentPathAlloc(io, allocator);
        defer allocator.free(cwd_path);
        break :blk try std.fs.path.resolve(allocator, &.{ cwd_path, input_dir });
    };
    defer allocator.free(abs_input_dir);

    // Walk ancestors looking for a directory named "conformance".
    var current: []const u8 = abs_input_dir;
    while (true) {
        const base = std.fs.path.basename(current);
        if (std.mem.eql(u8, base, "conformance")) {
            return try std.fs.path.join(allocator, &.{ current, "tests", case_name, "expected-ir.json" });
        }
        const parent = std.fs.path.dirname(current) orelse break;
        if (std.mem.eql(u8, parent, current)) break;
        current = parent;
    }
    return error.ConformanceRootNotFound;
}

/// Populate a string-keyed ANFValue map from a JSON object. Caller owns the
/// map; values borrow into the ANFValue arena (string keys are slices into
/// the parsed-input arena; the input is kept alive across the SDK call).
fn populateMap(
    allocator: std.mem.Allocator,
    map: *std.StringHashMap(ANFValue),
    val: std.json.Value,
) !void {
    if (val != .object) return;
    var it = val.object.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        const v = try jsonValueToANFValue(allocator, entry.value_ptr.*);
        try map.put(key, v);
    }
}

/// Decode a single JSON value into an ANFValue per the parity protocol:
///   - "Xn" / "-Xn" string → int (bigint encoding)
///   - JSON integer       → int
///   - JSON bool          → boolean
///   - JSON string        → bytes (hex string, passed through as-is)
///   - JSON null / other  → none
///
/// Note: the protocol restricts the "Xn" form to /^-?\d+n$/. We do NOT
/// promote plain numeric strings (e.g. "123") to ints, even though the SDK's
/// own `parseJSONToANFValue` does — that helper is for ANF *literals*, not
/// the wire protocol. Hex-looking strings ("deadbeef") MUST stay bytes.
fn jsonValueToANFValue(allocator: std.mem.Allocator, val: std.json.Value) error{OutOfMemory}!ANFValue {
    _ = allocator;
    return switch (val) {
        .integer => |n| .{ .int = n },
        .bool => |b| .{ .boolean = b },
        .float => |f| .{ .int = @intFromFloat(f) },
        .string => |s| blk: {
            if (matchBigintString(s)) |digits| {
                const parsed = std.fmt.parseInt(i64, digits, 10) catch break :blk .{ .bytes = s };
                break :blk .{ .int = parsed };
            }
            break :blk .{ .bytes = s };
        },
        .null => .{ .none = {} },
        else => .{ .none = {} },
    };
}

/// Returns the digits portion (without the trailing `n`) if the string
/// matches `/^-?\d+n$/`, otherwise null.
fn matchBigintString(s: []const u8) ?[]const u8 {
    if (s.len < 2) return null;
    if (s[s.len - 1] != 'n') return null;
    var i: usize = 0;
    if (s[0] == '-') i = 1;
    if (i >= s.len - 1) return null; // need at least one digit
    while (i < s.len - 1) : (i += 1) {
        if (s[i] < '0' or s[i] > '9') return null;
    }
    return s[0 .. s.len - 1];
}

/// Encode the interpreter result as the protocol-defined output JSON object.
fn writeOutputJson(
    w: *std.Io.Writer,
    result: NewStateResult,
) !void {
    try w.writeAll("{\"state\":{");
    var first = true;
    var it = result.state.iterator();
    while (it.next()) |entry| {
        if (!first) try w.writeAll(",");
        first = false;
        try writeJsonString(w, entry.key_ptr.*);
        try w.writeAll(":");
        try writeAnfValueAsJson(w, entry.value_ptr.*);
    }
    try w.writeAll("},\"dataOutputs\":[");
    for (result.data_outputs, 0..) |d, i| {
        if (i != 0) try w.writeAll(",");
        try w.writeAll("{\"satoshis\":\"");
        try w.print("{d}", .{d.satoshis});
        try w.writeAll("n\",\"script\":");
        try writeJsonString(w, d.script);
        try w.writeAll("}");
    }
    try w.writeAll("]}");
}

/// Encode an ANFValue as the JSON value used in the protocol's `state`
/// field: ints → "Xn" strings, booleans → JSON bools, bytes → JSON string
/// (hex), none → JSON null.
fn writeAnfValueAsJson(w: *std.Io.Writer, v: ANFValue) !void {
    switch (v) {
        .int => |n| {
            try w.writeAll("\"");
            try w.print("{d}", .{n});
            try w.writeAll("n\"");
        },
        .boolean => |b| {
            try w.writeAll(if (b) "true" else "false");
        },
        .bytes => |b| try writeJsonString(w, b),
        .array => |items| {
            try w.writeAll("[");
            for (items, 0..) |item, i| {
                if (i > 0) try w.writeAll(",");
                try writeAnfValueAsJson(w, item);
            }
            try w.writeAll("]");
        },
        .none => try w.writeAll("null"),
    }
}

/// Write a JSON string literal, escaping the JSON-required minimum set of
/// characters (`"`, `\`, control codepoints < 0x20). This is sufficient for
/// hex strings and plain identifiers; if richer payloads ever flow through
/// the wire we'll need a fuller escaper.
fn writeJsonString(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeAll("\"");
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0x08 => try w.writeAll("\\b"),
            0x0c => try w.writeAll("\\f"),
            else => {
                if (c < 0x20) {
                    try w.print("\\u{x:0>4}", .{c});
                } else {
                    try w.writeAll(&[_]u8{c});
                }
            },
        }
    }
    try w.writeAll("\"");
}
