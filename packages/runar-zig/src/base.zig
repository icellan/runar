const std = @import("std");
const bsvz = @import("bsvz");

pub const Int = i64;
pub const Bigint = i64;
pub const PubKey = []const u8;
pub const Sig = []const u8;
pub const Addr = []const u8;
pub const ByteString = []const u8;
pub const Sha256 = []const u8;
pub const Ripemd160 = []const u8;
pub const SigHashPreimage = []const u8;
pub const RabinSig = []const u8;
pub const RabinPubKey = []const u8;
pub const Point = []const u8;

pub fn Readonly(comptime T: type) type {
    return T;
}

pub const OutputValue = union(enum) {
    bigint: Bigint,
    boolean: bool,
    bytes: ByteString,

    pub fn deinit(self: OutputValue, allocator: std.mem.Allocator) void {
        switch (self) {
            .bytes => |bytes| allocator.free(bytes),
            else => {},
        }
    }
};

pub const OutputSnapshot = struct {
    satoshis: Bigint,
    values: []OutputValue,
    stateScript: ByteString,
    continuationScript: ByteString,

    pub fn deinit(self: *OutputSnapshot, allocator: std.mem.Allocator) void {
        for (self.values) |value| value.deinit(allocator);
        allocator.free(self.values);
        if (self.stateScript.len != 0) allocator.free(self.stateScript);
        if (self.continuationScript.len != 0) allocator.free(self.continuationScript);
        self.* = .{
            .satoshis = 0,
            .values = &.{},
            .stateScript = &.{},
            .continuationScript = &.{},
        };
    }
};

pub const SmartContract = struct {};

pub const StatefulSmartContractError = error{
    UnsupportedOutputValue,
};

pub const StatefulRuntimeError = std.mem.Allocator.Error || StatefulSmartContractError;

pub const StatefulSmartContract = struct {
    allocator: std.mem.Allocator,
    txPreimage: SigHashPreimage,
    _outputs: std.ArrayListUnmanaged(OutputSnapshot),
    _current_state_script: ByteString,
    _continuation_prefix: ByteString,
    _continuation_suffix: ByteString,

    pub fn init(allocator: std.mem.Allocator) StatefulSmartContract {
        return .{
            .allocator = allocator,
            .txPreimage = &.{},
            ._outputs = .empty,
            ._current_state_script = &.{},
            ._continuation_prefix = &.{},
            ._continuation_suffix = &.{},
        };
    }

    pub fn deinit(self: *StatefulSmartContract) void {
        self.resetOutputs();
        self.clearCurrentStateScript();
        self.clearContinuationEnvelope();
    }

    pub fn outputs(self: *const StatefulSmartContract) []const OutputSnapshot {
        return self._outputs.items;
    }

    pub fn hashOutputs(self: *const StatefulSmartContract) StatefulRuntimeError!Sha256 {
        const output_views = try buildBsvzOutputViews(self.allocator, self._outputs.items);
        defer self.allocator.free(output_views);

        const digest = try bsvz.transaction.Output.hashAll(self.allocator, output_views);
        return try self.allocator.dupe(u8, &digest.bytes);
    }

    pub fn setTxPreimage(self: *StatefulSmartContract, tx_preimage: SigHashPreimage) !void {
        self.txPreimage = try self.allocator.dupe(u8, tx_preimage);
    }

    pub fn resetOutputs(self: *StatefulSmartContract) void {
        if (self.txPreimage.len != 0) {
            self.allocator.free(self.txPreimage);
            self.txPreimage = &.{};
        }
        for (self._outputs.items) |*output| output.deinit(self.allocator);
        self._outputs.deinit(self.allocator);
        self._outputs = .empty;
    }

    pub fn setCurrentStateScript(self: *StatefulSmartContract, state_script: ByteString) StatefulRuntimeError!void {
        self.clearCurrentStateScript();
        self._current_state_script = try self.allocator.dupe(u8, state_script);
    }

    pub fn setCurrentStateValues(self: *StatefulSmartContract, values: anytype) StatefulRuntimeError!void {
        const serialized = try serializeTestStateValues(self.allocator, values);
        errdefer self.allocator.free(serialized);
        try self.setCurrentStateScript(serialized);
        self.allocator.free(serialized);
    }

    pub fn clearCurrentStateScript(self: *StatefulSmartContract) void {
        if (self._current_state_script.len != 0) {
            self.allocator.free(self._current_state_script);
            self._current_state_script = &.{};
        }
    }

    pub fn setContinuationEnvelope(
        self: *StatefulSmartContract,
        prefix: ByteString,
        suffix: ByteString,
    ) StatefulRuntimeError!void {
        self.clearContinuationEnvelope();
        self._continuation_prefix = try self.allocator.dupe(u8, prefix);
        errdefer {
            self.allocator.free(self._continuation_prefix);
            self._continuation_prefix = &.{};
        }
        self._continuation_suffix = try self.allocator.dupe(u8, suffix);
    }

    pub fn clearContinuationEnvelope(self: *StatefulSmartContract) void {
        if (self._continuation_prefix.len != 0) {
            self.allocator.free(self._continuation_prefix);
            self._continuation_prefix = &.{};
        }
        if (self._continuation_suffix.len != 0) {
            self.allocator.free(self._continuation_suffix);
            self._continuation_suffix = &.{};
        }
    }

    pub fn addOutput(self: *StatefulSmartContract, satoshis: Bigint, values: anytype) StatefulRuntimeError!void {
        const copied_values = try duplicateTupleValues(self.allocator, values);
        errdefer freeOutputValues(self.allocator, copied_values);
        const state_script = try serializeOutputValueSlice(self.allocator, copied_values);
        errdefer self.allocator.free(state_script);
        const continuation_script = try wrapContinuationScript(
            self.allocator,
            self._continuation_prefix,
            state_script,
            self._continuation_suffix,
        );
        errdefer self.allocator.free(continuation_script);
        try self._outputs.append(self.allocator, .{
            .satoshis = satoshis,
            .values = copied_values,
            .stateScript = state_script,
            .continuationScript = continuation_script,
        });
    }

    pub fn addRawOutput(self: *StatefulSmartContract, satoshis: Bigint, script_bytes: ByteString) StatefulRuntimeError!void {
        const copied_values = try self.allocator.alloc(OutputValue, 0);
        errdefer self.allocator.free(copied_values);
        const continuation_script = try self.allocator.dupe(u8, script_bytes);
        errdefer self.allocator.free(continuation_script);
        try self._outputs.append(self.allocator, .{
            .satoshis = satoshis,
            .values = copied_values,
            .stateScript = &.{},
            .continuationScript = continuation_script,
        });
    }

    pub fn getStateScript(self: *const StatefulSmartContract) ByteString {
        return self._current_state_script;
    }
};

pub const StatefulContext = struct {
    runtime: *StatefulSmartContract,
    txPreimage: SigHashPreimage,

    pub fn init(runtime: *StatefulSmartContract, tx_preimage: SigHashPreimage) StatefulRuntimeError!StatefulContext {
        runtime.resetOutputs();
        try runtime.setTxPreimage(tx_preimage);
        return .{
            .runtime = runtime,
            .txPreimage = runtime.txPreimage,
        };
    }

    pub fn addOutput(self: StatefulContext, satoshis: Bigint, values: anytype) void {
        self.runtime.addOutput(satoshis, values) catch @panic("failed to record output");
    }

    pub fn addRawOutput(self: StatefulContext, satoshis: Bigint, script_bytes: ByteString) void {
        self.runtime.addRawOutput(satoshis, script_bytes) catch @panic("failed to record raw output");
    }

    pub fn getStateScript(self: StatefulContext) ByteString {
        return self.runtime.getStateScript();
    }

    pub fn outputs(self: StatefulContext) []const OutputSnapshot {
        return self.runtime.outputs();
    }

    pub fn hashOutputs(self: StatefulContext) StatefulRuntimeError!Sha256 {
        return self.runtime.hashOutputs();
    }
};

fn duplicateTupleValues(allocator: std.mem.Allocator, values: anytype) StatefulRuntimeError![]OutputValue {
    const Values = @TypeOf(values);
    const info = @typeInfo(Values);
    if (info != .@"struct" or !info.@"struct".is_tuple) {
        @compileError("addOutput expects a tuple literal like .{ value1, value2 }");
    }

    const fields = info.@"struct".fields;
    var copied = try allocator.alloc(OutputValue, fields.len);
    inline for (fields, 0..) |_, index| {
        copied[index] = try outputValueFrom(allocator, values[index]);
    }
    return copied;
}

pub fn serializeTestStateValues(allocator: std.mem.Allocator, values: anytype) StatefulRuntimeError![]u8 {
    const copied = try duplicateTupleValues(allocator, values);
    defer freeOutputValues(allocator, copied);
    return serializeOutputValueSlice(allocator, copied);
}

pub fn wrapTestContinuationScript(
    allocator: std.mem.Allocator,
    prefix: ByteString,
    values: anytype,
    suffix: ByteString,
) StatefulRuntimeError![]u8 {
    const state_script = try serializeTestStateValues(allocator, values);
    defer allocator.free(state_script);
    return wrapContinuationScript(allocator, prefix, state_script, suffix);
}

fn outputValueFrom(allocator: std.mem.Allocator, value: anytype) StatefulRuntimeError!OutputValue {
    const Value = @TypeOf(value);
    return switch (@typeInfo(Value)) {
        .bool => .{ .boolean = value },
        .int, .comptime_int => .{ .bigint = std.math.cast(i64, value) orelse return error.UnsupportedOutputValue },
        .pointer, .array => .{ .bytes = try allocator.dupe(u8, asByteSlice(value) orelse return error.UnsupportedOutputValue) },
        else => error.UnsupportedOutputValue,
    };
}

fn asByteSlice(value: anytype) ?[]const u8 {
    const Value = @TypeOf(value);
    return switch (@typeInfo(Value)) {
        .pointer => |pointer| switch (pointer.size) {
            .slice => if (pointer.child == u8) value else null,
            .one => switch (@typeInfo(pointer.child)) {
                .array => |array| if (array.child == u8) value[0..] else null,
                else => null,
            },
            else => null,
        },
        .array => |array| if (array.child == u8) value[0..] else null,
        else => null,
    };
}

fn freeOutputValues(allocator: std.mem.Allocator, values: []OutputValue) void {
    for (values) |value| value.deinit(allocator);
    allocator.free(values);
}

const test_state_magic = "rnrt";

fn serializeOutputValueSlice(allocator: std.mem.Allocator, values: []const OutputValue) StatefulRuntimeError![]u8 {
    var out = std.ArrayList(u8){};
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, test_state_magic);
    try appendU32(&out, allocator, @intCast(values.len));
    for (values) |value| {
        switch (value) {
            .bigint => |bigint| {
                try out.append(allocator, 0x01);
                var encoded: [8]u8 = undefined;
                std.mem.writeInt(i64, encoded[0..], bigint, .big);
                try out.appendSlice(allocator, &encoded);
            },
            .boolean => |boolean| {
                try out.append(allocator, 0x02);
                try out.append(allocator, if (boolean) 1 else 0);
            },
            .bytes => |bytes| {
                try out.append(allocator, 0x03);
                try appendU32(&out, allocator, @intCast(bytes.len));
                try out.appendSlice(allocator, bytes);
            },
        }
    }

    return out.toOwnedSlice(allocator);
}

fn wrapContinuationScript(
    allocator: std.mem.Allocator,
    prefix: ByteString,
    state_script: ByteString,
    suffix: ByteString,
) StatefulRuntimeError![]u8 {
    var out = std.ArrayList(u8){};
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, prefix);
    try out.appendSlice(allocator, state_script);
    try out.appendSlice(allocator, suffix);

    return out.toOwnedSlice(allocator);
}

fn serializeRecordedOutput(allocator: std.mem.Allocator, output: OutputSnapshot) StatefulRuntimeError![]u8 {
    var out = std.ArrayList(u8){};
    defer out.deinit(allocator);
    try appendRecordedOutput(&out, allocator, output);
    return out.toOwnedSlice(allocator);
}

fn buildBsvzOutputViews(
    allocator: std.mem.Allocator,
    outputs: []const OutputSnapshot,
) StatefulRuntimeError![]bsvz.transaction.Output {
    const views = try allocator.alloc(bsvz.transaction.Output, outputs.len);
    for (outputs, 0..) |output, index| {
        views[index] = .{
            .satoshis = output.satoshis,
            .locking_script = bsvz.script.Script.init(output.continuationScript),
        };
    }
    return views;
}

fn appendRecordedOutput(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    output: OutputSnapshot,
) StatefulRuntimeError!void {
    var satoshis_bytes: [8]u8 = undefined;
    std.mem.writeInt(i64, &satoshis_bytes, output.satoshis, .little);
    try out.appendSlice(allocator, &satoshis_bytes);

    var length_bytes: [9]u8 = undefined;
    const length_len = bsvz.primitives.varint.VarInt.encodeInto(length_bytes[0..], output.continuationScript.len) catch unreachable;
    try out.appendSlice(allocator, length_bytes[0..length_len]);
    try out.appendSlice(allocator, output.continuationScript);
}

fn appendU32(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32) !void {
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, encoded[0..], value, .big);
    try out.appendSlice(allocator, &encoded);
}

test "stateful runtime records and resets outputs" {
    var runtime = StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();

    try runtime.addOutput(10, .{ "alice", @as(i64, 7), true });
    try runtime.addRawOutput(5, "raw-script");
    try std.testing.expectEqual(@as(usize, 2), runtime.outputs().len);
    try std.testing.expectEqual(@as(i64, 10), runtime.outputs()[0].satoshis);
    try std.testing.expect(runtime.outputs()[0].stateScript.len != 0);
    try std.testing.expectEqualSlices(u8, runtime.outputs()[0].stateScript, runtime.outputs()[0].continuationScript);
    try std.testing.expectEqualStrings("alice", switch (runtime.outputs()[0].values[0]) {
        .bytes => |bytes| bytes,
        else => return error.TestUnexpectedResult,
    });
    try std.testing.expectEqual(@as(i64, 5), runtime.outputs()[1].satoshis);
    try std.testing.expectEqual(@as(usize, 0), runtime.outputs()[1].stateScript.len);
    try std.testing.expectEqualSlices(u8, "raw-script", runtime.outputs()[1].continuationScript);

    runtime.resetOutputs();
    try std.testing.expectEqual(@as(usize, 0), runtime.outputs().len);
}

test "Readonly returns the wrapped type unchanged" {
    try std.testing.expect(Readonly(i64) == i64);
}

test "StatefulContext exposes txPreimage and mutating output helpers" {
    var runtime = StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();

    const ctx = try StatefulContext.init(&runtime, "preimage");
    try std.testing.expectEqualStrings("preimage", ctx.txPreimage);

    ctx.addOutput(21, .{ "alice", @as(i64, 7) });
    ctx.addRawOutput(22, "raw-script");
    try std.testing.expectEqual(@as(usize, 2), ctx.outputs().len);
    try std.testing.expectEqual(@as(i64, 21), ctx.outputs()[0].satoshis);
    try std.testing.expectEqualSlices(u8, "raw-script", ctx.outputs()[1].continuationScript);
    const output_hash = try ctx.hashOutputs();
    defer std.testing.allocator.free(output_hash);
    try std.testing.expectEqual(@as(usize, 32), output_hash.len);
}

test "stateful runtime supports explicit current-state and continuation envelopes" {
    var runtime = StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();

    try runtime.setCurrentStateValues(.{ "owner", @as(i64, 25), false });
    try std.testing.expect(runtime.getStateScript().len != 0);

    try runtime.setContinuationEnvelope("code-prefix:", ":code-suffix");
    try runtime.addOutput(1, .{ "bob", @as(i64, 30), @as(i64, 0) });

    const output = runtime.outputs()[0];
    try std.testing.expect(output.stateScript.len != 0);
    try std.testing.expect(std.mem.startsWith(u8, output.continuationScript, "code-prefix:"));
    try std.testing.expect(std.mem.endsWith(u8, output.continuationScript, ":code-suffix"));
    try std.testing.expect(std.mem.indexOf(u8, output.continuationScript, output.stateScript) != null);
    const serialized = try serializeRecordedOutput(std.testing.allocator, output);
    defer std.testing.allocator.free(serialized);
    const hash = try runtime.hashOutputs();
    defer std.testing.allocator.free(hash);
    try std.testing.expectEqualSlices(u8, &bsvz.crypto.hash.hash256(serialized).bytes, hash);
}

test "serialize helpers produce explicit deterministic test state bytes" {
    const serialized = try serializeTestStateValues(std.testing.allocator, .{ "bob", @as(i64, -2), true });
    defer std.testing.allocator.free(serialized);

    try std.testing.expect(std.mem.startsWith(u8, serialized, test_state_magic));

    const continuation = try wrapTestContinuationScript(std.testing.allocator, "prefix:", .{ "bob" }, ":suffix");
    defer std.testing.allocator.free(continuation);

    try std.testing.expect(std.mem.startsWith(u8, continuation, "prefix:"));
    try std.testing.expect(std.mem.endsWith(u8, continuation, ":suffix"));
}
