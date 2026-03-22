//! Pass 6: Emit — converts Stack IR to hex-encoded Bitcoin Script and artifact JSON.
//!
//! This pass takes the StackProgram (from Pass 5: Stack Lower) and the ANFProgram
//! (for ABI metadata) and produces a complete deployment artifact containing:
//! - Hex-encoded Bitcoin Script with multi-method dispatch table
//! - Human-readable ASM representation
//! - ABI definition (constructor params, method signatures)
//! - Constructor slot positions for parameter injection
//! - State field definitions for stateful contracts

const std = @import("std");
const types = @import("../ir/types.zig");
const opcodes = @import("opcodes.zig");
const Opcode = opcodes.Opcode;

// ============================================================================
// Emit Context — accumulates hex, asm, and metadata during emission
// ============================================================================

pub const EmitContext = struct {
    /// Raw script bytes accumulated during emission.
    script_bytes: std.ArrayListUnmanaged(u8) = .empty,
    /// ASM text parts (space-separated opcode names and data representations).
    /// Static string pointers (from toName) and owned allocations are mixed.
    /// Owned allocations are tracked in owned_asm_parts for cleanup.
    asm_parts: std.ArrayListUnmanaged([]const u8) = .empty,
    /// Track which asm_parts indices were heap-allocated so we can free them.
    owned_asm_parts: std.ArrayListUnmanaged([]const u8) = .empty,
    /// Current byte offset into the script (for constructor slot tracking).
    byte_offset: u32 = 0,
    /// Constructor slot positions: (param_index, byte_offset) pairs.
    constructor_slots: std.ArrayListUnmanaged(types.ConstructorSlot) = .empty,
    /// Byte offsets of OP_CODESEPARATOR instructions.
    code_separator_indices: std.ArrayListUnmanaged(u32) = .empty,
    /// Allocator for all dynamic allocation.
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) EmitContext {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *EmitContext) void {
        self.script_bytes.deinit(self.allocator);
        for (self.owned_asm_parts.items) |part| {
            self.allocator.free(part);
        }
        self.owned_asm_parts.deinit(self.allocator);
        self.asm_parts.deinit(self.allocator);
        self.constructor_slots.deinit(self.allocator);
        self.code_separator_indices.deinit(self.allocator);
    }

    /// Emit a single opcode byte and its ASM name.
    pub fn emitOpcode(self: *EmitContext, op: Opcode) !void {
        try self.script_bytes.append(self.allocator, op.toByte());
        try self.asm_parts.append(self.allocator, opcodes.toName(op));
        self.byte_offset += 1;
        if (op == .op_codeseparator) {
            try self.code_separator_indices.append(self.allocator, self.byte_offset - 1);
        }
    }

    /// Emit a named opcode string (e.g. "OP_ADD"). Looks up byte value via byName.
    pub fn emitNamedOpcode(self: *EmitContext, name: []const u8) !void {
        const op = opcodes.byName(name) orelse return error.UnknownOpcode;
        try self.emitOpcode(op);
    }

    /// Emit raw bytes (push data) with TS-compatible minimal encoding for single-byte values.
    pub fn emitPushData(self: *EmitContext, data: []const u8) !void {
        if (data.len == 0) {
            try self.emitOpcode(.op_0);
            return;
        }

        if (data.len == 1) {
            const byte = data[0];
            if (byte >= 1 and byte <= 16) {
                try self.emitOpcode(@enumFromInt(@as(u8, 0x50 + byte)));
                return;
            }
            if (byte == 0x81) {
                try self.emitOpcode(.op_1negate);
                return;
            }
        }

        const start = self.script_bytes.items.len;
        try opcodes.encodePushData(self.script_bytes.writer(self.allocator), data);
        const bytes_written: u32 = @intCast(self.script_bytes.items.len - start);
        self.byte_offset += bytes_written;

        const hex = try opcodes.bytesToHex(self.allocator, data);
        try self.owned_asm_parts.append(self.allocator, hex);
        try self.asm_parts.append(self.allocator, hex);
    }

    /// Emit a script number with proper encoding and ASM representation.
    pub fn emitScriptNumber(self: *EmitContext, n: i64) !void {
        const start = self.script_bytes.items.len;
        try opcodes.encodeScriptNumber(self.script_bytes.writer(self.allocator), n);
        const bytes_written: u32 = @intCast(self.script_bytes.items.len - start);
        self.byte_offset += bytes_written;

        // ASM representation
        if (n == 0) {
            try self.asm_parts.append(self.allocator, "OP_0");
        } else if (n >= 1 and n <= 16) {
            const name = opcodes.toName(@enumFromInt(@as(u8, @intCast(0x50 + n))));
            try self.asm_parts.append(self.allocator, name);
        } else if (n == -1) {
            try self.asm_parts.append(self.allocator, "OP_1NEGATE");
        } else {
            // Show the decimal value
            const num_str = try std.fmt.allocPrint(self.allocator, "{d}", .{n});
            try self.owned_asm_parts.append(self.allocator, num_str);
            try self.asm_parts.append(self.allocator, num_str);
        }
    }

    /// Emit a push bool: true -> OP_TRUE (OP_1), false -> OP_FALSE (OP_0).
    pub fn emitPushBool(self: *EmitContext, b: bool) !void {
        if (b) {
            try self.emitOpcode(.op_1);
        } else {
            try self.emitOpcode(.op_0);
        }
    }

    /// Record a constructor slot at the current byte offset.
    pub fn recordConstructorSlot(self: *EmitContext, param_index: u32) !void {
        try self.constructor_slots.append(self.allocator, .{
            .param_index = param_index,
            .byte_offset = self.byte_offset,
        });
    }

    /// Get the final hex-encoded script. Caller owns the returned memory.
    pub fn getHex(self: *EmitContext) ![]u8 {
        return opcodes.bytesToHex(self.allocator, self.script_bytes.items);
    }

    /// Get the final ASM text (space-separated). Caller owns the returned memory.
    pub fn getAsm(self: *EmitContext) ![]u8 {
        if (self.asm_parts.items.len == 0) {
            return try self.allocator.dupe(u8, "");
        }
        // Calculate total length
        var total_len: usize = 0;
        for (self.asm_parts.items, 0..) |part, i| {
            total_len += part.len;
            if (i < self.asm_parts.items.len - 1) total_len += 1; // space separator
        }
        const result = try self.allocator.alloc(u8, total_len);
        var pos: usize = 0;
        for (self.asm_parts.items, 0..) |part, i| {
            @memcpy(result[pos .. pos + part.len], part);
            pos += part.len;
            if (i < self.asm_parts.items.len - 1) {
                result[pos] = ' ';
                pos += 1;
            }
        }
        return result;
    }
};

// ============================================================================
// StackOp Emission — dispatch on StackOp variant (tree-structured IR)
// ============================================================================

/// Emit a single StackOp (tree-structured, possibly nested) into the context.
pub fn emitStackOp(ctx: *EmitContext, op: types.StackOp) !void {
    switch (op) {
        .push => |pv| switch (pv) {
            .bytes => |data| try ctx.emitPushData(data),
            .integer => |n| try ctx.emitScriptNumber(n),
            .boolean => |b| try ctx.emitPushBool(b),
        },
        .dup => try ctx.emitOpcode(.op_dup),
        .swap => try ctx.emitOpcode(.op_swap),
        .drop => try ctx.emitOpcode(.op_drop),
        .nip => try ctx.emitOpcode(.op_nip),
        .over => try ctx.emitOpcode(.op_over),
        .rot => try ctx.emitOpcode(.op_rot),
        .tuck => try ctx.emitOpcode(.op_tuck),
        .roll => |depth| {
            try ctx.emitScriptNumber(@intCast(depth));
            try ctx.emitOpcode(.op_roll);
        },
        .pick => |depth| {
            try ctx.emitScriptNumber(@intCast(depth));
            try ctx.emitOpcode(.op_pick);
        },
        .opcode => |name| try ctx.emitNamedOpcode(name),
        .@"if" => |if_op| {
            try ctx.emitOpcode(.op_if);
            for (if_op.then) |then_op| {
                try emitStackOp(ctx, then_op);
            }
            if (if_op.@"else") |else_ops| {
                try ctx.emitOpcode(.op_else);
                for (else_ops) |else_op| {
                    try emitStackOp(ctx, else_op);
                }
            }
            try ctx.emitOpcode(.op_endif);
        },
        .placeholder => |ph| {
            // Record the slot position, then emit a zero placeholder that will be patched
            try ctx.recordConstructorSlot(ph.param_index);
            try ctx.emitOpcode(.op_0); // placeholder byte, overwritten at deployment
        },
    }
}

/// Emit a single flat StackInstruction into the context.
pub fn emitStackInstruction(ctx: *EmitContext, inst: types.StackInstruction) !void {
    switch (inst) {
        .op => |opcode| try ctx.emitOpcode(opcode),
        .push_data => |data| try ctx.emitPushData(data),
        .push_int => |n| try ctx.emitScriptNumber(n),
        .push_bool => |b| try ctx.emitPushBool(b),
    }
}

// ============================================================================
// Method Script Emission
// ============================================================================

/// Emit a single method's flat instructions to hex script. Caller owns the returned memory.
pub fn emitMethodScript(allocator: std.mem.Allocator, instructions: []const types.StackInstruction) ![]const u8 {
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    for (instructions) |inst| {
        try emitStackInstruction(&ctx, inst);
    }

    return try ctx.getHex();
}

/// Emit a single method's tree-structured StackOps to hex script. Caller owns the returned memory.
pub fn emitMethodOps(allocator: std.mem.Allocator, ops: []const types.StackOp) ![]const u8 {
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    for (ops) |op| {
        try emitStackOp(&ctx, op);
    }

    return try ctx.getHex();
}

fn emitMethodBody(ctx: *EmitContext, method: types.StackMethod) !void {
    if (method.instructions.len > 0) {
        for (method.instructions) |inst| {
            try emitStackInstruction(ctx, inst);
        }
        return;
    }

    for (method.ops) |op| {
        try emitStackOp(ctx, op);
    }
}

// ============================================================================
// Multi-Method Dispatch Table
// ============================================================================

/// Emit the dispatch table for a multi-method contract.
/// Pattern: OP_DUP <idx> OP_NUMEQUAL OP_IF OP_DROP <body> OP_ELSE ... OP_ENDIF
/// For a single method, no dispatch table is needed — just emit the body.
fn emitDispatchTable(ctx: *EmitContext, methods: []const types.StackMethod) !void {
    if (methods.len == 0) return;

    if (methods.len == 1) {
        // Single method: no dispatch needed, just emit the body
        try emitMethodBody(ctx, methods[0]);
        return;
    }

    // Multi-method dispatch:
    // The method index is expected on top of the stack.
    // OP_DUP <0> OP_NUMEQUAL OP_IF OP_DROP <body0> OP_ELSE
    //   OP_DUP <1> OP_NUMEQUAL OP_IF OP_DROP <body1> OP_ELSE
    //     ...
    //     OP_DUP <N-1> OP_NUMEQUAL OP_IF OP_DROP <bodyN-1> OP_ELSE OP_RETURN OP_ENDIF
    //   OP_ENDIF
    // OP_ENDIF

    for (methods, 0..) |method, i| {
        try ctx.emitOpcode(.op_dup);
        try ctx.emitScriptNumber(@intCast(i));
        try ctx.emitOpcode(.op_numequal);
        try ctx.emitOpcode(.op_if);
        try ctx.emitOpcode(.op_drop); // consume the method index

        // Emit method body
        try emitMethodBody(ctx, method);

        if (i < methods.len - 1) {
            try ctx.emitOpcode(.op_else);
        } else {
            // Last method: else branch is OP_RETURN (invalid method index)
            try ctx.emitOpcode(.op_else);
            try ctx.emitOpcode(.op_return);
            try ctx.emitOpcode(.op_endif);
        }
    }

    // Close all the nested if/else blocks (one OP_ENDIF per method except last which already closed)
    var closes: usize = methods.len - 1;
    while (closes > 0) : (closes -= 1) {
        try ctx.emitOpcode(.op_endif);
    }
}

// ============================================================================
// Artifact JSON Emission
// ============================================================================

/// Write a JSON string value, escaping special characters.
fn writeJsonString(writer: anytype, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0x08 => try writer.writeAll("\\b"),
            0x0C => try writer.writeAll("\\f"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
    try writer.writeByte('"');
}

/// Produce the full artifact JSON from a StackProgram and ANFProgram.
/// Returns a JSON string. Caller owns the returned memory.
pub fn emitArtifact(
    allocator: std.mem.Allocator,
    stack_program: types.StackProgram,
    anf_program: types.ANFProgram,
) ![]const u8 {
    // Emit script with dispatch table
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    // Emit OP_CODESEPARATOR before the dispatch table
    try ctx.emitOpcode(.op_codeseparator);

    // Emit multi-method dispatch
    try emitDispatchTable(&ctx, stack_program.methods);

    const script_hex = try ctx.getHex();
    defer allocator.free(script_hex);

    const asm_text = try ctx.getAsm();
    defer allocator.free(asm_text);

    // Build JSON output
    var json_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer json_buf.deinit(allocator);
    const w = json_buf.writer(allocator);

    try w.writeAll("{");

    // version
    try w.writeAll("\"version\":\"runar-v0.1.0\",");

    // compilerVersion
    try w.writeAll("\"compilerVersion\":\"runar-zig-0.2.7\",");

    // contract
    try w.writeAll("\"contract\":");
    try writeJsonString(w, stack_program.contract_name);
    try w.writeByte(',');

    // abi
    try w.writeAll("\"abi\":{");

    // abi.constructor — extract from ANF properties (constructor params are readonly properties)
    try w.writeAll("\"constructor\":{\"params\":[");
    {
        var first = true;
        for (anf_program.properties) |prop| {
            if (prop.readonly) {
                if (!first) try w.writeByte(',');
                first = false;
                try w.writeAll("{\"name\":");
                try writeJsonString(w, prop.name);
                try w.writeAll(",\"type\":");
                try writeJsonString(w, prop.type_name);
                try w.writeByte('}');
            }
        }
    }
    try w.writeAll("]},");

    // abi.methods
    try w.writeAll("\"methods\":[");
    for (anf_program.methods, 0..) |method, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"name\":");
        try writeJsonString(w, method.name);
        try w.writeAll(",\"params\":[");
        for (method.params, 0..) |param, j| {
            if (j > 0) try w.writeByte(',');
            try w.writeAll("{\"name\":");
            try writeJsonString(w, param.name);
            try w.writeAll(",\"type\":");
            try writeJsonString(w, param.type_name);
            try w.writeByte('}');
        }
        try w.writeAll("],\"index\":");
        try w.print("{d}", .{i});
        try w.writeAll(",\"public\":");
        try w.writeAll(if (method.is_public) "true" else "false");
        try w.writeByte('}');
    }
    try w.writeAll("]},");

    // hex
    try w.writeAll("\"hex\":");
    try writeJsonString(w, script_hex);
    try w.writeByte(',');

    // asm
    try w.writeAll("\"asm\":");
    try writeJsonString(w, asm_text);
    try w.writeByte(',');

    // constructorSlots
    try w.writeAll("\"constructorSlots\":[");
    for (ctx.constructor_slots.items, 0..) |slot, i| {
        if (i > 0) try w.writeByte(',');
        try w.print("{{\"paramIndex\":{d},\"byteOffset\":{d}}}", .{ slot.param_index, slot.byte_offset });
    }
    try w.writeAll("],");

    // stateFields — mutable (non-readonly) properties
    try w.writeAll("\"stateFields\":[");
    {
        var state_idx: u32 = 0;
        for (anf_program.properties) |prop| {
            if (!prop.readonly) {
                if (state_idx > 0) try w.writeByte(',');
                try w.writeAll("{\"name\":");
                try writeJsonString(w, prop.name);
                try w.writeAll(",\"type\":");
                try writeJsonString(w, prop.type_name);
                try w.print(",\"index\":{d}}}", .{state_idx});
                state_idx += 1;
            }
        }
    }
    try w.writeAll("],");

    // codeSeparatorIndex
    try w.writeAll("\"codeSeparatorIndex\":");
    if (ctx.code_separator_indices.items.len > 0) {
        try w.print("{d}", .{ctx.code_separator_indices.items[0]});
    } else {
        try w.writeAll("0");
    }

    try w.writeByte('}');

    return try json_buf.toOwnedSlice(allocator);
}

// ============================================================================
// Tests
// ============================================================================

test "emitStackInstruction — opcode" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackInstruction(&ctx, .{ .op = .op_dup });
    try std.testing.expectEqualSlices(u8, &.{0x76}, ctx.script_bytes.items);
    try std.testing.expectEqual(@as(usize, 1), ctx.asm_parts.items.len);
    try std.testing.expectEqualStrings("OP_DUP", ctx.asm_parts.items[0]);
}

test "emitStackInstruction — push_int small" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackInstruction(&ctx, .{ .push_int = 5 });
    try std.testing.expectEqualSlices(u8, &.{0x55}, ctx.script_bytes.items);
    try std.testing.expectEqualStrings("OP_5", ctx.asm_parts.items[0]);
}

test "emitStackInstruction — push_int zero" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackInstruction(&ctx, .{ .push_int = 0 });
    try std.testing.expectEqualSlices(u8, &.{0x00}, ctx.script_bytes.items);
    try std.testing.expectEqualStrings("OP_0", ctx.asm_parts.items[0]);
}

test "emitStackInstruction — push_int negative one" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackInstruction(&ctx, .{ .push_int = -1 });
    try std.testing.expectEqualSlices(u8, &.{0x4f}, ctx.script_bytes.items);
    try std.testing.expectEqualStrings("OP_1NEGATE", ctx.asm_parts.items[0]);
}

test "emitStackInstruction — push_int large" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackInstruction(&ctx, .{ .push_int = 1000 });
    // 1000 = 0x03E8 LE -> e8 03, push: 02 e8 03
    try std.testing.expectEqualSlices(u8, &.{ 0x02, 0xe8, 0x03 }, ctx.script_bytes.items);
    try std.testing.expectEqualStrings("1000", ctx.asm_parts.items[0]);
}

test "emitStackInstruction — push_bool true" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackInstruction(&ctx, .{ .push_bool = true });
    try std.testing.expectEqualSlices(u8, &.{0x51}, ctx.script_bytes.items);
    try std.testing.expectEqualStrings("OP_1", ctx.asm_parts.items[0]);
}

test "emitStackInstruction — push_bool false" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackInstruction(&ctx, .{ .push_bool = false });
    try std.testing.expectEqualSlices(u8, &.{0x00}, ctx.script_bytes.items);
    try std.testing.expectEqualStrings("OP_0", ctx.asm_parts.items[0]);
}

test "emitStackInstruction — push_data" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackInstruction(&ctx, .{ .push_data = &.{ 0xaa, 0xbb, 0xcc } });
    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0xaa, 0xbb, 0xcc }, ctx.script_bytes.items);
    try std.testing.expectEqualStrings("aabbcc", ctx.asm_parts.items[0]);
}

test "emitStackInstruction — push_data uses OP_N for single-byte 1 through 16" {
    const allocator = std.testing.allocator;

    var value: u8 = 1;
    while (value <= 16) : (value += 1) {
        var ctx = EmitContext.init(allocator);
        defer ctx.deinit();

        try emitStackInstruction(&ctx, .{ .push_data = &.{value} });
        try std.testing.expectEqualSlices(u8, &.{@as(u8, 0x50 + value)}, ctx.script_bytes.items);
        const expected = try std.fmt.allocPrint(allocator, "OP_{d}", .{value});
        defer allocator.free(expected);
        try std.testing.expectEqualStrings(expected, ctx.asm_parts.items[0]);
    }
}

test "emitStackInstruction — push_data uses OP_1NEGATE for 0x81" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackInstruction(&ctx, .{ .push_data = &.{0x81} });
    try std.testing.expectEqualSlices(u8, &.{0x4f}, ctx.script_bytes.items);
    try std.testing.expectEqualStrings("OP_1NEGATE", ctx.asm_parts.items[0]);
}

test "emitStackOp — dup/swap/drop/nip/over/rot/tuck" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackOp(&ctx, .{ .dup = {} });
    try emitStackOp(&ctx, .{ .swap = {} });
    try emitStackOp(&ctx, .{ .drop = {} });
    try emitStackOp(&ctx, .{ .nip = {} });
    try emitStackOp(&ctx, .{ .over = {} });
    try emitStackOp(&ctx, .{ .rot = {} });
    try emitStackOp(&ctx, .{ .tuck = {} });

    try std.testing.expectEqualSlices(u8, &.{ 0x76, 0x7c, 0x75, 0x77, 0x78, 0x7b, 0x7d }, ctx.script_bytes.items);
}

test "emitStackOp — roll and pick" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackOp(&ctx, .{ .roll = 3 });
    try emitStackOp(&ctx, .{ .pick = 2 });

    // roll 3: push 3 (OP_3=0x53), OP_ROLL=0x7a
    // pick 2: push 2 (OP_2=0x52), OP_PICK=0x79
    try std.testing.expectEqualSlices(u8, &.{ 0x53, 0x7a, 0x52, 0x79 }, ctx.script_bytes.items);
}

test "emitStackOp — opcode by name" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackOp(&ctx, .{ .opcode = "OP_ADD" });
    try emitStackOp(&ctx, .{ .opcode = "OP_CHECKSIG" });

    try std.testing.expectEqualSlices(u8, &.{ 0x93, 0xac }, ctx.script_bytes.items);
}

test "emitStackOp — push values" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackOp(&ctx, .{ .push = .{ .integer = 42 } });
    try emitStackOp(&ctx, .{ .push = .{ .boolean = true } });
    try emitStackOp(&ctx, .{ .push = .{ .bytes = &.{ 0xab, 0xcd } } });

    // 42: push 01 2a
    // true: OP_1 = 51
    // bytes: push 02 ab cd
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x2a, 0x51, 0x02, 0xab, 0xcd }, ctx.script_bytes.items);
}

test "emitStackOp — if/else" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    var then_ops = [_]types.StackOp{.{ .opcode = "OP_ADD" }};
    var else_ops = [_]types.StackOp{.{ .opcode = "OP_SUB" }};

    try emitStackOp(&ctx, .{ .@"if" = .{
        .then = &then_ops,
        .@"else" = &else_ops,
    } });

    // OP_IF(63) OP_ADD(93) OP_ELSE(67) OP_SUB(94) OP_ENDIF(68)
    try std.testing.expectEqualSlices(u8, &.{ 0x63, 0x93, 0x67, 0x94, 0x68 }, ctx.script_bytes.items);
}

test "emitStackOp — if without else" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    var then_ops = [_]types.StackOp{.{ .opcode = "OP_VERIFY" }};

    try emitStackOp(&ctx, .{ .@"if" = .{
        .then = &then_ops,
        .@"else" = null,
    } });

    // OP_IF(63) OP_VERIFY(69) OP_ENDIF(68)
    try std.testing.expectEqualSlices(u8, &.{ 0x63, 0x69, 0x68 }, ctx.script_bytes.items);
}

test "emitStackOp — placeholder" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try ctx.emitOpcode(.op_dup); // offset 0 -> 1
    try emitStackOp(&ctx, .{ .placeholder = .{ .param_index = 0, .param_name = "owner" } });

    try std.testing.expectEqual(@as(usize, 1), ctx.constructor_slots.items.len);
    try std.testing.expectEqual(@as(u32, 1), ctx.constructor_slots.items[0].byte_offset);
    try std.testing.expectEqual(@as(u32, 0), ctx.constructor_slots.items[0].param_index);
}

test "emitMethodScript — P2PKH pattern" {
    const allocator = std.testing.allocator;

    const instructions = [_]types.StackInstruction{
        .{ .op = .op_dup },
        .{ .op = .op_hash160 },
        .{ .push_data = &.{ 0xaa, 0xbb, 0xcc } },
        .{ .op = .op_equalverify },
        .{ .op = .op_checksig },
    };

    const hex = try emitMethodScript(allocator, &instructions);
    defer allocator.free(hex);

    try std.testing.expectEqualStrings("76a903aabbcc88ac", hex);
}

test "emitMethodScript — empty" {
    const allocator = std.testing.allocator;
    const hex = try emitMethodScript(allocator, &.{});
    defer allocator.free(hex);
    try std.testing.expectEqualStrings("", hex);
}

test "emitMethodScript — mixed ops and values" {
    const allocator = std.testing.allocator;

    const instructions = [_]types.StackInstruction{
        .{ .push_int = 3 },
        .{ .push_int = 5 },
        .{ .op = .op_add },
        .{ .push_int = 8 },
        .{ .op = .op_numequal },
    };

    const hex = try emitMethodScript(allocator, &instructions);
    defer allocator.free(hex);

    // OP_3=53, OP_5=55, OP_ADD=93, OP_8=58, OP_NUMEQUAL=9c
    try std.testing.expectEqualStrings("535593589c", hex);
}

test "emitMethodScript — booleans" {
    const allocator = std.testing.allocator;

    const instructions = [_]types.StackInstruction{
        .{ .push_bool = true },
        .{ .push_bool = false },
        .{ .op = .op_booland },
    };

    const hex = try emitMethodScript(allocator, &instructions);
    defer allocator.free(hex);

    // OP_1=51, OP_0=00, OP_BOOLAND=9a
    try std.testing.expectEqualStrings("51009a", hex);
}

test "emitMethodOps — tree-structured" {
    const allocator = std.testing.allocator;

    var then_ops = [_]types.StackOp{.{ .opcode = "OP_ADD" }};
    var else_ops = [_]types.StackOp{.{ .opcode = "OP_SUB" }};

    const ops = [_]types.StackOp{
        .{ .push = .{ .integer = 1 } },
        .{ .@"if" = .{ .then = &then_ops, .@"else" = &else_ops } },
    };

    const hex = try emitMethodOps(allocator, &ops);
    defer allocator.free(hex);

    // OP_1(51) OP_IF(63) OP_ADD(93) OP_ELSE(67) OP_SUB(94) OP_ENDIF(68)
    try std.testing.expectEqualStrings("516393679468", hex);
}

test "EmitContext — code separator tracking" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try ctx.emitOpcode(.op_dup); // offset 0
    try ctx.emitOpcode(.op_codeseparator); // offset 1
    try ctx.emitOpcode(.op_checksig); // offset 2

    try std.testing.expectEqual(@as(usize, 1), ctx.code_separator_indices.items.len);
    try std.testing.expectEqual(@as(u32, 1), ctx.code_separator_indices.items[0]);
}

test "EmitContext — constructor slot recording" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try ctx.emitOpcode(.op_dup); // 1 byte
    try ctx.recordConstructorSlot(0);
    try ctx.emitPushData(&.{ 0x01, 0x02 }); // 3 bytes (1 len + 2 data)
    try ctx.recordConstructorSlot(1);

    try std.testing.expectEqual(@as(usize, 2), ctx.constructor_slots.items.len);
    try std.testing.expectEqual(@as(u32, 1), ctx.constructor_slots.items[0].byte_offset);
    try std.testing.expectEqual(@as(u32, 0), ctx.constructor_slots.items[0].param_index);
    try std.testing.expectEqual(@as(u32, 4), ctx.constructor_slots.items[1].byte_offset);
    try std.testing.expectEqual(@as(u32, 1), ctx.constructor_slots.items[1].param_index);
}

test "EmitContext — getAsm" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try ctx.emitOpcode(.op_dup);
    try ctx.emitOpcode(.op_hash160);
    try ctx.emitOpcode(.op_equalverify);

    const asm_text = try ctx.getAsm();
    defer allocator.free(asm_text);

    try std.testing.expectEqualStrings("OP_DUP OP_HASH160 OP_EQUALVERIFY", asm_text);
}

test "EmitContext — getAsm empty" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    const asm_text = try ctx.getAsm();
    defer allocator.free(asm_text);

    try std.testing.expectEqualStrings("", asm_text);
}

test "dispatch table — single method (no dispatch)" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    var body = [_]types.StackOp{
        .{ .opcode = "OP_DUP" },
        .{ .opcode = "OP_CHECKSIG" },
    };
    const methods = [_]types.StackMethod{
        .{ .name = "unlock", .ops = &body, .max_stack_depth = 2 },
    };

    try emitDispatchTable(&ctx, &methods);

    const hex = try ctx.getHex();
    defer allocator.free(hex);

    // Single method: just the body, no dispatch overhead
    // OP_DUP=76, OP_CHECKSIG=ac
    try std.testing.expectEqualStrings("76ac", hex);
}

test "dispatch table — two methods" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    var body0 = [_]types.StackOp{.{ .opcode = "OP_ADD" }};
    var body1 = [_]types.StackOp{.{ .opcode = "OP_SUB" }};
    const methods = [_]types.StackMethod{
        .{ .name = "add", .ops = &body0, .max_stack_depth = 2 },
        .{ .name = "sub", .ops = &body1, .max_stack_depth = 2 },
    };

    try emitDispatchTable(&ctx, &methods);

    const hex = try ctx.getHex();
    defer allocator.free(hex);

    // Expected pattern:
    // OP_DUP(76) OP_0(00) OP_NUMEQUAL(9c) OP_IF(63) OP_DROP(75) OP_ADD(93) OP_ELSE(67)
    // OP_DUP(76) OP_1(51) OP_NUMEQUAL(9c) OP_IF(63) OP_DROP(75) OP_SUB(94) OP_ELSE(67) OP_RETURN(6a) OP_ENDIF(68)
    // OP_ENDIF(68)
    try std.testing.expectEqualStrings("76009c6375936776519c637594676a6868", hex);

    const asm_text = try ctx.getAsm();
    defer allocator.free(asm_text);

    try std.testing.expectEqualStrings(
        "OP_DUP OP_0 OP_NUMEQUAL OP_IF OP_DROP OP_ADD OP_ELSE OP_DUP OP_1 OP_NUMEQUAL OP_IF OP_DROP OP_SUB OP_ELSE OP_RETURN OP_ENDIF OP_ENDIF",
        asm_text,
    );
}

test "dispatch table — three methods" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    var body0 = [_]types.StackOp{.{ .opcode = "OP_ADD" }};
    var body1 = [_]types.StackOp{.{ .opcode = "OP_SUB" }};
    var body2 = [_]types.StackOp{.{ .opcode = "OP_MUL" }};
    const methods = [_]types.StackMethod{
        .{ .name = "add", .ops = &body0, .max_stack_depth = 2 },
        .{ .name = "sub", .ops = &body1, .max_stack_depth = 2 },
        .{ .name = "mul", .ops = &body2, .max_stack_depth = 2 },
    };

    try emitDispatchTable(&ctx, &methods);

    const hex = try ctx.getHex();
    defer allocator.free(hex);

    // method 0: DUP 0 NUMEQUAL IF DROP ADD ELSE
    // method 1: DUP 1 NUMEQUAL IF DROP SUB ELSE
    // method 2: DUP 2 NUMEQUAL IF DROP MUL ELSE RETURN ENDIF
    // close:    ENDIF ENDIF
    const expected = "76009c6375936776519c6375946776529c637595676a686868";
    try std.testing.expectEqualStrings(expected, hex);
}

test "dispatch table — empty methods list" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitDispatchTable(&ctx, &.{});

    try std.testing.expectEqual(@as(usize, 0), ctx.script_bytes.items.len);
}

test "emitArtifact — simple contract" {
    const allocator = std.testing.allocator;

    var body = [_]types.StackOp{
        .{ .opcode = "OP_DUP" },
        .{ .opcode = "OP_HASH160" },
        .{ .opcode = "OP_EQUALVERIFY" },
        .{ .opcode = "OP_CHECKSIG" },
    };
    var stack_methods = [_]types.StackMethod{
        .{ .name = "unlock", .ops = &body, .max_stack_depth = 4 },
    };

    var anf_params = [_]types.ANFParam{
        .{ .name = "sig", .type_name = "Sig" },
        .{ .name = "pubKey", .type_name = "PubKey" },
    };

    var anf_methods = [_]types.ANFMethod{
        .{
            .name = "unlock",
            .is_public = true,
            .params = &anf_params,
            .bindings = &.{},
        },
    };

    var properties = [_]types.ANFProperty{
        .{ .name = "pubKeyHash", .type_name = "Ripemd160", .readonly = true },
    };

    const stack_program = types.StackProgram{
        .methods = &stack_methods,
        .contract_name = "P2PKH",
    };

    const anf_program = types.ANFProgram{
        .contract_name = "P2PKH",
        .properties = &properties,
        .methods = &anf_methods,
    };

    const json = try emitArtifact(allocator, stack_program, anf_program);
    defer allocator.free(json);

    // Verify it contains expected fields
    try std.testing.expect(std.mem.indexOf(u8, json, "\"contract\":\"P2PKH\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"hex\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"asm\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"abi\":{") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"constructor\":{\"params\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"pubKeyHash\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"Ripemd160\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"methods\":[{\"name\":\"unlock\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"public\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"codeSeparatorIndex\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"stateFields\":[]") != null);

    // The script should start with OP_CODESEPARATOR (ab) then the body
    // ab 76 a9 88 ac -> "ab76a988ac"
    try std.testing.expect(std.mem.indexOf(u8, json, "ab76a988ac") != null);
}

test "emitArtifact — stateful contract with state fields" {
    const allocator = std.testing.allocator;

    var body = [_]types.StackOp{
        .{ .opcode = "OP_1ADD" },
        .{ .opcode = "OP_VERIFY" },
    };
    var stack_methods = [_]types.StackMethod{
        .{ .name = "increment", .ops = &body, .max_stack_depth = 2 },
    };

    var anf_methods = [_]types.ANFMethod{
        .{
            .name = "increment",
            .is_public = true,
            .params = &.{},
            .bindings = &.{},
        },
    };

    var properties = [_]types.ANFProperty{
        .{ .name = "count", .type_name = "bigint", .readonly = false },
        .{ .name = "owner", .type_name = "PubKey", .readonly = true },
    };

    const stack_program = types.StackProgram{
        .methods = &stack_methods,
        .contract_name = "Counter",
    };

    const anf_program = types.ANFProgram{
        .contract_name = "Counter",
        .properties = &properties,
        .methods = &anf_methods,
    };

    const json = try emitArtifact(allocator, stack_program, anf_program);
    defer allocator.free(json);

    // Stateful: only non-readonly properties are state fields
    try std.testing.expect(std.mem.indexOf(u8, json, "\"stateFields\":[{\"name\":\"count\",\"type\":\"bigint\",\"index\":0}]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"contract\":\"Counter\"") != null);
    // Constructor params = readonly properties = owner only
    try std.testing.expect(std.mem.indexOf(u8, json, "\"constructor\":{\"params\":[{\"name\":\"owner\",\"type\":\"PubKey\"}]}") != null);
}

test "writeJsonString — escaping" {
    const allocator = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    const w = buf.writer(allocator);

    try writeJsonString(w, "hello \"world\"");
    try std.testing.expectEqualStrings("\"hello \\\"world\\\"\"", buf.items);

    buf.clearRetainingCapacity();
    try writeJsonString(w, "line1\nline2");
    try std.testing.expectEqualStrings("\"line1\\nline2\"", buf.items);

    buf.clearRetainingCapacity();
    try writeJsonString(w, "back\\slash");
    try std.testing.expectEqualStrings("\"back\\\\slash\"", buf.items);
}

test "push value encoding — bigint 0 uses OP_0" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackOp(&ctx, .{ .push = .{ .integer = 0 } });
    try std.testing.expectEqualSlices(u8, &.{0x00}, ctx.script_bytes.items);
}

test "push value encoding — bigint 1 through 16 uses OP_N" {
    const allocator = std.testing.allocator;

    var i: i64 = 1;
    while (i <= 16) : (i += 1) {
        var ctx = EmitContext.init(allocator);
        defer ctx.deinit();

        try emitStackOp(&ctx, .{ .push = .{ .integer = i } });
        try std.testing.expectEqual(@as(usize, 1), ctx.script_bytes.items.len);
        const expected_byte: u8 = @intCast(0x50 + @as(u8, @intCast(i)));
        try std.testing.expectEqual(expected_byte, ctx.script_bytes.items[0]);
    }
}

test "push value encoding — -1 uses OP_1NEGATE" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackOp(&ctx, .{ .push = .{ .integer = -1 } });
    try std.testing.expectEqualSlices(u8, &.{0x4f}, ctx.script_bytes.items);
}

test "push value encoding — bool true is OP_1" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackOp(&ctx, .{ .push = .{ .boolean = true } });
    try std.testing.expectEqualSlices(u8, &.{0x51}, ctx.script_bytes.items);
}

test "push value encoding — bool false is OP_0" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try emitStackOp(&ctx, .{ .push = .{ .boolean = false } });
    try std.testing.expectEqualSlices(u8, &.{0x00}, ctx.script_bytes.items);
}

test "byte offset tracking" {
    const allocator = std.testing.allocator;
    var ctx = EmitContext.init(allocator);
    defer ctx.deinit();

    try ctx.emitOpcode(.op_dup); // 1 byte
    try std.testing.expectEqual(@as(u32, 1), ctx.byte_offset);

    try ctx.emitPushData(&.{ 0x01, 0x02, 0x03 }); // 1 len + 3 data = 4 bytes
    try std.testing.expectEqual(@as(u32, 5), ctx.byte_offset);

    try ctx.emitScriptNumber(7); // OP_7 = 1 byte
    try std.testing.expectEqual(@as(u32, 6), ctx.byte_offset);

    try ctx.emitScriptNumber(1000); // 1 len + 2 data = 3 bytes
    try std.testing.expectEqual(@as(u32, 9), ctx.byte_offset);
}
