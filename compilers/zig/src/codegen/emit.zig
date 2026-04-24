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
    /// CodeSepIndex placeholder slots: OP_0 placeholders that the SDK replaces
    /// with the adjusted codeSeparatorIndex at deployment time.
    code_sep_index_slots: std.ArrayListUnmanaged(types.CodeSepIndexSlot) = .empty,
    /// Byte offsets of OP_CODESEPARATOR instructions.
    code_separator_indices: std.ArrayListUnmanaged(u32) = .empty,
    /// Source map: records which opcode corresponds to which source location.
    source_map: std.ArrayListUnmanaged(types.SourceMapping) = .empty,
    /// Pending source location to record on the next emitted opcode.
    pending_source_loc: ?types.SourceLocation = null,
    /// Current opcode index (incremented per emitted instruction).
    opcode_index: u32 = 0,
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
        self.code_sep_index_slots.deinit(self.allocator);
        self.code_separator_indices.deinit(self.allocator);
        self.source_map.deinit(self.allocator);
    }

    /// Record a source mapping for the current opcode if a source location is pending.
    fn recordSourceMapping(self: *EmitContext) !void {
        if (self.pending_source_loc) |loc| {
            try self.source_map.append(self.allocator, .{
                .opcode_index = self.opcode_index,
                .source_file = loc.file,
                .line = loc.line,
                .column = loc.column,
            });
            self.pending_source_loc = null;
        }
    }

    /// Emit a single opcode byte and its ASM name.
    pub fn emitOpcode(self: *EmitContext, op: Opcode) !void {
        try self.recordSourceMapping();
        try self.script_bytes.append(self.allocator, op.toByte());
        try self.asm_parts.append(self.allocator, opcodes.toName(op));
        self.byte_offset += 1;
        self.opcode_index += 1;
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

        try self.recordSourceMapping();
        const start = self.script_bytes.items.len;
        const pd_writer = opcodes.ArrayListWriter{ .list = &self.script_bytes, .allocator = self.allocator };
        try opcodes.encodePushData(pd_writer, data);
        const bytes_written: u32 = @intCast(self.script_bytes.items.len - start);
        self.byte_offset += bytes_written;
        self.opcode_index += 1;

        const hex = try opcodes.bytesToHex(self.allocator, data);
        try self.owned_asm_parts.append(self.allocator, hex);
        try self.asm_parts.append(self.allocator, hex);
    }

    /// Emit a script number with proper encoding and ASM representation.
    pub fn emitScriptNumber(self: *EmitContext, n: i64) !void {
        try self.recordSourceMapping();
        const start = self.script_bytes.items.len;
        const sn_writer = opcodes.ArrayListWriter{ .list = &self.script_bytes, .allocator = self.allocator };
        try opcodes.encodeScriptNumber(sn_writer, n);
        const bytes_written: u32 = @intCast(self.script_bytes.items.len - start);
        self.byte_offset += bytes_written;
        self.opcode_index += 1;

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
    /// Note: delegates to emitOpcode which handles recordSourceMapping + opcode_index.
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
        .push_codesep_index => {
            // Emit an OP_0 placeholder that the SDK will replace with the
            // adjusted codeSeparatorIndex at runtime.
            const code_sep_idx: usize = if (ctx.code_separator_indices.items.len > 0)
                @intCast(ctx.code_separator_indices.items[ctx.code_separator_indices.items.len - 1])
            else
                0;
            const byte_off = ctx.byte_offset;
            try ctx.recordSourceMapping();
            try ctx.script_bytes.append(ctx.allocator, 0x00); // OP_0 placeholder byte
            try ctx.asm_parts.append(ctx.allocator, "OP_0");
            ctx.byte_offset += 1;
            ctx.opcode_index += 1;
            try ctx.code_sep_index_slots.append(ctx.allocator, .{
                .byte_offset = byte_off,
                .code_sep_index = code_sep_idx,
            });
        },
        .placeholder => |ph| {
            try ctx.recordConstructorSlot(ph.param_index);
            try ctx.emitOpcode(.op_0);
        },
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
        for (method.instructions, 0..) |inst, i| {
            // Set pending source location from the parallel array (if available).
            // After peephole optimization the array may be shorter or absent.
            if (i < method.instruction_source_locs.len) {
                if (method.instruction_source_locs[i]) |loc| {
                    ctx.pending_source_loc = loc;
                }
            }
            try emitStackInstruction(ctx, inst);
        }
        return;
    }

    for (method.ops) |op| {
        try emitStackOp(ctx, op);
    }
}

/// Emit a method body with a given source location applied to the first instruction.
/// Used when per-instruction source locs are not available (e.g. after peephole).
fn emitMethodBodyWithLoc(ctx: *EmitContext, method: types.StackMethod, loc: ?types.SourceLocation) !void {
    if (loc) |l| ctx.pending_source_loc = l;
    try emitMethodBody(ctx, method);
}

// ============================================================================
// Multi-Method Dispatch Table
// ============================================================================

/// Find the first non-null source_loc from a method's ANF bindings.
fn findMethodSourceLoc(anf_methods: []const types.ANFMethod, method_name: []const u8) ?types.SourceLocation {
    for (anf_methods) |m| {
        if (std.mem.eql(u8, m.name, method_name)) {
            for (m.body) |binding| {
                if (binding.source_loc) |loc| return loc;
            }
        }
    }
    return null;
}

/// Emit dispatch table with source map support (looks up source locs from ANF methods).
///
/// Mirrors the TS reference compiler's emitMethodDispatch
/// (packages/runar-compiler/src/passes/06-emit.ts).
///
/// Pattern (N >= 2 public methods):
///   OP_DUP <0> OP_NUMEQUAL OP_IF OP_DROP <body0> OP_ELSE
///     OP_DUP <1> OP_NUMEQUAL OP_IF OP_DROP <body1> OP_ELSE
///       ...
///       <N-1> OP_NUMEQUALVERIFY <bodyN-1>
///     OP_ENDIF
///   OP_ENDIF (×(N-1) total ENDIFs)
fn emitDispatchTableWithSourceMap(ctx: *EmitContext, methods: []const types.StackMethod, anf_methods: []const types.ANFMethod) !void {
    if (methods.len == 0) return;

    if (methods.len == 1) {
        ctx.pending_source_loc = findMethodSourceLoc(anf_methods, methods[0].name);
        try emitMethodBody(ctx, methods[0]);
        return;
    }

    for (methods, 0..) |method, i| {
        const is_last = i == methods.len - 1;
        if (!is_last) {
            try ctx.emitOpcode(.op_dup);
            try ctx.emitScriptNumber(@intCast(i));
            try ctx.emitOpcode(.op_numequal);
            try ctx.emitOpcode(.op_if);
            try ctx.emitOpcode(.op_drop);
        } else {
            try ctx.emitScriptNumber(@intCast(i));
            try ctx.emitOpcode(.op_numequalverify);
        }
        ctx.pending_source_loc = findMethodSourceLoc(anf_methods, method.name);
        try emitMethodBody(ctx, method);
        if (!is_last) {
            try ctx.emitOpcode(.op_else);
        }
    }

    // Close all the nested OP_IF / OP_ELSE blocks (one OP_ENDIF per non-last method).
    var closes: usize = methods.len - 1;
    while (closes > 0) : (closes -= 1) {
        try ctx.emitOpcode(.op_endif);
    }
}

/// Emit the dispatch table for a multi-method contract.
/// Pattern: see `emitDispatchTableWithSourceMap`.
pub fn emitDispatchTable(ctx: *EmitContext, methods: []const types.StackMethod) !void {
    if (methods.len == 0) return;

    if (methods.len == 1) {
        // Single method: no dispatch needed, just emit the body
        try emitMethodBody(ctx, methods[0]);
        return;
    }

    for (methods, 0..) |method, i| {
        const is_last = i == methods.len - 1;
        if (!is_last) {
            try ctx.emitOpcode(.op_dup);
            try ctx.emitScriptNumber(@intCast(i));
            try ctx.emitOpcode(.op_numequal);
            try ctx.emitOpcode(.op_if);
            try ctx.emitOpcode(.op_drop); // consume the method index
        } else {
            try ctx.emitScriptNumber(@intCast(i));
            try ctx.emitOpcode(.op_numequalverify);
        }

        // Emit method body
        try emitMethodBody(ctx, method);

        if (!is_last) {
            try ctx.emitOpcode(.op_else);
        }
    }

    // Close all the nested OP_IF / OP_ELSE blocks.
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

    // Emit multi-method dispatch with source map support.
    // Pass ANF methods so we can look up source locations per-method.
    try emitDispatchTableWithSourceMap(&ctx, stack_program.methods, anf_program.methods);

    const script_hex = try ctx.getHex();
    defer allocator.free(script_hex);

    const asm_text = try ctx.getAsm();
    defer allocator.free(asm_text);

    // Build JSON output
    var json_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer json_buf.deinit(allocator);
    const w = opcodes.ArrayListWriter{ .list = &json_buf, .allocator = allocator };

    try w.writeAll("{");

    // version
    try w.writeAll("\"version\":\"runar-v0.4.4\",");

    // compilerVersion
    try w.writeAll("\"compilerVersion\":\"0.4.4-zig\",");

    // contractName
    try w.writeAll("\"contractName\":");
    try writeJsonString(w, stack_program.contract_name);
    try w.writeByte(',');

    // abi
    try w.writeAll("\"abi\":{");

    // abi.constructor — extract params from the ANF constructor method
    try w.writeAll("\"constructor\":{\"params\":[");
    {
        var first = true;
        for (anf_program.methods) |method| {
            if (std.mem.eql(u8, method.name, "constructor")) {
                for (method.params) |param| {
                    if (!first) try w.writeByte(',');
                    first = false;
                    try w.writeAll("{\"name\":");
                    try writeJsonString(w, param.name);
                    try w.writeAll(",\"type\":");
                    try writeJsonString(w, param.type_name);
                    try w.writeByte('}');
                }
                break;
            }
        }
    }
    try w.writeAll("]},");

    // abi.methods — only non-constructor methods
    try w.writeAll("\"methods\":[");
    {
        var first = true;
        for (anf_program.methods) |method| {
            if (std.mem.eql(u8, method.name, "constructor")) continue;
            if (!first) try w.writeByte(',');
            first = false;
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
            try w.writeAll("],\"isPublic\":");
            try w.writeAll(if (method.is_public) "true" else "false");
            try w.writeByte('}');
        }
    }
    try w.writeAll("]},");

    // script
    try w.writeAll("\"script\":");
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

    // codeSepIndexSlots — OP_0 placeholders for codeSeparatorIndex values
    if (ctx.code_sep_index_slots.items.len > 0) {
        try w.writeAll("\"codeSepIndexSlots\":[");
        for (ctx.code_sep_index_slots.items, 0..) |slot, i| {
            if (i > 0) try w.writeByte(',');
            try w.print("{{\"byteOffset\":{d},\"codeSepIndex\":{d}}}", .{ slot.byte_offset, slot.code_sep_index });
        }
        try w.writeAll("],");
    }

    // stateFields — mutable (non-readonly) properties, with synthetic
    // FixedArray runs re-grouped into a single logical entry via the
    // iterative marker-driven regrouper (mirrors the TS assembler).
    try w.writeAll("\"stateFields\":[");
    {
        const regrouped = try regroupStateFields(allocator, anf_program.properties);
        defer freeRegroupedEntries(allocator, regrouped);
        for (regrouped, 0..) |entry, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeAll("{\"name\":");
            try writeJsonString(w, entry.name);
            try w.writeAll(",\"type\":");
            try writeJsonString(w, entry.type_str);
            try w.print(",\"index\":{d}", .{entry.index});
            if (entry.fixed_array) |fa| {
                try w.writeAll(",\"fixedArray\":{\"elementType\":");
                try writeJsonString(w, fa.element_type);
                try w.print(",\"length\":{d},\"syntheticNames\":[", .{fa.length});
                for (fa.synthetic_names, 0..) |sn, j| {
                    if (j > 0) try w.writeByte(',');
                    try writeJsonString(w, sn);
                }
                try w.writeAll("]}");
            }
            try w.writeByte('}');
        }
    }
    try w.writeAll("],");

    // codeSeparatorIndex — byte offset of the first OP_CODESEPARATOR
    try w.writeAll("\"codeSeparatorIndex\":");
    if (ctx.code_separator_indices.items.len > 0) {
        try w.print("{d}", .{ctx.code_separator_indices.items[0]});
    } else {
        try w.writeAll("0");
    }

    // codeSeparatorIndices — per-method byte offsets
    if (ctx.code_separator_indices.items.len > 0) {
        try w.writeAll(",\"codeSeparatorIndices\":[");
        for (ctx.code_separator_indices.items, 0..) |idx, i| {
            if (i > 0) try w.writeByte(',');
            try w.print("{d}", .{idx});
        }
        try w.writeAll("]");
    }

    // sourceMap — opcode-to-source-location mappings
    if (ctx.source_map.items.len > 0) {
        try w.writeAll(",\"sourceMap\":[");
        for (ctx.source_map.items, 0..) |mapping, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeAll("{\"opcodeIndex\":");
            try w.print("{d}", .{mapping.opcode_index});
            try w.writeAll(",\"sourceFile\":");
            try writeJsonString(w, mapping.source_file);
            try w.writeAll(",\"line\":");
            try w.print("{d}", .{mapping.line});
            try w.writeAll(",\"column\":");
            try w.print("{d}", .{mapping.column});
            try w.writeByte('}');
        }
        try w.writeAll("]");
    }

    // anf — full ANF IR for SDK auto-state computation
    try w.writeAll(",\"anf\":");
    try emitANFProgramJson(w, anf_program);

    try w.writeByte('}');

    return try json_buf.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// ANF IR JSON serialization (for inclusion in artifact)
// ---------------------------------------------------------------------------

fn emitANFProgramJson(w: anytype, program: types.ANFProgram) !void {
    try w.writeAll("{\"contractName\":");
    try writeJsonString(w, program.contract_name);

    // properties
    try w.writeAll(",\"properties\":[");
    for (program.properties, 0..) |prop, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"name\":");
        try writeJsonString(w, prop.name);
        try w.writeAll(",\"type\":");
        try writeJsonString(w, prop.type_name);
        try w.writeAll(",\"readonly\":");
        try w.writeAll(if (prop.readonly) "true" else "false");
        if (prop.initial_value) |iv| {
            try w.writeAll(",\"initialValue\":");
            try emitConstValueJson(w, iv);
        }
        try w.writeByte('}');
    }
    try w.writeAll("]");

    // methods (including constructor as a non-public method named "constructor")
    try w.writeAll(",\"methods\":[");
    {
        var first = true;
        // Emit constructor as a method
        if (program.constructor.params.len > 0 or program.constructor.assertions.len > 0) {
            try w.writeAll("{\"name\":\"constructor\",\"params\":[");
            for (program.constructor.params, 0..) |param, j| {
                if (j > 0) try w.writeByte(',');
                try w.writeAll("{\"name\":");
                try writeJsonString(w, param.name);
                try w.writeAll(",\"type\":");
                try writeJsonString(w, param.type_name);
                try w.writeByte('}');
            }
            try w.writeAll("],\"body\":[");
            for (program.constructor.assertions, 0..) |binding, j| {
                if (j > 0) try w.writeByte(',');
                try emitANFBindingJson(w, binding);
            }
            try w.writeAll("],\"isPublic\":false}");
            first = false;
        }

        // Emit regular methods
        for (program.methods) |method| {
            if (!first) try w.writeByte(',');
            first = false;
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
            try w.writeAll("],\"body\":[");
            // Use .body if available (populated by ANF lower), fallback to .bindings
            const body = if (method.body.len > 0) method.body else method.bindings;
            for (body, 0..) |binding, j| {
                if (j > 0) try w.writeByte(',');
                try emitANFBindingJson(w, binding);
            }
            try w.writeAll("],\"isPublic\":");
            try w.writeAll(if (method.is_public) "true" else "false");
            try w.writeByte('}');
        }
    }
    try w.writeAll("]");

    try w.writeByte('}');
}

fn emitANFBindingJson(w: anytype, binding: types.ANFBinding) error{OutOfMemory}!void {
    try w.writeAll("{\"name\":");
    try writeJsonString(w, binding.name);
    try w.writeAll(",\"value\":");
    try emitANFValueJson(w, binding.value);
    if (binding.source_loc) |loc| {
        try w.writeAll(",\"sourceLoc\":{\"file\":");
        try writeJsonString(w, loc.file);
        try w.print(",\"line\":{d},\"column\":{d}}}", .{ loc.line, loc.column });
    }
    try w.writeByte('}');
}

fn emitANFValueJson(w: anytype, value: types.ANFValue) error{OutOfMemory}!void {
    switch (value) {
        .load_param => |lp| {
            try w.writeAll("{\"kind\":\"load_param\",\"name\":");
            try writeJsonString(w, lp.name);
            try w.writeByte('}');
        },
        .load_prop => |lp| {
            try w.writeAll("{\"kind\":\"load_prop\",\"name\":");
            try writeJsonString(w, lp.name);
            try w.writeByte('}');
        },
        .load_const => |lc| {
            try w.writeAll("{\"kind\":\"load_const\",\"value\":");
            try emitConstValueJson(w, lc.value);
            try w.writeByte('}');
        },
        .bin_op => |bo| {
            try w.writeAll("{\"kind\":\"bin_op\",\"op\":");
            try writeJsonString(w, bo.op);
            try w.writeAll(",\"left\":");
            try writeJsonString(w, bo.left);
            try w.writeAll(",\"right\":");
            try writeJsonString(w, bo.right);
            if (bo.result_type) |rt| {
                try w.writeAll(",\"result_type\":");
                try writeJsonString(w, rt);
            }
            try w.writeByte('}');
        },
        .unary_op => |uo| {
            try w.writeAll("{\"kind\":\"unary_op\",\"op\":");
            try writeJsonString(w, uo.op);
            try w.writeAll(",\"operand\":");
            try writeJsonString(w, uo.operand);
            if (uo.result_type) |rt| {
                try w.writeAll(",\"result_type\":");
                try writeJsonString(w, rt);
            }
            try w.writeByte('}');
        },
        .call => |c| {
            try w.writeAll("{\"kind\":\"call\",\"func\":");
            try writeJsonString(w, c.func);
            try w.writeAll(",\"args\":[");
            for (c.args, 0..) |arg, j| {
                if (j > 0) try w.writeByte(',');
                try writeJsonString(w, arg);
            }
            try w.writeAll("]}");
        },
        .method_call => |mc| {
            try w.writeAll("{\"kind\":\"method_call\",\"method\":");
            try writeJsonString(w, mc.method);
            try w.writeAll(",\"args\":[");
            for (mc.args, 0..) |arg, j| {
                if (j > 0) try w.writeByte(',');
                try writeJsonString(w, arg);
            }
            try w.writeAll("]}");
        },
        .@"if" => |ifn| {
            try w.writeAll("{\"kind\":\"if\",\"cond\":");
            try writeJsonString(w, ifn.cond);
            try w.writeAll(",\"then\":[");
            for (ifn.then, 0..) |binding, j| {
                if (j > 0) try w.writeByte(',');
                try emitANFBindingJson(w, binding);
            }
            try w.writeAll("],\"else\":[");
            for (ifn.@"else", 0..) |binding, j| {
                if (j > 0) try w.writeByte(',');
                try emitANFBindingJson(w, binding);
            }
            try w.writeAll("]}");
        },
        .loop => |ln| {
            try w.writeAll("{\"kind\":\"loop\",\"count\":");
            try w.print("{d}", .{ln.count});
            try w.writeAll(",\"iterVar\":");
            try writeJsonString(w, ln.iter_var);
            try w.writeAll(",\"body\":[");
            for (ln.body, 0..) |binding, j| {
                if (j > 0) try w.writeByte(',');
                try emitANFBindingJson(w, binding);
            }
            try w.writeAll("]}");
        },
        .assert => |a| {
            try w.writeAll("{\"kind\":\"assert\",\"value\":");
            try writeJsonString(w, a.value);
            try w.writeByte('}');
        },
        .update_prop => |up| {
            try w.writeAll("{\"kind\":\"update_prop\",\"name\":");
            try writeJsonString(w, up.name);
            try w.writeAll(",\"value\":");
            try writeJsonString(w, up.value);
            try w.writeByte('}');
        },
        .add_output => |ao| {
            try w.writeAll("{\"kind\":\"add_output\",\"satoshis\":");
            try writeJsonString(w, ao.satoshis);
            if (ao.state_values.len > 0) {
                try w.writeAll(",\"stateValues\":[");
                for (ao.state_values, 0..) |sv, j| {
                    if (j > 0) try w.writeByte(',');
                    try writeJsonString(w, sv);
                }
                try w.writeByte(']');
            }
            try w.writeByte('}');
        },
        .add_raw_output => {
            try w.writeAll("{\"kind\":\"add_raw_output\"}");
        },
        .add_data_output => {
            try w.writeAll("{\"kind\":\"add_data_output\"}");
        },
        .get_state_script => {
            try w.writeAll("{\"kind\":\"get_state_script\"}");
        },
        .check_preimage => |cp| {
            try w.writeAll("{\"kind\":\"check_preimage\",\"preimage\":");
            try writeJsonString(w, cp.preimage);
            try w.writeByte('}');
        },
        .deserialize_state => |ds| {
            try w.writeAll("{\"kind\":\"deserialize_state\",\"preimage\":");
            try writeJsonString(w, ds.preimage);
            try w.writeByte('}');
        },
        .array_literal => {
            try w.writeAll("{\"kind\":\"array_literal\"}");
        },
    }
}

fn emitConstValueJson(w: anytype, cv: types.ConstValue) !void {
    switch (cv) {
        .boolean => |b| try w.writeAll(if (b) "true" else "false"),
        .integer => |n| try w.print("{d}", .{n}),
        .string => |s| try writeJsonString(w, s),
    }
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

    // Expected pattern (matches TS reference compiler):
    // method 0 (non-last): OP_DUP(76) OP_0(00) OP_NUMEQUAL(9c) OP_IF(63) OP_DROP(75) OP_ADD(93) OP_ELSE(67)
    // method 1 (last):     OP_1(51) OP_NUMEQUALVERIFY(9d) OP_SUB(94)
    // close:               OP_ENDIF(68)
    try std.testing.expectEqualStrings("76009c63759367519d9468", hex);

    const asm_text = try ctx.getAsm();
    defer allocator.free(asm_text);
    try std.testing.expectEqualStrings(
        "OP_DUP OP_0 OP_NUMEQUAL OP_IF OP_DROP OP_ADD OP_ELSE OP_1 OP_NUMEQUALVERIFY OP_SUB OP_ENDIF",
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

    // Expected pattern (matches TS reference compiler):
    // method 0 (non-last): OP_DUP(76) OP_0(00) OP_NUMEQUAL(9c) OP_IF(63) OP_DROP(75) OP_ADD(93) OP_ELSE(67)
    // method 1 (non-last): OP_DUP(76) OP_1(51) OP_NUMEQUAL(9c) OP_IF(63) OP_DROP(75) OP_SUB(94) OP_ELSE(67)
    // method 2 (last):     OP_2(52) OP_NUMEQUALVERIFY(9d) OP_MUL(95)
    // close:               OP_ENDIF(68) OP_ENDIF(68)
    const expected = "76009c6375936776519c6375946752" ++ "9d" ++ "956868";
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

    var ctor_params = [_]types.ANFParam{
        .{ .name = "pubKeyHash", .type_name = "Ripemd160" },
    };

    var anf_methods = [_]types.ANFMethod{
        .{
            .name = "constructor",
            .is_public = false,
            .params = &ctor_params,
            .bindings = &.{},
        },
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
    try std.testing.expect(std.mem.indexOf(u8, json, "\"contractName\":\"P2PKH\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"script\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"asm\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"abi\":{") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"constructor\":{\"params\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"pubKeyHash\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"Ripemd160\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"methods\":[{\"name\":\"unlock\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"isPublic\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"codeSeparatorIndex\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"stateFields\":[]") != null);

    // Single-method contract: no dispatch table, just the body opcodes
    // 76 a9 88 ac = OP_DUP OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG
    try std.testing.expect(std.mem.indexOf(u8, json, "76a988ac") != null);
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

    var ctor_params = [_]types.ANFParam{
        .{ .name = "count", .type_name = "bigint" },
    };

    var anf_methods = [_]types.ANFMethod{
        .{
            .name = "constructor",
            .is_public = false,
            .params = &ctor_params,
            .bindings = &.{},
        },
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
    try std.testing.expect(std.mem.indexOf(u8, json, "\"contractName\":\"Counter\"") != null);
    // Constructor params come from the ANF constructor method
    try std.testing.expect(std.mem.indexOf(u8, json, "\"constructor\":{\"params\":[{\"name\":\"count\",\"type\":\"bigint\"}]}") != null);
}

test "writeJsonString — escaping" {
    const allocator = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    const w = opcodes.ArrayListWriter{ .list = &buf, .allocator = allocator };

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

// ---------------------------------------------------------------------------
// StateField re-grouping (FixedArray collapse)
// ---------------------------------------------------------------------------
//
// Mirrors packages/runar-compiler/src/artifact/assembler.ts `regroupOnePass`/
// `regroupSyntheticRuns`. Walks mutable (non-readonly) ANF properties and
// collapses runs whose innermost `synthetic_array_chain` level forms a
// contiguous 0..N-1 sequence under the same `base` name. Iterated until no
// chain has any unconsumed levels, so nested arrays collapse from innermost
// outward.

const RegroupFA = struct {
    element_type: []const u8,
    length: u32,
    synthetic_names: [][]const u8,
};

const RegroupEntry = struct {
    name: []const u8,
    type_str: []const u8,
    chain: []const types.SyntheticArrayLevel,
    index: u32,
    fixed_array: ?RegroupFA,
};

fn regroupStateFields(allocator: std.mem.Allocator, props: []const types.ANFProperty) ![]RegroupEntry {
    var flat: std.ArrayListUnmanaged(RegroupEntry) = .empty;
    var state_idx: u32 = 0;
    for (props) |p| {
        if (p.readonly) continue;
        const chain: []const types.SyntheticArrayLevel = if (p.synthetic_array_chain) |c| c else &.{};
        try flat.append(allocator, .{
            .name = p.name,
            .type_str = p.type_name,
            .chain = chain,
            .index = state_idx,
            .fixed_array = null,
        });
        state_idx += 1;
    }

    var current = try flat.toOwnedSlice(allocator);
    var iter: usize = 0;
    while (iter < 1024) : (iter += 1) {
        const res = try regroupOnePass(allocator, current);
        allocator.free(current);
        current = res.out;
        if (!res.changed) return current;
    }
    return current;
}

fn freeRegroupedEntries(allocator: std.mem.Allocator, entries: []RegroupEntry) void {
    for (entries) |e| {
        if (e.fixed_array) |fa| {
            allocator.free(fa.synthetic_names);
        }
    }
    allocator.free(entries);
}

const PassResult = struct { out: []RegroupEntry, changed: bool };

fn regroupOnePass(allocator: std.mem.Allocator, entries: []const RegroupEntry) !PassResult {
    var out: std.ArrayListUnmanaged(RegroupEntry) = .empty;
    var changed = false;
    var i: usize = 0;
    while (i < entries.len) {
        const entry = entries[i];
        const chain_len = entry.chain.len;
        if (chain_len == 0) {
            try out.append(allocator, entry);
            i += 1;
            continue;
        }
        const marker = entry.chain[chain_len - 1];
        if (marker.index != 0) {
            try out.append(allocator, entry);
            i += 1;
            continue;
        }

        // Greedily extend: every follower must share the same innermost
        // {base, length}, carry the expected index = k, and have identical
        // current type.
        var run_count: u32 = 1;
        var j: usize = i + 1;
        while (j < entries.len and run_count < marker.length) : (j += 1) {
            const next = entries[j];
            if (next.chain.len == 0) break;
            const m2 = next.chain[next.chain.len - 1];
            if (!std.mem.eql(u8, m2.base, marker.base)) break;
            if (m2.length != marker.length) break;
            if (m2.index != run_count) break;
            if (!std.mem.eql(u8, next.type_str, entry.type_str)) break;
            run_count += 1;
        }
        if (run_count != marker.length) {
            try out.append(allocator, entry);
            i += 1;
            continue;
        }

        // Collapse the run.
        const inner_type = entry.type_str;
        const grouped_type = try std.fmt.allocPrint(allocator, "FixedArray<{s}, {d}>", .{ inner_type, marker.length });

        // Flatten synthetic names.
        var synth: std.ArrayListUnmanaged([]const u8) = .empty;
        var k: usize = 0;
        while (k < run_count) : (k += 1) {
            const child = entries[i + k];
            if (child.fixed_array) |fa| {
                for (fa.synthetic_names) |sn| try synth.append(allocator, sn);
            } else {
                try synth.append(allocator, child.name);
            }
        }

        try out.append(allocator, .{
            .name = marker.base,
            .type_str = grouped_type,
            .chain = entry.chain[0 .. chain_len - 1],
            .index = entry.index,
            .fixed_array = .{
                .element_type = inner_type,
                .length = marker.length,
                .synthetic_names = try synth.toOwnedSlice(allocator),
            },
        });
        i += run_count;
        changed = true;
    }
    return .{ .out = try out.toOwnedSlice(allocator), .changed = changed };
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
