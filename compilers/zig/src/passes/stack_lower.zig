//! Pass 5: Stack Lower — transforms ANF IR into Stack IR (Bitcoin Script stack operations).
//!
//! This is the core of the compiler. The algorithm maps named variables to stack positions
//! and emits PICK/ROLL/DUP/SWAP/ROT/OVER operations to shuttle values into the correct
//! positions for each operation.
//!
//! The central data structure is StackMap, which tracks which named variable lives at which
//! stack depth (0 = top of stack). bringToTop is the critical function that emits the
//! minimal sequence of opcodes to move a variable to the top.

const std = @import("std");
const types = @import("../ir/types.zig");
const opcodes = @import("../codegen/opcodes.zig");
const stateful_templates = @import("helpers/stateful_templates.zig");
const crypto_builtins = @import("helpers/crypto_builtins.zig");
const crypto_emitters = @import("helpers/crypto_emitters.zig");
const blake3_emitters = @import("helpers/blake3_emitters.zig");
const ec_emitters = @import("helpers/ec_emitters.zig");
const pq_emitters = @import("helpers/pq_emitters.zig");
const sha256_emitters = @import("helpers/sha256_emitters.zig");
const babybear_emitters = @import("helpers/babybear_emitters.zig");
const merkle_emitters = @import("helpers/merkle_emitters.zig");
const Allocator = std.mem.Allocator;
const Opcode = types.Opcode;

// ============================================================================
// StackMap — tracks named variables at stack positions
// ============================================================================

/// StackMap tracks which named variable lives at which stack depth.
/// Depth 0 = top of stack = last element in the slots array.
/// A parallel hash map provides O(1) name-to-depth lookup.
pub const StackMap = struct {
    /// Stack slots: bottom of stack is index 0, top of stack is last element.
    slots: std.ArrayListUnmanaged(?[]const u8) = .empty,
    /// Maps variable names to their array index in slots for O(1) findDepth.
    name_index: std.StringHashMapUnmanaged(usize) = .empty,

    /// Push a value onto the top of the stack (appends to end — O(1) amortized).
    pub fn push(self: *StackMap, allocator: Allocator, name: ?[]const u8) !void {
        const idx = self.slots.items.len;
        try self.slots.append(allocator, name);
        if (name) |n| {
            try self.name_index.put(allocator, n, idx);
        }
    }

    /// Pop the top of the stack (removes from end — O(1)).
    pub fn pop(self: *StackMap) ?[]const u8 {
        if (self.slots.items.len == 0) return null;
        const val = self.slots.items[self.slots.items.len - 1];
        if (val) |v| {
            _ = self.name_index.remove(v);
        }
        self.slots.items.len -= 1;
        return val;
    }

    /// Find the stack depth (0 = top) of a named variable — O(1) via hash map.
    pub fn findDepth(self: *const StackMap, name: []const u8) ?usize {
        var i = self.slots.items.len;
        while (i > 0) {
            i -= 1;
            const slot = self.slots.items[i] orelse continue;
            if (std.mem.eql(u8, slot, name)) {
                return self.slots.items.len - 1 - i;
            }
        }
        return null;
    }

    fn rebuildNameIndex(self: *StackMap, allocator: Allocator) !void {
        self.name_index.clearRetainingCapacity();
        for (self.slots.items, 0..) |slot, idx| {
            if (slot) |name| {
                try self.name_index.put(allocator, name, idx);
            }
        }
    }

    /// Remove the slot at the given depth (0 = top). Depth d maps to array
    /// index `len - 1 - d`.
    pub fn removeAtDepth(self: *StackMap, allocator: Allocator, d: usize) !void {
        const idx = self.slots.items.len - 1 - d;
        _ = self.slots.orderedRemove(idx);
        try self.rebuildNameIndex(allocator);
    }

    /// Rename the variable at the given depth.
    pub fn renameAtDepth(self: *StackMap, allocator: Allocator, d: usize, new_name: ?[]const u8) !void {
        const idx = self.slots.items.len - 1 - d;
        self.slots.items[idx] = new_name;
        try self.rebuildNameIndex(allocator);
    }

    /// Peek at the variable name at the given depth (0 = top).
    pub fn peekAtDepth(self: *const StackMap, d: usize) ?[]const u8 {
        if (d >= self.slots.items.len) return null;
        return self.slots.items[self.slots.items.len - 1 - d];
    }

    pub fn clone(self: *const StackMap, allocator: Allocator) !StackMap {
        var new_slots: std.ArrayListUnmanaged(?[]const u8) = .empty;
        try new_slots.appendSlice(allocator, self.slots.items);
        var new_index: std.StringHashMapUnmanaged(usize) = .empty;
        try new_index.ensureTotalCapacity(allocator, @intCast(self.slots.items.len));
        for (self.slots.items, 0..) |slot, idx| {
            if (slot) |name| {
                try new_index.put(allocator, name, idx);
            }
        }
        return .{ .slots = new_slots, .name_index = new_index };
    }

    pub fn depth(self: *const StackMap) usize {
        return self.slots.items.len;
    }

    pub fn namedSlots(self: *const StackMap, allocator: Allocator) !std.StringHashMapUnmanaged(void) {
        var set: std.StringHashMapUnmanaged(void) = .empty;
        for (self.slots.items) |slot| {
            if (slot) |s| {
                try set.put(allocator, s, {});
            }
        }
        return set;
    }

    pub fn deinit(self: *StackMap, allocator: Allocator) void {
        self.slots.deinit(allocator);
        self.name_index.deinit(allocator);
    }
};

// ============================================================================
// Lowering context
// ============================================================================

const LowerError = error{
    OutOfMemory,
    VariableNotFound,
    InvalidBuiltin,
    UnsupportedOperation,
    BranchStackMismatch,
};

const LowerCtx = struct {
    allocator: Allocator,
    instructions: std.ArrayListUnmanaged(types.StackInstruction),
    /// Parallel to `instructions`: source location for each emitted instruction.
    instruction_source_locs: std.ArrayListUnmanaged(?types.SourceLocation),
    stack: StackMap,
    program: types.ANFProgram,
    last_uses: std.StringHashMapUnmanaged(usize),
    local_bindings: std.StringHashMapUnmanaged(void),
    force_copy_bindings: std.StringHashMapUnmanaged(void),
    owned_push_data: std.ArrayListUnmanaged([]u8),
    scope_bindings: []const types.ANFBinding,
    copy_ref_aliases: bool,
    current_idx: usize,
    in_branch: bool,
    updated_props: std.StringHashMapUnmanaged(void),
    max_depth: u32,
    /// Current ANF binding's source location — set before processing each binding.
    current_source_loc: ?types.SourceLocation = null,

    fn init(allocator: Allocator, program: types.ANFProgram) LowerCtx {
        return .{
            .allocator = allocator,
            .instructions = .empty,
            .instruction_source_locs = .empty,
            .stack = .{},
            .program = program,
            .last_uses = .empty,
            .local_bindings = .empty,
            .force_copy_bindings = .empty,
            .owned_push_data = .empty,
            .scope_bindings = &.{},
            .copy_ref_aliases = false,
            .current_idx = 0,
            .in_branch = false,
            .updated_props = .empty,
            .max_depth = 0,
        };
    }

    fn deinit(self: *LowerCtx) void {
        self.instructions.deinit(self.allocator);
        self.instruction_source_locs.deinit(self.allocator);
        self.stack.deinit(self.allocator);
        self.last_uses.deinit(self.allocator);
        self.local_bindings.deinit(self.allocator);
        self.force_copy_bindings.deinit(self.allocator);
        for (self.owned_push_data.items) |data| self.allocator.free(data);
        self.owned_push_data.deinit(self.allocator);
        self.updated_props.deinit(self.allocator);
    }

    fn trackDepth(self: *LowerCtx) void {
        const d: u32 = @intCast(self.stack.depth());
        if (d > self.max_depth) self.max_depth = d;
    }

    fn cleanupExcessStack(self: *LowerCtx) !void {
        if (self.stack.depth() <= 1) return;
        const excess = self.stack.depth() - 1;
        var i: usize = 0;
        while (i < excess) : (i += 1) {
            try self.emitOp(.op_nip);
            try self.stack.removeAtDepth(self.allocator, 1);
        }
    }

    // ========================================================================
    // Emit helpers
    // ========================================================================

    fn emit(self: *LowerCtx, inst: types.StackInstruction) !void {
        try self.instructions.append(self.allocator, inst);
        try self.instruction_source_locs.append(self.allocator, self.current_source_loc);
    }

    fn emitOp(self: *LowerCtx, op: Opcode) !void {
        try self.emit(.{ .op = op });
    }

    fn emitPushInt(self: *LowerCtx, n: i64) !void {
        try self.emit(.{ .push_int = n });
    }

    fn emitPushBool(self: *LowerCtx, b: bool) !void {
        try self.emit(.{ .push_bool = b });
    }

    fn emitPushData(self: *LowerCtx, data: []const u8) !void {
        try self.emit(.{ .push_data = data });
    }

    fn emitOwnedPushData(self: *LowerCtx, data: []u8) !void {
        try self.owned_push_data.append(self.allocator, data);
        try self.emitPushData(data);
    }

    fn emitPushHexString(self: *LowerCtx, hex: []const u8) !void {
        if (hex.len % 2 != 0) return LowerError.UnsupportedOperation;
        const decoded = try self.allocator.alloc(u8, hex.len / 2);
        _ = std.fmt.hexToBytes(decoded, hex) catch return LowerError.UnsupportedOperation;
        try self.emitOwnedPushData(decoded);
    }

    fn emitSwapTracked(self: *LowerCtx) !void {
        try self.emitOp(.op_swap);
        const top = self.stack.pop();
        const next = self.stack.pop();
        try self.stack.push(self.allocator, top);
        try self.stack.push(self.allocator, next);
    }

    fn appendInstructions(self: *LowerCtx, insts: []const types.StackInstruction) !void {
        try self.instructions.appendSlice(self.allocator, insts);
    }

    fn cloneVoidMap(
        allocator: Allocator,
        src: std.StringHashMapUnmanaged(void),
    ) !std.StringHashMapUnmanaged(void) {
        var dst: std.StringHashMapUnmanaged(void) = .empty;
        try dst.ensureTotalCapacity(allocator, src.count());
        var it = src.iterator();
        while (it.next()) |entry| {
            dst.putAssumeCapacity(entry.key_ptr.*, {});
        }
        return dst;
    }

    /// Drop a value from arbitrary stack depth in the bilateral branch
    /// reconciliation phase of `lowerIf`. Mirrors the TS reference compiler's
    /// pre-IF reconciliation (`05-stack-lower.ts` ~line 1640), which uses
    /// `push depth + roll(depth=depth) + drop`.
    fn removeBranchValueAtDepth(ctx: *LowerCtx, depth: usize) !void {
        if (depth == 0) {
            try ctx.emitOp(.op_drop);
            _ = ctx.stack.pop();
            return;
        }

        if (depth == 1) {
            try ctx.emitOp(.op_nip);
            try ctx.stack.removeAtDepth(ctx.allocator, 1);
            return;
        }

        try ctx.emitPushInt(@intCast(depth));
        try ctx.stack.push(ctx.allocator, null);
        try ctx.emitOp(.op_roll);
        _ = ctx.stack.pop();
        const rolled = ctx.stack.peekAtDepth(depth);
        try ctx.stack.removeAtDepth(ctx.allocator, depth);
        try ctx.stack.push(ctx.allocator, rolled);
        try ctx.emitOp(.op_drop);
        _ = ctx.stack.pop();
    }

    /// Drop a stale property entry after an if-else expression that wrote the
    /// same property in both branches. Mirrors the TS reference compiler's
    /// `lowerUpdateProp` post-if cleanup (`05-stack-lower.ts` ~line 1909),
    /// which uses `push d + roll(depth=d+1) + drop`. The push value (`d`) is
    /// the visible depth from the StackMap, but the runtime roll consumes the
    /// extra temporary from the push (`d + 1`). The peephole rule
    /// `push 2n + roll(depth=2) → rot` checks the *IR* depth, not the push
    /// value, so this case never folds in TS. Keep the literal
    /// `push d + OP_ROLL + OP_DROP` here for byte equivalence.
    fn removeStalePropertyAtDepth(ctx: *LowerCtx, depth: usize) !void {
        if (depth == 0) {
            try ctx.emitOp(.op_drop);
            _ = ctx.stack.pop();
            return;
        }

        if (depth == 1) {
            try ctx.emitOp(.op_nip);
            try ctx.stack.removeAtDepth(ctx.allocator, 1);
            return;
        }

        try ctx.emitPushInt(@intCast(depth));
        try ctx.stack.push(ctx.allocator, null);
        try ctx.emitOp(.op_roll);
        _ = ctx.stack.pop();
        const rolled = ctx.stack.peekAtDepth(depth);
        try ctx.stack.removeAtDepth(ctx.allocator, depth);
        try ctx.stack.push(ctx.allocator, rolled);
        try ctx.emitOp(.op_drop);
        _ = ctx.stack.pop();
    }

    fn duplicateBranchValueAtDepth(ctx: *LowerCtx, depth: usize, name: ?[]const u8) !void {
        if (depth == 0) {
            try ctx.emitOp(.op_dup);
        } else if (depth == 1) {
            // Foldable pick: depth 1 → OP_OVER. Mirrors TS peephole
            // `push 1n + pick(depth=1) → over`.
            try ctx.emitOp(.op_over);
        } else {
            try ctx.emitPushInt(@intCast(depth));
            try ctx.stack.push(ctx.allocator, null);
            try ctx.emitOp(.op_pick);
            _ = ctx.stack.pop();
        }
        try ctx.stack.push(ctx.allocator, name);
        ctx.trackDepth();
    }

    // ========================================================================
    // bringToTop — THE critical function
    // ========================================================================

    fn bringToTop(self: *LowerCtx, name: []const u8, consume: bool) !void {
        const d = self.stack.findDepth(name) orelse return LowerError.VariableNotFound;

        if (d == 0 and !consume) {
            try self.emitOp(.op_dup);
            try self.stack.push(self.allocator, name);
            self.trackDepth();
            return;
        }

        if (d == 0 and consume) {
            return;
        }

        if (consume) {
            switch (d) {
                1 => {
                    try self.emitOp(.op_swap);
                    // Swap the top two elements (last two in the array)
                    const len = self.stack.slots.items.len;
                    const top_idx = len - 1;
                    const next_idx = len - 2;
                    const old_top = self.stack.slots.items[top_idx];
                    const old_next = self.stack.slots.items[next_idx];
                    self.stack.slots.items[top_idx] = old_next;
                    self.stack.slots.items[next_idx] = old_top;
                },
                2 => {
                    try self.emitOp(.op_rot);
                    try self.stack.removeAtDepth(self.allocator, d);
                    try self.stack.push(self.allocator, name);
                },
                else => {
                    try self.emitPushInt(@intCast(d));
                    try self.stack.push(self.allocator, null);
                    try self.emitOp(.op_roll);
                    _ = self.stack.pop();
                    try self.stack.removeAtDepth(self.allocator, d);
                    try self.stack.push(self.allocator, name);
                },
            }
        } else {
            switch (d) {
                1 => {
                    try self.emitOp(.op_over);
                    try self.stack.push(self.allocator, name);
                },
                else => {
                    try self.emitPushInt(@intCast(d));
                    try self.stack.push(self.allocator, null);
                    try self.emitOp(.op_pick);
                    _ = self.stack.pop();
                    try self.stack.push(self.allocator, name);
                },
            }
        }
        self.trackDepth();
    }

    fn isLastUse(self: *const LowerCtx, name: []const u8) bool {
        if (self.last_uses.get(name)) |last_idx| {
            return self.current_idx >= last_idx;
        }
        return true;
    }

    fn bringToTopAuto(self: *LowerCtx, name: []const u8) !void {
        const consume = self.isLastUse(name);
        try self.bringToTop(name, consume);
    }

    // ========================================================================
    // Last-use analysis
    // ========================================================================

    fn computeLastUses(self: *LowerCtx, bindings: []const types.ANFBinding) !void {
        self.last_uses.clearRetainingCapacity();
        for (bindings, 0..) |binding, idx| {
            self.scanValueForRefs(binding.value, idx);
        }
    }

    fn scanValueForRefs(self: *LowerCtx, value: types.ANFValue, idx: usize) void {
        switch (value) {
            .literal_int, .literal_bigint, .literal_bool, .literal_bytes, .nop => {},
            .load_param => |lp| {
                self.last_uses.put(self.allocator, lp.name, idx) catch return;
            },
            .load_prop, .get_state_script => {},
            .load_const => |lc| {
                switch (lc.value) {
                    .string => |s| {
                        if (std.mem.startsWith(u8, s, "@ref:")) {
                            self.last_uses.put(self.allocator, s[5..], idx) catch return;
                        }
                    },
                    else => {},
                }
            },
            .ref => |name| {
                self.last_uses.put(self.allocator, name, idx) catch return;
            },
            .property_read => {},
            .property_write => |pw| {
                self.last_uses.put(self.allocator, pw.value_ref, idx) catch return;
            },
            .binary_op => |bop| {
                self.last_uses.put(self.allocator, bop.left, idx) catch return;
                self.last_uses.put(self.allocator, bop.right, idx) catch return;
            },
            .bin_op => |bop| {
                self.last_uses.put(self.allocator, bop.left, idx) catch return;
                self.last_uses.put(self.allocator, bop.right, idx) catch return;
            },
            .unary_op => |uop| {
                self.last_uses.put(self.allocator, uop.operand, idx) catch return;
            },
            .builtin_call => |call| {
                for (call.args) |arg| {
                    self.last_uses.put(self.allocator, arg, idx) catch return;
                }
            },
            .call => |c| {
                for (c.args) |arg| {
                    self.last_uses.put(self.allocator, arg, idx) catch return;
                }
            },
            .method_call => |mc| {
                if (mc.object.len > 0) {
                    self.last_uses.put(self.allocator, mc.object, idx) catch return;
                }
                for (mc.args) |arg| {
                    self.last_uses.put(self.allocator, arg, idx) catch return;
                }
            },
            .@"if" => |ie| {
                self.last_uses.put(self.allocator, ie.cond, idx) catch return;
                for (ie.then) |binding| {
                    self.scanValueForRefs(binding.value, idx);
                }
                for (ie.@"else") |binding| {
                    self.scanValueForRefs(binding.value, idx);
                }
            },
            .if_expr => |ie| {
                self.last_uses.put(self.allocator, ie.condition, idx) catch return;
                for (ie.then_bindings) |binding| {
                    self.scanValueForRefs(binding.value, idx);
                }
                if (ie.else_bindings) |else_bindings| {
                    for (else_bindings) |binding| {
                        self.scanValueForRefs(binding.value, idx);
                    }
                }
            },
            .for_loop => |fl| {
                for (fl.body_bindings) |binding| {
                    self.scanValueForRefs(binding.value, idx);
                }
            },
            .loop => |lp| {
                for (lp.body) |binding| {
                    self.scanValueForRefs(binding.value, idx);
                }
            },
            .assert_op => |a| {
                self.last_uses.put(self.allocator, a.condition, idx) catch return;
            },
            .assert => |a| {
                self.last_uses.put(self.allocator, a.value, idx) catch return;
            },
            .update_prop => |up| {
                self.last_uses.put(self.allocator, up.value, idx) catch return;
            },
            .check_preimage => |cp| {
                self.last_uses.put(self.allocator, cp.preimage, idx) catch return;
            },
            .deserialize_state => |ds| {
                self.last_uses.put(self.allocator, ds.preimage, idx) catch return;
            },
            .add_output => |ao| {
                if (ao.satoshis.len > 0) {
                    self.last_uses.put(self.allocator, ao.satoshis, idx) catch return;
                }
                if (ao.preimage.len > 0) {
                    self.last_uses.put(self.allocator, ao.preimage, idx) catch return;
                }
                for (ao.state_values) |sv| {
                    if (sv.len > 0) {
                        self.last_uses.put(self.allocator, sv, idx) catch return;
                    }
                }
                for (ao.state_refs) |sr| {
                    if (sr.len > 0) {
                        self.last_uses.put(self.allocator, sr, idx) catch return;
                    }
                }
            },
            .add_raw_output => |aro| {
                if (aro.satoshis.len > 0) {
                    self.last_uses.put(self.allocator, aro.satoshis, idx) catch return;
                }
                if (aro.script_ref.len > 0) {
                    self.last_uses.put(self.allocator, aro.script_ref, idx) catch return;
                }
            },
            .array_literal => |al| {
                for (al.elements) |elem| {
                    self.last_uses.put(self.allocator, elem, idx) catch return;
                }
            },
        }
    }

    // ========================================================================
    // Lower a binding sequence
    // ========================================================================

    fn lowerBindings(self: *LowerCtx, bindings: []const types.ANFBinding, terminal_assert: bool) LowerError!void {
        const saved_scope_bindings = self.scope_bindings;
        self.scope_bindings = bindings;
        defer self.scope_bindings = saved_scope_bindings;

        self.local_bindings.clearRetainingCapacity();
        for (bindings) |binding| {
            try self.local_bindings.put(self.allocator, binding.name, {});
        }
        try self.computeLastUses(bindings);

        var terminal_assert_idx: ?usize = null;
        if (terminal_assert and bindings.len > 0) {
            const last_idx = bindings.len - 1;
            switch (bindings[last_idx].value) {
                .assert, .assert_op => terminal_assert_idx = last_idx,
                else => {},
            }
        }

        for (bindings, 0..) |binding, idx| {
            self.current_idx = idx;
            self.current_source_loc = binding.source_loc;
            if (terminal_assert_idx != null and idx == terminal_assert_idx.?) {
                switch (binding.value) {
                    .assert => |a| try self.lowerAssertOp(binding.name, .{ .condition = a.value }, true),
                    .assert_op => |a| try self.lowerAssertOp(binding.name, a, true),
                    else => try self.lowerBinding(binding),
                }
            } else {
                try self.lowerBinding(binding);
            }
            self.current_source_loc = null;
        }
    }

    fn hasLocalBinding(self: *const LowerCtx, name: []const u8) bool {
        return self.local_bindings.contains(name);
    }

    fn isForceCopyBinding(self: *const LowerCtx, name: []const u8) bool {
        return self.force_copy_bindings.contains(name);
    }

    fn valueReferencesName(value: types.ANFValue, name: []const u8) bool {
        switch (value) {
            .load_param => |lp| return std.mem.eql(u8, lp.name, name),
            .load_const => |lc| switch (lc.value) {
                .string => |s| return std.mem.startsWith(u8, s, "@ref:") and std.mem.eql(u8, s[5..], name),
                else => return false,
            },
            .ref => |ref_name| return std.mem.eql(u8, ref_name, name),
            .property_write => |pw| return std.mem.eql(u8, pw.value_ref, name),
            .binary_op => |bop| return std.mem.eql(u8, bop.left, name) or std.mem.eql(u8, bop.right, name),
            .bin_op => |bop| return std.mem.eql(u8, bop.left, name) or std.mem.eql(u8, bop.right, name),
            .unary_op => |uop| return std.mem.eql(u8, uop.operand, name),
            .builtin_call => |call| {
                for (call.args) |arg| {
                    if (std.mem.eql(u8, arg, name)) return true;
                }
                return false;
            },
            .call => |call| {
                for (call.args) |arg| {
                    if (std.mem.eql(u8, arg, name)) return true;
                }
                return false;
            },
            .method_call => |mc| {
                if (mc.object.len > 0 and std.mem.eql(u8, mc.object, name)) return true;
                for (mc.args) |arg| {
                    if (std.mem.eql(u8, arg, name)) return true;
                }
                return false;
            },
            .assert_op => |a| return std.mem.eql(u8, a.condition, name),
            .assert => |a| return std.mem.eql(u8, a.value, name),
            .update_prop => |up| return std.mem.eql(u8, up.value, name),
            .check_preimage => |cp| return std.mem.eql(u8, cp.preimage, name),
            .deserialize_state => |ds| return std.mem.eql(u8, ds.preimage, name),
            .add_output => |ao| {
                if (ao.satoshis.len > 0 and std.mem.eql(u8, ao.satoshis, name)) return true;
                if (ao.preimage.len > 0 and std.mem.eql(u8, ao.preimage, name)) return true;
                for (ao.state_values) |sv| {
                    if (sv.len > 0 and std.mem.eql(u8, sv, name)) return true;
                }
                for (ao.state_refs) |sr| {
                    if (sr.len > 0 and std.mem.eql(u8, sr, name)) return true;
                }
                return false;
            },
            .add_raw_output => |aro| {
                if (aro.satoshis.len > 0 and std.mem.eql(u8, aro.satoshis, name)) return true;
                return aro.script_ref.len > 0 and std.mem.eql(u8, aro.script_ref, name);
            },
            .array_literal => |al| {
                for (al.elements) |elem| {
                    if (std.mem.eql(u8, elem, name)) return true;
                }
                return false;
            },
            .@"if", .if_expr, .for_loop, .loop, .load_prop, .property_read, .get_state_script, .literal_int, .literal_bigint, .literal_bool, .literal_bytes, .nop => return false,
        }
    }

    fn futureUseCount(self: *const LowerCtx, name: []const u8) usize {
        if (self.scope_bindings.len == 0 or self.current_idx + 1 >= self.scope_bindings.len) return 0;
        var count: usize = 0;
        for (self.scope_bindings[self.current_idx + 1 ..]) |binding| {
            if (valueReferencesName(binding.value, name)) count += 1;
        }
        return count;
    }

    fn feedsLaterAliasedBinding(self: *const LowerCtx, name: []const u8) bool {
        if (self.scope_bindings.len == 0 or self.current_idx + 1 >= self.scope_bindings.len) return false;
        const future = self.scope_bindings[self.current_idx + 1 ..];
        for (future, 0..) |binding, rel_idx| {
            if (!valueReferencesName(binding.value, name)) continue;
            for (future[rel_idx + 1 ..]) |later| {
                switch (later.value) {
                    .load_const => |lc| switch (lc.value) {
                        .string => |s| {
                            if (std.mem.startsWith(u8, s, "@ref:") and std.mem.eql(u8, s[5..], binding.name)) {
                                return true;
                            }
                        },
                        else => {},
                    },
                    else => {},
                }
            }
        }
        return false;
    }

    fn feedsPrivateMethodCall(self: *const LowerCtx, name: []const u8) bool {
        if (self.scope_bindings.len == 0 or self.current_idx + 1 >= self.scope_bindings.len) return false;
        for (self.scope_bindings[self.current_idx + 1 ..]) |binding| {
            switch (binding.value) {
                .method_call => |mc| {
                    if (findPrivateMethod(self.program.methods, mc.method) == null) continue;
                    if (mc.object.len > 0 and std.mem.eql(u8, mc.object, name)) return true;
                    for (mc.args) |arg| {
                        if (std.mem.eql(u8, arg, name)) return true;
                    }
                },
                else => {},
            }
        }
        return false;
    }

    fn lowerBinding(self: *LowerCtx, binding: types.ANFBinding) LowerError!void {
        switch (binding.value) {
            .literal_int => |n| {
                try self.emitPushInt(n);
                try self.stack.push(self.allocator, binding.name);
                self.trackDepth();
            },
            .literal_bigint => |s| {
                try self.emitPushData(s);
                try self.stack.push(self.allocator, binding.name);
                self.trackDepth();
            },
            .literal_bool => |b| {
                try self.emitPushBool(b);
                try self.stack.push(self.allocator, binding.name);
                self.trackDepth();
            },
            .literal_bytes => |data| {
                try self.emitPushData(data);
                try self.stack.push(self.allocator, binding.name);
                self.trackDepth();
            },
            .ref => |name| try self.lowerRef(binding.name, name),
            .property_read => |prop_name| try self.lowerPropertyRead(binding.name, prop_name),
            .property_write => |pw| try self.lowerPropertyWrite(binding.name, pw),
            .binary_op => |bop| try self.lowerBinaryOp(binding.name, bop),
            .unary_op => |uop| try self.lowerUnaryOp(binding.name, uop),
            .builtin_call => |call| try self.lowerBuiltinCall(binding.name, call),
            .if_expr => |ie| try self.lowerIfExpr(binding.name, ie),
            .for_loop => |fl| try self.lowerForLoop(binding.name, fl),
            .assert_op => |a| try self.lowerAssertOp(binding.name, a, false),
            .add_output => |ao| try self.lowerAddOutput(binding.name, ao),
            .add_raw_output => |aro| try self.lowerAddRawOutput(binding.name, aro),
            .nop => {},
            .get_state_script => try self.lowerGetStateScript(binding.name),
            // TypeScript-matching variants: delegate to equivalent legacy handlers
            .load_param => |lp| try self.lowerLoadParam(binding.name, lp.name),
            .load_prop => |lp| try self.lowerPropertyRead(binding.name, lp.name),
            .load_const => |lc| {
                try self.lowerLoadConst(binding.name, lc.value);
            },
            .bin_op => |bop| {
                const legacy_op = types.BinOperator.fromTsString(bop.op) orelse return LowerError.UnsupportedOperation;
                try self.lowerBinaryOp(binding.name, .{ .op = legacy_op, .left = bop.left, .right = bop.right, .result_type = bop.result_type });
            },
            .call => |c| {
                if (std.mem.eql(u8, c.func, "super")) {
                    try self.stack.push(self.allocator, binding.name);
                    self.trackDepth();
                } else {
                    try self.lowerBuiltinCall(binding.name, .{ .name = c.func, .args = c.args });
                }
            },
            .method_call => |mc| try self.lowerMethodCall(binding.name, mc),
            .@"if" => |ie| {
                const legacy = try self.allocator.create(types.ANFIfExpr);
                legacy.* = .{ .condition = ie.cond, .then_bindings = ie.then, .else_bindings = if (ie.@"else".len > 0) ie.@"else" else null };
                try self.lowerIfExpr(binding.name, legacy);
            },
            .loop => |lp| {
                const legacy = try self.allocator.create(types.ANFForLoop);
                legacy.* = .{ .var_name = lp.iter_var, .init_val = 0, .bound = @intCast(lp.count), .body_bindings = lp.body };
                try self.lowerForLoop(binding.name, legacy);
            },
            .assert => |a| try self.lowerAssertOp(binding.name, .{ .condition = a.value }, false),
            .update_prop => |up| try self.lowerPropertyWrite(binding.name, .{ .name = up.name, .value_ref = up.value }),
            .check_preimage => |cp| try self.lowerCheckPreimage(binding.name, &.{cp.preimage}),
            .deserialize_state => |ds| try self.lowerDeserializeState(binding.name, &.{ds.preimage}),
            .array_literal => |al| {
                for (al.elements) |elem| {
                    try self.bringToTopAuto(elem);
                }
                try self.stack.push(self.allocator, binding.name);
                self.trackDepth();
            },
        }
    }

    // ========================================================================
    // Individual value kind lowering
    // ========================================================================

    fn lowerRef(self: *LowerCtx, bind_name: []const u8, ref_name: []const u8) !void {
        const consume = self.isLastUse(ref_name);
        try self.bringToTop(ref_name, consume);
        try self.stack.renameAtDepth(self.allocator, 0, bind_name);
        if (self.isForceCopyBinding(ref_name)) {
            try self.force_copy_bindings.put(self.allocator, bind_name, {});
        }
    }

    fn lowerLoadParam(self: *LowerCtx, bind_name: []const u8, param_name: []const u8) !void {
        if (self.stack.findDepth(param_name) != null) {
            const consume = self.isLastUse(param_name);
            try self.bringToTop(param_name, consume);
            try self.stack.renameAtDepth(self.allocator, 0, bind_name);
            return;
        }

        try self.emitPushInt(0);
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerMethodCall(self: *LowerCtx, bind_name: []const u8, mc: types.ANFMethodCall) !void {
        if (std.mem.eql(u8, mc.method, "getStateScript")) {
            if (self.stack.findDepth(mc.object) != null) {
                try self.bringToTop(mc.object, true);
                try self.emitOp(.op_drop);
                _ = self.stack.pop();
            }
            try self.lowerGetStateScript(bind_name);
            return;
        }

        if (findPrivateMethod(self.program.methods, mc.method)) |method| {
            if (self.stack.findDepth(mc.object) != null) {
                try self.bringToTop(mc.object, true);
                try self.emitOp(.op_drop);
                _ = self.stack.pop();
            }
            try self.inlineMethodCall(bind_name, method, mc.args);
            return;
        }

        try self.lowerBuiltinCall(bind_name, .{ .name = mc.method, .args = mc.args });
    }

    fn inlineMethodCall(self: *LowerCtx, bind_name: []const u8, method: types.ANFMethod, args: []const []const u8) !void {
        const ShadowedName = struct {
            param_name: []const u8,
            shadowed_name: []const u8,
        };

        var shadowed = std.ArrayListUnmanaged(ShadowedName).empty;
        defer {
            for (shadowed.items) |entry| {
                self.allocator.free(entry.shadowed_name);
            }
            shadowed.deinit(self.allocator);
        }

        for (args, 0..) |arg, idx| {
            if (idx >= method.params.len) break;
            const param_name = method.params[idx].name;
            const consume = self.isLastUse(arg);
            try self.bringToTop(arg, consume);
            _ = self.stack.pop();

            if (self.stack.findDepth(param_name)) |depth| {
                const shadowed_name = try std.fmt.allocPrint(self.allocator, "__shadowed_{d}_{s}", .{ self.current_idx, param_name });
                try shadowed.append(self.allocator, .{ .param_name = param_name, .shadowed_name = shadowed_name });
                try self.stack.renameAtDepth(self.allocator, depth, shadowed_name);
            }

            try self.stack.push(self.allocator, param_name);
            self.trackDepth();
        }

        const saved_last_uses = self.last_uses;
        const saved_local_bindings = self.local_bindings;
        var saved_force_copy_bindings = self.force_copy_bindings;
        const saved_copy_ref_aliases = self.copy_ref_aliases;
        defer {
            self.local_bindings.deinit(self.allocator);
            self.local_bindings = saved_local_bindings;
            self.force_copy_bindings.deinit(self.allocator);
            self.force_copy_bindings = saved_force_copy_bindings;
            self.last_uses.deinit(self.allocator);
            self.last_uses = saved_last_uses;
            self.copy_ref_aliases = saved_copy_ref_aliases;
        }

        self.last_uses = .empty;
        self.local_bindings = .empty;
        self.force_copy_bindings = .empty;
        self.copy_ref_aliases = false;
        try self.lowerBindings(method.body, false);

        for (shadowed.items) |entry| {
            if (self.stack.findDepth(entry.shadowed_name)) |depth| {
                try self.stack.renameAtDepth(self.allocator, depth, entry.param_name);
            }
        }

        if (method.body.len > 0 and self.stack.depth() > 0) {
            const last_binding = method.body[method.body.len - 1];
            const last_binding_name = last_binding.name;
            if (self.stack.peekAtDepth(0)) |top_name| {
                if (std.mem.eql(u8, top_name, last_binding_name)) {
                    try self.stack.renameAtDepth(self.allocator, 0, bind_name);
                    const should_force_copy =
                        self.isForceCopyBinding(last_binding_name) or
                        switch (last_binding.value) {
                            .call, .builtin_call, .method_call => true,
                            else => false,
                        };
                    if (should_force_copy) {
                        try saved_force_copy_bindings.put(self.allocator, bind_name, {});
                    }
                }
            }
        }
    }

    fn lowerLoadConst(self: *LowerCtx, bind_name: []const u8, value: types.ConstValue) !void {
        switch (value) {
            .boolean => |b| try self.emitPushBool(b),
            .integer => |n| try self.emitPushInt(@intCast(n)),
            .string => |s| {
                if (std.mem.startsWith(u8, s, "@ref:")) {
                    const ref_name = s[5..];
                    const depends_on_private_result = self.isForceCopyBinding(ref_name);
                    const forced_copy = depends_on_private_result and (self.futureUseCount(bind_name) > 1 or self.feedsLaterAliasedBinding(bind_name) or self.feedsPrivateMethodCall(bind_name));
                    const consume = !self.copy_ref_aliases and !forced_copy and self.hasLocalBinding(ref_name) and self.isLastUse(ref_name);
                    try self.bringToTop(ref_name, consume);
                    try self.stack.renameAtDepth(self.allocator, 0, bind_name);
                    if (depends_on_private_result) {
                        try self.force_copy_bindings.put(self.allocator, bind_name, {});
                    }
                    return;
                }

                if (std.mem.eql(u8, s, "@this")) {
                    try self.emitPushInt(0);
                } else {
                    try self.emitPushHexString(s);
                }
            },
        }
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerPropertyRead(self: *LowerCtx, bind_name: []const u8, prop_name: []const u8) !void {
        // Check if property has been updated on stack
        if (self.updated_props.get(prop_name) != null) {
            if (self.stack.findDepth(prop_name)) |_| {
                try self.bringToTop(prop_name, false);
                try self.stack.renameAtDepth(self.allocator, 0, bind_name);
                return;
            }
        }
        // Property might be on stack from setup
        if (self.stack.findDepth(prop_name)) |_| {
            try self.bringToTop(prop_name, false);
            try self.stack.renameAtDepth(self.allocator, 0, bind_name);
            return;
        }
        // Check if the property has an initial_value
        for (self.program.properties) |prop| {
            if (std.mem.eql(u8, prop.name, prop_name)) {
                if (prop.initial_value) |iv| {
                    switch (iv) {
                        .boolean => |b| try self.emitPushBool(b),
                        .integer => |n| try self.emitPushInt(@intCast(n)),
                        .string => |s| try self.emitPushHexString(s),
                    }
                    try self.stack.push(self.allocator, bind_name);
                    self.trackDepth();
                    return;
                }
            }
        }
        // Not found — push constructor param placeholder
        // Determine param_index: count properties without initial_value before this one
        var param_idx: u32 = 0;
        for (self.program.properties) |prop| {
            if (std.mem.eql(u8, prop.name, prop_name)) break;
            if (prop.initial_value == null) param_idx += 1;
        }
        try self.emit(.{ .placeholder = .{ .param_index = param_idx, .param_name = prop_name } });
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerPropertyWrite(self: *LowerCtx, bind_name: []const u8, pw: types.PropertyWrite) !void {
        const consume = self.isLastUse(pw.value_ref);
        try self.bringToTop(pw.value_ref, consume);
        try self.stack.renameAtDepth(self.allocator, 0, pw.name);
        try self.updated_props.put(self.allocator, pw.name, {});

        // Remove stale entry via ROLL+DROP (unless inside branch)
        if (!self.in_branch) {
            var found_first = false;
            var old_depth: ?usize = null;
            // Scan from top (end of array) to bottom, finding first then stale duplicate
            const len = self.stack.slots.items.len;
            var scan: usize = 0;
            while (scan < len) : (scan += 1) {
                const depth_idx = len - 1 - scan;
                if (self.stack.slots.items[depth_idx]) |s| {
                    if (std.mem.eql(u8, s, pw.name)) {
                        if (found_first) {
                            old_depth = scan; // depth from top
                            break;
                        }
                        found_first = true;
                    }
                }
            }
            if (old_depth) |od| {
                if (od == 1) {
                    try self.emitOp(.op_nip);
                } else {
                    try self.emitPushInt(@intCast(od));
                    try self.emitOp(.op_roll);
                    try self.emitOp(.op_drop);
                }
                try self.stack.removeAtDepth(self.allocator, od);
            }
        }
        _ = bind_name;
    }

    fn lowerBinaryOp(self: *LowerCtx, bind_name: []const u8, bop: types.ANFBinaryOp) !void {
        try self.bringToTopAuto(bop.left);
        try self.bringToTopAuto(bop.right);

        const is_bytes = if (bop.result_type) |t| std.mem.eql(u8, t, "bytes") else false;

        switch (bop.op) {
            .add => try self.emitOp(if (is_bytes) .op_cat else .op_add),
            .sub => try self.emitOp(.op_sub),
            .mul => try self.emitOp(.op_mul),
            .div => try self.emitOp(.op_div),
            .mod => try self.emitOp(.op_mod),
            .eq => try self.emitOp(if (is_bytes) .op_equal else .op_numequal),
            .neq => {
                try self.emitOp(if (is_bytes) .op_equal else .op_numequal);
                try self.emitOp(.op_not);
            },
            .lt => try self.emitOp(.op_lessthan),
            .gt => try self.emitOp(.op_greaterthan),
            .lte => try self.emitOp(.op_lessthanorequal),
            .gte => try self.emitOp(.op_greaterthanorequal),
            .and_op => try self.emitOp(.op_booland),
            .or_op => try self.emitOp(.op_boolor),
            .bitand => try self.emitOp(.op_and),
            .bitor => try self.emitOp(.op_or),
            .bitxor => try self.emitOp(.op_xor),
            .lshift => try self.emitOp(.op_lshift),
            .rshift => try self.emitOp(.op_rshift),
        }

        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        if (self.isForceCopyBinding(bop.left) or self.isForceCopyBinding(bop.right)) {
            try self.force_copy_bindings.put(self.allocator, bind_name, {});
        }
        self.trackDepth();
    }

    fn lowerUnaryOp(self: *LowerCtx, bind_name: []const u8, uop: types.ANFUnaryOp) !void {
        try self.bringToTopAuto(uop.operand);

        if (std.mem.eql(u8, uop.op, "-")) {
            try self.emitOp(.op_negate);
        } else if (std.mem.eql(u8, uop.op, "!")) {
            try self.emitOp(.op_not);
        } else if (std.mem.eql(u8, uop.op, "~")) {
            try self.emitOp(.op_invert);
        }

        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        if (self.isForceCopyBinding(uop.operand)) {
            try self.force_copy_bindings.put(self.allocator, bind_name, {});
        }
        self.trackDepth();
    }

    const BuiltinId = enum {
        sha256,
        hash160,
        hash256,
        ripemd160,
        checkSig,
        checkMultiSig,
        len,
        cat,
        num2bin,
        bin2num,
        abs,
        min,
        max,
        within,
        split,
        left,
        int2str,
        bool_builtin,
        unpack,
        assert,
        substr,
        reverseBytes,
        safediv,
        safemod,
        pow,
        mulDiv,
        percentOf,
        sqrt,
        gcd,
        divmod,
        log2,
        clamp,
        checkPreimage,
        deserializeState,
        extractHashPrevouts,
        extractLocktime,
        extractOutpoint,
        extractOutputHash,
        buildChangeOutput,
        getStateScript,
        buildStateOutput,
        computeStateOutput,
        computeStateOutputHash,
        sign,
        verifyRabinSig,
        verifyWOTS,
        ecNegate,
        ecOnCurve,
        ecMulGen,
        ecModReduce,
        ecEncodeCompressed,
        ecMakePoint,
        ecPointX,
        ecPointY,
        // Wave 3 placeholders
        sha256Compress,
        sha256Finalize,
        blake3,
        ecAdd,
        ecMul,
        ecPairing,
        slhDsaVerify,
        schnorrVerify,
        // Baby Bear field arithmetic
        bbFieldAdd,
        bbFieldSub,
        bbFieldMul,
        bbFieldInv,
        // Baby Bear quartic extension field arithmetic
        bbExt4Mul0,
        bbExt4Mul1,
        bbExt4Mul2,
        bbExt4Mul3,
        bbExt4Inv0,
        bbExt4Inv1,
        bbExt4Inv2,
        bbExt4Inv3,
        // Merkle proof verification
        merkleRootSha256,
        merkleRootHash256,
        super_call,
    };

    const builtin_map = std.StaticStringMap(BuiltinId).initComptime(.{
        .{ "sha256", .sha256 },
        .{ "hash160", .hash160 },
        .{ "hash256", .hash256 },
        .{ "ripemd160", .ripemd160 },
        .{ "checkSig", .checkSig },
        .{ "checkMultiSig", .checkMultiSig },
        .{ "len", .len },
        .{ "size", .len },
        .{ "cat", .cat },
        .{ "num2bin", .num2bin },
        .{ "bin2num", .bin2num },
        .{ "abs", .abs },
        .{ "min", .min },
        .{ "max", .max },
        .{ "within", .within },
        .{ "split", .split },
        .{ "left", .left },
        .{ "int2str", .int2str },
        .{ "bool", .bool_builtin },
        .{ "unpack", .unpack },
        .{ "assert", .assert },
        .{ "substr", .substr },
        .{ "reverseBytes", .reverseBytes },
        .{ "safediv", .safediv },
        .{ "safemod", .safemod },
        .{ "pow", .pow },
        .{ "mulDiv", .mulDiv },
        .{ "percentOf", .percentOf },
        .{ "sqrt", .sqrt },
        .{ "gcd", .gcd },
        .{ "divmod", .divmod },
        .{ "log2", .log2 },
        .{ "clamp", .clamp },
        .{ "checkPreimage", .checkPreimage },
        .{ "deserializeState", .deserializeState },
        .{ "extractHashPrevouts", .extractHashPrevouts },
        .{ "extractLocktime", .extractLocktime },
        .{ "extractOutpoint", .extractOutpoint },
        .{ "extractOutputHash", .extractOutputHash },
        .{ "buildChangeOutput", .buildChangeOutput },
        .{ "getStateScript", .getStateScript },
        .{ "buildStateOutput", .buildStateOutput },
        .{ "computeStateOutput", .computeStateOutput },
        .{ "computeStateOutputHash", .computeStateOutputHash },
        .{ "sign", .sign },
        .{ "verifyRabinSig", .verifyRabinSig },
        .{ "verifyWOTS", .verifyWOTS },
        .{ "ecNegate", .ecNegate },
        .{ "ecOnCurve", .ecOnCurve },
        .{ "ecMulGen", .ecMulGen },
        .{ "ecModReduce", .ecModReduce },
        .{ "ecEncodeCompressed", .ecEncodeCompressed },
        .{ "ecMakePoint", .ecMakePoint },
        .{ "ecPointX", .ecPointX },
        .{ "ecPointY", .ecPointY },
        .{ "sha256Compress", .sha256Compress },
        .{ "sha256Finalize", .sha256Finalize },
        .{ "blake3Compress", .blake3 },
        .{ "blake3Hash", .blake3 },
        .{ "blake3", .blake3 },
        .{ "ecAdd", .ecAdd },
        .{ "ecMul", .ecMul },
        .{ "ecPairing", .ecPairing },
        .{ "verifySLHDSA_SHA2_128s", .slhDsaVerify },
        .{ "verifySLHDSA_SHA2_128f", .slhDsaVerify },
        .{ "verifySLHDSA_SHA2_192s", .slhDsaVerify },
        .{ "verifySLHDSA_SHA2_192f", .slhDsaVerify },
        .{ "verifySLHDSA_SHA2_256s", .slhDsaVerify },
        .{ "verifySLHDSA_SHA2_256f", .slhDsaVerify },
        .{ "slhDsaVerify", .slhDsaVerify },
        .{ "schnorrVerify", .schnorrVerify },
        .{ "bbFieldAdd", .bbFieldAdd },
        .{ "bbFieldSub", .bbFieldSub },
        .{ "bbFieldMul", .bbFieldMul },
        .{ "bbFieldInv", .bbFieldInv },
        .{ "bbExt4Mul0", .bbExt4Mul0 },
        .{ "bbExt4Mul1", .bbExt4Mul1 },
        .{ "bbExt4Mul2", .bbExt4Mul2 },
        .{ "bbExt4Mul3", .bbExt4Mul3 },
        .{ "bbExt4Inv0", .bbExt4Inv0 },
        .{ "bbExt4Inv1", .bbExt4Inv1 },
        .{ "bbExt4Inv2", .bbExt4Inv2 },
        .{ "bbExt4Inv3", .bbExt4Inv3 },
        .{ "merkleRootSha256", .merkleRootSha256 },
        .{ "merkleRootHash256", .merkleRootHash256 },
        .{ "super", .super_call },
    });

    fn lowerBuiltinCall(self: *LowerCtx, bind_name: []const u8, call: types.ANFBuiltinCall) LowerError!void {
        const args = call.args;

        const id = builtin_map.get(call.name) orelse return LowerError.InvalidBuiltin;

        switch (id) {
            .sha256 => try self.lowerSimpleUnaryBuiltin(bind_name, args, .op_sha256),
            .hash160 => try self.lowerSimpleUnaryBuiltin(bind_name, args, .op_hash160),
            .hash256 => try self.lowerSimpleUnaryBuiltin(bind_name, args, .op_hash256),
            .ripemd160 => try self.lowerSimpleUnaryBuiltin(bind_name, args, .op_ripemd160),
            .checkSig => try self.lowerCheckSig(bind_name, args),
            .checkMultiSig => try self.lowerCheckMultiSig(bind_name, args),
            .len => try self.lowerLen(bind_name, args),
            .cat => try self.lowerCat(bind_name, args),
            .num2bin => try self.lowerNum2Bin(bind_name, args),
            .bin2num => try self.lowerSimpleUnaryBuiltin(bind_name, args, .op_bin2num),
            .abs => try self.lowerSimpleUnaryBuiltin(bind_name, args, .op_abs),
            .min => try self.lowerSimpleBinaryBuiltin(bind_name, args, .op_min),
            .max => try self.lowerSimpleBinaryBuiltin(bind_name, args, .op_max),
            .within => try self.lowerWithin(bind_name, args),
            .split => try self.lowerSplit(bind_name, args),
            .left => try self.lowerLeft(bind_name, args),
            .int2str => try self.lowerNum2Bin(bind_name, args),
            .bool_builtin => try self.lowerSimpleUnaryBuiltin(bind_name, args, .op_0notequal),
            .unpack => try self.lowerSimpleUnaryBuiltin(bind_name, args, .op_bin2num),
            .assert => try self.lowerAssertBuiltin(bind_name, args),
            .substr => try self.lowerSubstr(bind_name, args),
            .reverseBytes => try self.lowerReverseBytes(bind_name, args),
            .safediv => try self.lowerSafeDiv(bind_name, args),
            .safemod => try self.lowerSafeMod(bind_name, args),
            .pow => try self.lowerPow(bind_name, args),
            .mulDiv => try self.lowerMulDiv(bind_name, args),
            .percentOf => try self.lowerPercentOf(bind_name, args),
            .sqrt => try self.lowerSqrt(bind_name, args),
            .gcd => try self.lowerGcd(bind_name, args),
            .divmod => try self.lowerDivMod(bind_name, args),
            .log2 => try self.lowerLog2(bind_name, args),
            .clamp => try self.lowerClamp(bind_name, args),
            .checkPreimage => try self.lowerCheckPreimage(bind_name, args),
            .deserializeState => try self.lowerDeserializeState(bind_name, args),
            .extractHashPrevouts, .extractLocktime, .extractOutpoint, .extractOutputHash => try self.lowerExtractor(bind_name, id, args),
            .sign => try self.lowerSign(bind_name, args),
            .buildChangeOutput => try self.lowerBuildChangeOutput(bind_name, args),
            .getStateScript => try self.lowerGetStateScript(bind_name),
            .buildStateOutput, .computeStateOutput => try self.lowerComputeStateOutput(bind_name, args),
            .computeStateOutputHash => try self.lowerComputeStateOutputHash(bind_name, args),
            .verifyRabinSig => try self.lowerCryptoBuiltin(bind_name, args, .verify_rabin_sig),
            .verifyWOTS => {
                const crypto_builtin = crypto_builtins.classify(call.name) orelse return LowerError.InvalidBuiltin;
                try self.lowerPqBuiltin(bind_name, args, crypto_builtin);
            },
            .ecNegate => try self.lowerEcBuiltin(bind_name, args, .ec_negate),
            .ecOnCurve => try self.lowerEcBuiltin(bind_name, args, .ec_on_curve),
            .ecMulGen => try self.lowerEcBuiltin(bind_name, args, .ec_mul_gen),
            .ecModReduce => try self.lowerCryptoBuiltin(bind_name, args, .ec_mod_reduce),
            .ecEncodeCompressed => try self.lowerCryptoBuiltin(bind_name, args, .ec_encode_compressed),
            .ecMakePoint => try self.lowerCryptoBuiltin(bind_name, args, .ec_make_point),
            .ecPointX => try self.lowerCryptoBuiltin(bind_name, args, .ec_point_x),
            .ecPointY => try self.lowerCryptoBuiltin(bind_name, args, .ec_point_y),
            .ecAdd => try self.lowerEcBuiltin(bind_name, args, .ec_add),
            .ecMul => try self.lowerEcBuiltin(bind_name, args, .ec_mul),
            .sha256Compress => try self.lowerSha256Builtin(bind_name, args, .compress),
            .sha256Finalize => try self.lowerSha256Builtin(bind_name, args, .finalize),
            .blake3 => {
                const crypto_builtin = crypto_builtins.classify(call.name) orelse return LowerError.InvalidBuiltin;
                try self.lowerBlake3Builtin(bind_name, args, crypto_builtin);
            },
            .slhDsaVerify => {
                const crypto_builtin = crypto_builtins.classify(call.name) orelse return LowerError.InvalidBuiltin;
                try self.lowerPqBuiltin(bind_name, args, crypto_builtin);
            },
            // Baby Bear field arithmetic
            .bbFieldAdd => try self.lowerBBBuiltin(bind_name, args, .bb_field_add),
            .bbFieldSub => try self.lowerBBBuiltin(bind_name, args, .bb_field_sub),
            .bbFieldMul => try self.lowerBBBuiltin(bind_name, args, .bb_field_mul),
            .bbFieldInv => try self.lowerBBBuiltin(bind_name, args, .bb_field_inv),
            // Baby Bear quartic extension field arithmetic
            .bbExt4Mul0 => try self.lowerBBBuiltin(bind_name, args, .bb_ext4_mul0),
            .bbExt4Mul1 => try self.lowerBBBuiltin(bind_name, args, .bb_ext4_mul1),
            .bbExt4Mul2 => try self.lowerBBBuiltin(bind_name, args, .bb_ext4_mul2),
            .bbExt4Mul3 => try self.lowerBBBuiltin(bind_name, args, .bb_ext4_mul3),
            .bbExt4Inv0 => try self.lowerBBBuiltin(bind_name, args, .bb_ext4_inv0),
            .bbExt4Inv1 => try self.lowerBBBuiltin(bind_name, args, .bb_ext4_inv1),
            .bbExt4Inv2 => try self.lowerBBBuiltin(bind_name, args, .bb_ext4_inv2),
            .bbExt4Inv3 => try self.lowerBBBuiltin(bind_name, args, .bb_ext4_inv3),
            // Merkle proof verification
            .merkleRootSha256 => try self.lowerMerkleBuiltin(bind_name, args, call.name, .merkle_root_sha256),
            .merkleRootHash256 => try self.lowerMerkleBuiltin(bind_name, args, call.name, .merkle_root_hash256),
            // super() is the constructor superclass call — no-op in Bitcoin Script
            .super_call => {
                try self.stack.push(self.allocator, bind_name);
                self.trackDepth();
            },
            // Wave 3 placeholders — consume args and push placeholder
            .ecPairing, .schnorrVerify => {
                for (args) |arg| {
                    try self.bringToTopAuto(arg);
                    _ = self.stack.pop();
                }
                try self.emitPushInt(0);
                try self.stack.push(self.allocator, bind_name);
                self.trackDepth();
            },
        }
    }

    fn lowerCryptoBuiltin(self: *LowerCtx, bind_name: []const u8, args: []const []const u8, builtin: crypto_builtins.CryptoBuiltin) LowerError!void {
        if (args.len < crypto_builtins.requiredArgCount(builtin)) return LowerError.InvalidBuiltin;

        for (args) |arg| {
            try self.bringToTopAuto(arg);
        }
        for (args) |_| {
            _ = self.stack.pop();
        }

        var emitted: std.ArrayListUnmanaged(crypto_emitters.CryptoInstruction) = .empty;
        defer emitted.deinit(self.allocator);
        crypto_emitters.appendBuiltinInstructions(&emitted, self.allocator, builtin) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NotImplemented => return error.InvalidBuiltin,
        };

        for (emitted.items) |inst| {
            switch (inst) {
                .op_name => |name| {
                    const opcode = opcodes.byName(name) orelse return LowerError.InvalidBuiltin;
                    try self.emitOp(opcode);
                },
                .push_int => |n| try self.emitPushInt(n),
                .push_data => |data| try self.emitPushData(data),
            }
        }

        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerSha256Builtin(self: *LowerCtx, bind_name: []const u8, args: []const []const u8, builtin: sha256_emitters.Sha256Builtin) LowerError!void {
        if (args.len < sha256_emitters.requiredArgCount(builtin)) return LowerError.InvalidBuiltin;

        for (args) |arg| {
            try self.bringToTopAuto(arg);
        }
        for (args) |_| {
            _ = self.stack.pop();
        }

        var emitted: std.ArrayListUnmanaged(sha256_emitters.Sha256Instruction) = .empty;
        defer emitted.deinit(self.allocator);
        sha256_emitters.appendBuiltinInstructions(&emitted, self.allocator, builtin) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidBuiltin,
        };

        for (emitted.items) |inst| {
            switch (inst) {
                .op_name => |name| {
                    const opcode = opcodes.byName(name) orelse return LowerError.InvalidBuiltin;
                    try self.emitOp(opcode);
                },
                .push_int => |n| try self.emitPushInt(n),
                .push_data => |data| try self.emitPushData(data),
            }
        }

        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerBlake3Builtin(self: *LowerCtx, bind_name: []const u8, args: []const []const u8, builtin: crypto_builtins.CryptoBuiltin) LowerError!void {
        const blake_builtin = switch (builtin) {
            .blake3_compress => blake3_emitters.Blake3Builtin.compress,
            .blake3_hash => blake3_emitters.Blake3Builtin.hash,
            .blake3 => blake3_emitters.Blake3Builtin.blake3,
            else => return LowerError.InvalidBuiltin,
        };
        if (args.len < crypto_builtins.requiredArgCount(builtin)) return LowerError.InvalidBuiltin;

        for (args) |arg| {
            try self.bringToTopAuto(arg);
        }
        for (args) |_| {
            _ = self.stack.pop();
        }

        var emitted: std.ArrayListUnmanaged(blake3_emitters.Blake3Instruction) = .empty;
        defer emitted.deinit(self.allocator);
        blake3_emitters.appendBuiltinInstructions(&emitted, self.allocator, blake_builtin) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidBuiltin,
        };

        for (emitted.items) |inst| {
            switch (inst) {
                .op_name => |name| {
                    const opcode = opcodes.byName(name) orelse return LowerError.InvalidBuiltin;
                    try self.emitOp(opcode);
                },
                .push_int => |n| try self.emitPushInt(n),
                .push_data => |data| try self.emitPushData(data),
            }
        }

        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerPqBuiltin(self: *LowerCtx, bind_name: []const u8, args: []const []const u8, builtin: crypto_builtins.CryptoBuiltin) LowerError!void {
        if (args.len < crypto_builtins.requiredArgCount(builtin)) return LowerError.InvalidBuiltin;

        for (args) |arg| {
            try self.bringToTopAuto(arg);
        }
        for (args) |_| {
            _ = self.stack.pop();
        }

        var emitted: std.ArrayListUnmanaged(pq_emitters.CryptoInstruction) = .empty;
        defer emitted.deinit(self.allocator);
        pq_emitters.appendBuiltinInstructions(&emitted, self.allocator, builtin) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidBuiltin,
        };

        for (emitted.items) |inst| {
            switch (inst) {
                .op_name => |name| {
                    const opcode = opcodes.byName(name) orelse return LowerError.InvalidBuiltin;
                    try self.emitOp(opcode);
                },
                .push_int => |n| try self.emitPushInt(n),
                .push_data => |data| try self.emitPushData(data),
            }
        }

        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn emitEcStackOp(self: *LowerCtx, op: ec_emitters.StackOp) LowerError!void {
        switch (op) {
            .push => |value| switch (value) {
                .bytes => |bytes| {
                    const owned = try self.allocator.dupe(u8, bytes);
                    try self.emitOwnedPushData(owned);
                },
                .integer => |n| try self.emitPushInt(n),
                .boolean => |b| try self.emitPushBool(b),
            },
            .dup => try self.emitOp(.op_dup),
            .swap => try self.emitOp(.op_swap),
            .drop => try self.emitOp(.op_drop),
            .nip => try self.emitOp(.op_nip),
            .over => try self.emitOp(.op_over),
            .rot => try self.emitOp(.op_rot),
            .tuck => try self.emitOp(.op_tuck),
            .roll => |depth| {
                try self.emitPushInt(@intCast(depth));
                try self.emitOp(.op_roll);
            },
            .pick => |depth| {
                try self.emitPushInt(@intCast(depth));
                try self.emitOp(.op_pick);
            },
            .opcode => |name| {
                const opcode = opcodes.byName(name) orelse return LowerError.InvalidBuiltin;
                try self.emitOp(opcode);
            },
            .@"if" => |stack_if| {
                try self.emitOp(.op_if);
                for (stack_if.then) |then_op| {
                    try self.emitEcStackOp(then_op);
                }
                if (stack_if.@"else") |else_ops| {
                    try self.emitOp(.op_else);
                    for (else_ops) |else_op| {
                        try self.emitEcStackOp(else_op);
                    }
                }
                try self.emitOp(.op_endif);
            },
        }
    }

    fn lowerEcBuiltin(self: *LowerCtx, bind_name: []const u8, args: []const []const u8, builtin: crypto_builtins.CryptoBuiltin) LowerError!void {
        if (args.len < crypto_builtins.requiredArgCount(builtin)) return LowerError.InvalidBuiltin;

        for (args) |arg| {
            try self.bringToTopAuto(arg);
        }
        for (args) |_| {
            _ = self.stack.pop();
        }

        var bundle = ec_emitters.buildBuiltinOps(self.allocator, builtin) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.UnsupportedBuiltin => return error.InvalidBuiltin,
            else => return error.UnsupportedOperation,
        };
        defer bundle.deinit();

        for (bundle.ops) |op| {
            try self.emitEcStackOp(op);
        }

        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerBBBuiltin(self: *LowerCtx, bind_name: []const u8, args: []const []const u8, builtin: babybear_emitters.BBBuiltin) LowerError!void {
        const required: usize = switch (builtin) {
            .bb_field_add, .bb_field_sub, .bb_field_mul => 2,
            .bb_field_inv => 1,
            .bb_ext4_mul0, .bb_ext4_mul1, .bb_ext4_mul2, .bb_ext4_mul3 => 8,
            .bb_ext4_inv0, .bb_ext4_inv1, .bb_ext4_inv2, .bb_ext4_inv3 => 4,
        };
        if (args.len < required) return LowerError.InvalidBuiltin;

        for (args) |arg| {
            try self.bringToTopAuto(arg);
        }
        for (args) |_| {
            _ = self.stack.pop();
        }

        var bundle = babybear_emitters.buildBuiltinOps(self.allocator, builtin) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.UnsupportedOperation,
        };
        defer bundle.deinit();

        for (bundle.ops) |op| {
            try self.emitEcStackOp(op);
        }

        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerMerkleBuiltin(
        self: *LowerCtx,
        bind_name: []const u8,
        args: []const []const u8,
        func_name: []const u8,
        builtin: merkle_emitters.MerkleBuiltin,
    ) LowerError!void {
        // args: [leaf, proof, index, depth]
        // depth must be a compile-time constant
        if (args.len != 4) return LowerError.InvalidBuiltin;
        _ = func_name;

        // Extract depth constant from ANF binding
        const depth_arg = args[3];
        const depth_value = self.findConstantInt(depth_arg) orelse return LowerError.InvalidBuiltin;
        if (depth_value < 1 or depth_value > 64) return LowerError.InvalidBuiltin;

        // Remove depth from the real stack FIRST (compile-time constant, not runtime).
        if (self.stack.findDepth(depth_arg) != null) {
            try self.bringToTopAuto(depth_arg);
            try self.emitOp(.op_drop);
            _ = self.stack.pop();
        }

        // Bring leaf, proof, index to stack top for the codegen
        for (0..3) |i| {
            try self.bringToTopAuto(args[i]);
        }
        // Pop the 3 args -- the codegen consumes them and produces 1 result
        for (0..3) |_| {
            _ = self.stack.pop();
        }

        var bundle = merkle_emitters.buildBuiltinOps(self.allocator, builtin, @intCast(depth_value)) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.UnsupportedOperation,
        };
        defer bundle.deinit();

        for (bundle.ops) |op| {
            try self.emitEcStackOp(op);
        }

        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    /// Look up a binding name in scope_bindings to find a compile-time constant integer.
    fn findConstantInt(self: *const LowerCtx, name: []const u8) ?i64 {
        for (self.scope_bindings) |binding| {
            if (std.mem.eql(u8, binding.name, name)) {
                switch (binding.value) {
                    .literal_int => |n| return n,
                    .load_const => |lc| switch (lc.value) {
                        .integer => |n| return std.math.cast(i64, n),
                        else => return null,
                    },
                    else => return null,
                }
            }
        }
        return null;
    }

    // ========================================================================
    // Simple builtin helpers
    // ========================================================================

    fn lowerSimpleUnaryBuiltin(self: *LowerCtx, bind_name: []const u8, args: []const []const u8, op: Opcode) !void {
        if (args.len < 1) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        try self.emitOp(op);
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerSimpleBinaryBuiltin(self: *LowerCtx, bind_name: []const u8, args: []const []const u8, op: Opcode) !void {
        if (args.len < 2) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        try self.bringToTopAuto(args[1]);
        try self.emitOp(op);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    // ========================================================================
    // Specific builtin implementations
    // ========================================================================

    fn lowerCheckSig(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        return self.lowerSimpleBinaryBuiltin(bind_name, args, .op_checksig);
    }

    fn lowerCheckMultiSig(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        for (args) |arg| {
            try self.bringToTopAuto(arg);
        }
        try self.emitOp(.op_checkmultisig);
        for (args) |_| {
            _ = self.stack.pop();
        }
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerLen(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 1) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        try self.emitOp(.op_size);
        try self.emitOp(.op_nip);
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerCat(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        return self.lowerSimpleBinaryBuiltin(bind_name, args, .op_cat);
    }

    fn lowerNum2Bin(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        return self.lowerSimpleBinaryBuiltin(bind_name, args, .op_num2bin);
    }

    fn lowerWithin(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 3) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        try self.bringToTopAuto(args[1]);
        try self.bringToTopAuto(args[2]);
        try self.emitOp(.op_within);
        _ = self.stack.pop();
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerAssertBuiltin(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 1) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        try self.emitOp(.op_verify);
        _ = self.stack.pop();
        _ = bind_name;
    }

    fn lowerSplit(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 2) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]); // data
        try self.bringToTopAuto(args[1]); // position
        try self.emitOp(.op_split);
        // OP_SPLIT consumes data + position, produces left + right (two outputs)
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null); // left part
        try self.stack.push(self.allocator, bind_name); // right part (top)
        self.trackDepth();
    }

    fn lowerLeft(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 2) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]); // data
        try self.bringToTopAuto(args[1]); // length
        try self.emitOp(.op_split);
        try self.emitOp(.op_drop); // drop right, keep left
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerSubstr(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 3) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]); // s
        try self.bringToTopAuto(args[1]); // start
        try self.emitOp(.op_split);
        try self.emitOp(.op_nip); // drop left, keep right
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        self.trackDepth();

        try self.bringToTopAuto(args[2]); // length
        try self.emitOp(.op_split);
        try self.emitOp(.op_drop); // drop rest, keep substr
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerReverseBytes(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 1) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        // reverseBytes is typically unrolled at compile time for known sizes.
        // For generic use, the value is left as-is (future optimization pass).
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerSafeDivMod(self: *LowerCtx, bind_name: []const u8, args: []const []const u8, final_op: Opcode) !void {
        if (args.len < 2) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        try self.bringToTopAuto(args[1]);
        try self.emitOp(.op_dup);
        try self.emitOp(.op_0notequal);
        try self.emitOp(.op_verify);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.emitOp(final_op);
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerSafeDiv(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        return self.lowerSafeDivMod(bind_name, args, .op_div);
    }

    fn lowerSafeMod(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        return self.lowerSafeDivMod(bind_name, args, .op_mod);
    }

    fn lowerPow(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 2) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        try self.bringToTopAuto(args[1]);
        _ = self.stack.pop();
        _ = self.stack.pop();

        try self.emitOp(.op_swap);
        try self.emitPushInt(1);
        var iter: u32 = 0;
        while (iter < 32) : (iter += 1) {
            try self.emitPushInt(2);
            try self.emitOp(.op_pick);
            try self.emitPushInt(iter);
            try self.emitOp(.op_greaterthan);
            try self.emitOp(.op_if);
            try self.emitOp(.op_over);
            try self.emitOp(.op_mul);
            try self.emitOp(.op_endif);
        }
        try self.emitOp(.op_nip);
        try self.emitOp(.op_nip);

        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerMulDiv(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 3) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        try self.bringToTopAuto(args[1]);
        try self.emitOp(.op_mul);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        self.trackDepth();
        try self.bringToTopAuto(args[2]);
        try self.emitOp(.op_div);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerPercentOf(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 2) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        try self.bringToTopAuto(args[1]);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.emitOp(.op_mul);
        try self.emitPushInt(10000);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_div);
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerSqrt(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 1) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        _ = self.stack.pop();
        try self.emitOp(.op_dup);
        try self.emitOp(.op_if);
        try self.emitOp(.op_dup);
        var iter: u32 = 0;
        while (iter < 16) : (iter += 1) {
            try self.emitOp(.op_over);
            try self.emitOp(.op_over);
            try self.emitOp(.op_div);
            try self.emitOp(.op_add);
            try self.emitPushInt(2);
            try self.emitOp(.op_div);
        }
        try self.emitOp(.op_nip);
        try self.emitOp(.op_endif);
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerGcd(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 2) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        try self.bringToTopAuto(args[1]);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.emitOp(.op_abs);
        try self.emitOp(.op_swap);
        try self.emitOp(.op_abs);
        try self.emitOp(.op_swap);
        var iter: u32 = 0;
        while (iter < 256) : (iter += 1) {
            try self.emitOp(.op_dup);
            try self.emitOp(.op_0notequal);
            try self.emitOp(.op_if);
            try self.emitOp(.op_tuck);
            try self.emitOp(.op_mod);
            try self.emitOp(.op_endif);
        }
        try self.emitOp(.op_drop);
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerDivMod(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 2) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        try self.bringToTopAuto(args[1]);
        try self.emitOp(.op_over);
        try self.emitOp(.op_over);
        try self.emitOp(.op_mod);
        try self.emitOp(.op_rot);
        try self.emitOp(.op_rot);
        try self.emitOp(.op_div);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerLog2(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 1) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        _ = self.stack.pop();
        try self.emitPushInt(0);
        var iter: u32 = 0;
        while (iter < 64) : (iter += 1) {
            try self.emitOp(.op_swap);
            try self.emitOp(.op_dup);
            try self.emitPushInt(1);
            try self.emitOp(.op_greaterthan);
            try self.emitOp(.op_if);
            try self.emitPushInt(2);
            try self.emitOp(.op_div);
            try self.emitOp(.op_swap);
            try self.emitOp(.op_1add);
            try self.emitOp(.op_swap);
            try self.emitOp(.op_endif);
            try self.emitOp(.op_swap);
        }
        try self.emitOp(.op_nip);
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerClamp(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 3) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        try self.bringToTopAuto(args[1]);
        try self.emitOp(.op_max);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        self.trackDepth();
        try self.bringToTopAuto(args[2]);
        try self.emitOp(.op_min);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerSign(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 1) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        _ = self.stack.pop();
        try self.emitOp(.op_dup);
        try self.emitOp(.op_if);
        try self.emitOp(.op_dup);
        try self.emitOp(.op_abs);
        try self.emitOp(.op_swap);
        try self.emitOp(.op_div);
        try self.emitOp(.op_endif);
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerCheckPreimage(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 1) return LowerError.InvalidBuiltin;
        try self.emitOp(.op_codeseparator);
        try self.bringToTopAuto(args[0]);
        if (self.stack.findDepth("_opPushTxSig") == null) return LowerError.VariableNotFound;
        try self.bringToTop("_opPushTxSig", true);
        try self.emitPushData(&generator_point_g);
        // Track the generator point in the stack map so pop accounting is correct
        try self.stack.push(self.allocator, null);
        self.trackDepth();
        // OP_CHECKSIGVERIFY consumes top 2 items (sig/txsig + pubkey/G)
        try self.emitOp(.op_checksigverify);
        _ = self.stack.pop(); // G (generator point)
        _ = self.stack.pop(); // _opPushTxSig
        // preimage (args[0]) remains on stack — consumed by caller or used downstream
        try self.stack.renameAtDepth(self.allocator, 0, bind_name);
        self.trackDepth();
    }

    fn lowerDeserializeState(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 1) return LowerError.InvalidBuiltin;
        _ = bind_name;

        // Collect mutable state properties and their sizes
        var state_props = std.ArrayListUnmanaged(types.ANFProperty).empty;
        defer state_props.deinit(self.allocator);
        var prop_sizes = std.ArrayListUnmanaged(i64).empty;
        defer prop_sizes.deinit(self.allocator);
        var has_variable_length = false;
        for (self.program.properties) |prop| {
            if (prop.readonly) continue;
            try state_props.append(self.allocator, prop);
            const sz = try statePropSize(prop);
            try prop_sizes.append(self.allocator, sz);
            if (sz < 0) has_variable_length = true;
        }
        if (state_props.items.len == 0) return;

        try self.bringToTopAuto(args[0]);

        // 1. Skip first 104 bytes (header), drop prefix
        try self.emitPushInt(104);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_nip);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);

        // 2. Drop tail 44 bytes
        try self.emitOp(.op_size);
        try self.stack.push(self.allocator, null);
        try self.emitPushInt(44);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_sub);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_drop);
        _ = self.stack.pop();

        // 3. Drop amount (last 8 bytes)
        try self.emitOp(.op_size);
        try self.stack.push(self.allocator, null);
        try self.emitPushInt(8);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_sub);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_drop);
        _ = self.stack.pop();

        if (!has_variable_length) {
            // All fields fixed-size -- existing code path (backward compatible)
            var state_len: i64 = 0;
            for (prop_sizes.items) |sz| state_len += sz;

            // 4. Extract last stateLen bytes (the state section)
            try self.emitOp(.op_size);
            try self.stack.push(self.allocator, null);
            try self.emitPushInt(state_len);
            try self.stack.push(self.allocator, null);
            try self.emitOp(.op_sub);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null);
            try self.emitOp(.op_split);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null);
            try self.stack.push(self.allocator, null);
            try self.emitOp(.op_nip);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null);

            // 5. Split fixed-size state fields
            try self.splitFixedStateFields(state_props.items, prop_sizes.items);
        } else if (self.stack.findDepth("_codePart") == null) {
            // Variable-length state but _codePart not available (terminal method).
            // Skip deserialization -- the method body doesn't use mutable state.
            try self.emitOp(.op_drop);
            _ = self.stack.pop();
        } else {
            // Variable-length path: strip varint, use _codePart to find state

            // Strip varint prefix from varint+scriptCode
            // SPLIT 1 -> [..., firstByte, rest]
            try self.emitPushInt(1);
            try self.stack.push(self.allocator, null);
            try self.emitOp(.op_split);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null); // firstByte
            try self.stack.push(self.allocator, null); // rest
            // SWAP -> [..., rest, firstByte]
            try self.emitOp(.op_swap);
            const vt_top = self.stack.pop();
            const vt_next = self.stack.pop();
            try self.stack.push(self.allocator, vt_top);
            try self.stack.push(self.allocator, vt_next);
            // DUP -> [..., rest, firstByte, firstByte]
            try self.emitOp(.op_dup);
            try self.stack.push(self.allocator, self.stack.peekAtDepth(0));
            // Zero-pad before BIN2NUM to prevent sign-bit misinterpretation (0xfd -> -125 without pad)
            // push 0x00
            try self.emitPushData(&.{0x00});
            try self.stack.push(self.allocator, null);
            // CAT -> [..., rest, firstByte, firstByte||0x00]
            try self.emitOp(.op_cat);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null);
            // BIN2NUM -> [..., rest, firstByte, fb_num]
            try self.emitOp(.op_bin2num);
            // push 253
            try self.emitPushInt(253);
            try self.stack.push(self.allocator, null);
            // OP_LESSTHAN -> [..., rest, firstByte, (fb<253)]
            try self.emitOp(.op_lessthan);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null);

            // OP_IF
            try self.emitOp(.op_if);
            _ = self.stack.pop();
            var sm_at_varint_if = try self.stack.clone(self.allocator);

            // THEN: fb < 253 -> 1-byte varint, already consumed by the SPLIT 1
            // DROP firstByte (not needed anymore)
            try self.emitOp(.op_drop);
            _ = self.stack.pop();

            // OP_ELSE
            try self.emitOp(.op_else);
            self.stack.deinit(self.allocator);
            self.stack = sm_at_varint_if;
            sm_at_varint_if = .{};

            // ELSE: fb >= 253 -> 2-byte varint follows, skip 2 more bytes
            // DROP firstByte
            try self.emitOp(.op_drop);
            _ = self.stack.pop();
            // push 2
            try self.emitPushInt(2);
            try self.stack.push(self.allocator, null);
            // SPLIT -> [..., 2bytes, rest2]
            try self.emitOp(.op_split);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null);
            try self.stack.push(self.allocator, null);
            // NIP -> [..., rest2]
            try self.emitOp(.op_nip);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null);

            // OP_ENDIF
            try self.emitOp(.op_endif);

            // Compute skip = SIZE(_codePart) - codeSepIdx
            // PICK _codePart (non-consuming)
            try self.bringToTop("_codePart", false);
            // SIZE -> [..., scriptCode, _codePart_copy, size(_codePart)]
            try self.emitOp(.op_size);
            try self.stack.push(self.allocator, null);
            // NIP -> [..., scriptCode, size(_codePart)]
            try self.emitOp(.op_nip);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null);
            // push_codesep_index -> [..., scriptCode, size(_codePart), codeSepIdx]
            try self.emit(.{ .push_codesep_index = {} });
            try self.stack.push(self.allocator, null);
            // SUB -> [..., scriptCode, skip]
            try self.emitOp(.op_sub);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null);

            // Split scriptCode at skip to get state
            // SPLIT -> [..., codePart, state]
            try self.emitOp(.op_split);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null);
            try self.stack.push(self.allocator, null);
            // NIP -> [..., state]
            try self.emitOp(.op_nip);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null);

            // Parse state fields left-to-right
            try self.parseVariableLengthStateFields(state_props.items, prop_sizes.items);
        }
        self.trackDepth();
    }

    fn lowerBuildChangeOutput(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 2) return LowerError.InvalidBuiltin;
        try self.emitPushData(&stateful_templates.p2pkh_prefix_with_len);
        try self.stack.push(self.allocator, null);
        try self.bringToTopAuto(args[0]);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);

        try self.emitPushData(&stateful_templates.p2pkh_suffix);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);

        try self.bringToTopAuto(args[1]);
        try self.emitPushInt(8);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_num2bin);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_swap);
        const amount = self.stack.pop();
        const script = self.stack.pop();
        try self.stack.push(self.allocator, amount);
        try self.stack.push(self.allocator, script);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerGetStateScript(self: *LowerCtx, bind_name: []const u8) !void {
        var state_prop_count: usize = 0;
        for (self.program.properties) |prop| {
            if (!prop.readonly) state_prop_count += 1;
        }

        if (state_prop_count == 0) {
            try self.emitPushData("");
            try self.stack.push(self.allocator, bind_name);
            self.trackDepth();
            return;
        }

        var first = true;
        for (self.program.properties) |prop| {
            if (prop.readonly) continue;

            if (self.stack.findDepth(prop.name) != null) {
                try self.bringToTop(prop.name, true);
            } else if (prop.initial_value) |iv| {
                switch (iv) {
                    .boolean => |b| try self.emitPushBool(b),
                    .integer => |n| try self.emitPushInt(@intCast(n)),
                    .string => |s| try self.emitPushData(s),
                }
                try self.stack.push(self.allocator, null);
            } else {
                try self.emitPushInt(0);
                try self.stack.push(self.allocator, null);
            }

            switch (prop.type_info) {
                .bigint => {
                    try self.emitPushInt(8);
                    try self.stack.push(self.allocator, null);
                    try self.emitOp(.op_num2bin);
                    _ = self.stack.pop();
                    _ = self.stack.pop();
                    try self.stack.push(self.allocator, null);
                },
                .boolean => {
                    try self.emitPushInt(1);
                    try self.stack.push(self.allocator, null);
                    try self.emitOp(.op_num2bin);
                    _ = self.stack.pop();
                    _ = self.stack.pop();
                    try self.stack.push(self.allocator, null);
                },
                .byte_string => {
                    // Prepend push-data length prefix (matching SDK format)
                    try self.emitPushDataEncode();
                },
                else => {},
            }

            if (!first) {
                try self.emitOp(.op_cat);
                _ = self.stack.pop();
                _ = self.stack.pop();
                try self.stack.push(self.allocator, null);
            }
            first = false;
        }

        try self.stack.renameAtDepth(self.allocator, 0, bind_name);
        self.trackDepth();
    }

    fn statePropSize(prop: types.ANFProperty) LowerError!i64 {
        return switch (prop.type_info) {
            .bigint => 8,
            .boolean => 1,
            .pub_key => 33,
            .addr, .ripemd160 => 20,
            .sha256 => 32,
            .point => 64,
            .byte_string => -1,
            else => LowerError.UnsupportedOperation,
        };
    }

    /// Emit opcodes to encode a ByteString value on top of the stack with a
    /// Bitcoin Script push-data length prefix.
    ///
    /// Expects stack: [..., bs_value]
    /// Leaves stack:  [..., pushdata_encoded_value]
    fn emitPushDataEncode(self: *LowerCtx) !void {
        // OP_SIZE -> [..., bs_value, size]
        try self.emitOp(.op_size);
        try self.stack.push(self.allocator, null);
        // OP_DUP -> [..., bs_value, size, size]
        try self.emitOp(.op_dup);
        try self.stack.push(self.allocator, null);
        // push 76 -> [..., bs_value, size, size, 76]
        try self.emitPushInt(76);
        try self.stack.push(self.allocator, null);
        // OP_LESSTHAN -> [..., bs_value, size, (size<76)]
        try self.emitOp(.op_lessthan);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);

        // OP_IF
        try self.emitOp(.op_if);
        _ = self.stack.pop();
        // Save stack state: [..., bs_value, size]
        var sm_after_outer_if = try self.stack.clone(self.allocator);

        // THEN: len <= 75
        // NUM2BIN(size, 2) -> [..., bs_value, size_2bytes]
        try self.emitPushInt(2);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_num2bin);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        // SPLIT 1 -> [..., bs_value, len_byte, padding]
        try self.emitPushInt(1);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.stack.push(self.allocator, null);
        // DROP padding -> [..., bs_value, len_byte]
        try self.emitOp(.op_drop);
        _ = self.stack.pop();
        // SWAP -> [..., len_byte, bs_value]
        try self.emitOp(.op_swap);
        _ = self.stack.pop();
        _ = self.stack.pop();
        // CAT -> [..., len_byte || bs_value]
        try self.emitOp(.op_cat);
        try self.stack.push(self.allocator, null);
        // Save end target state
        var sm_end_target = try self.stack.clone(self.allocator);

        // OP_ELSE
        try self.emitOp(.op_else);
        self.stack.deinit(self.allocator);
        self.stack = sm_after_outer_if;
        sm_after_outer_if = .{};

        // DUP size -> [..., bs_value, size, size]
        try self.emitOp(.op_dup);
        try self.stack.push(self.allocator, null);
        // push 256 -> [..., bs_value, size, size, 256]
        try self.emitPushInt(256);
        try self.stack.push(self.allocator, null);
        // OP_LESSTHAN -> [..., bs_value, size, (size<256)]
        try self.emitOp(.op_lessthan);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);

        // OP_IF
        try self.emitOp(.op_if);
        _ = self.stack.pop();
        var sm_after_inner_if = try self.stack.clone(self.allocator);

        // THEN: 76-255 -> 0x4c + 1-byte length
        try self.emitPushInt(2);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_num2bin);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.emitPushInt(1);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_drop);
        _ = self.stack.pop();
        // push 0x4c
        try self.emitPushData(&.{0x4c});
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_swap);
        const t1_top = self.stack.pop();
        const t1_next = self.stack.pop();
        try self.stack.push(self.allocator, t1_top);
        try self.stack.push(self.allocator, t1_next);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.emitOp(.op_cat);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_swap);
        const t2_top = self.stack.pop();
        const t2_next = self.stack.pop();
        try self.stack.push(self.allocator, t2_top);
        try self.stack.push(self.allocator, t2_next);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.emitOp(.op_cat);
        try self.stack.push(self.allocator, null);

        // OP_ELSE
        try self.emitOp(.op_else);
        self.stack.deinit(self.allocator);
        self.stack = sm_after_inner_if;
        sm_after_inner_if = .{};

        // ELSE: >= 256 -> 0x4d + 2-byte LE length
        try self.emitPushInt(4);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_num2bin);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.emitPushInt(2);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_drop);
        _ = self.stack.pop();
        // push 0x4d
        try self.emitPushData(&.{0x4d});
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_swap);
        const t3_top = self.stack.pop();
        const t3_next = self.stack.pop();
        try self.stack.push(self.allocator, t3_top);
        try self.stack.push(self.allocator, t3_next);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.emitOp(.op_cat);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_swap);
        const t4_top = self.stack.pop();
        const t4_next = self.stack.pop();
        try self.stack.push(self.allocator, t4_top);
        try self.stack.push(self.allocator, t4_next);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.emitOp(.op_cat);
        try self.stack.push(self.allocator, null);

        // OP_ENDIF (inner)
        try self.emitOp(.op_endif);
        // OP_ENDIF (outer)
        try self.emitOp(.op_endif);
        self.stack.deinit(self.allocator);
        self.stack = sm_end_target;
        sm_end_target = .{};
    }

    /// Emit opcodes to decode a push-data encoded ByteString from the state
    /// bytes on top of the stack.
    ///
    /// Expects stack: [..., state_bytes]
    /// Leaves stack:  [..., data, remaining_state]
    fn emitPushDataDecode(self: *LowerCtx) !void {
        // Split first byte
        try self.emitPushInt(1);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null); // first_byte
        try self.stack.push(self.allocator, null); // rest
        // SWAP -> [..., rest, first_byte]
        try self.emitOp(.op_swap);
        const sw1_top = self.stack.pop();
        const sw1_next = self.stack.pop();
        try self.stack.push(self.allocator, sw1_top);
        try self.stack.push(self.allocator, sw1_next);
        // BIN2NUM -> [..., rest, fb_num]
        try self.emitOp(.op_bin2num);
        // DUP -> [..., rest, fb_num, fb_num]
        try self.emitOp(.op_dup);
        try self.stack.push(self.allocator, null);
        // push 76 -> [..., rest, fb_num, fb_num, 76]
        try self.emitPushInt(76);
        try self.stack.push(self.allocator, null);
        // OP_LESSTHAN -> [..., rest, fb_num, (fb<76)]
        try self.emitOp(.op_lessthan);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);

        // OP_IF
        try self.emitOp(.op_if);
        _ = self.stack.pop();
        // Save stack at branch: [..., rest, fb_num]
        var sm_after_outer_if = try self.stack.clone(self.allocator);

        // THEN: fb_num < 76 -> fb_num IS the length
        // SPLIT -> [..., data, remaining]
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null); // data
        try self.stack.push(self.allocator, null); // remaining
        // Save end target
        var sm_end_target = try self.stack.clone(self.allocator);

        // OP_ELSE
        try self.emitOp(.op_else);
        self.stack.deinit(self.allocator);
        self.stack = sm_after_outer_if;
        sm_after_outer_if = .{};
        // Stack: [..., rest, fb_num]

        // DUP -> [..., rest, fb_num, fb_num]
        try self.emitOp(.op_dup);
        try self.stack.push(self.allocator, null);
        // push 77 -> [..., rest, fb_num, fb_num, 77]
        try self.emitPushInt(77);
        try self.stack.push(self.allocator, null);
        // OP_NUMEQUAL -> [..., rest, fb_num, (fb==77)]
        try self.emitOp(.op_numequal);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);

        // OP_IF
        try self.emitOp(.op_if);
        _ = self.stack.pop();
        var sm_after_inner_if = try self.stack.clone(self.allocator);

        // THEN: fb_num == 77 (0x4d) -> 2-byte LE length
        // DROP fb_num -> [..., rest]
        try self.emitOp(.op_drop);
        _ = self.stack.pop();
        // push 2
        try self.emitPushInt(2);
        try self.stack.push(self.allocator, null);
        // SPLIT -> [..., len_2bytes, rest2]
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.stack.push(self.allocator, null);
        // SWAP -> [..., rest2, len_2bytes]
        try self.emitOp(.op_swap);
        const sw2_top = self.stack.pop();
        const sw2_next = self.stack.pop();
        try self.stack.push(self.allocator, sw2_top);
        try self.stack.push(self.allocator, sw2_next);
        // BIN2NUM -> [..., rest2, len]
        try self.emitOp(.op_bin2num);
        // SPLIT -> [..., data, remaining]
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.stack.push(self.allocator, null);

        // OP_ELSE
        try self.emitOp(.op_else);
        self.stack.deinit(self.allocator);
        self.stack = sm_after_inner_if;
        sm_after_inner_if = .{};

        // ELSE: fb_num == 76 (0x4c) -> 1-byte length
        // DROP fb_num -> [..., rest]
        try self.emitOp(.op_drop);
        _ = self.stack.pop();
        // push 1
        try self.emitPushInt(1);
        try self.stack.push(self.allocator, null);
        // SPLIT -> [..., len_1byte, rest2]
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.stack.push(self.allocator, null);
        // SWAP -> [..., rest2, len_1byte]
        try self.emitOp(.op_swap);
        const sw3_top = self.stack.pop();
        const sw3_next = self.stack.pop();
        try self.stack.push(self.allocator, sw3_top);
        try self.stack.push(self.allocator, sw3_next);
        // BIN2NUM -> [..., rest2, len]
        try self.emitOp(.op_bin2num);
        // SPLIT -> [..., data, remaining]
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.stack.push(self.allocator, null);

        // OP_ENDIF (inner)
        try self.emitOp(.op_endif);
        // OP_ENDIF (outer)
        try self.emitOp(.op_endif);
        self.stack.deinit(self.allocator);
        self.stack = sm_end_target;
        sm_end_target = .{};
    }

    /// Split fixed-size state bytes into individual properties.
    fn splitFixedStateFields(self: *LowerCtx, state_props: []const types.ANFProperty, prop_sizes: []const i64) !void {
        if (state_props.len == 1) {
            const prop = state_props[0];
            switch (prop.type_info) {
                .bigint, .boolean => try self.emitOp(.op_bin2num),
                else => {},
            }
            try self.stack.renameAtDepth(self.allocator, 0, prop.name);
        } else {
            for (state_props, 0..) |prop, i| {
                const sz = prop_sizes[i];
                if (i < state_props.len - 1) {
                    try self.emitPushInt(sz);
                    try self.stack.push(self.allocator, null);
                    try self.emitOp(.op_split);
                    _ = self.stack.pop();
                    _ = self.stack.pop();
                    try self.stack.push(self.allocator, null);
                    try self.stack.push(self.allocator, null);

                    try self.emitOp(.op_swap);
                    const rest = self.stack.pop();
                    const prop_bytes = self.stack.pop();
                    try self.stack.push(self.allocator, rest);
                    try self.stack.push(self.allocator, prop_bytes);

                    switch (prop.type_info) {
                        .bigint, .boolean => try self.emitOp(.op_bin2num),
                        else => {},
                    }

                    try self.emitOp(.op_swap);
                    const prop_value = self.stack.pop();
                    const remainder = self.stack.pop();
                    try self.stack.push(self.allocator, prop_value);
                    try self.stack.push(self.allocator, remainder);
                    try self.stack.renameAtDepth(self.allocator, 1, prop.name);
                } else {
                    switch (prop.type_info) {
                        .bigint, .boolean => try self.emitOp(.op_bin2num),
                        else => {},
                    }
                    try self.stack.renameAtDepth(self.allocator, 0, prop.name);
                }
            }
        }
    }

    /// Parse state fields left-to-right, handling variable-length ByteString fields.
    fn parseVariableLengthStateFields(self: *LowerCtx, state_props: []const types.ANFProperty, prop_sizes: []const i64) !void {
        if (state_props.len == 1) {
            const prop = state_props[0];
            if (prop.type_info == .byte_string) {
                // Single ByteString field: decode push-data prefix, drop trailing empty
                try self.emitPushDataDecode(); // [..., data, remaining]
                try self.emitOp(.op_drop);
                _ = self.stack.pop();
            } else {
                switch (prop.type_info) {
                    .bigint, .boolean => try self.emitOp(.op_bin2num),
                    else => {},
                }
            }
            try self.stack.renameAtDepth(self.allocator, 0, prop.name);
        } else {
            for (state_props, 0..) |prop, i| {
                if (i < state_props.len - 1) {
                    if (prop.type_info == .byte_string) {
                        // ByteString: decode push-data prefix, extract data
                        try self.emitPushDataDecode(); // [..., data, rest]
                        _ = self.stack.pop();
                        _ = self.stack.pop();
                        try self.stack.push(self.allocator, prop.name);
                        try self.stack.push(self.allocator, null); // rest on top
                    } else {
                        try self.emitPushInt(prop_sizes[i]);
                        try self.stack.push(self.allocator, null);
                        try self.emitOp(.op_split);
                        _ = self.stack.pop();
                        _ = self.stack.pop();
                        try self.stack.push(self.allocator, null);
                        try self.stack.push(self.allocator, null);
                        try self.emitOp(.op_swap);
                        const sw_top = self.stack.pop();
                        const sw_next = self.stack.pop();
                        try self.stack.push(self.allocator, sw_top);
                        try self.stack.push(self.allocator, sw_next);
                        switch (prop.type_info) {
                            .bigint, .boolean => try self.emitOp(.op_bin2num),
                            else => {},
                        }
                        try self.emitOp(.op_swap);
                        const prop_val = self.stack.pop();
                        const rest_val = self.stack.pop();
                        try self.stack.push(self.allocator, prop_val);
                        try self.stack.push(self.allocator, rest_val);
                        try self.stack.renameAtDepth(self.allocator, 1, prop.name);
                    }
                } else {
                    if (prop.type_info == .byte_string) {
                        // Last ByteString: decode push-data prefix, drop trailing empty
                        try self.emitPushDataDecode(); // [..., data, remaining]
                        try self.emitOp(.op_drop);
                        _ = self.stack.pop();
                    } else {
                        switch (prop.type_info) {
                            .bigint, .boolean => try self.emitOp(.op_bin2num),
                            else => {},
                        }
                    }
                    try self.stack.renameAtDepth(self.allocator, 0, prop.name);
                }
            }
        }
    }

    fn lowerComputeStateOutput(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 3) return LowerError.InvalidBuiltin;

        try self.bringToTopAuto(args[0]);
        try self.emitOp(.op_drop);
        _ = self.stack.pop();

        try self.bringToTopAuto(args[2]);
        try self.emitPushInt(8);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_num2bin);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_toaltstack);
        _ = self.stack.pop();

        try self.bringToTopAuto(args[1]);
        try self.bringToTop("_codePart", false);

        try self.emitPushData(&stateful_templates.op_return_byte);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);

        try self.emitOp(.op_swap);
        const code_part_with_op_return = self.stack.pop();
        const state_bytes = self.stack.pop();
        try self.stack.push(self.allocator, code_part_with_op_return);
        try self.stack.push(self.allocator, state_bytes);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);

        try self.emitOp(.op_size);
        try self.stack.push(self.allocator, null);
        try self.emitVarintEncoding();

        try self.emitOp(.op_swap);
        const varint = self.stack.pop();
        const script = self.stack.pop();
        try self.stack.push(self.allocator, varint);
        try self.stack.push(self.allocator, script);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);

        try self.emitOp(.op_fromaltstack);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_swap);
        const script_with_len = self.stack.pop();
        const new_amount = self.stack.pop();
        try self.stack.push(self.allocator, new_amount);
        try self.stack.push(self.allocator, script_with_len);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerComputeStateOutputHash(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 2) return LowerError.InvalidBuiltin;

        try self.bringToTopAuto(args[1]);
        try self.bringToTopAuto(args[0]);

        try self.emitOp(.op_size);
        try self.stack.push(self.allocator, null);
        try self.emitPushInt(52);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_sub);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_nip);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.emitPushInt(8);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_drop);
        _ = self.stack.pop();

        try self.emitOp(.op_toaltstack);
        _ = self.stack.pop();

        try self.bringToTop("_codePart", false);
        try self.emitPushData(&stateful_templates.op_return_byte);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);

        try self.emitSwapTracked();
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);

        try self.emitOp(.op_size);
        try self.stack.push(self.allocator, null);
        try self.emitVarintEncoding();

        try self.emitSwapTracked();
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);

        try self.emitOp(.op_fromaltstack);
        try self.stack.push(self.allocator, null);
        try self.emitSwapTracked();
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);

        try self.emitOp(.op_hash256);
        try self.stack.renameAtDepth(self.allocator, 0, bind_name);
        self.trackDepth();
    }

    fn lowerExtractor(self: *LowerCtx, bind_name: []const u8, id: BuiltinId, args: []const []const u8) !void {
        if (args.len < 1) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        _ = self.stack.pop();

        switch (id) {
            .extractHashPrevouts => {
                try self.emitPushInt(4);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_split);
                _ = self.stack.pop();
                try self.stack.push(self.allocator, null);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_nip);
                _ = self.stack.pop();
                _ = self.stack.pop();
                try self.stack.push(self.allocator, null);
                try self.emitPushInt(32);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_split);
                _ = self.stack.pop();
                _ = self.stack.pop();
                try self.stack.push(self.allocator, null);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_drop);
                _ = self.stack.pop();
            },
            .extractOutpoint => {
                try self.emitPushInt(68);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_split);
                _ = self.stack.pop();
                try self.stack.push(self.allocator, null);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_nip);
                _ = self.stack.pop();
                _ = self.stack.pop();
                try self.stack.push(self.allocator, null);
                try self.emitPushInt(36);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_split);
                _ = self.stack.pop();
                _ = self.stack.pop();
                try self.stack.push(self.allocator, null);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_drop);
                _ = self.stack.pop();
            },
            .extractLocktime => {
                try self.emitOp(.op_size);
                try self.stack.push(self.allocator, null);
                try self.stack.push(self.allocator, null);
                try self.emitPushInt(8);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_sub);
                _ = self.stack.pop();
                _ = self.stack.pop();
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_split);
                _ = self.stack.pop();
                _ = self.stack.pop();
                try self.stack.push(self.allocator, null);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_nip);
                _ = self.stack.pop();
                _ = self.stack.pop();
                try self.stack.push(self.allocator, null);
                try self.emitPushInt(4);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_split);
                _ = self.stack.pop();
                _ = self.stack.pop();
                try self.stack.push(self.allocator, null);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_drop);
                _ = self.stack.pop();
                try self.emitOp(.op_bin2num);
            },
            .extractOutputHash => {
                try self.emitOp(.op_size);
                try self.stack.push(self.allocator, null);
                try self.stack.push(self.allocator, null);
                try self.emitPushInt(40);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_sub);
                _ = self.stack.pop();
                _ = self.stack.pop();
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_split);
                _ = self.stack.pop();
                _ = self.stack.pop();
                try self.stack.push(self.allocator, null);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_nip);
                _ = self.stack.pop();
                _ = self.stack.pop();
                try self.stack.push(self.allocator, null);
                try self.emitPushInt(32);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_split);
                _ = self.stack.pop();
                _ = self.stack.pop();
                try self.stack.push(self.allocator, null);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_drop);
                _ = self.stack.pop();
            },
            else => return LowerError.InvalidBuiltin,
        }

        try self.stack.renameAtDepth(self.allocator, 0, bind_name);
        self.trackDepth();
    }

    fn emitVarintEncoding(self: *LowerCtx) !void {
        try self.emitOp(.op_dup);
        try self.stack.push(self.allocator, null);
        try self.emitPushInt(253);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_lessthan);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);

        try self.emitOp(.op_if);
        _ = self.stack.pop();

        try self.emitPushInt(2);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_num2bin);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.emitPushInt(1);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_drop);
        _ = self.stack.pop();

        try self.emitOp(.op_else);

        try self.emitPushInt(4);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_num2bin);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.emitPushInt(2);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_drop);
        _ = self.stack.pop();
        try self.emitPushData(&.{0xfd});
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_swap);
        const top = self.stack.pop();
        const next = self.stack.pop();
        try self.stack.push(self.allocator, top);
        try self.stack.push(self.allocator, next);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.emitOp(.op_cat);
        try self.stack.push(self.allocator, null);

        try self.emitOp(.op_endif);
    }

    // ========================================================================
    // assert_op
    // ========================================================================

    fn lowerAssertOp(self: *LowerCtx, bind_name: []const u8, a: types.ANFLegacyAssert, terminal: bool) !void {
        try self.bringToTopAuto(a.condition);
        if (!terminal) {
            try self.emitOp(.op_verify);
            _ = self.stack.pop();
        }
        _ = bind_name;
    }

    // ========================================================================
    // if_expr
    // ========================================================================

    fn lowerIfExpr(self: *LowerCtx, bind_name: []const u8, ie: *const types.ANFIfExpr) !void {
        try self.bringToTopAuto(ie.condition);
        _ = self.stack.pop();
        var base_stack = try self.stack.clone(self.allocator);
        defer base_stack.deinit(self.allocator);
        var pre_if_names = try self.stack.namedSlots(self.allocator);
        defer pre_if_names.deinit(self.allocator);

        var protected_refs: std.StringHashMapUnmanaged(void) = .empty;
        defer protected_refs.deinit(self.allocator);
        var last_use_it = self.last_uses.iterator();
        while (last_use_it.next()) |entry| {
            if (entry.value_ptr.* > self.current_idx and self.stack.findDepth(entry.key_ptr.*) != null) {
                try protected_refs.put(self.allocator, entry.key_ptr.*, {});
            }
        }

        var then_ctx = LowerCtx.init(self.allocator, self.program);
        defer then_ctx.deinit();
        then_ctx.stack = try base_stack.clone(self.allocator);
        then_ctx.updated_props = try cloneVoidMap(self.allocator, self.updated_props);
        then_ctx.force_copy_bindings = try cloneVoidMap(self.allocator, self.force_copy_bindings);
        then_ctx.in_branch = true;
        then_ctx.copy_ref_aliases = self.copy_ref_aliases;
        then_ctx.max_depth = self.max_depth;
        for (ie.then_bindings) |binding| {
            try then_ctx.local_bindings.put(self.allocator, binding.name, {});
        }
        try then_ctx.computeLastUses(ie.then_bindings);
        var protected_then = protected_refs.iterator();
        while (protected_then.next()) |entry| {
            try then_ctx.last_uses.put(self.allocator, entry.key_ptr.*, ie.then_bindings.len);
        }
        for (ie.then_bindings, 0..) |binding, idx| {
            then_ctx.current_idx = idx;
            try then_ctx.lowerBinding(binding);
        }

        var else_ctx = LowerCtx.init(self.allocator, self.program);
        defer else_ctx.deinit();
        else_ctx.stack = try base_stack.clone(self.allocator);
        else_ctx.updated_props = try cloneVoidMap(self.allocator, self.updated_props);
        else_ctx.force_copy_bindings = try cloneVoidMap(self.allocator, self.force_copy_bindings);
        else_ctx.in_branch = true;
        else_ctx.copy_ref_aliases = self.copy_ref_aliases;
        else_ctx.max_depth = self.max_depth;
        const else_bindings = ie.else_bindings orelse &.{};
        for (else_bindings) |binding| {
            try else_ctx.local_bindings.put(self.allocator, binding.name, {});
        }
        try else_ctx.computeLastUses(else_bindings);
        var protected_else = protected_refs.iterator();
        while (protected_else.next()) |entry| {
            try else_ctx.last_uses.put(self.allocator, entry.key_ptr.*, else_bindings.len);
        }
        for (else_bindings, 0..) |binding, idx| {
            else_ctx.current_idx = idx;
            try else_ctx.lowerBinding(binding);
        }

        var post_then_names = try then_ctx.stack.namedSlots(self.allocator);
        defer post_then_names.deinit(self.allocator);
        var post_else_names = try else_ctx.stack.namedSlots(self.allocator);
        defer post_else_names.deinit(self.allocator);

        var consumed_depths = std.ArrayListUnmanaged(usize).empty;
        defer consumed_depths.deinit(self.allocator);
        var pre_it = pre_if_names.iterator();
        while (pre_it.next()) |entry| {
            if (post_then_names.get(entry.key_ptr.*) == null) {
                if (else_ctx.stack.findDepth(entry.key_ptr.*)) |depth| {
                    try consumed_depths.append(self.allocator, depth);
                }
            }
        }

        var else_consumed_depths = std.ArrayListUnmanaged(usize).empty;
        defer else_consumed_depths.deinit(self.allocator);
        pre_it = pre_if_names.iterator();
        while (pre_it.next()) |entry| {
            if (post_else_names.get(entry.key_ptr.*) == null) {
                if (then_ctx.stack.findDepth(entry.key_ptr.*)) |depth| {
                    try else_consumed_depths.append(self.allocator, depth);
                }
            }
        }

        std.mem.sort(usize, consumed_depths.items, {}, comptime std.sort.desc(usize));
        for (consumed_depths.items) |depth| {
            try removeBranchValueAtDepth(&else_ctx, depth);
        }
        std.mem.sort(usize, else_consumed_depths.items, {}, comptime std.sort.desc(usize));
        for (else_consumed_depths.items) |depth| {
            try removeBranchValueAtDepth(&then_ctx, depth);
        }

        if (then_ctx.stack.depth() > else_ctx.stack.depth()) {
            const then_top = then_ctx.stack.peekAtDepth(0);
            if (else_bindings.len == 0 and then_top != null) {
                if (else_ctx.stack.findDepth(then_top.?)) |var_depth| {
                    try duplicateBranchValueAtDepth(&else_ctx, var_depth, then_top);
                } else {
                    try else_ctx.emitPushData("");
                    try else_ctx.stack.push(self.allocator, null);
                    else_ctx.trackDepth();
                }
            } else {
                try else_ctx.emitPushData("");
                try else_ctx.stack.push(self.allocator, null);
                else_ctx.trackDepth();
            }
        } else if (else_ctx.stack.depth() > then_ctx.stack.depth()) {
            try then_ctx.emitPushData("");
            try then_ctx.stack.push(self.allocator, null);
            then_ctx.trackDepth();
        }

        if (then_ctx.stack.depth() != else_ctx.stack.depth()) {
            return LowerError.BranchStackMismatch;
        }

        try self.emitOp(.op_if);
        try self.appendInstructions(then_ctx.instructions.items);
        if (else_ctx.instructions.items.len > 0) {
            try self.emitOp(.op_else);
            try self.appendInstructions(else_ctx.instructions.items);
        }
        try self.emitOp(.op_endif);

        var post_branch_names = try then_ctx.stack.namedSlots(self.allocator);
        defer post_branch_names.deinit(self.allocator);
        pre_it = pre_if_names.iterator();
        while (pre_it.next()) |entry| {
            if (post_branch_names.get(entry.key_ptr.*) == null) {
                if (self.stack.findDepth(entry.key_ptr.*)) |depth| {
                    try self.stack.removeAtDepth(self.allocator, depth);
                }
            }
        }

        if (then_ctx.stack.depth() > self.stack.depth()) {
            const then_top = then_ctx.stack.peekAtDepth(0);
            const else_top = else_ctx.stack.peekAtDepth(0);
            var is_property = false;
            if (then_top) |top_name| {
                for (self.program.properties) |prop| {
                    if (std.mem.eql(u8, prop.name, top_name)) {
                        is_property = true;
                        break;
                    }
                }
            }

            if (then_top != null and is_property and else_top != null and std.mem.eql(u8, then_top.?, else_top.?) and !std.mem.eql(u8, then_top.?, bind_name) and self.stack.findDepth(then_top.?) != null) {
                try self.stack.push(self.allocator, then_top.?);
                var d: usize = 1;
                while (d < self.stack.depth()) : (d += 1) {
                    if (self.stack.peekAtDepth(d)) |name| {
                        if (std.mem.eql(u8, name, then_top.?)) {
                            try removeStalePropertyAtDepth(self, d);
                            break;
                        }
                    }
                }
            } else if (then_top != null and !is_property and else_bindings.len == 0 and !std.mem.eql(u8, then_top.?, bind_name) and self.stack.findDepth(then_top.?) != null) {
                try self.stack.push(self.allocator, then_top.?);
                var d: usize = 1;
                while (d < self.stack.depth()) : (d += 1) {
                    if (self.stack.peekAtDepth(d)) |name| {
                        if (std.mem.eql(u8, name, then_top.?)) {
                            try removeStalePropertyAtDepth(self, d);
                            break;
                        }
                    }
                }
            } else {
                try self.stack.push(self.allocator, bind_name);
            }
        } else if (else_ctx.stack.depth() > self.stack.depth()) {
            try self.stack.push(self.allocator, bind_name);
        }
        self.trackDepth();

        if (then_ctx.max_depth > self.max_depth) self.max_depth = then_ctx.max_depth;
        if (else_ctx.max_depth > self.max_depth) self.max_depth = else_ctx.max_depth;
    }

    // ========================================================================
    // for_loop
    // ========================================================================

    fn lowerForLoop(self: *LowerCtx, bind_name: []const u8, fl: *const types.ANFForLoop) !void {
        var body_binding_names: std.StringHashMapUnmanaged(void) = .empty;
        defer body_binding_names.deinit(self.allocator);
        for (fl.body_bindings) |binding| {
            try body_binding_names.put(self.allocator, binding.name, {});
        }

        var outer_refs: std.StringHashMapUnmanaged(void) = .empty;
        defer outer_refs.deinit(self.allocator);
        for (fl.body_bindings) |binding| {
            switch (binding.value) {
                .load_param => |lp| {
                    if (!std.mem.eql(u8, lp.name, fl.var_name)) {
                        try outer_refs.put(self.allocator, lp.name, {});
                    }
                },
                .load_const => |lc| {
                    switch (lc.value) {
                        .string => |s| {
                            if (std.mem.startsWith(u8, s, "@ref:")) {
                                const ref_name = s[5..];
                                if (!body_binding_names.contains(ref_name)) {
                                    try outer_refs.put(self.allocator, ref_name, {});
                                }
                            }
                        },
                        else => {},
                    }
                },
                else => {},
            }
        }

        const saved_local_bindings = self.local_bindings;
        const saved_force_copy_bindings = self.force_copy_bindings;
        self.local_bindings = try cloneVoidMap(self.allocator, saved_local_bindings);
        self.force_copy_bindings = try cloneVoidMap(self.allocator, saved_force_copy_bindings);
        defer {
            self.local_bindings.deinit(self.allocator);
            self.local_bindings = saved_local_bindings;
            self.force_copy_bindings.deinit(self.allocator);
            self.force_copy_bindings = saved_force_copy_bindings;
        }
        var body_name_it = body_binding_names.iterator();
        while (body_name_it.next()) |entry| {
            try self.local_bindings.put(self.allocator, entry.key_ptr.*, {});
        }

        var i: i64 = fl.init_val;
        while (i < fl.bound) : (i += 1) {
            try self.emitPushInt(i);
            try self.stack.push(self.allocator, fl.var_name);
            self.trackDepth();

            const saved_lu = self.last_uses;
            self.last_uses = .empty;
            try self.computeLastUses(fl.body_bindings);
            if (i < fl.bound - 1) {
                var outer_it = outer_refs.iterator();
                while (outer_it.next()) |entry| {
                    try self.last_uses.put(self.allocator, entry.key_ptr.*, fl.body_bindings.len);
                }
            }
            for (fl.body_bindings, 0..) |binding, idx| {
                self.current_idx = idx;
                try self.lowerBinding(binding);
            }
            self.last_uses.deinit(self.allocator);
            self.last_uses = saved_lu;

            // Remove iteration variable if still on stack
            if (self.stack.findDepth(fl.var_name)) |d| {
                if (d == 0) {
                    try self.emitOp(.op_drop);
                    _ = self.stack.pop();
                }
            }
        }

        _ = bind_name;
    }

    // ========================================================================
    // add_output / add_raw_output
    // ========================================================================

    fn lowerAddOutput(self: *LowerCtx, bind_name: []const u8, ao: types.ANFAddOutput) !void {
        var state_prop_count: usize = 0;
        for (self.program.properties) |prop| {
            if (!prop.readonly) state_prop_count += 1;
        }

        try self.bringToTop("_codePart", false);
        try self.emitPushData(&.{0x6a});
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        self.trackDepth();

        var state_index: usize = 0;
        for (self.program.properties) |prop| {
            if (prop.readonly) continue;
            if (state_index >= ao.state_values.len or state_index >= state_prop_count) break;
            const value_ref = ao.state_values[state_index];
            state_index += 1;

            try self.bringToTopAuto(value_ref);
            switch (prop.type_info) {
                .bigint => {
                    try self.emitPushInt(8);
                    try self.stack.push(self.allocator, null);
                    try self.emitOp(.op_num2bin);
                    _ = self.stack.pop();
                },
                .boolean => {
                    try self.emitPushInt(1);
                    try self.stack.push(self.allocator, null);
                    try self.emitOp(.op_num2bin);
                    _ = self.stack.pop();
                },
                .byte_string => {
                    try self.emitPushDataEncode();
                },
                else => {},
            }

            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.emitOp(.op_cat);
            try self.stack.push(self.allocator, null);
        }

        try self.emitOp(.op_size);
        try self.stack.push(self.allocator, null);
        try self.emitVarintEncoding();
        try self.emitOp(.op_swap);
        const script_len = self.stack.pop();
        const script = self.stack.pop();
        try self.stack.push(self.allocator, script_len);
        try self.stack.push(self.allocator, script);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        self.trackDepth();

        try self.bringToTopAuto(ao.satoshis);
        try self.emitPushInt(8);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_num2bin);
        _ = self.stack.pop();
        try self.emitOp(.op_swap);
        const satoshis = self.stack.pop();
        const script_with_len = self.stack.pop();
        try self.stack.push(self.allocator, satoshis);
        try self.stack.push(self.allocator, script_with_len);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerAddRawOutput(self: *LowerCtx, bind_name: []const u8, aro: types.ANFAddRawOutput) !void {
        try self.bringToTopAuto(aro.script_ref);
        try self.emitOp(.op_size);
        try self.stack.push(self.allocator, null);
        try self.emitVarintEncoding();
        try self.emitOp(.op_swap);
        const script_len = self.stack.pop();
        const script = self.stack.pop();
        try self.stack.push(self.allocator, script_len);
        try self.stack.push(self.allocator, script);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        self.trackDepth();

        try self.bringToTopAuto(aro.satoshis);
        try self.emitPushInt(8);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_num2bin);
        _ = self.stack.pop();
        try self.emitOp(.op_swap);
        const satoshis = self.stack.pop();
        const script_with_len = self.stack.pop();
        try self.stack.push(self.allocator, satoshis);
        try self.stack.push(self.allocator, script_with_len);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }
};

// ============================================================================
// Generator point G (secp256k1, compressed)
// ============================================================================

const generator_point_g = [33]u8{
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb,
    0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
    0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
};

// ============================================================================
// Public API
// ============================================================================

/// Lower an ANF program to Stack IR.
///
/// Each public method is lowered into its own StackMethod. The multi-method
/// dispatch table is added at emit time (in emit.zig), matching the TS
/// reference compiler's pipeline. This keeps the dispatch-table opcodes
/// outside the peephole optimization window so that `OP_DUP, OP_0,
/// OP_NUMEQUAL, OP_IF, OP_DROP` dispatch entries are not folded into
/// `OP_DUP, OP_NOT, OP_IF, OP_DROP` (which is semantically equivalent
/// but byte-divergent from the canonical TS output).
pub fn lower(allocator: Allocator, program: types.ANFProgram) !types.StackProgram {
    var methods = std.ArrayListUnmanaged(types.StackMethod).empty;
    defer methods.deinit(allocator);
    var owned_push_data = std.ArrayListUnmanaged([]u8).empty;
    defer owned_push_data.deinit(allocator);

    for (program.methods) |method| {
        if (!method.is_public) continue;

        var ctx = LowerCtx.init(allocator, program);
        defer ctx.deinit();

        try setupMethodStack(&ctx, program, method);
        ctx.copy_ref_aliases = false;

        // Use body or bindings (whichever is populated)
        const bindings = if (method.body.len > 0) method.body else method.bindings;
        try ctx.lowerBindings(bindings, method.is_public);
        if (method.is_public and methodUsesDeserializeState(bindings)) {
            try ctx.cleanupExcessStack();
        }
        if (!method.is_public or !endsWithAssert(bindings)) {
            try ctx.emitOp(.op_1);
        }

        const instructions = try allocator.dupe(types.StackInstruction, ctx.instructions.items);
        const src_locs = try allocator.dupe(?types.SourceLocation, ctx.instruction_source_locs.items);
        try methods.append(allocator, .{
            .name = method.name,
            .instructions = instructions,
            .max_stack_depth = ctx.max_depth,
            .instruction_source_locs = src_locs,
        });
        try owned_push_data.appendSlice(allocator, ctx.owned_push_data.items);
        ctx.owned_push_data.deinit(allocator);
        ctx.owned_push_data = .empty;
    }

    return .{
        .methods = try allocator.dupe(types.StackMethod, methods.items),
        .contract_name = program.contract_name,
        .properties = program.properties,
        .constructor_params = program.constructor.params,
        .owned_push_data = try allocator.dupe([]u8, owned_push_data.items),
    };
}

fn countPublicMethods(methods: []const types.ANFMethod) usize {
    var count: usize = 0;
    for (methods) |m| {
        if (m.is_public) count += 1;
    }
    return count;
}

fn usesOutputBuiltins(methods: []const types.ANFMethod) bool {
    for (methods) |method| {
        if (methodUsesCodePart(methodBindings(method))) return true;
    }
    return false;
}

fn isStateful(program: types.ANFProgram) bool {
    return program.parent_class == .stateful_smart_contract;
}

fn setupMethodStack(ctx: *LowerCtx, _: types.ANFProgram, method: types.ANFMethod) !void {
    const bindings = methodBindings(method);

    if (methodUsesCodePart(bindings)) {
        try ctx.stack.push(ctx.allocator, "_codePart");
        ctx.trackDepth();
    }

    if (methodUsesCheckPreimage(bindings)) {
        try ctx.stack.push(ctx.allocator, "_opPushTxSig");
        ctx.trackDepth();
    }

    for (method.params) |param| {
        try ctx.stack.push(ctx.allocator, param.name);
    }
    ctx.trackDepth();
}

fn setupPropertyStack(ctx: *LowerCtx, program: types.ANFProgram) !void {
    _ = ctx;
    _ = program;
}

fn methodBindings(method: types.ANFMethod) []const types.ANFBinding {
    return if (method.body.len > 0) method.body else method.bindings;
}

fn endsWithAssert(bindings: []const types.ANFBinding) bool {
    if (bindings.len == 0) return false;
    return switch (bindings[bindings.len - 1].value) {
        .assert, .assert_op => true,
        else => false,
    };
}

fn anyMethodUsesCheckPreimage(methods: []const types.ANFMethod) bool {
    for (methods) |method| {
        if (method.is_public and methodUsesCheckPreimage(methodBindings(method))) return true;
    }
    return false;
}

fn anyMethodUsesCodePart(methods: []const types.ANFMethod) bool {
    for (methods) |method| {
        if (method.is_public and methodUsesCodePart(methodBindings(method))) return true;
    }
    return false;
}

fn methodUsesCheckPreimage(bindings: []const types.ANFBinding) bool {
    for (bindings) |binding| {
        switch (binding.value) {
            .check_preimage => return true,
            .@"if" => |ie| {
                if (methodUsesCheckPreimage(ie.then) or methodUsesCheckPreimage(ie.@"else")) return true;
            },
            .if_expr => |ie| {
                if (methodUsesCheckPreimage(ie.then_bindings)) return true;
                if (ie.else_bindings) |else_bindings| {
                    if (methodUsesCheckPreimage(else_bindings)) return true;
                }
            },
            .loop => |loop| {
                if (methodUsesCheckPreimage(loop.body)) return true;
            },
            .for_loop => |loop| {
                if (methodUsesCheckPreimage(loop.body_bindings)) return true;
            },
            else => {},
        }
    }
    return false;
}

fn methodUsesCodePart(bindings: []const types.ANFBinding) bool {
    for (bindings) |binding| {
        switch (binding.value) {
            .add_output, .add_raw_output => return true,
            .call => |call| {
                if (std.mem.eql(u8, call.func, "computeStateOutput") or
                    std.mem.eql(u8, call.func, "computeStateOutputHash") or
                    std.mem.eql(u8, call.func, "buildChangeOutput") or
                    std.mem.eql(u8, call.func, "buildStateOutput"))
                {
                    return true;
                }
            },
            .builtin_call => |call| {
                if (std.mem.eql(u8, call.name, "computeStateOutput") or
                    std.mem.eql(u8, call.name, "computeStateOutputHash") or
                    std.mem.eql(u8, call.name, "buildChangeOutput") or
                    std.mem.eql(u8, call.name, "buildStateOutput"))
                {
                    return true;
                }
            },
            .@"if" => |ie| {
                if (methodUsesCodePart(ie.then) or methodUsesCodePart(ie.@"else")) return true;
            },
            .if_expr => |ie| {
                if (methodUsesCodePart(ie.then_bindings)) return true;
                if (ie.else_bindings) |else_bindings| {
                    if (methodUsesCodePart(else_bindings)) return true;
                }
            },
            .loop => |loop| {
                if (methodUsesCodePart(loop.body)) return true;
            },
            .for_loop => |loop| {
                if (methodUsesCodePart(loop.body_bindings)) return true;
            },
            else => {},
        }
    }
    return false;
}

fn findPrivateMethod(methods: []const types.ANFMethod, name: []const u8) ?types.ANFMethod {
    for (methods) |method| {
        if (method.is_public or std.mem.eql(u8, method.name, "constructor")) continue;
        if (std.mem.eql(u8, method.name, name)) return method;
    }
    return null;
}

fn methodUsesDeserializeState(bindings: []const types.ANFBinding) bool {
    for (bindings) |binding| {
        switch (binding.value) {
            .deserialize_state => return true,
            .@"if" => |ie| {
                if (methodUsesDeserializeState(ie.then)) return true;
                if (methodUsesDeserializeState(ie.@"else")) return true;
            },
            .if_expr => |ie| {
                if (methodUsesDeserializeState(ie.then_bindings)) return true;
                if (ie.else_bindings) |else_bindings| {
                    if (methodUsesDeserializeState(else_bindings)) return true;
                }
            },
            .loop => |loop| {
                if (methodUsesDeserializeState(loop.body)) return true;
            },
            .for_loop => |loop| {
                if (methodUsesDeserializeState(loop.body_bindings)) return true;
            },
            else => {},
        }
    }
    return false;
}

fn emitDispatchTable(ctx: *LowerCtx, program: types.ANFProgram) !void {
    var public_indices = std.ArrayListUnmanaged(usize).empty;
    defer public_indices.deinit(ctx.allocator);

    for (program.methods, 0..) |method, idx| {
        if (method.is_public) {
            try public_indices.append(ctx.allocator, idx);
        }
    }

    if (public_indices.items.len == 0) return;

    const last_pub = public_indices.items.len - 1;

    for (public_indices.items, 0..) |method_idx, pub_idx| {
        const method = program.methods[method_idx];
        const bindings = if (method.body.len > 0) method.body else method.bindings;

        const ensureMethodPrelude = struct {
            fn apply(inner_ctx: *LowerCtx, inner_bindings: []const types.ANFBinding, inner_method: types.ANFMethod) !void {
                if (methodUsesCodePart(inner_bindings) and inner_ctx.stack.findDepth("_codePart") == null) {
                    try inner_ctx.stack.push(inner_ctx.allocator, "_codePart");
                    inner_ctx.trackDepth();
                }
                if (methodUsesCheckPreimage(inner_bindings) and inner_ctx.stack.findDepth("_opPushTxSig") == null) {
                    try inner_ctx.stack.push(inner_ctx.allocator, "_opPushTxSig");
                    inner_ctx.trackDepth();
                }
                for (inner_method.params) |param| {
                    try inner_ctx.stack.push(inner_ctx.allocator, param.name);
                }
                inner_ctx.trackDepth();
            }
        };

        if (pub_idx < last_pub) {
            try ctx.emitOp(.op_dup);
            try ctx.emitPushInt(@intCast(pub_idx));
            try ctx.emitOp(.op_numequal);
            try ctx.emitOp(.op_if);
            try ctx.emitOp(.op_drop);

            var branch_stack = try ctx.stack.clone(ctx.allocator);
            const saved_stack = ctx.stack;
            const saved_force_copy_bindings = ctx.force_copy_bindings;
            ctx.stack = branch_stack;
            ctx.force_copy_bindings = .empty;
            try ensureMethodPrelude.apply(ctx, bindings, method);

            try ctx.lowerBindings(bindings, method.is_public);
            if (method.is_public and methodUsesDeserializeState(bindings)) {
                try ctx.cleanupExcessStack();
            }
            if (!endsWithAssert(bindings)) {
                try ctx.emitOp(.op_1);
            }

            branch_stack = ctx.stack;
            branch_stack.deinit(ctx.allocator);
            ctx.stack = saved_stack;
            ctx.force_copy_bindings.deinit(ctx.allocator);
            ctx.force_copy_bindings = saved_force_copy_bindings;

            try ctx.emitOp(.op_else);
        } else {
            try ctx.emitPushInt(@intCast(pub_idx));
            try ctx.emitOp(.op_numequalverify);
            try ensureMethodPrelude.apply(ctx, bindings, method);

            try ctx.lowerBindings(bindings, method.is_public);
            if (method.is_public and methodUsesDeserializeState(bindings)) {
                try ctx.cleanupExcessStack();
            }
            if (!endsWithAssert(bindings)) {
                try ctx.emitOp(.op_1);
            }
        }
    }

    var endif_count: usize = 0;
    while (endif_count < last_pub) : (endif_count += 1) {
        try ctx.emitOp(.op_endif);
    }
}

// ============================================================================
// Tests
// ============================================================================

test "stack map basics" {
    const allocator = std.testing.allocator;
    var map = StackMap{};
    defer map.deinit(allocator);

    try map.push(allocator, "a");
    try map.push(allocator, "b");
    try map.push(allocator, "c");

    try std.testing.expectEqual(@as(?usize, 0), map.findDepth("c"));
    try std.testing.expectEqual(@as(?usize, 1), map.findDepth("b"));
    try std.testing.expectEqual(@as(?usize, 2), map.findDepth("a"));
    try std.testing.expectEqual(@as(?usize, null), map.findDepth("d"));
    try std.testing.expectEqual(@as(usize, 3), map.depth());
}

test "stack map push/pop" {
    const allocator = std.testing.allocator;
    var map = StackMap{};
    defer map.deinit(allocator);

    try map.push(allocator, "x");
    try map.push(allocator, "y");

    const popped = map.pop();
    try std.testing.expectEqualStrings("y", popped.?);
    try std.testing.expectEqual(@as(usize, 1), map.depth());
    try std.testing.expectEqual(@as(?usize, 0), map.findDepth("x"));
}

test "stack map clone" {
    const allocator = std.testing.allocator;
    var map = StackMap{};
    defer map.deinit(allocator);

    try map.push(allocator, "a");
    try map.push(allocator, "b");

    var cloned = try map.clone(allocator);
    defer cloned.deinit(allocator);

    try std.testing.expectEqual(@as(?usize, 0), cloned.findDepth("b"));
    try std.testing.expectEqual(@as(?usize, 1), cloned.findDepth("a"));

    _ = cloned.pop();
    try std.testing.expectEqual(@as(usize, 2), map.depth());
    try std.testing.expectEqual(@as(usize, 1), cloned.depth());
}

test "stack map removeAtDepth" {
    const allocator = std.testing.allocator;
    var map = StackMap{};
    defer map.deinit(allocator);

    try map.push(allocator, "a");
    try map.push(allocator, "b");
    try map.push(allocator, "c");

    try map.removeAtDepth(allocator, 1);
    try std.testing.expectEqual(@as(usize, 2), map.depth());
    try std.testing.expectEqual(@as(?usize, 0), map.findDepth("c"));
    try std.testing.expectEqual(@as(?usize, 1), map.findDepth("a"));
    try std.testing.expectEqual(@as(?usize, null), map.findDepth("b"));
}

test "stack map renameAtDepth" {
    const allocator = std.testing.allocator;
    var map = StackMap{};
    defer map.deinit(allocator);

    try map.push(allocator, "old");
    try map.renameAtDepth(allocator, 0, "new");
    try std.testing.expectEqual(@as(?usize, null), map.findDepth("old"));
    try std.testing.expectEqual(@as(?usize, 0), map.findDepth("new"));
}

test "stack map namedSlots" {
    const allocator = std.testing.allocator;
    var map = StackMap{};
    defer map.deinit(allocator);

    try map.push(allocator, "a");
    try map.push(allocator, null);
    try map.push(allocator, "b");

    var named = try map.namedSlots(allocator);
    defer named.deinit(allocator);

    try std.testing.expect(named.get("a") != null);
    try std.testing.expect(named.get("b") != null);
    try std.testing.expectEqual(@as(u32, 2), named.count());
}

test "bringToTop depth 0 no consume (DUP)" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, test_program());
    defer ctx.deinit();

    try ctx.stack.push(allocator, "x");
    try ctx.bringToTop("x", false);

    try std.testing.expectEqual(@as(usize, 1), ctx.instructions.items.len);
    try std.testing.expectEqual(Opcode.op_dup, ctx.instructions.items[0].op);
    try std.testing.expectEqual(@as(usize, 2), ctx.stack.depth());
    try std.testing.expectEqualStrings("x", ctx.stack.peekAtDepth(0).?);
    try std.testing.expectEqualStrings("x", ctx.stack.peekAtDepth(1).?);
}

test "bringToTop depth 0 consume (no-op)" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, test_program());
    defer ctx.deinit();

    try ctx.stack.push(allocator, "x");
    try ctx.bringToTop("x", true);

    try std.testing.expectEqual(@as(usize, 0), ctx.instructions.items.len);
    try std.testing.expectEqual(@as(usize, 1), ctx.stack.depth());
}

test "bringToTop depth 1 consume (SWAP)" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, test_program());
    defer ctx.deinit();

    try ctx.stack.push(allocator, "a");
    try ctx.stack.push(allocator, "b");
    try ctx.bringToTop("a", true);

    try std.testing.expectEqual(@as(usize, 1), ctx.instructions.items.len);
    try std.testing.expectEqual(Opcode.op_swap, ctx.instructions.items[0].op);
    try std.testing.expectEqualStrings("a", ctx.stack.peekAtDepth(0).?);
    try std.testing.expectEqualStrings("b", ctx.stack.peekAtDepth(1).?);
}

test "bringToTop depth 1 no consume (OVER)" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, test_program());
    defer ctx.deinit();

    try ctx.stack.push(allocator, "a");
    try ctx.stack.push(allocator, "b");
    try ctx.bringToTop("a", false);

    try std.testing.expectEqual(@as(usize, 1), ctx.instructions.items.len);
    try std.testing.expectEqual(Opcode.op_over, ctx.instructions.items[0].op);
    try std.testing.expectEqual(@as(usize, 3), ctx.stack.depth());
    try std.testing.expectEqualStrings("a", ctx.stack.peekAtDepth(0).?);
}

test "bringToTop depth 2 consume (ROT)" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, test_program());
    defer ctx.deinit();

    try ctx.stack.push(allocator, "a");
    try ctx.stack.push(allocator, "b");
    try ctx.stack.push(allocator, "c");
    try ctx.bringToTop("a", true);

    try std.testing.expectEqual(@as(usize, 1), ctx.instructions.items.len);
    try std.testing.expectEqual(Opcode.op_rot, ctx.instructions.items[0].op);
    try std.testing.expectEqual(@as(usize, 3), ctx.stack.depth());
    try std.testing.expectEqualStrings("a", ctx.stack.peekAtDepth(0).?);
}

test "bringToTop depth 3+ consume (ROLL)" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, test_program());
    defer ctx.deinit();

    try ctx.stack.push(allocator, "a");
    try ctx.stack.push(allocator, "b");
    try ctx.stack.push(allocator, "c");
    try ctx.stack.push(allocator, "d");
    try ctx.bringToTop("a", true);

    try std.testing.expectEqual(@as(usize, 2), ctx.instructions.items.len);
    try std.testing.expectEqual(@as(i64, 3), ctx.instructions.items[0].push_int);
    try std.testing.expectEqual(Opcode.op_roll, ctx.instructions.items[1].op);
    try std.testing.expectEqualStrings("a", ctx.stack.peekAtDepth(0).?);
    try std.testing.expectEqual(@as(usize, 4), ctx.stack.depth());
}

test "bringToTop depth 2+ no consume (PICK)" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, test_program());
    defer ctx.deinit();

    try ctx.stack.push(allocator, "a");
    try ctx.stack.push(allocator, "b");
    try ctx.stack.push(allocator, "c");
    try ctx.bringToTop("a", false);

    try std.testing.expectEqual(@as(usize, 2), ctx.instructions.items.len);
    try std.testing.expectEqual(@as(i64, 2), ctx.instructions.items[0].push_int);
    try std.testing.expectEqual(Opcode.op_pick, ctx.instructions.items[1].op);
    try std.testing.expectEqual(@as(usize, 4), ctx.stack.depth());
    try std.testing.expectEqualStrings("a", ctx.stack.peekAtDepth(0).?);
}

test "lower simple P2PKH contract" {
    const allocator = std.testing.allocator;

    const bindings = [_]types.ANFBinding{
        .{
            .name = "t0",
            .value = .{ .builtin_call = .{
                .name = "checkSig",
                .args = &[_][]const u8{ "sig", "pubkey" },
            } },
        },
        .{
            .name = "t1",
            .value = .{ .assert_op = .{
                .condition = "t0",
            } },
        },
    };

    const ctor_params = [_]types.ParamNode{
        .{ .name = "pubKeyHash", .type_info = .ripemd160 },
    };

    const method = types.ANFMethod{
        .name = "unlock",
        .is_public = true,
        .params = @constCast(&[_]types.ANFParam{
            .{ .name = "sig", .type_name = "Sig" },
            .{ .name = "pubkey", .type_name = "PubKey" },
        }),
        .bindings = @constCast(&bindings),
    };

    var props = [_]types.ANFProperty{
        .{ .name = "pubKeyHash", .type_name = "Ripemd160", .readonly = true },
    };
    var methods_arr = [_]types.ANFMethod{method};
    const program = types.ANFProgram{
        .contract_name = "P2PKH",
        .properties = &props,
        .methods = &methods_arr,
        .constructor = .{ .params = @constCast(&ctor_params), .assertions = &.{} },
    };

    const result = try lower(allocator, program);
    defer {
        for (result.methods) |m| {
            allocator.free(m.instructions);
            if (m.instruction_source_locs.len > 0) allocator.free(m.instruction_source_locs);
        }
        allocator.free(result.methods);
    }

    try std.testing.expectEqual(@as(usize, 1), result.methods.len);
    try std.testing.expectEqualStrings("unlock", result.methods[0].name);

    const insts = result.methods[0].instructions;
    try std.testing.expect(insts.len > 0);

    var found_checksig = false;
    var found_verify = false;
    for (insts) |inst| {
        switch (inst) {
            .op => |op| {
                if (op == .op_checksig) found_checksig = true;
                if (op == .op_verify) found_verify = true;
            },
            else => {},
        }
    }
    try std.testing.expect(found_checksig);
    try std.testing.expect(!found_verify);
}

test "lower arithmetic bindings" {
    const allocator = std.testing.allocator;

    const bindings = [_]types.ANFBinding{
        .{
            .name = "t0",
            .value = .{ .binary_op = .{
                .op = .add,
                .left = "x",
                .right = "y",
            } },
        },
    };

    const method = types.ANFMethod{
        .name = "add",
        .is_public = true,
        .params = @constCast(&[_]types.ANFParam{
            .{ .name = "x", .type_name = "bigint" },
            .{ .name = "y", .type_name = "bigint" },
        }),
        .bindings = @constCast(&bindings),
    };

    const program = types.ANFProgram{
        .contract_name = "Arithmetic",
        .properties = &.{},
        .methods = @constCast(&[_]types.ANFMethod{method}),
    };

    const result = try lower(allocator, program);
    defer {
        for (result.methods) |m| {
            allocator.free(m.instructions);
            if (m.instruction_source_locs.len > 0) allocator.free(m.instruction_source_locs);
        }
        allocator.free(result.methods);
    }

    const insts = result.methods[0].instructions;
    var found_add = false;
    for (insts) |inst| {
        switch (inst) {
            .op => |op| {
                if (op == .op_add) found_add = true;
            },
            else => {},
        }
    }
    try std.testing.expect(found_add);
}

test "lower literal push" {
    const allocator = std.testing.allocator;

    const bindings = [_]types.ANFBinding{
        .{ .name = "t0", .value = .{ .literal_int = 42 } },
        .{ .name = "t1", .value = .{ .literal_bool = true } },
    };

    const method = types.ANFMethod{
        .name = "test_method",
        .is_public = true,
        .params = &.{},
        .bindings = @constCast(&bindings),
    };

    const program = types.ANFProgram{
        .contract_name = "Literals",
        .properties = &.{},
        .methods = @constCast(&[_]types.ANFMethod{method}),
    };

    const result = try lower(allocator, program);
    defer {
        for (result.methods) |m| {
            allocator.free(m.instructions);
            if (m.instruction_source_locs.len > 0) allocator.free(m.instruction_source_locs);
        }
        allocator.free(result.methods);
    }

    const insts = result.methods[0].instructions;
    try std.testing.expect(insts.len >= 2);
    try std.testing.expectEqual(@as(i64, 42), insts[0].push_int);
    try std.testing.expectEqual(true, insts[1].push_bool);
}

test "lower hash builtin" {
    const allocator = std.testing.allocator;

    const bindings = [_]types.ANFBinding{
        .{
            .name = "t0",
            .value = .{ .builtin_call = .{
                .name = "sha256",
                .args = &[_][]const u8{"data"},
            } },
        },
    };

    const method = types.ANFMethod{
        .name = "hashIt",
        .is_public = true,
        .params = @constCast(&[_]types.ANFParam{
            .{ .name = "data", .type_name = "ByteString" },
        }),
        .bindings = @constCast(&bindings),
    };

    const program = types.ANFProgram{
        .contract_name = "Hasher",
        .properties = &.{},
        .methods = @constCast(&[_]types.ANFMethod{method}),
    };

    const result = try lower(allocator, program);
    defer {
        for (result.methods) |m| {
            allocator.free(m.instructions);
            if (m.instruction_source_locs.len > 0) allocator.free(m.instruction_source_locs);
        }
        allocator.free(result.methods);
    }

    var found_sha256 = false;
    for (result.methods[0].instructions) |inst| {
        switch (inst) {
            .op => |op| {
                if (op == .op_sha256) found_sha256 = true;
            },
            else => {},
        }
    }
    try std.testing.expect(found_sha256);
}

test "lower sha256Compress builtin" {
    const allocator = std.testing.allocator;

    const bindings = [_]types.ANFBinding{
        .{
            .name = "t0",
            .value = .{ .builtin_call = .{
                .name = "sha256Compress",
                .args = &[_][]const u8{ "state", "block" },
            } },
        },
    };

    const method = types.ANFMethod{
        .name = "compress",
        .is_public = true,
        .params = @constCast(&[_]types.ANFParam{
            .{ .name = "state", .type_name = "ByteString" },
            .{ .name = "block", .type_name = "ByteString" },
        }),
        .bindings = @constCast(&bindings),
    };

    const program = types.ANFProgram{
        .contract_name = "Sha256CompressTest",
        .properties = &.{},
        .methods = @constCast(&[_]types.ANFMethod{method}),
    };

    const result = try lower(allocator, program);
    defer {
        for (result.methods) |m| {
            allocator.free(m.instructions);
            if (m.instruction_source_locs.len > 0) allocator.free(m.instruction_source_locs);
        }
        allocator.free(result.methods);
    }

    var found_lshift = false;
    var found_rshift = false;
    var found_bin2num = false;
    for (result.methods[0].instructions) |inst| {
        switch (inst) {
            .op => |op| {
                if (op == .op_lshift) found_lshift = true;
                if (op == .op_rshift) found_rshift = true;
                if (op == .op_bin2num) found_bin2num = true;
            },
            else => {},
        }
    }
    try std.testing.expect(found_lshift);
    try std.testing.expect(found_rshift);
    try std.testing.expect(found_bin2num);
}

test "lower sha256Finalize builtin" {
    const allocator = std.testing.allocator;

    const bindings = [_]types.ANFBinding{
        .{
            .name = "t0",
            .value = .{ .builtin_call = .{
                .name = "sha256Finalize",
                .args = &[_][]const u8{ "state", "remaining", "bit_len" },
            } },
        },
    };

    const method = types.ANFMethod{
        .name = "finalize",
        .is_public = true,
        .params = @constCast(&[_]types.ANFParam{
            .{ .name = "state", .type_name = "ByteString" },
            .{ .name = "remaining", .type_name = "ByteString" },
            .{ .name = "bit_len", .type_name = "bigint" },
        }),
        .bindings = @constCast(&bindings),
    };

    const program = types.ANFProgram{
        .contract_name = "Sha256FinalizeTest",
        .properties = &.{},
        .methods = @constCast(&[_]types.ANFMethod{method}),
    };

    const result = try lower(allocator, program);
    defer {
        for (result.methods) |m| {
            allocator.free(m.instructions);
            if (m.instruction_source_locs.len > 0) allocator.free(m.instruction_source_locs);
        }
        allocator.free(result.methods);
    }

    var found_if = false;
    var found_else = false;
    var found_endif = false;
    var found_num2bin = false;
    for (result.methods[0].instructions) |inst| {
        switch (inst) {
            .op => |op| {
                if (op == .op_if) found_if = true;
                if (op == .op_else) found_else = true;
                if (op == .op_endif) found_endif = true;
                if (op == .op_num2bin) found_num2bin = true;
            },
            else => {},
        }
    }
    try std.testing.expect(found_if);
    try std.testing.expect(found_else);
    try std.testing.expect(found_endif);
    try std.testing.expect(found_num2bin);
}

test "lower if expression" {
    const allocator = std.testing.allocator;

    const then_bindings = [_]types.ANFBinding{
        .{ .name = "t_then", .value = .{ .literal_int = 1 } },
    };

    const else_bindings = [_]types.ANFBinding{
        .{ .name = "t_else", .value = .{ .literal_int = 0 } },
    };

    var if_expr = types.ANFIfExpr{
        .condition = "cond",
        .then_bindings = @constCast(&then_bindings),
        .else_bindings = @constCast(&else_bindings),
    };

    const bindings = [_]types.ANFBinding{
        .{ .name = "cond", .value = .{ .literal_bool = true } },
        .{ .name = "result", .value = .{ .if_expr = &if_expr } },
    };

    const method = types.ANFMethod{
        .name = "choose",
        .is_public = true,
        .params = &.{},
        .bindings = @constCast(&bindings),
    };

    const program = types.ANFProgram{
        .contract_name = "Chooser",
        .properties = &.{},
        .methods = @constCast(&[_]types.ANFMethod{method}),
    };

    const result = try lower(allocator, program);
    defer {
        for (result.methods) |m| {
            allocator.free(m.instructions);
            if (m.instruction_source_locs.len > 0) allocator.free(m.instruction_source_locs);
        }
        allocator.free(result.methods);
    }

    var found_if = false;
    var found_else = false;
    var found_endif = false;
    for (result.methods[0].instructions) |inst| {
        switch (inst) {
            .op => |op| {
                if (op == .op_if) found_if = true;
                if (op == .op_else) found_else = true;
                if (op == .op_endif) found_endif = true;
            },
            else => {},
        }
    }
    try std.testing.expect(found_if);
    try std.testing.expect(found_else);
    try std.testing.expect(found_endif);
}

test "lower for loop unrolling" {
    const allocator = std.testing.allocator;

    const loop_body = [_]types.ANFBinding{
        .{ .name = "t_body", .value = .{ .literal_int = 99 } },
    };

    var loop_val = types.ANFForLoop{
        .var_name = "i",
        .init_val = 0,
        .bound = 3,
        .body_bindings = @constCast(&loop_body),
    };

    const bindings = [_]types.ANFBinding{
        .{ .name = "loop_result", .value = .{ .for_loop = &loop_val } },
    };

    const method = types.ANFMethod{
        .name = "looper",
        .is_public = true,
        .params = &.{},
        .bindings = @constCast(&bindings),
    };

    const program = types.ANFProgram{
        .contract_name = "Looper",
        .properties = &.{},
        .methods = @constCast(&[_]types.ANFMethod{method}),
    };

    const result = try lower(allocator, program);
    defer {
        for (result.methods) |m| {
            allocator.free(m.instructions);
            if (m.instruction_source_locs.len > 0) allocator.free(m.instruction_source_locs);
        }
        allocator.free(result.methods);
    }

    var push_count: usize = 0;
    for (result.methods[0].instructions) |inst| {
        switch (inst) {
            .push_int => push_count += 1,
            else => {},
        }
    }
    // 3 iteration vars + 3 body constants = at least 6
    try std.testing.expect(push_count >= 6);
}

test "lower multi-method produces one StackMethod per public method" {
    const allocator = std.testing.allocator;

    const bindings1 = [_]types.ANFBinding{
        .{ .name = "t0", .value = .{ .literal_int = 1 } },
    };
    const bindings2 = [_]types.ANFBinding{
        .{ .name = "t0", .value = .{ .literal_int = 2 } },
    };

    var methods_arr = [_]types.ANFMethod{
        .{ .name = "methodA", .is_public = true, .params = &.{}, .bindings = @constCast(&bindings1) },
        .{ .name = "methodB", .is_public = true, .params = &.{}, .bindings = @constCast(&bindings2) },
    };

    const program = types.ANFProgram{
        .contract_name = "MultiMethod",
        .properties = &.{},
        .methods = &methods_arr,
    };

    const result = try lower(allocator, program);
    defer {
        for (result.methods) |m| {
            allocator.free(m.instructions);
            if (m.instruction_source_locs.len > 0) allocator.free(m.instruction_source_locs);
        }
        allocator.free(result.methods);
    }

    // Dispatch wrapping is added at emit time, so stack_lower produces one
    // StackMethod per public method. The dispatch table opcodes (OP_DUP,
    // OP_NUMEQUAL, OP_IF, OP_ELSE, OP_ENDIF, OP_NUMEQUALVERIFY) live in emit.zig.
    try std.testing.expectEqual(@as(usize, 2), result.methods.len);
    try std.testing.expectEqualStrings("methodA", result.methods[0].name);
    try std.testing.expectEqualStrings("methodB", result.methods[1].name);
}

test "lower ecOnCurve preserves field prime pushdata" {
    const allocator = std.testing.allocator;

    const bindings = [_]types.ANFBinding{
        .{
            .name = "t0",
            .value = .{ .call = .{
                .func = "ecOnCurve",
                .args = @constCast(&[_][]const u8{"pt"}),
            } },
        },
        .{
            .name = "t1",
            .value = .{ .assert = .{ .value = "t0" } },
        },
    };

    const method = types.ANFMethod{
        .name = "check",
        .is_public = true,
        .params = @constCast(&[_]types.ANFParam{
            .{ .name = "pt", .type_name = "Point" },
        }),
        .bindings = @constCast(&bindings),
    };

    const program = types.ANFProgram{
        .contract_name = "ECTest",
        .properties = &.{},
        .methods = @constCast(&[_]types.ANFMethod{method}),
    };

    const result = try lower(allocator, program);
    defer result.deinit(allocator);

    var found = false;
    for (result.methods[0].instructions) |inst| {
        switch (inst) {
            .push_data => |data| {
                if (data.len != 33) continue;
                if (data[0] != 0x2f or data[1] != 0xfc or data[2] != 0xff or data[3] != 0xff or data[4] != 0xfe) continue;
                if (data[32] != 0x00) continue;
                found = true;
                break;
            },
            else => {},
        }
    }

    try std.testing.expect(found);
}

// ============================================================================
// Test helper
// ============================================================================

fn test_program() types.ANFProgram {
    return .{
        .contract_name = "_test_",
        .properties = &.{},
        .methods = &.{},
    };
}
