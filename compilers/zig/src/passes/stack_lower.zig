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
        const idx = self.name_index.get(name) orelse return null;
        return self.slots.items.len - 1 - idx;
    }

    /// Remove the slot at the given depth (0 = top). Depth d maps to array
    /// index `len - 1 - d`. Requires rebuilding affected hash map entries.
    pub fn removeAtDepth(self: *StackMap, d: usize) void {
        const idx = self.slots.items.len - 1 - d;
        const removed = self.slots.items[idx];
        if (removed) |v| {
            _ = self.name_index.remove(v);
        }
        _ = self.slots.orderedRemove(idx);
        // Update indices for all slots that shifted down (those above idx)
        for (self.slots.items[idx..], idx..) |slot, new_idx| {
            if (slot) |s| {
                self.name_index.putAssumeCapacity(s, new_idx);
            }
        }
    }

    /// Rename the variable at the given depth.
    pub fn renameAtDepth(self: *StackMap, d: usize, new_name: ?[]const u8) void {
        const idx = self.slots.items.len - 1 - d;
        const old_name = self.slots.items[idx];
        if (old_name) |v| {
            _ = self.name_index.remove(v);
        }
        self.slots.items[idx] = new_name;
        if (new_name) |n| {
            self.name_index.putAssumeCapacity(n, idx);
        }
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
        try new_index.ensureTotalCapacity(allocator, self.name_index.capacity());
        var it = self.name_index.iterator();
        while (it.next()) |entry| {
            new_index.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
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
    stack: StackMap,
    program: types.ANFProgram,
    last_uses: std.StringHashMapUnmanaged(usize),
    current_idx: usize,
    in_branch: bool,
    updated_props: std.StringHashMapUnmanaged(void),
    max_depth: u32,

    fn init(allocator: Allocator, program: types.ANFProgram) LowerCtx {
        return .{
            .allocator = allocator,
            .instructions = .empty,
            .stack = .{},
            .program = program,
            .last_uses = .empty,
            .current_idx = 0,
            .in_branch = false,
            .updated_props = .empty,
            .max_depth = 0,
        };
    }

    fn deinit(self: *LowerCtx) void {
        self.instructions.deinit(self.allocator);
        self.stack.deinit(self.allocator);
        self.last_uses.deinit(self.allocator);
        self.updated_props.deinit(self.allocator);
    }

    fn trackDepth(self: *LowerCtx) void {
        const d: u32 = @intCast(self.stack.depth());
        if (d > self.max_depth) self.max_depth = d;
    }

    // ========================================================================
    // Emit helpers
    // ========================================================================

    fn emit(self: *LowerCtx, inst: types.StackInstruction) !void {
        try self.instructions.append(self.allocator, inst);
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
                    // Update hash map for both swapped names
                    if (old_top) |n| self.stack.name_index.putAssumeCapacity(n, next_idx);
                    if (old_next) |n| self.stack.name_index.putAssumeCapacity(n, top_idx);
                },
                2 => {
                    try self.emitOp(.op_rot);
                    self.stack.removeAtDepth(d);
                    try self.stack.push(self.allocator, name);
                },
                else => {
                    try self.emitPushInt(@intCast(d));
                    try self.emitOp(.op_roll);
                    self.stack.removeAtDepth(d);
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
                    try self.emitOp(.op_pick);
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
            .load_param, .load_prop, .load_const, .get_state_script => {},
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
            .if_expr => |ie| {
                self.last_uses.put(self.allocator, ie.condition, idx) catch return;
            },
            .@"if" => |ie| {
                self.last_uses.put(self.allocator, ie.cond, idx) catch return;
            },
            .for_loop, .loop => {},
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

    fn lowerBindings(self: *LowerCtx, bindings: []const types.ANFBinding) LowerError!void {
        try self.computeLastUses(bindings);
        for (bindings, 0..) |binding, idx| {
            self.current_idx = idx;
            try self.lowerBinding(binding);
        }
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
            .assert_op => |a| try self.lowerAssertOp(binding.name, a),
            .add_output => |ao| try self.lowerAddOutput(binding.name, ao),
            .add_raw_output => |aro| try self.lowerAddRawOutput(binding.name, aro),
            .nop, .get_state_script => {},
            // TypeScript-matching variants: delegate to equivalent legacy handlers
            .load_param => |lp| try self.lowerRef(binding.name, lp.name),
            .load_prop => |lp| try self.lowerPropertyRead(binding.name, lp.name),
            .load_const => |lc| {
                switch (lc.value) {
                    .boolean => |b| try self.emitPushBool(b),
                    .integer => |n| try self.emitPushInt(@intCast(n)),
                    .string => |s| try self.emitPushData(s),
                }
                try self.stack.push(self.allocator, binding.name);
                self.trackDepth();
            },
            .bin_op => |bop| {
                const legacy_op = types.BinOperator.fromTsString(bop.op) orelse return LowerError.UnsupportedOperation;
                try self.lowerBinaryOp(binding.name, .{ .op = legacy_op, .left = bop.left, .right = bop.right, .result_type = bop.result_type });
            },
            .call => |c| try self.lowerBuiltinCall(binding.name, .{ .name = c.func, .args = c.args }),
            .method_call => {
                return LowerError.UnsupportedOperation;
            },
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
            .assert => |a| try self.lowerAssertOp(binding.name, .{ .condition = a.value }),
            .update_prop => |up| try self.lowerPropertyWrite(binding.name, .{ .name = up.name, .value_ref = up.value }),
            .check_preimage => |cp| {
                try self.lowerRef(binding.name, cp.preimage);
            },
            .deserialize_state => |ds| {
                try self.lowerRef(binding.name, ds.preimage);
            },
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
        self.stack.renameAtDepth(0, bind_name);
    }

    fn lowerPropertyRead(self: *LowerCtx, bind_name: []const u8, prop_name: []const u8) !void {
        // Check if property has been updated on stack
        if (self.updated_props.get(prop_name) != null) {
            if (self.stack.findDepth(prop_name)) |_| {
                const consume = self.isLastUse(prop_name);
                try self.bringToTop(prop_name, consume);
                self.stack.renameAtDepth(0, bind_name);
                return;
            }
        }
        // Property might be on stack from setup
        if (self.stack.findDepth(prop_name)) |_| {
            const consume = self.isLastUse(prop_name);
            try self.bringToTop(prop_name, consume);
            self.stack.renameAtDepth(0, bind_name);
            return;
        }
        // Check if the property has an initial_value
        for (self.program.properties) |prop| {
            if (std.mem.eql(u8, prop.name, prop_name)) {
                if (prop.initial_value) |iv| {
                    switch (iv) {
                        .boolean => |b| try self.emitPushBool(b),
                        .integer => |n| try self.emitPushInt(@intCast(n)),
                        .string => |s| try self.emitPushData(s),
                    }
                    try self.stack.push(self.allocator, bind_name);
                    self.trackDepth();
                    return;
                }
            }
        }
        // Not found — push placeholder
        try self.emitPushInt(0);
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerPropertyWrite(self: *LowerCtx, bind_name: []const u8, pw: types.PropertyWrite) !void {
        const consume = self.isLastUse(pw.value_ref);
        try self.bringToTop(pw.value_ref, consume);
        self.stack.renameAtDepth(0, pw.name);
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
                    try self.emitOp(.op_swap);
                    try self.emitOp(.op_drop);
                } else if (od == 2) {
                    try self.emitOp(.op_rot);
                    try self.emitOp(.op_drop);
                } else {
                    try self.emitPushInt(@intCast(od));
                    try self.emitOp(.op_roll);
                    try self.emitOp(.op_drop);
                }
                self.stack.removeAtDepth(od);
            }
        }
        _ = bind_name;
    }

    fn lowerBinaryOp(self: *LowerCtx, bind_name: []const u8, bop: types.ANFBinaryOp) !void {
        try self.bringToTopAuto(bop.left);
        try self.bringToTopAuto(bop.right);

        switch (bop.op) {
            .add => try self.emitOp(.op_add),
            .sub => try self.emitOp(.op_sub),
            .mul => try self.emitOp(.op_mul),
            .div => try self.emitOp(.op_div),
            .mod => try self.emitOp(.op_mod),
            .eq => try self.emitOp(.op_numequal),
            .neq => {
                try self.emitOp(.op_numequal);
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
        buildChangeOutput,
        getStateScript,
        buildStateOutput,
        computeStateOutput,
        // Wave 3 placeholders
        sha256Compress,
        blake3,
        ecAdd,
        ecMul,
        ecPairing,
        slhDsaVerify,
        schnorrVerify,
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
        .{ "buildChangeOutput", .buildChangeOutput },
        .{ "getStateScript", .getStateScript },
        .{ "buildStateOutput", .buildStateOutput },
        .{ "computeStateOutput", .computeStateOutput },
        .{ "sha256Compress", .sha256Compress },
        .{ "blake3", .blake3 },
        .{ "ecAdd", .ecAdd },
        .{ "ecMul", .ecMul },
        .{ "ecPairing", .ecPairing },
        .{ "slhDsaVerify", .slhDsaVerify },
        .{ "schnorrVerify", .schnorrVerify },
        .{ "super", .super_call },
    });

    fn lowerBuiltinCall(self: *LowerCtx, bind_name: []const u8, call: types.ANFBuiltinCall) !void {
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
            .buildChangeOutput => try self.lowerBuildChangeOutput(bind_name, args),
            .getStateScript, .buildStateOutput, .computeStateOutput => {
                // No-op or handled elsewhere
                try self.stack.push(self.allocator, bind_name);
                self.trackDepth();
            },
            // super() is the constructor superclass call — no-op in Bitcoin Script
            .super_call => {
                try self.stack.push(self.allocator, bind_name);
                self.trackDepth();
            },
            // Wave 3 placeholders — consume args and push placeholder
            .sha256Compress, .blake3, .ecAdd, .ecMul, .ecPairing, .slhDsaVerify, .schnorrVerify => {
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
        try self.emitPushInt(0);
        try self.emitOp(.op_numequal);
        try self.emitOp(.op_not);
        try self.emitOp(.op_verify);
        try self.emitOp(final_op);
        _ = self.stack.pop();
        _ = self.stack.pop();
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
        try self.bringToTopAuto(args[0]); // base
        try self.bringToTopAuto(args[1]); // exp

        // Handle exp==0 => 1, exp==1 => base, else binary exponentiation (30 iterations)
        try self.emitOp(.op_dup);
        try self.emitPushInt(0);
        try self.emitOp(.op_numequal);
        try self.emitOp(.op_if);
        try self.emitOp(.op_2drop);
        try self.emitPushInt(1);
        try self.emitOp(.op_else);
        try self.emitOp(.op_dup);
        try self.emitPushInt(1);
        try self.emitOp(.op_numequal);
        try self.emitOp(.op_if);
        try self.emitOp(.op_drop); // drop exp, leave base
        try self.emitOp(.op_else);
        // General case: stack is base exp. Set up acc=1 base exp
        try self.emitOp(.op_swap); // exp base
        try self.emitPushInt(1); // exp base 1
        try self.emitOp(.op_swap); // exp 1 base
        try self.emitOp(.op_rot); // 1 base exp

        // 30 iterations of binary exponentiation
        // Each iter: stack = acc base exp
        var iter: u32 = 0;
        while (iter < 30) : (iter += 1) {
            // acc base exp
            try self.emitOp(.op_dup); // acc base exp exp
            try self.emitPushInt(1);
            try self.emitOp(.op_and); // acc base exp (exp&1)
            try self.emitOp(.op_if);
            // exp is odd: acc *= base
            // Stack: acc base exp
            try self.emitOp(.op_rot); // base exp acc
            try self.emitOp(.op_rot); // exp acc base
            try self.emitOp(.op_dup); // exp acc base base
            try self.emitOp(.op_rot); // exp base base acc
            try self.emitOp(.op_mul); // exp base (base*acc)
            try self.emitOp(.op_rot); // base (base*acc) exp
            try self.emitOp(.op_rot); // (base*acc) exp base
            try self.emitOp(.op_swap); // (base*acc) base exp
            try self.emitOp(.op_else);
            try self.emitOp(.op_endif);
            // Stack: acc base exp
            // base = base * base
            try self.emitOp(.op_swap); // acc exp base
            try self.emitOp(.op_dup);
            try self.emitOp(.op_mul); // acc exp (base^2)
            try self.emitOp(.op_swap); // acc (base^2) exp
            // exp >>= 1
            try self.emitPushInt(2);
            try self.emitOp(.op_div); // acc (base^2) (exp/2)
            // Reorder to acc base exp
            try self.emitOp(.op_rot); // (base^2) (exp/2) acc
            try self.emitOp(.op_rot); // (exp/2) acc (base^2)
            try self.emitOp(.op_rot); // acc (base^2) (exp/2)
        }
        // Stack: acc base exp (exp should be 0)
        try self.emitOp(.op_drop);
        try self.emitOp(.op_drop);
        try self.emitOp(.op_endif);
        try self.emitOp(.op_endif);

        _ = self.stack.pop();
        _ = self.stack.pop();
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
        try self.emitOp(.op_mul);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        self.trackDepth();
        try self.emitPushInt(100);
        try self.emitOp(.op_div);
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerSqrt(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 1) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        try self.emitOp(.op_dup);
        var iter: u32 = 0;
        while (iter < 20) : (iter += 1) {
            try self.emitOp(.op_over);
            try self.emitOp(.op_over);
            try self.emitOp(.op_div);
            try self.emitOp(.op_add);
            try self.emitPushInt(2);
            try self.emitOp(.op_div);
        }
        try self.emitOp(.op_nip);
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerGcd(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 2) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        try self.bringToTopAuto(args[1]);
        var iter: u32 = 0;
        while (iter < 30) : (iter += 1) {
            try self.emitOp(.op_dup);
            try self.emitOp(.op_if);
            try self.emitOp(.op_swap);
            try self.emitOp(.op_over);
            try self.emitOp(.op_mod);
            try self.emitOp(.op_else);
            try self.emitOp(.op_drop);
            try self.emitPushInt(0);
            try self.emitOp(.op_endif);
        }
        try self.emitOp(.op_drop);
        _ = self.stack.pop();
        _ = self.stack.pop();
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
        try self.emitPushInt(0);
        try self.emitOp(.op_swap);
        var iter: u32 = 0;
        while (iter < 32) : (iter += 1) {
            try self.emitOp(.op_dup);
            try self.emitOp(.op_if);
            try self.emitPushInt(2);
            try self.emitOp(.op_div);
            try self.emitOp(.op_swap);
            try self.emitOp(.op_1add);
            try self.emitOp(.op_swap);
            try self.emitOp(.op_else);
            try self.emitOp(.op_endif);
        }
        try self.emitOp(.op_drop);
        try self.emitOp(.op_1sub);
        _ = self.stack.pop();
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

    fn lowerCheckPreimage(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 1) return LowerError.InvalidBuiltin;
        try self.emitOp(.op_codeseparator);
        try self.bringToTopAuto(args[0]);
        const has_sig = self.stack.findDepth("_opPushTxSig") != null;
        if (has_sig) {
            try self.bringToTop("_opPushTxSig", true);
        }
        try self.emitPushData(&generator_point_g);
        // Track the generator point in the stack map so pop accounting is correct
        try self.stack.push(self.allocator, null);
        self.trackDepth();
        // OP_CHECKSIGVERIFY consumes top 2 items (sig/txsig + pubkey/G)
        try self.emitOp(.op_checksigverify);
        _ = self.stack.pop(); // G (generator point)
        if (has_sig) {
            _ = self.stack.pop(); // _opPushTxSig
            // preimage (args[0]) remains on stack — consumed by caller or used downstream
        } else {
            _ = self.stack.pop(); // args[0] consumed as sig when no _opPushTxSig
        }
        _ = bind_name;
    }

    fn lowerDeserializeState(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 1) return LowerError.InvalidBuiltin;
        try self.bringToTopAuto(args[0]);
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerBuildChangeOutput(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 2) return LowerError.InvalidBuiltin;
        // args: [changePKH, changeAmount]
        try self.bringToTopAuto(args[1]); // changeAmount
        try self.emitPushInt(8);
        try self.emitOp(.op_num2bin);
        // Build P2PKH script: 76 a9 14 <pkh> 88 ac
        try self.emitPushData(&.{ 0x76, 0xa9, 0x14 });
        try self.bringToTopAuto(args[0]); // changePKH
        try self.emitOp(.op_cat);
        try self.emitPushData(&.{ 0x88, 0xac });
        try self.emitOp(.op_cat);
        // Varint prefix for 25-byte P2PKH script
        try self.emitPushData(&.{0x19});
        try self.emitOp(.op_swap);
        try self.emitOp(.op_cat);
        // Combine satoshis + script
        try self.emitOp(.op_swap);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    // ========================================================================
    // assert_op
    // ========================================================================

    fn lowerAssertOp(self: *LowerCtx, bind_name: []const u8, a: types.ANFLegacyAssert) !void {
        try self.bringToTopAuto(a.condition);
        try self.emitOp(.op_verify);
        _ = self.stack.pop();
        _ = bind_name;
    }

    // ========================================================================
    // if_expr
    // ========================================================================

    fn lowerIfExpr(self: *LowerCtx, bind_name: []const u8, ie: *const types.ANFIfExpr) !void {
        try self.bringToTopAuto(ie.condition);
        _ = self.stack.pop();
        try self.emitOp(.op_if);

        // Save base stack for else branch
        var base_stack = try self.stack.clone(self.allocator);
        defer base_stack.deinit(self.allocator);

        const saved_in_branch = self.in_branch;
        self.in_branch = true;

        // -- Then branch --
        if (ie.then_bindings.len > 0) {
            const saved_lu = self.last_uses;
            self.last_uses = .empty;
            try self.computeLastUses(ie.then_bindings);
            for (ie.then_bindings, 0..) |binding, idx| {
                self.current_idx = idx;
                try self.lowerBinding(binding);
            }
            self.last_uses.deinit(self.allocator);
            self.last_uses = saved_lu;
        }

        // Save then stack state for reconciliation
        const then_depth = self.stack.depth();
        const then_top_name = if (then_depth > 0) self.stack.peekAtDepth(0) else null;

        try self.emitOp(.op_else);

        // -- Else branch: restore base stack --
        self.stack.deinit(self.allocator);
        self.stack = try base_stack.clone(self.allocator);

        if (ie.else_bindings) |else_bindings| {
            if (else_bindings.len > 0) {
                const saved_lu2 = self.last_uses;
                self.last_uses = .empty;
                try self.computeLastUses(else_bindings);
                for (else_bindings, 0..) |binding, idx| {
                    self.current_idx = idx;
                    try self.lowerBinding(binding);
                }
                self.last_uses.deinit(self.allocator);
                self.last_uses = saved_lu2;
            }
        }

        const else_depth = self.stack.depth();
        const else_top_name = if (else_depth > 0) self.stack.peekAtDepth(0) else null;

        // Phase 3: Balance stack depth between branches.
        // Bitcoin Script requires identical stack state after OP_IF/OP_ELSE/OP_ENDIF
        // regardless of which branch executes. A mismatch means one path leaves
        // extra items (or too few) — the script will fail at runtime or, worse,
        // silently misinterpret stack positions, risking fund loss.
        if (then_depth != else_depth) {
            return LowerError.BranchStackMismatch;
        }

        // Verify top-of-stack names are consistent between branches.
        // Both branches should produce compatible named results.
        if (then_top_name != null and else_top_name != null) {
            // Both branches have named tops — they should match for the binding
            // to be meaningful. We don't error here because the rename below
            // will unify them under bind_name anyway.
        } else if (then_top_name == null and else_top_name == null) {
            // Both anonymous — fine
        }
        // Mixed named/null is acceptable: the rename below normalizes it.

        self.in_branch = saved_in_branch;
        try self.emitOp(.op_endif);

        if (self.stack.depth() > 0) {
            self.stack.renameAtDepth(0, bind_name);
        }
    }

    // ========================================================================
    // for_loop
    // ========================================================================

    fn lowerForLoop(self: *LowerCtx, bind_name: []const u8, fl: *const types.ANFForLoop) !void {
        var i: i64 = fl.init_val;
        while (i < fl.bound) : (i += 1) {
            try self.emitPushInt(i);
            try self.stack.push(self.allocator, fl.var_name);
            self.trackDepth();

            const saved_lu = self.last_uses;
            self.last_uses = .empty;
            try self.computeLastUses(fl.body_bindings);
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
                } else {
                    try self.emitPushInt(@intCast(d));
                    try self.emitOp(.op_roll);
                    try self.emitOp(.op_drop);
                    self.stack.removeAtDepth(d);
                }
            }
        }

        if (self.stack.depth() > 0) {
            self.stack.renameAtDepth(0, bind_name);
        }
    }

    // ========================================================================
    // add_output / add_raw_output
    // ========================================================================

    fn lowerAddOutput(self: *LowerCtx, bind_name: []const u8, ao: types.ANFAddOutput) !void {
        // Get _codePart
        if (self.stack.findDepth("_codePart")) |_| {
            try self.bringToTop("_codePart", false);
        } else {
            try self.emitPushData(&.{});
            try self.stack.push(self.allocator, null);
            self.trackDepth();
        }

        // CAT each state reference
        for (ao.state_refs) |state_ref| {
            try self.bringToTopAuto(state_ref);
            try self.emitOp(.op_cat);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null);
            self.trackDepth();
        }

        // OP_RETURN separator
        try self.emitPushData(&.{0x6a});
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        self.trackDepth();

        // Script length varint
        try self.emitOp(.op_dup);
        try self.emitOp(.op_size);
        try self.emitOp(.op_nip);
        try self.emitOp(.op_swap);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        self.trackDepth();

        // Satoshis as 8-byte LE
        try self.bringToTopAuto(ao.satoshis);
        try self.emitPushInt(8);
        try self.emitOp(.op_num2bin);
        try self.emitOp(.op_swap);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerAddRawOutput(self: *LowerCtx, bind_name: []const u8, aro: types.ANFAddRawOutput) !void {
        try self.bringToTopAuto(aro.script_ref);
        try self.emitOp(.op_dup);
        try self.emitOp(.op_size);
        try self.emitOp(.op_nip);
        try self.emitOp(.op_swap);
        try self.emitOp(.op_cat);
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        self.trackDepth();

        try self.bringToTopAuto(aro.satoshis);
        try self.emitPushInt(8);
        try self.emitOp(.op_num2bin);
        try self.emitOp(.op_swap);
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
pub fn lower(allocator: Allocator, program: types.ANFProgram) !types.StackProgram {
    const public_methods = countPublicMethods(program.methods);
    const needs_dispatch = public_methods > 1;

    var methods = std.ArrayListUnmanaged(types.StackMethod).empty;
    defer methods.deinit(allocator);

    if (needs_dispatch) {
        var ctx = LowerCtx.init(allocator, program);
        defer ctx.deinit();

        try setupPropertyStack(&ctx, program);
        try emitDispatchTable(&ctx, program);

        const instructions = try allocator.dupe(types.StackInstruction, ctx.instructions.items);
        try methods.append(allocator, .{
            .name = "__dispatch",
            .instructions = instructions,
            .max_stack_depth = ctx.max_depth,
        });
    } else {
        for (program.methods) |method| {
            var ctx = LowerCtx.init(allocator, program);
            defer ctx.deinit();

            try setupMethodStack(&ctx, program, method);

            // Use body or bindings (whichever is populated)
            const bindings = if (method.body.len > 0) method.body else method.bindings;
            try ctx.lowerBindings(bindings);

            try ctx.emitOp(.op_1); // OP_TRUE

            const instructions = try allocator.dupe(types.StackInstruction, ctx.instructions.items);
            try methods.append(allocator, .{
                .name = method.name,
                .instructions = instructions,
                .max_stack_depth = ctx.max_depth,
            });
        }
    }

    return .{
        .methods = try allocator.dupe(types.StackMethod, methods.items),
        .contract_name = program.contract_name,
        .properties = program.properties,
        .constructor_params = program.constructor.params,
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
        const bindings = if (method.body.len > 0) method.body else method.bindings;
        for (bindings) |binding| {
            switch (binding.value) {
                .add_output, .add_raw_output => return true,
                .builtin_call => |call| {
                    if (std.mem.eql(u8, call.name, "buildChangeOutput") or
                        std.mem.eql(u8, call.name, "computeStateOutput") or
                        std.mem.eql(u8, call.name, "buildStateOutput"))
                    {
                        return true;
                    }
                },
                else => {},
            }
        }
    }
    return false;
}

fn isStateful(program: types.ANFProgram) bool {
    return program.parent_class == .stateful_smart_contract;
}

fn setupMethodStack(ctx: *LowerCtx, program: types.ANFProgram, method: types.ANFMethod) !void {
    // Constructor params at the bottom (reverse order so first param is deepest)
    var i: usize = program.constructor.params.len;
    while (i > 0) {
        i -= 1;
        try ctx.stack.push(ctx.allocator, program.constructor.params[i].name);
    }
    ctx.trackDepth();

    if (isStateful(program)) {
        try ctx.stack.push(ctx.allocator, "_opPushTxSig");
        ctx.trackDepth();
        if (usesOutputBuiltins(program.methods)) {
            try ctx.stack.push(ctx.allocator, "_codePart");
            ctx.trackDepth();
        }
    }

    // Method parameters
    i = method.params.len;
    while (i > 0) {
        i -= 1;
        try ctx.stack.push(ctx.allocator, method.params[i].name);
    }
    ctx.trackDepth();
}

fn setupPropertyStack(ctx: *LowerCtx, program: types.ANFProgram) !void {
    var i: usize = program.constructor.params.len;
    while (i > 0) {
        i -= 1;
        try ctx.stack.push(ctx.allocator, program.constructor.params[i].name);
    }
    ctx.trackDepth();

    if (isStateful(program)) {
        try ctx.stack.push(ctx.allocator, "_opPushTxSig");
        ctx.trackDepth();
        if (usesOutputBuiltins(program.methods)) {
            try ctx.stack.push(ctx.allocator, "_codePart");
            ctx.trackDepth();
        }
    }
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

        if (pub_idx < last_pub) {
            try ctx.emitOp(.op_dup);
            try ctx.emitPushInt(@intCast(pub_idx));
            try ctx.emitOp(.op_numequal);
            try ctx.emitOp(.op_if);
            try ctx.emitOp(.op_drop);

            var branch_stack = try ctx.stack.clone(ctx.allocator);
            const saved_stack = ctx.stack;
            ctx.stack = branch_stack;

            var pi: usize = method.params.len;
            while (pi > 0) {
                pi -= 1;
                try ctx.stack.push(ctx.allocator, method.params[pi].name);
            }
            ctx.trackDepth();

            try ctx.lowerBindings(bindings);
            try ctx.emitOp(.op_1);

            branch_stack = ctx.stack;
            branch_stack.deinit(ctx.allocator);
            ctx.stack = saved_stack;

            try ctx.emitOp(.op_else);
        } else {
            try ctx.emitPushInt(@intCast(pub_idx));
            try ctx.emitOp(.op_numequalverify);

            var pi: usize = method.params.len;
            while (pi > 0) {
                pi -= 1;
                try ctx.stack.push(ctx.allocator, method.params[pi].name);
            }
            ctx.trackDepth();

            try ctx.lowerBindings(bindings);
            try ctx.emitOp(.op_1);
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

    map.removeAtDepth(1);
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
    map.renameAtDepth(0, "new");
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
    try std.testing.expect(found_verify);
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

test "lower multi-method dispatch" {
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
        }
        allocator.free(result.methods);
    }

    try std.testing.expectEqual(@as(usize, 1), result.methods.len);
    try std.testing.expectEqualStrings("__dispatch", result.methods[0].name);

    var found_numequal = false;
    var found_numequalverify = false;
    for (result.methods[0].instructions) |inst| {
        switch (inst) {
            .op => |op| {
                if (op == .op_numequal) found_numequal = true;
                if (op == .op_numequalverify) found_numequalverify = true;
            },
            else => {},
        }
    }
    try std.testing.expect(found_numequal);
    try std.testing.expect(found_numequalverify);
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
