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
const nist_ec_emitters = @import("helpers/nist_ec_emitters.zig");
const pq_emitters = @import("helpers/pq_emitters.zig");
const sha256_emitters = @import("helpers/sha256_emitters.zig");
const babybear_emitters = @import("helpers/babybear_emitters.zig");
const koalabear_emitters = @import("helpers/koalabear_emitters.zig");
const bn254_emitters = @import("helpers/bn254_emitters.zig");
const poseidon2_merkle = @import("helpers/poseidon2_merkle.zig");
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

    /// Debug string of the slot names (bottom -> top) for error messages.
    /// Mirrors the TS reference compiler's `StackMap.debugSlots`.
    pub fn debugSlots(self: *const StackMap, allocator: Allocator) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);
        for (self.slots.items, 0..) |slot, i| {
            if (i > 0) try buf.appendSlice(allocator, ", ");
            try buf.appendSlice(allocator, slot orelse "<null>");
        }
        return buf.toOwnedSlice(allocator);
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
    /// The ANF carries a `__merge$` block in a branch arm but the `if` node
    /// declares no results — the pre-multi-result wire format. `--ir` /
    /// `--ir-parity` are documented surfaces and ANF has no version field, so a
    /// stored ANF from before the node landed deserialises cleanly and the
    /// result count silently falls back to counting the arm's untrimmed block
    /// residue. Refused rather than miscompiled.
    StaleMergedLocalAnf,
    /// The `if` node declares the same result name twice. Result slots are
    /// matched by name, so duplicates cannot be told apart and one value would
    /// silently replace the other while the layout assertion passes by
    /// coincidence.
    DuplicateDeclaredResults,
    VariableNotFound,
    InvalidBuiltin,
    UnsupportedOperation,
    BranchStackMismatch,
    /// A ref (method param or @ref: value) is no longer on the stack at a
    /// point that needs it — a compiler invariant violation historically
    /// caused by unrolled loops consuming outer-scope refs (see lowerForLoop).
    /// Emitting a silent OP_0 here produced scripts that compiled, passed the
    /// env-based interpreter, and then failed on chain — so we fail loudly.
    SilentOpZeroRefused,
    /// #119 tail (H1): a `load_prop` for a property that is neither on the
    /// stack, initialized, nor a constructor parameter has no deploy-time slot
    /// of its own. Coercing it onto slot 0 silently splices an UNRELATED
    /// constructor argument's placeholder into the locking script, so we fail
    /// loudly instead.
    LoadPropNoConstructorSlot,
    /// Layer C: after `lowerIf` returns, the parent stackMap must describe the
    /// physical stack exactly. When it names FEWER slots than the arms left,
    /// every later operand resolves to the wrong slot — the signature of the
    /// whole 2026-08 branch/loop miscompile family. Silent until the UTXO is
    /// already locked, so we fail loudly at compile time instead.
    BranchResultDepthMismatch,
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
    /// Tracks the number of elements in array literal bindings so that
    /// consumers like checkMultiSig can emit the count push. Mirrors TS
    /// `arrayLengths` in `05-stack-lower.ts`.
    array_lengths: std.StringHashMapUnmanaged(usize),
    /// Tracks the element refs of array literal bindings so that consumers
    /// like checkMultiSig can bring each element to TOS at the use site.
    /// Mirrors TS `arrayElements` in `05-stack-lower.ts`.
    array_elements: std.StringHashMapUnmanaged([]const []const u8),
    owned_push_data: std.ArrayListUnmanaged([]u8),
    scope_bindings: []const types.ANFBinding,
    copy_ref_aliases: bool,
    current_idx: usize,
    in_branch: bool,
    /// Refs from the enclosing scope that must not be consumed inside branches
    /// (used by lowerIfExpr to protect outer values). Mirrors TS
    /// `outerProtectedRefs` — a pointer so it can be shared without copying.
    outer_protected_refs: ?*const std.StringHashMapUnmanaged(void) = null,
    updated_props: std.StringHashMapUnmanaged(void),
    max_depth: u32,
    /// Method params whose names collide with a MUTABLE property, mapped to the
    /// reserved stack-slot name their witness value lives under (issue #130).
    /// deserialize_state pushes each mutable property onto the stack under its
    /// own name, so a same-named param slot would otherwise be shadowed and
    /// lowerLoadParam would read the stale deserialized state. Empty for the
    /// common no-collision case (byte-identical output).
    renamed_params: std.StringHashMapUnmanaged([]const u8),
    /// Current ANF binding's source location — set before processing each binding.
    current_source_loc: ?types.SourceLocation = null,
    /// EXPERIMENTAL EC size options (constant pool, sign lattice / reduction
    /// sinking, fixed-base comb), handed down to the EC emitters. All-false —
    /// the default — makes them take their untouched path, so the emitted bytes
    /// are provably identical to the shipping ones.
    ec_opts: ec_emitters.EcCodegenOptions = .{},

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
            .array_lengths = .empty,
            .array_elements = .empty,
            .owned_push_data = .empty,
            .scope_bindings = &.{},
            .copy_ref_aliases = false,
            .current_idx = 0,
            .in_branch = false,
            .updated_props = .empty,
            .max_depth = 0,
            .renamed_params = .empty,
        };
    }

    fn deinit(self: *LowerCtx) void {
        self.instructions.deinit(self.allocator);
        self.instruction_source_locs.deinit(self.allocator);
        self.stack.deinit(self.allocator);
        self.last_uses.deinit(self.allocator);
        self.local_bindings.deinit(self.allocator);
        self.force_copy_bindings.deinit(self.allocator);
        self.array_lengths.deinit(self.allocator);
        // Free the element slice arrays (the inner []const u8 strings are
        // owned by the ANF program, not by us).
        var it_ae = self.array_elements.iterator();
        while (it_ae.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.array_elements.deinit(self.allocator);
        for (self.owned_push_data.items) |data| self.allocator.free(data);
        self.owned_push_data.deinit(self.allocator);
        self.updated_props.deinit(self.allocator);
        self.renamed_params.deinit(self.allocator);
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

    /// Emit a push for a decimal-string-encoded big integer (overflows `i64`).
    /// The decoder side handles converting the canonical decimal text into
    /// little-endian sign-magnitude bytes; see `encodeScriptNumberFromDecimal`.
    fn emitPushBigIntDecimal(self: *LowerCtx, decimal: []const u8) !void {
        try self.emit(.{ .push_big_int_decimal = decimal });
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
    /// pre-IF reconciliation (`05-stack-lower.ts` ~line 1640), which emits
    /// `push(depth) + roll(depth=depth) + drop`. TS's peephole folds
    /// `push(1)+roll(depth=1) → swap` and `push(2)+roll(depth=2) → rot`, so
    /// the byte output at depth 2 is `rot+drop` (2 bytes) instead of
    /// `push(2)+roll+drop` (3 bytes). Zig's peephole cannot distinguish
    /// foldable from non-foldable rolls at the instruction-stream level
    /// (unlike Go/TS which retain a depth field on typed RollOp), so we
    /// emit the folded form directly here.
    fn removeBranchValueAtDepth(ctx: *LowerCtx, depth: usize) !void {
        if (depth == 0) {
            try ctx.emitOp(.op_drop);
            _ = ctx.stack.pop();
            return;
        }

        if (depth == 1) {
            // push(1)+roll(1)+drop → swap+drop, and Zig's peephole folds
            // swap+drop → nip (or directly here).
            try ctx.emitOp(.op_nip);
            try ctx.stack.removeAtDepth(ctx.allocator, 1);
            return;
        }

        if (depth == 2) {
            // push(2)+roll(2)+drop → rot+drop (TS peephole fold).
            try ctx.emitOp(.op_rot);
            try ctx.stack.removeAtDepth(ctx.allocator, 2);
            try ctx.stack.push(ctx.allocator, null);
            try ctx.emitOp(.op_drop);
            _ = ctx.stack.pop();
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

    /// Consume-vs-copy decision for one operand of a multi-operand ANF value.
    ///
    /// `operands` is the FULL operand-ref list of the value (including `name`
    /// itself). The load may consume (ROLL / move) the ref only when this
    /// binding is the ref's last use AND the ref occurs exactly once in the
    /// operand list. A ref read at more than one operand position of the same
    /// value must be copied (PICK / DUP) at EVERY position: a consume-mode
    /// bringToTop of a ref already on top of the stack is a no-op, so two
    /// consume-mode loads of the same ref would leave a single slot for an
    /// opcode that pops one item per operand (e.g. `t := x + x` underflowing
    /// OP_ADD), or silently pair the opcode with the wrong slot. The original
    /// then stays on the stack and the existing method epilogue cleans it up.
    /// Unreachable from the frontend (every operand gets a fresh temp);
    /// reachable via compile-ir hand-written ANF.
    fn operandConsume(self: *const LowerCtx, name: []const u8, operands: []const []const u8) bool {
        if (!self.isLastUse(name)) return false;
        var occurrences: usize = 0;
        for (operands) |o| {
            if (std.mem.eql(u8, o, name)) occurrences += 1;
        }
        return occurrences <= 1;
    }

    /// bringToTop with the repeated-operand-aware consume decision.
    fn bringToTopOperand(self: *LowerCtx, name: []const u8, operands: []const []const u8) !void {
        try self.bringToTop(name, self.operandConsume(name, operands));
    }

    /// Drain branch-private residue from below TOS at the end of a branch
    /// body, so both branches converge to a layout the parent stack model can
    /// faithfully describe before OP_ENDIF (issue #36).
    ///
    /// A slot is residue when its name is NOT in `pre_if_names` (the snapshot
    /// of the parent's named slots taken before the branch ran). This catches
    /// both anonymous slots (null-named, pushed by intrinsics like substr's
    /// OP_SPLIT residue) and named branch-local bindings that lingered past
    /// their last-use (e.g. dead-code load_const intermediates the optimizer
    /// didn't fold). Slots whose name was already in `pre_if_names` are kept.
    /// Process deepest-first so removing a deeper slot doesn't shift a
    /// shallower slot's depth-from-top.
    fn drainBranchPrivateResidue(self: *LowerCtx, pre_if_names: *const std.StringHashMapUnmanaged(void)) !void {
        var drain_depths: std.ArrayListUnmanaged(usize) = .empty;
        defer drain_depths.deinit(self.allocator);
        var d: usize = 1;
        while (d < self.stack.depth()) : (d += 1) {
            const slot = self.stack.peekAtDepth(d);
            if (slot) |name| {
                if (!pre_if_names.contains(name)) {
                    try drain_depths.append(self.allocator, d);
                }
            } else {
                try drain_depths.append(self.allocator, d);
            }
        }
        if (drain_depths.items.len == 0) return;
        std.mem.sort(usize, drain_depths.items, {}, std.sort.desc(usize));
        for (drain_depths.items) |depth| {
            try removeBranchValueAtDepth(self, depth);
        }
    }

    // ========================================================================
    // Last-use analysis
    // ========================================================================

    fn computeLastUses(self: *LowerCtx, bindings: []const types.ANFBinding) !void {
        self.last_uses.clearRetainingCapacity();
        // Pre-scan: map each array_literal binding to its element refs. Used
        // to propagate last-use across the array indirection (the array
        // binding is pure metadata in lowerArrayLiteral — its elements must
        // remain live until the array's consumer, not until the array_literal
        // binding itself). Stored on the lowering context for scanValueForRefs.
        var array_elems = std.StringHashMapUnmanaged([]const []const u8){};
        defer array_elems.deinit(self.allocator);
        for (bindings) |binding| {
            switch (binding.value) {
                .array_literal => |al| {
                    try array_elems.put(self.allocator, binding.name, al.elements);
                },
                else => {},
            }
        }
        for (bindings, 0..) |binding, idx| {
            // array_literal is metadata-only — do NOT advance its elements'
            // last-use to here; defer to the array's consumer.
            switch (binding.value) {
                .array_literal => continue,
                else => {},
            }
            self.scanValueForRefs(binding.value, idx, &array_elems);
        }
    }

    fn putLastUseExpanding(
        self: *LowerCtx,
        name: []const u8,
        idx: usize,
        array_elems: *const std.StringHashMapUnmanaged([]const []const u8),
    ) void {
        self.last_uses.put(self.allocator, name, idx) catch return;
        if (array_elems.get(name)) |elems| {
            for (elems) |e| {
                self.last_uses.put(self.allocator, e, idx) catch return;
            }
        }
    }

    fn scanValueForRefs(
        self: *LowerCtx,
        value: types.ANFValue,
        idx: usize,
        array_elems: *const std.StringHashMapUnmanaged([]const []const u8),
    ) void {
        switch (value) {
            .load_param => |lp| {
                self.putLastUseExpanding(lp.name, idx, array_elems);
            },
            .load_prop, .get_state_script => {},
            .load_const => |lc| {
                switch (lc.value) {
                    .string => |s| {
                        if (std.mem.startsWith(u8, s, "@ref:")) {
                            self.putLastUseExpanding(s[5..], idx, array_elems);
                        }
                    },
                    else => {},
                }
            },
            .bin_op => |bop| {
                self.putLastUseExpanding(bop.left, idx, array_elems);
                self.putLastUseExpanding(bop.right, idx, array_elems);
            },
            .unary_op => |uop| {
                self.putLastUseExpanding(uop.operand, idx, array_elems);
            },
            .call => |c| {
                for (c.args) |arg| {
                    self.putLastUseExpanding(arg, idx, array_elems);
                }
            },
            .method_call => |mc| {
                if (mc.object.len > 0) {
                    self.putLastUseExpanding(mc.object, idx, array_elems);
                }
                for (mc.args) |arg| {
                    self.putLastUseExpanding(arg, idx, array_elems);
                }
            },
            .@"if" => |ie| {
                self.putLastUseExpanding(ie.cond, idx, array_elems);
                for (ie.then) |binding| {
                    self.scanValueForRefs(binding.value, idx, array_elems);
                }
                for (ie.@"else") |binding| {
                    self.scanValueForRefs(binding.value, idx, array_elems);
                }
            },
            .loop => |lp| {
                for (lp.body) |binding| {
                    self.scanValueForRefs(binding.value, idx, array_elems);
                }
            },
            .assert => |a| {
                self.putLastUseExpanding(a.value, idx, array_elems);
            },
            .update_prop => |up| {
                self.putLastUseExpanding(up.value, idx, array_elems);
            },
            .check_preimage => |cp| {
                self.putLastUseExpanding(cp.preimage, idx, array_elems);
            },
            .deserialize_state => |ds| {
                self.putLastUseExpanding(ds.preimage, idx, array_elems);
            },
            .add_output => |ao| {
                if (ao.satoshis.len > 0) {
                    self.putLastUseExpanding(ao.satoshis, idx, array_elems);
                }
                if (ao.preimage.len > 0) {
                    self.putLastUseExpanding(ao.preimage, idx, array_elems);
                }
                for (ao.state_values) |sv| {
                    if (sv.len > 0) {
                        self.putLastUseExpanding(sv, idx, array_elems);
                    }
                }
                for (ao.state_refs) |sr| {
                    if (sr.len > 0) {
                        self.putLastUseExpanding(sr, idx, array_elems);
                    }
                }
            },
            .add_raw_output => |aro| {
                if (aro.satoshis.len > 0) {
                    self.putLastUseExpanding(aro.satoshis, idx, array_elems);
                }
                if (aro.script_bytes.len > 0) {
                    self.putLastUseExpanding(aro.script_bytes, idx, array_elems);
                }
            },
            .add_data_output => |ado| {
                if (ado.satoshis.len > 0) {
                    self.putLastUseExpanding(ado.satoshis, idx, array_elems);
                }
                if (ado.script_bytes.len > 0) {
                    self.putLastUseExpanding(ado.script_bytes, idx, array_elems);
                }
            },
            .array_literal => {
                // array_literal is metadata-only — skip; computeLastUses
                // pre-screens these out so scanValueForRefs never receives a
                // top-level array_literal, and nested ones (if-branches etc.)
                // are similarly metadata-only.
            },
            .raw_script => {
                // Opaque byte span — no SSA operand refs. Stack effect is
                // declared via in_arity / out_arity and consumed by
                // lowerRawScript directly.
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

        // Protect parent-scope refs from consume inside this scope: extend
        // their last-use index past the end of the bindings, mirroring TS
        // `outerProtectedRefs` handling in `lowerBindings`.
        if (self.outer_protected_refs) |protected| {
            var it = protected.iterator();
            while (it.next()) |entry| {
                try self.last_uses.put(self.allocator, entry.key_ptr.*, bindings.len);
            }
        }

        // Terminal-assert propagation mirrors TS reference compiler
        // (`05-stack-lower.ts` lines 819-832): if the last binding is an
        // `if`, mark it as the terminal-if point so its branches can
        // propagate `terminalAssert=true` to their last assert. Otherwise
        // scan backwards for the last plain assert.
        var terminal_assert_idx: ?usize = null;
        var terminal_if_idx: ?usize = null;
        if (terminal_assert and bindings.len > 0) {
            const last_idx = bindings.len - 1;
            switch (bindings[last_idx].value) {
                .@"if" => terminal_if_idx = last_idx,
                else => {
                    var i: usize = bindings.len;
                    while (i > 0) {
                        i -= 1;
                        switch (bindings[i].value) {
                            .assert => {
                                terminal_assert_idx = i;
                                break;
                            },
                            else => {},
                        }
                    }
                },
            }
        }

        for (bindings, 0..) |binding, idx| {
            self.current_idx = idx;
            self.current_source_loc = binding.source_loc;
            if (terminal_assert_idx != null and idx == terminal_assert_idx.?) {
                switch (binding.value) {
                    .assert => |a| try self.lowerAssertOp(binding.name, .{ .condition = a.value }, true),
                    else => try self.lowerBinding(binding),
                }
            } else if (terminal_if_idx != null and idx == terminal_if_idx.?) {
                switch (binding.value) {
                    .@"if" => |ie| {
                        const legacy = try self.allocator.create(types.ANFIfExpr);
                        defer self.allocator.destroy(legacy);
                        legacy.* = .{ .condition = ie.cond, .then_bindings = ie.then, .else_bindings = if (ie.@"else".len > 0) ie.@"else" else null, .results = ie.results };
                        try self.lowerIfExprTerminal(binding.name, legacy, true);
                    },
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
            .bin_op => |bop| return std.mem.eql(u8, bop.left, name) or std.mem.eql(u8, bop.right, name),
            .unary_op => |uop| return std.mem.eql(u8, uop.operand, name),
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
                return aro.script_bytes.len > 0 and std.mem.eql(u8, aro.script_bytes, name);
            },
            .add_data_output => |ado| {
                if (ado.satoshis.len > 0 and std.mem.eql(u8, ado.satoshis, name)) return true;
                return ado.script_bytes.len > 0 and std.mem.eql(u8, ado.script_bytes, name);
            },
            .array_literal => |al| {
                for (al.elements) |elem| {
                    if (std.mem.eql(u8, elem, name)) return true;
                }
                return false;
            },
            .@"if", .loop, .load_prop, .get_state_script => return false,
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
            .add_output => |ao| try self.lowerAddOutput(binding.name, ao),
            .add_raw_output => |aro| try self.lowerAddRawOutput(binding.name, aro),
            .add_data_output => |ado| {
                // Wire shape identical to add_raw_output; the ordering into
                // the continuation hash is handled during ANF lowering.
                try self.lowerAddRawOutput(binding.name, .{ .satoshis = ado.satoshis, .script_bytes = ado.script_bytes });
            },
            .get_state_script => try self.lowerGetStateScript(binding.name),
            .load_param => |lp| try self.lowerLoadParam(binding.name, lp.name),
            .load_prop => |lp| try self.lowerPropertyRead(binding.name, lp.name),
            .load_const => |lc| try self.lowerLoadConst(binding.name, lc.value),
            .unary_op => |uop| try self.lowerUnaryOp(binding.name, uop),
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
                defer self.allocator.destroy(legacy);
                legacy.* = .{ .condition = ie.cond, .then_bindings = ie.then, .else_bindings = if (ie.@"else".len > 0) ie.@"else" else null, .results = ie.results };
                try self.lowerIfExpr(binding.name, legacy);
            },
            .loop => |lp| {
                const legacy = try self.allocator.create(types.ANFForLoop);
                defer self.allocator.destroy(legacy);
                // Issue #121: carry start/step so the unroll pushes
                // `start + n*step` on iteration `n`.
                legacy.* = .{ .var_name = lp.iter_var, .start = lp.start, .step = lp.step, .count = lp.count, .body_bindings = lp.body };
                try self.lowerForLoop(binding.name, legacy);
            },
            .assert => |a| try self.lowerAssertOp(binding.name, .{ .condition = a.value }, false),
            .update_prop => |up| try self.lowerPropertyWrite(binding.name, .{ .name = up.name, .value_ref = up.value }),
            .check_preimage => |cp| try self.lowerCheckPreimage(binding.name, &.{cp.preimage}, cp.sighash_flag),
            .deserialize_state => |ds| try self.lowerDeserializeState(binding.name, &.{ds.preimage}),
            .array_literal => |al| try self.lowerArrayLiteral(binding.name, al.elements),
            .raw_script => |rs| try self.lowerRawScript(binding.name, rs.bytes, rs.in_arity, rs.out_arity),
        }
    }

    /// Lower a raw_script ANF node to a single opaque raw_bytes
    /// StackInstruction. The bytes pass through verbatim — the emit pass
    /// writes them as-is, and the peephole optimizer must not bridge across
    /// them. Stack-tracker bookkeeping consumes in_arity items and pushes
    /// out_arity items named after the binding so downstream PICK/ROLL/DROP
    /// refer to the correct logical slot.
    fn lowerRawScript(self: *LowerCtx, bind_name: []const u8, bytes_hex: []const u8, in_arity: i32, out_arity: i32) !void {
        if (in_arity < 0 or out_arity < 0) return LowerError.UnsupportedOperation;
        const in_n: usize = @intCast(in_arity);
        const out_n: usize = @intCast(out_arity);
        if (self.stack.depth() < in_n) return LowerError.UnsupportedOperation;

        if (bytes_hex.len % 2 != 0) return LowerError.UnsupportedOperation;
        const decoded = try self.allocator.alloc(u8, bytes_hex.len / 2);
        _ = std.fmt.hexToBytes(decoded, bytes_hex) catch {
            self.allocator.free(decoded);
            return LowerError.UnsupportedOperation;
        };
        // Track the buffer so it gets freed when the program is deinit'd.
        try self.owned_push_data.append(self.allocator, decoded);

        try self.emit(.{ .raw_bytes = .{ .bytes = decoded, .in_arity = in_arity, .out_arity = out_arity } });

        var i: usize = 0;
        while (i < in_n) : (i += 1) _ = self.stack.pop();

        if (out_n == 1) {
            try self.stack.push(self.allocator, bind_name);
        } else {
            var j: usize = 0;
            while (j < out_n) : (j += 1) {
                const slot = try std.fmt.allocPrint(self.allocator, "{s}.{d}", .{ bind_name, j });
                // The slot name is owned by the program lifetime alongside other
                // allocations — track via owned_push_data ([]u8) cast to []const u8
                // via append on slots list (StackMap stores []const u8 references).
                try self.owned_push_data.append(self.allocator, slot);
                try self.stack.push(self.allocator, slot);
            }
        }
        self.trackDepth();
    }

    /// Metadata-only. Array literals in Rúnar today only feed into
    /// `checkMultiSig`. Pre-laying the elements onto the runtime stack here
    /// would desync the stack-map from the runtime stack (the map can only
    /// model one slot per binding, but an array binding spans N runtime
    /// slots). `lowerCheckMultiSig` pulls each element to TOS at the use site.
    /// Mirrors TS `lowerArrayLiteral` in `05-stack-lower.ts`.
    fn lowerArrayLiteral(self: *LowerCtx, bind_name: []const u8, elements: []const []const u8) !void {
        try self.array_lengths.put(self.allocator, bind_name, elements.len);
        // Duplicate the slice so it survives even if the source ANF buffer
        // is freed (it's owned by the program, but defensive copying keeps
        // the lifetime contract local).
        const copy = try self.allocator.alloc([]const u8, elements.len);
        @memcpy(copy, elements);
        try self.array_elements.put(self.allocator, bind_name, copy);
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
        // The parameter is already on the stack under its original name — or, for
        // a param that shadows a mutable property, under a reserved renamed slot
        // (issue #130) so it is not confused with the deserialized property slot.
        const slot_name = self.renamed_params.get(param_name) orelse param_name;
        if (self.stack.findDepth(slot_name) != null) {
            const consume = self.isLastUse(param_name);
            try self.bringToTop(slot_name, consume);
            try self.stack.renameAtDepth(self.allocator, 0, bind_name);
            return;
        }

        // Parameter no longer on the stack — a compiler invariant violation
        // (historically caused by unrolled loops consuming outer refs; see
        // lowerForLoop). Silently emitting OP_0 here produced scripts that
        // compiled, passed the env-based interpreter, and then failed on
        // chain — fail loudly instead.
        const slots_str = self.stack.debugSlots(self.allocator) catch null;
        defer if (slots_str) |s| self.allocator.free(s);
        std.log.warn(
            "stack lowering: method parameter '{s}' is not on the stack at a " ++
                "post-consumption reference (stack: [{s}]). Refusing to emit a " ++
                "silent OP_0 placeholder.",
            .{ param_name, slots_str orelse "<unavailable>" },
        );
        return LowerError.SilentOpZeroRefused;
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
            const consume = self.operandConsume(arg, args);
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

        // Match TS reference compiler: `inlineMethodCall` calls
        // `this.lowerBindings(method.body)`, which overwrites
        // `this.localBindings` with the inlined method's body binding names.
        // TS does NOT restore the caller's localBindings afterwards — this
        // "bug" is load-bearing: subsequent `@ref:<caller_binding>` lookups
        // after the inlining miss the caller's scope and fall back to
        // `consume=false` (PICK/DUP), keeping values alive. Zig previously
        // restored local_bindings which caused divergent byte output.
        //
        // last_uses IS restored because in TS `lastUses` is a local variable
        // inside each `lowerBindings` call, so the caller's analysis survives.
        const saved_last_uses = self.last_uses;
        var saved_force_copy_bindings = self.force_copy_bindings;
        const saved_copy_ref_aliases = self.copy_ref_aliases;
        defer {
            self.force_copy_bindings.deinit(self.allocator);
            self.force_copy_bindings = saved_force_copy_bindings;
            self.last_uses.deinit(self.allocator);
            self.last_uses = saved_last_uses;
            self.copy_ref_aliases = saved_copy_ref_aliases;
        }

        self.last_uses = .empty;
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
                            .call, .method_call => true,
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
            .big_integer => |s| try self.emitPushBigIntDecimal(s),
            .string => |s| {
                if (std.mem.startsWith(u8, s, "@ref:")) {
                    const ref_name = s[5..];
                    // Special case: if the referenced binding is an
                    // array_literal (metadata-only — no physical stack slot),
                    // alias the array metadata into the new binding name and
                    // emit nothing. The downstream checkMultiSig consumer will
                    // read elements via array_elements.
                    if (self.array_elements.get(ref_name)) |elems| {
                        const copy = try self.allocator.alloc([]const u8, elems.len);
                        @memcpy(copy, elems);
                        try self.array_elements.put(self.allocator, bind_name, copy);
                        if (self.array_lengths.get(ref_name)) |len| {
                            try self.array_lengths.put(self.allocator, bind_name, len);
                        }
                        return;
                    }
                    // Referenced value no longer on the stack — a compiler
                    // invariant violation (see lowerForLoop for the loop-
                    // consumption history). Fail loudly instead of relying on a
                    // silent OP_0 placeholder / an opaque VariableNotFound.
                    if (self.stack.findDepth(ref_name) == null) {
                        const slots_str = self.stack.debugSlots(self.allocator) catch null;
                        defer if (slots_str) |dbg| self.allocator.free(dbg);
                        std.log.warn(
                            "stack lowering: value '{s}' referenced by '{s}' is not on " ++
                                "the stack (stack: [{s}]). Refusing to emit a silent OP_0 " ++
                                "placeholder.",
                            .{ ref_name, bind_name, slots_str orelse "<unavailable>" },
                        );
                        return LowerError.SilentOpZeroRefused;
                    }
                    // Match TS reference compiler: consume only if ref target is
                    // a local binding in the current scope and this is the last
                    // use. No force-copy tracking — TS does not have it.
                    const consume = !self.copy_ref_aliases and self.hasLocalBinding(ref_name) and self.isLastUse(ref_name);
                    try self.bringToTop(ref_name, consume);
                    try self.stack.renameAtDepth(self.allocator, 0, bind_name);
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

    /// Comma-separated names of the constructor-param properties (those with no
    /// initial value, i.e. the ones that occupy a deploy-time slot). Used only
    /// for the H1 diagnostic in `lowerPropertyRead`.
    fn knownCtorPropNames(self: *const LowerCtx) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(self.allocator);
        var first = true;
        for (self.program.properties) |prop| {
            if (prop.initial_value != null) continue;
            if (!first) try buf.appendSlice(self.allocator, ", ");
            first = false;
            try buf.appendSlice(self.allocator, prop.name);
        }
        return buf.toOwnedSlice(self.allocator);
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
                        .big_integer => |s| try self.emitPushBigIntDecimal(s),
                        .string => |s| try self.emitPushHexString(s),
                    }
                    try self.stack.push(self.allocator, bind_name);
                    self.trackDepth();
                    return;
                }
            }
        }
        // Not found on stack / initialized — push constructor param placeholder.
        // Determine param_index: count properties without initial_value before
        // this one. Zig signals "not a declared property" by never breaking, so
        // track it explicitly with `found`.
        var param_idx: u32 = 0;
        var found = false;
        for (self.program.properties) |prop| {
            if (std.mem.eql(u8, prop.name, prop_name)) {
                found = true;
                break;
            }
            if (prop.initial_value == null) param_idx += 1;
        }
        // #119 tail (H1): a property that reaches this fallback with no matching
        // constructor slot (found == false) has no deploy-time bytes of its own.
        // The previous behaviour left `param_idx` at the count of ctor-param
        // properties and emitted a placeholder for an UNRELATED constructor
        // argument — a silent-wrong-code path that splices the wrong value into
        // the locking script. Fail loudly instead. (A real constructor-param
        // property — readonly, or a mutable state field whose initial value is
        // spliced at deploy — is found and unaffected.)
        if (!found) {
            const known = self.knownCtorPropNames() catch null;
            defer if (known) |k| self.allocator.free(k);
            if (self.current_source_loc) |loc| {
                std.log.warn(
                    "stack lowering: property '{s}' at {s}:{d}:{d} is neither on " ++
                        "the stack, initialized, nor a constructor parameter, so it " ++
                        "has no deploy-time slot. Refusing to emit a placeholder for " ++
                        "an unrelated constructor argument (slot 0). Known " ++
                        "constructor-param properties: [{s}].",
                    .{ prop_name, loc.file, loc.line, loc.column, known orelse "<unavailable>" },
                );
            } else {
                std.log.warn(
                    "stack lowering: property '{s}' is neither on the stack, " ++
                        "initialized, nor a constructor parameter, so it has no " ++
                        "deploy-time slot. Refusing to emit a placeholder for an " ++
                        "unrelated constructor argument (slot 0). Known " ++
                        "constructor-param properties: [{s}].",
                    .{ prop_name, known orelse "<unavailable>" },
                );
            }
            return LowerError.LoadPropNoConstructorSlot;
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
        const bin_operands = [_][]const u8{ bop.left, bop.right };
        try self.bringToTopOperand(bop.left, &bin_operands);
        try self.bringToTopOperand(bop.right, &bin_operands);

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
        extractSigHashType,
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
        // NIST P-256
        verifyECDSA_P256,
        p256Add,
        p256Mul,
        p256MulGen,
        p256Negate,
        p256OnCurve,
        p256EncodeCompressed,
        // NIST P-384
        verifyECDSA_P384,
        p384Add,
        p384Mul,
        p384MulGen,
        p384Negate,
        p384OnCurve,
        p384EncodeCompressed,
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
        // KoalaBear field arithmetic
        kbFieldAdd,
        kbFieldSub,
        kbFieldMul,
        kbFieldInv,
        // KoalaBear quartic extension field arithmetic
        kbExt4Mul0,
        kbExt4Mul1,
        kbExt4Mul2,
        kbExt4Mul3,
        kbExt4Inv0,
        kbExt4Inv1,
        kbExt4Inv2,
        kbExt4Inv3,
        // BN254 field arithmetic
        bn254FieldAdd,
        bn254FieldSub,
        bn254FieldMul,
        bn254FieldInv,
        bn254FieldNeg,
        // BN254 G1 point operations
        bn254G1Add,
        bn254G1ScalarMul,
        bn254G1Negate,
        bn254G1OnCurve,
        // Poseidon2 KoalaBear Merkle
        poseidon2MerkleRoot,
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
        .{ "extractSigHashType", .extractSigHashType },
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
        .{ "kbFieldAdd", .kbFieldAdd },
        .{ "kbFieldSub", .kbFieldSub },
        .{ "kbFieldMul", .kbFieldMul },
        .{ "kbFieldInv", .kbFieldInv },
        .{ "kbExt4Mul0", .kbExt4Mul0 },
        .{ "kbExt4Mul1", .kbExt4Mul1 },
        .{ "kbExt4Mul2", .kbExt4Mul2 },
        .{ "kbExt4Mul3", .kbExt4Mul3 },
        .{ "kbExt4Inv0", .kbExt4Inv0 },
        .{ "kbExt4Inv1", .kbExt4Inv1 },
        .{ "kbExt4Inv2", .kbExt4Inv2 },
        .{ "kbExt4Inv3", .kbExt4Inv3 },
        .{ "bn254FieldAdd", .bn254FieldAdd },
        .{ "bn254FieldSub", .bn254FieldSub },
        .{ "bn254FieldMul", .bn254FieldMul },
        .{ "bn254FieldInv", .bn254FieldInv },
        .{ "bn254FieldNeg", .bn254FieldNeg },
        .{ "bn254G1Add", .bn254G1Add },
        .{ "bn254G1ScalarMul", .bn254G1ScalarMul },
        .{ "bn254G1Negate", .bn254G1Negate },
        .{ "bn254G1OnCurve", .bn254G1OnCurve },
        .{ "poseidon2MerkleRoot", .poseidon2MerkleRoot },
        .{ "merkleRootSha256", .merkleRootSha256 },
        .{ "merkleRootHash256", .merkleRootHash256 },
        .{ "super", .super_call },
        // NIST P-256
        .{ "verifyECDSA_P256", .verifyECDSA_P256 },
        .{ "p256Add", .p256Add },
        .{ "p256Mul", .p256Mul },
        .{ "p256MulGen", .p256MulGen },
        .{ "p256Negate", .p256Negate },
        .{ "p256OnCurve", .p256OnCurve },
        .{ "p256EncodeCompressed", .p256EncodeCompressed },
        // NIST P-384
        .{ "verifyECDSA_P384", .verifyECDSA_P384 },
        .{ "p384Add", .p384Add },
        .{ "p384Mul", .p384Mul },
        .{ "p384MulGen", .p384MulGen },
        .{ "p384Negate", .p384Negate },
        .{ "p384OnCurve", .p384OnCurve },
        .{ "p384EncodeCompressed", .p384EncodeCompressed },
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
            // Builtin-call dispatch path: reached only for a `call` node named
            // checkPreimage, which anf_lower never emits (it lowers manual
            // checkPreimage() into a dedicated check_preimage node carrying the
            // sighash flag). Default flag (0 = ALL|FORKID) is correct here.
            .checkPreimage => try self.lowerCheckPreimage(bind_name, args, 0),
            .deserializeState => try self.lowerDeserializeState(bind_name, args),
            .extractHashPrevouts, .extractLocktime, .extractOutpoint, .extractOutputHash, .extractSigHashType => try self.lowerExtractor(bind_name, id, args),
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
            // KoalaBear field arithmetic
            .kbFieldAdd => try self.lowerKBBuiltin(bind_name, args, .kb_field_add),
            .kbFieldSub => try self.lowerKBBuiltin(bind_name, args, .kb_field_sub),
            .kbFieldMul => try self.lowerKBBuiltin(bind_name, args, .kb_field_mul),
            .kbFieldInv => try self.lowerKBBuiltin(bind_name, args, .kb_field_inv),
            // KoalaBear quartic extension field arithmetic
            .kbExt4Mul0 => try self.lowerKBBuiltin(bind_name, args, .kb_ext4_mul0),
            .kbExt4Mul1 => try self.lowerKBBuiltin(bind_name, args, .kb_ext4_mul1),
            .kbExt4Mul2 => try self.lowerKBBuiltin(bind_name, args, .kb_ext4_mul2),
            .kbExt4Mul3 => try self.lowerKBBuiltin(bind_name, args, .kb_ext4_mul3),
            .kbExt4Inv0 => try self.lowerKBBuiltin(bind_name, args, .kb_ext4_inv0),
            .kbExt4Inv1 => try self.lowerKBBuiltin(bind_name, args, .kb_ext4_inv1),
            .kbExt4Inv2 => try self.lowerKBBuiltin(bind_name, args, .kb_ext4_inv2),
            .kbExt4Inv3 => try self.lowerKBBuiltin(bind_name, args, .kb_ext4_inv3),
            // BN254 field arithmetic
            .bn254FieldAdd => try self.lowerBN254Builtin(bind_name, args, .bn254_field_add),
            .bn254FieldSub => try self.lowerBN254Builtin(bind_name, args, .bn254_field_sub),
            .bn254FieldMul => try self.lowerBN254Builtin(bind_name, args, .bn254_field_mul),
            .bn254FieldInv => try self.lowerBN254Builtin(bind_name, args, .bn254_field_inv),
            .bn254FieldNeg => try self.lowerBN254Builtin(bind_name, args, .bn254_field_neg),
            // BN254 G1 point operations
            .bn254G1Add => try self.lowerBN254Builtin(bind_name, args, .bn254_g1_add),
            .bn254G1ScalarMul => try self.lowerBN254Builtin(bind_name, args, .bn254_g1_scalar_mul),
            .bn254G1Negate => try self.lowerBN254Builtin(bind_name, args, .bn254_g1_negate),
            .bn254G1OnCurve => try self.lowerBN254Builtin(bind_name, args, .bn254_g1_on_curve),
            // Poseidon2 KoalaBear Merkle
            .poseidon2MerkleRoot => try self.lowerPoseidon2MerkleBuiltin(bind_name, args),
            // Merkle proof verification
            .merkleRootSha256 => try self.lowerMerkleBuiltin(bind_name, args, call.name, .merkle_root_sha256),
            .merkleRootHash256 => try self.lowerMerkleBuiltin(bind_name, args, call.name, .merkle_root_hash256),
            // NIST P-256
            .verifyECDSA_P256 => try self.lowerNistEcBuiltin(bind_name, args, .verify_ecdsa_p256),
            .p256Add => try self.lowerNistEcBuiltin(bind_name, args, .p256_add),
            .p256Mul => try self.lowerNistEcBuiltin(bind_name, args, .p256_mul),
            .p256MulGen => try self.lowerNistEcBuiltin(bind_name, args, .p256_mul_gen),
            .p256Negate => try self.lowerNistEcBuiltin(bind_name, args, .p256_negate),
            .p256OnCurve => try self.lowerNistEcBuiltin(bind_name, args, .p256_on_curve),
            .p256EncodeCompressed => try self.lowerNistEcBuiltin(bind_name, args, .p256_encode_compressed),
            // NIST P-384
            .verifyECDSA_P384 => try self.lowerNistEcBuiltin(bind_name, args, .verify_ecdsa_p384),
            .p384Add => try self.lowerNistEcBuiltin(bind_name, args, .p384_add),
            .p384Mul => try self.lowerNistEcBuiltin(bind_name, args, .p384_mul),
            .p384MulGen => try self.lowerNistEcBuiltin(bind_name, args, .p384_mul_gen),
            .p384Negate => try self.lowerNistEcBuiltin(bind_name, args, .p384_negate),
            .p384OnCurve => try self.lowerNistEcBuiltin(bind_name, args, .p384_on_curve),
            .p384EncodeCompressed => try self.lowerNistEcBuiltin(bind_name, args, .p384_encode_compressed),
            // super() is the constructor superclass call — no-op in Bitcoin Script
            .super_call => {
                try self.stack.push(self.allocator, bind_name);
                self.trackDepth();
            },
            // Wave 3 placeholders — consume args and push placeholder
            .ecPairing, .schnorrVerify => {
                for (args) |arg| {
                    try self.bringToTopOperand(arg, args);
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
            try self.bringToTopOperand(arg, args);
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
            try self.bringToTopOperand(arg, args);
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
            try self.bringToTopOperand(arg, args);
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
            try self.bringToTopOperand(arg, args);
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
            try self.bringToTopOperand(arg, args);
        }
        for (args) |_| {
            _ = self.stack.pop();
        }

        var bundle = ec_emitters.buildBuiltinOpsOpts(self.allocator, builtin, self.ec_opts) catch |err| switch (err) {
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

    fn lowerNistEcBuiltin(self: *LowerCtx, bind_name: []const u8, args: []const []const u8, builtin: crypto_builtins.CryptoBuiltin) LowerError!void {
        if (args.len < crypto_builtins.requiredArgCount(builtin)) return LowerError.InvalidBuiltin;

        for (args) |arg| {
            try self.bringToTopOperand(arg, args);
        }
        for (args) |_| {
            _ = self.stack.pop();
        }

        var bundle = nist_ec_emitters.buildBuiltinOpsOpts(self.allocator, builtin, self.ec_opts) catch |err| switch (err) {
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

    fn lowerBBBuiltin(self: *LowerCtx, bind_name: []const u8, args: []const []const u8, builtin: babybear_emitters.BBBuiltin) LowerError!void {
        const required: usize = switch (builtin) {
            .bb_field_add, .bb_field_sub, .bb_field_mul => 2,
            .bb_field_inv => 1,
            .bb_ext4_mul0, .bb_ext4_mul1, .bb_ext4_mul2, .bb_ext4_mul3 => 8,
            .bb_ext4_inv0, .bb_ext4_inv1, .bb_ext4_inv2, .bb_ext4_inv3 => 4,
        };
        if (args.len < required) return LowerError.InvalidBuiltin;

        for (args) |arg| {
            try self.bringToTopOperand(arg, args);
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

    fn lowerKBBuiltin(self: *LowerCtx, bind_name: []const u8, args: []const []const u8, builtin: koalabear_emitters.KBBuiltin) LowerError!void {
        const required: usize = switch (builtin) {
            .kb_field_add, .kb_field_sub, .kb_field_mul => 2,
            .kb_field_inv => 1,
            .kb_ext4_mul0, .kb_ext4_mul1, .kb_ext4_mul2, .kb_ext4_mul3 => 8,
            .kb_ext4_inv0, .kb_ext4_inv1, .kb_ext4_inv2, .kb_ext4_inv3 => 4,
        };
        if (args.len < required) return LowerError.InvalidBuiltin;

        for (args) |arg| {
            try self.bringToTopOperand(arg, args);
        }
        for (args) |_| {
            _ = self.stack.pop();
        }

        var bundle = koalabear_emitters.buildBuiltinOps(self.allocator, builtin) catch |err| switch (err) {
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

    fn lowerBN254Builtin(self: *LowerCtx, bind_name: []const u8, args: []const []const u8, builtin: bn254_emitters.BN254Builtin) LowerError!void {
        const required: usize = switch (builtin) {
            .bn254_field_add, .bn254_field_sub, .bn254_field_mul, .bn254_g1_add, .bn254_g1_scalar_mul => 2,
            .bn254_field_inv, .bn254_field_neg, .bn254_g1_negate, .bn254_g1_on_curve => 1,
        };
        if (args.len < required) return LowerError.InvalidBuiltin;

        for (args) |arg| {
            try self.bringToTopOperand(arg, args);
        }
        for (args) |_| {
            _ = self.stack.pop();
        }

        var bundle = bn254_emitters.buildBuiltinOps(self.allocator, builtin) catch |err| switch (err) {
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

    fn lowerPoseidon2MerkleBuiltin(
        self: *LowerCtx,
        bind_name: []const u8,
        args: []const []const u8,
    ) LowerError!void {
        // args: [leaf_0..leaf_7(8), proof(depth*8 elems), index, depth]
        // depth must be a compile-time constant
        // The depth arg is always last.
        if (args.len < 3) return LowerError.InvalidBuiltin;

        const depth_arg = args[args.len - 1];
        const depth_value = self.findConstantInt(depth_arg) orelse return LowerError.InvalidBuiltin;
        if (depth_value < 1 or depth_value > 32) return LowerError.InvalidBuiltin;

        // Remove depth from the real stack (compile-time constant, not runtime).
        if (self.stack.findDepth(depth_arg) != null) {
            try self.bringToTopAuto(depth_arg);
            try self.emitOp(.op_drop);
            _ = self.stack.pop();
        }

        // Bring remaining args to the stack top.
        const runtime_args = args[0 .. args.len - 1];
        for (runtime_args) |arg| {
            try self.bringToTopOperand(arg, args);
        }
        for (runtime_args) |_| {
            _ = self.stack.pop();
        }

        var bundle = poseidon2_merkle.buildPoseidon2MerkleRootOps(self.allocator, @intCast(depth_value)) catch |err| switch (err) {
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
            try self.bringToTopOperand(args[i], args);
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
        try self.bringToTopOperand(args[0], args);
        try self.bringToTopOperand(args[1], args);
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
        // Lower checkMultiSig([sig1..sigN], [pk1..pkM]) to Bitcoin Script.
        //
        // OP_CHECKMULTISIG expects the stack (bottom -> top):
        //   <dummy=OP_0> <sig1> ... <sigN> <N> <pk1> ... <pkM> <M>
        //
        // args[0] and args[1] are bindings produced by array_literal. Those
        // bindings are NOT physical stack slots — their element refs live on
        // the stack-map as individual named bindings. We pull each element to
        // TOS via bringToTop. computeLastUses propagates each element's
        // last-use through the array indirection to THIS binding. Mirrors
        // TS `lowerCheckMultiSig` in `05-stack-lower.ts`.
        if (args.len != 2) return LowerError.InvalidBuiltin;

        const sigs_ref = args[0];
        const pks_ref = args[1];
        const sig_elems = self.array_elements.get(sigs_ref) orelse return LowerError.InvalidBuiltin;
        const pk_elems = self.array_elements.get(pks_ref) orelse return LowerError.InvalidBuiltin;

        // Dummy OP_0 (historical CHECKMULTISIG off-by-one).
        try self.emitPushInt(0);
        try self.stack.push(self.allocator, null);

        // A ref repeated across the combined element list (e.g. the same
        // pubkey twice) must be copied at every position — see operandConsume.
        const msig_operands = try std.mem.concat(self.allocator, []const u8, &.{ sig_elems, pk_elems });
        defer self.allocator.free(msig_operands);

        // Bring each sig element to TOS in declaration order.
        for (sig_elems) |sig| {
            const consume = self.operandConsume(sig, msig_operands);
            try self.bringToTop(sig, consume);
        }

        // Push nSigs.
        try self.emitPushInt(@intCast(sig_elems.len));
        try self.stack.push(self.allocator, null);

        // Bring each pubkey element to TOS in declaration order.
        for (pk_elems) |pk| {
            const consume = self.operandConsume(pk, msig_operands);
            try self.bringToTop(pk, consume);
        }

        // Push nPKs.
        try self.emitPushInt(@intCast(pk_elems.len));
        try self.stack.push(self.allocator, null);

        // OP_CHECKMULTISIG consumes: dummy + N sigs + nSigs + M pks + nPKs.
        const consumed = 1 + sig_elems.len + 1 + pk_elems.len + 1;
        for (0..consumed) |_| {
            _ = self.stack.pop();
        }

        try self.emitOp(.op_checkmultisig);
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
        try self.bringToTopOperand(args[0], args);
        try self.bringToTopOperand(args[1], args);
        try self.bringToTopOperand(args[2], args);
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
        try self.bringToTopOperand(args[0], args); // data
        try self.bringToTopOperand(args[1], args); // position
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
        try self.bringToTopOperand(args[0], args); // data
        try self.bringToTopOperand(args[1], args); // length
        try self.emitOp(.op_split);
        try self.emitOp(.op_drop); // drop right, keep left
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerSubstr(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 3) return LowerError.InvalidBuiltin;
        try self.bringToTopOperand(args[0], args); // s
        try self.bringToTopOperand(args[1], args); // start
        try self.emitOp(.op_split);
        try self.emitOp(.op_nip); // drop left, keep right
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        self.trackDepth();

        try self.bringToTopOperand(args[2], args); // length
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
        try self.bringToTopOperand(args[0], args);
        try self.bringToTopOperand(args[1], args);
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
        try self.bringToTopOperand(args[0], args);
        try self.bringToTopOperand(args[1], args);
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
        try self.bringToTopOperand(args[0], args);
        try self.bringToTopOperand(args[1], args);
        try self.emitOp(.op_mul);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        self.trackDepth();
        try self.bringToTopOperand(args[2], args);
        try self.emitOp(.op_div);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, bind_name);
        self.trackDepth();
    }

    fn lowerPercentOf(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 2) return LowerError.InvalidBuiltin;
        try self.bringToTopOperand(args[0], args);
        try self.bringToTopOperand(args[1], args);
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
        try self.bringToTopOperand(args[0], args);
        try self.bringToTopOperand(args[1], args);
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
        // divmod(a, b): returns the quotient (drops the remainder).
        // Mirrors TS / Go / Java / Rust / Python / Ruby:
        //   OP_2DUP  -> a b a b
        //   OP_DIV   -> a b (a/b)
        //   OP_ROT   -> b (a/b) a
        //   OP_ROT   -> (a/b) a b
        //   OP_MOD   -> (a/b) (a%b)
        //   OP_DROP  -> (a/b)
        // The previous Zig implementation used OP_OVER OP_OVER OP_MOD
        // OP_ROT OP_ROT OP_DIV which produced the quotient on top but a
        // different intermediate stack shape, breaking byte-level parity
        // with the other 6 tiers (caught by the math-demo conformance
        // fixture once the divmod method was added).
        if (args.len < 2) return LowerError.InvalidBuiltin;
        // divmod(a, b): returns the quotient (drops the remainder).
        // Mirrors TS / Go / Java / Rust / Python / Ruby:
        //   OP_2DUP  -> a b a b
        //   OP_DIV   -> a b (a/b)
        //   OP_ROT   -> b (a/b) a
        //   OP_ROT   -> (a/b) a b
        //   OP_MOD   -> (a/b) (a%b)
        //   OP_DROP  -> (a/b)
        // The previous Zig implementation used OP_OVER OP_OVER OP_MOD
        // OP_ROT OP_ROT OP_DIV which produced the quotient on top but a
        // different intermediate stack shape, breaking byte-level parity
        // with the other 6 tiers (caught by the math-demo conformance
        // fixture once the divmod method was added).
        try self.bringToTopOperand(args[0], args);
        try self.bringToTopOperand(args[1], args);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.emitOp(.op_2dup);
        try self.emitOp(.op_div);
        try self.emitOp(.op_rot);
        try self.emitOp(.op_rot);
        try self.emitOp(.op_mod);
        try self.emitOp(.op_drop);
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
        try self.bringToTopOperand(args[0], args);
        try self.bringToTopOperand(args[1], args);
        try self.emitOp(.op_max);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        self.trackDepth();
        try self.bringToTopOperand(args[2], args);
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

    fn lowerCheckPreimage(self: *LowerCtx, bind_name: []const u8, args: []const []const u8, sighash_flag: i32) !void {
        if (args.len < 1) return LowerError.InvalidBuiltin;
        // OP_PUSH_TX: verify the pushed BIP-143 sighash preimage is bound to the
        // current spending transaction. The signature is DERIVED FROM THE PREIMAGE
        // ON CHAIN (Optimal OP_PUSH_TX): s = (hash256(preimage) + r)*k⁻¹ mod n, with
        // fixed nonce k and privkey d=1 (pubkey = G). OP_CHECKSIG(sig, G) then passes
        // iff hash256(preimage) equals the node's real tx sighash — closing BUG-100.
        // The unlocking script pushes ONLY <preimage> (no witness signature).
        // See emitCheckPreimageBinding for the construction.

        // Emit OP_CODESEPARATOR so the scriptCode in the BIP-143 preimage is only
        // the code after this point (smaller preimage; required for large scripts).
        try self.emitOp(.op_codeseparator);

        // Bring the preimage to the top (kept for field extractors below).
        try self.bringToTopAuto(args[0]);

        // Derive + verify the signature on-chain (single opaque raw_bytes blob).
        // For the default ALL|FORKID (sighash_flag 0/0x41) the blob is
        // byte-identical to the pinned cross-tier constant; issue #123 lets a
        // method declare a different mode, which only changes the appended
        // sighash flag byte. Net stack effect is zero.
        try self.emitCheckPreimageBinding(sighash_flag);

        // Preimage remains on top. Rename for field extractors.
        try self.stack.renameAtDepth(self.allocator, 0, bind_name);
        self.trackDepth();
    }

    /// Emit the on-chain preimage binding (BUG-100 fix) as one opaque raw_bytes
    /// op. Net stack effect is 0 (preimage in → preimage out), declared as
    /// in=1/out=1 so the static analyzer keeps the depth consistent and the
    /// peephole optimizer treats it as a hard barrier. The construction is the
    /// canonical output of the TypeScript reference, byte-identical across all
    /// seven tiers (guarded by the cross-tier conformance suite).
    fn emitCheckPreimageBinding(self: *LowerCtx, sighash_flag: i32) !void {
        // The frozen binding hex pushes SIGHASH_ALL|FORKID (0x41) as the DER
        // signature's appended sighash byte via the single `0141` push
        // immediately before the fixed G-pubkey tail. Issue #123 lets a method
        // declare a different mode, which only changes that one appended flag
        // byte — byte-for-byte matching the TS reference's
        // emitCheckPreimageBinding(flag). All valid (FORKID-required) sighash
        // flags (0x41/0x42/0x43/0xc1/0xc2/0xc3) minimal-push as OP_DATA_1 + flag.
        var flag: i32 = sighash_flag;
        if (flag == 0) flag = 0x41;

        var owned_hex: ?[]u8 = null;
        defer if (owned_hex) |h| self.allocator.free(h);
        const hex: []const u8 = if (flag == 0x41) check_preimage_binding_hex else blk: {
            const suffix = "0141" ++ check_preimage_sighash_tail;
            if (!std.mem.endsWith(u8, check_preimage_binding_hex, suffix)) {
                return LowerError.UnsupportedOperation;
            }
            const prefix = check_preimage_binding_hex[0 .. check_preimage_binding_hex.len - suffix.len];
            const new_hex = try std.fmt.allocPrint(self.allocator, "{s}01{x:0>2}{s}", .{
                prefix,
                @as(u8, @intCast(flag & 0xff)),
                check_preimage_sighash_tail,
            });
            owned_hex = new_hex;
            break :blk new_hex;
        };

        const decoded = try self.allocator.alloc(u8, hex.len / 2);
        _ = std.fmt.hexToBytes(decoded, hex) catch {
            self.allocator.free(decoded);
            return LowerError.UnsupportedOperation;
        };
        // Track the buffer so it gets freed when the program is deinit'd.
        try self.owned_push_data.append(self.allocator, decoded);
        try self.emit(.{ .raw_bytes = .{ .bytes = decoded, .in_arity = 1, .out_arity = 1 } });
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
            // Variable-length path: strip varint, use _codePart to find state.
            //
            // BIP-143 scriptCode is prefixed by a Bitcoin varint:
            //   length < 0xfd:        1 byte (length itself)
            //   length <= 0xffff:     0xfd + 2 bytes LE                (3 bytes)
            //   length <= 0xffffffff: 0xfe + 4 bytes LE                (5 bytes)
            //   otherwise:            0xff + 8 bytes LE                (9 bytes)
            //
            // We must support all four shapes, otherwise scripts whose
            // scriptCode exceeds 65,535 bytes (e.g. embedded BN254 verifiers)
            // silently strip too few varint bytes and corrupt the subsequent
            // state-extraction OP_SPLITs.

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
            // Zero-pad firstByte before BIN2NUM so 0xfd/0xfe/0xff aren't read
            // as negative script numbers.
            try self.emitPushData(&.{0x00});
            try self.stack.push(self.allocator, null);
            // CAT -> [..., rest, firstByte||0x00]
            try self.emitOp(.op_cat);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null);
            // BIN2NUM -> [..., rest, fb_num]
            try self.emitOp(.op_bin2num);

            // IF fb_num < 253: 1-byte varint, drop fb_num.
            try self.emitOp(.op_dup);
            try self.stack.push(self.allocator, self.stack.peekAtDepth(0));
            try self.emitPushInt(253);
            try self.stack.push(self.allocator, null);
            try self.emitOp(.op_lessthan);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null);
            try self.emitOp(.op_if);
            _ = self.stack.pop();
            var sm_at_1byte_if = try self.stack.clone(self.allocator);
            // THEN: 1-byte varint
            try self.emitOp(.op_drop);
            _ = self.stack.pop();
            try self.emitOp(.op_else);
            self.stack.deinit(self.allocator);
            self.stack = sm_at_1byte_if;
            sm_at_1byte_if = .{};

            // ELSE: fb_num >= 253. Check 0xfe (5-byte varint) next.
            try self.emitOp(.op_dup);
            try self.stack.push(self.allocator, self.stack.peekAtDepth(0));
            try self.emitPushInt(254);
            try self.stack.push(self.allocator, null);
            try self.emitOp(.op_numequal);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null);
            try self.emitOp(.op_if);
            _ = self.stack.pop();
            var sm_at_fe_if = try self.stack.clone(self.allocator);
            // THEN: 5-byte varint (0xfe + 4 bytes LE).
            try self.emitOp(.op_drop);
            _ = self.stack.pop();
            try self.emitDropMoreVarintBytes(4);
            try self.emitOp(.op_else);
            self.stack.deinit(self.allocator);
            self.stack = sm_at_fe_if;
            sm_at_fe_if = .{};

            // ELSE: fb_num != 254. Check 0xff (9-byte varint) next.
            try self.emitOp(.op_dup);
            try self.stack.push(self.allocator, self.stack.peekAtDepth(0));
            try self.emitPushInt(255);
            try self.stack.push(self.allocator, null);
            try self.emitOp(.op_numequal);
            _ = self.stack.pop();
            _ = self.stack.pop();
            try self.stack.push(self.allocator, null);
            try self.emitOp(.op_if);
            _ = self.stack.pop();
            var sm_at_ff_if = try self.stack.clone(self.allocator);
            // THEN: 9-byte varint (0xff + 8 bytes LE).
            try self.emitOp(.op_drop);
            _ = self.stack.pop();
            try self.emitDropMoreVarintBytes(8);
            try self.emitOp(.op_else);
            self.stack.deinit(self.allocator);
            self.stack = sm_at_ff_if;
            sm_at_ff_if = .{};

            // ELSE: fb_num must be 253 (0xfd) -- 3-byte varint.
            try self.emitOp(.op_drop);
            _ = self.stack.pop();
            try self.emitDropMoreVarintBytes(2);
            try self.emitOp(.op_endif);
            try self.emitOp(.op_endif);
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
        try self.bringToTopOperand(args[0], args);
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

        try self.bringToTopOperand(args[1], args);
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
                    .big_integer => |s| try self.emitPushBigIntDecimal(s),
                    .string => |s| try self.emitPushData(s),
                }
                try self.stack.push(self.allocator, null);
            } else {
                try self.emitPushInt(0);
                try self.stack.push(self.allocator, null);
            }

            if (isNumericStateType(prop.type_info)) {
                const width: i64 = if (prop.type_info == .boolean) 1 else 8;
                try self.emitPushInt(width);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_num2bin);
                _ = self.stack.pop();
                _ = self.stack.pop();
                try self.stack.push(self.allocator, null);
            } else if (isVariableLengthStateType(prop.type_info)) {
                // Prepend push-data length prefix (matching SDK format)
                try self.emitPushDataEncode();
            }
            // Fixed-width byte types (PubKey, Addr, Ripemd160, Sha256, Point,
            // P256Point, P384Point) are already byte sequences and used as-is.

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

    /// Returns true if the type is serialized as a fixed-size big-endian numeric
    /// value via OP_NUM2BIN (and deserialized via OP_BIN2NUM). Covers bigint,
    /// boolean and the Rabin primitives (treated as 8-byte scalars on the wire).
    fn isNumericStateType(t: types.RunarType) bool {
        return switch (t) {
            .bigint, .boolean, .rabin_sig, .rabin_pub_key => true,
            else => false,
        };
    }

    /// Returns true if the type has no fixed wire length and must be serialized
    /// with a push-data length prefix (ByteString, Sig, SigHashPreimage).
    fn isVariableLengthStateType(t: types.RunarType) bool {
        return switch (t) {
            .byte_string, .sig, .sig_hash_preimage => true,
            else => false,
        };
    }

    /// Size in bytes of a state property on the wire, or -1 for variable-length
    /// fields that carry a push-data length prefix.
    ///
    /// Covers all 14 validator-permitted property types. Keep in sync with
    /// lowerGetStateScript, splitFixedStateFields, parseVariableLengthStateFields,
    /// and lowerAddOutput — all of which dispatch on the same type set.
    fn statePropSize(prop: types.ANFProperty) LowerError!i64 {
        return switch (prop.type_info) {
            .bigint, .rabin_sig, .rabin_pub_key => 8,
            .boolean => 1,
            .addr, .ripemd160 => 20,
            .sha256 => 32,
            .pub_key => 33,
            .point, .p256_point => 64,
            .p384_point => 96,
            .byte_string, .sig, .sig_hash_preimage => -1,
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
            if (isNumericStateType(prop.type_info)) try self.emitOp(.op_bin2num);
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

                    if (isNumericStateType(prop.type_info)) try self.emitOp(.op_bin2num);

                    try self.emitOp(.op_swap);
                    const prop_value = self.stack.pop();
                    const remainder = self.stack.pop();
                    try self.stack.push(self.allocator, prop_value);
                    try self.stack.push(self.allocator, remainder);
                    try self.stack.renameAtDepth(self.allocator, 1, prop.name);
                } else {
                    if (isNumericStateType(prop.type_info)) try self.emitOp(.op_bin2num);
                    try self.stack.renameAtDepth(self.allocator, 0, prop.name);
                }
            }
        }
    }

    /// Parse state fields left-to-right, handling variable-length fields
    /// (ByteString, Sig, SigHashPreimage) that carry a push-data length prefix.
    fn parseVariableLengthStateFields(self: *LowerCtx, state_props: []const types.ANFProperty, prop_sizes: []const i64) !void {
        if (state_props.len == 1) {
            const prop = state_props[0];
            if (isVariableLengthStateType(prop.type_info)) {
                // Single variable-length field: decode push-data prefix, drop trailing empty
                try self.emitPushDataDecode(); // [..., data, remaining]
                try self.emitOp(.op_drop);
                _ = self.stack.pop();
            } else if (isNumericStateType(prop.type_info)) {
                try self.emitOp(.op_bin2num);
            }
            try self.stack.renameAtDepth(self.allocator, 0, prop.name);
        } else {
            for (state_props, 0..) |prop, i| {
                if (i < state_props.len - 1) {
                    if (isVariableLengthStateType(prop.type_info)) {
                        // Variable-length: decode push-data prefix, extract data
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
                        if (isNumericStateType(prop.type_info)) try self.emitOp(.op_bin2num);
                        try self.emitOp(.op_swap);
                        const prop_val = self.stack.pop();
                        const rest_val = self.stack.pop();
                        try self.stack.push(self.allocator, prop_val);
                        try self.stack.push(self.allocator, rest_val);
                        try self.stack.renameAtDepth(self.allocator, 1, prop.name);
                    }
                } else {
                    if (isVariableLengthStateType(prop.type_info)) {
                        // Last variable-length field: decode push-data prefix, drop trailing empty
                        try self.emitPushDataDecode(); // [..., data, remaining]
                        try self.emitOp(.op_drop);
                        _ = self.stack.pop();
                    } else if (isNumericStateType(prop.type_info)) {
                        try self.emitOp(.op_bin2num);
                    }
                    try self.stack.renameAtDepth(self.allocator, 0, prop.name);
                }
            }
        }
    }

    fn lowerComputeStateOutput(self: *LowerCtx, bind_name: []const u8, args: []const []const u8) !void {
        if (args.len < 3) return LowerError.InvalidBuiltin;

        try self.bringToTopOperand(args[0], args);
        try self.emitOp(.op_drop);
        _ = self.stack.pop();

        try self.bringToTopOperand(args[2], args);
        try self.emitPushInt(8);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_num2bin);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_toaltstack);
        _ = self.stack.pop();

        try self.bringToTopOperand(args[1], args);
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

        try self.bringToTopOperand(args[1], args);
        try self.bringToTopOperand(args[0], args);

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
            .extractSigHashType => {
                // End-relative: last 4 bytes -> number.
                // OP_SIZE 4 OP_SUB OP_SPLIT OP_NIP OP_BIN2NUM (matches TS
                // 05-stack-lower extractSigHashType).
                try self.emitOp(.op_size);
                try self.stack.push(self.allocator, null);
                try self.stack.push(self.allocator, null);
                try self.emitPushInt(4);
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

    // emitVarintEncoding encodes a script number length on top of the stack
    // as a Bitcoin varint byte sequence.
    //
    // Expects stack: [..., script, len]
    // Leaves stack:  [..., script, varint_bytes]
    //
    // Bitcoin varint format:
    //   len < 0xfd:        1 byte (len itself)
    //   len <= 0xffff:     0xfd + 2 bytes LE                (3 bytes)
    //   len <= 0xffffffff: 0xfe + 4 bytes LE                (5 bytes)
    //   otherwise:         0xff + 8 bytes LE                (9 bytes)
    //
    // We must support all four shapes; emitting a 3-byte varint for a script
    // whose length exceeds 0xffff produces a truncated value that no longer
    // matches what the BSV node uses for hashOutputs, breaking the
    // state-continuation hash equality assertion downstream.
    //
    // OP_NUM2BIN uses sign-magnitude encoding where high-bit values need an
    // extra sign byte; we generate one extra byte and then SPLIT off the
    // unsigned low bytes.
    fn emitVarintEncoding(self: *LowerCtx) !void {
        // Stack: [..., script, len]

        // IF len < 253: 1-byte varint.
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
        var sm_at_1byte = try self.stack.clone(self.allocator);
        try self.emitNumToLowBytes(1);
        try self.emitOp(.op_else);
        self.stack.deinit(self.allocator);
        self.stack = sm_at_1byte;
        sm_at_1byte = .{};

        // ELSE-IF len <= 0xffff: 0xfd + 2-byte LE.
        try self.emitOp(.op_dup);
        try self.stack.push(self.allocator, null);
        try self.emitPushInt(0x10000);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_lessthan);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_if);
        _ = self.stack.pop();
        var sm_at_3byte = try self.stack.clone(self.allocator);
        try self.emitNumToLowBytes(2);
        try self.emitVarintPrefix(0xfd);
        try self.emitOp(.op_else);
        self.stack.deinit(self.allocator);
        self.stack = sm_at_3byte;
        sm_at_3byte = .{};

        // ELSE-IF len <= 0xffffffff: 0xfe + 4-byte LE.
        try self.emitOp(.op_dup);
        try self.stack.push(self.allocator, null);
        try self.emitPushInt(0x100000000);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_lessthan);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_if);
        _ = self.stack.pop();
        var sm_at_5byte = try self.stack.clone(self.allocator);
        try self.emitNumToLowBytes(4);
        try self.emitVarintPrefix(0xfe);
        try self.emitOp(.op_else);
        self.stack.deinit(self.allocator);
        self.stack = sm_at_5byte;
        sm_at_5byte = .{};

        // ELSE: 0xff + 8-byte LE. (Practically unreachable on BSV but kept
        // for spec completeness so we never silently truncate.)
        try self.emitNumToLowBytes(8);
        try self.emitVarintPrefix(0xff);

        try self.emitOp(.op_endif);
        try self.emitOp(.op_endif);
        try self.emitOp(.op_endif);
        // --- Stack: [..., script, varint] ---
    }

    // emitNumToLowBytes: [..., len] -> [..., low_n_bytes]. Uses
    // NUM2BIN(n+1) then SPLIT(n) DROP to drop the sign byte.
    fn emitNumToLowBytes(self: *LowerCtx, n_bytes: i64) !void {
        try self.emitPushInt(n_bytes + 1);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_num2bin);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.emitPushInt(n_bytes);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_split);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.stack.push(self.allocator, null);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_drop);
        _ = self.stack.pop();
    }

    // emitVarintPrefix: [..., script, low_bytes] -> [..., script, prefix||low_bytes].
    //
    // The prefix slice MUST live in static memory (not the heap) because Zig's
    // GeneralPurposeAllocator overwrites freed memory with the 0xaa debug
    // pattern, and earlier attempts to heap-allocate the prefix byte caused
    // every emitted varint prefix to read back as 0xaa after the lowering ctx
    // was deinit'd. Static `&.{0xfd}` literals live in the binary's data
    // segment forever, so we hard-code the three call sites instead of
    // taking the byte as a runtime parameter.
    const VARINT_PREFIX_FD: []const u8 = &.{0xfd};
    const VARINT_PREFIX_FE: []const u8 = &.{0xfe};
    const VARINT_PREFIX_FF: []const u8 = &.{0xff};

    fn emitVarintPrefix(self: *LowerCtx, prefix_byte: u8) !void {
        const data: []const u8 = switch (prefix_byte) {
            0xfd => VARINT_PREFIX_FD,
            0xfe => VARINT_PREFIX_FE,
            0xff => VARINT_PREFIX_FF,
            else => unreachable,
        };
        try self.emitPushData(data);
        try self.stack.push(self.allocator, null);
        try self.emitOp(.op_swap);
        const vp_top = self.stack.pop();
        const vp_next = self.stack.pop();
        try self.stack.push(self.allocator, vp_top);
        try self.stack.push(self.allocator, vp_next);
        _ = self.stack.pop();
        _ = self.stack.pop();
        try self.emitOp(.op_cat);
        try self.stack.push(self.allocator, null);
    }

    // emitDropMoreVarintBytes drops `n` additional varint bytes from the
    // top of stack `rest`. Stack in: [..., rest], stack out: [..., rest_minus_n].
    fn emitDropMoreVarintBytes(self: *LowerCtx, n: i64) !void {
        try self.emitPushInt(n);
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


    fn lowerIfExprTerminal(self: *LowerCtx, bind_name: []const u8, ie: *const types.ANFIfExpr, terminal_assert: bool) !void {
        return self.lowerIfExprImpl(bind_name, ie, terminal_assert);
    }

    fn lowerIfExpr(self: *LowerCtx, bind_name: []const u8, ie: *const types.ANFIfExpr) !void {
        return self.lowerIfExprImpl(bind_name, ie, false);
    }

    fn lowerIfExprImpl(self: *LowerCtx, bind_name: []const u8, ie: *const types.ANFIfExpr, terminal_assert: bool) !void {
        // The ANF wire format has no version field, and `--ir` / `--ir-parity`
        // are documented surfaces that feed a checked-in ANF JSON straight into
        // this pass. An ANF produced BEFORE the multi-result node carries the
        // trailing `__merge$` block WITHOUT results — back then the block was a
        // naming CONVENTION this pass recognised, and no tier recognises it any
        // more. Refuse it: the block can only be emitted by
        // `appendBranchResults`, which only runs for an `if` that declares
        // results. Emits no opcodes.
        if (ie.results.len == 0) {
            for (ie.then_bindings) |b| {
                if (std.mem.startsWith(u8, b.name, types.merged_local_temp_prefix)) {
                    return LowerError.StaleMergedLocalAnf;
                }
            }
            if (ie.else_bindings) |eb| {
                for (eb) |b| {
                    if (std.mem.startsWith(u8, b.name, types.merged_local_temp_prefix)) {
                        return LowerError.StaleMergedLocalAnf;
                    }
                }
            }
        }

        // Result slots are identified BY NAME — two identically-named results
        // are indistinguishable, so the layout assertion would be satisfied by
        // coincidence while one value silently replaced the other. ANF lowering
        // refuses the source shape; this guards the `--ir` path.
        if (ie.results.len > 1) {
            for (ie.results, 0..) |a, i| {
                for (ie.results[i + 1 ..]) |b| {
                    if (std.mem.eql(u8, a, b)) return LowerError.DuplicateDeclaredResults;
                }
            }
        }

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

        // The K>=2 merged-local block reads every merged local in BOTH arms,
        // and that read is RECONCILIATION, not a use: it is what makes each arm
        // leave exactly K equally-named result slots for the N>=2 reconcile
        // below to adopt. So the merged locals must be copied, never consumed —
        // regardless of whether the ENCLOSING scope reads them again.
        //
        // `appendMergedLocalResults` (ANF lowering) states that as its premise:
        // "pass 1 always COPIES ... because a local live after the `if` is in
        // `outerProtectedRefs`". Enclosing-scope liveness is the wrong
        // question, and the premise silently failed for every merged local
        // whose last enclosing use IS this `if` — which is EVERY merged local
        // of an `if` in a loop body, since the body's last-use map ends at the
        // `if` itself.
        //
        // What happened then: pass 1 ROLLED instead of picking, the arm's stack
        // effect stopped being +K, the arms ended at different depths, phase 3
        // padded the shortfall with EMPTY pushes, the N-result layout check saw
        // an unnamed slot where it needed the merged name, and control fell
        // through to the single-slot fallback `push(bind_name)` — ONE stackMap
        // name registered for K physical results, with `acc`/`wacc` still
        // naming the dead pre-`if` slots.
        // `for (i<2) { if (i<5) { acc = acc + step; wacc = wacc + acc; } }`
        // with step = 3 produced wacc = 3 where the source says 9: silently in
        // a stateless contract, and as a permanently unspendable UTXO in a
        // stateful one.
        //
        // Byte-neutral for every program whose merged locals were already live
        // after the `if`: those names are already protected above, which is
        // precisely why those programs compiled correctly.
        //
        // Now driven by the node's DECLARED results instead of by recognising a
        // trailing `__merge$` block, so an arm-written property is protected on
        // the same footing as a rebound local.
        for (ie.results) |name| {
            if (self.stack.findDepth(name) != null) {
                try protected_refs.put(self.allocator, name, {});
            }
        }

        var then_ctx = LowerCtx.init(self.allocator, self.program);
        defer then_ctx.deinit();
        then_ctx.stack = try base_stack.clone(self.allocator);
        then_ctx.updated_props = try cloneVoidMap(self.allocator, self.updated_props);
        then_ctx.force_copy_bindings = try cloneVoidMap(self.allocator, self.force_copy_bindings);
        then_ctx.in_branch = true;
        then_ctx.copy_ref_aliases = self.copy_ref_aliases;
        then_ctx.ec_opts = self.ec_opts;
        then_ctx.max_depth = self.max_depth;
        then_ctx.outer_protected_refs = &protected_refs;
        try then_ctx.lowerBindings(ie.then_bindings, terminal_assert);
        try then_ctx.drainBranchPrivateResidue(&pre_if_names);
        if (terminal_assert and then_ctx.stack.depth() > 1) {
            const excess = then_ctx.stack.depth() - 1;
            var i: usize = 0;
            while (i < excess) : (i += 1) {
                try then_ctx.emitOp(.op_nip);
                try then_ctx.stack.removeAtDepth(self.allocator, 1);
            }
        }

        var else_ctx = LowerCtx.init(self.allocator, self.program);
        defer else_ctx.deinit();
        else_ctx.stack = try base_stack.clone(self.allocator);
        else_ctx.updated_props = try cloneVoidMap(self.allocator, self.updated_props);
        else_ctx.force_copy_bindings = try cloneVoidMap(self.allocator, self.force_copy_bindings);
        else_ctx.in_branch = true;
        else_ctx.copy_ref_aliases = self.copy_ref_aliases;
        else_ctx.ec_opts = self.ec_opts;
        else_ctx.max_depth = self.max_depth;
        else_ctx.outer_protected_refs = &protected_refs;
        const else_bindings = ie.else_bindings orelse &.{};
        try else_ctx.lowerBindings(else_bindings, terminal_assert);
        try else_ctx.drainBranchPrivateResidue(&pre_if_names);
        if (terminal_assert and else_ctx.stack.depth() > 1) {
            const excess = else_ctx.stack.depth() - 1;
            var i: usize = 0;
            while (i < excess) : (i += 1) {
                try else_ctx.emitOp(.op_nip);
                try else_ctx.stack.removeAtDepth(self.allocator, 1);
            }
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

        // Branch-merged locals: trim each arm down to exactly its K result slots.
        //
        // ANF lowering ends both arms with an identical K-binding block that
        // rebinds every merged local from a `__merge$<i>` temp (see
        // appendMergedLocalResults). That block leaves the K live values on top
        // in the same canonical order in both arms — but BENEATH them each arm
        // still holds whatever its own body produced, and those differ per arm,
        // which is exactly what the N>=2 reconcile further down compares.
        // Everything beneath the K results is dead: the block copied each
        // merged local before rebinding it, and a branch-local binding is not
        // visible after the `if`.
        //
        // Runs AFTER the phase-2 consumption drops, so both arms have given up
        // the same parent slots and share one base depth.
        const n_declared = ie.results.len;
        if (n_declared >= 1) {
            var still_held = try then_ctx.stack.namedSlots(self.allocator);
            defer still_held.deinit(self.allocator);
            var consumed_from_parent: usize = 0;
            var merge_it = pre_if_names.iterator();
            while (merge_it.next()) |entry| {
                if (!still_held.contains(entry.key_ptr.*) and self.stack.findDepth(entry.key_ptr.*) != null) {
                    consumed_from_parent += 1;
                }
            }
            const target_depth = self.stack.depth() - consumed_from_parent + n_declared;
            for ([_]*LowerCtx{ &then_ctx, &else_ctx }) |arm_ctx| {
                while (arm_ctx.stack.depth() > target_depth) {
                    try removeBranchValueAtDepth(arm_ctx, n_declared);
                }
            }

            // The declared contract, checked rather than assumed: after the
            // trim, each arm's top N slots must BE the declared results, in the
            // declared order (`results[0]` deepest). `appendBranchResults` is
            // what makes this true; if it ever stops being true the arms
            // disagree on layout, which is precisely the failure that produced
            // the 2026-08 miscompile family. Emits no opcodes.
            const arms = [_]struct { label: []const u8, ctx: *LowerCtx }{
                .{ .label = "then", .ctx = &then_ctx },
                .{ .label = "else", .ctx = &else_ctx },
            };
            for (arms) |arm| {
                if (arm.ctx.stack.depth() != target_depth) {
                    std.log.warn(
                        "stack lowering: branch result layout mismatch -- the {s}-arm of the " ++
                            "conditional ends at depth {d}, but its {d} declared result(s) " ++
                            "require depth {d}. binding='{s}'.",
                        .{ arm.label, arm.ctx.stack.depth(), n_declared, target_depth, bind_name },
                    );
                    return LowerError.BranchResultDepthMismatch;
                }
                var li: usize = 0;
                while (li < n_declared) : (li += 1) {
                    const want = ie.results[n_declared - 1 - li];
                    const got = arm.ctx.stack.peekAtDepth(li);
                    if (got == null or !std.mem.eql(u8, got.?, want)) {
                        std.log.warn(
                            "stack lowering: branch result layout mismatch -- the {s}-arm of the " ++
                                "conditional holds '{s}' where the node declares '{s}' (slot {d}). " ++
                                "Every later operand would resolve to the wrong slot. binding='{s}'.",
                            .{ arm.label, got orelse "<unnamed>", want, n_declared - 1 - li, bind_name },
                        );
                        return LowerError.BranchResultDepthMismatch;
                    }
                }
            }
        }

        // Phase 3: depth-balance reconciliation after ALL drops (issue #99 Bug 1).
        // Compensate the FULL depth difference between the branches — NOT just a
        // single item. A conditional write of N state fields leaves N result
        // values on the then-branch, so the (empty) else-branch must preserve N
        // old values. The previous single-shot check only balanced a 1-item
        // difference, leaving N>=2 conditional writes imbalanced by (N-1).
        while (then_ctx.stack.depth() > else_ctx.stack.depth()) {
            const result_depth = then_ctx.stack.depth() - else_ctx.stack.depth() - 1;
            const then_name = then_ctx.stack.peekAtDepth(result_depth);
            if (else_bindings.len == 0 and then_name != null and else_ctx.stack.findDepth(then_name.?) != null) {
                const var_depth = else_ctx.stack.findDepth(then_name.?).?;
                try duplicateBranchValueAtDepth(&else_ctx, var_depth, then_name);
            } else {
                try else_ctx.emitPushData("");
                try else_ctx.stack.push(self.allocator, null);
                else_ctx.trackDepth();
            }
        }
        while (else_ctx.stack.depth() > then_ctx.stack.depth()) {
            try then_ctx.emitPushData("");
            try then_ctx.stack.push(self.allocator, null);
            then_ctx.trackDepth();
        }

        // Layer B — branch-balance invariant (#99 Bug 1 guard; pre-existing).
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

        // Transfer ownership of push_data buffers allocated by the branch
        // contexts to self, so the `push_data` slices we just copied into
        // self.instructions remain valid after then_ctx/else_ctx.deinit()
        // runs and frees their owned buffers. Without this, branch-allocated
        // buffers (e.g., hex-decoded ByteString property initial values)
        // would be freed, and Debug mode fills freed memory with 0xaa,
        // producing corrupt push_data output.
        try self.owned_push_data.appendSlice(self.allocator, then_ctx.owned_push_data.items);
        then_ctx.owned_push_data.clearRetainingCapacity();
        try self.owned_push_data.appendSlice(self.allocator, else_ctx.owned_push_data.items);
        else_ctx.owned_push_data.clearRetainingCapacity();

        // Physical slots this function drops AFTER OP_ENDIF, while reconciling
        // the parent stackMap against the arms' results. Counted because the
        // invariant at the end of lowerIf cannot compare the two depths
        // directly: the post-ENDIF reconcile legitimately ROLL/DROPs stale slots
        // out from under the results, so those drops have to be added back
        // before comparing.
        var post_endif_drops: usize = 0;

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

        // C27: the N>=2 result reconcile below also applies when the else-branch
        // is PRESENT and BOTH arms wrote the same N mutable fields (e.g. each
        // branch runs `this.a = ...; this.b = ...`). This is the else-present
        // twin of the empty-else fix (#99 Bug 1). Without it, lowerIf falls
        // through to `push(bind_name)` further down — registering ONE stackMap
        // name for N physical results — so state serialization emits against the
        // wrong slot (OP_NUM2BIN on a byte string) and the continuation is
        // unspendable (a funds-safety bug). Only fire when both arms leave the
        // identical top-N property names in the identical order, so a single
        // post-ENDIF reconcile is valid regardless of which branch the spender
        // takes. The single-field same-property case (N==1, "turn flip") is
        // unaffected — it still takes the dedicated path below.
        const then_depth = then_ctx.stack.depth();
        const self_depth = self.stack.depth();
        const else_depth = else_ctx.stack.depth();
        const n_results: usize = if (then_depth > self_depth) then_depth - self_depth else 0;
        var else_matches_then_n_result_layout = false;
        if (else_bindings.len > 0 and n_results >= 2 and else_depth > self_depth and else_depth - self_depth == n_results) {
            else_matches_then_n_result_layout = true;
            var mi: usize = 0;
            while (mi < n_results) : (mi += 1) {
                const tn = then_ctx.stack.peekAtDepth(mi);
                const en = else_ctx.stack.peekAtDepth(mi);
                if (tn == null or en == null or !std.mem.eql(u8, tn.?, en.?)) {
                    else_matches_then_n_result_layout = false;
                    break;
                }
            }
        }

        if (n_declared >= 1) {
            // DECLARED RESULTS. Both arms were normalised by
            // `appendBranchResults` and the layout check above proved they hold
            // exactly `results`, so the parent adopts them BY THE DECLARED
            // ORDER -- no counting of trailing `__merge$` bindings, no
            // comparison of arm depths, no inference of which names are still
            // live. `results[0]` is the deepest slot, matching the order pass 2
            // of the normalisation rebound them in.
            //
            // Then each parent slot the block shadows (the pre-`if` binding of
            // a merged local, the stale value of a written property) is
            // physically rolled out from under the results, exactly as the
            // pre-existing N>=2 reconcile did -- which is why the four
            // `__merge$` goldens keep their bytes.
            for (ie.results) |name| {
                try self.stack.push(self.allocator, name);
            }
            // How far below the result block the deepest stale slot sat.
            // Adopting a result puts it ON TOP, but its pre-`if` binding lived
            // at depth `d`, i.e. BENEATH the `d - n_declared` slots in between.
            // Removing the stale copy does not reorder those in-between slots,
            // so after the loop the adopted result has crossed them: the layout
            // is rotated even though the NAME SET and the DEPTH are both
            // unchanged. That is invisible to the reconcile's name-set check
            // and to Layer C's depth check, and it is the whole of issue #149
            // -- see `sink_below` below.
            var sink_below: usize = 0;
            var ri2: usize = n_declared;
            while (ri2 > 0) {
                ri2 -= 1;
                const name = ie.results[ri2];
                var d: usize = n_declared;
                while (d < self.stack.depth()) : (d += 1) {
                    if (self.stack.peekAtDepth(d)) |nm2| {
                        if (std.mem.eql(u8, nm2, name)) {
                            // The unconditional push/roll/drop of the
                            // pre-existing N>=2 reconcile, NOT
                            // `removeStalePropertyAtDepth` — that helper nips at
                            // depth 1, and the reference tier does not, so using
                            // it here would diverge by three bytes on every
                            // single-result `if` whose stale slot sits at depth
                            // 1 (`if-else`, `selector`).
                            try self.emitPushInt(@intCast(d));
                            try self.stack.push(self.allocator, null);
                            try self.emitOp(.op_roll);
                            _ = self.stack.pop();
                            const rolled = self.stack.peekAtDepth(d);
                            try self.stack.removeAtDepth(self.allocator, d);
                            try self.stack.push(self.allocator, rolled);
                            try self.emitOp(.op_drop);
                            _ = self.stack.pop();
                            post_endif_drops += 1;
                            if (d - n_declared > sink_below) sink_below = d - n_declared;
                            break;
                        }
                    }
                }
            }

            // Restore the inherited layout: sink the whole result block back
            // under the `sink_below` slots it just crossed, so BOTH paths of
            // the enclosing `if` leave the same slot order and every
            // post-OP_ENDIF read resolves against the layout it was generated
            // for. Rolling the deepest item of the `n_declared + sink_below`
            // window to the top, `sink_below` times, lifts those slots back
            // above the results while preserving their own relative order.
            // Applied unconditionally, NOT gated on this `if`'s own else. The
            // asymmetry that makes #149 unspendable belongs to the ENCLOSING
            // `if` (whose fall-through path keeps the pre-`if` layout), and
            // `lowerIf` has no view of its parent here. Gating on
            // `else_bindings.len == 0` was measured and is WRONG: the #149
            // inner `if` has a real else, so the gate disables the repair
            // exactly where it is needed. Restoring the pre-`if` order
            // unconditionally keeps the parent's own model -- names at the
            // depths it recorded before the branch -- true on every path.
            if (sink_below > 0) {
                const window_size = n_declared + sink_below;
                var sj: usize = 0;
                while (sj < sink_below) : (sj += 1) {
                    try self.emitPushInt(@intCast(window_size - 1));
                    try self.stack.push(self.allocator, null);
                    try self.emitOp(.op_roll);
                    _ = self.stack.pop();
                    const lifted = self.stack.peekAtDepth(window_size - 1);
                    try self.stack.removeAtDepth(self.allocator, window_size - 1);
                    try self.stack.push(self.allocator, lifted);
                }
            }
        } else if (then_depth > self_depth and n_results >= 2 and (else_bindings.len == 0 or else_matches_then_n_result_layout)) {
            // #99 Bug 1: a conditional write of N>=2 state fields leaves N result
            // values on top; record them in their on-stack order, then remove
            // the N stale old property values beneath them.
            const result_count = then_ctx.stack.depth() - self.stack.depth();
            var ri: usize = result_count;
            while (ri > 0) {
                ri -= 1;
                const nm = then_ctx.stack.peekAtDepth(ri);
                try self.stack.push(self.allocator, if (nm) |n| n else bind_name);
            }
            var rj: usize = 0;
            while (rj < result_count) : (rj += 1) {
                const name = self.stack.peekAtDepth(rj) orelse continue;
                var d: usize = result_count;
                while (d < self.stack.depth()) : (d += 1) {
                    if (self.stack.peekAtDepth(d)) |nm2| {
                        if (std.mem.eql(u8, nm2, name)) {
                            try removeStalePropertyAtDepth(self, d);
                            post_endif_drops += 1;
                            break;
                        }
                    }
                }
            }
        } else if (then_ctx.stack.depth() > self.stack.depth()) {
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
                            post_endif_drops += 1;
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
                            post_endif_drops += 1;
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

        // Layer C — branch result-depth invariant.
        //
        // The stackMap is the compiler's ONLY model of the stack, so a stackMap
        // that names FEWER slots than the arms physically left is not detectable
        // anywhere downstream: every later operand silently resolves N slots
        // off. That single failure mode produced the whole 2026-08 branch/loop
        // miscompile family -- wrong-but-accepted state continuations at best,
        // and scripts the interpreter rejects outright (locked funds) at worst.
        //
        // What must hold when lowerIf returns: the parent stackMap describes
        // exactly the physical stack. Both arms ended at arm_depth (Layer B
        // above proves they agree), OP_ENDIF changes nothing, and the only
        // physical effect after it is the post_endif_drops stale-slot drops the
        // reconcile emitted. So:
        //
        //     self.stack.depth() + post_endif_drops == arm_depth
        //
        // The naive self.stack.depth() == arm_depth is WRONG -- the reconcile
        // legitimately ROLL/DROPs stale slots out from under the results, which
        // is exactly what post_endif_drops counts.
        //
        // A failure here is always a codegen bug, never a user error. Emits no
        // opcodes: byte-neutral by construction. Same genre as Layer B (#99),
        // added for the same reason.
        const arm_depth = then_ctx.stack.depth();
        if (self.stack.depth() + post_endif_drops != arm_depth) {
            std.log.warn(
                "stack lowering: branch result depth mismatch -- the parent stack " ++
                    "model does not describe the physical stack after OP_ENDIF " ++
                    "(stackMap depth {d} + {d} post-ENDIF drop(s) != arm depth {d}). " ++
                    "The arms leave more physical slots than the compiler recorded, " ++
                    "so every later operand would resolve to the wrong slot and the " ++
                    "script would be wrong or unspendable. binding='{s}'.",
                .{ self.stack.depth(), post_endif_drops, arm_depth, bind_name },
            );
            return LowerError.BranchResultDepthMismatch;
        }

        self.trackDepth();

        if (then_ctx.max_depth > self.max_depth) self.max_depth = then_ctx.max_depth;
        if (else_ctx.max_depth > self.max_depth) self.max_depth = else_ctx.max_depth;
    }

    // ========================================================================
    // for_loop
    // ========================================================================

    /// Collect every binding name defined anywhere in `bindings`, recursing
    /// into nested if-branches and loop bodies. Mirrors the TS reference
    /// compiler's `collectDeepBindingNames` (05-stack-lower.ts). Used by
    /// `lowerForLoop` to distinguish loop-internal (re)definitions from true
    /// outer-scope refs, so reassigned locals keep flowing through
    /// `lowerIfExpr`'s branch-reassignment reconciliation instead of the
    /// outer-ref protection path.
    fn collectDeepBindingNames(
        allocator: Allocator,
        bindings: []const types.ANFBinding,
        out: *std.StringHashMapUnmanaged(void),
    ) !void {
        for (bindings) |b| {
            try out.put(allocator, b.name, {});
            switch (b.value) {
                .@"if" => |ie| {
                    try collectDeepBindingNames(allocator, ie.then, out);
                    try collectDeepBindingNames(allocator, ie.@"else", out);
                },
                .loop => |lp| {
                    try collectDeepBindingNames(allocator, lp.body, out);
                },
                else => {},
            }
        }
    }

    /// Collect every SSA operand name referenced by a single ANF value,
    /// recursing into nested if-branches and loop bodies. Mirrors the TS
    /// reference compiler's `collectRefs` (05-stack-lower.ts). Used by
    /// `lowerForLoop` to find outer-scope refs used anywhere in the body —
    /// including refs that only occur inside a nested if-branch.
    fn collectValueRefs(
        allocator: Allocator,
        value: types.ANFValue,
        out: *std.StringHashMapUnmanaged(void),
    ) !void {
        switch (value) {
            .load_param => |lp| try out.put(allocator, lp.name, {}),
            .load_prop, .get_state_script => {},
            .load_const => |lc| {
                switch (lc.value) {
                    .string => |s| {
                        if (std.mem.startsWith(u8, s, "@ref:")) {
                            try out.put(allocator, s[5..], {});
                        }
                    },
                    else => {},
                }
            },
            .bin_op => |bop| {
                try out.put(allocator, bop.left, {});
                try out.put(allocator, bop.right, {});
            },
            .unary_op => |uop| try out.put(allocator, uop.operand, {}),
            .call => |c| {
                for (c.args) |arg| try out.put(allocator, arg, {});
            },
            .method_call => |mc| {
                if (mc.object.len > 0) try out.put(allocator, mc.object, {});
                for (mc.args) |arg| try out.put(allocator, arg, {});
            },
            .@"if" => |ie| {
                try out.put(allocator, ie.cond, {});
                for (ie.then) |b| try collectValueRefs(allocator, b.value, out);
                for (ie.@"else") |b| try collectValueRefs(allocator, b.value, out);
            },
            .loop => |lp| {
                for (lp.body) |b| try collectValueRefs(allocator, b.value, out);
            },
            .assert => |a| try out.put(allocator, a.value, {}),
            .update_prop => |up| try out.put(allocator, up.value, {}),
            .check_preimage => |cp| try out.put(allocator, cp.preimage, {}),
            .deserialize_state => |ds| try out.put(allocator, ds.preimage, {}),
            .add_output => |ao| {
                if (ao.satoshis.len > 0) try out.put(allocator, ao.satoshis, {});
                if (ao.preimage.len > 0) try out.put(allocator, ao.preimage, {});
                for (ao.state_values) |sv| {
                    if (sv.len > 0) try out.put(allocator, sv, {});
                }
            },
            .add_raw_output => |aro| {
                if (aro.satoshis.len > 0) try out.put(allocator, aro.satoshis, {});
                if (aro.script_bytes.len > 0) try out.put(allocator, aro.script_bytes, {});
            },
            .add_data_output => |ado| {
                if (ado.satoshis.len > 0) try out.put(allocator, ado.satoshis, {});
                if (ado.script_bytes.len > 0) try out.put(allocator, ado.script_bytes, {});
            },
            .array_literal => |al| {
                for (al.elements) |e| try out.put(allocator, e, {});
            },
            .raw_script => {},
        }
    }

    /// Collect the locals a loop body REBINDS and then READS AGAIN in the same
    /// iteration. Mirrors the TS reference compiler's
    /// `collectLoopCarriedRebinds` (05-stack-lower.ts).
    ///
    /// `computeLastUses` maps a name to the MAXIMUM index that references it,
    /// so for a body like
    ///
    ///     t3   = acc + step     (index 1 — reads the value carried in)
    ///     acc  = @ref:t3        (index 2 — rebinds: renames t3's slot to acc)
    ///     t4   = wacc + acc     (index 3 — reads the value just rebound)
    ///
    /// `acc` gets last-use 3. Index 1 is therefore NOT a last use and copies
    /// (PICK) instead of consuming, leaving the incoming slot on the stack
    /// under the same name as the rebound one; index 3 then IS the last use,
    /// and findDepth resolves to the topmost match — so it consumes the
    /// UPDATED value and leaves the dead incoming one. The next iteration
    /// reads that dead slot, and every iteration recomputes from the pre-loop
    /// value: `for (let i = 0n; i < N; i++) { acc = acc + step; wacc = wacc +
    /// acc; }` produced `wacc = step*N` where the source says
    /// `step*N*(N+1)/2` — silently in a stateless contract, and as a
    /// permanently unspendable UTXO in a stateful one (the covenant commits to
    /// a continuation the SDK never builds). `outer_refs` does not cover it:
    /// `acc` is excluded there precisely because the body binds it.
    ///
    /// The value these names hold at the end of an iteration is live at the
    /// start of the next one, so `lowerForLoop` protects them from consumption
    /// exactly like an outer ref. The incoming slot each rebinding shadows is
    /// left behind and drained with the rest of the frame at method exit — a
    /// name always resolves to its newest slot, so the reads stay correct.
    ///
    /// Both halves of the predicate are load-bearing:
    ///   - read BEFORE the first rebinding: the name is carried IN from the
    ///     enclosing scope, rather than being a body-private temp that merely
    ///     happens to be read after it is bound;
    ///   - read AFTER the last rebinding: without it the rebound value is dead
    ///     at the end of the iteration and consuming it is correct. This is
    ///     what keeps every shipped accumulator (`sum = sum + i`, `off = off +
    ///     len`) byte-for-byte unchanged.
    ///
    /// NESTED loops: the scan runs over `flattenNestedLoopBodies(body)`, not
    /// over `body` itself. A name rebound only inside an INNER loop is bound
    /// at no top-level index of the outer body, so the raw scan classified it
    /// as neither an outer ref (`collectDeepBindingNames` excludes it — the
    /// body does bind it, deeply) nor a carried rebind, and the outer loop
    /// never marked it live. The inner loop's final iteration then consumed
    /// it, because `used_after_loop` asks the enclosing scope and the
    /// enclosing scope had not been told either, so every outer iteration
    /// restarted from the slot the previous one left behind:
    /// `for (i<2) { for (j<2) { acc = acc + step; wacc = wacc + acc; } }` with
    /// step = 3 produced `wacc = 24` where the source says 30. Splicing the
    /// inner body in at the loop's position preserves the read/rebind/read
    /// ordering the inner level already sees, so the outer level draws the
    /// same conclusion.
    fn collectLoopCarriedRebinds(
        allocator: Allocator,
        body: []const types.ANFBinding,
        out: *std.StringHashMapUnmanaged(void),
    ) !void {
        var flat_buf: std.ArrayListUnmanaged(types.ANFBinding) = .empty;
        defer flat_buf.deinit(allocator);
        try flattenNestedLoopBodies(allocator, body, &flat_buf);
        const flat = flat_buf.items;

        var first_bind: std.StringHashMapUnmanaged(usize) = .empty;
        defer first_bind.deinit(allocator);
        var last_bind: std.StringHashMapUnmanaged(usize) = .empty;
        defer last_bind.deinit(allocator);
        for (flat, 0..) |binding, i| {
            if (!first_bind.contains(binding.name)) {
                try first_bind.put(allocator, binding.name, i);
            }
            try last_bind.put(allocator, binding.name, i);
        }

        var read_before: std.StringHashMapUnmanaged(void) = .empty;
        defer read_before.deinit(allocator);
        var read_after: std.StringHashMapUnmanaged(void) = .empty;
        defer read_after.deinit(allocator);
        for (flat, 0..) |binding, i| {
            var refs: std.StringHashMapUnmanaged(void) = .empty;
            defer refs.deinit(allocator);
            try collectValueRefs(allocator, binding.value, &refs);
            var it = refs.iterator();
            while (it.next()) |entry| {
                const ref = entry.key_ptr.*;
                if (first_bind.get(ref)) |first| {
                    if (i < first) try read_before.put(allocator, ref, {});
                }
                if (last_bind.get(ref)) |last| {
                    if (i > last) try read_after.put(allocator, ref, {});
                }
            }
        }

        var before_it = read_before.iterator();
        while (before_it.next()) |entry| {
            const ref = entry.key_ptr.*;
            if (read_after.contains(ref)) try out.put(allocator, ref, {});
        }
    }

    /// Append `body` to `out` with every nested `loop` binding — and every `if`
    /// binding — replaced, in place, by its own (recursively flattened) body.
    ///
    /// Only `collectLoopCarriedRebinds` uses this, and only to order reads
    /// against rebindings. Neither replaced binding contributes a stack slot
    /// that predicate reasons about, so dropping it loses nothing; splicing the
    /// sub-body in at its position is what lets an enclosing loop see a
    /// rebinding one level down.
    ///
    /// `if` arms ARE spliced, in `then ++ else` order, even though they are
    /// alternatives rather than a sequence. The predicate asks only "is this
    /// name read, then rebound, then read again", and treating the arms as a
    /// sequence can only ADD names to the carried set, never remove one —
    /// conservative in the safe direction. Without it a local rebound ONLY
    /// inside an `if` arm was bound at no index the predicate could see:
    /// neither an outer ref (`collectDeepBindingNames` excludes it, since the
    /// body does bind it, deeply) nor a carried rebind. The loop consumed it
    /// and the next iteration had nothing to read, so
    /// `for (i<2) { if (i<5) { acc = acc + step; } wacc = wacc + acc; }` was
    /// REJECTED outright with `Value 'acc' not found on stack` — the loud face
    /// of the same gap the merged-local protection in `lowerIfExprImpl` fixes
    /// silently at K>=2.
    ///
    /// The `if` binding itself is NOT re-appended after its arms. Appending it
    /// would count the arms' reads a second time at an index past every arm
    /// rebinding, making a local that BOTH arms rebind look "read after its
    /// last rebinding" — which protected a K=1 alias that must stay consumable.
    ///
    /// A body with no nested loop and no `if` is appended entry-for-entry
    /// unchanged, which is what makes this byte-neutral for every flat loop.
    fn flattenNestedLoopBodies(
        allocator: Allocator,
        body: []const types.ANFBinding,
        out: *std.ArrayListUnmanaged(types.ANFBinding),
    ) !void {
        for (body) |binding| {
            switch (binding.value) {
                .loop => |lp| try flattenNestedLoopBodies(allocator, lp.body, out),
                .@"if" => |ie| {
                    try flattenNestedLoopBodies(allocator, ie.then, out);
                    try flattenNestedLoopBodies(allocator, ie.@"else", out);
                },
                else => try out.append(allocator, binding),
            }
        }
    }

    fn lowerForLoop(self: *LowerCtx, bind_name: []const u8, fl: *const types.ANFForLoop) !void {
        var body_binding_names: std.StringHashMapUnmanaged(void) = .empty;
        defer body_binding_names.deinit(self.allocator);
        for (fl.body_bindings) |binding| {
            try body_binding_names.put(self.allocator, binding.name, {});
        }

        // Names (re)defined anywhere inside the loop body, nested if-branches
        // and nested loops included. A name the body itself binds is NOT an
        // outer ref — reassigned locals (e.g. `off = off + ...` inside an if)
        // flow through lowerIfExpr's branch-reassignment reconciliation, not
        // through the outer-ref protection here.
        var deep_body_names: std.StringHashMapUnmanaged(void) = .empty;
        defer deep_body_names.deinit(self.allocator);
        try collectDeepBindingNames(self.allocator, fl.body_bindings, &deep_body_names);

        // Collect ALL outer-scope refs used anywhere in the body — including
        // refs that only occur inside a nested if-branch (collectValueRefs
        // recurses). The previous top-level-only scan (top-level load_param +
        // top-level load_const @ref) missed nested references: a const defined
        // before the loop and referenced only inside an if-branch was consumed
        // by the first iteration, making iteration 2 fail with
        // "Value 'X' not found on stack".
        var all_refs: std.StringHashMapUnmanaged(void) = .empty;
        defer all_refs.deinit(self.allocator);
        for (fl.body_bindings) |binding| {
            try collectValueRefs(self.allocator, binding.value, &all_refs);
        }

        var outer_refs: std.StringHashMapUnmanaged(void) = .empty;
        defer outer_refs.deinit(self.allocator);
        var all_refs_it = all_refs.iterator();
        while (all_refs_it.next()) |entry| {
            const ref = entry.key_ptr.*;
            if (!std.mem.eql(u8, ref, fl.var_name) and !deep_body_names.contains(ref)) {
                try outer_refs.put(self.allocator, ref, {});
            }
        }

        // A local the body REBINDS and then READS AGAIN in the same iteration
        // is carried across iterations through the rebound slot, so it must
        // survive the body exactly like an outer ref. `deep_body_names` above
        // excludes it precisely because the body binds it — which is what made
        // the updated value consumable. See `collectLoopCarriedRebinds`.
        var carried_rebinds: std.StringHashMapUnmanaged(void) = .empty;
        defer carried_rebinds.deinit(self.allocator);
        try collectLoopCarriedRebinds(self.allocator, fl.body_bindings, &carried_rebinds);
        var carried_it = carried_rebinds.iterator();
        while (carried_it.next()) |entry| {
            const ref = entry.key_ptr.*;
            if (!std.mem.eql(u8, ref, fl.var_name)) {
                try outer_refs.put(self.allocator, ref, {});
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

        // The enclosing binding index of this loop, captured before the
        // per-iteration body lowering clobbers `current_idx`. Combined with the
        // enclosing scope's last-use map (still live in `self.last_uses` on
        // entry), it tells us whether an outer ref is still needed AFTER the
        // loop. Zig threads the enclosing index / last-use map implicitly via
        // the shared LowerCtx (unlike the TS reference, which passes them as
        // explicit params to lowerLoop).
        const loop_binding_index = self.current_idx;

        var n: u32 = 0;
        while (n < fl.count) : (n += 1) {
            // Iteration `n` binds `start + n*step` (issue #121). Zero-start
            // counting-up loops (start=0, step=1) reduce to `n`, preserving the
            // historical byte-for-byte lowering.
            const iter_val: i64 = fl.start + @as(i64, @intCast(n)) * fl.step;
            try self.emitPushInt(iter_val);
            try self.stack.push(self.allocator, fl.var_name);
            self.trackDepth();

            const enclosing_last_uses = self.last_uses;
            self.last_uses = .empty;
            try self.computeLastUses(fl.body_bindings);

            // Prevent outer-scope refs from being consumed by pinning their
            // last-use past every body binding index:
            //  - in non-final iterations: always (the next iteration re-reads);
            //  - in the FINAL iteration: only when the enclosing scope still
            //    references the ref AFTER the loop. Previously the final
            //    iteration consumed every outer ref at its last body use, so a
            //    method param (or const) referenced after the loop was gone
            //    from the stack and was silently lowered to an OP_0 — the
            //    script compiled and the env interpreter passed, but the
            //    emitted Script failed on chain (silent interpreter/Script
            //    divergence).
            const is_final_iteration = (n == fl.count - 1);
            var outer_it = outer_refs.iterator();
            while (outer_it.next()) |entry| {
                const ref = entry.key_ptr.*;
                const used_after_loop = if (enclosing_last_uses.get(ref)) |lu|
                    lu > loop_binding_index
                else
                    false;
                if (!is_final_iteration or used_after_loop) {
                    try self.last_uses.put(self.allocator, ref, fl.body_bindings.len);
                }
            }

            for (fl.body_bindings, 0..) |binding, idx| {
                self.current_idx = idx;
                try self.lowerBinding(binding);
            }
            self.last_uses.deinit(self.allocator);
            self.last_uses = enclosing_last_uses;

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
        const output_operands = try std.mem.concat(
            self.allocator,
            []const u8,
            &.{ &.{ao.satoshis}, ao.state_values },
        );
        defer self.allocator.free(output_operands);

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

            try self.bringToTopOperand(value_ref, output_operands);
            if (isNumericStateType(prop.type_info)) {
                const width: i64 = if (prop.type_info == .boolean) 1 else 8;
                try self.emitPushInt(width);
                try self.stack.push(self.allocator, null);
                try self.emitOp(.op_num2bin);
                _ = self.stack.pop();
            } else if (isVariableLengthStateType(prop.type_info)) {
                try self.emitPushDataEncode();
            }
            // Fixed-width byte types (PubKey, Addr, Ripemd160, Sha256, Point,
            // P256Point, P384Point) are already byte sequences and used as-is.

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

        try self.bringToTopOperand(ao.satoshis, output_operands);
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
        try self.bringToTopOperand(aro.script_bytes, &.{ aro.satoshis, aro.script_bytes });
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

        try self.bringToTopOperand(aro.satoshis, &.{ aro.satoshis, aro.script_bytes });
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
// OP_PUSH_TX on-chain signature derivation (BUG-100 fix)
// ============================================================================
//
// The insecure legacy checkPreimage accepted a witness signature over the real
// spending transaction and checked it against pubkey G, never reading the pushed
// preimage — so the preimage was decoupled from the tx. This derives the ECDSA
// signature FROM the preimage on-chain (s = (hash256(preimage) + r)*kinv mod n,
// fixed nonce k=2, privkey d=1, low-S, minimal DER), so OP_CHECKSIG passes only
// when hash256(preimage) equals the real tx sighash.
//
// The construction compiles to a FIXED byte sequence identical across all seven
// tiers; it is the canonical output of the TypeScript reference
// (packages/runar-compiler/src/passes/oppushtx-codegen.ts). Emitted as a single
// opaque raw_bytes op (peephole barrier). The cross-tier conformance suite
// guards that this constant matches every other tier byte-for-byte.
const check_preimage_binding_hex = "76aa007c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c7501007e8121e59e705cb909acaba73cef8c4b8e775cd87cc0956e4045306d7ded41947f04c6009320a1201b68462fe9df1d50a457736e575dffffffffffffffffffffffffffffff7f9521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff006e977b7578937c977620a0201b68462fe9df1d50a457736e575dffffffffffffffffffffffffffffff7fa07821414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007c8d7c949594826b012080007c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c756c01207c947f777682775180527c7e7c7e768277012393518023022100c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee50130527a7e7c7e7c7e01417e210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad";

// The frozen binding hex above ends with `0141` (OP_DATA_1 SIGHASH_ALL|FORKID)
// immediately before this fixed G-pubkey tail. Issue #123: a non-default
// @sighash mode swaps only that single push (`0141` -> `01<flag>`), leaving the
// tail intact — byte-for-byte matching the TS reference. Mirrors Go's
// checkPreimageSighashTail (compilers/go/codegen/oppushtx.go).
const check_preimage_sighash_tail = "7e210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad";

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
    return lowerOpts(allocator, program, .{});
}

/// `lower` with the EXPERIMENTAL EC script-size options.
///
/// An all-false value keeps every EC emitter byte-identical to the shipping
/// output; see `ec_emitters.EcCodegenOptions` and
/// docs/experiments/script-size-optimizer-results.md.
pub fn lowerOpts(
    allocator: Allocator,
    program: types.ANFProgram,
    ec_opts: ec_emitters.EcCodegenOptions,
) !types.StackProgram {
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
        ctx.ec_opts = ec_opts;

        // Use body or bindings (whichever is populated)
        const bindings = if (method.body.len > 0) method.body else method.bindings;
        try ctx.lowerBindings(bindings, method.is_public);
        // CLEANSTACK: drop excess items left below the top-of-stack boolean.
        // cleanupExcessStack() is a no-op when depth <= 1, so running it for
        // every public method also fixes all-readonly stateful methods.
        if (method.is_public) {
            try ctx.cleanupExcessStack();
        }
        if (!method.is_public or (!endsWithAssert(bindings) and !endsWithTerminalRawScript(bindings))) {
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

fn setupMethodStack(ctx: *LowerCtx, program: types.ANFProgram, method: types.ANFMethod) !void {
    const bindings = methodBindings(method);

    if (methodUsesCodePartFull(bindings, program.properties, program.methods)) {
        try ctx.stack.push(ctx.allocator, "_codePart");
        ctx.trackDepth();
    }

    // BUG-100 fix: the OP_PUSH_TX signature is now derived on-chain from the
    // preimage (see lowerCheckPreimage), so NO _opPushTxSig witness item is
    // pushed. The unlocking script provides only the preimage.

    for (method.params) |param| {
        try ctx.stack.push(ctx.allocator, param.name);
    }
    ctx.trackDepth();

    // Issue #130: a method param whose name collides with a MUTABLE property
    // gets a duplicate stackMap slot once deserialize_state pushes that property
    // under the same name. Name lookups resolve to the shallowest match (the
    // deserialized property), so lowerLoadParam would read the stale on-chain
    // state instead of the witness value. Rename the colliding param's slot to a
    // reserved, collision-proof name up front and remember the mapping so
    // lowerLoadParam targets the real param slot. Only mutable properties are
    // deserialized onto the stack, so readonly shadows (handled purely by ANF
    // resolution) never enter this map, and non-colliding contracts get an empty
    // map — byte-identical output.
    for (method.params) |param| {
        const is_mutable_prop = for (program.properties) |prop| {
            if (!prop.readonly and std.mem.eql(u8, prop.name, param.name)) break true;
        } else false;
        if (is_mutable_prop) {
            if (ctx.stack.findDepth(param.name)) |d| {
                const renamed = try std.fmt.allocPrint(ctx.allocator, "__param_{s}", .{param.name});
                try ctx.owned_push_data.append(ctx.allocator, renamed);
                try ctx.stack.renameAtDepth(ctx.allocator, d, renamed);
                try ctx.renamed_params.put(ctx.allocator, param.name, renamed);
            }
        }
    }
}

fn setupPropertyStack(ctx: *LowerCtx, program: types.ANFProgram) !void {
    _ = ctx;
    _ = program;
}

pub fn methodBindings(method: types.ANFMethod) []const types.ANFBinding {
    return if (method.body.len > 0) method.body else method.bindings;
}

fn endsWithAssert(bindings: []const types.ANFBinding) bool {
    if (bindings.len == 0) return false;
    return switch (bindings[bindings.len - 1].value) {
        .assert => true,
        // TS reference compiler propagates `terminalAssert=true` into the
        // last `if` binding, and both branches leave a truthy value on the
        // stack instead of executing OP_VERIFY. Treat such a terminal `if`
        // as ending-with-assert so we don't append an extra OP_1 at the
        // method tail.
        .@"if" => |ie| endsWithAssert(ie.then) and endsWithAssert(ie.@"else"),
        else => false,
    };
}

/// Returns true when the last binding is a `raw_script` with declared
/// out_arity 1. Mirrors the validator's `endsWithTerminalAsm` rule — such a
/// terminal asm({...}) leaves a single truthy value on the stack, so the
/// stack lowerer must NOT append a trailing OP_1.
fn endsWithTerminalRawScript(bindings: []const types.ANFBinding) bool {
    if (bindings.len == 0) return false;
    return switch (bindings[bindings.len - 1].value) {
        .raw_script => |rs| rs.out_arity == 1,
        .@"if" => |ie| (endsWithAssert(ie.then) or endsWithTerminalRawScript(ie.then)) and
            (endsWithAssert(ie.@"else") or endsWithTerminalRawScript(ie.@"else")),
        else => false,
    };
}

fn anyMethodUsesCheckPreimage(methods: []const types.ANFMethod) bool {
    for (methods) |method| {
        if (method.is_public and methodUsesCheckPreimage(methodBindings(method), methods)) return true;
    }
    return false;
}

fn anyMethodUsesCodePart(methods: []const types.ANFMethod) bool {
    for (methods) |method| {
        if (method.is_public and methodUsesCodePart(methodBindings(method))) return true;
    }
    return false;
}

/// C27: the sole entry point used to hard-code `null` for the private-method
/// map, so the `method_call` recursion below was dead code — a `checkPreimage`
/// reachable ONLY through a private helper made this return false while the TS
/// reference (`methodUsesCheckPreimage(method.body, privateMethods)`,
/// 05-stack-lower.ts) returned true. Thread the real method list, using the
/// same `findPrivateMethod` lookup the inliner (`lowerMethodCall`) and the
/// sibling `methodReadsVarLenStateRec` use.
fn methodUsesCheckPreimage(
    bindings: []const types.ANFBinding,
    methods: []const types.ANFMethod,
) bool {
    return methodUsesCheckPreimageRec(bindings, methods, 0);
}

const MAX_PREIMAGE_RECURSION_DEPTH: u32 = 64;

fn methodUsesCheckPreimageRec(
    bindings: []const types.ANFBinding,
    methods: []const types.ANFMethod,
    depth: u32,
) bool {
    if (depth > MAX_PREIMAGE_RECURSION_DEPTH) return false;
    for (bindings) |binding| {
        switch (binding.value) {
            .check_preimage => return true,
            .@"if" => |ie| {
                if (methodUsesCheckPreimageRec(ie.then, methods, depth)) return true;
                if (methodUsesCheckPreimageRec(ie.@"else", methods, depth)) return true;
            },
            .loop => |loop| {
                if (methodUsesCheckPreimageRec(loop.body, methods, depth)) return true;
            },
            .method_call => |mc| {
                if (findPrivateMethod(methods, mc.method)) |target| {
                    if (methodUsesCheckPreimageRec(methodBindings(target), methods, depth + 1)) return true;
                }
            },
            else => {},
        }
    }
    return false;
}

fn methodUsesCodePart(bindings: []const types.ANFBinding) bool {
    for (bindings) |binding| {
        switch (binding.value) {
            .add_output, .add_raw_output, .add_data_output => return true,
            .call => |call| {
                if (std.mem.eql(u8, call.func, "computeStateOutput") or
                    std.mem.eql(u8, call.func, "computeStateOutputHash") or
                    std.mem.eql(u8, call.func, "buildChangeOutput") or
                    std.mem.eql(u8, call.func, "buildStateOutput"))
                {
                    return true;
                }
            },
            .@"if" => |ie| {
                if (methodUsesCodePart(ie.then) or methodUsesCodePart(ie.@"else")) return true;
            },
            .loop => |loop| {
                if (methodUsesCodePart(loop.body)) return true;
            },
            else => {},
        }
    }
    return false;
}

/// Whether a method READS a mutable variable-length (ByteString) state field's
/// value (via load_prop). Issue #100: such a terminal method needs _codePart for
/// the preimage-relative state offset. Narrowed to the live var-length read so
/// methods that only read readonly fields (baked into the locking script) or
/// fixed-size fields keep their original terminal codegen.
///
/// C18: the read may live entirely inside a private helper reached via
/// `method_call`. `lowerMethodCall` INLINES private methods into the caller's
/// stack context, so that load_prop really does execute here — recurse through
/// private method bodies exactly like `methodUsesCheckPreimageRec` does (same
/// `findPrivateMethod` lookup the inliner uses, same depth guard against
/// mutually recursive helpers). Without it a public method whose only
/// var-length state read sits behind a helper silently skips `_codePart` and
/// falls back to the deploy-time constant instead of the live on-chain state.
fn methodReadsVarLenState(
    bindings: []const types.ANFBinding,
    properties: []const types.ANFProperty,
    methods: []const types.ANFMethod,
) bool {
    return methodReadsVarLenStateRec(bindings, properties, methods, 0);
}

fn methodReadsVarLenStateRec(
    bindings: []const types.ANFBinding,
    properties: []const types.ANFProperty,
    methods: []const types.ANFMethod,
    depth: u32,
) bool {
    if (depth > MAX_PREIMAGE_RECURSION_DEPTH) return false;
    for (bindings) |binding| {
        switch (binding.value) {
            .load_prop => |lp| {
                for (properties) |prop| {
                    if (!prop.readonly and prop.type_info == .byte_string and std.mem.eql(u8, prop.name, lp.name)) return true;
                }
            },
            .@"if" => |ie| {
                if (methodReadsVarLenStateRec(ie.then, properties, methods, depth) or
                    methodReadsVarLenStateRec(ie.@"else", properties, methods, depth)) return true;
            },
            .loop => |loop| {
                if (methodReadsVarLenStateRec(loop.body, properties, methods, depth)) return true;
            },
            .method_call => |mc| {
                if (findPrivateMethod(methods, mc.method)) |target| {
                    if (methodReadsVarLenStateRec(methodBindings(target), properties, methods, depth + 1)) return true;
                }
            },
            else => {},
        }
    }
    return false;
}

/// Combined `_codePart` requirement (issue #100): continuation builders OR
/// terminal methods that read a mutable variable-length state field. Gated on
/// checkPreimage so the SDK side (which provisions _codePart) stays in sync.
pub fn methodUsesCodePartFull(
    bindings: []const types.ANFBinding,
    properties: []const types.ANFProperty,
    methods: []const types.ANFMethod,
) bool {
    return methodUsesCheckPreimage(bindings, methods) and
        (methodUsesCodePart(bindings) or methodReadsVarLenState(bindings, properties, methods));
}


fn findPrivateMethod(methods: []const types.ANFMethod, name: []const u8) ?types.ANFMethod {
    for (methods) |method| {
        if (method.is_public or std.mem.eql(u8, method.name, "constructor")) continue;
        if (std.mem.eql(u8, method.name, name)) return method;
    }
    return null;
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
                // BUG-100 fix: no _opPushTxSig — signature derived on-chain from
                // the preimage (see lowerCheckPreimage).
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
            // CLEANSTACK: drop excess items left below the top-of-stack boolean.
            // cleanupExcessStack() is a no-op when depth <= 1, so running it for
            // every public method also fixes all-readonly stateful methods.
            if (method.is_public) {
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
            // CLEANSTACK: drop excess items left below the top-of-stack boolean.
            // cleanupExcessStack() is a no-op when depth <= 1, so running it for
            // every public method also fixes all-readonly stateful methods.
            if (method.is_public) {
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
            .value = .{ .call = .{
                .func = "checkSig",
                .args = &[_][]const u8{ "sig", "pubkey" },
            } },
        },
        .{
            .name = "t1",
            .value = .{ .assert = .{ .value = "t0" } },
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
            .value = .{ .bin_op = .{
                .op = "+",
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
        .{ .name = "t0", .value = .{ .load_const = .{ .value = .{ .integer = 42 } } } },
        .{ .name = "t1", .value = .{ .load_const = .{ .value = .{ .boolean = true } } } },
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
            .value = .{ .call = .{
                .func = "sha256",
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
            .value = .{ .call = .{
                .func = "sha256Compress",
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
            .value = .{ .call = .{
                .func = "sha256Finalize",
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
        .{ .name = "t_then", .value = .{ .load_const = .{ .value = .{ .integer = 1 } } } },
    };

    const else_bindings = [_]types.ANFBinding{
        .{ .name = "t_else", .value = .{ .load_const = .{ .value = .{ .integer = 0 } } } },
    };

    var if_expr = types.ANFIf{
        .cond = "cond",
        .then = @constCast(&then_bindings),
        .@"else" = @constCast(&else_bindings),
    };

    const bindings = [_]types.ANFBinding{
        .{ .name = "cond", .value = .{ .load_const = .{ .value = .{ .boolean = true } } } },
        .{ .name = "result", .value = .{ .@"if" = &if_expr } },
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
        .{ .name = "t_body", .value = .{ .load_const = .{ .value = .{ .integer = 99 } } } },
    };

    var loop_val = types.ANFLoop{
        .iter_var = "i",
        .count = 3,
        .body = @constCast(&loop_body),
    };

    const bindings = [_]types.ANFBinding{
        .{ .name = "loop_result", .value = .{ .loop = &loop_val } },
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

test "lower for loop keeps outer const alive across iterations (fix 5)" {
    // Regression: a const defined before the loop and referenced inside the
    // body (here via bin_op `base + i`) was consumed by the first iteration,
    // making iteration 2 fail with VariableNotFound. The deep outer-ref
    // collection now protects `base` across the non-final iterations.
    const allocator = std.testing.allocator;

    const loop_body = [_]types.ANFBinding{
        .{ .name = "t_sum", .value = .{ .bin_op = .{ .op = "+", .left = "base", .right = "i" } } },
    };

    var loop_val = types.ANFLoop{
        .iter_var = "i",
        .count = 3,
        .body = @constCast(&loop_body),
    };

    const bindings = [_]types.ANFBinding{
        .{ .name = "base", .value = .{ .load_const = .{ .value = .{ .integer = 5 } } } },
        .{ .name = "loop_result", .value = .{ .loop = &loop_val } },
    };

    const method = types.ANFMethod{
        .name = "looper",
        .is_public = true,
        .params = &.{},
        .bindings = @constCast(&bindings),
    };

    const program = types.ANFProgram{
        .contract_name = "OuterRefLooper",
        .properties = &.{},
        .methods = @constCast(&[_]types.ANFMethod{method}),
    };

    // Previously threw VariableNotFound on the second iteration; must now
    // lower cleanly.
    const result = try lower(allocator, program);
    defer result.deinit(allocator);
    try std.testing.expect(result.methods.len == 1);
    try std.testing.expect(result.methods[0].instructions.len > 0);
}

test "lower rejects load_param of a missing param instead of emitting OP_0 (fix 5)" {
    // Hand-written ANF referencing a parameter that is not on the stack.
    // The old fallback silently pushed OP_0 (producing scripts that passed
    // the interpreter but failed on chain); it must now hard-error.
    const allocator = std.testing.allocator;

    const bindings = [_]types.ANFBinding{
        .{ .name = "t0", .value = .{ .load_param = .{ .name = "ghost" } } },
        .{ .name = "t1", .value = .{ .assert = .{ .value = "t0" } } },
    };

    const method = types.ANFMethod{
        .name = "spend",
        .is_public = true,
        .params = &.{},
        .bindings = @constCast(&bindings),
    };

    const program = types.ANFProgram{
        .contract_name = "GhostParam",
        .properties = &.{},
        .methods = @constCast(&[_]types.ANFMethod{method}),
    };

    try std.testing.expectError(LowerError.SilentOpZeroRefused, lower(allocator, program));
}

test "lower rejects load_prop for a property with no constructor slot (H1)" {
    // #119 tail: a `load_prop` whose name is not a declared constructor-param
    // property used to be coerced onto slot 0, silently splicing an UNRELATED
    // constructor argument's placeholder into the locking script. It must now
    // hard-error instead. The contract has a real ctor-param property `pk`, and
    // the method reads a `ghost` property that is not declared at all.
    const allocator = std.testing.allocator;

    const bindings = [_]types.ANFBinding{
        .{
            .name = "t0",
            .value = .{ .load_prop = .{ .name = "ghost" } },
            .source_loc = .{ .file = "Ghost.runar.ts", .line = 7, .column = 4 },
        },
        .{ .name = "t1", .value = .{ .assert = .{ .value = "t0" } } },
    };

    var props = [_]types.ANFProperty{
        .{ .name = "pk", .type_name = "PubKey", .readonly = true },
    };
    var methods_arr = [_]types.ANFMethod{
        .{ .name = "spend", .is_public = true, .params = &.{}, .bindings = @constCast(&bindings) },
    };
    const program = types.ANFProgram{
        .contract_name = "Ghost",
        .properties = &props,
        .methods = &methods_arr,
    };

    try std.testing.expectError(LowerError.LoadPropNoConstructorSlot, lower(allocator, program));
}

test "lower accepts load_prop for a real constructor-param property (H1)" {
    // A genuine readonly constructor-param property has a deploy-time slot
    // (found == true) and must still lower to a placeholder without error.
    const allocator = std.testing.allocator;

    const bindings = [_]types.ANFBinding{
        .{ .name = "t0", .value = .{ .load_prop = .{ .name = "pk" } } },
        .{ .name = "t1", .value = .{ .assert = .{ .value = "t0" } } },
    };

    var props = [_]types.ANFProperty{
        .{ .name = "pk", .type_name = "PubKey", .readonly = true },
    };
    var methods_arr = [_]types.ANFMethod{
        .{ .name = "spend", .is_public = true, .params = &.{}, .bindings = @constCast(&bindings) },
    };
    const ctor_params = [_]types.ParamNode{
        .{ .name = "pk", .type_info = .pub_key },
    };
    const program = types.ANFProgram{
        .contract_name = "Ok",
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
}

test "lower multi-method produces one StackMethod per public method" {
    const allocator = std.testing.allocator;

    const bindings1 = [_]types.ANFBinding{
        .{ .name = "t0", .value = .{ .load_const = .{ .value = .{ .integer = 1 } } } },
    };
    const bindings2 = [_]types.ANFBinding{
        .{ .name = "t0", .value = .{ .load_const = .{ .value = .{ .integer = 2 } } } },
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

/// Test-only shim exposing the private state-property size calculation.
/// Kept together with the in-file tests that exercise it; not part of any
/// public compiler API.
fn testStatePropSize(t: types.RunarType) !i64 {
    return LowerCtx.statePropSize(.{ .name = "p", .type_info = t, .readonly = false });
}

test "statePropSize P384Point is 96 bytes" {
    try std.testing.expectEqual(@as(i64, 96), try testStatePropSize(.p384_point));
}

test "statePropSize P256Point is 64 bytes" {
    try std.testing.expectEqual(@as(i64, 64), try testStatePropSize(.p256_point));
}

test "statePropSize covers all fixed-size state types" {
    try std.testing.expectEqual(@as(i64, 8), try testStatePropSize(.bigint));
    try std.testing.expectEqual(@as(i64, 1), try testStatePropSize(.boolean));
    try std.testing.expectEqual(@as(i64, 20), try testStatePropSize(.addr));
    try std.testing.expectEqual(@as(i64, 20), try testStatePropSize(.ripemd160));
    try std.testing.expectEqual(@as(i64, 32), try testStatePropSize(.sha256));
    try std.testing.expectEqual(@as(i64, 33), try testStatePropSize(.pub_key));
    try std.testing.expectEqual(@as(i64, 64), try testStatePropSize(.point));
    try std.testing.expectEqual(@as(i64, 8), try testStatePropSize(.rabin_sig));
    try std.testing.expectEqual(@as(i64, 8), try testStatePropSize(.rabin_pub_key));
}

test "statePropSize covers all variable-length state types" {
    try std.testing.expectEqual(@as(i64, -1), try testStatePropSize(.byte_string));
    try std.testing.expectEqual(@as(i64, -1), try testStatePropSize(.sig));
    try std.testing.expectEqual(@as(i64, -1), try testStatePropSize(.sig_hash_preimage));
}

// --- Integration: stateful contracts with uncommon state types compile ---

fn loweredGetStateScript(allocator: std.mem.Allocator, prop_type: types.RunarType, type_name: []const u8) !types.StackProgram {
    const bindings = try allocator.dupe(types.ANFBinding, &[_]types.ANFBinding{
        .{ .name = "_state", .value = .{ .get_state_script = {} } },
        .{ .name = "t0", .value = .{ .assert = .{ .value = "_state" } } },
    });

    const props = try allocator.dupe(types.ANFProperty, &[_]types.ANFProperty{
        .{ .name = "field", .type_name = type_name, .type_info = prop_type, .readonly = false },
    });

    const methods = try allocator.dupe(types.ANFMethod, &[_]types.ANFMethod{
        .{ .name = "snapshot", .is_public = true, .params = &.{}, .bindings = bindings },
    });

    const program = types.ANFProgram{
        .contract_name = "S",
        .parent_class = .stateful_smart_contract,
        .properties = props,
        .methods = methods,
        .constructor = .{ .params = &.{}, .assertions = &.{} },
    };
    defer allocator.free(bindings);
    defer allocator.free(props);
    defer allocator.free(methods);
    return try lower(allocator, program);
}

test "stateful contract with RabinSig state property compiles" {
    const allocator = std.testing.allocator;
    const result = try loweredGetStateScript(allocator, .rabin_sig, "RabinSig");
    defer result.deinit(allocator);
    try std.testing.expect(result.methods.len == 1);
    try std.testing.expect(result.methods[0].instructions.len > 0);
}

test "stateful contract with Sig state property compiles" {
    const allocator = std.testing.allocator;
    const result = try loweredGetStateScript(allocator, .sig, "Sig");
    defer result.deinit(allocator);
    try std.testing.expect(result.methods.len == 1);
    try std.testing.expect(result.methods[0].instructions.len > 0);
}

test "stateful contract with Ripemd160 state property compiles" {
    const allocator = std.testing.allocator;
    const result = try loweredGetStateScript(allocator, .ripemd160, "Ripemd160");
    defer result.deinit(allocator);
    try std.testing.expect(result.methods.len == 1);
    try std.testing.expect(result.methods[0].instructions.len > 0);
}

test "stateful contract with P384Point state property compiles" {
    const allocator = std.testing.allocator;
    const result = try loweredGetStateScript(allocator, .p384_point, "P384Point");
    defer result.deinit(allocator);
    try std.testing.expect(result.methods.len == 1);
    try std.testing.expect(result.methods[0].instructions.len > 0);
}
