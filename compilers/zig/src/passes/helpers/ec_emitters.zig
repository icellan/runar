const std = @import("std");
const registry = @import("crypto_builtins.zig");
const opcodes = @import("../../codegen/opcodes.zig");
const comb = @import("comb.zig");

const Allocator = std.mem.Allocator;

pub const PushValue = union(enum) {
    bytes: []const u8,
    integer: i64,
    boolean: bool,
};

pub const StackIf = struct {
    then: []StackOp,
    @"else": ?[]StackOp = null,
};

pub const StackOp = union(enum) {
    push: PushValue,
    dup: void,
    swap: void,
    drop: void,
    nip: void,
    over: void,
    rot: void,
    tuck: void,
    roll: u32,
    pick: u32,
    opcode: []const u8,
    @"if": StackIf,
};

const FIELD_P_MINUS_2_LOW_BITS: u32 = 0xfffffc2d;

const field_p_be = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
};

const curve_n_be = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
};

const curve_3n_script_num_le = [_]u8{
    0xc3, 0xc3, 0xa2, 0x70, 0xa6, 0x1b, 0x77, 0x3f,
    0xb3, 0xe0, 0xd9, 0x0d, 0xb4, 0x96, 0x0c, 0x30,
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x02,
};

const gen_x_be = [_]u8{
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
};

const gen_y_be = [_]u8{
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
    0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
    0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
};

pub const EcEmitterError = anyerror;

/// Codegen options shared by every EC / NIST-curve emitter.
///
/// Off by default: with an all-false value each emitter is byte-identical to
/// what the seven tiers ship today, so no golden, size baseline, or cross-tier
/// parity gate can move.
pub const EcCodegenOptions = struct {
    /// Park large repeated constants (the field prime, the group order) in a
    /// stack slot and copy them with `OP_PICK` instead of re-pushing the
    /// literal.
    ///
    /// `fieldMod` pushes the 256-bit prime at every modular reduction — 34 bytes
    /// a time, 20,025 times in `p256-wallet` (71 % of that fixture). A pick from
    /// a slot a dozen deep costs 2.
    constant_pool: bool = false,

    /// Emit `a mod p` without the sign fix-up wherever the dividend is provably
    /// non-negative, and the cheap `a - b + p` form for subtraction wherever the
    /// subtrahend is provably reduced.
    ///
    /// Which reductions qualify is decided by the sign lattice below — never
    /// assumed. Only useful alongside `constant_pool`: the cheap subtraction
    /// references the prime twice, so without a pooled slot it does not pay (and
    /// the emitters compare the two costs, so it is never taken when it does
    /// not).
    reduction_sinking: bool = false,

    /// Use a fixed-base comb instead of the binary ladder wherever the base
    /// point is a compile-time constant. The window width is not fixed here: the
    /// emitter renders each candidate and keeps whichever the byte-cost model
    /// scores smallest.
    fixed_base_comb: bool = false,

    pub fn any(self: EcCodegenOptions) bool {
        return self.constant_pool or self.reduction_sinking or self.fixed_base_comb;
    }
};

/// What is known about a tracked value's sign and range.
///
/// `.reduced` implies `.non_negative`; the ordering is what the transfer
/// functions meet over. `.unknown` is the default for every slot the analysis
/// has not explicitly proved something about — including everything a `rawBlock`
/// or an `OP_IF` produces — so an un-analysed value can only ever fall back to
/// the shipping reduction.
///
/// The distinction is not academic. `OP_BIN2NUM` of 32 unsigned coordinate bytes
/// gives `.non_negative` but NOT `.reduced`: a coordinate may legitimately be up
/// to `2^256 - 1` while p is `2^32 + 977` smaller. Multiplication and addition
/// need only `.non_negative`; subtraction's cheap form needs the subtrahend
/// `.reduced`, and conflating the two produces a script that passes 256 EC
/// oracle assertions and is still wrong on `ecAdd((0,1), (2^256-1,1))`.
pub const Dom = enum(u2) {
    /// Nothing known. May be negative.
    unknown = 0,
    /// Provably >= 0. May be >= p.
    non_negative = 1,
    /// Provably in [0, p).
    reduced = 2,

    /// True when this proves the value is >= 0.
    pub fn isNonNegative(self: Dom) bool {
        return self != .unknown;
    }
};

/// Stack slot names reserved for pooled constants.
pub const POOL_FIELD_P = "_pool$p";

/// Length of the field prime's unsigned script-number encoding.
///
/// secp256k1's p is 32 big-endian bytes whose most significant byte is 0xff, so
/// the little-endian sign-magnitude form needs a trailing 0x00 sign byte: 33.
/// Used by `cheapSubPays` to price the pooled constant without allocating.
pub const FIELD_P_SCRIPT_NUM_LEN: usize = 33;
pub const POOL_GROUP_N = "_pool$n";


pub const EcOpBundle = struct {
    allocator: Allocator,
    ops: []StackOp,
    owned_bytes: [][]u8,

    pub fn deinit(self: *EcOpBundle) void {
        deinitOpsRecursive(self.allocator, self.ops);
        self.allocator.free(self.ops);
        for (self.owned_bytes) |bytes| self.allocator.free(bytes);
        self.allocator.free(self.owned_bytes);
        self.* = undefined;
    }
};

pub fn buildBuiltinOps(allocator: Allocator, builtin: registry.CryptoBuiltin) EcEmitterError!EcOpBundle {
    return buildBuiltinOpsOpts(allocator, builtin, .{});
}

/// `buildBuiltinOps` with the EXPERIMENTAL EC script-size options.
///
/// An all-false value keeps every emitter byte-identical to the shipping output;
/// see `EcCodegenOptions` and docs/experiments/script-size-optimizer-results.md.
pub fn buildBuiltinOpsOpts(
    allocator: Allocator,
    builtin: registry.CryptoBuiltin,
    opts: EcCodegenOptions,
) EcEmitterError!EcOpBundle {
    var tracker = try ECTracker.initOpts(allocator, initialNames(builtin), opts, null);
    errdefer tracker.deinit();

    switch (builtin) {
        .ec_add => try emitEcAdd(&tracker),
        .ec_mul => try emitEcMul(&tracker, "_pt", "_k"),
        .ec_mul_gen => try emitEcMulGen(&tracker),
        .ec_negate => try emitEcNegate(&tracker),
        .ec_on_curve => try emitEcOnCurve(&tracker),
        else => return error.UnsupportedBuiltin,
    }

    return tracker.takeBundle();
}

pub fn appendBuiltinOps(
    list: *std.ArrayListUnmanaged(StackOp),
    allocator: Allocator,
    builtin: registry.CryptoBuiltin,
) EcEmitterError!EcOpBundle {
    var bundle = try buildBuiltinOps(allocator, builtin);
    errdefer bundle.deinit();
    try list.appendSlice(allocator, bundle.ops);
    return bundle;
}

pub fn deinitOpsRecursive(allocator: Allocator, ops: []StackOp) void {
    for (ops) |*op| {
        switch (op.*) {
            .@"if" => |stack_if| {
                deinitOpsRecursive(allocator, stack_if.then);
                allocator.free(stack_if.then);
                if (stack_if.@"else") |else_ops| {
                    deinitOpsRecursive(allocator, else_ops);
                    allocator.free(else_ops);
                }
            },
            else => {},
        }
    }
}


// ---------------------------------------------------------------------------
// Byte-cost helpers for the constant pool
// ---------------------------------------------------------------------------
//
// These route through the SAME encoders `emit.zig` uses, so the pool's
// cheaper-of-two comparison is exact rather than estimated and can never make a
// call site bigger. `ec_cost_model.zig` is the full model and is pinned against
// the real emitter over every EC emitter; these two are the slice of it the
// tracker itself needs, and are the same functions that model calls.

/// A writer that counts bytes and discards them.
const CostWriter = struct {
    n: usize = 0,

    pub const Error = error{};

    pub fn writeByte(self: *CostWriter, _: u8) Error!void {
        self.n += 1;
    }

    pub fn writeAll(self: *CostWriter, bytes: []const u8) Error!void {
        self.n += bytes.len;
    }

    pub fn writeInt(self: *CostWriter, comptime T: type, _: T, _: std.builtin.Endian) Error!void {
        self.n += @sizeOf(T);
    }
};

/// Serialized byte cost of a bare script number.
pub fn scriptNumberCost(n: i64) usize {
    var w = CostWriter{};
    opcodes.encodeScriptNumber(&w, n) catch unreachable;
    return w.n;
}

/// Serialized byte cost of pushing `len` bytes of push data.
pub fn pushDataCost(len: usize) usize {
    if (len == 0) return 1;
    if (len <= 75) return 1 + len;
    if (len <= 255) return 2 + len;
    if (len <= 65535) return 3 + len;
    return 5 + len;
}

/// Serialized byte cost of a single push value.
pub fn sizeOfPushValue(pv: PushValue) usize {
    return switch (pv) {
        .bytes => |data| pushDataCost(data.len),
        .integer => |n| scriptNumberCost(n),
        // OP_TRUE (0x51) / OP_FALSE (0x00).
        .boolean => 1,
    };
}

/// Serialized byte cost of one Stack IR operation, including nested `if` arms.
///
/// ONE THING DIFFERS FROM THE OTHER TIERS. There the tracker emits a separate
/// depth `push` op immediately before a `roll` / `pick`, and the cost model
/// charges the roll ONE byte so the depth is not double-counted. This tier's
/// `StackOp.roll` / `.pick` carry the depth in the op itself and `emitStackOp`
/// writes the depth push as part of emitting them — so here they cost
/// `scriptNumberCost(depth) + 1`. Same emitted bytes; the cost-model test is
/// what keeps the two spellings honest.
pub fn sizeOfStackOp(op: StackOp) usize {
    return switch (op) {
        .push => |pv| sizeOfPushValue(pv),
        .dup, .swap, .drop, .nip, .over, .rot, .tuck => 1,
        .roll => |d| scriptNumberCost(@intCast(d)) + 1,
        .pick => |d| scriptNumberCost(@intCast(d)) + 1,
        .opcode => 1,
        // OP_IF + then + [OP_ELSE + else] + OP_ENDIF. The emitter writes
        // OP_ELSE only for a NON-EMPTY else arm.
        .@"if" => |if_op| blk: {
            var total: usize = 2;
            total += estimateScriptBytes(if_op.then);
            if (if_op.@"else") |else_ops| {
                if (else_ops.len > 0) total += 1 + estimateScriptBytes(else_ops);
            }
            break :blk total;
        },
    };
}

/// Serialized byte cost of a Stack IR sequence.
pub fn estimateScriptBytes(ops: []const StackOp) usize {
    var total: usize = 0;
    for (ops) |op| total += sizeOfStackOp(op);
    return total;
}

/// Named stack-state tracker, shared with `nist_ec_emitters.zig`.
///
/// It is `pub` for exactly that reason. The NIST emitters kept their own copy
/// until this port; two independently-maintained copies of a sign lattice are
/// two chances to prove `.reduced` where only `.non_negative` holds, and the
/// resulting script is smaller, passes every local test, and is wrong. The
/// curve-specific parts (prime, order, coordinate width) are function
/// parameters over there, not tracker state, so one tracker serves both.
pub const ECTracker = struct {
    allocator: Allocator,
    names: std.ArrayListUnmanaged(?[]const u8),
    /// Sign-lattice fact per stack SLOT, kept parallel to `names`.
    ///
    /// Slot-parallel rather than keyed by name on purpose: names are reused
    /// (`_fmul_prod` is written by every multiply) and the same name can be
    /// resident twice, so a name-keyed map would go stale in exactly the cases
    /// that matter. Every mutation of `names` below mirrors into `doms` with the
    /// same splice, so the two cannot drift.
    doms: std.ArrayListUnmanaged(Dom),
    /// Lattice facts for values parked on the alt stack, bottom -> top.
    alt_doms: std.ArrayListUnmanaged(Dom),
    ops: std.ArrayListUnmanaged(StackOp),
    owned_bytes: std.ArrayListUnmanaged([]u8),
    /// Heap copies of generated slot names (`_Tx3`, `_eq5`, ...).
    ///
    /// The comb builds names by formatting into a stack buffer, which would
    /// dangle the moment the buffer is reused. `internName` copies into here and
    /// the copies live exactly as long as the tracker's name list does — nothing
    /// in the emitted ops refers to them.
    owned_names: std.ArrayListUnmanaged([]u8),
    opts: EcCodegenOptions,

    fn init(allocator: Allocator, initial_names: []const ?[]const u8) !ECTracker {
        return initOpts(allocator, initial_names, .{}, null);
    }

    /// Create a tracker carrying codegen options and, optionally, initial
    /// lattice facts for the pre-existing slots.
    pub fn initOpts(
        allocator: Allocator,
        initial_names: []const ?[]const u8,
        opts: EcCodegenOptions,
        initial_doms: ?[]const Dom,
    ) !ECTracker {
        var names: std.ArrayListUnmanaged(?[]const u8) = .empty;
        errdefer names.deinit(allocator);
        try names.appendSlice(allocator, initial_names);
        var doms: std.ArrayListUnmanaged(Dom) = .empty;
        errdefer doms.deinit(allocator);
        if (initial_doms) |d| {
            try doms.appendSlice(allocator, d);
        } else {
            try doms.appendNTimes(allocator, .unknown, initial_names.len);
        }
        return .{
            .allocator = allocator,
            .names = names,
            .doms = doms,
            .alt_doms = .empty,
            .ops = .empty,
            .owned_bytes = .empty,
            .owned_names = .empty,
            .opts = opts,
        };
    }

    pub fn deinit(self: *ECTracker) void {
        deinitOpsRecursive(self.allocator, self.ops.items);
        self.ops.deinit(self.allocator);
        self.names.deinit(self.allocator);
        self.doms.deinit(self.allocator);
        self.alt_doms.deinit(self.allocator);
        for (self.owned_bytes.items) |bytes| self.allocator.free(bytes);
        self.owned_bytes.deinit(self.allocator);
        for (self.owned_names.items) |name| self.allocator.free(name);
        self.owned_names.deinit(self.allocator);
    }

    /// Copy a formatted slot name into tracker-owned storage.
    pub fn internName(self: *ECTracker, name: []const u8) ![]const u8 {
        const copy = try self.allocator.dupe(u8, name);
        try self.owned_names.append(self.allocator, copy);
        return copy;
    }

    // -- sign lattice --------------------------------------------------------

    /// What is known about the named value. `.unknown` when the name is absent.
    pub fn domainOf(self: *const ECTracker, name: []const u8) Dom {
        // A silent desync here would hand a transfer function a fact about the
        // WRONG slot, which is the one failure mode that produces a smaller
        // script that quietly computes something else. Fail loudly instead.
        std.debug.assert(self.doms.items.len == self.names.items.len);
        var i = self.names.items.len;
        while (i > 0) {
            i -= 1;
            const slot = self.names.items[i] orelse continue;
            if (std.mem.eql(u8, slot, name)) return self.doms.items[i];
        }
        return .unknown;
    }

    /// Record a fact about the named value's slot.
    pub fn setDomain(self: *ECTracker, name: []const u8, d: Dom) void {
        var i = self.names.items.len;
        while (i > 0) {
            i -= 1;
            const slot = self.names.items[i] orelse continue;
            if (std.mem.eql(u8, slot, name)) {
                self.doms.items[i] = d;
                return;
            }
        }
    }

    /// Push a slot the caller tracks itself (used where raw opcodes create items).
    pub fn pushTracked(self: *ECTracker, name: ?[]const u8, d: Dom) !void {
        try self.names.append(self.allocator, name);
        try self.doms.append(self.allocator, d);
    }

    /// Pop a slot the caller tracks itself. Mirror of `pushTracked`.
    pub fn popTracked(self: *ECTracker) void {
        if (self.names.items.len == 0) return;
        _ = self.names.pop();
        _ = self.doms.pop();
    }

    /// Remove the slot at an absolute (bottom-relative) index.
    pub fn removeSlotAt(self: *ECTracker, index: usize) struct { name: ?[]const u8, dom: Dom } {
        const n = self.names.orderedRemove(index);
        const d = self.doms.orderedRemove(index);
        return .{ .name = n, .dom = d };
    }

    pub fn takeBundle(self: *ECTracker) !EcOpBundle {
        const ops = try self.ops.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(ops);
        const owned_bytes = try self.owned_bytes.toOwnedSlice(self.allocator);
        self.names.deinit(self.allocator);
        self.doms.deinit(self.allocator);
        self.alt_doms.deinit(self.allocator);
        // Names are referenced only while building; nothing in `ops` points at
        // them, so they can go now rather than riding along in the bundle.
        for (self.owned_names.items) |name| self.allocator.free(name);
        self.owned_names.deinit(self.allocator);
        self.names = .empty;
        self.doms = .empty;
        self.alt_doms = .empty;
        self.owned_names = .empty;
        self.ops = .empty;
        self.owned_bytes = .empty;
        return .{
            .allocator = self.allocator,
            .ops = ops,
            .owned_bytes = owned_bytes,
        };
    }

    fn depth(self: *const ECTracker) usize {
        return self.names.items.len;
    }

    pub fn findDepth(self: *const ECTracker, name: []const u8) !usize {
        var i = self.names.items.len;
        while (i > 0) {
            i -= 1;
            const slot = self.names.items[i] orelse continue;
            if (std.mem.eql(u8, slot, name)) {
                return self.names.items.len - 1 - i;
            }
        }
        return error.UnsupportedBuiltin;
    }

    pub fn emitRaw(self: *ECTracker, op: StackOp) !void {
        try self.ops.append(self.allocator, op);
    }

    pub fn emitOpcode(self: *ECTracker, code: []const u8) !void {
        try self.emitRaw(.{ .opcode = code });
    }

    pub fn emitPushIntRaw(self: *ECTracker, value: i64) !void {
        try self.emitRaw(.{ .push = .{ .integer = value } });
    }

    pub fn emitPushBytesRaw(self: *ECTracker, value: []const u8) !void {
        try self.emitRaw(.{ .push = .{ .bytes = value } });
    }

    pub fn pushInt(self: *ECTracker, name: ?[]const u8, value: i64) !void {
        try self.emitPushIntRaw(value);
        try self.pushTracked(name, if (value >= 0) .non_negative else .unknown);
    }

    pub fn pushOwnedBytes(self: *ECTracker, name: ?[]const u8, value: []u8) !void {
        try self.owned_bytes.append(self.allocator, value);
        try self.emitPushBytesRaw(value);
        // A byte blob is not a number until BIN2NUM decides how to read it.
        try self.pushTracked(name, .unknown);
    }

    pub fn pushStaticBytes(self: *ECTracker, name: ?[]const u8, value: []const u8) !void {
        try self.emitPushBytesRaw(value);
        try self.pushTracked(name, .unknown);
    }

    pub fn dup(self: *ECTracker, name: ?[]const u8) !void {
        try self.emitRaw(.{ .dup = {} });
        const d: Dom = if (self.doms.items.len > 0) self.doms.items[self.doms.items.len - 1] else .unknown;
        try self.pushTracked(name, d);
    }

    pub fn drop(self: *ECTracker) !void {
        try self.emitRaw(.{ .drop = {} });
        self.popTracked();
    }

    pub fn swap(self: *ECTracker) !void {
        try self.emitRaw(.{ .swap = {} });
        const len = self.names.items.len;
        if (len >= 2) {
            const tmp = self.names.items[len - 1];
            self.names.items[len - 1] = self.names.items[len - 2];
            self.names.items[len - 2] = tmp;
            const dtmp = self.doms.items[len - 1];
            self.doms.items[len - 1] = self.doms.items[len - 2];
            self.doms.items[len - 2] = dtmp;
        }
    }

    pub fn rot(self: *ECTracker) !void {
        try self.emitRaw(.{ .rot = {} });
        const len = self.names.items.len;
        if (len >= 3) {
            const rolled = self.removeSlotAt(len - 3);
            try self.pushTracked(rolled.name, rolled.dom);
        }
    }

    pub fn over(self: *ECTracker, name: ?[]const u8) !void {
        try self.emitRaw(.{ .over = {} });
        const d: Dom = if (self.doms.items.len >= 2) self.doms.items[self.doms.items.len - 2] else .unknown;
        try self.pushTracked(name, d);
    }

    pub fn roll(self: *ECTracker, depth_from_top: usize) !void {
        if (depth_from_top == 0) return;
        if (depth_from_top == 1) return self.swap();
        if (depth_from_top == 2) return self.rot();
        try self.emitRaw(.{ .roll = @intCast(depth_from_top) });
        const idx = self.names.items.len - 1 - depth_from_top;
        const rolled = self.removeSlotAt(idx);
        try self.pushTracked(rolled.name, rolled.dom);
    }

    pub fn pick(self: *ECTracker, depth_from_top: usize, name: ?[]const u8) !void {
        if (depth_from_top == 0) return self.dup(name);
        if (depth_from_top == 1) return self.over(name);
        try self.emitRaw(.{ .pick = @intCast(depth_from_top) });
        // The copied slot sits at depth `depth_from_top` from the top.
        const src: Dom = if (self.doms.items.len > depth_from_top)
            self.doms.items[self.doms.items.len - 1 - depth_from_top]
        else
            .unknown;
        try self.pushTracked(name, src);
    }

    pub fn toTop(self: *ECTracker, name: []const u8) !void {
        try self.roll(try self.findDepth(name));
    }

    pub fn copyToTop(self: *ECTracker, name: []const u8, copy_name: ?[]const u8) !void {
        try self.pick(try self.findDepth(name), copy_name);
    }

    pub fn renameTop(self: *ECTracker, name: ?[]const u8) void {
        if (self.names.items.len > 0) {
            self.names.items[self.names.items.len - 1] = name;
        }
    }

    pub fn popNames(self: *ECTracker, count: usize) void {
        var i: usize = 0;
        while (i < count and self.names.items.len > 0) : (i += 1) {
            self.popTracked();
        }
    }

    pub fn rawBlock(
        self: *ECTracker,
        consume_count: usize,
        produce_name: ?[]const u8,
        body: *const fn (*ECTracker) anyerror!void,
    ) !void {
        self.popNames(consume_count);
        try body(self);
        if (produce_name) |name| {
            // Opaque opcodes: nothing is known about the result unless the
            // caller proves it and records that with `setDomain` afterwards.
            try self.pushTracked(name, .unknown);
        }
    }

    // -- constant pool -------------------------------------------------------
    //
    // A pooled constant is an ordinary tracked slot; nothing about the stack
    // model changes. `pushConst` just chooses, per call site and by emitted
    // bytes, between copying that slot and re-pushing the literal. Nested
    // trackers seeded from `names.items` inherit the slot for free, so pooled
    // constants work unchanged inside an `OP_IF` arm.

    pub fn hasSlot(self: *const ECTracker, slot: []const u8) bool {
        for (self.names.items) |n| {
            const name = n orelse continue;
            if (std.mem.eql(u8, name, slot)) return true;
        }
        return false;
    }

    /// Park the script-number encoding of `value_be` in `slot` for the lifetime
    /// of this emitter. No-op when pooling is off.
    ///
    /// The slot carries `.non_negative`, not `.unknown`. The reference spells
    /// this `pushInt(slot, value)`, whose fact for a positive literal is
    /// NonNegative; here the constant arrives as a byte slice, and
    /// `pushOwnedBytes`'s blanket `.unknown` — "a byte blob is not a number
    /// until BIN2NUM reads it" — is the wrong default for a value that already
    /// IS a script number. Every `pick` off this slot inherits the fact.
    ///
    /// Measured: it moves no bytes today, on either curve family, under any flag
    /// combination — no emitter currently passes a pooled constant as the
    /// operand of a reduction that consults the lattice. It is stated anyway,
    /// because the tracker is now shared with the NIST emitters and a fact that
    /// quietly disagrees with the reference is the exact shape of divergence
    /// this port is gated against.
    pub fn poolConstant(self: *ECTracker, slot: []const u8, value_be: []const u8) !void {
        if (!self.opts.constant_pool or self.hasSlot(slot)) return;
        const encoded = try beToUnsignedScriptNumAlloc(self.allocator, value_be);
        try self.pushOwnedBytes(slot, encoded);
        self.setDomain(slot, .non_negative);
    }

    /// Remove a pooled slot. No-op when pooling is off or the slot is absent.
    pub fn releaseConstant(self: *ECTracker, slot: []const u8) !void {
        if (!self.opts.constant_pool or !self.hasSlot(slot)) return;
        try self.toTop(slot);
        try self.drop();
    }

    /// Emitted bytes a `pushConst` of this constant would cost right now.
    ///
    /// The comparison is exact — the same encoders the emit pass uses — so
    /// pooling can never make a call site bigger. A pick at depth d costs
    /// `sizeOfScriptNumber(d) + 1`; depths 0 and 1 are OP_DUP / OP_OVER,
    /// 1 byte each.
    pub fn constCost(self: *const ECTracker, slot: []const u8, encoded_len: usize) usize {
        const literal = pushDataCost(encoded_len);
        if (self.opts.constant_pool and self.hasSlot(slot)) {
            const d = self.findDepth(slot) catch return literal;
            const pick_cost: usize = if (d <= 1) 1 else scriptNumberCost(@intCast(d)) + 1;
            if (pick_cost < literal) return pick_cost;
        }
        return literal;
    }

    /// Materialize the constant on top as `name`, from the pooled slot when that
    /// is cheaper in emitted bytes than pushing the literal.
    ///
    /// `.non_negative` on both paths, for the reason `poolConstant` gives — the
    /// picked copy inherits the fact from the slot, the literal needs it stated
    /// here.
    pub fn pushConst(self: *ECTracker, slot: []const u8, value_be: []const u8, name: []const u8) !void {
        const encoded = try beToUnsignedScriptNumAlloc(self.allocator, value_be);
        if (self.opts.constant_pool and self.hasSlot(slot)) {
            const d = try self.findDepth(slot);
            const pick_cost: usize = if (d <= 1) 1 else scriptNumberCost(@intCast(d)) + 1;
            if (pick_cost < pushDataCost(encoded.len)) {
                self.allocator.free(encoded);
                try self.pick(d, name);
                return;
            }
        }
        try self.pushOwnedBytes(name, encoded);
        self.setDomain(name, .non_negative);
    }

    pub fn toAlt(self: *ECTracker) !void {
        try self.emitOpcode("OP_TOALTSTACK");
        if (self.names.items.len == 0) return;
        const d = self.doms.items[self.doms.items.len - 1];
        self.popTracked();
        try self.alt_doms.append(self.allocator, d);
    }

    pub fn fromAlt(self: *ECTracker, name: ?[]const u8) !void {
        try self.emitOpcode("OP_FROMALTSTACK");
        const d: Dom = if (self.alt_doms.items.len > 0) self.alt_doms.pop().? else .unknown;
        try self.pushTracked(name, d);
    }
};

fn initialNames(builtin: registry.CryptoBuiltin) []const ?[]const u8 {
    return switch (builtin) {
        .ec_add => &.{ "_pa", "_pb" },
        .ec_mul => &.{ "_pt", "_k" },
        .ec_mul_gen => &.{ "_k" },
        .ec_negate => &.{ "_pt" },
        .ec_on_curve => &.{ "_pt" },
        else => &.{},
    };
}

fn emitNumEqualOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_NUMEQUAL");
}

fn emitAddOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_ADD");
}


fn emitSubOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_SUB");
}

fn emitMulOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_MUL");
}

fn emitCatOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_CAT");
}

fn emitEqualOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_EQUAL");
}

fn emitDivOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_DIV");
}

fn emit2DivOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_2DIV");
}

fn emitRshiftnumOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_RSHIFTNUM");
}

fn emitModOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_MOD");
}

fn emit0NotEqualOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_0NOTEQUAL");
}

fn emitLessThanOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_LESSTHAN");
}

fn emitBoolAndOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_BOOLAND");
}

fn emitSubNotSequence(t: *ECTracker) !void {
    try t.emitOpcode("OP_SUB");
    try t.emitOpcode("OP_NOT");
}

fn emitFieldModSequence(t: *ECTracker) !void {
    try t.emitOpcode("OP_2DUP");
    try t.emitOpcode("OP_MOD");
    try t.emitRaw(.{ .rot = {} });
    try t.emitRaw(.{ .drop = {} });
    try t.emitRaw(.{ .over = {} });
    try t.emitOpcode("OP_ADD");
    try t.emitRaw(.{ .swap = {} });
    try t.emitOpcode("OP_MOD");
}

fn emitSplit32Sequence(t: *ECTracker) !void {
    try t.emitPushIntRaw(32);
    try t.emitOpcode("OP_SPLIT");
}

fn emitBytesToUnsignedNumSequence(t: *ECTracker) !void {
    try emitReverse32Raw(t);
    try t.emitPushBytesRaw(&.{0x00});
    try t.emitOpcode("OP_CAT");
    try t.emitOpcode("OP_BIN2NUM");
}

fn emitUnsignedNumToBigEndianBytes32Sequence(t: *ECTracker) !void {
    try t.emitPushIntRaw(33);
    try t.emitOpcode("OP_NUM2BIN");
    try t.emitPushIntRaw(32);
    try t.emitOpcode("OP_SPLIT");
    try t.emitRaw(.{ .drop = {} });
    try emitReverse32Raw(t);
}

fn emitReverse32Raw(t: *ECTracker) !void {
    try t.emitOpcode("OP_0");
    try t.emitRaw(.{ .swap = {} });
    for (0..32) |_| {
        try t.emitPushIntRaw(1);
        try t.emitOpcode("OP_SPLIT");
        try t.emitRaw(.{ .rot = {} });
        try t.emitRaw(.{ .rot = {} });
        try t.emitRaw(.{ .swap = {} });
        try t.emitOpcode("OP_CAT");
        try t.emitRaw(.{ .swap = {} });
    }
    try t.emitRaw(.{ .drop = {} });
}

pub fn beToUnsignedScriptNumAlloc(allocator: Allocator, be: []const u8) ![]u8 {
    var first: usize = 0;
    while (first < be.len and be[first] == 0) : (first += 1) {}
    if (first == be.len) {
        return allocator.dupe(u8, &.{});
    }

    const trimmed = be[first..];
    const needs_sign_byte = (trimmed[0] & 0x80) != 0;
    const out_len = trimmed.len + @as(usize, if (needs_sign_byte) 1 else 0);
    const out = try allocator.alloc(u8, out_len);
    for (trimmed, 0..) |_, idx| {
        out[idx] = trimmed[trimmed.len - 1 - idx];
    }
    if (needs_sign_byte) out[out_len - 1] = 0;
    return out;
}

fn pow2ScriptNumAlloc(allocator: Allocator, bit: usize) ![]u8 {
    const byte_index = bit / 8;
    const byte_mask: u8 = @as(u8, 1) << @intCast(bit % 8);
    const needs_sign_byte = byte_mask == 0x80;
    const out_len = byte_index + 1 + @as(usize, if (needs_sign_byte) 1 else 0);
    const out = try allocator.alloc(u8, out_len);
    @memset(out, 0);
    out[byte_index] = byte_mask;
    return out;
}

fn pushFieldPNum(t: *ECTracker, name: []const u8) !void {
    try t.pushConst(POOL_FIELD_P, field_p_be[0..], name);
}

fn pushCurveNNum(t: *ECTracker, name: []const u8) !void {
    try t.pushConst(POOL_GROUP_N, curve_n_be[0..], name);
}

fn pushPow2Divisor(t: *ECTracker, name: []const u8, bit: usize) !void {
    if (bit <= 4) {
        const value: i64 = @as(i64, 1) << @intCast(bit);
        try t.pushInt(name, value);
        return;
    }
    const encoded = try pow2ScriptNumAlloc(t.allocator, bit);
    try t.pushOwnedBytes(name, encoded);
}

fn generatorPointAlloc(allocator: Allocator) ![]u8 {
    const point = try allocator.alloc(u8, 64);
    @memcpy(point[0..32], gen_x_be[0..]);
    @memcpy(point[32..64], gen_y_be[0..]);
    return point;
}

/// `a mod p` with no sign fix-up: 1 opcode instead of 7.
///
/// Sound only when the dividend is provably >= 0, because `OP_MOD` takes the
/// sign of the dividend. The caller proves that; this function does not check.
fn fieldModShort(t: *ECTracker, a_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try pushFieldPNum(t, "_fmods_p");
    try t.rawBlock(2, result_name, emitModOpcode);
    t.setDomain(result_name, .reduced);
}

/// Does the cheap `a - b + p` subtraction shape pay here?
///
/// It references the prime TWICE where the shipping shape references it once and
/// pays six more opcodes, so it only wins when the prime is cheap to materialise
/// — i.e. when it is pooled. Without a pool this rewrite makes p256-wallet
/// LARGER (958,792 -> 999,371 measured), which is why it is a cost comparison
/// and not a flag.
fn cheapSubPays(t: *const ECTracker) bool {
    const c = t.constCost(POOL_FIELD_P, FIELD_P_SCRIPT_NUM_LEN);
    return 2 * c + 2 < c + 8;
}

fn fieldMod(t: *ECTracker, a_name: []const u8, result_name: []const u8) !void {
    if (t.opts.reduction_sinking and t.domainOf(a_name).isNonNegative()) {
        try fieldModShort(t, a_name, result_name);
        return;
    }
    try t.toTop(a_name);
    try pushFieldPNum(t, "_fmod_p");
    try t.rawBlock(2, result_name, emitFieldModSequence);
    t.setDomain(result_name, .reduced);
}

fn fieldAdd(t: *ECTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    // Read the operand facts BEFORE rawBlock consumes their slots.
    const sum_non_neg = t.domainOf(a_name).isNonNegative() and t.domainOf(b_name).isNonNegative();
    try t.toTop(a_name);
    try t.toTop(b_name);
    try t.rawBlock(2, "_fadd_sum", emitAddOpcode);
    if (sum_non_neg) t.setDomain("_fadd_sum", .non_negative);
    try fieldMod(t, "_fadd_sum", result_name);
}

fn fieldSub(t: *ECTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    // The cheap shape needs a >= 0 AND b in [0, p): then a - b > -p, so a single
    // shifted reduction is exact. `b >= 0` alone is NOT enough — a coordinate
    // decoded from 32 unsigned bytes can exceed p by up to 2^32 + 977, which is
    // precisely the `ecAdd((0,1), (2^256-1,1))` counterexample.
    const cheap = t.opts.reduction_sinking and
        t.domainOf(a_name).isNonNegative() and
        t.domainOf(b_name) == .reduced and
        cheapSubPays(t);

    try t.rawBlock(2, "_fsub_diff", emitSubOpcode);

    if (cheap) {
        try pushFieldPNum(t, "_fsub_p");
        try t.rawBlock(2, "_fsub_shift", emitAddOpcode);
        t.setDomain("_fsub_shift", .non_negative);
        try fieldModShort(t, "_fsub_shift", result_name);
        return;
    }
    try fieldMod(t, "_fsub_diff", result_name);
}

fn fieldMul(t: *ECTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try fieldMulSigned(t, a_name, b_name, result_name, false);
}

/// `fieldMul` with an explicit assertion about the product's sign, independent
/// of the operands — `fieldSqr` uses it, since a*a >= 0 for any a whatsoever.
fn fieldMulSigned(
    t: *ECTracker,
    a_name: []const u8,
    b_name: []const u8,
    result_name: []const u8,
    product_non_negative: bool,
) !void {
    const non_neg = product_non_negative or
        (t.domainOf(a_name).isNonNegative() and t.domainOf(b_name).isNonNegative());
    try t.toTop(a_name);
    try t.toTop(b_name);
    try t.rawBlock(2, "_fmul_prod", emitMulOpcode);
    if (non_neg) t.setDomain("_fmul_prod", .non_negative);
    try fieldMod(t, "_fmul_prod", result_name);
}

fn emit2MulOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_2MUL");
}

fn fieldMulConst(t: *ECTracker, a_name: []const u8, c: i64, result_name: []const u8) !void {
    // Every call site passes a small positive c, so the product keeps a's sign.
    const non_neg = c > 0 and t.domainOf(a_name).isNonNegative();
    try t.toTop(a_name);
    if (c == 2) {
        // Use OP_2MUL (single opcode, no push needed)
        try t.rawBlock(1, "_fmc_prod", emit2MulOpcode);
    } else {
        try t.pushInt("_fmc_c", c);
        try t.rawBlock(2, "_fmc_prod", emitMulOpcode);
    }
    if (non_neg) t.setDomain("_fmc_prod", .non_negative);
    try fieldMod(t, "_fmc_prod", result_name);
}

/// `(a * a) mod p`. A square is non-negative whatever a's sign is.
fn fieldSqr(t: *ECTracker, a_name: []const u8, result_name: []const u8) !void {
    try t.copyToTop(a_name, "_fsqr_copy");
    try fieldMulSigned(t, a_name, "_fsqr_copy", result_name, true);
}

fn fieldInv(t: *ECTracker, a_name: []const u8, result_name: []const u8) !void {
    try t.copyToTop(a_name, "_inv_r");

    var i: usize = 0;
    while (i < 222) : (i += 1) {
        try fieldSqr(t, "_inv_r", "_inv_r2");
        t.renameTop("_inv_r");
        try t.copyToTop(a_name, "_inv_a");
        try fieldMul(t, "_inv_r", "_inv_a", "_inv_m");
        t.renameTop("_inv_r");
    }

    try fieldSqr(t, "_inv_r", "_inv_r2");
    t.renameTop("_inv_r");

    var bit: i32 = 31;
    while (bit >= 0) : (bit -= 1) {
        try fieldSqr(t, "_inv_r", "_inv_r2");
        t.renameTop("_inv_r");
        if (((FIELD_P_MINUS_2_LOW_BITS >> @intCast(bit)) & 1) != 0) {
            try t.copyToTop(a_name, "_inv_a");
            try fieldMul(t, "_inv_r", "_inv_a", "_inv_m");
            t.renameTop("_inv_r");
        }
    }

    try t.toTop(a_name);
    try t.drop();
    try t.toTop("_inv_r");
    t.renameTop(result_name);
}

fn decomposePoint(t: *ECTracker, point_name: []const u8, x_name: []const u8, y_name: []const u8) !void {
    try t.toTop(point_name);
    t.popNames(1);
    try emitSplit32Sequence(t);
    try t.pushTracked("_dp_xb", .unknown);
    try t.pushTracked("_dp_yb", .unknown);

    try t.toTop("_dp_yb");
    try t.rawBlock(1, y_name, emitBytesToUnsignedNumSequence);
    // A 0x00 sign byte is appended before BIN2NUM, so the coordinate decodes
    // UNSIGNED: >= 0, but it may be up to 2^256 - 1 and therefore >= p. That gap
    // is exactly what the subtraction precondition turns on.
    t.setDomain(y_name, .non_negative);

    try t.toTop("_dp_xb");
    try t.rawBlock(1, x_name, emitBytesToUnsignedNumSequence);
    t.setDomain(x_name, .non_negative);
    try t.swap();
}

fn composePoint(t: *ECTracker, x_name: []const u8, y_name: []const u8, result_name: []const u8) !void {
    try t.toTop(x_name);
    try t.rawBlock(1, "_cp_xb", emitUnsignedNumToBigEndianBytes32Sequence);

    try t.toTop(y_name);
    try t.rawBlock(1, "_cp_yb", emitUnsignedNumToBigEndianBytes32Sequence);

    try t.toTop("_cp_xb");
    try t.toTop("_cp_yb");
    try t.rawBlock(2, result_name, emitCatOpcode);
}

fn affineAdd(t: *ECTracker) !void {
    // The chord slope s = (qy - py) / (qx - px) is undefined when P == Q: the
    // denominator is zero and the correct slope is the TANGENT, 3px^2 / (2py).
    // Without this, ecAdd(P, P) silently produced a wrong point, so every
    // contract that doubled deployed an unspendable script.
    //
    // Both cases are `s = num / den`, so only the NUMERATOR and DENOMINATOR are
    // selected and the single expensive fieldInv still runs exactly once.
    // rx and ry below are already correct for doubling.
    //
    //   cond   = (px == qx) AND (py == qy)     1 when doubling, else 0
    //   num    = cond ? 3*px^2 : (qy - py)
    //   den    = cond ? 2*py   : (qx - px)
    //
    // selected as `b + cond*(a - b)`, which needs no branch and keeps the
    // emitted op sequence identical on both paths.
    //
    // THE THIRD CASE, P == -Q: px == qx but py != qy. Testing px == qx ALONE
    // sends it down the tangent path and returns 2P — an on-curve, entirely
    // plausible, WRONG point. Before the doubling fix the chord path ran there,
    // divided by zero (fieldInv is Fermat, inv(0) = 0) and produced an OFF-curve
    // blob, so `assert(ecOnCurve(ecAdd(a, b)))` — the idiom this codegen tells
    // authors to write — happened to reject it. Selecting on px alone would have
    // silently disarmed that.
    //
    // P + (-P) is the point at infinity, which affine x||y cannot represent. This
    // codegen already has a representation for O: the ALL-ZERO blob, which is
    // what `ecMul(P, 0n)` returns and what the `ec-mulgen-linear` rewrite in
    // ec_optimizer.zig produces for k1 + k2 == 0 (mod n). So return that, by
    // masking the result with `notinf = NOT(px == qx AND NOT cond)`:
    //
    //   - it agrees with the rewrite, so the same source cannot give two answers
    //     depending on whether the optimizer fired;
    //   - O is not on the curve (0^2 != 0^3 + 7), so the on-curve gate rejects it
    //     and the idiom above works again;
    //   - it adds no failure channel to what is a pure value-producing
    //     expression, the same reason emitScalarReduce reduces instead of
    //     rejecting.
    //
    // The mask is a bare OP_MUL with no reduction: rx, ry are already in [0, p)
    // and notinf is 0 or 1, so the product is canonical either way.
    try t.copyToTop("px", "_px_eq");
    try t.copyToTop("qx", "_qx_eq");
    try t.rawBlock(2, "_xeq", emitNumEqualOpcode);
    try t.copyToTop("py", "_py_eq");
    try t.copyToTop("qy", "_qy_eq");
    try t.rawBlock(2, "_yeq", emitNumEqualOpcode);
    try t.copyToTop("_xeq", "_xeq_c");
    try t.toTop("_yeq");
    try t.rawBlock(2, "_cond", emitBoolAndOpcode);
    // notinf = NOT(xeq - cond): xeq - cond is 1 exactly when px == qx and the
    // points are not equal, i.e. exactly the P == -Q case.
    try t.toTop("_xeq");
    try t.copyToTop("_cond", "_cond_c");
    try t.rawBlock(2, "_notinf", emitSubNotSequence);

    try t.copyToTop("qy", "_qy1");
    try t.copyToTop("py", "_py1");
    try fieldSub(t, "_qy1", "_py1", "_num_chord");

    try t.copyToTop("qx", "_qx1");
    try t.copyToTop("px", "_px1");
    try fieldSub(t, "_qx1", "_px1", "_den_chord");

    try t.copyToTop("px", "_px_t");
    try fieldSqr(t, "_px_t", "_px_sq");
    try fieldMulConst(t, "_px_sq", 3, "_num_tan");
    try t.copyToTop("py", "_py_t");
    try fieldMulConst(t, "_py_t", 2, "_den_tan");

    try t.copyToTop("_num_chord", "_num_chord_c");
    try fieldSub(t, "_num_tan", "_num_chord_c", "_num_diff");
    try t.copyToTop("_cond", "_cond_n");
    try fieldMul(t, "_num_diff", "_cond_n", "_num_sel");
    try fieldAdd(t, "_num_chord", "_num_sel", "_s_num");

    try t.copyToTop("_den_chord", "_den_chord_c");
    try fieldSub(t, "_den_tan", "_den_chord_c", "_den_diff");
    try t.toTop("_cond");
    t.renameTop("_cond_d");
    try fieldMul(t, "_den_diff", "_cond_d", "_den_sel");
    try fieldAdd(t, "_den_chord", "_den_sel", "_s_den");

    try fieldInv(t, "_s_den", "_s_den_inv");
    try fieldMul(t, "_s_num", "_s_den_inv", "_s");

    try t.copyToTop("_s", "_s_keep");
    try fieldSqr(t, "_s", "_s2");
    try t.copyToTop("px", "_px2");
    try fieldSub(t, "_s2", "_px2", "_rx1");
    try t.copyToTop("qx", "_qx2");
    try fieldSub(t, "_rx1", "_qx2", "rx");

    try t.copyToTop("px", "_px3");
    try t.copyToTop("rx", "_rx2");
    try fieldSub(t, "_px3", "_rx2", "_px_rx");
    try fieldMul(t, "_s_keep", "_px_rx", "_s_px_rx");
    try t.copyToTop("py", "_py2");
    try fieldSub(t, "_s_px_rx", "_py2", "ry");

    try t.toTop("px");
    try t.drop();
    try t.toTop("py");
    try t.drop();
    try t.toTop("qx");
    try t.drop();
    try t.toTop("qy");
    try t.drop();

    // P == -Q -> force the all-zero point (see the header comment).
    try t.toTop("rx");
    try t.copyToTop("_notinf", "_notinf_x");
    try t.rawBlock(2, "rx", emitMulOpcode);
    try t.toTop("ry");
    try t.toTop("_notinf");
    try t.rawBlock(2, "ry", emitMulOpcode);
}

fn jacobianDouble(t: *ECTracker) !void {
    try t.copyToTop("jy", "_jy_save");
    try t.copyToTop("jx", "_jx_save");
    try t.copyToTop("jz", "_jz_save");

    try fieldSqr(t, "jy", "_A");

    try t.copyToTop("_A", "_A_save");
    try fieldMul(t, "jx", "_A", "_xA");
    try t.pushInt("_four", 4);
    try fieldMul(t, "_xA", "_four", "_B");

    try fieldSqr(t, "_A_save", "_A2");
    try t.pushInt("_eight", 8);
    try fieldMul(t, "_A2", "_eight", "_C");

    try fieldSqr(t, "_jx_save", "_x2");
    try t.pushInt("_three", 3);
    try fieldMul(t, "_x2", "_three", "_D");

    try t.copyToTop("_D", "_D_save");
    try t.copyToTop("_B", "_B_save");
    try fieldSqr(t, "_D", "_D2");
    try t.copyToTop("_B", "_B1");
    try fieldMulConst(t, "_B1", 2, "_2B");
    try fieldSub(t, "_D2", "_2B", "_nx");

    try t.copyToTop("_nx", "_nx_copy");
    try fieldSub(t, "_B_save", "_nx_copy", "_B_nx");
    try fieldMul(t, "_D_save", "_B_nx", "_D_B_nx");
    try fieldSub(t, "_D_B_nx", "_C", "_ny");

    try fieldMul(t, "_jy_save", "_jz_save", "_yz");
    try fieldMulConst(t, "_yz", 2, "_nz");

    try t.toTop("_B");
    try t.drop();
    try t.toTop("jz");
    try t.drop();
    try t.toTop("_nx");
    t.renameTop("jx");
    try t.toTop("_ny");
    t.renameTop("jy");
    try t.toTop("_nz");
    t.renameTop("jz");
}

fn jacobianToAffine(t: *ECTracker, rx_name: []const u8, ry_name: []const u8) !void {
    try fieldInv(t, "jz", "_zinv");
    try t.copyToTop("_zinv", "_zinv_keep");
    try fieldSqr(t, "_zinv", "_zinv2");
    try t.copyToTop("_zinv2", "_zinv2_keep");
    try fieldMul(t, "_zinv_keep", "_zinv2", "_zinv3");
    try fieldMul(t, "jx", "_zinv2_keep", rx_name);
    try fieldMul(t, "jy", "_zinv3", ry_name);
}

fn buildJacobianAddAffineInline(
    allocator: Allocator,
    base_names: []const ?[]const u8,
    opts: EcCodegenOptions,
    base_doms: []const Dom,
) !EcOpBundle {
    // The inner tracker inherits the stack state AND the lattice facts: the
    // operands' proved domains are what decide which reduction shape the body
    // emits, so dropping them here would silently fall back everywhere.
    var inner = try ECTracker.initOpts(allocator, base_names, opts, base_doms);
    errdefer inner.deinit();

    try jacobianAddAffineBody(&inner, false);
    return inner.takeBundle();
}

/// The mixed-add itself, emitting through a tracker the caller owns.
///
/// `keep_hr` additionally leaves copies of H and R on the stack. They are the
/// exception detector: H = U2 - X1 and R = S2 - Y1 are both zero exactly when
/// the Jacobian accumulator is the same curve point as the affine operand, the
/// one case these formulas cannot compute (see buildJacobianAddOrDoubleInline).
fn jacobianAddAffineBody(inner: *ECTracker, keep_hr: bool) !void {
    try inner.copyToTop("jz", "_jz_for_z1cu");
    try inner.copyToTop("jz", "_jz_for_z3");
    try inner.copyToTop("jy", "_jy_for_y3");
    try inner.copyToTop("jx", "_jx_for_u1h2");

    try fieldSqr(inner, "jz", "_Z1sq");
    try inner.copyToTop("_Z1sq", "_Z1sq_for_u2");
    try fieldMul(inner, "_jz_for_z1cu", "_Z1sq", "_Z1cu");

    try inner.copyToTop("ax", "_ax_c");
    try fieldMul(inner, "_ax_c", "_Z1sq_for_u2", "_U2");

    try inner.copyToTop("ay", "_ay_c");
    try fieldMul(inner, "_ay_c", "_Z1cu", "_S2");

    try fieldSub(inner, "_U2", "jx", "_H");
    try fieldSub(inner, "_S2", "jy", "_R");

    if (keep_hr) {
        try inner.copyToTop("_H", "_H_keep");
        try inner.copyToTop("_R", "_R_keep");
    }

    try inner.copyToTop("_H", "_H_for_h3");
    try inner.copyToTop("_H", "_H_for_z3");

    try fieldSqr(inner, "_H", "_H2");
    try inner.copyToTop("_H2", "_H2_for_u1h2");

    try fieldMul(inner, "_H_for_h3", "_H2", "_H3");
    try fieldMul(inner, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2");

    try inner.copyToTop("_R", "_R_for_y3");
    try inner.copyToTop("_U1H2", "_U1H2_for_y3");
    try inner.copyToTop("_H3", "_H3_for_y3");

    try fieldSqr(inner, "_R", "_R2");
    try fieldSub(inner, "_R2", "_H3", "_x3_tmp");
    try fieldMulConst(inner, "_U1H2", 2, "_2U1H2");
    try fieldSub(inner, "_x3_tmp", "_2U1H2", "_X3");

    try inner.copyToTop("_X3", "_X3_c");
    try fieldSub(inner, "_U1H2_for_y3", "_X3_c", "_u_minus_x");
    try fieldMul(inner, "_R_for_y3", "_u_minus_x", "_r_tmp");
    try fieldMul(inner, "_jy_for_y3", "_H3_for_y3", "_jy_h3");
    try fieldSub(inner, "_r_tmp", "_jy_h3", "_Y3");

    try fieldMul(inner, "_jz_for_z3", "_H_for_z3", "_Z3");

    try inner.toTop("_X3");
    inner.renameTop("jx");
    try inner.toTop("_Y3");
    inner.renameTop("jy");
    try inner.toTop("_Z3");
    inner.renameTop("jz");
}

/// Branchless select of one Jacobian coordinate: `add + cond*(dbl - add)`.
/// Same shape as the numerator/denominator select in affineAdd, so both paths
/// emit the identical op sequence and the tracker's static stack model holds.
/// Consumes add_name, dbl_name and cond_name.
fn selectCoord(
    t: *ECTracker,
    add_name: []const u8,
    dbl_name: []const u8,
    cond_name: []const u8,
    result_name: []const u8,
) !void {
    try t.copyToTop(add_name, "_sel_add_c");
    try fieldSub(t, dbl_name, "_sel_add_c", "_sel_diff");
    try fieldMul(t, "_sel_diff", cond_name, "_sel_scaled");
    try fieldAdd(t, add_name, "_sel_scaled", result_name);
}

/// The ladder's LAST conditional step: mixed-add, but correct when the
/// accumulator already equals the point being added.
///
/// The Jacobian mixed-add cannot double. It computes H = U2 - X1, and when the
/// two operands are the same curve point H = 0, so Z3 = Z1*H = 0 — the point at
/// infinity — and since fieldInv is Fermat (inv(0) = 0), jacobianToAffine turns
/// that into the ALL-ZERO point instead of 2P. ecMul(P, 2n) and ecMulGen(2n)
/// returned 64 zero bytes.
///
/// WHY ONLY THE LAST STEP. After step i the accumulator holds c_i*P where
/// c_i = k' >> i and k' = k + 3n, so the conditional step adds P to
/// (c_i - 1)*P. secp256k1 has cofactor 1, so P has order n and the degenerate
/// cases are exactly c_i == 2 (mod n) — accumulator == P — and c_i == 0 or 1
/// (mod n) — accumulator == -P or O. c_i ranges over a CONTIGUOUS interval
/// determined only by i, so this is decidable by interval arithmetic rather
/// than by sampling, and over the whole domain k in [0, n-1] only two steps
/// qualify, both at i = 0:
///
///   k = 2  ->  c_0 = 3n+2 == 2, odd, so the add runs: accumulator == P. <- bug
///   k = 0  ->  c_0 = 3n   == 0, odd, so the add runs: accumulator == -P,
///              true result the point at infinity, which affine coordinates
///              cannot represent; it stays the all-zero point, as before.
///
/// At i >= 1, c_i lies in [3n>>i, (4n-1)>>i] — the lower bound is 3n, not 3n+1,
/// because the reduce puts k = 0 in the domain — and that interval contains no
/// value == 0, 1 or 2 (mod n) that is also odd; c_256 = 2 is even, so no add
/// runs. Handling H == 0 at every one of the 257 steps would cost ~70% more
/// script bytes; handling it here costs 0.26%.
///
/// THE ENTIRE ARGUMENT IS CONDITIONED ON k in [0, n-1], which is only true
/// because emitEcMul reduces k mod n before adding 3n. That reduce landed one
/// commit AFTER this select (03f50d48 then f16790a9). 03f50d48 ON ITS OWN IS
/// UNSOUND: a last-step-only select while the scalar is still unbounded leaves
/// c_i free to hit 0, 1 or 2 (mod n) at other steps. The two commits must land
/// together and must never be bisected, cherry-picked or reverted apart.
///
/// The interval argument does 100% of the work; there is no defence in depth
/// here. In particular c_i == 1 (mod n) — a pre-add accumulator of O — is
/// UNREACHABLE, not handled: were it reachable the select would still take the
/// ADD path, because O is carried as Z1 = 0, which makes U2 = 0 and
/// H = -X1 != 0. Anything that changes the +3n offset, the iteration count or
/// the reduce must redo the interval check, not assume this still holds.
///
/// This is NOT a "no honest input hits it" argument: the operand P is caller-
/// supplied and cannot move the exception, because the condition depends only
/// on c_i mod ord(P) and ord(P) = n for every point on the curve. Points that
/// are NOT on the curve carry no such guarantee — gate untrusted input on
/// ecOnCurve first.
///
/// Stack layout: [..., ax, ay, _k, jx, jy, jz] — same in and out.
fn buildJacobianAddOrDoubleInline(
    allocator: Allocator,
    base_names: []const ?[]const u8,
    opts: EcCodegenOptions,
    base_doms: []const Dom,
) !EcOpBundle {
    var inner = try ECTracker.initOpts(allocator, base_names, opts, base_doms);
    errdefer inner.deinit();

    // Keep the pre-add accumulator: it is what must be DOUBLED in the
    // exceptional case, and the add below consumes jx/jy/jz.
    try inner.copyToTop("jx", "_sx");
    try inner.copyToTop("jy", "_sy");
    try inner.copyToTop("jz", "_sz");

    try jacobianAddAffineBody(&inner, true);

    // cond = (H == 0) AND (R == 0). Requiring R == 0 too keeps the
    // accumulator == -P case (k = 0) on the add path, where Z3 = 0 correctly
    // signals the point at infinity.
    try inner.toTop("_H_keep");
    try inner.pushInt("_zero_h", 0);
    try inner.rawBlock(2, "_h_is0", emitNumEqualOpcode);
    try inner.toTop("_R_keep");
    try inner.pushInt("_zero_r", 0);
    try inner.rawBlock(2, "_r_is0", emitNumEqualOpcode);
    try inner.toTop("_h_is0");
    try inner.toTop("_r_is0");
    try inner.rawBlock(2, "_cond", emitBoolAndOpcode);

    // Move the add result aside so jacobianDouble can work on jx/jy/jz again,
    // this time holding the saved accumulator.
    try inner.toTop("jx");
    inner.renameTop("_add_x");
    try inner.toTop("jy");
    inner.renameTop("_add_y");
    try inner.toTop("jz");
    inner.renameTop("_add_z");
    try inner.toTop("_sx");
    inner.renameTop("jx");
    try inner.toTop("_sy");
    inner.renameTop("jy");
    try inner.toTop("_sz");
    inner.renameTop("jz");
    try jacobianDouble(&inner);
    try inner.toTop("jx");
    inner.renameTop("_dbl_x");
    try inner.toTop("jy");
    inner.renameTop("_dbl_y");
    try inner.toTop("jz");
    inner.renameTop("_dbl_z");

    try inner.copyToTop("_cond", "_cond_x");
    try selectCoord(&inner, "_add_x", "_dbl_x", "_cond_x", "jx");
    try inner.copyToTop("_cond", "_cond_y");
    try selectCoord(&inner, "_add_y", "_dbl_y", "_cond_y", "jy");
    try inner.toTop("_cond");
    inner.renameTop("_cond_z");
    try selectCoord(&inner, "_add_z", "_dbl_z", "_cond_z", "jz");

    return inner.takeBundle();
}

fn emitEcAdd(t: *ECTracker) !void {
    try t.poolConstant(POOL_FIELD_P, field_p_be[0..]);
    try decomposePoint(t, "_pa", "px", "py");
    try decomposePoint(t, "_pb", "qx", "qy");
    try affineAdd(t);
    try composePoint(t, "rx", "ry", "_result");
    try t.releaseConstant(POOL_FIELD_P);
}

/// Reduce a scalar to [0, n-1]: ((k mod n) + n) mod n.
///
/// OP_MOD takes the sign of the DIVIDEND, so `k mod n` alone lands in (-n, n);
/// the `+ n, mod n` normalises the negative half. One push of n covers both
/// reductions — the same shape as fieldMod / ecModReduce.
///
/// Without it, emitEcMul's ladder is only correct while 2^257 <= k + 3n < 2^258:
/// a scalar >= ~n sets bit 258, the 257-iteration loop never sees it, and the
/// ladder returns a DIFFERENT multiple of P rather than failing. Scalars are
/// contract input, so that is attacker-chosen. Reducing costs 1 push + 8 opcodes
/// (42 bytes) against a ~429 KB script, and makes k >= n, k < 0 and k = 0 all
/// well defined.
fn emitScalarReduce(t: *ECTracker, k_name: []const u8, result_name: []const u8) !void {
    try t.toTop(k_name);
    try pushCurveNNum(t, "_n_red");
    try t.rawBlock(2, result_name, emitFieldModSequence);
}

fn emitEcMul(t: *ECTracker, point_name: []const u8, scalar_name: []const u8) !void {
    try t.poolConstant(POOL_FIELD_P, field_p_be[0..]);
    try t.poolConstant(POOL_GROUP_N, curve_n_be[0..]);
    try decomposePoint(t, point_name, "ax", "ay");

    // "k in [1, n-1]" is a PRECONDITION the caller cannot enforce — the scalar is
    // usually an unlock argument — so reduce it first. See emitScalarReduce.
    try t.toTop(scalar_name);
    try emitScalarReduce(t, scalar_name, "_kr");
    if (t.opts.constant_pool) {
        // Three separate `+n` steps, each served from the pooled slot — the
        // shape the reference emits.
        try pushCurveNNum(t, "_n");
        try t.rawBlock(2, "_kn", emitAddOpcode);
        try pushCurveNNum(t, "_n2");
        try t.rawBlock(2, "_kn2", emitAddOpcode);
        try pushCurveNNum(t, "_n3");
        try t.rawBlock(2, "_kn3", emitAddOpcode);
    } else {
        // Pre-folded `3n` on the DEFAULT path, and only there.
        //
        // The reference emits three literal `+n` steps and lets its peephole
        // reassociate them back to `push 3n; OP_ADD`. This tier's peephole folds
        // only i64 `push_int` chains (see peephole.zig rule 27), and a 256-bit
        // constant is a `push_data` blob here — so emitting three steps would
        // ship 68 extra bytes rather than collapsing. Same shipped bytes as the
        // reference, different pre-peephole spelling, which is exactly why the
        // Zig parity test is gated on the POST-peephole hash.
        try t.pushStaticBytes("_3n", curve_3n_script_num_le[0..]);
        try t.rawBlock(2, "_kn3", emitAddOpcode);
    }
    t.renameTop("_k");

    try t.copyToTop("ax", "jx");
    try t.copyToTop("ay", "jy");
    try t.pushInt("jz", 1);

    var bit: i32 = 256;
    while (bit >= 0) : (bit -= 1) {
        try jacobianDouble(t);

        try t.copyToTop("_k", "_k_copy");
        if (bit == 1) {
            // Single-bit shift: OP_2DIV (no push needed)
            try t.rawBlock(1, "_shifted", emit2DivOpcode);
        } else if (bit > 1) {
            // Multi-bit shift: push shift amount, OP_RSHIFTNUM
            try t.pushInt("_shift", @as(i64, bit));
            try t.rawBlock(2, "_shifted", emitRshiftnumOpcode);
        } else {
            t.renameTop("_shifted");
        }
        try t.pushInt("_two", 2);
        try t.rawBlock(2, "_bit", emitModOpcode);

        try t.toTop("_bit");
        t.popNames(1);

        // Only the final step can be handed two equal operands — see
        // buildJacobianAddOrDoubleInline for why, and for what it costs not to.
        var add_bundle = if (bit == 0)
            try buildJacobianAddOrDoubleInline(t.allocator, t.names.items, t.opts, t.doms.items)
        else
            try buildJacobianAddAffineInline(t.allocator, t.names.items, t.opts, t.doms.items);
        errdefer add_bundle.deinit();

        try t.owned_bytes.appendSlice(t.allocator, add_bundle.owned_bytes);
        t.allocator.free(add_bundle.owned_bytes);
        add_bundle.owned_bytes = &.{};

        try t.emitRaw(.{ .@"if" = .{ .then = add_bundle.ops, .@"else" = null } });
        add_bundle.ops = &.{};
    }

    try jacobianToAffine(t, "_rx", "_ry");

    try t.toTop("ax");
    try t.drop();
    try t.toTop("ay");
    try t.drop();
    try t.toTop("_k");
    try t.drop();

    try composePoint(t, "_rx", "_ry", "_result");
    try t.releaseConstant(POOL_GROUP_N);
    try t.releaseConstant(POOL_FIELD_P);
}

// ===========================================================================
// Fixed-base comb (secp256k1)
// ===========================================================================

/// Render a comb table coordinate as a 32-byte big-endian buffer.
fn combCoordBeAlloc(allocator: Allocator, v: comb.Big) ![]u8 {
    const out = try allocator.alloc(u8, 32);
    var x = v;
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        out[i] = @intCast(@as(u8, @truncate(@as(u256, @intCast(x)) & 0xff)));
        x >>= 8;
    }
    return out;
}

/// Push a comb table coordinate as an unsigned script number.
fn pushCombCoord(t: *ECTracker, name: []const u8, v: comb.Big) !void {
    const be = try combCoordBeAlloc(t.allocator, v);
    defer t.allocator.free(be);
    const encoded = try beToUnsignedScriptNumAlloc(t.allocator, be);
    try t.pushOwnedBytes(name, encoded);
}

/// Round `i`'s digit and the selected table entry, as `ax`/`ay`/`_flag`.
///
/// Exactly one equality holds, so `sum(eq_j * T_j)` is that entry's coordinate
/// and every term is non-negative and below p — no reduction is needed, and the
/// result is `.reduced` by construction. When the digit is zero every term
/// vanishes and `_flag` is 0, so no add runs.
fn combEmitSelect(t: *ECTracker, i: usize, w: usize, d: usize) !void {
    var buf: [24]u8 = undefined;
    const entries = (@as(usize, 1) << @intCast(w)) - 1;

    var b: usize = 0;
    while (b < w) : (b += 1) {
        const shift = i + b * d;
        const kc = try t.internName(try std.fmt.bufPrint(&buf, "_kc{d}", .{b}));
        const sh = try t.internName(try std.fmt.bufPrint(&buf, "_sh{d}", .{b}));
        try t.copyToTop("_k", kc);
        if (shift == 0) {
            t.renameTop(sh);
        } else if (shift == 1) {
            try t.rawBlock(1, sh, emit2DivOpcode);
        } else {
            const sd = try t.internName(try std.fmt.bufPrint(&buf, "_sd{d}", .{b}));
            try t.pushInt(sd, @intCast(shift));
            try t.rawBlock(2, sh, emitRshiftnumOpcode);
        }
        const two = try t.internName(try std.fmt.bufPrint(&buf, "_two{d}", .{b}));
        const bit = try t.internName(try std.fmt.bufPrint(&buf, "_b{d}", .{b}));
        try t.pushInt(two, 2);
        try t.rawBlock(2, bit, emitModOpcode);
        t.setDomain(bit, .reduced);
    }

    try t.toTop("_b0");
    t.renameTop("_idx");
    b = 1;
    while (b < w) : (b += 1) {
        const bit = try t.internName(try std.fmt.bufPrint(&buf, "_b{d}", .{b}));
        const wt = try t.internName(try std.fmt.bufPrint(&buf, "_wt{d}", .{b}));
        const bw = try t.internName(try std.fmt.bufPrint(&buf, "_bw{d}", .{b}));
        try t.toTop(bit);
        try t.pushInt(wt, @as(i64, 1) << @intCast(b));
        try t.rawBlock(2, bw, emitMulOpcode);
        try t.toTop("_idx");
        try t.rawBlock(2, "_idx", emitAddOpcode);
    }
    t.setDomain("_idx", .reduced);

    var j: usize = 1;
    while (j <= entries) : (j += 1) {
        const ic = try t.internName(try std.fmt.bufPrint(&buf, "_ic{d}", .{j}));
        const jv = try t.internName(try std.fmt.bufPrint(&buf, "_jv{d}", .{j}));
        const eq = try t.internName(try std.fmt.bufPrint(&buf, "_eq{d}", .{j}));
        try t.copyToTop("_idx", ic);
        try t.pushInt(jv, @intCast(j));
        try t.rawBlock(2, eq, emitNumEqualOpcode);
        t.setDomain(eq, .reduced);
    }

    for ([_][]const u8{ "x", "y" }) |coord| {
        const acc: []const u8 = if (coord[0] == 'x') "ax" else "ay";
        j = 1;
        while (j <= entries) : (j += 1) {
            const ec_n = try t.internName(try std.fmt.bufPrint(&buf, "_e{s}{d}", .{ coord, j }));
            const tc = try t.internName(try std.fmt.bufPrint(&buf, "_t{s}{d}", .{ coord, j }));
            const pr = try t.internName(try std.fmt.bufPrint(&buf, "_pr{s}{d}", .{ coord, j }));
            const eq = try t.internName(try std.fmt.bufPrint(&buf, "_eq{d}", .{j}));
            const tj = try t.internName(try std.fmt.bufPrint(&buf, "_T{s}{d}", .{ coord, j }));
            try t.copyToTop(eq, ec_n);
            try t.copyToTop(tj, tc);
            try t.rawBlock(2, pr, emitMulOpcode);
            if (j == 1) {
                t.renameTop(acc);
            } else {
                try t.toTop(acc);
                try t.rawBlock(2, acc, emitAddOpcode);
            }
        }
        t.setDomain(acc, .reduced);
    }

    j = entries;
    while (j >= 1) : (j -= 1) {
        const eq = try t.internName(try std.fmt.bufPrint(&buf, "_eq{d}", .{j}));
        try t.toTop(eq);
        try t.drop();
        if (j == 1) break;
    }

    try t.toTop("_idx");
    try t.rawBlock(1, "_flag", emit0NotEqualOpcode);
}

/// `k*G` by a Lim-Lee fixed-base comb instead of the 257-round binary ladder.
///
/// The ladder doubles and conditionally adds once per SCALAR BIT. A comb splits
/// the scalar into `w` blocks of `d` bits and reads one bit from each block per
/// round, so it performs one doubling and one conditional add per COLUMN: the
/// round count falls from `w*d` to `d` at the price of a `2^w - 1` entry table.
/// G is a compile-time constant here, so the table costs nothing to build.
///
/// SOUNDNESS. The cheap incomplete mixed add cannot represent a pre-add
/// accumulator equal to the addend, its negation, or the point at infinity.
/// `buildJacobianAddOrDoubleInline`'s comment justifies using it everywhere but
/// the ladder's LAST step by an interval argument over `c_i mod n`, and insists
/// that argument be re-derived by anything changing the offset or the iteration
/// count. A comb changes both, so it is re-derived: `comb.combSafeRounds`
/// evaluates the same argument as executable interval arithmetic over the comb's
/// own geometry, and any round it cannot prove gets the complete add-or-double
/// form instead. Nothing is assumed safe.
///
/// The other half of that argument is that the accumulator never starts at
/// infinity, which needs the first digit non-zero. `comb.combGeometry` searches
/// for the scalar offset that guarantees it rather than reusing the ladder's
/// hardcoded `+3n` — right for secp256k1 at w=3, wrong for P-384.
///
/// Stack in: [_k]. Stack out: [_result]. False when no geometry exists for `w`.
fn emitCombMulGen(t: *ECTracker, w: usize) !bool {
    const curve = comb.SECP256K1_COMB_CURVE;
    const params = comb.combGeometry(w, curve) orelse return false;
    const d = params.d;
    var table: [1 << comb.MAX_W]?comb.Point = undefined;
    comb.combTable(w, d, curve, &table);
    var safe: [comb.MAX_D]bool = undefined;
    comb.combSafeRounds(params, curve, &safe);
    const entries = (@as(usize, 1) << @intCast(w)) - 1;
    var buf: [24]u8 = undefined;

    try t.poolConstant(POOL_FIELD_P, field_p_be[0..]);
    try t.poolConstant(POOL_GROUP_N, curve_n_be[0..]);

    // k' = (k mod n) + m*n. The reduce is what confines k to [0, n-1] and so
    // what makes the interval argument apply at all; see emitScalarReduce.
    try t.toTop("_k");
    try emitScalarReduce(t, "_k", "_kr");
    t.renameTop("_k");
    var i: usize = 0;
    while (i < params.offset_multiple) : (i += 1) {
        const off = try t.internName(try std.fmt.bufPrint(&buf, "_off{d}", .{i}));
        try pushCurveNNum(t, off);
        try t.rawBlock(2, "_k", emitAddOpcode);
    }
    t.setDomain("_k", .non_negative);

    // Table, resident for the whole comb: picking an entry costs 2-3 bytes
    // against a 34-byte literal push, and every round reads all of them.
    var j: usize = 1;
    while (j <= entries) : (j += 1) {
        const pt = table[j].?;
        const tx = try t.internName(try std.fmt.bufPrint(&buf, "_Tx{d}", .{j}));
        const ty = try t.internName(try std.fmt.bufPrint(&buf, "_Ty{d}", .{j}));
        try pushCombCoord(t, tx, pt.x);
        try pushCombCoord(t, ty, pt.y);
        t.setDomain(tx, .reduced);
        t.setDomain(ty, .reduced);
    }

    // Round d-1 initialises the accumulator. The first digit is non-zero by
    // construction (combGeometry), so this is a real point, never infinity.
    try combEmitSelect(t, d - 1, w, d);
    try t.toTop("_flag");
    try t.drop();
    try t.toTop("ax");
    t.renameTop("jx");
    try t.toTop("ay");
    t.renameTop("jy");
    try t.pushInt("jz", 1);
    t.setDomain("jz", .reduced);

    var round: usize = d - 1;
    while (round > 0) {
        round -= 1;
        try jacobianDouble(t);
        try combEmitSelect(t, round, w, d);

        // `jacobianAddAffineBody` documents its layout as
        // [..., ax, ay, jx, jy, jz] and replaces the accumulator IN PLACE at the
        // top. The selection leaves ax/ay above jz, so restore the contract
        // before the branch — otherwise the add arm would reorder the stack and
        // the empty else arm would not, leaving the two arms with different
        // layouts at OP_ENDIF.
        try t.toTop("_flag");
        try t.toAlt();
        try t.toTop("jx");
        try t.toTop("jy");
        try t.toTop("jz");
        try t.fromAlt("_flag");

        t.popNames(1); // consumed by OP_IF
        var add_bundle = if (safe[round])
            try buildJacobianAddAffineInline(t.allocator, t.names.items, t.opts, t.doms.items)
        else
            try buildJacobianAddOrDoubleInline(t.allocator, t.names.items, t.opts, t.doms.items);
        errdefer add_bundle.deinit();

        try t.owned_bytes.appendSlice(t.allocator, add_bundle.owned_bytes);
        t.allocator.free(add_bundle.owned_bytes);
        add_bundle.owned_bytes = &.{};
        try t.emitRaw(.{ .@"if" = .{ .then = add_bundle.ops, .@"else" = null } });
        add_bundle.ops = &.{};

        // The addend was selected fresh for this round; the add only copied it.
        try t.toTop("ay");
        try t.drop();
        try t.toTop("ax");
        try t.drop();
    }

    try jacobianToAffine(t, "_rx", "_ry");

    j = entries;
    while (j >= 1) : (j -= 1) {
        const ty = try t.internName(try std.fmt.bufPrint(&buf, "_Ty{d}", .{j}));
        const tx = try t.internName(try std.fmt.bufPrint(&buf, "_Tx{d}", .{j}));
        try t.toTop(ty);
        try t.drop();
        try t.toTop(tx);
        try t.drop();
        if (j == 1) break;
    }
    try t.toTop("_k");
    try t.drop();

    try composePoint(t, "_rx", "_ry", "_result");
    try t.releaseConstant(POOL_GROUP_N);
    try t.releaseConstant(POOL_FIELD_P);
    return true;
}

/// Emit the cheapest comb over the candidate window widths into `t`.
///
/// Each candidate is rendered in full and scored with the same byte-cost model
/// the emitter is measured by, and the smallest wins — the window width is not
/// hardcoded. w=1 is the binary ladder and is excluded; beyond w=4 the `2^w`
/// selection logic outgrows the saving.
///
/// Returns false when no candidate could be built, so the caller falls back to
/// the ladder rather than emitting nothing.
fn emitCombBest(t: *ECTracker) !bool {
    var best_w: ?usize = null;
    var best_bytes: usize = 0;
    for ([_]usize{ 2, 3, 4 }) |w| {
        var probe = try ECTracker.initOpts(t.allocator, t.names.items, t.opts, t.doms.items);
        defer probe.deinit();
        const built = emitCombMulGen(&probe, w) catch continue;
        if (!built) continue;
        const bytes = estimateScriptBytes(probe.ops.items);
        if (best_w == null or bytes < best_bytes) {
            best_w = w;
            best_bytes = bytes;
        }
    }
    const w = best_w orelse return false;
    return emitCombMulGen(t, w);
}

/// Render the comb at one window width, for the width-selection test.
///
/// The emitter picks `w` by rendering every candidate and keeping the smallest;
/// this exposes a single candidate so the test can pin WHICH width wins rather
/// than only that the total matches.
pub fn buildCombProbeForTest(allocator: Allocator, w: usize) !EcOpBundle {
    var t = try ECTracker.initOpts(allocator, &.{"_k"}, .{
        .constant_pool = true,
        .reduction_sinking = true,
        .fixed_base_comb = true,
    }, null);
    errdefer t.deinit();
    _ = try emitCombMulGen(&t, w);
    return t.takeBundle();
}

fn emitEcMulGen(t: *ECTracker) !void {
    // G is a compile-time constant, so this is the one secp256k1 call site where
    // a fixed-base comb applies. `emitEcMul` cannot use it: its base arrives at
    // run time.
    if (t.opts.fixed_base_comb) {
        if (try emitCombBest(t)) return;
    }

    const point = try generatorPointAlloc(t.allocator);
    try t.pushOwnedBytes("_pt", point);
    try t.swap();
    try emitEcMul(t, "_pt", "_k");
}

fn emitEcNegate(t: *ECTracker) !void {
    try t.poolConstant(POOL_FIELD_P, field_p_be[0..]);
    try decomposePoint(t, "_pt", "_nx", "_ny");
    try pushFieldPNum(t, "_fp");
    try fieldSub(t, "_fp", "_ny", "_neg_y");
    try composePoint(t, "_nx", "_neg_y", "_result");
    try t.releaseConstant(POOL_FIELD_P);
}

fn emitEcOnCurve(t: *ECTracker) !void {
    try t.poolConstant(POOL_FIELD_P, field_p_be[0..]);
    try decomposePoint(t, "_pt", "_x", "_y");

    // GAP-301: coordinate canonicity. `decomposePoint` BIN2NUMs each coordinate
    // as an unsigned value that may be >= p; the field arithmetic below would
    // silently reduce it mod p, so a non-canonical encoding of a valid point
    // would pass. Reject it: require x < p AND y < p (coordinates are unsigned,
    // so the 0 <= lower bound holds by construction). Combined with the curve
    // equation at the end via OP_BOOLAND so ecOnCurve still returns a boolean.
    try t.copyToTop("_x", "_x_lt");
    try pushFieldPNum(t, "_p_for_x");
    try t.rawBlock(2, "_x_canon", emitLessThanOpcode);
    try t.copyToTop("_y", "_y_lt");
    try pushFieldPNum(t, "_p_for_y");
    try t.rawBlock(2, "_y_canon", emitLessThanOpcode);
    try t.toTop("_x_canon");
    try t.toTop("_y_canon");
    try t.rawBlock(2, "_canon", emitBoolAndOpcode);

    try fieldSqr(t, "_y", "_y2");

    try t.copyToTop("_x", "_x_copy");
    try fieldSqr(t, "_x", "_x2");
    try fieldMul(t, "_x2", "_x_copy", "_x3");
    try t.pushInt("_seven", 7);
    try fieldAdd(t, "_x3", "_seven", "_rhs");

    try t.toTop("_y2");
    try t.toTop("_rhs");
    try t.rawBlock(2, "_curve_eq", emitEqualOpcode);

    try t.toTop("_canon");
    try t.toTop("_curve_eq");
    try t.rawBlock(2, "_result", emitBoolAndOpcode);
    try t.releaseConstant(POOL_FIELD_P);
}

fn containsOpcode(ops: []const StackOp, opcode: []const u8) bool {
    for (ops) |op| {
        switch (op) {
            .opcode => |value| if (std.mem.eql(u8, value, opcode)) return true,
            .@"if" => |stack_if| {
                if (containsOpcode(stack_if.then, opcode)) return true;
                if (stack_if.@"else") |else_ops| {
                    if (containsOpcode(else_ops, opcode)) return true;
                }
            },
            else => {},
        }
    }
    return false;
}

fn firstPushBytesLen(ops: []const StackOp) ?usize {
    for (ops) |op| {
        switch (op) {
            .push => |value| switch (value) {
                .bytes => |bytes| return bytes.len,
                else => {},
            },
            else => {},
        }
    }
    return null;
}

test "ec add helper emits affine split and compose flow" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .ec_add);
    defer bundle.deinit();

    try std.testing.expect(bundle.ops.len > 0);
    try std.testing.expect(containsOpcode(bundle.ops, "OP_SPLIT"));
    try std.testing.expect(containsOpcode(bundle.ops, "OP_CAT"));
    try std.testing.expectEqualStrings("OP_CAT", bundle.ops[bundle.ops.len - 1].opcode);
}

// ---------------------------------------------------------------------------
// T-11: Op-count goldens for the Zig EC helper bundles.
//
// The structural tests above check load-bearing opcodes (OP_SPLIT, OP_CAT,
// 257 OP_IF branches in ec_mul, ...) but not the total op-count. These
// goldens pin the Zig helper's pre-stack-lowering bundle size so a
// regression in `buildBuiltinOps` surfaces here as a localized failure
// rather than only as a cross-tier hex mismatch from the golden harness.
//
// The counts are op-TREE sizes (if bodies included, see countOpTree) and
// still diverge slightly from the Python/Java peers because the Zig tier
// bundles some sequences differently at the helper level. Final compiled hex
// is byte-identical (enforced by the conformance harness).
// ---------------------------------------------------------------------------

/// Total number of StackOps in `ops`, INCLUDING the bodies of `.@"if"` ops.
///
/// A flat `ops.len` cannot see inside a branch, so any emitter whose work sits
/// in an if body — the scalar ladders emit 257 / 385 conditional additions —
/// reports a count that barely moves no matter what the branch contains.
/// Adding +1.3 KB of script inside the ladder's last step left the p256Mul /
/// p384Mul goldens byte-identical. Recursing is what makes the golden a gate.
fn countOpTree(ops: []const StackOp) usize {
    var total: usize = 0;
    for (ops) |op| {
        total += 1;
        switch (op) {
            .@"if" => |stack_if| {
                total += countOpTree(stack_if.then);
                if (stack_if.@"else") |else_ops| total += countOpTree(else_ops);
            },
            else => {},
        }
    }
    return total;
}

test "ec helper op-count goldens" {
    // ecAdd 8183 -> 8199 (+16): affineAdd now detects P == -Q (px == qx but
    // py != qy) and masks the result to the all-zero point, instead of taking
    // the tangent and returning an on-curve, plausible, WRONG 2P. The 16 ops
    // are the (py == qy) conjunct (2 picks + OP_NUMEQUAL), the AND that builds
    // cond (pick + swap + OP_BOOLAND), notinf (swap + over + OP_SUB + OP_NOT)
    // and the rx/ry mask (3 rolls + 1 pick + 2 OP_MUL). +21 script BYTES.
    //
    // The TS/Go/Rust/Python/Ruby/Java peers book the same change as +21 OPS:
    // they emit a deep pick/roll as two ops (push depth, then OP_PICK/OP_ROLL)
    // where this tracker models it as one `.pick` / `.roll` StackOp, and 5 of
    // the 16 movements here are deep. Same bytes, different counting point.
    const cases = .{
        .{ registry.CryptoBuiltin.ec_add, "ecAdd", @as(usize, 8199) },
        .{ registry.CryptoBuiltin.ec_mul, "ecMul", @as(usize, 119671) },
        .{ registry.CryptoBuiltin.ec_mul_gen, "ecMulGen", @as(usize, 119673) },
        .{ registry.CryptoBuiltin.ec_negate, "ecNegate", @as(usize, 945) },
        .{ registry.CryptoBuiltin.ec_on_curve, "ecOnCurve", @as(usize, 530) },
    };
    inline for (cases) |c| {
        var bundle = try buildBuiltinOps(std.testing.allocator, c[0]);
        defer bundle.deinit();
        const got = countOpTree(bundle.ops);
        if (got != c[2]) {
            std.debug.print(
                "{s}: op-count drift — got {d}, want {d}\n",
                .{ c[1], got, c[2] },
            );
        }
        try std.testing.expectEqual(c[2], got);
    }
}

test "ec mul helper emits 257 conditional additions" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .ec_mul);
    defer bundle.deinit();

    var if_count: usize = 0;
    for (bundle.ops) |op| switch (op) {
        .@"if" => if_count += 1,
        else => {},
    };

    try std.testing.expectEqual(@as(usize, 257), if_count);
}

test "ec mul gen helper seeds the generator point" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .ec_mul_gen);
    defer bundle.deinit();

    try std.testing.expect(bundle.ops.len > 2);
    try std.testing.expectEqual(@as(?usize, 64), firstPushBytesLen(bundle.ops));
    try std.testing.expect(containsOpcode(bundle.ops, "OP_SPLIT"));
}

test "ec on curve helper ends in canonicity-anded equality" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .ec_on_curve);
    defer bundle.deinit();

    // GAP-301: ecOnCurve now returns (x < p) AND (y < p) AND curve-equation,
    // so the final op is the OP_BOOLAND that folds canonicity into the result.
    try std.testing.expect(bundle.ops.len > 0);
    try std.testing.expectEqualStrings("OP_BOOLAND", bundle.ops[bundle.ops.len - 1].opcode);
    try std.testing.expect(containsOpcode(bundle.ops, "OP_LESSTHAN"));
}

test "ec negate helper uses field-prime script number bytes" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .ec_negate);
    defer bundle.deinit();

    var found = false;
    for (bundle.ops) |op| {
        switch (op) {
            .push => |value| switch (value) {
                .bytes => |bytes| {
                    if (bytes.len != 33) continue;
                    if (bytes[0] != 0x2f or bytes[1] != 0xfc or bytes[2] != 0xff or bytes[3] != 0xff or bytes[4] != 0xfe) continue;
                    if (bytes[32] != 0x00) continue;
                    found = true;
                    break;
                },
                else => {},
            },
            else => {},
        }
    }

    try std.testing.expect(found);
}

test "ec mul helper uses combined 3n scalar offset" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .ec_mul);
    defer bundle.deinit();

    var found = false;
    for (bundle.ops) |op| {
        switch (op) {
            .push => |value| switch (value) {
                .bytes => |bytes| {
                    if (std.mem.eql(u8, bytes, curve_3n_script_num_le[0..])) {
                        found = true;
                        break;
                    }
                },
                else => {},
            },
            else => {},
        }
    }

    try std.testing.expect(found);
}

test "field prime encoding uses initialized script number bytes" {
    const encoded = try beToUnsignedScriptNumAlloc(std.testing.allocator, field_p_be[0..]);
    defer std.testing.allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 33), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x2f), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0xfc), encoded[1]);
    try std.testing.expectEqual(@as(u8, 0xff), encoded[2]);
    try std.testing.expectEqual(@as(u8, 0xff), encoded[3]);
    try std.testing.expectEqual(@as(u8, 0xfe), encoded[4]);
    try std.testing.expectEqual(@as(u8, 0x00), encoded[32]);
}

test "small power-of-two divisors use small-int pushes" {
    var tracker = try ECTracker.init(std.testing.allocator, &.{});
    defer tracker.deinit();

    try pushPow2Divisor(&tracker, "_pow2", 4);

    try std.testing.expectEqual(@as(usize, 1), tracker.ops.items.len);
    try std.testing.expectEqualDeep(StackOp{ .push = .{ .integer = 16 } }, tracker.ops.items[0]);
}
