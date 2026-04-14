//! Fiat-Shamir duplex sponge (DuplexChallenger) over KoalaBear — codegen for Bitcoin Script.
//!
//! Implements the Fiat-Shamir challenge derivation used by SP1's StackedBasefold
//! verifier. The sponge uses Poseidon2 as the permutation primitive.
//!
//! Parameters (SP1 v6, DuplexChallenger<KoalaBear, KoalaPerm, 16, 8>):
//!   - State width: 16 KoalaBear field elements
//!   - Rate: 8 elements (positions 0-7)
//!   - Capacity: 8 elements (positions 8-15)
//!
//! Key design property: the sponge position is tracked at codegen time (in Zig),
//! not at runtime (in Bitcoin Script). Because the verifier's transcript structure
//! is fully deterministic, we always know exactly when to permute without runtime
//! conditionals.
//!
//! Matches Plonky3 DuplexChallenger behavior:
//!   - Observations write directly into the sponge state and invalidate cached
//!     squeeze outputs. When the rate is filled, the state is permuted.
//!   - Squeezing reads consecutive elements from the permuted state. A single
//!     permutation provides up to RATE (8) squeeze outputs.
//!   - Any observation after squeezing invalidates the cached outputs.

const std = @import("std");
const kb = @import("koalabear_emitters.zig");
const p2kb = @import("poseidon2_koalabear.zig");
const ec = @import("ec_emitters.zig");

const Allocator = std.mem.Allocator;
const KBTracker = kb.KBTracker;
const StackOp = ec.StackOp;

// ===========================================================================
// Constants
// ===========================================================================

/// fsSpongeWidth is the full Poseidon2 state width (rate + capacity).
const fsSpongeWidth: usize = 16;

/// fsSpongeRate is the number of rate elements in the duplex sponge.
const fsSpongeRate: usize = 8;

// Static string literals for names that are referenced by slice but never freed.
// These are valid for the lifetime of the program.
const FS_ABSORB_ELEM: []const u8 = "_fs_absorb_elem";
const FS_SQUEEZED: []const u8 = "_fs_squeezed";

// ===========================================================================
// State naming helpers
// ===========================================================================

/// fsSpongeStateName returns the canonical name for sponge state element i.
/// Writes into buf and returns a slice of it.
pub fn fsSpongeStateName(i: usize, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "fs{d}", .{i}) catch unreachable;
}

// ===========================================================================
// FiatShamirState — codegen-time duplex sponge state machine
// ===========================================================================

/// FiatShamirState tracks the duplex sponge position at codegen time, matching
/// Plonky3's DuplexChallenger semantics. The 16-element KoalaBear state lives
/// on the Bitcoin Script stack as fs0 (deepest) through fs15 (top).
///
/// Two independent positions are tracked:
///   - absorb_pos: where the next observation will be written (0..RATE-1)
///   - squeeze_pos: where the next squeeze will read from (0..RATE-1)
///   - output_valid: whether the current state has been permuted and is safe
///     to squeeze from (invalidated by any observation)
pub const FiatShamirState = struct {
    absorb_pos: usize,
    squeeze_pos: usize,
    output_valid: bool,
    allocator: Allocator,

    /// init creates a new sponge state. The initial state has no valid output
    /// (first squeeze will trigger a permutation).
    pub fn init(allocator: Allocator) FiatShamirState {
        return .{
            .absorb_pos = 0,
            .squeeze_pos = 0,
            .output_valid = false,
            .allocator = allocator,
        };
    }

    // ===========================================================================
    // emitInit — push the initial all-zero sponge state
    // ===========================================================================

    /// emitInit pushes 16 zero-valued KoalaBear field elements onto the stack as
    /// the initial sponge state. After this call the stack contains:
    ///   [..., fs0=0, fs1=0, ..., fs15=0]  (fs15 on top)
    pub fn emitInit(self: *FiatShamirState, t: *KBTracker) !void {
        for (0..fsSpongeWidth) |i| {
            var name_buf: [16]u8 = undefined;
            const name = fsSpongeStateName(i, &name_buf);
            const name_owned = try self.allocator.dupe(u8, name);
            try t.owned_bytes.append(self.allocator, name_owned);
            try t.pushInt(name_owned, 0);
        }
        self.absorb_pos = 0;
        self.squeeze_pos = 0;
        self.output_valid = false;
    }

    // ===========================================================================
    // emitPermute — rename sponge state, run Poseidon2, rename back
    // ===========================================================================

    /// emitPermute emits a full Poseidon2 permutation on the 16-element sponge
    /// state. The sponge elements fs0..fs15 are renamed to the Poseidon2 canonical
    /// names _p2s0.._p2s15, the permutation is applied, and the results are
    /// renamed back to fs0..fs15.
    fn emitPermute(self: *FiatShamirState, t: *KBTracker) !void {
        // Allocate owned Poseidon2 state names (_p2s0.._p2s15).
        var p2_name_bufs: [fsSpongeWidth][16]u8 = undefined;
        var p2_names: [fsSpongeWidth][]const u8 = undefined;
        for (0..fsSpongeWidth) |i| {
            const p2n = p2kb.p2kbStateName(i, &p2_name_bufs[i]);
            // Make an owned copy so the tracker can hold it.
            const p2n_owned = try self.allocator.dupe(u8, p2n);
            try t.owned_bytes.append(self.allocator, p2n_owned);
            p2_names[i] = p2n_owned;
        }

        // Rename fs0..fs15 → _p2s0.._p2s15 and reorder for Poseidon2.
        for (0..fsSpongeWidth) |i| {
            var fs_buf: [16]u8 = undefined;
            const fs_name = fsSpongeStateName(i, &fs_buf);
            try t.toTop(fs_name);
            t.renameTop(p2_names[i]);
        }

        // Cache the KoalaBear prime on the alt-stack for the duration of the permutation.
        try t.pushPrimeCache();

        // Run the permutation in-place on the tracker.
        try p2kb.poseidon2KBPermuteShared(t, &p2_names, self.allocator);

        try t.popPrimeCache();

        // Reorder post-permutation elements and rename back to fs0..fs15.
        for (0..fsSpongeWidth) |i| {
            var fs_buf: [16]u8 = undefined;
            const fs_name_str = fsSpongeStateName(i, &fs_buf);
            const fs_owned = try self.allocator.dupe(u8, fs_name_str);
            try t.owned_bytes.append(self.allocator, fs_owned);

            try t.toTop(p2_names[i]);
            t.renameTop(fs_owned);
        }
    }

    // ===========================================================================
    // emitObserve — absorb one field element into the sponge
    // ===========================================================================

    /// emitObserve absorbs one KoalaBear field element from the top of the stack
    /// into the sponge state.
    ///
    /// Stack in:  [..., fs0, ..., fs15, element]
    /// Stack out: [..., fs0', ..., fs15']   (element consumed)
    pub fn emitObserve(self: *FiatShamirState, t: *KBTracker) !void {
        // Allocate owned target name for the sponge slot being overwritten.
        var target_buf: [16]u8 = undefined;
        const target_name_str = fsSpongeStateName(self.absorb_pos, &target_buf);
        const target_owned = try self.allocator.dupe(u8, target_name_str);
        try t.owned_bytes.append(self.allocator, target_owned);

        // The element to absorb is on top. Rename it to a temp name.
        t.renameTop(FS_ABSORB_ELEM);

        // Bring the target sponge slot to the top and drop it.
        try t.toTop(target_owned);
        try t.drop();

        // Move the absorbed element to the top and rename it to the sponge slot.
        try t.toTop(FS_ABSORB_ELEM);
        t.renameTop(target_owned);

        // Invalidate cached squeeze outputs.
        self.output_valid = false;

        self.absorb_pos += 1;
        if (self.absorb_pos == fsSpongeRate) {
            try self.emitPermute(t);
            self.absorb_pos = 0;
            self.squeeze_pos = 0;
            self.output_valid = true;
        }
    }

    // ===========================================================================
    // emitSqueeze — sample one field element from the sponge
    // ===========================================================================

    /// emitSqueeze samples one KoalaBear field element from the sponge.
    ///
    /// Stack in:  [..., fs0, ..., fs15]
    /// Stack out: [..., fs0', ..., fs15', sampled]
    pub fn emitSqueeze(self: *FiatShamirState, t: *KBTracker) !void {
        if (!self.output_valid or self.squeeze_pos >= fsSpongeRate) {
            try self.emitPermute(t);
            self.absorb_pos = 0;
            self.squeeze_pos = 0;
            self.output_valid = true;
        }

        var source_buf: [16]u8 = undefined;
        const source_name = fsSpongeStateName(self.squeeze_pos, &source_buf);
        try t.copyToTop(source_name, FS_SQUEEZED);

        self.squeeze_pos += 1;
    }

    // ===========================================================================
    // emitSqueezeExt4 — sample a quartic extension element (4 field elements)
    // ===========================================================================

    /// emitSqueezeExt4 samples 4 consecutive KoalaBear field elements from the
    /// sponge, forming a quartic extension field element.
    ///
    /// Stack in:  [..., fs0, ..., fs15]
    /// Stack out: [..., fs0', ..., fs15', e0, e1, e2, e3]
    pub fn emitSqueezeExt4(self: *FiatShamirState, t: *KBTracker) !void {
        for (0..4) |i| {
            try self.emitSqueeze(t);
            // Rename from _fs_squeezed to a numbered output name.
            var name_buf: [32]u8 = undefined;
            const name_str = try std.fmt.bufPrint(&name_buf, "_fs_ext4_{d}", .{i});
            const name_owned = try self.allocator.dupe(u8, name_str);
            try t.owned_bytes.append(self.allocator, name_owned);
            t.renameTop(name_owned);
        }
    }

    // ===========================================================================
    // emitSampleBits — squeeze and extract low n bits
    // ===========================================================================

    /// emitSampleBits squeezes one field element and extracts its low n bits.
    /// n must be in [1, 20].
    ///
    /// Stack in:  [..., fs0, ..., fs15]
    /// Stack out: [..., fs0', ..., fs15', bits]
    pub fn emitSampleBits(self: *FiatShamirState, t: *KBTracker, n: u5) !void {
        std.debug.assert(n >= 1 and n <= 20);
        try self.emitSqueeze(t);
        // _fs_squeezed is on top. Mask to low n bits: val % (2^n).
        const mask: i64 = @as(i64, 1) << n;
        // Consume _fs_squeezed name, emit push + mod, produce _fs_bits
        t.popNames(1);
        try t.emitPushInt(mask);
        try t.emitOpcode("OP_MOD");
        try t.names.append(self.allocator, "_fs_bits");
    }

    // ===========================================================================
    // emitCheckWitness — verify proof-of-work on sponge state
    // ===========================================================================

    /// emitCheckWitness absorbs a witness element from the top of the stack,
    /// squeezes a challenge, and verifies that the low `bits` bits of the
    /// challenge are all zero (proof-of-work check).
    ///
    /// Stack in:  [..., fs0, ..., fs15, witness]
    /// Stack out: [..., fs0', ..., fs15']   (witness consumed, assert on failure)
    pub fn emitCheckWitness(self: *FiatShamirState, t: *KBTracker, bits: u5) !void {
        std.debug.assert(bits >= 1 and bits <= 30);

        // Absorb the witness.
        try self.emitObserve(t);

        // Squeeze a challenge element.
        try self.emitSqueeze(t);

        // Extract low `bits` bits.
        const mask: i64 = @as(i64, 1) << bits;
        t.popNames(1); // consume _fs_squeezed
        try t.emitPushInt(mask);
        try t.emitOpcode("OP_MOD");
        try t.names.append(self.allocator, "_fs_pow_check");

        // Assert _fs_pow_check == 0: push 0, NUMEQUAL, VERIFY.
        try t.pushInt("_fs_pow_zero", 0);
        t.popNames(2); // consume _fs_pow_check and _fs_pow_zero
        try t.emitOpcode("OP_NUMEQUAL");
        try t.emitOpcode("OP_VERIFY");
    }
};

// ===========================================================================
// Tests
// ===========================================================================

test "FiatShamirState init state" {
    const fs = FiatShamirState.init(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), fs.absorb_pos);
    try std.testing.expectEqual(@as(usize, 0), fs.squeeze_pos);
    try std.testing.expect(!fs.output_valid);
}

test "emitInit pushes 16 zeros" {
    const allocator = std.testing.allocator;
    var fs = FiatShamirState.init(allocator);
    var tracker = try KBTracker.init(allocator, &.{});
    defer tracker.deinit();
    try fs.emitInit(&tracker);
    // Should have pushed 16 integer zeros
    var push_count: usize = 0;
    for (tracker.ops.items) |op| {
        switch (op) {
            .push => |pv| {
                if (pv == .integer and pv.integer == 0) push_count += 1;
            },
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 16), push_count);
    // Name stack should have 16 entries
    try std.testing.expectEqual(@as(usize, 16), tracker.names.items.len);
}

test "fsSpongeStateName produces correct names" {
    var buf0: [16]u8 = undefined;
    var buf7: [16]u8 = undefined;
    var buf15: [16]u8 = undefined;
    try std.testing.expectEqualStrings("fs0", fsSpongeStateName(0, &buf0));
    try std.testing.expectEqualStrings("fs7", fsSpongeStateName(7, &buf7));
    try std.testing.expectEqualStrings("fs15", fsSpongeStateName(15, &buf15));
}

test "emitObserve advances absorb_pos" {
    const allocator = std.testing.allocator;
    var fs = FiatShamirState.init(allocator);

    // Build a tracker that already has fs0..fs15 + one element on top
    var initial: [17]?[]const u8 = undefined;
    for (0..16) |i| {
        initial[i] = try std.fmt.allocPrint(allocator, "fs{d}", .{i});
    }
    initial[16] = "elem";
    defer {
        for (initial[0..16]) |name| {
            if (name) |n| allocator.free(n);
        }
    }

    var tracker = try KBTracker.init(allocator, &initial);
    defer tracker.deinit();

    // Emit a few pushes to fill the name list (the tracker doesn't own ops yet)
    for (0..17) |_| {
        try tracker.emitPushInt(0);
    }

    // emitObserve should consume the top element and update absorb_pos
    try fs.emitObserve(&tracker);
    try std.testing.expectEqual(@as(usize, 1), fs.absorb_pos);
    try std.testing.expect(!fs.output_valid);
}
