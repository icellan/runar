//! N-434 -- computeOpPushTxImpl registered `errdefer allocator.free(sig_hex)` and
//! then also freed `sig_hex` by hand inside the `catch` arms of the preimage-hex
//! allocation/encode, so an allocation failure there freed the signature buffer
//! twice. The fix drops the manual frees and leaves the errdefer as the single
//! owner.
//!
//! Proves: with the allocation-failure index swept over every allocation
//! computeOpPushTx makes (the signing path, so `sig_hex` is non-empty), a
//! tracking allocator (below) sees no free of a non-live pointer (the
//! DebugAllocator only logs a double free and does not fail the run, so the
//! tracker turns it into a failing assertion) and no live allocation left after
//! a failed run; the run past the last allocation succeeds. Says nothing about encode failures (hex.encodeLower cannot fail on
//! a correctly sized buffer, so that arm is unreachable by input) nor about the
//! preimage-only (`want_sig = false`) variant's signature bytes.

const std = @import("std");
const oppushtx = @import("sdk_oppushtx.zig");

const tx_hex = "01000000" ++ "01" ++
    "1111111111111111111111111111111111111111111111111111111111111111" ++
    "00000000" ++ "00" ++ "ffffffff" ++ "01" ++ "e803000000000000" ++
    "01" ++ "51" ++ "00000000";
const subscript_hex = "76a914" ++ "0000000000000000000000000000000000000000" ++ "88ac";

/// Records live allocations by pointer; flags any free of a pointer that is
/// not live. Wraps `backing` but never forwards a bad free to it.
const Tracker = struct {
    backing: std.mem.Allocator,
    live: [32]?[*]u8 = [_]?[*]u8{null} ** 32,
    double_freed: bool = false,

    fn allocator(self: *Tracker) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn liveCount(self: *const Tracker) usize {
        var n: usize = 0;
        for (self.live) |p| {
            if (p != null) n += 1;
        }
        return n;
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Tracker = @ptrCast(@alignCast(ctx));
        const p = self.backing.rawAlloc(len, alignment, ra) orelse return null;
        for (&self.live) |*slot| {
            if (slot.* == null) {
                slot.* = p;
                return p;
            }
        }
        unreachable; // live table too small
    }

    fn resize(ctx: *anyopaque, m: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *Tracker = @ptrCast(@alignCast(ctx));
        return self.backing.rawResize(m, alignment, new_len, ra);
    }

    fn remap(ctx: *anyopaque, m: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *Tracker = @ptrCast(@alignCast(ctx));
        const np = self.backing.rawRemap(m, alignment, new_len, ra) orelse return null;
        if (np != m.ptr) {
            for (&self.live) |*slot| {
                if (slot.* == m.ptr) slot.* = np;
            }
        }
        return np;
    }

    fn free(ctx: *anyopaque, m: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *Tracker = @ptrCast(@alignCast(ctx));
        for (&self.live) |*slot| {
            if (slot.* == m.ptr) {
                slot.* = null;
                self.backing.rawFree(m, alignment, ra);
                return;
            }
        }
        self.double_freed = true; // not live: do not pass it on
    }
};

fn sweep(comptime with_sig: bool) !void {
    var fail_index: usize = 0;
    while (fail_index < 256) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        var tracker = Tracker{ .backing = failing.allocator() };
        const a = tracker.allocator();
        const r = if (with_sig)
            oppushtx.computeOpPushTx(a, tx_hex, 0, subscript_hex, 1000, -1)
        else
            oppushtx.computeOpPushTxPreimageWithSigHash(a, tx_hex, 0, subscript_hex, 1000, -1, 0x41);
        if (r) |res| {
            var m = res;
            m.deinit(a);
            try std.testing.expect(!tracker.double_freed);
            try std.testing.expectEqual(@as(usize, 0), tracker.liveCount());
            // fail_index is past every allocation: the run completed.
            try std.testing.expect(!failing.has_induced_failure);
            return;
        } else |_| {
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expect(!tracker.double_freed);
            try std.testing.expectEqual(@as(usize, 0), tracker.liveCount());
        }
    }
    return error.SweepNeverCompleted;
}

test "N-434: computeOpPushTx frees each buffer exactly once under allocation failure" {
    try sweep(true);
}

test "N-434: computeOpPushTxPreimageWithSigHash frees each buffer exactly once under allocation failure" {
    try sweep(false);
}
