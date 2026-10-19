//! N-343 — compile WORK must not grow quadratically in if-nesting depth.
//!
//! Stack lowering peepholes each `if` arm on its own (N-100) and splices the
//! result into the enclosing arm, which is then peepholed and spliced in turn.
//! Every enclosing `if` therefore re-scanned and re-copied everything nested
//! inside it, so the work grew with the SQUARE of the nesting depth. On the
//! N-264 / N-280 shape (D helpers, each calling the next under 120 nested ifs)
//! the ReleaseSafe CLI took 97 s at D=127 against Go's 7 s on the same host.
//!
//! The test compiles that shape in-process and reads two work counters the
//! compiler keeps for this purpose: `peephole.ops_visited` (instructions read
//! by the peephole, every pass of every call) and `stack_lower.spliced_insts`
//! (instructions copied while assembling a conditional into its parent). Both
//! must stay within a constant factor of the size of the emitted script. A
//! deterministic count, unlike wall-clock time, does not depend on the host's
//! load or the build mode.
//!
//! Proves: at D=8 x 120 (960 nested ifs after inlining) the peephole reads at
//! most `visit_factor` instructions per script byte and stack lowering copies
//! at most `splice_factor` per script byte, and the script is byte-identical
//! to the one the Go compiler prints for the same source (the sha256 the
//! N-280 test pins). Because the depth is fixed, it is the RATIO that the
//! bound catches: before the fix both counters sit hundreds of times above
//! it.
//! Does not prove: wall-clock time (measured by hand: D=127 in ReleaseSafe),
//! the cost of stack lowering's own bookkeeping outside these two counters,
//! or the other tiers.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const peephole = @import("../passes/peephole.zig");
const stack_lower = @import("../passes/stack_lower.zig");
const n264 = @import("n264_composite_nesting.zig");

/// Peephole reads allowed per emitted script byte. Each instruction is read by
/// a few passes of its own arm's optimization and a few of the method-level
/// one; a constant, whatever the depth.
const visit_factor: usize = 16;
/// Splice copies allowed per emitted script byte.
const splice_factor: usize = 4;

test "N-343: D=8 x 120 compiles to Go's bytes with work linear in the script size" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const w = arena.allocator();

    peephole.ops_visited = 0;
    stack_lower.spliced_insts = 0;
    const hex = try compiler_api.compileSourceToHex(w, try n264.comp(w, 8, 120), "comp8k120.runar.ts");
    const visited = peephole.ops_visited;
    const spliced = stack_lower.spliced_insts;

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(hex, &digest, .{});
    const got = std.fmt.bytesToHex(digest, .lower);
    try std.testing.expectEqualStrings("579eeccfa4389f180849590c9857e7520a284bc3e5fb6d367a3291ee9c8a5052", &got);

    const script_bytes = hex.len / 2;
    if (visited > visit_factor * script_bytes or spliced > splice_factor * script_bytes) {
        std.debug.print(
            "N-343: D=8 x 120 ({d} script bytes): peephole read {d} instructions (bound {d}), " ++
                "stack lowering copied {d} (bound {d})\n",
            .{ script_bytes, visited, visit_factor * script_bytes, spliced, splice_factor * script_bytes },
        );
        return error.WorkNotLinear;
    }
}
