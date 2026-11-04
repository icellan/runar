//! N-279: `anf_lower.zig`'s MAX_PRIVATE_CALL_DEPTH (the cutoff for the
//! `methodMutatesState` / `methodHasAddOutput` / `methodHasAddDataOutput` /
//! requireOutputP2PKH BFS walks over the private-call graph) was 64, while
//! N-180's MAX_CALL_DEPTH -- the call depth `validate.zig` actually admits --
//! is 128. A mutation (or addOutput/addDataOutput/requireOutputP2PKH call)
//! reachable only through >=65 private-helper hops is validator-legal but
//! sat past this tier's predicate cutoff, so `methodMutatesState` returned
//! false for it: the public method was classified TERMINAL, the compiler
//! omitted the `_changePKH` / `_changeAmount` continuation parameters and the
//! `hashOutputs` continuation assertion, and the deployed script carried no
//! covenant at all -- a silent fund-loss shape, not a refusal. The other six
//! tiers (TS's `side-effect-summary.ts`, Go's `side_effect_summary.go`, and
//! their Rust/Python/Ruby/Java equivalents) walk the private-call graph with
//! a visited-set but no depth cutoff of their own, relying on `validate.zig`
//! (MAX_CALL_DEPTH=128) to bound the walk, so they never truncated.
//!
//! The fixture: a chain of 71 flat private helpers (`m0..m70`, no nested
//! ifs, since compile memory grows quadratically with nesting depth -- see
//! N-280), where only the LAST helper (`m70`) mutates a non-readonly
//! property. The call distance from `verify` to that mutation is 71 hops --
//! past the old 64-hop cutoff, comfortably under N-180's 128-hop admission
//! limit.
//!
//! Proves: at HEAD before this fix (MAX_PRIVATE_CALL_DEPTH=64,
//! branch rem/N-279 off 287f12413) this tier's hex differs from the pinned
//! sha256 digest of the hex the unmodified Go compiler printed for the
//! identical source (captured once, offline, with `compilers/go/runar-go
//! --source <fixture> --disable-constant-folding --hex`); after raising
//! MAX_PRIVATE_CALL_DEPTH to 128 (N-180's admitted call depth), this tier's
//! hex matches that digest -- i.e. the `_changePKH`/`_changeAmount`
//! continuation and `hashOutputs` assertion are emitted, byte-identical to
//! Go. `compileSourceToHex` here compiles fold-ON (constant folding
//! enabled, `compileSource`'s default); the pinned digest was independently
//! confirmed identical between Go's fold-ON and fold-OFF output for this
//! fixture (no literal in it is foldable), so one digest covers both modes.
//! The D=127/D=128 boundary (one hop short of / exactly at N-180's limit)
//! was hand-checked against Go and found correct: D=127 compiles
//! byte-identically in both tiers, and D=128 is refused by both with the
//! shared "call depth ... exceeds MAX_CALL_DEPTH (limit=128)" diagnostic --
//! not re-asserted here as a second pinned digest.
//! Does not prove: that every tier agrees (checked once, by hand, against
//! Go/Rust/Python/Ruby/Java/TS CLIs at remediation time, in BOTH fold modes
//! -- all five native tiers and TS matched Go byte-for-byte; TS differed
//! only by a trailing newline in captured CLI output), that the fix is
//! correct for every depth between 65 and 128 (only D=70, and by hand D=127
//! and D=128, were exercised), or that Go's reference output is itself
//! correct beyond that cross-tier agreement.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

/// A flat chain of `n` private helpers `m0 -> m1 -> ... -> mn`. Every helper
/// but the last just forwards its argument to the next one; `mn` assigns it
/// into the contract's only mutable property. `verify` is the one public
/// entry point, calling `m0`.
fn chainWithMutationAtLeaf(w: std.mem.Allocator, n: usize) ![]const u8 {
    var b: std.ArrayListUnmanaged(u8) = .empty;
    try b.appendSlice(w, "import { StatefulSmartContract, assert } from 'runar-lang';\nclass P extends StatefulSmartContract {\n count: bigint;\n constructor(count: bigint) { super(count); this.count = count; }\n");
    for (0..n) |i| {
        try b.appendSlice(w, try std.fmt.allocPrint(w, " private m{d}(x: bigint): bigint {{ return this.m{d}(x); }}\n", .{ i, i + 1 }));
    }
    try b.appendSlice(w, try std.fmt.allocPrint(
        w,
        " private m{d}(x: bigint): bigint {{ this.count = x; return x; }}\n public verify(a: bigint) {{ this.m0(a); }}\n}}\n",
        .{n},
    ));
    return b.items;
}

test "N-279: a mutation 71 private-helper hops deep compiles byte-identically to Go" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const w = arena.allocator();

    const src = try chainWithMutationAtLeaf(w, 70);
    const hex = try compiler_api.compileSourceToHex(w, src, "P.runar.ts");

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(hex, &digest, .{});
    const got = std.fmt.bytesToHex(digest, .lower);

    // sha256 of the hex `compilers/go/runar-go --source <this fixture>
    // --disable-constant-folding --hex` printed at HEAD (5b75534ec-equivalent
    // tip for N-279), independently reproduced by Rust, Python, Ruby, Java
    // and the TS reference compiler against the same source.
    // N-216 (2026-10-21): re-pinned; the branch-reconcile rolls now fold (`<k> OP_ROLL` -> OP_SWAP / OP_ROT), opcode diff vs the old pin is folds only (Go agrees).
    // Ports #170: re-pinned; the C=1 binding blob is 6 B shorter (Go and TS agree).
    try std.testing.expectEqualStrings("27af114291005cad95d905511793a9fa98cc0560faebcf6a312e6097ec44b85d", &got);
}
