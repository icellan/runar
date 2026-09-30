//! N-064 — constant folding must not fold with a constant a name no longer
//! holds. Port of the reference tier's case in
//! packages/runar-compiler/src/__tests__/optimizer.test.ts.
//!
//! The folder recorded a name's constant when a binding produced one and never
//! dropped it. A name can be bound more than once, so with folding ON (the
//! default) later uses folded with a stale value: Rebind's guard became OP_TRUE
//! (7600a0695151515177777777, spendable with any p > 0), RebindEq's became
//! OP_FALSE, and a rebinding inside an if arm or a loop body leaked the same
//! way past the if / into later iterations.
//!
//! The four probes reached that shape from source by naming a local like an
//! earlier ANF temp (`let t1: bigint = p;`). N-065 now refuses that source in
//! every tier, which this test asserts. The fold must still be right for the
//! shape itself, so each probe's EXACT fold-OFF ANF
//! (conformance/negatives/n064-collision-anf.json, generated from the source
//! with parse -> lowerToANF and no validator) is loaded through the IR loader
//! (duplicate `t<N>` BINDING names are legal IR) and run through this tier's
//! folder. On the reference tier the pre-N-064 folder reproduces each
//! `staleFoldOn` script byte for byte on that ANF, so the replay keeps the
//! regression value the source probes had.
//!
//! Proves: this tier refuses each probe source with the N-065 message, and on
//! the collision ANF compiles the same bytes with and without folding, pinned
//! to the shared fold-OFF bytes and distinct from the stale script. Does NOT
//! prove on-chain behaviour — the Spend-engine proof is
//! packages/runar-testing/src/__tests__/n064-rebind-fold-spend.test.ts.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const json = @import("../ir/json.zig");
const constant_fold = @import("../passes/constant_fold.zig");
const ec_optimizer = @import("../passes/ec_optimizer.zig");
const stack_lower = @import("../passes/stack_lower.zig");
const peephole = @import("../passes/peephole.zig");
const emit = @import("../codegen/emit.zig");

const corpus_path = "../../conformance/negatives/n064-collision-anf.json";

/// The local each probe spells like a temp — the name N-065 refuses.
fn collidingLocal(name: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, name, "Rebind")) "t1" else "t2";
}

/// main.zig's `--ir` pipeline, optionally with the constant folder in front
/// (the position it holds in the source pipeline).
fn compileAnf(a: std.mem.Allocator, src: []const u8, fold: bool) ![]const u8 {
    var program = try json.parseANFProgram(a, src);
    if (fold) program = try constant_fold.foldConstants(a, program);
    const optimized = try ec_optimizer.optimize(a, program);
    const sp = try stack_lower.lower(a, optimized);
    const methods = try peephole.optimize(a, sp.methods);
    const artifact = try emit.emitArtifact(a, .{
        .methods = methods,
        .contract_name = sp.contract_name,
        .properties = sp.properties,
        .constructor_params = sp.constructor_params,
    }, optimized);
    return try compiler_api.extractArtifactScript(artifact);
}

test "N-064: on the collision ANF, fold-ON equals the fold-OFF bytes; the source is refused (N-065)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, corpus_path, a, .limited(1024 * 1024));
    const corpus = try std.json.parseFromSliceLeaky(std.json.Value, a, raw, .{});
    const probes = corpus.object.get("probes").?.array.items;
    try std.testing.expectEqual(@as(usize, 4), probes.len);

    for (probes) |p| {
        const name = p.object.get("name").?.string;
        const fold_off = p.object.get("foldOff").?.string;
        const stale = p.object.get("staleFoldOn").?.string;
        try std.testing.expect(!std.mem.eql(u8, fold_off, stale));

        // N-065: the source form is refused.
        const file = try std.fmt.allocPrint(a, "{s}.runar.ts", .{name});
        const parsed = compiler_api.parseSource(a, p.object.get("source").?.string, file);
        try std.testing.expect(parsed.contract != null);
        const vr = try compiler_api.validateForFile(a, parsed.contract.?, file);
        const want = try std.fmt.allocPrint(a, "'{s}' is reserved for compiler-generated names and cannot be used as an identifier", .{collidingLocal(name)});
        var refused = false;
        for (vr.errors) |d| {
            if (std.mem.eql(u8, d.message, want)) refused = true;
        }
        if (!refused) {
            std.debug.print("{s}: source not refused with \"{s}\"\n", .{ name, want });
            return error.TestUnexpectedResult;
        }

        // N-064: the folder on the exact collision ANF.
        const ir = try std.json.Stringify.valueAlloc(a, p.object.get("ir").?, .{});
        for ([_]bool{ false, true }) |fold| {
            const hex = try compileAnf(a, ir, fold);
            if (!std.mem.eql(u8, fold_off, hex)) {
                std.debug.print("{s} fold={}: want {s}, got {s}\n", .{ name, fold, fold_off, hex });
                return error.TestExpectedEqual;
            }
        }
    }
}
