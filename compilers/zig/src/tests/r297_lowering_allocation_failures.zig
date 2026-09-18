//! R-297 (CL-GAP-092): ANF lowering swallows allocation failures.
//!
//! Eighteen call sites in `passes/anf_lower.zig` and `passes/stack_lower.zig`
//! end in `catch {}` or `catch return`. Every one of them is a hash-map `put`
//! or a list `append` whose only error is `OutOfMemory`, and every one of them
//! records a FACT the rest of lowering reads back:
//!
//!     add_output_refs.append(...)  catch {}   the outputs the continuation
//!                                             hash is built from
//!     local_names.put(...)         catch {}   whether a name is a local
//!     param_names.put(...)         catch {}   whether a name is a parameter
//!     local_aliases.put(...)       catch {}   which binding a local resolves to
//!     auto_injected_set.put(...)   catch return  the intent-injected witness
//!                                                params, and their ABI order
//!
//! Under allocation failure the effect is not a crash and not an error — it is
//! a MISCOMPILE. A dropped `add_output_refs` entry removes an output from the
//! continuation hash; a dropped `local_names` entry makes a local look like a
//! property. The compiler then finishes normally and prints a script.
//!
//! The property asserted here is the one that makes the difference observable
//! without naming any individual call site: under ANY single allocation
//! failure, lowering must either REPORT the failure or produce EXACTLY the
//! program it produces when nothing fails. "Silently different" is the third
//! outcome, and it is the defect.
//!
//! The sweep runs `lowerToANF` once per allocation the successful run makes,
//! failing that one allocation and no other, and compares the canonical JSON.
//! Measured against the unfixed compiler: 124 allocations, 18 runs finished
//! anyway (those are the swallowing sites, continuing past their own failure),
//! and 4 of those 18 produced a DIFFERENT program. After the fix every one of
//! the 124 reports the failure instead.
//!
//! `std.testing.FailingAllocator` cannot be the instrument. Its `fail_index`
//! does not increment `alloc_index` on the induced failure, so once it fires
//! EVERY later allocation fails too — the first `try` after it turns the run
//! into a plain `error.OutOfMemory` and the swallowed site is never reached.
//! The first version of this test used it and swept 124 indices with ZERO runs
//! completing: it asserted nothing. `OneShotFailing` below fails exactly one
//! allocation and then behaves normally, which is the only way a `catch {}`
//! site can be observed continuing past its own failure.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const typecheck = @import("../passes/typecheck.zig");
const expand_fixed_arrays = @import("../passes/expand_fixed_arrays.zig");
const anf_lower = @import("../passes/anf_lower.zig");
const stack_lower = @import("../passes/stack_lower.zig");
const emit = @import("../codegen/emit.zig");
const ir_json = @import("../ir/json.zig");
const types = @import("../ir/types.zig");

/// An allocator that fails EXACTLY the n-th allocation and then behaves
/// normally. `std.testing.FailingAllocator` fails the n-th and every one after
/// it, which turns any swallowed failure into an unrelated hard OOM downstream.
const OneShotFailing = struct {
    backing: std.mem.Allocator,
    fail_at: usize,
    index: usize = 0,
    fired: bool = false,

    fn allocator(self: *OneShotFailing) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *OneShotFailing = @ptrCast(@alignCast(ctx));
        const at = self.index;
        self.index += 1;
        if (at == self.fail_at) {
            self.fired = true;
            return null;
        }
        return self.backing.rawAlloc(len, alignment, ra);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *OneShotFailing = @ptrCast(@alignCast(ctx));
        return self.backing.rawResize(memory, alignment, new_len, ra);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *OneShotFailing = @ptrCast(@alignCast(ctx));
        return self.backing.rawRemap(memory, alignment, new_len, ra);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *OneShotFailing = @ptrCast(@alignCast(ctx));
        self.backing.rawFree(memory, alignment, ra);
    }
};

/// A stateful contract that exercises the swallowing sites together: a local
/// (`local_names`), a rebound local read after an `if` (`local_aliases` and a
/// sub-context), a parameter used in both arms (`param_names`), a loop, and an
/// `addOutput` whose continuation hash is built from `add_output_refs`.
const SRC =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\class AllocProbe extends StatefulSmartContract {
    \\  count: bigint;
    \\  readonly step: bigint;
    \\
    \\  constructor(count: bigint, step: bigint) {
    \\    super(count, step);
    \\    this.count = count;
    \\    this.step = step;
    \\  }
    \\
    \\  public bump(delta: bigint) {
    \\    let acc: bigint = 0n;
    \\    for (let i = 0n; i < 3n; i++) {
    \\      acc = acc + this.step;
    \\    }
    \\    let merged: bigint = acc;
    \\    if (delta > 0n) {
    \\      merged = merged + delta;
    \\    } else {
    \\      merged = merged + 1n;
    \\    }
    \\    this.count = this.count + merged;
    \\    assert(this.count >= 0n);
    \\  }
    \\}
    \\
;

/// A contract whose stack lowering leans on `last_uses`: every local below is
/// read TWICE, so the last-use map is what decides copy-versus-consume at each
/// read. A dropped entry makes a value look dead at its first read.
const STACK_SRC =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\class StackProbe extends SmartContract {
    \\  readonly base: bigint;
    \\
    \\  constructor(base: bigint) {
    \\    super(base);
    \\    this.base = base;
    \\  }
    \\
    \\  public check(a: bigint, b: bigint, c: bigint) {
    \\    const p: bigint = a + this.base;
    \\    const q: bigint = b + p;
    \\    const r: bigint = c + q;
    \\    const s: bigint = p + q;
    \\    const t: bigint = q + r;
    \\    const u: bigint = r + s;
    \\    assert(s + t + u + p + q + r > 0n);
    \\  }
    \\}
    \\
;

/// Parse, validate, typecheck and expand with `a`; the returned contract is the
/// exact input `lowerToANF` takes in `runPipeline`.
fn frontend(a: std.mem.Allocator) !types.ContractNode {
    return frontendOf(a, SRC, "AllocProbe.runar.ts");
}

fn frontendOf(a: std.mem.Allocator, source: []const u8, file_name: []const u8) !types.ContractNode {
    const parsed = compiler_api.parseSource(a, source, file_name);
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    const contract = parsed.contract orelse return error.ParseFailed;

    const validated = try compiler_api.validateForFile(a, contract, file_name);
    try std.testing.expectEqual(@as(usize, 0), validated.errors.len);

    const tc = try typecheck.typeCheck(a, contract);
    try std.testing.expectEqual(@as(usize, 0), tc.errors.len);

    const expanded = try expand_fixed_arrays.expand(a, contract);
    try std.testing.expectEqual(@as(usize, 0), expanded.errors.len);
    return expanded.contract;
}

test "R-297: under any single allocation failure ANF lowering reports it or produces the same program" {
    var ref_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer ref_arena.deinit();
    const ref_alloc = ref_arena.allocator();

    const contract = try frontend(ref_alloc);

    const reference = try anf_lower.lowerToANF(ref_alloc, contract);
    const reference_json = try ir_json.serializeCanonicalJSON(ref_alloc, reference);
    // A program with no bindings would make the comparison vacuous.
    try std.testing.expect(reference_json.len > 200);

    // How many allocations does a successful lowering make? Count with a
    // FailingAllocator that never fails, so the count is the sweep's bound.
    const total = blk: {
        var count_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer count_arena.deinit();
        var counting = OneShotFailing{ .backing = count_arena.allocator(), .fail_at = std.math.maxInt(usize) };
        _ = try anf_lower.lowerToANF(counting.allocator(), contract);
        break :blk counting.index;
    };
    try std.testing.expect(total > 0);

    var differed: usize = 0;
    var first_differing: usize = 0;
    var completed: usize = 0;
    var fired: usize = 0;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var failing = OneShotFailing{ .backing = arena.allocator(), .fail_at = i };
        const fa = failing.allocator();

        // A failure during the frontend is not this test's subject: parse with
        // the good allocator and fail only inside lowering.
        const program = anf_lower.lowerToANF(fa, contract) catch {
            if (failing.fired) fired += 1;
            continue;
        };
        if (failing.fired) fired += 1;

        // Serialising with the FAILING allocator would conflate a serialisation
        // OOM with a lowering difference, so serialise with a good one.
        const got_json = ir_json.serializeCanonicalJSON(ref_alloc, program) catch continue;
        completed += 1;
        if (!std.mem.eql(u8, reference_json, got_json)) {
            if (differed == 0) first_differing = i;
            differed += 1;
        }
    }

    // ANTI-VACUITY. `completed` is 0 once every swallowing site propagates, so
    // it cannot be the guard — the first version of this test had completed = 0
    // for the opposite reason (the allocator failed everything after the first
    // failure) and asserted nothing at all. What must hold is that the sweep
    // really perturbed lowering once per allocation: every iteration induced
    // its failure. If a refactor makes lowering allocate less on the path this
    // contract takes, `total` shrinks and this still holds; if the sweep stops
    // reaching lowering, it does not.
    try std.testing.expectEqual(total, fired);

    if (differed != 0) {
        std.log.err(
            "ANF lowering produced a SILENTLY DIFFERENT program for {d} of {d} single-allocation failures ({d} ran to completion); first at allocation #{d}",
            .{ differed, total, completed, first_differing },
        );
    }
    try std.testing.expectEqual(@as(usize, 0), differed);
}

test "R-297: under any single allocation failure stack lowering reports it or produces the same script" {
    // The sibling sweep for `stack_lower.zig`, whose `putLastUseExpanding`
    // swallowed the same way.
    //
    // HONEST SCOPE. This one did NOT go red. Re-breaking `putLastUseExpanding`
    // back to `catch return` and re-running measured 21 allocations, every one
    // induced, 4 runs continuing past the swallowed failure, and 0 producing a
    // different script. A missing `last_uses` entry reads as "no later use", so
    // the value is CONSUMED rather than copied, and a value that is still
    // needed then fails loudly out of stack lowering instead of silently
    // compiling. So the sibling site is a wrong answer to an allocation
    // failure, not a demonstrated miscompile — it is fixed because propagating
    // is right and costs nothing, and this sweep pins the property going
    // forward rather than proving a bug today.
    var ref_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer ref_arena.deinit();
    const ref_alloc = ref_arena.allocator();

    const contract = try frontendOf(ref_alloc, STACK_SRC, "StackProbe.runar.ts");
    const program = try anf_lower.lowerToANF(ref_alloc, contract);

    const reference_stack = try stack_lower.lower(ref_alloc, program);
    const reference_artifact = try emit.emitArtifact(ref_alloc, reference_stack, program);
    try std.testing.expect(reference_artifact.len > 200);

    const total = blk: {
        var count_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer count_arena.deinit();
        var counting = OneShotFailing{ .backing = count_arena.allocator(), .fail_at = std.math.maxInt(usize) };
        _ = try stack_lower.lower(counting.allocator(), program);
        break :blk counting.index;
    };
    try std.testing.expect(total > 0);

    var differed: usize = 0;
    var first_differing: usize = 0;
    var completed: usize = 0;
    var fired: usize = 0;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var failing = OneShotFailing{ .backing = arena.allocator(), .fail_at = i };

        const got_stack = stack_lower.lower(failing.allocator(), program) catch {
            if (failing.fired) fired += 1;
            continue;
        };
        if (failing.fired) fired += 1;

        const got_artifact = emit.emitArtifact(ref_alloc, got_stack, program) catch continue;
        completed += 1;
        if (!std.mem.eql(u8, reference_artifact, got_artifact)) {
            if (differed == 0) first_differing = i;
            differed += 1;
        }
    }

    try std.testing.expectEqual(total, fired);
    if (differed != 0) {
        std.log.err(
            "stack lowering produced a SILENTLY DIFFERENT script for {d} of {d} single-allocation failures ({d} ran to completion); first at allocation #{d}",
            .{ differed, total, completed, first_differing },
        );
    }
    try std.testing.expectEqual(@as(usize, 0), differed);
}
