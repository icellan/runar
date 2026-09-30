//! N-065 / N-060 — a user identifier spelled like a name the compiler mints is
//! refused, with the diagnostic shared verbatim by all seven tiers (the corpus
//! is conformance/negatives/reserved-names-cases.json; the reference is
//! packages/runar-compiler/src/passes/reserved-names.ts).
//!
//! Before: `let t2: bigint = p; assert(p > 0n); if (c) { t2 = p; }
//! assert(t2 + 1n === 1n);` compiled to a script that accepts p = 1, c = false
//! (the final guard read the ANF temp `t2`, not the local), and `--ir` accepted
//! parameters, properties, bindings and references named after stack
//! lowering's own slots (`_codePart`, `__param_*`, `__shadowed_*`, `_pub_<n>`).
//!
//! Proves: every source case is refused by this tier's validator with the
//! exact shared message while its renamed twin compiles; the accepted source
//! (a stateless contract's own `txPreimage` parameter) compiles; every `--ir`
//! case is refused by `parseANFProgram` with the shared message; the accepted
//! IR (ANF temps and `__merge$0` as binding names, `txPreimage` as a
//! parameter) compiles to `00ac`. Does not prove: cross-tier CLI parity
//! (conformance/negatives/reserved-names.test.ts does) or on-chain effect.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const json = @import("../ir/json.zig");
const required_fields = @import("../ir/required_fields.zig");
const ec_optimizer = @import("../passes/ec_optimizer.zig");
const stack_lower = @import("../passes/stack_lower.zig");
const peephole = @import("../passes/peephole.zig");
const emit = @import("../codegen/emit.zig");
const types = @import("../ir/types.zig");

const corpus_path = "../../conformance/negatives/reserved-names-cases.json";

fn readCorpus(a: std.mem.Allocator) !std.json.Value {
    const raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, corpus_path, a, .limited(4 * 1024 * 1024));
    return (try std.json.parseFromSliceLeaky(std.json.Value, a, raw, .{}));
}

fn str(v: std.json.Value, key: []const u8) []const u8 {
    return v.object.get(key).?.string;
}

/// The `--ir` pipeline of main.zig's `compileFromIR`, returning the script hex.
fn compileIr(a: std.mem.Allocator, src: []const u8) ![]const u8 {
    const program = try json.parseANFProgram(a, src);
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

test "N-065: every source case is refused with the shared diagnostic; its twin compiles" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const corpus = try readCorpus(a);
    const src_obj = corpus.object.get("source").?;
    const cases = src_obj.object.get("cases").?.array.items;
    try std.testing.expect(cases.len >= 30);

    var failures: usize = 0;
    for (cases) |c| {
        const file = str(c, "file");
        const want = str(c, "error");
        const parsed = compiler_api.parseSource(a, str(c, "src"), file);
        if (parsed.errors.len > 0 or parsed.contract == null) {
            std.debug.print("{s}: parse failed: {s}\n", .{ str(c, "name"), if (parsed.errors.len > 0) parsed.errors[0] else "<no contract>" });
            failures += 1;
            continue;
        }
        const vr = try compiler_api.validateForFile(a, parsed.contract.?, file);
        var found = false;
        for (vr.errors) |d| {
            if (std.mem.eql(u8, d.message, want)) found = true;
        }
        if (!found) {
            std.debug.print("{s}: not refused with \"{s}\" ({d} validation errors)\n", .{ str(c, "name"), want, vr.errors.len });
            failures += 1;
        }

        const twin = compiler_api.compileSourceWithOptions(std.testing.allocator, str(c, "twin"), file, true) catch |err| {
            std.debug.print("{s}: twin failed to compile: {s}\n", .{ str(c, "name"), @errorName(err) });
            failures += 1;
            continue;
        };
        twin.deinit(std.testing.allocator);
    }
    for (src_obj.object.get("accept").?.array.items) |c| {
        const r = compiler_api.compileSourceWithOptions(std.testing.allocator, str(c, "src"), str(c, "file"), false) catch |err| {
            std.debug.print("{s}: accepted program refused: {s}\n", .{ str(c, "name"), @errorName(err) });
            failures += 1;
            continue;
        };
        r.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
}

test "N-060 / N-065: every --ir case is refused with the shared diagnostic; accepted IR compiles" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const corpus = try readCorpus(a);
    const ir_obj = corpus.object.get("ir").?;
    const cases = ir_obj.object.get("cases").?.array.items;
    try std.testing.expect(cases.len >= 10);

    var failures: usize = 0;
    for (cases) |c| {
        const src = try std.json.Stringify.valueAlloc(a, c.object.get("ir").?, .{});
        const want = str(c, "error");
        if (json.parseANFProgram(a, src)) |_| {
            std.debug.print("{s}: --ir accepted; want \"{s}\"\n", .{ str(c, "name"), want });
            failures += 1;
        } else |err| {
            const got = required_fields.lastDiagnostic() orelse "<none>";
            if (!std.mem.eql(u8, @errorName(err), "ReservedName") or std.mem.indexOf(u8, got, want) == null) {
                std.debug.print("{s}: got {s} \"{s}\"; want \"{s}\"\n", .{ str(c, "name"), @errorName(err), got, want });
                failures += 1;
            }
        }
    }
    for (ir_obj.object.get("accept").?.array.items) |c| {
        const src = try std.json.Stringify.valueAlloc(a, c.object.get("ir").?, .{});
        const hex = compileIr(a, src) catch |err| {
            std.debug.print("{s}: accepted IR refused: {s}\n", .{ str(c, "name"), @errorName(err) });
            failures += 1;
            continue;
        };
        if (!std.mem.eql(u8, hex, "00ac")) {
            std.debug.print("{s}: want 00ac, got {s}\n", .{ str(c, "name"), hex });
            failures += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
}
