//! N-008 — a `.runar.zig` while-loop whose `var i` declaration is not the
//! statement immediately before the loop must be REFUSED, as every other tier
//! refuses it, not compiled from a start of 0.
//!
//! The reference `.runar.zig` parser (01-parse-zig.ts) lowers every
//! `while (cond) : (upd) { ... }` to a for-statement whose init is the
//! placeholder `__while_no_init`, and folds the preceding statement in as the
//! init only when it declares the variable the UPDATE advances. An unfolded
//! loop keeps the placeholder, whose name the condition never tests, so the
//! condition-iterator rule refuses it. This tier instead folded on the name the
//! CONDITION tests and, when nothing folded, kept that name with a start of 0:
//!
//!     var i: i64 = 3;
//!     var sum: i64 = 0;
//!     while (i < 5) : (i += 1) { sum = sum + i; }
//!
//! compiled to a script accepting sum = 10 (0+1+2+3+4) and rejecting the
//! correct 7 under @bsv/sdk Spend.validate(), while TS/Go/Rust/Python/Ruby/Java
//! refused the program. A while with no continue expression (`while (i < 5) {
//! ...; i += 1; }`) folded here too and compiled, where the reference refuses
//! it the same way.
//!
//! What this proves: on the `.runar.zig` surface this tier refuses both shapes
//! with the reference's sentence, word for word and as the ONLY diagnostic
//! (the reference reports exactly one), and the adjacent-declaration control
//! still compiles to the reference bytes with its start of 3 honoured.
//! What it does NOT prove: anything about the other six tiers (gated across
//! all seven by conformance/negatives/N162-zig-while-non-adjacent-init.runar.zig),
//! or anything on chain.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const COND_ITER =
    "For loop condition must compare the loop variable '__while_no_init' to a " ++
    "compile-time constant (`__while_no_init < 10n`). The unrolled loop binds the " ++
    "iterator as `start + k*step` and takes its trip count from the bound alone, so a " ++
    "condition whose left-hand side is anything else -- a computed expression, or a " ++
    "different variable -- is not the condition the loop actually evaluates";

fn contract(comptime body: []const u8) []const u8 {
    return "const runar = @import(\"runar\");\n\n" ++
        "pub const Probe = struct {\n" ++
        "    pub const Contract = runar.SmartContract;\n\n" ++
        "    target: i64,\n\n" ++
        "    pub fn init(target: i64) Probe {\n" ++
        "        return .{ .target = target };\n" ++
        "    }\n\n" ++
        "    pub fn check(self: *const Probe, expected: i64) void {\n" ++
        body ++
        "        runar.assert(sum == expected);\n" ++
        "        runar.assert(self.target == self.target);\n" ++
        "    }\n" ++
        "};\n";
}

const NON_ADJACENT = contract(
    \\        var i: i64 = 3;
    \\        var sum: i64 = 0;
    \\        while (i < 5) : (i += 1) {
    \\            sum = sum + i;
    \\        }
    \\
);

const NO_CONTINUE = contract(
    \\        var sum: i64 = 0;
    \\        var i: i64 = 3;
    \\        while (i < 5) {
    \\            sum = sum + i;
    \\            i += 1;
    \\        }
    \\
);

const ADJACENT = contract(
    \\        var sum: i64 = 0;
    \\        var i: i64 = 3;
    \\        while (i < 5) : (i += 1) {
    \\            sum = sum + i;
    \\        }
    \\
);

fn expectOnlyCondIterRefusal(src: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var diag: compiler_api.Diagnostics = .{};
    if (compiler_api.runPipeline(a, src, "Probe.runar.zig", .{ .disable_constant_folding = true }, &diag)) |_| {
        std.debug.print("non-adjacent while compiled (start ignored)\n", .{});
        return error.NonAdjacentWhileCompiled;
    } else |_| {}
    if (diag.errors.items.len == 1 and std.mem.endsWith(u8, diag.errors.items[0], COND_ITER)) return;
    std.debug.print("expected exactly the reference diagnostic, got {d}:\n", .{diag.errors.items.len});
    for (diag.errors.items) |line| std.debug.print("    {s}\n", .{line});
    return error.WrongDiagnostic;
}

test "N-008: a while whose declaration is not adjacent is refused with the reference diagnostic" {
    try expectOnlyCondIterRefusal(NON_ADJACENT);
}

test "N-008: a while with no continue expression is refused with the reference diagnostic" {
    try expectOnlyCondIterRefusal(NO_CONTINUE);
}

test "N-008 control: the adjacent declaration still folds and its start of 3 is honoured" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Reference (TS/Go, fold-off and fold-on): OP_7 OP_SWAP OP_NUMEQUALVERIFY
    // OP_0 OP_0 OP_NUMEQUAL — the sum is 3 + 4 = 7, not 0+1+2+3+4 = 10.
    const result = try compiler_api.compileSourceWithOptions(a, ADJACENT, "Probe.runar.zig", true);
    try std.testing.expectEqualStrings("577c9d00009c", result.script_hex);
}
