//! F-064 — the .runar.ts surface refuses every statement kind outside
//! spec/grammar.md §9 with the TS reference's diagnostic,
//! "Unsupported statement kind: <ts.SyntaxKind name>", and never drops one.
//!
//! Pre-fix this parser swallowed stray `;` (skipSemicolons), fell through to
//! the expression parser for every keyword it did not dispatch on (`throw x;`
//! became an identifier a later pass happened to reject) and parsed
//! `for (const k of xs)` as a C-style loop that only the validator's bound
//! check stopped.
//!
//! Proves: the Zig .runar.ts parser refuses each kind (top level, nested in
//! if, in a for body) with the shared diagnostic. Does not prove: the other
//! Zig-tier surfaces (.runar.zig/.sol/.move/...).

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");

const Case = struct { stmt: []const u8, kind: []const u8 };

const cases = [_]Case{
    .{ .stmt = "while (x > 0n) { assert(false); }", .kind = "WhileStatement" },
    .{ .stmt = "do { assert(false); } while (x > 0n);", .kind = "DoStatement" },
    .{ .stmt = "switch (x) { case 1n: assert(false); break; default: assert(false); }", .kind = "SwitchStatement" },
    .{ .stmt = "outer: for (let i = 0n; i < 2n; i++) { assert(false); }", .kind = "LabeledStatement" },
    .{ .stmt = "try { assert(false); } catch (e) { assert(false); }", .kind = "TryStatement" },
    .{ .stmt = "throw x;", .kind = "ThrowStatement" },
    .{ .stmt = "for (const k in this) { assert(false); }", .kind = "ForInStatement" },
    .{ .stmt = "for (const k of [x]) { assert(false); }", .kind = "ForOfStatement" },
    .{ .stmt = "{ assert(false); }", .kind = "Block" },
    .{ .stmt = ";", .kind = "EmptyStatement" },
    .{ .stmt = "assert(x > 1n);;", .kind = "EmptyStatement" },
    .{ .stmt = "const y = x;;", .kind = "EmptyStatement" },
    .{ .stmt = "class Inner { }", .kind = "ClassDeclaration" },
    .{ .stmt = "function inner(): void { assert(false); }", .kind = "FunctionDeclaration" },
    .{ .stmt = "debugger;", .kind = "DebuggerStatement" },
    .{ .stmt = "with (x) { assert(false); }", .kind = "WithStatement" },
    .{ .stmt = "break;", .kind = "BreakStatement" },
    .{ .stmt = "continue;", .kind = "ContinueStatement" },
};

const contexts = [_][]const u8{ "{s}", "if (x > 0n) {{ {s} }}", "for (let j = 0n; j < 2n; j++) {{ {s} }}" };

fn wrap(alloc: std.mem.Allocator, body: []const u8) ![]const u8 {
    return std.fmt.allocPrint(alloc,
        \\import {{ SmartContract, assert }} from 'runar-lang';
        \\
        \\class Probe extends SmartContract {{
        \\  readonly a: bigint;
        \\
        \\  constructor(a: bigint) {{
        \\    super(a);
        \\    this.a = a;
        \\  }}
        \\
        \\  public unlock(x: bigint) {{
        \\    {s}
        \\    assert(x > this.a);
        \\  }}
        \\}}
        \\
    , .{body});
}

test "F-064: every unsupported statement kind is refused with the shared diagnostic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var failures: usize = 0;
    for (cases) |c| {
        inline for (contexts) |ctx| {
            const body = try std.fmt.allocPrint(alloc, ctx, .{c.stmt});
            const r = parse_ts.parseTs(alloc, try wrap(alloc, body), "Probe.runar.ts");
            const want = try std.fmt.allocPrint(alloc, "Unsupported statement kind: {s}", .{c.kind});
            var found = false;
            for (r.errors) |e| {
                if (std.mem.endsWith(u8, e, want)) found = true;
            }
            if (!found) {
                failures += 1;
                std.debug.print("F-064: `{s}` not refused with \"{s}\"\n", .{ body, want });
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
}

test "F-064: a well-formed body still parses clean" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const r = parse_ts.parseTs(alloc, try wrap(alloc, "const y = x + 1n;\n    assert(y > 0n);"), "Probe.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
}
