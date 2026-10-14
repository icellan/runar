//! N-199 (user decision R75, "Refuse, all 7 tiers") — a `@sighash` /
//! `@embedAlways` marker inside the contract class body that is not in the
//! leading comments of the member kind that reads it (`@sighash` -> a method,
//! `@embedAlways` -> a property) is a compile error with one shared message,
//! located at the marker's `@` (1-based line, 0-based byte column).
//!
//! ts-morph never attaches a comment that shares a line with the PRECEDING
//! token (F-282), so `foo(): void {} // @sighash SINGLE|FORKID` above a public
//! method used to compile under the default ALL|FORKID with no diagnostic.
//!
//! Proves: the Zig TS-surface parser refuses each lost-directive shape the TS
//! reference refuses (sighash-parse.test.ts, "N-199"; Go
//! TestN199_LostDirectiveRefused) with the same text and location, and still
//! accepts attached directives and prose outside the class body.
//! Does not prove: cross-tier agreement (conformance/negatives
//! n199-lost-directive-parity.test.ts does) or non-ASCII column units.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const sighash_directive = @import("../frontend/sighash_directive.zig");

const LOST_SIGHASH = "@sighash directive is not attached to any method and would be silently ignored; put the comment on its own line directly above the method it annotates (a comment that shares a line with the preceding code belongs to that code)";
const LOST_EMBED = "@embedAlways directive is not attached to any property and would be silently ignored; put the comment on its own line directly above the property it annotates (a comment that shares a line with the preceding code belongs to that code)";

fn stateful(comptime body: []const u8) []const u8 {
    return "import { StatefulSmartContract } from 'runar-lang';\n" ++
        "export class C extends StatefulSmartContract {\n" ++
        "  n: bigint;\n" ++
        "  constructor(n: bigint) { super(n); this.n = n; }\n" ++
        body ++ "\n}\n";
}

const BUMP = "  public bump(): void { this.addOutput(1000n, this.n); }";

fn expectLost(source: []const u8, marker: []const u8, want: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const idx = std.mem.indexOf(u8, source, marker).?;
    const line = std.mem.count(u8, source[0..idx], "\n") + 1;
    const line_start = if (std.mem.lastIndexOfScalar(u8, source[0..idx], '\n')) |nl| nl + 1 else 0;
    const expected = try std.fmt.allocPrint(a, "X.runar.ts:{d}:{d}: {s}", .{ line, idx - line_start, want });
    const parsed = parse_ts.parseTs(a, source, "X.runar.ts");
    if (parsed.errors.len != 1 or !std.mem.eql(u8, parsed.errors[0], expected)) {
        std.debug.print("want exactly: {s}\ngot {d} error(s):\n", .{ expected, parsed.errors.len });
        for (parsed.errors) |e| std.debug.print("  {s}\n", .{e});
        return error.TestExpectedLostDirective;
    }
}

test "N-199 shared lost-directive messages match the reference text" {
    try std.testing.expectEqualStrings(LOST_SIGHASH, sighash_directive.LOST_SIGHASH_ERROR);
    try std.testing.expectEqualStrings(LOST_EMBED, sighash_directive.LOST_EMBED_ALWAYS_ERROR);
}

test "N-199 lost @sighash directives are refused" {
    try expectLost(stateful("  private foo(): void {} // @sighash SINGLE|FORKID\n" ++ BUMP), "@sighash", LOST_SIGHASH);
    try expectLost(stateful("  private foo(): void {} /** @sighash SINGLE|FORKID */\n" ++ BUMP), "@sighash", LOST_SIGHASH);
    try expectLost(stateful(BUMP ++ "\n  /** @sighash SINGLE|FORKID */"), "@sighash", LOST_SIGHASH);
    try expectLost(stateful("  public bump(): void {\n    // @sighash SINGLE|FORKID\n    this.addOutput(1000n, this.n);\n  }"), "@sighash", LOST_SIGHASH);
    try expectLost(stateful("  /** @sighash SINGLE|FORKID */\n  readonly k: bigint = 1n;\n" ++ BUMP), "@sighash", LOST_SIGHASH);
    try expectLost("import { StatefulSmartContract } from 'runar-lang';\n" ++
        "export class C extends StatefulSmartContract {\n" ++
        "  n: bigint;\n" ++
        "  /** @sighash SINGLE|FORKID */\n" ++
        "  constructor(n: bigint) { super(n); this.n = n; }\n" ++
        BUMP ++ "\n}\n", "@sighash", LOST_SIGHASH);
}

test "N-199 lost @embedAlways directives are refused" {
    try expectLost("import { SmartContract, assert } from 'runar-lang';\n" ++
        "export class C extends SmartContract {\n" ++
        "  readonly a: bigint; // @embedAlways\n" ++
        "  readonly tag: bigint;\n" ++
        "  constructor(a: bigint, tag: bigint) { super(a, tag); this.a = a; this.tag = tag; }\n" ++
        "  public go(x: bigint): void { assert(x == this.a); }\n" ++
        "}\n", "@embedAlways", LOST_EMBED);
    try expectLost("import { SmartContract, assert } from 'runar-lang';\n" ++
        "export class C extends SmartContract {\n" ++
        "  readonly a: bigint;\n" ++
        "  constructor(a: bigint) { super(a); this.a = a; }\n" ++
        "  /** @embedAlways */\n" ++
        "  public go(x: bigint): void { assert(x == this.a); }\n" ++
        "}\n", "@embedAlways", LOST_EMBED);
}

test "N-199 every lost directive is reported, in source order" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source = stateful("  private foo(): void {} // @sighash SINGLE|FORKID\n" ++ BUMP ++ " // @embedAlways");
    const parsed = parse_ts.parseTs(arena.allocator(), source, "X.runar.ts");
    try std.testing.expectEqual(@as(usize, 2), parsed.errors.len);
    try std.testing.expectEqualStrings("X.runar.ts:5:28: " ++ LOST_SIGHASH, parsed.errors[0]);
    try std.testing.expectEqualStrings("X.runar.ts:6:60: " ++ LOST_EMBED, parsed.errors[1]);
}

test "N-199 attached directives and prose outside the class body still compile" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source = "import { StatefulSmartContract } from 'runar-lang';\n" ++
        "// File header prose: this contract uses @sighash SINGLE|FORKID and @embedAlways.\n" ++
        "/** Class doc: `@sighash` lives on bump, `@embedAlways` on tag. */\n" ++
        "export class C extends StatefulSmartContract {\n" ++
        "  n: bigint;\n" ++
        "  /** @embedAlways */\n" ++
        "  readonly tag: bigint;\n" ++
        "  constructor(n: bigint, tag: bigint) { super(n, tag); this.n = n; this.tag = tag; }\n" ++
        "  private foo(): void {}\n" ++
        "  // @sighash SINGLE|FORKID\n" ++
        BUMP ++ "\n}\n";
    const parsed = parse_ts.parseTs(arena.allocator(), source, "X.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    try std.testing.expect(parsed.contract.?.properties[1].embed_always);
    for (parsed.contract.?.methods) |m| {
        if (std.mem.eql(u8, m.name, "bump")) {
            try std.testing.expectEqual(@as(?i32, 0x43), m.sighash_type);
            return;
        }
    }
    return error.MethodNotFound;
}
