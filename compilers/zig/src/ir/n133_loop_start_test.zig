//! N-133 — an unreadable `loop.start` must produce an ERROR, never 0.
//!
//! `Loop.start` is `integer | string` and the string arm is the sanctioned
//! `"<decimal>n"` form (issue #121). This tier read it as:
//!
//!     .string => |s| blk: {
//!         const text = if (s[s.len - 1] == 'n') s[0 .. s.len - 1] else s;
//!         break :blk std.fmt.parseInt(i64, text, 10) catch 0;   // <- here
//!     },
//!     else => 0,                                                // <- and here
//!
//! Both fallbacks answer 0, and 0 is the worst possible answer: it is a
//! perfectly plausible loop start — the commonest one, and the one
//! `bounded-loop`'s own golden carries — so the wrong program compiles, emits
//! a well-formed locking script, and nothing anywhere looks wrong.
//!
//! Measured on that golden with only `start` edited, fold-off:
//!
//!     "999999999999999999999999999999n"
//!                  go/rust/python/ruby/java the value · ZIG the start-0 script
//!     "abc" / "" / "5nn" / true
//!                  go/python/java refuse    · rust/ZIG/ruby the start-0 script
//!
//! The `catch 0` case is not hypothetical. A source contract whose loop starts
//! past int64 compiles, and ts / go / rust write that start as
//! `"999999999999999999999999999999n"` in their `--emit-ir` output — which is
//! exactly the string this tier turned into 0.
//!
//! THE OVER-INT64 CASE IS A REAL SPLIT, and refusing is this tier's half of
//! it rather than a fix for it. `types.ANFLoop.start` is an `i64`, so 10^30 is
//! a value this tier genuinely cannot carry, while its five peers hold `start`
//! as an arbitrary-precision integer and emit the right script. Widening it is
//! separate work — `start` is an `i64` through the whole codegen path, not
//! just at the loader. What this change settles is only that an unrepresentable
//! start is REFUSED instead of silently replaced, which was a defect under
//! either reading.
//!
//! Every assertion here is one the pre-fix loader could not have passed by
//! accident: `expectError` cannot be satisfied by a loader that returns a
//! program, and `catch 0` always returned one.

const std = @import("std");
const testing = std.testing;
const json = @import("json.zig");

/// Smallest IR carrying one `loop` whose `start` is the spliced-in text.
fn irWithStart(allocator: std.mem.Allocator, start: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        \\{{"contractName":"Probe","properties":[],"methods":[{{"name":"unlock","params":[],"isPublic":true,"body":[{{"name":"t0","value":{{"kind":"loop","count":2,"start":{s},"step":1,"iterVar":"i","body":[{{"name":"t1","value":{{"kind":"load_const","value":0}}}}]}}}}]}}]}}
    , .{start});
}

fn expectStartRefused(a: std.mem.Allocator, start: []const u8) !void {
    const src = try irWithStart(a, start);
    try testing.expectError(error.InvalidLoopStart, json.parseANFProgram(a, src));
}

fn expectStartLoads(a: std.mem.Allocator, start: []const u8, want: i64) !void {
    const src = try irWithStart(a, start);
    const program = try json.parseANFProgram(a, src);
    const value = program.methods[0].body[0].value;
    try testing.expectEqual(want, value.loop.start);
}

test "N-133: a loop start string without the `n` suffix is refused" {
    // The row that shows how bad the substitution is: go, python, zig and ruby
    // all read "5" as 5 while rust read the SAME input as 0, and both sides
    // exited 0 with a well-formed script. There is no majority answer to
    // adopt, so the sanctioned form is the rule and "5" is not it.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try expectStartRefused(arena.allocator(), "\"5\"");
}

test "N-133: a non-numeric loop start string is refused, not read as 0" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try expectStartRefused(a, "\"abc\"");
    try expectStartRefused(a, "\"\"");
    try expectStartRefused(a, "\"n\"");
    try expectStartRefused(a, "\"-n\"");
}

test "N-133: exactly one trailing `n` is stripped, so \"5nn\" stays refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try expectStartRefused(arena.allocator(), "\"5nn\"");
}

test "N-133: a float-shaped string cannot reopen the float boundary" {
    // N-131 closed the numeric float arm. `"1.5n"` is the way back in through
    // the string arm, and `parseInt` refusing it used to mean 0, not an error.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try expectStartRefused(arena.allocator(), "\"1.5n\"");
}

test "N-133: a non-integer, non-string loop start is refused" {
    // The `else => 0` arm: a boolean, a null, an object, an array.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try expectStartRefused(a, "true");
    try expectStartRefused(a, "null");
    try expectStartRefused(a, "{}");
    try expectStartRefused(a, "[]");
}

test "N-133: a start wider than i64 is refused rather than replaced by 0" {
    // The documented split. This tier cannot represent it; five peers can and
    // do. Refusing is the half that stops a DIFFERENT loop being compiled.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try expectStartRefused(a, "\"999999999999999999999999999999n\"");
    // A bare JSON number past i64 lands in std.json's `number_string` arm,
    // which the same `else => 0` used to swallow. python, ruby and java all
    // WRITE the over-int64 start in exactly this shape.
    try expectStartRefused(a, "999999999999999999999999999999");
    // The boundary itself: i64 max loads, i64 max + 1 does not.
    try expectStartLoads(a, "9223372036854775807", 9223372036854775807);
    try expectStartRefused(a, "9223372036854775808");
    try expectStartLoads(a, "-9223372036854775808", -9223372036854775808);
    try expectStartRefused(a, "-9223372036854775809");
}

test "N-133 control: the sanctioned forms still load, as the numbers they spell" {
    // The teeth against an over-broad guard: a loader that refuses the bad
    // starts by refusing strings, or by refusing loops, reddens here.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try expectStartLoads(a, "\"5n\"", 5);
    try expectStartLoads(a, "\"-3n\"", -3);
    try expectStartLoads(a, "\"0n\"", 0);
    try expectStartLoads(a, "5", 5);
    try expectStartLoads(a, "-3", -3);
    try expectStartLoads(a, "0", 0);
}

test "N-133 control: a loop with no start at all is still a zero-start loop" {
    // Older payloads omit `start` entirely. Absent is not the same as
    // unreadable, and must keep defaulting to 0 rather than becoming an error.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src =
        \\{"contractName":"Probe","properties":[],"methods":[{"name":"unlock","params":[],"isPublic":true,"body":[{"name":"t0","value":{"kind":"loop","count":2,"iterVar":"i","body":[{"name":"t1","value":{"kind":"load_const","value":0}}]}}]}]}
    ;
    const program = try json.parseANFProgram(a, src);
    try testing.expectEqual(@as(i64, 0), program.methods[0].body[0].value.loop.start);
}
