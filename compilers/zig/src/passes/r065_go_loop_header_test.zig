//! R-065 — a Go-format `for` header the unrolled loop model cannot represent
//! must be REFUSED, not guessed at.
//!
//! Two holes, two passes, one rule.
//!
//! 1. `parse_go.zig` tried the three-part header, failed on the missing `;`,
//!    restored the tokenizer and then threw the entire header away:
//!
//!        while (self.current.kind != .lbrace and ... ) { _ = self.bump(); }
//!
//!    `bound` therefore kept its `0` default and `update` ended up null only
//!    as a side effect. `anf_lower.lowerForStatement` then computed
//!    `base = bound - start = 0` and unrolled ZERO times. Measured on
//!    `for i < 5 { sum = sum + start + i; i++ }`: 16 hexchars,
//!    `0000007b7c9c7777` — the loop body is gone, `sum` never accumulates, and
//!    the spending guard degrades to `0 == expectedSum`. Anyone-can-spend if
//!    that constant is 0, permanently unspendable if it is not.
//!
//!    The R-065 rule in `validate.zig` never fired, because there was no
//!    update in the AST for it to inspect. A parser that silently discards
//!    tokens it could not parse defeats every downstream rule by construction.
//!
//! 2. The R-065 rule itself sat inside `if (f.update) |u|`. `null` is
//!    legitimate for `for i in 0..N` (Rust) and `range(N)` (Python), where the
//!    step is implied by the surface syntax — but a C-style three-part header
//!    with an EMPTY post clause (`for i := runar.Int(0); i < 5; {`, legal Go)
//!    is not the same thing, and the AST could not tell them apart. Measured:
//!    Zig unrolled it five times, 114 hexchars, while all six peers refused.
//!
//! The fix gives the AST a `header_requires_update` flag that only the C-style
//! parsers set, so the rule can distinguish "no update clause exists in this
//! surface syntax" from "this header has an update slot and it is empty".
//!
//! The assertions below are on the REFUSAL, deliberately. Asserting that the
//! seven tiers' exit codes merely agree would have been satisfied by the
//! pre-fix state of the world in spirit — Rust and Zig both "succeeded" and
//! produced different wrong scripts.

const std = @import("std");
const testing = std.testing;
const parse_go = @import("parse_go.zig");
const validate = @import("validate.zig");

const loop_update_substr = "For loop update must advance the loop variable by one";

/// The control's whole job is to prove the probes are not passing because the
/// Go parser stopped accepting loops altogether.
const three_part_ok =
    \\package contract
    \\
    \\import "runar"
    \\
    \\type T struct {
    \\    runar.SmartContract
    \\    ExpectedSum runar.Int `runar:"readonly"`
    \\}
    \\
    \\func (c *T) Verify(start runar.Int) {
    \\    sum := runar.Int(0)
    \\    for i := runar.Int(0); i < 5; i++ {
    \\        sum = sum + start + i
    \\    }
    \\    runar.Assert(sum == c.ExpectedSum)
    \\}
    \\
;

const condition_only =
    \\package contract
    \\
    \\import "runar"
    \\
    \\type T struct {
    \\    runar.SmartContract
    \\    ExpectedSum runar.Int `runar:"readonly"`
    \\}
    \\
    \\func (c *T) Verify(start runar.Int) {
    \\    sum := runar.Int(0)
    \\    i := runar.Int(0)
    \\    for i < 5 {
    \\        sum = sum + start + i
    \\        i++
    \\    }
    \\    runar.Assert(sum == c.ExpectedSum)
    \\}
    \\
;

const empty_post =
    \\package contract
    \\
    \\import "runar"
    \\
    \\type T struct {
    \\    runar.SmartContract
    \\    ExpectedSum runar.Int `runar:"readonly"`
    \\}
    \\
    \\func (c *T) Verify(start runar.Int) {
    \\    sum := runar.Int(0)
    \\    for i := runar.Int(0); i < 5; {
    \\        sum = sum + start + i
    \\        i++
    \\    }
    \\    runar.Assert(sum == c.ExpectedSum)
    \\}
    \\
;

test "control: an ordinary three-part Go for header still parses and validates" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const parsed = parse_go.parseGo(allocator, three_part_ok, "T.runar.go");
    try testing.expectEqual(@as(usize, 0), parsed.errors.len);
    const contract = parsed.contract orelse return error.NoContract;

    const result = try validate.validate(allocator, contract);
    try testing.expectEqual(@as(usize, 0), result.errors.len);
}

test "a condition-only Go for header is a PARSE ERROR, not a silently emptied loop" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const parsed = parse_go.parseGo(allocator, condition_only, "T.runar.go");
    try testing.expect(parsed.errors.len > 0);
}

test "the condition-only header never reaches lowering with a zero bound" {
    // The sharper form of the assertion above: pre-fix the parser returned NO
    // errors and a contract whose loop had bound=0. A test that only checked
    // `errors.len > 0` could be satisfied by a future refactor that reports an
    // error AND still hands a bogus loop downstream; this one cannot.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const parsed = parse_go.parseGo(allocator, condition_only, "T.runar.go");
    if (parsed.errors.len == 0) return error.ParserAcceptedConditionOnlyHeader;

    // A loud parse failure may still return a partial AST. What must NOT
    // happen is a loop node claiming a derived bound the source never gave.
    if (parsed.contract) |contract| {
        for (contract.methods) |method| {
            for (method.body) |stmt| {
                switch (stmt) {
                    .for_stmt => |f| {
                        // bound=0 with start=0 is the zero-iteration shape that
                        // produced `0000007b7c9c7777`.
                        try testing.expect(!(f.bound == 0 and f.init_value == 0));
                    },
                    else => {},
                }
            }
        }
    }
}

test "a three-part Go for header with an empty post clause is rejected by R-065" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const parsed = parse_go.parseGo(allocator, empty_post, "T.runar.go");
    const contract = parsed.contract orelse {
        // A parse-level refusal is an acceptable answer to the same question.
        try testing.expect(parsed.errors.len > 0);
        return;
    };
    if (parsed.errors.len > 0) return;

    const result = try validate.validate(allocator, contract);
    for (result.errors) |e| {
        if (std.mem.indexOf(u8, e.message, loop_update_substr) != null) return;
    }
    std.debug.print("expected R-065 diagnostic, got {d} errors: ", .{result.errors.len});
    for (result.errors) |e| std.debug.print("[{s}] ", .{e.message});
    std.debug.print("\n", .{});
    return error.EmptyPostClauseAccepted;
}

test "R-065 still tolerates a surface with no update clause at all (for i in 0..N)" {
    // The reason the rule was written inside `if (f.update) |u|` in the first
    // place. A range-style loop carries its step in the syntax, so a null
    // update there is correct and must stay accepted — otherwise the fix for
    // the empty-post hole would break every Rust- and Python-format loop.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const parse_rust = @import("parse_rust.zig");
    const src =
        \\use runar::prelude::*;
        \\
        \\#[runar::contract]
        \\struct T {
        \\    #[readonly]
        \\    expected_sum: Int,
        \\}
        \\
        \\impl T {
        \\    pub fn verify(&self, start: Int) {
        \\        let mut sum: Int = 0;
        \\        for i in 0..5 {
        \\            sum = sum + start + i;
        \\        }
        \\        assert!(sum == self.expected_sum);
        \\    }
        \\}
        \\
    ;
    const parsed = parse_rust.parseRust(allocator, src, "T.runar.rs");
    try testing.expectEqual(@as(usize, 0), parsed.errors.len);
    const contract = parsed.contract orelse return error.NoContract;
    const result = try validate.validate(allocator, contract);
    for (result.errors) |e| {
        if (std.mem.indexOf(u8, e.message, loop_update_substr) != null) {
            return error.RangeLoopWronglyRejected;
        }
    }
}
