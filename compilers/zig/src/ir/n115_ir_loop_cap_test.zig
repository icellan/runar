//! N-115 — the unroll ceiling on the `--ir` path, and the panic it hid.
//!
//! `types.MAX_LOOP_COUNT` (10000) has existed in this tier since CL-BUG-088,
//! but the only thing that read it was `passes/anf_lower.zig` — the SOURCE
//! path. A loop arriving as IR was bounded by nothing.
//!
//! Two consequences, both measured against the checked-in `bounded-loop`
//! golden (`conformance/tests/bounded-loop/expected-ir.json`):
//!
//!   count=10001   accepted; emitted a 199734-hexchar (~97 KB) locking script.
//!                 Rust and Java accepted the identical input and emitted the
//!                 identical bytes (sha256 e2c1be39...), so the cross-tier hex
//!                 parity run saw three tiers agreeing and reported no
//!                 divergence. Only Go, Python and Ruby refused.
//!
//!   count=2^33    `thread N panic: integer does not fit in destination type`
//!                 — the `@intCast` to the `u32` count, exactly as the doc
//!                 comment on `types.MAX_LOOP_COUNT` predicted. A panic is not
//!                 a rejection: the process dies on a signal and renders no
//!                 verdict at all.
//!
//! One guard on the raw `i64`, ahead of the narrowing cast, closes both — and
//! makes the cast total, since everything reaching it is now in [0, 10000].
//!
//! Zig's IR loader is an error-enum channel with no message payload, so the
//! error NAME is the whole diagnostic: `LoopCountExceedsMaximum`, not another
//! `UnexpectedValueType` (the value's TYPE is fine; its MAGNITUDE is not).

const std = @import("std");
const testing = std.testing;
const json = @import("json.zig");
const types = @import("types.zig");

/// A one-method contract parameterised on the loop count alone, so every case
/// below differs from the control in exactly one field — the same discipline
/// `conformance/negatives/ir/I07-loop-count-over-max.ir.json` follows against
/// the `bounded-loop` golden.
fn irJson(allocator: std.mem.Allocator, count: i64) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        \\{{"contractName":"Bounded","properties":[],"methods":[{{"name":"unlock","params":[],"isPublic":true,"body":[{{"name":"t0","value":{{"kind":"loop","count":{d},"iterVar":"i","body":[{{"name":"t1","value":{{"kind":"load_const","value":0}}}}]}}}}]}}]}}
    , .{count});
}

// The control. A probe whose control also fails proves nothing: a count
// exactly AT the limit is legal and must still load, or "rejects 10001" would
// only be evidence that the loader had stopped reading loops at all.
test "control: a loop count at MAX_LOOP_COUNT still loads" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const src = try irJson(allocator, types.MAX_LOOP_COUNT);
    const program = try json.parseANFProgram(allocator, src);
    try testing.expectEqualStrings("Bounded", program.contract_name);
}

test "rejects a loop count above MAX_LOOP_COUNT" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const src = try irJson(allocator, types.MAX_LOOP_COUNT + 1);
    try testing.expectError(
        error.LoopCountExceedsMaximum,
        json.parseANFProgram(allocator, src),
    );
}

// The panic half. 2^33 is outside u32 entirely, so before the guard this did
// not return an error at all — it aborted the process. `expectError` is a
// meaningful assertion here precisely because the pre-fix behaviour could not
// have satisfied it: a panicking loader never returns to the test.
test "a loop count outside u32 is an error, not a panic" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const src = try irJson(allocator, 8589934592); // 2^33
    try testing.expectError(
        error.LoopCountExceedsMaximum,
        json.parseANFProgram(allocator, src),
    );
}

// A negative count is likewise rejected rather than wrapping into a huge
// unsigned unroll. Go's loader has a companion "negative loop count"
// diagnostic; here the single magnitude guard covers both ends.
test "rejects a negative loop count" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const src = try irJson(allocator, -1);
    try testing.expectError(
        error.LoopCountExceedsMaximum,
        json.parseANFProgram(allocator, src),
    );
}
