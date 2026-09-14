//! N-115 (second half) — a JSON float on the `--ir` trust boundary must
//! produce a DIAGNOSTIC, never an abort.
//!
//! The first half of N-115 put a magnitude guard on the loop count. It was
//! placed AFTER the narrowing:
//!
//!     const raw_count: i64 = switch (count_val) {
//!         .integer => |i| i,
//!         .float   => |f| @intFromFloat(f),   // <- here
//!         else => return ParseError.UnexpectedValueType,
//!     };
//!     if (raw_count > types.MAX_LOOP_COUNT or raw_count < 0) ...
//!
//! `@intFromFloat` is illegal behaviour when the value's integer part does not
//! fit the destination: a safety-checked abort in Debug/ReleaseSafe,
//! undefined behaviour in ReleaseFast. So the guard never ran for the inputs
//! that most needed it. `{"kind":"loop","count":1e30}` died on SIGABRT —
//! measured `rc=134`, "integer part of floating point value out of bounds" —
//! where every peer tier renders a verdict:
//!
//!     go      exit 1   cannot unmarshal number 1e30 into ANFValue
//!     rust    exit 1   invalid type: floating point `1e30`, expected usize
//!     python  exit 1   loop count 1e+30 exceeding maximum 10000
//!     ruby    exit 1   loop count 1.0e+30 exceeding maximum 10000
//!     java    exit 65  loop count is not an integer: Double
//!     zig     rc=134   SIGABRT — no verdict at all
//!
//! An aborting process renders no verdict: a caller reading the exit status
//! learns nothing, and a caller reading stdout gets a panic trace where a
//! diagnostic belongs.
//!
//! This is a CLASS, not three instances. Every `@intFromFloat` in json.zig is
//! fed by attacker-controlled JSON, and all six were reachable — each verified
//! by probe before this test was written, each `rc=134`:
//!
//!     json.zig:287  property `initialValue`   {"initialValue": 1e50}
//!     json.zig:504  raw_script `in_arity`     {"in_arity": 1e30}
//!     json.zig:517  raw_script `out_arity`    {"out_arity": 1e30}
//!     json.zig:539  load_const `value`        {"value": 1e50}
//!     json.zig:720  loop `count`              {"count": 1e30}
//!     json.zig:736  loop `start`              {"start": 1e30}
//!
//! Two of them — `start` and the arities — have no magnitude guard anywhere
//! near them, so moving the loop-count check above its cast would have closed
//! exactly one site and left five open. The fix is one total conversion
//! (`json.floatToInt`) that range-checks in the f64 domain before narrowing,
//! used at all six.
//!
//! **What the fix deliberately does NOT change.** Behaviour is identical
//! wherever `@intFromFloat` was already legal. That matters: `{"value":1e30}`
//! fits i128, and zig, rust, python and ruby all emit the same bytes for it
//! today (go and java refuse floats outright — a pre-existing cross-tier
//! divergence in the `--ir` float lane, not one this change introduces or
//! resolves). Silently moving Zig out of that agreeing group would trade an
//! abort for a hex divergence. The controls below pin that.
//!
//! A panicking loader cannot satisfy `expectError` — it never returns to the
//! test — so each assertion here is one the pre-fix code could not have
//! passed by accident.

const std = @import("std");
const testing = std.testing;
const json = @import("json.zig");
const types = @import("types.zig");

/// A one-method contract whose single binding is supplied verbatim, so each
/// case differs from its control in exactly one JSON token.
fn irWithBinding(allocator: std.mem.Allocator, binding: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        \\{{"contractName":"Probe","properties":[],"methods":[{{"name":"unlock","params":[],"isPublic":true,"body":[{s}]}}]}}
    , .{binding});
}

/// Same, with the properties list supplied verbatim instead.
fn irWithProperties(allocator: std.mem.Allocator, properties: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        \\{{"contractName":"Probe","properties":[{s}],"methods":[{{"name":"unlock","params":[],"isPublic":true,"body":[{{"name":"t0","value":{{"kind":"load_const","value":0}}}}]}}]}}
    , .{properties});
}

fn expectLoadError(src: []const u8, allocator: std.mem.Allocator, expected: anyerror) !void {
    try testing.expectError(expected, json.parseANFProgram(allocator, src));
}

fn expectLoads(src: []const u8, allocator: std.mem.Allocator) !void {
    const program = try json.parseANFProgram(allocator, src);
    try testing.expectEqualStrings("Probe", program.contract_name);
}

// ---------------------------------------------------------------------------
// json.zig:720 — loop `count`
// ---------------------------------------------------------------------------

test "a loop count float beyond i64 is LoopCountExceedsMaximum, not an abort" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"loop","count":1e30,"iterVar":"i","body":[{"name":"t1","value":{"kind":"load_const","value":0}}]}}
    );
    try expectLoadError(src, a, error.LoopCountExceedsMaximum);
}

test "control: an in-range loop count written as a float still loads" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"loop","count":5.0,"iterVar":"i","body":[{"name":"t1","value":{"kind":"load_const","value":0}}]}}
    );
    try expectLoads(src, a);
}

// ---------------------------------------------------------------------------
// json.zig:736 — loop `start`
// ---------------------------------------------------------------------------

test "a loop start float beyond i64 is an error, not an abort" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"loop","count":2,"start":1e30,"step":1,"iterVar":"i","body":[{"name":"t1","value":{"kind":"load_const","value":0}}]}}
    );
    try expectLoadError(src, a, error.InvalidConstValue);
}

test "control: an in-range loop start written as a float still loads" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"loop","count":2,"start":3.0,"step":1,"iterVar":"i","body":[{"name":"t1","value":{"kind":"load_const","value":0}}]}}
    );
    try expectLoads(src, a);
}

// ---------------------------------------------------------------------------
// json.zig:539 — load_const `value`
// ---------------------------------------------------------------------------

test "a load_const float beyond i128 is an error, not an abort" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"load_const","value":1e50}}
    );
    try expectLoadError(src, a, error.InvalidConstValue);
}

test "control: a load_const float that FITS i128 still loads, unchanged" {
    // 1e30 is inside i128 and survives the loader's existing round-trip check
    // (its nearest f64 is an exact integer — 1000000000000000019884624838656,
    // not 10^30, which is why the expected value below looks odd). Zig, Rust,
    // Python and Ruby all emit the same script for it today; the fix must not
    // move Zig out of that group by tightening what it accepts.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"load_const","value":1e30}}
    );
    const program = try json.parseANFProgram(a, src);
    const value = program.methods[0].body[0].value;
    switch (value) {
        .load_const => |lc| switch (lc.value) {
            .integer => |i| try testing.expectEqual(@as(i128, 1_000_000_000_000_000_019_884_624_838_656), i),
            else => return error.WrongConstVariant,
        },
        else => return error.WrongANFVariant,
    }
}

// ---------------------------------------------------------------------------
// json.zig:504 / :517 — raw_script arities
// ---------------------------------------------------------------------------

test "a raw_script in_arity float beyond i64 is an error, not an abort" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"raw_script","bytes":"51","in_arity":1e30,"out_arity":1}}
    );
    try expectLoadError(src, a, error.InvalidConstValue);
}

test "a raw_script out_arity float beyond i64 is an error, not an abort" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"raw_script","bytes":"51","in_arity":0,"out_arity":1e30}}
    );
    try expectLoadError(src, a, error.InvalidConstValue);
}

test "control: raw_script arities written as in-range floats still load" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"raw_script","bytes":"51","in_arity":0.0,"out_arity":1.0}}
    );
    try expectLoads(src, a);
}

// ---------------------------------------------------------------------------
// json.zig:287 — property `initialValue`
// ---------------------------------------------------------------------------

test "a property initialValue float beyond i128 is an error, not an abort" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const src = try irWithProperties(a,
        \\{"name":"balance","type":"bigint","readonly":false,"initialValue":1e50}
    );
    try expectLoadError(src, a, error.InvalidConstValue);
}

test "control: a property initialValue float that FITS i128 still loads" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const src = try irWithProperties(a,
        \\{"name":"balance","type":"bigint","readonly":false,"initialValue":42.0}
    );
    try expectLoads(src, a);
}

// ---------------------------------------------------------------------------
// The rest of the float domain
// ---------------------------------------------------------------------------
//
// NaN and the infinities are not "out of range" in the ordering sense — they
// fail every comparison — so a bounds check written as `if (f > limit)` lets
// them straight through to the same abort. `floatToInt` is written as
// `if (!(f >= -limit and f < limit))` for that reason.
//
// The test below does NOT prove that arm: `1e400` is refused by std.json
// before a float ever reaches the loader, so it pins the requirement (no
// abort, whatever the token) rather than exercising the non-finite path. The
// guard's shape is the real defence; this is the end-to-end reminder of why it
// has that shape.

test "a non-finite loop count is an error, not an abort" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // 1e400 overflows f64 to +inf.
    const src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"loop","count":1e400,"iterVar":"i","body":[{"name":"t1","value":{"kind":"load_const","value":0}}]}}
    );
    try testing.expect(std.meta.isError(json.parseANFProgram(a, src)));
}

test "a fractional loop count keeps its existing truncating behaviour" {
    // Pinned, not endorsed. Truncation is not the abort class this change is
    // about, and `count: 2.5` is accepted as 2 by this tier today; tightening
    // it is a separate cross-tier decision, so the fix must leave it alone.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"loop","count":2.5,"iterVar":"i","body":[{"name":"t1","value":{"kind":"load_const","value":0}}]}}
    );
    const program = try json.parseANFProgram(a, src);
    switch (program.methods[0].body[0].value) {
        .loop => |l| try testing.expectEqual(@as(u32, 2), l.count),
        else => return error.WrongANFVariant,
    }
}
