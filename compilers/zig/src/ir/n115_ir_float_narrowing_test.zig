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
//! A panicking loader cannot satisfy `expectError` — it never returns to the
//! test — so each assertion here is one the pre-fix code could not have
//! passed by accident. That property is why this file survives N-131 rather
//! than being replaced by it: the abort class is still the thing being
//! guarded, and only an assertion that the loader RETURNS can guard it.
//!
//! ---------------------------------------------------------------------------
//! SUPERSEDED IN PART BY N-131 — the answer is now "refused", not "narrowed"
//! ---------------------------------------------------------------------------
//!
//! N-115 deliberately left truncation alone. Its own words, on the last test
//! in this file: "Pinned, not endorsed [...] tightening it is a separate
//! cross-tier decision". It also recorded, as an aside, that go and java
//! refuse floats outright and called that "a pre-existing cross-tier
//! divergence in the `--ir` float lane, not one this change introduces or
//! resolves".
//!
//! N-131 is that separate decision, and it resolved the divergence the other
//! way: a JSON float is not legal ANF IR at all. The schema
//! (`packages/runar-ir-schema/src/schemas/anf-ir.schema.json`) has no
//! float-typed field, no tier's `--emit-ir` writes one (478 emitted documents
//! scanned, zero), no checked-in fixture contains one, and the `n`-suffixed
//! decimal string already carries values too large for a native integer. What
//! the six tiers did with a float was therefore unspecified — and they
//! disagreed in emitted BYTES: `{"start":1e30}` alone produced three different
//! answers, and this tier read `{"count":3.5}` as three unrolled bodies while
//! five peers refused the same file.
//!
//! So every case below now expects `FloatNotAllowedInIR`, raised by
//! `assertNoJSONFloats` at the door, and the five "control: an in-range float
//! still loads" cases have become refusals. They are kept rather than deleted
//! because the shape each one probes — count, start, load_const, the two
//! arities, initialValue — is still a distinct site, and because the case that
//! used to be the control (a float whose value is an exact integer, `5.0` /
//! `1.0` / `42.0`) is exactly the case a VALUE-based guard would let through.
//! They are now the tests that pin the rule as LEXICAL.
//!
//! `floatToInt` itself is left in place. It is no longer reachable from
//! `parseANFProgram` — nothing gets past the door — but it is the thing that
//! makes the six narrowing sites total if it ever is reached again, and
//! removing a guard because the guard in front of it works is how the first
//! N-115 fix came to check the range after the cast.

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
    try expectLoadError(src, a, error.FloatNotAllowedInIR);
}

test "N-131: a loop count of 5.0 is refused even though 5.0 IS five" {
    // Was N-115's control ("an in-range loop count written as a float still
    // loads"). It is now the case that distinguishes the rule N-131 chose
    // from the one it rejected: `5.0` is in range, is integral, and would
    // pass any value-based guard. Go and Java — the two tiers that were
    // already right — refuse it, so converging on them means refusing it too.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"loop","count":5.0,"iterVar":"i","body":[{"name":"t1","value":{"kind":"load_const","value":0}}]}}
    );
    try expectLoadError(src, a, error.FloatNotAllowedInIR);
}

test "N-131 control: the same loop count as an INTEGER still loads" {
    // The other half of the claim. A guard that refuses floats by refusing
    // loops passes the test above and fails this one.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"loop","count":5,"iterVar":"i","body":[{"name":"t1","value":{"kind":"load_const","value":0}}]}}
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
    try expectLoadError(src, a, error.FloatNotAllowedInIR);
}

test "N-131: a loop start of 3.0 is refused; the integer 3 is not" {
    // Was N-115's control. `start` is the field where the three-way split was
    // worst: go/zig/java refused 1e30, rust/python read it as 1e30, and ruby
    // read it as 0 and emitted a script for a loop the IR never described.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const float_src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"loop","count":2,"start":3.0,"step":1,"iterVar":"i","body":[{"name":"t1","value":{"kind":"load_const","value":0}}]}}
    );
    try expectLoadError(float_src, a, error.FloatNotAllowedInIR);

    const int_src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"loop","count":2,"start":3,"step":1,"iterVar":"i","body":[{"name":"t1","value":{"kind":"load_const","value":0}}]}}
    );
    try expectLoads(int_src, a);
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
    try expectLoadError(src, a, error.FloatNotAllowedInIR);
}

test "N-131: a load_const of 1e30 is refused, and the value it used to mean is why" {
    // Was N-115's control, which pinned Zig into the group that accepted
    // 1e30, on the reasoning that zig/rust/python/ruby all emitted the same
    // bytes for it.
    //
    // They did. But look at what those bytes MEANT: 1e30's nearest f64 is
    // 1000000000000000019884624838656, not 10^30, and that is the number the
    // four tiers agreed to put in a locking script. Agreement on a value none
    // of them was given is not parity; it is four copies of the same guess.
    // One token over, at 1e50, the agreement collapsed anyway — rust
    // saturated to i128::MAX and pushed 10ffffffffffffffffffffffffffffff7f
    // while python and ruby produced a different number again.
    //
    // A caller who means 10^30 already has a way to say so, and it is exact:
    // the `n`-suffixed decimal string, which all six tiers read identically.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const float_src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"load_const","value":1e30}}
    );
    try expectLoadError(float_src, a, error.FloatNotAllowedInIR);

    // The exact form, still accepted, and carrying 10^30 rather than the f64
    // nearest to it. It lands in `.big_integer` — the decimal text, kept
    // verbatim — which is precisely why it is exact where the float was not.
    const exact_src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"load_const","value":"1000000000000000000000000000000n"}}
    );
    const program = try json.parseANFProgram(a, exact_src);
    switch (program.methods[0].body[0].value) {
        .load_const => |lc| switch (lc.value) {
            .big_integer => |d| try testing.expectEqualStrings("1000000000000000000000000000000", d),
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
    try expectLoadError(src, a, error.FloatNotAllowedInIR);
}

test "a raw_script out_arity float beyond i64 is an error, not an abort" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"raw_script","bytes":"51","in_arity":0,"out_arity":1e30}}
    );
    try expectLoadError(src, a, error.FloatNotAllowedInIR);
}

test "N-131: raw_script arities of 0.0 / 1.0 are refused; 0 / 1 are not" {
    // Was N-115's control. `{"out_arity":1.0}` is the single input that proves
    // the old rule was value-based: this tier compiled it clean while all five
    // peers refused the same file.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const float_src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"raw_script","bytes":"51","in_arity":0.0,"out_arity":1.0}}
    );
    try expectLoadError(float_src, a, error.FloatNotAllowedInIR);

    const int_src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"raw_script","bytes":"51","in_arity":0,"out_arity":1}}
    );
    try expectLoads(int_src, a);
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
    try expectLoadError(src, a, error.FloatNotAllowedInIR);
}

test "N-131: a property initialValue of 42.0 is refused; 42 is not" {
    // Was N-115's control. `initialValue` is a seventh float site, reached by
    // the same door guard as the six in the method bodies — which is the
    // argument for a generic walk over the parsed document rather than a
    // check per named field.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const float_src = try irWithProperties(a,
        \\{"name":"balance","type":"bigint","readonly":false,"initialValue":42.0}
    );
    try expectLoadError(float_src, a, error.FloatNotAllowedInIR);

    const int_src = try irWithProperties(a,
        \\{"name":"balance","type":"bigint","readonly":false,"initialValue":42}
    );
    try expectLoads(int_src, a);
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

test "N-131: a fractional loop count is refused, not truncated" {
    // The test N-115 wrote as "pinned, not endorsed", inverted by the
    // cross-tier decision it was waiting for.
    //
    // `count: 2.5` unrolled two bodies here. It is worth being precise about
    // why that was the worst of the six shapes: 2.5 is INSIDE the 10000 cap,
    // so the magnitude guard never had an opinion about it, and it was the
    // only input in this file that five peers refused while this tier emitted
    // a script. The script it emitted was for a loop the IR did not describe.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const src = try irWithBinding(a,
        \\{"name":"t0","value":{"kind":"loop","count":2.5,"iterVar":"i","body":[{"name":"t1","value":{"kind":"load_const","value":0}}]}}
    );
    try expectLoadError(src, a, error.FloatNotAllowedInIR);
}
