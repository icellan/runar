//! Integer-domain parity tests (issue #162).
//!
//! The Rúnar language's integer domain is arbitrary-precision: post-Genesis
//! BSV Script has arbitrary-precision script numbers, the TS reference folder
//! works on native JS `bigint`, and the Go / Rust / Python / Ruby / Java tiers
//! all follow. The Zig tier carried THREE different bounds for that one
//! domain:
//!
//!   * the parsers thresholded at `i64` (`parseInt(i64, ...)`), routing
//!     anything larger to `literal_bigint`;
//!   * `ConstValue.integer` is `i128`;
//!   * `emitPushInt` takes `i64`.
//!
//! Each mismatch produced a distinct externally-visible defect:
//!
//!   D1  operands fit i64 but the folded product does not -> the unchecked
//!       `@intCast` in `lowerLoadConst` aborts the process (SIGABRT, no
//!       diagnostic, no source location).
//!   D2  a bare JSON number beyond i64 in an ANF-IR `load_const` -> the
//!       loader returns `InvalidConstValue` where Go compiles.
//!   D3  `builtin_pow` folded with Zig's WRAPPING `*%` on `i128`, so a power
//!       divisible by `2^128` folded to `0` and the tier silently emitted
//!       `OP_0` in place of a multi-byte push. No abort, no error, a
//!       different locking script — a miscompile, not an availability bug.
//!       The vector was `pow(2n, 200n)`; R-169 moved it to `pow(256n, 32n)`,
//!       which has the same residue and the same trap but an exponent inside
//!       the domain the emitted script can compute. 200 is no longer folded
//!       by any tier — its companion test pins that instead.
//!   D4  operands ABOVE i64 arrive as `big_integer`, which `evalBinOp` did
//!       not recognise, so the fold was skipped entirely and Zig emitted a
//!       runtime `OP_MUL` where the other six tiers emit a folded push.
//!
//! Every expected hex below was measured from the Go, Python AND Ruby tiers
//! on current `main` — all three agree byte-for-byte. These are therefore
//! cross-tier parity pins, not self-attested Zig goldens.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const ir_json = @import("../ir/json.zig");
const stack_lower = @import("../passes/stack_lower.zig");
const peephole = @import("../passes/peephole.zig");
const emit = @import("../codegen/emit.zig");

/// Compile a `.runar.ts` source to locking-script hex. `.runar.ts` rather
/// than the Zig surface syntax so these sources are byte-for-byte the ones
/// replayed against the Go / Python / Ruby CLIs when the expectations below
/// were measured.
fn compileTs(comptime source: []const u8) ![]const u8 {
    return compiler_api.compileSourceToHex(std.testing.allocator, source, "Probe.runar.ts");
}

fn expectHex(comptime source: []const u8, expected: []const u8) !void {
    const hex = try compileTs(source);
    defer std.testing.allocator.free(hex);
    try std.testing.expectEqualStrings(expected, hex);
}

/// Compile with the constant folder DISABLED. That mode is not a curiosity:
/// the checked-in conformance goldens are stamped fold-OFF, so it is the
/// path every `expected-script.hex` is replayed against.
fn expectHexFoldOff(comptime source: []const u8, expected: []const u8) !void {
    const result = try compiler_api.compileSourceWithOptions(
        std.testing.allocator,
        source,
        "Probe.runar.ts",
        true,
    );
    if (result.artifact_json) |json| std.testing.allocator.free(json);
    defer std.testing.allocator.free(result.script_hex);
    try std.testing.expectEqualStrings(expected, result.script_hex);
}

// ---------------------------------------------------------------------------
// D1 — folded product escapes i64
// ---------------------------------------------------------------------------

test "D1: product of two i64-max literals compiles instead of aborting" {
    // (2^63-1)^2 = 85070591730234615847396907784232501249, a 16-byte push.
    // Before the fix this aborted the whole process at stack_lower.zig's
    // `emitPushInt(@intCast(n))` with "integer does not fit in destination
    // type" and exit code 134.
    try expectHex(
        \\import { SmartContract, assert } from 'runar-lang';
        \\
        \\export class Probe extends SmartContract {
        \\  readonly target: bigint;
        \\  constructor(target: bigint) { super(target); this.target = target; }
        \\  public check() {
        \\    assert((9223372036854775807n * 9223372036854775807n) === this.target);
        \\  }
        \\}
    ,
        "08ffffffffffffff7f08ffffffffffffff7f100100000000000000ffffffffffffff3f009c7777",
    );
}

// ---------------------------------------------------------------------------
// D3 — wrapping fold silently emitted the wrong constant
// ---------------------------------------------------------------------------

test "D3: pow(256n, 32n) folds to 2^256, not the mod-2^128 residue" {
    // 2^256 mod 2^128 == 0 exactly, so the wrapping fold emitted a bare OP_0
    // (`00`) here and the contract compared its argument against zero. This
    // is the reachable silent-miscompile path: no abort, no diagnostic, just
    // a different locking script from the other six tiers.
    //
    // R-169 (pow half) moved this vector from pow(2n, 200n) to pow(256n, 32n).
    // Same trap, same residue, same 33-byte push — but an exponent INSIDE the
    // domain the emitted script can compute. 200 is no longer foldable by any
    // tier (see the companion test below), so a fold-result assertion on it
    // would have been asserting something that never happens.
    try expectHex(
        \\import { SmartContract, assert, pow } from 'runar-lang';
        \\
        \\export class Probe extends SmartContract {
        \\  readonly target: bigint;
        \\  constructor(target: bigint) { super(target); this.target = target; }
        \\  public check() {
        \\    assert(pow(256n, 32n) === this.target);
        \\  }
        \\}
    ,
        "020001012021000000000000000000000000000000000000000000000000000000000000000001009c7777",
    );
}

test "D3: pow(2n, 200n) is NOT folded — it is outside the domain the script computes" {
    // R-169, the pow half. `lowerPow` unrolls exactly 32 conditional
    // multiplies, so it computes base^min(exp, 32); until the guard landed it
    // returned that CLAMPED value with no error, while the folder computed the
    // TRUE power for any exp <= 256. Inside 33..256 the fold-ON and fold-OFF
    // scripts therefore accepted MUTUALLY EXCLUSIVE inputs.
    //
    // The folder now declines outside 0..32, so this compiles to the guarded
    // 32-round fragment rather than to a 2^200 push, and the guard
    // (76 00 0121 a5 69 = OP_DUP <0> <33> OP_WITHIN OP_VERIFY) makes the method
    // unspendable instead of silently answering 2^32. Pinned as full hex, and
    // cross-checked byte-for-byte against the go and rust tiers when written.
    try expectHex(
        \\import { SmartContract, assert, pow } from 'runar-lang';
        \\
        \\export class Probe extends SmartContract {
        \\  readonly target: bigint;
        \\  constructor(target: bigint) { super(target); this.target = target; }
        \\  public check() {
        \\    assert(pow(2n, 200n) === this.target);
        \\  }
        \\}
    ,
        "5202c80076000121a5697c51527900a063789568527951a063789568527952a063789568527953a063789568527954a063789568527955a063789568527956a063789568527957a063789568527958a063789568527959a06378956852795aa06378956852795ba06378956852795ca06378956852795da06378956852795ea06378956852795fa063789568527960a06378956852790111a06378956852790112a06378956852790113a06378956852790114a06378956852790115a06378956852790116a06378956852790117a06378956852790118a06378956852790119a0637895685279011aa0637895685279011ba0637895685279011ca0637895685279011da0637895685279011ea0637895685279011fa0637895687777009c",
    );
}

test "D3: mulDiv over above-i64 operands folds without wrapping" {
    // 2^64 * 2^64 / 2 = 2^127 — fits i128, but only just, and the operands
    // are themselves above i64, so this covers the builtin arm of D4 too.
    try expectHex(
        \\import { SmartContract, assert, mulDiv } from 'runar-lang';
        \\
        \\export class Probe extends SmartContract {
        \\  readonly target: bigint;
        \\  constructor(target: bigint) { super(target); this.target = target; }
        \\  public check() {
        \\    assert(mulDiv(18446744073709551616n, 18446744073709551616n, 2n) === this.target);
        \\  }
        \\}
    ,
        "090000000000000000010900000000000000000152110000000000000000000000000000008000009c777777",
    );
}

// ---------------------------------------------------------------------------
// D4 — operands above i64 are folded, not deferred to runtime opcodes
// ---------------------------------------------------------------------------

test "D4: product of two above-i64 literals is folded, not emitted as OP_MUL" {
    const source =
        \\import { SmartContract, assert } from 'runar-lang';
        \\
        \\export class Probe extends SmartContract {
        \\  readonly target: bigint;
        \\  constructor(target: bigint) { super(target); this.target = target; }
        \\  public check() {
        \\    assert((1180591620717411303424n * 1180591620717411303424n) === this.target);
        \\  }
        \\}
    ;
    // 2^70 * 2^70 = 2^140, an 18-byte push. Zig used to emit `95` (OP_MUL)
    // and defer the multiply to spend time; the other six tiers fold it.
    try expectHex(
        source,
        "090000000000000000400900000000000000004012000000000000000000000000000000000010009c7777",
    );
}

test "D4: sum of two above-i64 literals is folded, not emitted as OP_ADD" {
    // 2^64 + 2^64 = 2^65. Zig used to emit `93` (OP_ADD).
    try expectHex(
        \\import { SmartContract, assert } from 'runar-lang';
        \\
        \\export class Probe extends SmartContract {
        \\  readonly target: bigint;
        \\  constructor(target: bigint) { super(target); this.target = target; }
        \\  public check() {
        \\    assert((18446744073709551616n + 18446744073709551616n) === this.target);
        \\  }
        \\}
    ,
        "090000000000000000010900000000000000000109000000000000000002009c7777",
    );
}

// ---------------------------------------------------------------------------
// D2 — ANF-IR loader accepts bare JSON numbers beyond i64
// ---------------------------------------------------------------------------

test "D2: load_const with a bare JSON number above i64 loads as .integer" {
    const ir =
        \\{"contractName":"Probe","properties":[{"name":"target","type":"bigint","readonly":true}],
        \\ "methods":[{"name":"check","params":[],"isPublic":true,"body":[
        \\   {"name":"t0","value":{"kind":"load_const","value":18446744073709551616}},
        \\   {"name":"t1","value":{"kind":"load_prop","name":"target"}},
        \\   {"name":"t2","value":{"kind":"bin_op","op":"===","left":"t0","right":"t1"}},
        \\   {"name":"t3","value":{"kind":"assert","value":"t2"}}]}]}
    ;
    // parseANFProgram is arena-owned by convention: ANFProgram.deinit walks
    // the binding tree but does not free the duped strings, so every json.zig
    // test wraps it in an arena rather than the raw testing allocator.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const program = try ir_json.parseANFProgram(arena.allocator(), ir);

    // 2^64 exceeds i64 but fits i128, so per the ConstValue contract in
    // ir/types.zig it must land in `.integer`, not `.big_integer`.
    try std.testing.expectEqual(
        @as(i128, 18446744073709551616),
        program.methods[0].body[0].value.load_const.value.integer,
    );
}

test "D2: load_const with a bare JSON number beyond i128 loads as .big_integer" {
    // 2^200 has no fixed-width home at all; it must round through the
    // decimal-text variant.
    const ir =
        \\{"contractName":"Probe","properties":[{"name":"target","type":"bigint","readonly":true}],
        \\ "methods":[{"name":"check","params":[],"isPublic":true,"body":[
        \\   {"name":"t0","value":{"kind":"load_const","value":1606938044258990275541962092341162602522202993782792835301376}},
        \\   {"name":"t1","value":{"kind":"load_prop","name":"target"}},
        \\   {"name":"t2","value":{"kind":"bin_op","op":"===","left":"t0","right":"t1"}},
        \\   {"name":"t3","value":{"kind":"assert","value":"t2"}}]}]}
    ;
    // parseANFProgram is arena-owned by convention: ANFProgram.deinit walks
    // the binding tree but does not free the duped strings, so every json.zig
    // test wraps it in an arena rather than the raw testing allocator.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const program = try ir_json.parseANFProgram(arena.allocator(), ir);

    try std.testing.expectEqualStrings(
        "1606938044258990275541962092341162602522202993782792835301376",
        program.methods[0].body[0].value.load_const.value.big_integer,
    );
}

// ---------------------------------------------------------------------------
// D6 — the peephole could only read one of the two push representations
// ---------------------------------------------------------------------------

test "D6: peephole folds big-representation operands, not just push_int" {
    // The same arithmetic, but reaching the peephole as `push_big_int_decimal`
    // rather than `push_int` — which is what happens on the `--ir` path, where
    // the ANF names an oversize constant as decimal text.
    //
    // `getPushIntValue` could only see `push_int`, so the fold was skipped and
    // a SMALLER window rule fired instead: `PUSH(2^63-1), PUSH(1), OP_ADD`
    // collapsed to `PUSH(2^63-1), OP_1ADD`, and `PUSH(a), PUSH(a), OP_MUL`
    // kept a runtime OP_MUL, where the other six tiers emit one folded push.
    // The source path hides this completely, because the Zig parser routes an
    // i64-sized literal to `push_int` — it is reachable only through `--ir`.
    const ir =
        \\{"contractName":"Probe","properties":[{"name":"target","type":"bigint","readonly":true}],
        \\ "methods":[{"name":"check","params":[],"isPublic":true,"body":[
        \\   {"name":"t0","value":{"kind":"load_const","value":"9223372036854775807n"}},
        \\   {"name":"t1","value":{"kind":"load_const","value":"9223372036854775807n"}},
        \\   {"name":"t2","value":{"kind":"bin_op","op":"*","left":"t0","right":"t1"}},
        \\   {"name":"t3","value":{"kind":"load_prop","name":"target"}},
        \\   {"name":"t4","value":{"kind":"bin_op","op":"===","left":"t2","right":"t3"}},
        \\   {"name":"t5","value":{"kind":"assert","value":"t4"}}]}]}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const program = try ir_json.parseANFProgram(alloc, ir);
    const stack = try stack_lower.lower(alloc, program);
    const optimized = try peephole.optimize(alloc, stack.methods);
    const hex = try emit.emitMethodScript(alloc, optimized[0].instructions);

    // (2^63-1)^2 as one 16-byte push, then the constructor slot and the
    // comparison. No OP_MUL (0x95) survives.
    try std.testing.expectEqualStrings(
        "100100000000000000ffffffffffffff3f009c",
        hex,
    );
}

// ---------------------------------------------------------------------------
// D5 — the peephole's own constant folder truncated to i64
// ---------------------------------------------------------------------------
//
// The peephole runs on Stack IR between passes 5 and 6 and is ALWAYS enabled,
// including when the ANF constant folder is off. With folding off the literal
// arithmetic survives lowering as PUSH, PUSH, OP_MUL and the peephole folds it
// instead -- through `@as(i64, @truncate(...))`, which silently discarded the
// high bits.
//
// This path matters more than the fold-ON one: the checked-in conformance
// goldens are stamped fold-OFF, so it is what every `expected-script.hex` in
// the repo is replayed against.

test "D5: peephole folds push/push/OP_MUL at full width, not truncated to i64" {
    // (2^32-1)^2 = 18446744065119617025. Truncated to i64 that is
    // -8589934591, which the Zig tier emitted as a 5-byte push where Go,
    // Rust, Python and Ruby all emit 9 bytes.
    try expectHexFoldOff(
        \\import { SmartContract, assert } from 'runar-lang';
        \\
        \\export class Probe extends SmartContract {
        \\  readonly target: bigint;
        \\  constructor(target: bigint) { super(target); this.target = target; }
        \\  public check() {
        \\    assert((4294967295n * 4294967295n) === this.target);
        \\  }
        \\}
    ,
        "0901000000feffffff00009c",
    );
}

test "D5: peephole folds push/push/OP_ADD past i64 without truncating" {
    // (2^63-1) + 1 = 2^63, one past the signed 64-bit ceiling. Truncation
    // turned it into -2^63, flipping the encoded sign byte.
    try expectHexFoldOff(
        \\import { SmartContract, assert } from 'runar-lang';
        \\
        \\export class Probe extends SmartContract {
        \\  readonly target: bigint;
        \\  constructor(target: bigint) { super(target); this.target = target; }
        \\  public check() {
        \\    assert((9223372036854775807n + 1n) === this.target);
        \\  }
        \\}
    ,
        "09000000000000008000009c",
    );
}
