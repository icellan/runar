//! N-100 -- a conditional whose ELSE arm optimizes away must emit NO `OP_ELSE`.
//!
//! Six tiers keep a branch STRUCTURED (`StackOp{if, then, else}`) all the way to
//! the emitter: the peephole recurses into each arm, and the emitter decides
//! whether to write `OP_ELSE` from the arm's POST-optimization length
//! (`compilers/go/codegen/emit.go#emitIf`: `if len(elseOps) > 0`).
//!
//! Zig flattens the branch into a linear `StackInstruction` stream inside
//! `lowerIfExprImpl`, and used to take that decision from the PRE-optimization
//! instruction count (`if (else_ctx.instructions.items.len > 0)`). The peephole
//! runs later, over the already-flattened stream, so when it erased the arm's
//! whole body the `OP_ELSE` it had already committed to stayed behind:
//!
//!     assert((f ? this.s : this.id(p)) === this.s)
//!     six tiers  7c 63 00 77    68 00 9c
//!     zig        7c 63 00 77 67 68 00 9c      <- stray 0x67 OP_ELSE
//!
//! The producer of the erasable body is not the private call as such. A private
//! method call lowers its `@this` receiver marker to `push 0` and
//! `lowerMethodCall` immediately drops it again, so a trivial helper (`return x`)
//! leaves exactly `push_int 0, OP_DROP` -- peephole rule 1, `PUSH(x) + DROP ->
//! (removed)`. Any other body the peephole erases triggers the same divergence,
//! which is why `p + 0n` (rule 6) and `p - 0n` (rule 7) are pinned here
//! alongside the helper calls: the trigger is "the else arm optimizes to
//! nothing", not "the else arm contains a call".
//!
//! Every `want` below is the hex that ALL SIX other tiers (ts, go, rust, python,
//! ruby, java) produce for that source, in both constant-folding modes.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const PRELUDE =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\class C extends SmartContract {
    \\  readonly s: bigint;
    \\
    \\  constructor(s: bigint) { super(s); this.s = s; }
    \\
;

/// Identity helper: its entire inlined body is the `@this` push/drop pair.
const ID_HELPER =
    \\  private id(x: bigint): bigint { return x; }
    \\
;

// ---------------------------------------------------------------------------
// Shapes that DIVERGED: the else arm's whole body is peephole-erasable.
// ---------------------------------------------------------------------------

const ELSE_ARM_PRIVATE_CALL = PRELUDE ++ ID_HELPER ++
    \\
    \\  public m(f: boolean, p: bigint): void {
    \\    assert((f ? this.s : this.id(p)) === this.s);
    \\  }
    \\}
;

const BOTH_ARMS_PRIVATE_CALL = PRELUDE ++ ID_HELPER ++
    \\
    \\  public m(f: boolean, p: bigint): void {
    \\    assert((f ? this.id(p) : this.id(p)) === this.s);
    \\  }
    \\}
;

const NESTED_TERNARY_INNER_ELSE = PRELUDE ++ ID_HELPER ++
    \\
    \\  public m(f: boolean, g: boolean, p: bigint): void {
    \\    assert((f ? this.s : (g ? this.s : this.id(p))) === this.s);
    \\  }
    \\}
;

const NESTED_TERNARY_IN_THEN_ARM = PRELUDE ++ ID_HELPER ++
    \\
    \\  public m(f: boolean, g: boolean, p: bigint): void {
    \\    assert((f ? (g ? this.s : this.id(p)) : this.s) === this.s);
    \\  }
    \\}
;

/// No call anywhere -- the erasable body comes from peephole rule 6
/// (`PUSH(0) + OP_ADD -> (removed)`). Proves the trigger is the ERASURE, not
/// the private method.
const ELSE_ARM_ADD_ZERO = PRELUDE ++
    \\
    \\  public m(f: boolean, p: bigint): void {
    \\    assert((f ? this.s : (p + 0n)) === this.s);
    \\  }
    \\}
;

/// Same, via peephole rule 7 (`PUSH(0) + OP_SUB -> (removed)`).
const ELSE_ARM_SUB_ZERO = PRELUDE ++
    \\
    \\  public m(f: boolean, p: bigint): void {
    \\    assert((f ? this.s : (p - 0n)) === this.s);
    \\  }
    \\}
;

// ---------------------------------------------------------------------------
// Controls: shapes that already matched and MUST NOT MOVE.
// ---------------------------------------------------------------------------

/// A ternary with no call in either arm. The else arm emits nothing at all, so
/// the old pre-optimization count already said "no else".
const CTL_TERNARY_NO_CALL = PRELUDE ++
    \\
    \\  public m(f: boolean, p: bigint): void {
    \\    assert((f ? this.s : p) === this.s);
    \\  }
    \\}
;

/// The call sits in the CONSEQUENT. The then arm erases, but `OP_IF` is
/// unconditional and the else arm is real, so `OP_ELSE` is correct here.
const CTL_THEN_ARM_PRIVATE_CALL = PRELUDE ++ ID_HELPER ++
    \\
    \\  public m(f: boolean, p: bigint): void {
    \\    assert((f ? this.id(p) : this.s) === this.s);
    \\  }
    \\}
;

/// A private call in ordinary statement position, outside any arm.
const CTL_STATEMENT_PRIVATE_CALL = PRELUDE ++ ID_HELPER ++
    \\
    \\  public m(p: bigint): void {
    \\    const v: bigint = this.id(p);
    \\    assert(v === this.s);
    \\  }
    \\}
;

/// An `if` STATEMENT (not a ternary) whose else arm calls the helper. The arm
/// also has to write `v`, so its body does not erase.
const CTL_IF_STATEMENT_ELSE_PRIVATE_CALL = PRELUDE ++ ID_HELPER ++
    \\
    \\  public m(f: boolean, p: bigint): void {
    \\    let v: bigint = this.s;
    \\    if (f) { v = this.s; } else { v = this.id(p); }
    \\    assert(v === this.s);
    \\  }
    \\}
;

/// A BUILT-IN call in the else arm: `abs` emits `OP_ABS`, which does not erase.
const CTL_ELSE_ARM_BUILTIN_CALL =
    \\import { SmartContract, assert, abs } from 'runar-lang';
    \\
    \\class C extends SmartContract {
    \\  readonly s: bigint;
    \\
    \\  constructor(s: bigint) { super(s); this.s = s; }
    \\
    \\  public m(f: boolean, p: bigint): void {
    \\    assert((f ? this.s : abs(p)) === this.s);
    \\  }
    \\}
;

/// A private call in the else arm whose body survives the peephole.
const CTL_ELSE_ARM_NONTRIVIAL_HELPER = PRELUDE ++
    \\  private bump(x: bigint): bigint { return x + 1n; }
    \\
    \\  public m(f: boolean, p: bigint): void {
    \\    assert((f ? this.s : this.bump(p)) === this.s);
    \\  }
    \\}
;

/// An `if` statement with a helper call in BOTH arms.
const CTL_IF_STATEMENT_BOTH_ARMS_CALL = PRELUDE ++ ID_HELPER ++
    \\
    \\  public m(f: boolean, p: bigint): void {
    \\    if (f) { assert(this.s === this.s); } else { assert(this.id(p) === this.id(p)); }
    \\  }
    \\}
;

const Case = struct {
    label: []const u8,
    source: []const u8,
    want: []const u8,
};

/// The shapes N-100 moves. `want` is the six-tier hex.
const REGRESSION_CASES = [_]Case{
    .{ .label = "else-arm/private-call", .source = ELSE_ARM_PRIVATE_CALL, .want = "7c63007768009c" },
    .{ .label = "both-arms/private-call", .source = BOTH_ARMS_PRIVATE_CALL, .want = "7c6368009c" },
    .{ .label = "nested-ternary/inner-else", .source = NESTED_TERNARY_INNER_ELSE, .want = "7b63007b7577677c6300776868009c" },
    .{ .label = "nested-ternary/in-then-arm", .source = NESTED_TERNARY_IN_THEN_ARM, .want = "7b637c6300776867007b757768009c" },
    .{ .label = "else-arm/p+0n", .source = ELSE_ARM_ADD_ZERO, .want = "7c63007768009c" },
    .{ .label = "else-arm/p-0n", .source = ELSE_ARM_SUB_ZERO, .want = "7c63007768009c" },
};

/// The shapes N-100 must leave alone. `want` is the hex Zig already emitted
/// BEFORE the fix, which is also the six-tier hex.
const CONTROL_CASES = [_]Case{
    .{ .label = "ctl/ternary-no-call", .source = CTL_TERNARY_NO_CALL, .want = "7c63007768009c" },
    .{ .label = "ctl/then-arm-private-call", .source = CTL_THEN_ARM_PRIVATE_CALL, .want = "7c6367007768009c" },
    .{ .label = "ctl/statement-private-call", .source = CTL_STATEMENT_PRIVATE_CALL, .want = "76009c77" },
    .{ .label = "ctl/if-statement-else-private-call", .source = CTL_IF_STATEMENT_ELSE_PRIVATE_CALL, .want = "007b630076537a7577677c767676537a75777768517a75009c" },
    .{ .label = "ctl/else-arm-builtin-call", .source = CTL_ELSE_ARM_BUILTIN_CALL, .want = "7c630077679068009c" },
    .{ .label = "ctl/else-arm-nontrivial-helper", .source = CTL_ELSE_ARM_NONTRIVIAL_HELPER, .want = "7c630077678b68009c" },
    .{ .label = "ctl/if-statement-both-arms-call", .source = CTL_IF_STATEMENT_BOTH_ARMS_CALL, .want = "7c6300009c7767767c9c68" },
};

const CompileOut = struct {
    hex: []const u8,
    artifact: ?[]const u8,

    fn deinit(self: CompileOut, allocator: std.mem.Allocator) void {
        allocator.free(self.hex);
        if (self.artifact) |a| allocator.free(a);
    }
};

fn compile(
    allocator: std.mem.Allocator,
    source: []const u8,
    disable_constant_folding: bool,
) !CompileOut {
    const result = try compiler_api.compileSourceWithOptions(
        allocator,
        source,
        "C.runar.ts",
        disable_constant_folding,
    );
    return .{ .hex = result.script_hex, .artifact = result.artifact_json };
}

fn checkCases(cases: []const Case) !void {
    const allocator = std.testing.allocator;
    for (cases) |tc| {
        for ([_]bool{ true, false }) |disable| {
            const got = try compile(allocator, tc.source, disable);
            defer got.deinit(allocator);
            std.testing.expectEqualStrings(tc.want, got.hex) catch |err| {
                std.debug.print(
                    "{s} (disable_constant_folding={}): script hex diverged from the six-tier output\n",
                    .{ tc.label, disable },
                );
                return err;
            };
        }
    }
}

test "an else arm that optimizes away emits no OP_ELSE" {
    try checkCases(&REGRESSION_CASES);
}

test "shapes N-100 does not touch keep their bytes" {
    try checkCases(&CONTROL_CASES);
}

// Tier-independent oracle: no reference compiler is consulted. `OP_ELSE`
// immediately followed by `OP_ENDIF` is an else CLAUSE with no body -- a
// structure no correct lowering has any reason to emit, whatever the peers do.
test "no emitted script contains an empty else clause" {
    const allocator = std.testing.allocator;
    for ([_][]const Case{ &REGRESSION_CASES, &CONTROL_CASES }) |group| {
        for (group) |tc| {
            for ([_]bool{ true, false }) |disable| {
                const got = try compile(allocator, tc.source, disable);
                defer got.deinit(allocator);
                const artifact = got.artifact orelse return error.MissingArtifact;
                if (std.mem.indexOf(u8, artifact, "OP_ELSE OP_ENDIF") != null) {
                    std.debug.print(
                        "{s} (disable_constant_folding={}): asm contains an empty else clause\n",
                        .{ tc.label, disable },
                    );
                    return error.EmptyElseClauseEmitted;
                }
            }
        }
    }
}

// The empty `OP_ELSE` was semantically inert -- both spellings of
// `else-arm/private-call` run identically on the upstream `@bsv/sdk` `Spend`
// interpreter for every witness (`a` = 5, so the constructor slots read OP_5):
//
//   locking (zig, pre-fix)  7c 63 55 77 67 68 55 9c
//   locking (six tiers)     7c 63 55 77    68 55 9c
//
//   witness (f, p)   both interpreters
//   (true , 5)       stack ["01"]  success
//   (true , 9)       stack ["01"]  success
//   (true , 0)       stack ["01"]  success
//   (true , -1)      stack ["01"]  success
//   (false, 5)       stack ["01"]  success
//   (false, 9)       stack [""]    fail
//   (false, 0)       stack [""]    fail
//   (false, -1)      stack [""]    fail
//
// The Zig tier ships no ScriptVM (see CLAUDE.md), so that execution is recorded
// here rather than asserted. What the extra byte DID break is byte-level tier
// parity: the script is one byte longer, so a Zig-compiled contract hashes to a
// different locking script than the same source compiled anywhere else, and the
// artifact's `constructorSlots` byteOffsets shift with it (2,6 instead of 2,5).
// The arms are spliced into the enclosing method by `appendInstructions`, which
// used to append the instructions WITHOUT their source locations. `emit` keeps
// `instructions` and `instruction_source_locs` as two arrays read by index, so
// from the first conditional onward every later opcode was zipped against an
// earlier opcode's location: neither arm's own line appeared in the map at all.
//
//   before  OP_0@12 OP_SWAP@13 OP_IF@13 OP_SWAP@13 OP_0@13 OP_ADD@13
//           OP_DUP@18 OP_NIP@18 OP_ELSE@18 OP_SWAP@18 OP_0@- ...
//   after   OP_0@12 OP_SWAP@13 OP_IF@13 OP_SWAP@14 OP_0@14 OP_ADD@14
//           OP_DUP@- OP_NIP@- OP_ELSE@13 OP_SWAP@16 OP_0@16 OP_SUB@16 ...
//
// N-100 has to touch that splice anyway (it now hands over the OPTIMIZED arm),
// and leaving the two arrays desynchronised would only have reshuffled which
// opcode got which wrong line.
const SOURCE_MAP_ARMS =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\class C extends SmartContract {
    \\  readonly limit: bigint;
    \\
    \\  constructor(limit: bigint) {
    \\    super(limit);
    \\    this.limit = limit;
    \\  }
    \\
    \\  public check(value: bigint, mode: boolean): void {
    \\    let result: bigint = 0n;
    \\    if (mode) {
    \\      result = value + this.limit;
    \\    } else {
    \\      result = value - this.limit;
    \\    }
    \\    assert(result > 0n);
    \\  }
    \\}
;

test "each branch arm's own source line reaches the source map" {
    const allocator = std.testing.allocator;
    const got = try compile(allocator, SOURCE_MAP_ARMS, false);
    defer got.deinit(allocator);
    const artifact = got.artifact orelse return error.MissingArtifact;
    // Scope the search to the `sourceMap` object. The artifact also carries the
    // whole ANF, whose bindings have `sourceLoc` entries naming the very same
    // lines -- searching the raw artifact makes this assertion pass even with
    // the arms' locations thrown away.
    const start = std.mem.indexOf(u8, artifact, "\"sourceMap\"") orelse return error.MissingSourceMap;
    const end = std.mem.indexOfPos(u8, artifact, start, "\"anf\"") orelse artifact.len;
    const source_map = artifact[start..end];
    // line 14 is the then arm's assignment, line 16 the else arm's.
    for ([_][]const u8{ "\"line\":14", "\"line\":16" }) |needle| {
        if (std.mem.indexOf(u8, source_map, needle) == null) {
            std.debug.print("source map has no mapping for {s}\n", .{needle});
            return error.ArmSourceLineMissing;
        }
    }
}

test "the fix does not change what the script computes" {
    const allocator = std.testing.allocator;
    // `p` only reaches the result through the else arm, and the then arm only
    // through `this.s`; a lowering that lost an arm would collapse these two
    // programs onto one script.
    const a = try compile(allocator, ELSE_ARM_PRIVATE_CALL, false);
    defer a.deinit(allocator);
    const b = try compile(allocator, CTL_THEN_ARM_PRIVATE_CALL, false);
    defer b.deinit(allocator);
    try std.testing.expect(!std.mem.eql(u8, a.hex, b.hex));
}
