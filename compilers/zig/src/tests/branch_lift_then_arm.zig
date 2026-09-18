//! Regression test: the branch-lift must not zero the matched arm.
//!
//! `liftBranchUpdateProps` flattens a dispatch chain
//!
//!     if (p == 0n) { this.c0 = v; } else if (p == 1n) { this.c1 = v; }
//!     else { assert(false); }
//!
//! into one single-valued `if` per property plus a top-level `update_prop`. The
//! `if`'s then-arm must evaluate to the assigned value and its else-arm to the
//! property's old value.
//!
//! The defect: the then-arm was built from `branch.value_bindings` — everything
//! BEFORE the `update_prop` in the original arm. That ends on the assigned
//! value only when the value was computed INSIDE the arm. When the arm assigns
//! something bound outside it, `value_bindings` is empty, the arm was emitted
//! EMPTY, and stack lowering padded it with a zero push:
//!
//!     OP_IF OP_0 OP_ELSE OP_DUP OP_ENDIF      (63 00 67 76 68)
//!
//! i.e. the MATCHED branch pushed zero, so `if (p == 0n) { this.c0 = local; }`
//! compiled to `this.c0 = 0` — a silent state-corrupting miscompile that
//! reproduced identically in all seven tiers.
//!
//! `examples/ts/tic-tac-toe` escapes it only because `this.cN = this.turn` puts
//! a `load_prop` inside the arm — that shape is the control below.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const validate = @import("../passes/validate.zig");
const typecheck = @import("../passes/typecheck.zig");
const expand_fixed_arrays = @import("../passes/expand_fixed_arrays.zig");
const anf_lower = @import("../passes/anf_lower.zig");
const stack_lower = @import("../passes/stack_lower.zig");
const peephole = @import("../passes/peephole.zig");
const emit = @import("../codegen/emit.zig");
const types = @import("../ir/types.zig");

/// OP_IF OP_0 OP_ELSE OP_DUP OP_ENDIF — the matched branch pushing zero.
const ZEROED_ARM = "6300677668";

/// The dispatch chain assigns a LOCAL bound before the chain, so nothing in the
/// arm computes the value. This is the shape that miscompiled.
const LOCAL_VALUE_DISPATCH =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\export class LocalValueDispatch extends StatefulSmartContract {
    \\  c0: bigint;
    \\  c1: bigint;
    \\
    \\  constructor(c0: bigint, c1: bigint) {
    \\    super(c0, c1);
    \\    this.c0 = c0;
    \\    this.c1 = c1;
    \\  }
    \\
    \\  public poke(position: bigint, value: bigint) {
    \\    const doubled: bigint = value + value;
    \\    if (position == 0n) { this.c0 = doubled; }
    \\    else if (position == 1n) { this.c1 = doubled; }
    \\    else { assert(false); }
    \\  }
    \\}
;

/// CONTROL: the arms genuinely assign the literal 0. The zero push is correct
/// here and must survive — a fix that just suppresses the byte pattern fails.
const LITERAL_ZERO_DISPATCH =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\export class LiteralZeroDispatch extends StatefulSmartContract {
    \\  c0: bigint;
    \\  c1: bigint;
    \\
    \\  constructor(c0: bigint, c1: bigint) {
    \\    super(c0, c1);
    \\    this.c0 = c0;
    \\    this.c1 = c1;
    \\  }
    \\
    \\  public poke(position: bigint) {
    \\    if (position == 0n) { this.c0 = 0n; }
    \\    else if (position == 1n) { this.c1 = 0n; }
    \\    else { assert(false); }
    \\  }
    \\}
;

/// CONTROL: the arms compute the value inside themselves (the TicTacToe shape).
/// Already correct before the fix; the fix must add nothing here, or the
/// checked-in goldens move.
const IN_ARM_VALUE_DISPATCH =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\export class InArmValueDispatch extends StatefulSmartContract {
    \\  c0: bigint;
    \\  c1: bigint;
    \\  turn: bigint;
    \\
    \\  constructor(c0: bigint, c1: bigint, turn: bigint) {
    \\    super(c0, c1, turn);
    \\    this.c0 = c0;
    \\    this.c1 = c1;
    \\    this.turn = turn;
    \\  }
    \\
    \\  public poke(position: bigint) {
    \\    if (position == 0n) { this.c0 = this.turn; }
    \\    else if (position == 1n) { this.c1 = this.turn; }
    \\    else { assert(false); }
    \\  }
    \\}
;

fn extractHex(artifact: []const u8) ![]const u8 {
    const marker = "\"script\":\"";
    const idx = std.mem.indexOf(u8, artifact, marker) orelse return error.MissingHex;
    const after = idx + marker.len;
    const end = std.mem.indexOfPos(u8, artifact, after, "\"") orelse return error.MissingHex;
    return artifact[after..end];
}

fn lowerNoFold(alloc: std.mem.Allocator, source: []const u8) !types.ANFProgram {
    const parsed = parse_ts.parseTs(alloc, source, "Dispatch.runar.ts");
    if (parsed.errors.len > 0) return error.ParseFailed;
    const contract = parsed.contract orelse return error.ParseFailed;
    const val = try validate.validate(alloc, contract);
    if (val.errors.len > 0) return error.ValidateFailed;
    const tc = try typecheck.typeCheck(alloc, contract);
    if (tc.errors.len > 0) return error.TypeCheckFailed;
    const expanded = try expand_fixed_arrays.expand(alloc, contract);
    if (expanded.errors.len > 0) return error.ExpandFailed;
    return try anf_lower.lowerToANF(alloc, expanded.contract);
}

/// Fold-OFF pipeline, matching the `--disable-constant-folding` CLI mode.
fn compileNoFold(alloc: std.mem.Allocator, source: []const u8) ![]const u8 {
    const program = try lowerNoFold(alloc, source);
    const stack_program = try stack_lower.lower(alloc, program);
    const optimized_methods = try peephole.optimize(alloc, stack_program.methods);
    const optimized = types.StackProgram{
        .methods = optimized_methods,
        .contract_name = stack_program.contract_name,
        .properties = stack_program.properties,
        .constructor_params = stack_program.constructor_params,
    };
    const artifact = try emit.emitArtifact(alloc, optimized, program);
    return try alloc.dupe(u8, try extractHex(artifact));
}

/// Byte-aligned count of `seq` in a hex string.
fn countByteSequence(hex: []const u8, seq: []const u8) usize {
    var count: usize = 0;
    var i: usize = 0;
    while (i + seq.len <= hex.len) : (i += 2) {
        if (std.mem.eql(u8, hex[i .. i + seq.len], seq)) count += 1;
    }
    return count;
}

/// Every top-level `update_prop` whose value is an `if` binding, with that
/// `if`'s arms. Asserted per-property by the callers below.
fn assertLiftedArms(
    program: types.ANFProgram,
    expect_then_len: ?usize,
) !usize {
    var found: usize = 0;
    for (program.methods) |m| {
        if (!std.mem.eql(u8, m.name, "poke")) continue;
        for (m.bindings) |b| {
            const up = switch (b.value) {
                .update_prop => |u| u,
                else => continue,
            };
            // Locate the binding the update_prop reads.
            var producer: ?*types.ANFIf = null;
            for (m.bindings) |c| {
                if (!std.mem.eql(u8, c.name, up.value)) continue;
                producer = switch (c.value) {
                    .@"if" => |iff| iff,
                    else => null,
                };
                break;
            }
            const iff = producer orelse continue;
            found += 1;
            try std.testing.expect(iff.then.len > 0);
            try std.testing.expect(iff.@"else".len > 0);
            if (expect_then_len) |n| try std.testing.expectEqual(n, iff.then.len);
        }
    }
    return found;
}

test "branch-lift: then-arm carries a value bound outside the arm" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const program = try lowerNoFold(alloc, LOCAL_VALUE_DISPATCH);

    // Both properties in the chain must be lifted. If this is 0 the pass has
    // stopped recognising the shape and the arm assertions pass vacuously.
    const found = try assertLiftedArms(program, null);
    try std.testing.expectEqual(@as(usize, 2), found);

    // The arm must end on the assigned local, not on padding.
    for (program.methods) |m| {
        if (!std.mem.eql(u8, m.name, "poke")) continue;
        for (m.bindings) |b| {
            const iff = switch (b.value) {
                .@"if" => |x| x,
                else => continue,
            };
            if (iff.then.len == 0) continue;
            const last = iff.then[iff.then.len - 1];
            switch (last.value) {
                .load_const => |lc| switch (lc.value) {
                    .string => |s| try std.testing.expectEqualStrings("@ref:doubled", s),
                    else => {},
                },
                else => {},
            }
        }
    }
}

test "branch-lift: no zeroed matched arm for a non-zero assignment" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const hex = try compileNoFold(alloc, LOCAL_VALUE_DISPATCH);
    try std.testing.expectEqual(@as(usize, 0), countByteSequence(hex, ZEROED_ARM));
}

test "branch-lift CONTROL: an arm that really assigns 0n still pushes zero" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const hex = try compileNoFold(alloc, LITERAL_ZERO_DISPATCH);
    try std.testing.expectEqual(@as(usize, 2), countByteSequence(hex, ZEROED_ARM));
}

test "branch-lift CONTROL: the in-arm (TicTacToe) shape is unchanged" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const program = try lowerNoFold(alloc, IN_ARM_VALUE_DISPATCH);
    // Exactly one binding per arm — the in-arm load_prop. A second binding here
    // would move the checked-in goldens.
    const found = try assertLiftedArms(program, 1);
    try std.testing.expectEqual(@as(usize, 2), found);
}
