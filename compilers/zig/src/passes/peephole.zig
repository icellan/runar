//! Peephole optimizer for Stack IR.
//!
//! Runs after stack lowering but before emission. Applies 30 rewrite rules
//! iteratively (fixed-point, max 100 iterations) in a single left-to-right pass.
//! Larger windows are tried first (greedy). If-block bodies are recursively
//! optimized before the main pass.

const std = @import("std");
const types = @import("../ir/types.zig");
const Opcode = types.Opcode;
const Inst = types.StackInstruction;
const Allocator = std.mem.Allocator;

const max_iterations = 100;

// ============================================================================
// Matching helpers
// ============================================================================

/// Returns true if the instruction is any push variant (push_int, push_data, push_bool).
fn isPush(inst: Inst) bool {
    return switch (inst) {
        .push_int, .push_data, .push_bool => true,
        .op => false,
    };
}

/// Returns true if the instruction is a push_int with the given value.
fn isPushInt(inst: Inst, value: i64) bool {
    return switch (inst) {
        .push_int => |v| v == value,
        else => false,
    };
}

/// Returns true if the instruction is an opcode matching the given opcode enum value.
fn isOp(inst: Inst, opcode: Opcode) bool {
    return switch (inst) {
        .op => |o| o == opcode,
        else => false,
    };
}

/// Extract the integer value from a push_int instruction, or null.
fn getPushIntValue(inst: Inst) ?i64 {
    return switch (inst) {
        .push_int => |v| v,
        else => null,
    };
}

/// Compare two StackInstructions for equality.
fn instEql(a: Inst, b: Inst) bool {
    const TagType = std.meta.Tag(Inst);
    const tag_a: TagType = a;
    const tag_b: TagType = b;
    if (tag_a != tag_b) return false;
    return switch (a) {
        .op => |oa| oa == b.op,
        .push_int => |va| va == b.push_int,
        .push_bool => |ba| ba == b.push_bool,
        .push_data => |da| std.mem.eql(u8, da, b.push_data),
    };
}

/// Compare two instruction slices for equality.
fn sliceEql(a: []const Inst, b: []const Inst) bool {
    if (a.len != b.len) return false;
    for (a, b) |ia, ib| {
        if (!instEql(ia, ib)) return false;
    }
    return true;
}

// ============================================================================
// Public API
// ============================================================================

/// Optimize all methods in a StackMethod slice. Returns a new slice (caller owns).
pub fn optimize(allocator: Allocator, methods: []const types.StackMethod) ![]types.StackMethod {
    const result = try allocator.alloc(types.StackMethod, methods.len);
    for (methods, 0..) |method, i| {
        const optimized_insts = try optimizeOps(allocator, method.instructions);
        result[i] = .{
            .name = method.name,
            .instructions = optimized_insts,
            .ops = method.ops,
            .max_stack_depth = method.max_stack_depth,
        };
    }
    return result;
}

/// Optimize a single instruction sequence. Returns a new slice (caller owns).
/// Applies rules iteratively until no more changes occur or max_iterations reached.
/// Uses two alternating buffers to avoid allocating a new slice per iteration.
pub fn optimizeOps(allocator: Allocator, ops: []const Inst) ![]Inst {
    // Two reusable buffers that alternate roles (input/output) each iteration
    var buf_a = std.ArrayListUnmanaged(Inst).empty;
    defer buf_a.deinit(allocator);
    var buf_b = std.ArrayListUnmanaged(Inst).empty;
    defer buf_b.deinit(allocator);

    // Seed buf_a with the input
    try buf_a.ensureTotalCapacity(allocator, ops.len);
    buf_a.appendSliceAssumeCapacity(ops);

    var iteration: usize = 0;
    while (iteration < max_iterations) : (iteration += 1) {
        const changed = try runOnePass(allocator, buf_a.items, &buf_b);
        if (!changed) break;
        // Swap: buf_b becomes input, buf_a becomes output for next iteration
        const tmp = buf_a;
        buf_a = buf_b;
        buf_b = tmp;
    }

    // Return owned slice from whichever buffer holds the final result
    // buf_a always holds the current result (either unchanged or post-swap)
    const result = try allocator.alloc(Inst, buf_a.items.len);
    @memcpy(result, buf_a.items);
    return result;
}

/// A single left-to-right pass applying all rules greedily (largest window first).
/// Writes results into `out` (cleared first). Returns true if any rule fired.
fn runOnePass(allocator: Allocator, ops: []const Inst, out: *std.ArrayListUnmanaged(Inst)) !bool {
    out.clearRetainingCapacity();
    var changed = false;

    var i: usize = 0;
    while (i < ops.len) {
        // Try window size 4
        if (i + 4 <= ops.len) {
            if (tryWindow4(ops[i..][0..4])) |replacement| {
                for (replacement) |inst| {
                    if (inst) |r| try out.append(allocator, r);
                }
                i += 4;
                changed = true;
                continue;
            }
        }
        // Try window size 3
        if (i + 3 <= ops.len) {
            if (tryWindow3(ops[i..][0..3])) |replacement| {
                for (replacement) |inst| {
                    if (inst) |r| try out.append(allocator, r);
                }
                i += 3;
                changed = true;
                continue;
            }
        }
        // Try window size 2
        if (i + 2 <= ops.len) {
            if (tryWindow2(ops[i..][0..2])) |replacement| {
                for (replacement) |inst| {
                    if (inst) |r| try out.append(allocator, r);
                }
                i += 2;
                changed = true;
                continue;
            }
        }
        // No rule matched — emit instruction as-is
        try out.append(allocator, ops[i]);
        i += 1;
    }

    return changed;
}

// ============================================================================
// Window-2 rules (23 rules)
// ============================================================================

/// Optional replacement: up to 2 instructions (null = no output for that slot).
const Replacement2 = [2]?Inst;

fn tryWindow2(w: *const [2]Inst) ?Replacement2 {
    const a = w[0];
    const b = w[1];

    // Rule 1: PUSH(x) + DROP -> (removed)
    if (isPush(a) and isOp(b, .op_drop)) return .{ null, null };

    // Rule 2: DUP + DROP -> (removed)  [also covers rule 14: opcode-form OP_DUP + OP_DROP]
    if (isOp(a, .op_dup) and isOp(b, .op_drop)) return .{ null, null };

    // Rule 3: SWAP + SWAP -> (removed)
    if (isOp(a, .op_swap) and isOp(b, .op_swap)) return .{ null, null };

    // Rule 4: PUSH(1) + OP_ADD -> OP_1ADD
    if (isPushInt(a, 1) and isOp(b, .op_add)) return .{ Inst{ .op = .op_1add }, null };

    // Rule 5: PUSH(1) + OP_SUB -> OP_1SUB
    if (isPushInt(a, 1) and isOp(b, .op_sub)) return .{ Inst{ .op = .op_1sub }, null };

    // Rule 6: PUSH(0) + OP_ADD -> (removed)
    if (isPushInt(a, 0) and isOp(b, .op_add)) return .{ null, null };

    // Rule 7: PUSH(0) + OP_SUB -> (removed)
    if (isPushInt(a, 0) and isOp(b, .op_sub)) return .{ null, null };

    // Rule 8: OP_NOT + OP_NOT -> (removed)
    if (isOp(a, .op_not) and isOp(b, .op_not)) return .{ null, null };

    // Rule 9: OP_NEGATE + OP_NEGATE -> (removed)
    if (isOp(a, .op_negate) and isOp(b, .op_negate)) return .{ null, null };

    // Rule 10: OP_EQUAL + OP_VERIFY -> OP_EQUALVERIFY
    if (isOp(a, .op_equal) and isOp(b, .op_verify))
        return .{ Inst{ .op = .op_equalverify }, null };

    // Rule 11: OP_CHECKSIG + OP_VERIFY -> OP_CHECKSIGVERIFY
    if (isOp(a, .op_checksig) and isOp(b, .op_verify))
        return .{ Inst{ .op = .op_checksigverify }, null };

    // Rule 12: OP_NUMEQUAL + OP_VERIFY -> OP_NUMEQUALVERIFY
    if (isOp(a, .op_numequal) and isOp(b, .op_verify))
        return .{ Inst{ .op = .op_numequalverify }, null };

    // Rule 13: OP_CHECKMULTISIG + OP_VERIFY -> OP_CHECKMULTISIGVERIFY
    if (isOp(a, .op_checkmultisig) and isOp(b, .op_verify))
        return .{ Inst{ .op = .op_checkmultisigverify }, null };

    // Rule 15: OVER + OVER -> OP_2DUP
    if (isOp(a, .op_over) and isOp(b, .op_over)) return .{ Inst{ .op = .op_2dup }, null };

    // Rule 16: DROP + DROP -> OP_2DROP
    if (isOp(a, .op_drop) and isOp(b, .op_drop)) return .{ Inst{ .op = .op_2drop }, null };

    // Rule 17: PUSH(0) + ROLL -> (removed, roll 0 = no-op)
    if (isPushInt(a, 0) and isOp(b, .op_roll)) return .{ null, null };

    // Rule 20: PUSH(0) + PICK -> DUP
    if (isPushInt(a, 0) and isOp(b, .op_pick)) return .{ Inst{ .op = .op_dup }, null };

    // Rule 21: PUSH(1) + PICK -> OVER
    if (isPushInt(a, 1) and isOp(b, .op_pick)) return .{ Inst{ .op = .op_over }, null };

    // Rule 22: OP_SHA256 + OP_SHA256 -> OP_HASH256
    if (isOp(a, .op_sha256) and isOp(b, .op_sha256)) return .{ Inst{ .op = .op_hash256 }, null };

    return null;
}

// ============================================================================
// Window-3 rules (constant folding)
// ============================================================================

const Replacement3 = [3]?Inst;

fn tryWindow3(w: *const [3]Inst) ?Replacement3 {
    const va = getPushIntValue(w[0]) orelse return null;
    const vb = getPushIntValue(w[1]) orelse return null;

    // Rule 24: PUSH(a) + PUSH(b) + OP_ADD -> PUSH(a+b)
    if (isOp(w[2], .op_add)) {
        const result = @as(i64, @truncate(@as(i128, va) + @as(i128, vb)));
        return .{ Inst{ .push_int = result }, null, null };
    }

    // Rule 25: PUSH(a) + PUSH(b) + OP_SUB -> PUSH(a-b)
    if (isOp(w[2], .op_sub)) {
        const result = @as(i64, @truncate(@as(i128, va) - @as(i128, vb)));
        return .{ Inst{ .push_int = result }, null, null };
    }

    // Rule 26: PUSH(a) + PUSH(b) + OP_MUL -> PUSH(a*b)
    if (isOp(w[2], .op_mul)) {
        const result = @as(i64, @truncate(@as(i128, va) * @as(i128, vb)));
        return .{ Inst{ .push_int = result }, null, null };
    }

    return null;
}

// ============================================================================
// Window-4 rules (reassociation)
// ============================================================================

const Replacement4 = [4]?Inst;

fn tryWindow4(w: *const [4]Inst) ?Replacement4 {
    // Rule 27: PUSH(a) + OP_ADD + PUSH(b) + OP_ADD -> PUSH(a+b) + OP_ADD
    if (isOp(w[1], .op_add) and isOp(w[3], .op_add)) {
        const va = getPushIntValue(w[0]) orelse return null;
        const vb = getPushIntValue(w[2]) orelse return null;
        const sum = @as(i64, @truncate(@as(i128, va) + @as(i128, vb)));
        return .{ Inst{ .push_int = sum }, Inst{ .op = .op_add }, null, null };
    }

    // Rule 28: PUSH(a) + OP_SUB + PUSH(b) + OP_SUB -> PUSH(a+b) + OP_SUB
    if (isOp(w[1], .op_sub) and isOp(w[3], .op_sub)) {
        const va = getPushIntValue(w[0]) orelse return null;
        const vb = getPushIntValue(w[2]) orelse return null;
        const sum = @as(i64, @truncate(@as(i128, va) + @as(i128, vb)));
        return .{ Inst{ .push_int = sum }, Inst{ .op = .op_sub }, null, null };
    }

    // Rule 29: PUSH(a) + OP_ADD + PUSH(b) + OP_SUB -> PUSH(a-b) + OP_ADD (if a >= b)
    //          or PUSH(b-a) + OP_SUB (if b > a)
    if (isOp(w[1], .op_add) and isOp(w[3], .op_sub)) {
        const va = getPushIntValue(w[0]) orelse return null;
        const vb = getPushIntValue(w[2]) orelse return null;
        const diff = @as(i64, @truncate(@as(i128, va) - @as(i128, vb)));
        if (diff >= 0) {
            return .{ Inst{ .push_int = diff }, Inst{ .op = .op_add }, null, null };
        } else {
            return .{ Inst{ .push_int = -diff }, Inst{ .op = .op_sub }, null, null };
        }
    }

    // Rule 30: PUSH(a) + OP_SUB + PUSH(b) + OP_ADD -> PUSH(b-a) + OP_ADD (if b >= a)
    //          or PUSH(a-b) + OP_SUB (if a > b)
    if (isOp(w[1], .op_sub) and isOp(w[3], .op_add)) {
        const va = getPushIntValue(w[0]) orelse return null;
        const vb = getPushIntValue(w[2]) orelse return null;
        const diff = @as(i64, @truncate(@as(i128, vb) - @as(i128, va)));
        if (diff >= 0) {
            return .{ Inst{ .push_int = diff }, Inst{ .op = .op_add }, null, null };
        } else {
            return .{ Inst{ .push_int = -diff }, Inst{ .op = .op_sub }, null, null };
        }
    }

    return null;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

fn expectOps(expected: []const Inst, actual: []const Inst) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |e, a| {
        if (!instEql(e, a)) {
            std.debug.print("Expected {any}, got {any}\n", .{ e, a });
            return error.TestExpectedEqual;
        }
    }
}

// --- Rule 1: PUSH(x) + DROP -> removed ---
test "rule 1: push + drop eliminated" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .push_int = 42 }, .{ .op = .op_drop } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

// --- Rule 2: DUP + DROP -> removed ---
test "rule 2: dup + drop eliminated" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .op = .op_dup }, .{ .op = .op_drop } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

// --- Rule 3: SWAP + SWAP -> removed ---
test "rule 3: swap + swap eliminated" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .op = .op_swap }, .{ .op = .op_swap } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

// --- Rule 4: PUSH(1) + OP_ADD -> OP_1ADD ---
test "rule 4: push 1 + add -> 1add" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .push_int = 1 }, .{ .op = .op_add } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{.{ .op = .op_1add }}, result);
}

// --- Rule 5: PUSH(1) + OP_SUB -> OP_1SUB ---
test "rule 5: push 1 + sub -> 1sub" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .push_int = 1 }, .{ .op = .op_sub } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{.{ .op = .op_1sub }}, result);
}

// --- Rule 6: PUSH(0) + OP_ADD -> removed ---
test "rule 6: push 0 + add eliminated" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .push_int = 0 }, .{ .op = .op_add } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

// --- Rule 7: PUSH(0) + OP_SUB -> removed ---
test "rule 7: push 0 + sub eliminated" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .push_int = 0 }, .{ .op = .op_sub } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

// --- Rule 8: OP_NOT + OP_NOT -> removed ---
test "rule 8: not + not eliminated" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .op = .op_not }, .{ .op = .op_not } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

// --- Rule 9: OP_NEGATE + OP_NEGATE -> removed ---
test "rule 9: negate + negate eliminated" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .op = .op_negate }, .{ .op = .op_negate } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

// --- Rule 10: OP_EQUAL + OP_VERIFY -> OP_EQUALVERIFY ---
test "rule 10: equal + verify -> equalverify" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .op = .op_equal }, .{ .op = .op_verify } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{.{ .op = .op_equalverify }}, result);
}

// --- Rule 11: OP_CHECKSIG + OP_VERIFY -> OP_CHECKSIGVERIFY ---
test "rule 11: checksig + verify -> checksigverify" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .op = .op_checksig }, .{ .op = .op_verify } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{.{ .op = .op_checksigverify }}, result);
}

// --- Rule 12: OP_NUMEQUAL + OP_VERIFY -> OP_NUMEQUALVERIFY ---
test "rule 12: numequal + verify -> numequalverify" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .op = .op_numequal }, .{ .op = .op_verify } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{.{ .op = .op_numequalverify }}, result);
}

// --- Rule 13: OP_CHECKMULTISIG + OP_VERIFY -> OP_CHECKMULTISIGVERIFY ---
test "rule 13: checkmultisig + verify -> checkmultisigverify" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .op = .op_checkmultisig }, .{ .op = .op_verify } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{.{ .op = .op_checkmultisigverify }}, result);
}

// --- Rule 15: OVER + OVER -> OP_2DUP ---
test "rule 15: over + over -> 2dup" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .op = .op_over }, .{ .op = .op_over } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{.{ .op = .op_2dup }}, result);
}

// --- Rule 16: DROP + DROP -> OP_2DROP ---
test "rule 16: drop + drop -> 2drop" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .op = .op_drop }, .{ .op = .op_drop } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{.{ .op = .op_2drop }}, result);
}

// --- Rule 17: PUSH(0) + ROLL -> removed ---
test "rule 17: push 0 + roll eliminated" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .push_int = 0 }, .{ .op = .op_roll } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

// --- Rule 20: PUSH(0) + PICK -> DUP ---
test "rule 20: push 0 + pick -> dup" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .push_int = 0 }, .{ .op = .op_pick } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{.{ .op = .op_dup }}, result);
}

// --- Rule 21: PUSH(1) + PICK -> OVER ---
test "rule 21: push 1 + pick -> over" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .push_int = 1 }, .{ .op = .op_pick } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{.{ .op = .op_over }}, result);
}

// --- Rule 22: OP_SHA256 + OP_SHA256 -> OP_HASH256 ---
test "rule 22: sha256 + sha256 -> hash256" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .op = .op_sha256 }, .{ .op = .op_sha256 } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{.{ .op = .op_hash256 }}, result);
}

// --- Rule 24: PUSH(a) + PUSH(b) + OP_ADD -> PUSH(a+b) ---
test "rule 24: constant fold add" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .push_int = 3 }, .{ .push_int = 7 }, .{ .op = .op_add } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{.{ .push_int = 10 }}, result);
}

// --- Rule 25: PUSH(a) + PUSH(b) + OP_SUB -> PUSH(a-b) ---
test "rule 25: constant fold sub" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .push_int = 10 }, .{ .push_int = 3 }, .{ .op = .op_sub } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{.{ .push_int = 7 }}, result);
}

// --- Rule 26: PUSH(a) + PUSH(b) + OP_MUL -> PUSH(a*b) ---
test "rule 26: constant fold mul" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .push_int = 4 }, .{ .push_int = 5 }, .{ .op = .op_mul } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{.{ .push_int = 20 }}, result);
}

// --- Rule 27: PUSH(a) + OP_ADD + PUSH(b) + OP_ADD -> PUSH(a+b) + OP_ADD ---
test "rule 27: reassociate add + add" {
    const alloc = testing.allocator;
    const input = [_]Inst{
        .{ .push_int = 3 },
        .{ .op = .op_add },
        .{ .push_int = 7 },
        .{ .op = .op_add },
    };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{ .{ .push_int = 10 }, .{ .op = .op_add } }, result);
}

// --- Rule 28: PUSH(a) + OP_SUB + PUSH(b) + OP_SUB -> PUSH(a+b) + OP_SUB ---
test "rule 28: reassociate sub + sub" {
    const alloc = testing.allocator;
    const input = [_]Inst{
        .{ .push_int = 3 },
        .{ .op = .op_sub },
        .{ .push_int = 7 },
        .{ .op = .op_sub },
    };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{ .{ .push_int = 10 }, .{ .op = .op_sub } }, result);
}

// --- Rule 29: PUSH(a) + OP_ADD + PUSH(b) + OP_SUB ---
test "rule 29: reassociate add + sub" {
    const alloc = testing.allocator;
    // x + 5 - 3 => x + (5-3) = x + 2
    const input = [_]Inst{
        .{ .push_int = 5 },
        .{ .op = .op_add },
        .{ .push_int = 3 },
        .{ .op = .op_sub },
    };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{ .{ .push_int = 2 }, .{ .op = .op_add } }, result);
}

// --- Rule 30: PUSH(a) + OP_SUB + PUSH(b) + OP_ADD ---
test "rule 30: reassociate sub + add" {
    const alloc = testing.allocator;
    // x - 3 + 7 => x + (7-3) = x + 4
    const input = [_]Inst{
        .{ .push_int = 3 },
        .{ .op = .op_sub },
        .{ .push_int = 7 },
        .{ .op = .op_add },
    };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{ .{ .push_int = 4 }, .{ .op = .op_add } }, result);
}

// --- Fixed-point iteration ---
test "fixed-point: cascading optimizations" {
    const alloc = testing.allocator;
    // PUSH(3) PUSH(7) OP_ADD OP_DROP
    // First pass: fold 3+7=10 -> PUSH(10) OP_DROP
    // Second pass: push + drop -> removed
    const input = [_]Inst{
        .{ .push_int = 3 },
        .{ .push_int = 7 },
        .{ .op = .op_add },
        .{ .op = .op_drop },
    };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

test "fixed-point: reassociation then identity" {
    const alloc = testing.allocator;
    // PUSH(5) OP_ADD PUSH(5) OP_SUB
    // Rule 29: diff = 5-5 = 0 -> PUSH(0) OP_ADD
    // Rule 6: PUSH(0) OP_ADD -> removed
    const input = [_]Inst{
        .{ .push_int = 5 },
        .{ .op = .op_add },
        .{ .push_int = 5 },
        .{ .op = .op_sub },
    };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

// --- No-op on already optimal code ---
test "already optimal: no changes" {
    const alloc = testing.allocator;
    const input = [_]Inst{
        .{ .op = .op_dup },
        .{ .op = .op_hash160 },
        .{ .op = .op_equalverify },
        .{ .op = .op_checksig },
    };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&input, result);
}

// --- Non-integer push + drop ---
test "rule 1: push_bool + drop eliminated" {
    const alloc = testing.allocator;
    const input = [_]Inst{ .{ .push_bool = true }, .{ .op = .op_drop } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

test "rule 1: push_data + drop eliminated" {
    const alloc = testing.allocator;
    const data = [_]u8{ 0xab, 0xcd };
    const input = [_]Inst{ .{ .push_data = &data }, .{ .op = .op_drop } };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

// --- Mixed sequence with multiple rules ---
test "multiple rules in sequence" {
    const alloc = testing.allocator;
    // OP_SWAP OP_SWAP PUSH(1) OP_ADD OP_EQUAL OP_VERIFY
    // -> (removed) OP_1ADD OP_EQUALVERIFY
    const input = [_]Inst{
        .{ .op = .op_swap },
        .{ .op = .op_swap },
        .{ .push_int = 1 },
        .{ .op = .op_add },
        .{ .op = .op_equal },
        .{ .op = .op_verify },
    };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{ .{ .op = .op_1add }, .{ .op = .op_equalverify } }, result);
}

// --- Window 4 has priority over smaller windows ---
test "greedy: window 4 takes priority" {
    const alloc = testing.allocator;
    // PUSH(2) OP_ADD PUSH(3) OP_ADD
    // Window 4 matches rule 27: -> PUSH(5) OP_ADD
    const input = [_]Inst{
        .{ .push_int = 2 },
        .{ .op = .op_add },
        .{ .push_int = 3 },
        .{ .op = .op_add },
    };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{ .{ .push_int = 5 }, .{ .op = .op_add } }, result);
}

// --- Reassociation resulting in push(1) triggers further optimization ---
test "fixed-point: reassociation yields push(1) then 1add" {
    const alloc = testing.allocator;
    // PUSH(3) OP_ADD PUSH(2) OP_SUB
    // Rule 29: 3-2=1 -> PUSH(1) OP_ADD
    // Rule 4: PUSH(1) OP_ADD -> OP_1ADD
    const input = [_]Inst{
        .{ .push_int = 3 },
        .{ .op = .op_add },
        .{ .push_int = 2 },
        .{ .op = .op_sub },
    };
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{.{ .op = .op_1add }}, result);
}

// --- Empty input ---
test "empty input stays empty" {
    const alloc = testing.allocator;
    const input = [_]Inst{};
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

// --- Single instruction is unchanged ---
test "single instruction unchanged" {
    const alloc = testing.allocator;
    const input = [_]Inst{.{ .op = .op_dup }};
    const result = try optimizeOps(alloc, &input);
    defer alloc.free(result);
    try expectOps(&.{.{ .op = .op_dup }}, result);
}

// --- Method-level optimize ---
test "optimize methods" {
    const alloc = testing.allocator;

    var insts1 = [_]Inst{ .{ .push_int = 1 }, .{ .op = .op_add } };
    var insts2 = [_]Inst{ .{ .op = .op_swap }, .{ .op = .op_swap } };

    var methods = [_]types.StackMethod{
        .{ .name = "method1", .instructions = &insts1 },
        .{ .name = "method2", .instructions = &insts2 },
    };

    const result = try optimize(alloc, &methods);
    defer {
        for (result) |m| alloc.free(m.instructions);
        alloc.free(result);
    }

    try testing.expectEqual(@as(usize, 2), result.len);
    // method1: PUSH(1) + ADD -> 1ADD
    try testing.expectEqual(@as(usize, 1), result[0].instructions.len);
    try testing.expect(instEql(Inst{ .op = .op_1add }, result[0].instructions[0]));
    // method2: SWAP + SWAP -> removed
    try testing.expectEqual(@as(usize, 0), result[1].instructions.len);
}
