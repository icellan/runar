// Linear stack analysis (spec §8).

const std = @import("std");
const types = @import("analyzer_types.zig");

const Opcode = types.Opcode;
const Finding = types.Finding;
const Code = types.Code;

pub const StackEffect = struct {
    pops: i32,
    pushes: i32,
};

/// Static per-opcode stack effect (spec §8.1).
pub fn stackEffect(op: Opcode) StackEffect {
    // Raw span — bypass via rawSpanArity.
    if (op.opcode == -1) {
        if (op.raw_span_arity) |arity| return .{ .pops = arity[0], .pushes = arity[1] };
        return .{ .pops = 0, .pushes = 0 };
    }
    // Pushes (all forms) = (0, 1).
    if (op.opcode >= 0x01 and op.opcode <= 0x4e) return .{ .pops = 0, .pushes = 1 };
    if (op.opcode == 0x00 or op.opcode == 0x4f or (op.opcode >= 0x51 and op.opcode <= 0x60)) {
        return .{ .pops = 0, .pushes = 1 };
    }
    return switch (op.opcode) {
        0x61 => .{ .pops = 0, .pushes = 0 }, // OP_NOP
        0x63 => .{ .pops = 1, .pushes = 0 }, // OP_IF
        0x64 => .{ .pops = 1, .pushes = 0 }, // OP_NOTIF
        0x67 => .{ .pops = 0, .pushes = 0 }, // OP_ELSE
        0x68 => .{ .pops = 0, .pushes = 0 }, // OP_ENDIF
        0x69 => .{ .pops = 1, .pushes = 0 }, // OP_VERIFY
        0x6a => .{ .pops = 0, .pushes = 0 }, // OP_RETURN
        0x6b => .{ .pops = 1, .pushes = 0 }, // OP_TOALTSTACK
        0x6c => .{ .pops = 0, .pushes = 1 }, // OP_FROMALTSTACK
        0x6d => .{ .pops = 2, .pushes = 0 }, // OP_2DROP
        0x6e => .{ .pops = 2, .pushes = 4 }, // OP_2DUP
        0x6f => .{ .pops = 3, .pushes = 6 }, // OP_3DUP
        0x70 => .{ .pops = 4, .pushes = 6 }, // OP_2OVER
        0x71 => .{ .pops = 6, .pushes = 6 }, // OP_2ROT
        0x72 => .{ .pops = 4, .pushes = 4 }, // OP_2SWAP
        0x73 => .{ .pops = 1, .pushes = 1 }, // OP_IFDUP
        0x74 => .{ .pops = 0, .pushes = 1 }, // OP_DEPTH
        0x75 => .{ .pops = 1, .pushes = 0 }, // OP_DROP
        0x76 => .{ .pops = 1, .pushes = 2 }, // OP_DUP
        0x77 => .{ .pops = 2, .pushes = 1 }, // OP_NIP
        0x78 => .{ .pops = 2, .pushes = 3 }, // OP_OVER
        0x79 => .{ .pops = 1, .pushes = 1 }, // OP_PICK
        0x7a => .{ .pops = 1, .pushes = 0 }, // OP_ROLL
        0x7b => .{ .pops = 3, .pushes = 3 }, // OP_ROT
        0x7c => .{ .pops = 2, .pushes = 2 }, // OP_SWAP
        0x7d => .{ .pops = 2, .pushes = 3 }, // OP_TUCK
        0x7e => .{ .pops = 2, .pushes = 1 }, // OP_CAT
        0x7f => .{ .pops = 2, .pushes = 2 }, // OP_SPLIT
        0x80 => .{ .pops = 2, .pushes = 1 }, // OP_NUM2BIN
        0x81 => .{ .pops = 1, .pushes = 1 }, // OP_BIN2NUM
        0x82 => .{ .pops = 1, .pushes = 2 }, // OP_SIZE
        0x83 => .{ .pops = 1, .pushes = 1 }, // OP_INVERT
        0x84 => .{ .pops = 2, .pushes = 1 }, // OP_AND
        0x85 => .{ .pops = 2, .pushes = 1 }, // OP_OR
        0x86 => .{ .pops = 2, .pushes = 1 }, // OP_XOR
        0x87 => .{ .pops = 2, .pushes = 1 }, // OP_EQUAL
        0x88 => .{ .pops = 2, .pushes = 0 }, // OP_EQUALVERIFY
        0x8b => .{ .pops = 1, .pushes = 1 }, // OP_1ADD
        0x8c => .{ .pops = 1, .pushes = 1 }, // OP_1SUB
        0x8f => .{ .pops = 1, .pushes = 1 }, // OP_NEGATE
        0x90 => .{ .pops = 1, .pushes = 1 }, // OP_ABS
        0x91 => .{ .pops = 1, .pushes = 1 }, // OP_NOT
        0x92 => .{ .pops = 1, .pushes = 1 }, // OP_0NOTEQUAL
        0x93 => .{ .pops = 2, .pushes = 1 }, // OP_ADD
        0x94 => .{ .pops = 2, .pushes = 1 }, // OP_SUB
        0x95 => .{ .pops = 2, .pushes = 1 }, // OP_MUL
        0x96 => .{ .pops = 2, .pushes = 1 }, // OP_DIV
        0x97 => .{ .pops = 2, .pushes = 1 }, // OP_MOD
        0x98 => .{ .pops = 2, .pushes = 1 }, // OP_LSHIFT
        0x99 => .{ .pops = 2, .pushes = 1 }, // OP_RSHIFT
        0x9a => .{ .pops = 2, .pushes = 1 }, // OP_BOOLAND
        0x9b => .{ .pops = 2, .pushes = 1 }, // OP_BOOLOR
        0x9c => .{ .pops = 2, .pushes = 1 }, // OP_NUMEQUAL
        0x9d => .{ .pops = 2, .pushes = 0 }, // OP_NUMEQUALVERIFY
        0x9e => .{ .pops = 2, .pushes = 1 }, // OP_NUMNOTEQUAL
        0x9f => .{ .pops = 2, .pushes = 1 }, // OP_LESSTHAN
        0xa0 => .{ .pops = 2, .pushes = 1 }, // OP_GREATERTHAN
        0xa1 => .{ .pops = 2, .pushes = 1 }, // OP_LESSTHANOREQUAL
        0xa2 => .{ .pops = 2, .pushes = 1 }, // OP_GREATERTHANOREQUAL
        0xa3 => .{ .pops = 2, .pushes = 1 }, // OP_MIN
        0xa4 => .{ .pops = 2, .pushes = 1 }, // OP_MAX
        0xa5 => .{ .pops = 3, .pushes = 1 }, // OP_WITHIN
        0xa6 => .{ .pops = 1, .pushes = 1 }, // OP_RIPEMD160
        0xa7 => .{ .pops = 1, .pushes = 1 }, // OP_SHA1
        0xa8 => .{ .pops = 1, .pushes = 1 }, // OP_SHA256
        0xa9 => .{ .pops = 1, .pushes = 1 }, // OP_HASH160
        0xaa => .{ .pops = 1, .pushes = 1 }, // OP_HASH256
        0xac => .{ .pops = 2, .pushes = 1 }, // OP_CHECKSIG
        0xad => .{ .pops = 2, .pushes = 0 }, // OP_CHECKSIGVERIFY
        0xae => .{ .pops = 3, .pushes = 1 }, // OP_CHECKMULTISIG
        0xaf => .{ .pops = 3, .pushes = 0 }, // OP_CHECKMULTISIGVERIFY
        else => .{ .pops = 0, .pushes = 0 },
    };
}

pub const LinearResult = struct {
    depth: i64,
    max_depth: i64,
    findings: []Finding,

    pub fn deinit(self: LinearResult, allocator: std.mem.Allocator) void {
        for (self.findings) |f| f.deinit(allocator);
        allocator.free(self.findings);
    }
};

/// Linear analysis (spec §8.2). Caller owns returned findings.
pub fn analyzeStackLinear(
    allocator: std.mem.Allocator,
    ops: []const Opcode,
    initial_depth: i64,
) !LinearResult {
    var findings = std.ArrayList(Finding).empty;
    errdefer {
        for (findings.items) |f| f.deinit(allocator);
        findings.deinit(allocator);
    }

    var depth: i64 = initial_depth;
    var max_depth: i64 = initial_depth;
    var after_return: bool = false;

    for (ops) |op| {
        if (after_return) {
            const opname = try allocator.dupe(u8, op.name);
            errdefer allocator.free(opname);
            const msg = try std.fmt.allocPrint(allocator, "Unreachable opcode {s} after OP_RETURN", .{op.name});
            try findings.append(allocator, Finding{
                .severity = Code.UNREACHABLE_AFTER_RETURN.severity(),
                .code = .UNREACHABLE_AFTER_RETURN,
                .message = msg,
                .offset = op.offset,
                .opcode = opname,
            });
            continue;
        }
        if (op.opcode == 0x6a) {
            after_return = true;
            continue;
        }
        const eff = stackEffect(op);
        // Spec §8.2 step 4: only flag underflow when initial_depth > 0.
        if (initial_depth > 0 and depth < eff.pops) {
            const opname = try allocator.dupe(u8, op.name);
            errdefer allocator.free(opname);
            const msg = try std.fmt.allocPrint(
                allocator,
                "{s} requires {d} stack item(s) but only {d} available",
                .{ op.name, eff.pops, depth },
            );
            try findings.append(allocator, Finding{
                .severity = Code.STACK_UNDERFLOW.severity(),
                .code = .STACK_UNDERFLOW,
                .message = msg,
                .offset = op.offset,
                .opcode = opname,
            });
        }
        depth = depth - eff.pops + eff.pushes;
        if (depth > max_depth) max_depth = depth;
    }

    return LinearResult{
        .depth = depth,
        .max_depth = max_depth,
        .findings = try findings.toOwnedSlice(allocator),
    };
}

test "stackEffect for common opcodes" {
    const a = std.testing.allocator;
    const name_dup = try a.dupe(u8, "OP_DUP");
    defer a.free(name_dup);
    const op = Opcode{ .opcode = 0x76, .name = name_dup, .offset = 0, .size = 1 };
    const e = stackEffect(op);
    try std.testing.expectEqual(@as(i32, 1), e.pops);
    try std.testing.expectEqual(@as(i32, 2), e.pushes);
}

test "linear analysis from depth 0 ignores underflow" {
    const a = std.testing.allocator;
    // OP_DUP from depth 0: pops 1 but initial_depth=0, no underflow finding.
    const dup_name = try a.dupe(u8, "OP_DUP");
    var ops = [_]Opcode{
        Opcode{ .opcode = 0x76, .name = dup_name, .offset = 0, .size = 1 },
    };
    defer for (ops) |op| op.deinit(a);
    const r = try analyzeStackLinear(a, &ops, 0);
    defer r.deinit(a);
    try std.testing.expectEqual(@as(usize, 0), r.findings.len);
    try std.testing.expectEqual(@as(i64, 1), r.depth);
}
