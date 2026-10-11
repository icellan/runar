// Opcode concerns (spec §10): LARGE_SCRIPT, CODESEPARATOR_PRESENT,
// INEFFICIENT_PUSH.

const std = @import("std");
const types = @import("analyzer_types.zig");

const Opcode = types.Opcode;
const Finding = types.Finding;
const Code = types.Code;

const LARGE_SCRIPT_THRESHOLD: i64 = 500_000;

pub fn analyzeOpcodeConcerns(
    allocator: std.mem.Allocator,
    ops: []const Opcode,
    script_size_bytes: i64,
) ![]Finding {
    var findings = std.ArrayList(Finding).empty;
    errdefer {
        for (findings.items) |f| f.deinit(allocator);
        findings.deinit(allocator);
    }

    if (script_size_bytes > LARGE_SCRIPT_THRESHOLD) {
        const kb_str = try formatToFixed1(allocator, script_size_bytes);
        defer allocator.free(kb_str);
        const msg = try std.fmt.allocPrint(
            allocator,
            "Script is {d} bytes ({s} KB) — consider if this is intentional",
            .{ script_size_bytes, kb_str },
        );
        try findings.append(allocator, Finding{
            .severity = Code.LARGE_SCRIPT.severity(),
            .code = .LARGE_SCRIPT,
            .message = msg,
        });
    }

    for (ops) |op| {
        if (op.opcode == 0xab) {
            const msg = try allocator.dupe(u8, "OP_CODESEPARATOR found — expected for stateful contracts, unusual otherwise");
            try findings.append(allocator, Finding{
                .severity = Code.CODESEPARATOR_PRESENT.severity(),
                .code = .CODESEPARATOR_PRESENT,
                .message = msg,
                .offset = op.offset,
                .opcode = try allocator.dupe(u8, op.name),
            });
        }
        // INEFFICIENT_PUSH per §6.2.
        if (op.data_length) |dl| {
            const dlu: u64 = @intCast(dl);
            switch (op.push_encoding) {
                .pushdata1 => if (dlu <= 75) {
                    const msg = try std.fmt.allocPrint(
                        allocator,
                        "OP_PUSHDATA1 used for {d}-byte data — direct push (opcode 0x{x:0>2}) would be more efficient",
                        .{ dl, dlu },
                    );
                    try findings.append(allocator, Finding{
                        .severity = Code.INEFFICIENT_PUSH.severity(),
                        .code = .INEFFICIENT_PUSH,
                        .message = msg,
                        .offset = op.offset,
                        .opcode = try allocator.dupe(u8, op.name),
                    });
                },
                .pushdata2 => if (dlu <= 255) {
                    const msg = try std.fmt.allocPrint(
                        allocator,
                        "OP_PUSHDATA2 used for {d}-byte data — OP_PUSHDATA1 would be more efficient",
                        .{dl},
                    );
                    try findings.append(allocator, Finding{
                        .severity = Code.INEFFICIENT_PUSH.severity(),
                        .code = .INEFFICIENT_PUSH,
                        .message = msg,
                        .offset = op.offset,
                        .opcode = try allocator.dupe(u8, op.name),
                    });
                },
                .pushdata4 => if (dlu <= 65535) {
                    const msg = try std.fmt.allocPrint(
                        allocator,
                        "OP_PUSHDATA4 used for {d}-byte data — OP_PUSHDATA2 would be more efficient",
                        .{dl},
                    );
                    try findings.append(allocator, Finding{
                        .severity = Code.INEFFICIENT_PUSH.severity(),
                        .code = .INEFFICIENT_PUSH,
                        .message = msg,
                        .offset = op.offset,
                        .opcode = try allocator.dupe(u8, op.name),
                    });
                },
                else => {},
            }
        }
    }
    return try findings.toOwnedSlice(allocator);
}

/// Format `n / 1024` as JS `(n/1024).toFixed(1)` does.
///
/// Per ECMA-262, toFixed picks the integer k for which k/10 - value is
/// closest to zero, and on an exact tie picks the LARGER k —
/// round-half-up (ties away from zero for our non-negative n), not
/// IEEE-754 round-half-to-even. Verified live:
/// `node -e "console.log((500992/1024).toFixed(1))"` prints "489.3",
/// where round-half-to-even would give "489.2".
/// Spec §5.1: k = round_half_up(n * 10 / 1024) / 10.
/// Returns owned string like "1.0", "1.5", "851.8".
pub fn formatToFixed1(allocator: std.mem.Allocator, n: i64) ![]u8 {
    const numerator: i64 = n * 10;
    const denom: i64 = 1024;
    const q = @divTrunc(numerator, denom);
    const r = numerator - q * denom;
    // r in [0, denom) for non-negative n.
    const twice_r = r * 2;
    var k: i64 = q;
    if (twice_r >= denom) {
        k += 1;
    }
    const whole = @divTrunc(k, 10);
    const frac_signed = k - whole * 10;
    const frac: u64 = @intCast(if (frac_signed < 0) -frac_signed else frac_signed);
    return try std.fmt.allocPrint(allocator, "{d}.{d}", .{ whole, frac });
}

test "formatToFixed1 matches JS toFixed semantics" {
    const a = std.testing.allocator;
    {
        const s = try formatToFixed1(a, 1024);
        defer a.free(s);
        try std.testing.expectEqualStrings("1.0", s);
    }
    {
        const s = try formatToFixed1(a, 1500);
        defer a.free(s);
        try std.testing.expectEqualStrings("1.5", s);
    }
    {
        const s = try formatToFixed1(a, 872248);
        defer a.free(s);
        try std.testing.expectEqualStrings("851.8", s);
    }
    {
        const s = try formatToFixed1(a, 1328100);
        defer a.free(s);
        try std.testing.expectEqualStrings("1297.0", s);
    }
}

test "formatToFixed1 breaks ties like JS, not half-to-even" {
    // 500992/1024 = 489.25 exactly (1024 is a power of two, so the
    // division has no rounding error). Scaled by 10 that is 4892.5 — an
    // exact tie at the tenths digit. JS Number.prototype.toFixed(1) picks
    // the LARGER candidate on a tie (verified live: node -e
    // "console.log((500992/1024).toFixed(1))" -> "489.3"), not the even
    // one (round-half-to-even would give "489.2", since 4892 is even).
    const a = std.testing.allocator;
    const s = try formatToFixed1(a, 500992);
    defer a.free(s);
    try std.testing.expectEqualStrings("489.3", s);
}

test "formatToFixed1 does not move existing analyzer goldens" {
    // Pins the two LARGE_SCRIPT conformance goldens
    // (conformance/analyzer/{ec-demo,schnorr-zkp}) so the tie-rounding
    // fix above is proven not to move them — neither size lands on an
    // exact .5 tie at the tenths digit.
    const a = std.testing.allocator;
    {
        const s = try formatToFixed1(a, 1337343);
        defer a.free(s);
        try std.testing.expectEqualStrings("1306.0", s);
    }
    {
        const s = try formatToFixed1(a, 877253);
        defer a.free(s);
        try std.testing.expectEqualStrings("856.7", s);
    }
}
