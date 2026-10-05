//! N-049 (EXT-2 "TernaryToll") — an output intrinsic inside a ternary arm.
//!
//! `lowerTernaryExpr` lowers each arm into a sub-context whose output refs are
//! dropped, unlike the if-statement lowering, which merges each arm's refs into
//! the parent. The continuation hash therefore omitted the arm's output:
//! measured on every tier, a spend that drops the payee output was accepted
//! and the honest spend rejected. Fail-closed like R-127: the validator refuses
//! an output intrinsic (direct, or through an inlined private helper) in either
//! arm with the shared N-049 diagnostic, and pass 4 refuses it again
//! (`OutputIntrinsicInTernaryArm`) when reached unvalidated.
//!
//! What this proves: this tier refuses the ternary-arm shapes at validation and
//! at lowering with the shared diagnostic, and still accepts and lowers a
//! ternary that only selects VALUES.
//! What it does not prove: anything about emitted bytes (the cross-tier control
//! is conformance/negatives/ternary-output-control.test.ts).

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const validate = @import("../passes/validate.zig");
const typecheck = @import("../passes/typecheck.zig");
const anf_lower = @import("../passes/anf_lower.zig");

const head =
    \\import { StatefulSmartContract, ByteString } from 'runar-lang';
    \\
    \\class ConditionalPayout extends StatefulSmartContract {
    \\  count: bigint;
    \\  readonly payee: ByteString;
    \\  readonly refund: ByteString;
    \\
    \\  constructor(count: bigint, payee: ByteString, refund: ByteString) {
    \\    super(count, payee, refund);
    \\    this.count = count;
    \\    this.payee = payee;
    \\    this.refund = refund;
    \\  }
    \\
;

const ternary_arms =
    \\  public release() {
    \\    this.addOutput(1000n, this.count);
    \\    this.count > 0n ? this.addRawOutput(50000n, this.payee)
    \\                    : this.addRawOutput(50000n, this.refund);
    \\  }
;

const value_selecting =
    \\  public release() {
    \\    this.addOutput(1000n, this.count);
    \\    this.addRawOutput(50000n, this.count > 0n ? this.payee : this.refund);
    \\  }
;

const refusal = "Output intrinsic 'addRawOutput' cannot be called inside a conditional (ternary) expression arm.";

fn parseContract(alloc: std.mem.Allocator, methods: []const u8) !@TypeOf(parse_ts.parseTs(alloc, "", "").contract.?) {
    const source = try std.mem.concat(alloc, u8, &.{ head, methods, "\n}\n" });
    const parsed = parse_ts.parseTs(alloc, source, "ConditionalPayout.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    return parsed.contract orelse error.TestUnexpectedResult;
}

fn validationErrors(alloc: std.mem.Allocator, methods: []const u8) ![]const u8 {
    const contract = try parseContract(alloc, methods);
    const val = try validate.validate(alloc, contract);
    var out: std.ArrayListUnmanaged(u8) = .empty;
    for (val.errors) |e| {
        try out.appendSlice(alloc, e.message);
        try out.append(alloc, '\n');
    }
    return out.items;
}

/// Parse + typecheck + lower, deliberately skipping validation. Returns the
/// refusal diagnostic, or null when lowering accepted the contract.
fn lowerUnvalidated(alloc: std.mem.Allocator, methods: []const u8) !?[]const u8 {
    const contract = try parseContract(alloc, methods);
    const tc = try typecheck.typeCheck(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), tc.errors.len);
    var diag: anf_lower.LowerDiagnostic = .{};
    if (anf_lower.lowerToANFWithDiagnostic(alloc, tc.contract, &diag)) |_| {
        return null;
    } else |err| {
        try std.testing.expectEqual(anf_lower.LowerError.OutputIntrinsicInTernaryArm, err);
        return diag.message orelse error.TestExpectedDiagnostic;
    }
}

test "N-049: validation refuses an output intrinsic in a ternary arm" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const errs = try validationErrors(arena.allocator(), ternary_arms);
    if (std.mem.indexOf(u8, errs, refusal) == null) {
        std.debug.print("not refused with the N-049 diagnostic: {s}\n", .{errs});
        return error.TestExpectedRefusal;
    }
}

test "N-049: validation refuses a helper-emitted output in a ternary arm" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const errs = try validationErrors(arena.allocator(),
        \\  public release() {
        \\    this.addOutput(1000n, this.count);
        \\    this.count > 0n ? this.payTo(this.payee) : this.payTo(this.refund);
        \\  }
        \\
        \\  private payTo(script: ByteString): void {
        \\    this.addRawOutput(50000n, script);
        \\  }
    );
    const want = "Output intrinsic 'addRawOutput' (reached through private method 'payTo') cannot be called inside a conditional (ternary) expression arm.";
    if (std.mem.indexOf(u8, errs, want) == null) {
        std.debug.print("not refused with the N-049 diagnostic: {s}\n", .{errs});
        return error.TestExpectedRefusal;
    }
}

test "N-049: lowering refuses a ternary-arm output without validation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const message = (try lowerUnvalidated(arena.allocator(), ternary_arms)) orelse {
        std.debug.print("lowering accepted an output intrinsic inside a ternary arm\n", .{});
        return error.TestExpectedRefusal;
    };
    if (std.mem.indexOf(u8, message, refusal) == null) {
        std.debug.print("not the N-049 diagnostic: {s}\n", .{message});
        return error.TestUnexpectedDiagnostic;
    }
}

test "N-049 control: a value-selecting ternary is still accepted and lowered" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("", try validationErrors(arena.allocator(), value_selecting));
    try std.testing.expectEqual(@as(?[]const u8, null), try lowerUnvalidated(arena.allocator(), value_selecting));
}
