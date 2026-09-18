//! R-189 — a private method may shadow a builtin, and nothing upstream of ANF
//! lowering notices when the two disagree about arity.
//!
//! Typecheck resolves a BARE-IDENTIFIER call against the builtin table BEFORE
//! it looks at the contract's own methods; ANF lowering resolves the same call
//! against private methods FIRST. So `min(x, y)` against
//! `private min(a, b, c)` type-checks as the two-argument BUILTIN `min` and
//! then lowers as the three-parameter METHOD `min`. No validator forbids the
//! shadowing.
//!
//! The zip that bound params to args stopped at `@min(params.len, args.len)`.
//! When the surplus parameter was never read the contract compiled CLEAN — an
//! arity mismatch silently accepted. When it was read, the defect surfaced two
//! passes later as "method parameter 'c' is not on the stack", a stack
//! lowering message about a pass the author never wrote in.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const validate = @import("../passes/validate.zig");
const typecheck = @import("../passes/typecheck.zig");
const anf_lower = @import("../passes/anf_lower.zig");
const types = @import("../ir/types.zig");

/// The silent case: `c` is never read, so nothing downstream ever noticed.
const surplus_param_unread =
    \\import { StatefulSmartContract } from 'runar-lang';
    \\
    \\export class R189Unread extends StatefulSmartContract {
    \\  count: bigint;
    \\
    \\  constructor(count: bigint) {
    \\    super(count);
    \\    this.count = count;
    \\  }
    \\
    \\  private min(a: bigint, b: bigint, c: bigint): bigint {
    \\    this.count = a + b;
    \\    this.addOutput(1000n, this.count);
    \\    return a;
    \\  }
    \\
    \\  public go(x: bigint, y: bigint) {
    \\    min(x, y);
    \\  }
    \\}
    \\
;

/// Too many arguments: `y` was evaluated and then dropped on the floor.
const too_many_args =
    \\import { StatefulSmartContract } from 'runar-lang';
    \\
    \\export class R189Extra extends StatefulSmartContract {
    \\  count: bigint;
    \\
    \\  constructor(count: bigint) {
    \\    super(count);
    \\    this.count = count;
    \\  }
    \\
    \\  private min(a: bigint): bigint {
    \\    this.count = a;
    \\    this.addOutput(1000n, this.count);
    \\    return a;
    \\  }
    \\
    \\  public go(x: bigint, y: bigint) {
    \\    min(x, y);
    \\  }
    \\}
    \\
;

/// Control 1: the SAME builtin-shadowing private, called at its real arity
/// through `this.` — the bare form cannot reach pass 4 at arity 3, because
/// pass 3 checks it against the two-argument BUILTIN `min` and refuses.
const control_shadowing_at_real_arity =
    \\import { StatefulSmartContract } from 'runar-lang';
    \\
    \\export class R189ControlShadow extends StatefulSmartContract {
    \\  count: bigint;
    \\
    \\  constructor(count: bigint) {
    \\    super(count);
    \\    this.count = count;
    \\  }
    \\
    \\  private min(a: bigint, b: bigint, c: bigint): bigint {
    \\    this.count = a + b + c;
    \\    this.addOutput(1000n, this.count);
    \\    return a;
    \\  }
    \\
    \\  public go(x: bigint, y: bigint, z: bigint) {
    \\    this.min(x, y, z);
    \\  }
    \\}
    \\
;

/// Control 2: an ordinary private helper, bare-identifier call at matching
/// arity — the Move / Go-DSL lowering path this refusal sits directly on.
/// Without the controls, a refusal that simply rejected every private call
/// would pass both refusal tests above.
const control_plain_private =
    \\import { StatefulSmartContract } from 'runar-lang';
    \\
    \\export class R189ControlPlain extends StatefulSmartContract {
    \\  count: bigint;
    \\
    \\  constructor(count: bigint) {
    \\    super(count);
    \\    this.count = count;
    \\  }
    \\
    \\  private tally(a: bigint, b: bigint): bigint {
    \\    this.count = a + b;
    \\    this.addOutput(1000n, this.count);
    \\    return a;
    \\  }
    \\
    \\  public go(x: bigint, y: bigint) {
    \\    tally(x, y);
    \\  }
    \\}
    \\
;

/// Parse + validate + typecheck, returning the contract ready for pass 4. The
/// zero-error assertions are load-bearing: they are what proves the mismatch
/// really does reach ANF lowering rather than being caught upstream.
fn frontend(alloc: std.mem.Allocator, source: []const u8) !types.ContractNode {
    const parsed = parse_ts.parseTs(alloc, source, "R189.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    const contract = parsed.contract orelse return error.TestUnexpectedResult;

    const val_result = try validate.validate(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), val_result.errors.len);

    const tc_result = try typecheck.typeCheck(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), tc_result.errors.len);

    return tc_result.contract;
}

test "a private call with a surplus parameter is refused, naming both counts" {
    const cases = [_]struct { source: []const u8, params: []const u8 }{
        .{ .source = surplus_param_unread, .params = "3" },
        .{ .source = too_many_args, .params = "1" },
    };
    for (cases) |tc| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const contract = try frontend(alloc, tc.source);

        var diag: anf_lower.LowerDiagnostic = .{};
        const result = anf_lower.lowerToANFWithDiagnostic(alloc, contract, &diag);
        try std.testing.expectError(anf_lower.LowerError.PrivateCallArityMismatch, result);

        const message = diag.message orelse return error.TestExpectedDiagnostic;
        try std.testing.expect(std.mem.indexOf(u8, message, "private method 'min'") != null);
        try std.testing.expect(std.mem.indexOf(u8, message, tc.params) != null);
        try std.testing.expect(std.mem.indexOf(u8, message, "got 2") != null);
    }
}

test "a private call at its real arity still lowers" {
    const sources = [_][]const u8{ control_shadowing_at_real_arity, control_plain_private };
    for (sources) |source| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const contract = try frontend(alloc, source);

        var diag: anf_lower.LowerDiagnostic = .{};
        _ = try anf_lower.lowerToANFWithDiagnostic(alloc, contract, &diag);
    }
}
