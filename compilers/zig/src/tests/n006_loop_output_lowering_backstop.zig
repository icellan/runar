//! N-006 / CL-BUG-186 — the pass-4 backstop behind R-127.
//!
//! R-127 is a syntactic search in `passes/validate.zig`. ANF lowering is
//! reachable without it (`anf_lower.lowerToANF` is public), and
//! `lowerForStatement` used to drop the body sub-context's output refs without
//! a word: the loop's outputs were built but left out of the continuation hash,
//! so a spender could drop them (proven on @bsv/sdk Spend for the TS and Go
//! tiers in
//! packages/runar-testing/src/__tests__/f005-go-loop-output-continuation.test.ts).
//!
//! What this proves: this tier's pass 4 refuses a loop whose body registered
//! an output ref, with `OutputIntrinsicInLoop` and R-127's shared diagnostic,
//! whatever let the contract past validation; a loop with no output in it
//! still lowers.
//! What it does not prove: anything about emitted bytes.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const typecheck = @import("../passes/typecheck.zig");
const anf_lower = @import("../passes/anf_lower.zig");

const head =
    \\import { StatefulSmartContract, ByteString, assert, num2bin } from 'runar-lang';
    \\
    \\class Fan extends StatefulSmartContract {
    \\  count: bigint;
    \\
    \\  constructor(count: bigint) {
    \\    super(count);
    \\    this.count = count;
    \\  }
    \\
;

/// Parse + typecheck + lower, deliberately skipping validation. Returns the
/// refusal diagnostic, or null when lowering accepted the contract.
fn lowerUnvalidated(alloc: std.mem.Allocator, method: []const u8) !?[]const u8 {
    const source = try std.mem.concat(alloc, u8, &.{ head, method, "\n}\n" });
    const parsed = parse_ts.parseTs(alloc, source, "Fan.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    const contract = parsed.contract orelse return error.TestUnexpectedResult;
    const tc = try typecheck.typeCheck(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), tc.errors.len);

    var diag: anf_lower.LowerDiagnostic = .{};
    if (anf_lower.lowerToANFWithDiagnostic(alloc, tc.contract, &diag)) |_| {
        return null;
    } else |err| {
        try std.testing.expectEqual(anf_lower.LowerError.OutputIntrinsicInLoop, err);
        return diag.message orelse error.TestExpectedDiagnostic;
    }
}

fn expectRefusal(alloc: std.mem.Allocator, method: []const u8, needle: []const u8) !void {
    const message = (try lowerUnvalidated(alloc, method)) orelse {
        std.debug.print("lowering accepted an output intrinsic inside a loop body\n", .{});
        return error.TestExpectedRefusal;
    };
    if (std.mem.indexOf(u8, message, needle) == null) {
        std.debug.print("not the R-127 diagnostic: {s}\n", .{message});
        return error.TestUnexpectedDiagnostic;
    }
}

test "N-006: addRawOutput hidden in an array literal in a loop body is refused at lowering" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try expectRefusal(arena.allocator(),
        \\  public fan(n: bigint) {
        \\    this.addOutput(1000n, this.count + 1n);
        \\    for (let i = 0n; i < 2n; i++) {
        \\      const xs = [this.addRawOutput(n, num2bin(i, 4n))];
        \\    }
        \\  }
    , "Output intrinsic 'addRawOutput' cannot be called inside a loop body.");
}

test "N-006: addOutput and addDataOutput in a loop body are refused at lowering" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try expectRefusal(arena.allocator(),
        \\  public fan(n: bigint) {
        \\    this.addOutput(1000n, this.count);
        \\    for (let i = 0n; i < 2n; i++) {
        \\      this.addOutput(1000n, this.count + i);
        \\    }
        \\    assert(n > 0n);
        \\  }
    , "Output intrinsic 'addOutput' cannot be called inside a loop body.");
    try expectRefusal(arena.allocator(),
        \\  public fan(n: bigint) {
        \\    for (let i = 0n; i < 2n; i++) {
        \\      if (i < n) {
        \\        this.addDataOutput(0n, num2bin(i, 4n));
        \\      }
        \\    }
        \\    this.count = this.count + 1n;
        \\  }
    , "Output intrinsic 'addDataOutput' cannot be called inside a loop body.");
}

test "N-006 control: a loop with no output intrinsic still lowers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const refusal = try lowerUnvalidated(arena.allocator(),
        \\  public fan(n: bigint) {
        \\    let acc: bigint = 0n;
        \\    for (let i = 0n; i < 2n; i++) {
        \\      acc = acc + n;
        \\    }
        \\    this.addOutput(1000n, this.count + acc);
        \\  }
    );
    try std.testing.expectEqual(@as(?[]const u8, null), refusal);
}
