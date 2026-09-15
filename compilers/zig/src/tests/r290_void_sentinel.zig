//! R-290 — `inlinePrivateMethodCall` used to emit a `load_const "@void"`
//! sentinel when the inlined body produced no bindings.
//!
//! No tier's stack lowering recognises `"@void"` (unlike `"@this"`, which IS
//! special-cased), so the sentinel survived pass 4 and died in the hex
//! decoder: Go said `invalid byte: U+0040 '@'`, Rust said
//! `invalid hex string length: 5`. Neither names the method or the problem,
//! and both fire only because the string happens to be odd-length and
//! non-hex — an even-length sentinel would decode to zeros in Rust's
//! `from_str_radix(..).unwrap_or(0)` and reach the script.
//!
//! In the Go / Rust / Python / TypeScript tiers it is REACHABLE: their
//! side-effect summary resolves a called name through a LAST-WINS map and
//! caches the result under that name, while `getPrivateMethod` returns the
//! FIRST match. Declare the public caller BEFORE two same-named privates and
//! the two disagree — the summary describes the output-emitting `helper`, so
//! inlining fires, while the lowerer inlines the EMPTY one. Measured on the Go
//! CLI pre-fix: `--emit-ir` exit 0 with "@void" in the IR.
//!
//! This tier is NOT reachable that way: `shouldInlinePrivate` asks
//! `lookupPrivateMethod` — the same first-match lookup the inliner uses — so
//! the two cannot disagree. The refusal still ships here, because the sentinel
//! must not exist in any tier and because the tiers' inline-decision paths have
//! drifted before. The tests below therefore pin the INVARIANT rather than the
//! refusal: whatever this tier does with that contract, no "@void" may survive
//! into the ANF. If a future change routes this tier's inline decision through
//! a summary map, the contract starts refusing and the first branch takes over.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const validate = @import("../passes/validate.zig");
const typecheck = @import("../passes/typecheck.zig");
const anf_lower = @import("../passes/anf_lower.zig");
const types = @import("../ir/types.zig");

const empty_inlined_body =
    \\import { StatefulSmartContract } from 'runar-lang';
    \\
    \\export class R290Void extends StatefulSmartContract {
    \\  count: bigint;
    \\
    \\  constructor(count: bigint) {
    \\    super(count);
    \\    this.count = count;
    \\  }
    \\
    \\  public go(x: bigint) {
    \\    this.count = x;
    \\    this.helper();
    \\  }
    \\
    \\  private helper(): void {
    \\  }
    \\
    \\  private helper(): void {
    \\    this.addOutput(1000n, this.count);
    \\  }
    \\}
    \\
;

/// Control: the ordinary shape — one private helper that really does emit an
/// output. The inlining path must still work; a refusal that simply rejected
/// every inlined private would pass the test above.
const control_emitting_helper =
    \\import { StatefulSmartContract } from 'runar-lang';
    \\
    \\export class R290Control extends StatefulSmartContract {
    \\  count: bigint;
    \\
    \\  constructor(count: bigint) {
    \\    super(count);
    \\    this.count = count;
    \\  }
    \\
    \\  public go(x: bigint) {
    \\    this.count = x;
    \\    this.helper();
    \\  }
    \\
    \\  private helper(): void {
    \\    this.addOutput(1000n, this.count);
    \\  }
    \\}
    \\
;

fn frontend(alloc: std.mem.Allocator, source: []const u8) !types.ContractNode {
    const parsed = parse_ts.parseTs(alloc, source, "R290.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    const contract = parsed.contract orelse return error.TestUnexpectedResult;

    const val_result = try validate.validate(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), val_result.errors.len);

    const tc_result = try typecheck.typeCheck(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), tc_result.errors.len);

    return tc_result.contract;
}

fn carriesVoidSentinel(bindings: []const types.ANFBinding) bool {
    for (bindings) |b| {
        switch (b.value) {
            .load_const => |lc| switch (lc.value) {
                .string => |s| if (std.mem.eql(u8, s, "@void")) return true,
                else => {},
            },
            .@"if" => |i| {
                if (carriesVoidSentinel(i.then)) return true;
                if (carriesVoidSentinel(i.@"else")) return true;
            },
            .loop => |l| if (carriesVoidSentinel(l.body)) return true,
            else => {},
        }
    }
    return false;
}

fn programCarriesVoidSentinel(program: types.ANFProgram) bool {
    for (program.methods) |m| {
        if (carriesVoidSentinel(m.body)) return true;
    }
    return false;
}

test "an empty inlined body never yields a @void sentinel" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const contract = try frontend(alloc, empty_inlined_body);

    var diag: anf_lower.LowerDiagnostic = .{};
    const result = anf_lower.lowerToANFWithDiagnostic(alloc, contract, &diag);

    if (result) |program| {
        try std.testing.expect(!programCarriesVoidSentinel(program));
    } else |err| {
        try std.testing.expectEqual(anf_lower.LowerError.EmptyInlinedPrivateBody, err);
        const message = diag.message orelse return error.TestExpectedDiagnostic;
        try std.testing.expect(
            std.mem.indexOf(u8, message, "was inlined but produced no bindings") != null,
        );
    }
}

test "an ordinary inlined helper carries no @void sentinel" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const contract = try frontend(alloc, control_emitting_helper);

    var diag: anf_lower.LowerDiagnostic = .{};
    const program = try anf_lower.lowerToANFWithDiagnostic(alloc, contract, &diag);
    try std.testing.expect(!programCarriesVoidSentinel(program));
}
