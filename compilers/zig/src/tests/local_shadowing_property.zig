//! A local variable that shadows a contract property must be lowered as a
//! LOCAL, not as a property write.
//!
//! Zig's surface parsers strip `this.` before building `Assign`, so the AST
//! carries a bare target name. `anf_lower.zig` resolved that name by asking
//! `isProperty` FIRST and `isLocal` second, so in
//!
//!     let limit = 1n;      // local, shadows the property
//!     limit = n + 2n;      // plain local rebind
//!
//! the rebind lowered to `update_prop limit` — a write to the contract
//! property. The READ path (`lowerIdentifier`) asks `isLocal` first, so the
//! subsequent `limit > 0n` read the local. Write to the property, read from
//! the local: incoherent within the tier, and a cross-tier byte divergence.
//!
//! Measured on the source below with folding disabled:
//!
//!     ts   517c529300a0697600a077
//!     go   517c529300a0697600a077
//!     zig  517c52937700a0690000a0     <- outlier
//!
//! For a stateful contract the same defect writes an attacker-influenced
//! value into the state continuation, so it is not merely cosmetic.
//!
//! Fixed by keying the assignment on `Assign.target_is_property`, the field
//! the C2 readonly-write work added and every Zig surface parser populates.

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

/// The cross-tier hex every tier emits for `SHADOW_SRC` with constant folding
/// disabled.
///
/// N-016: this used to be `517c529300a0697600a077`, which TS and Go agreed on
/// and which was itself wrong — its tail `76 00 a0` read `this.limit` as an
/// OP_DUP of the LOCAL `limit` still on the stack, so `assert(this.limit > 0n)`
/// checked the local. The property read now pushes the constructor-slot
/// placeholder (`00 00 a0`). The part this test is about — the rebind stays a
/// local write (`51 7c 52 93 00 a0 69`) — is unchanged.
const CROSS_TIER_HEX = "517c529300a0690000a077";

/// What the tier emitted while the write resolved to the property.
const BUGGY_HEX = "517c52937700a0690000a0";

const SHADOW_SRC =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\export class Shadow extends SmartContract {
    \\  readonly limit: bigint;
    \\
    \\  constructor(limit: bigint) {
    \\    super(limit);
    \\    this.limit = limit;
    \\  }
    \\
    \\  public spend(n: bigint): void {
    \\    let limit = 1n;
    \\    limit = n + 2n;
    \\    assert(limit > 0n);
    \\    assert(this.limit > 0n);
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

/// Fold-OFF pipeline, matching the `--disable-constant-folding` CLI mode the
/// cross-tier hex above was measured under.
fn compileNoFold(alloc: std.mem.Allocator, source: []const u8) ![]const u8 {
    const parsed = parse_ts.parseTs(alloc, source, "Shadow.runar.ts");
    if (parsed.errors.len > 0) return error.ParseFailed;
    const contract = parsed.contract orelse return error.ParseFailed;
    const val = try validate.validate(alloc, contract);
    if (val.errors.len > 0) return error.ValidateFailed;
    const tc = try typecheck.typeCheck(alloc, contract);
    if (tc.errors.len > 0) return error.TypeCheckFailed;
    const expanded = try expand_fixed_arrays.expand(alloc, contract);
    if (expanded.errors.len > 0) return error.ExpandFailed;
    const program = try anf_lower.lowerToANF(alloc, expanded.contract);
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

test "local shadowing a property is a local, not a property write" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const hex = try compileNoFold(alloc, SHADOW_SRC);

    try std.testing.expect(!std.mem.eql(u8, hex, BUGGY_HEX));
    try std.testing.expectEqualStrings(CROSS_TIER_HEX, hex);
}

test "the shadowing rebind emits no update_prop" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const parsed = parse_ts.parseTs(alloc, SHADOW_SRC, "Shadow.runar.ts");
    const contract = parsed.contract orelse return error.ParseFailed;
    const expanded = try expand_fixed_arrays.expand(alloc, contract);
    const program = try anf_lower.lowerToANF(alloc, expanded.contract);

    // Scoped to `spend`. The CONSTRUCTOR legitimately emits `update_prop
    // limit` for its own `this.limit = limit`; that is the one property write
    // this contract is supposed to have. Inside `spend`, `limit` names the
    // local only, so any update_prop there is the rebind escaping into
    // contract state.
    var saw_spend = false;
    for (program.methods) |m| {
        if (!std.mem.eql(u8, m.name, "spend")) continue;
        saw_spend = true;
        for (m.bindings) |b| {
            try std.testing.expect(b.value != .update_prop);
        }
    }
    try std.testing.expect(saw_spend);
}
