//! N-007 -- a method parameter that shadows a MUTABLE property must stay the
//! parameter inside an `if` / ternary arm.
//!
//! Port of the TypeScript reference test
//! `packages/runar-compiler/src/__tests__/n007-param-shadow-branch-arm.test.ts`.
//!
//! Issue #130 (stack layer): deserialize_state pushes each mutable property
//! under its own name, so method lowering renames a same-named parameter's slot
//! to `__param_<name>` and records it in `renamed_params`; lowerLoadParam
//! resolves through that map.
//!
//! The defect: `stack_lower.zig`'s if-lowering built `then_ctx` / `else_ctx`
//! with `LowerCtx.init`, whose `renamed_params` starts EMPTY. The arm's cloned
//! stack still carries the `__param_<name>` slot, so a `load_param` inside the
//! arm resolved the bare name to the deserialized PROPERTY slot -- the stale
//! on-chain state -- instead of the caller's witness argument:
//!
//!   public set(count: bigint, flag: boolean) {
//!     if (flag) { assert(count == 5n); }     // arm read this.count (stale)
//!     this.count = count;
//!   }
//!
//! With on-chain count = 5, `set(7n, true)` passed a guard the source says must
//! fail. Real-engine proof:
//! packages/runar-testing/src/__tests__/n007-param-shadow-branch-arm-vm.test.ts.
//!
//! Oracle (needs no reference tier): a parameter's NAME is not part of the
//! program, so alpha-renaming `count` -> `newCount` must give byte-identical
//! script.
//!
//! Proves: Zig resolves a shadowing parameter to the same slot inside an
//! if-then arm, an if-else arm and a ternary arm as for a non-colliding name,
//! in both fold modes. Does NOT prove: that the renamed program is itself
//! correct on-chain (the VM test), or anything about other tiers.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const PRELUDE =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\class Probe extends StatefulSmartContract {
    \\  count: bigint;
    \\
    \\  constructor(count: bigint) { super(count); this.count = count; }
    \\
    \\
;

const THEN_ARM = PRELUDE ++
    \\  public set(count: bigint, flag: boolean) {
    \\    if (flag) {
    \\      assert(count == 5n);
    \\    }
    \\    this.count = count;
    \\  }
    \\}
    \\
;

const THEN_ARM_RENAMED = PRELUDE ++
    \\  public set(newCount: bigint, flag: boolean) {
    \\    if (flag) {
    \\      assert(newCount == 5n);
    \\    }
    \\    this.count = newCount;
    \\  }
    \\}
    \\
;

const ELSE_ARM = PRELUDE ++
    \\  public set(count: bigint, flag: boolean) {
    \\    if (flag) {
    \\      assert(flag);
    \\    } else {
    \\      assert(count > 10n);
    \\    }
    \\    this.count = count;
    \\  }
    \\}
    \\
;

const ELSE_ARM_RENAMED = PRELUDE ++
    \\  public set(newCount: bigint, flag: boolean) {
    \\    if (flag) {
    \\      assert(flag);
    \\    } else {
    \\      assert(newCount > 10n);
    \\    }
    \\    this.count = newCount;
    \\  }
    \\}
    \\
;

const TERNARY_ARM = PRELUDE ++
    \\  public set(count: bigint, flag: boolean) {
    \\    const v: bigint = flag ? count + 1n : 0n;
    \\    assert(v != 3n);
    \\    this.count = count;
    \\  }
    \\}
    \\
;

const TERNARY_ARM_RENAMED = PRELUDE ++
    \\  public set(newCount: bigint, flag: boolean) {
    \\    const v: bigint = flag ? newCount + 1n : 0n;
    \\    assert(v != 3n);
    \\    this.count = newCount;
    \\  }
    \\}
    \\
;

/// Control: the parameter is read only OUTSIDE any arm (already correct before
/// the fix; pins that the oracle is not vacuous).
const NO_ARM = PRELUDE ++
    \\  public set(count: bigint, flag: boolean) {
    \\    assert(count != 3n);
    \\    assert(flag);
    \\    this.count = count;
    \\  }
    \\}
    \\
;

const NO_ARM_RENAMED = PRELUDE ++
    \\  public set(newCount: bigint, flag: boolean) {
    \\    assert(newCount != 3n);
    \\    assert(flag);
    \\    this.count = newCount;
    \\  }
    \\}
    \\
;

const Case = struct { label: []const u8, shadowing: []const u8, renamed: []const u8 };

const CASES = [_]Case{
    .{ .label = "then-arm", .shadowing = THEN_ARM, .renamed = THEN_ARM_RENAMED },
    .{ .label = "else-arm", .shadowing = ELSE_ARM, .renamed = ELSE_ARM_RENAMED },
    .{ .label = "ternary-arm", .shadowing = TERNARY_ARM, .renamed = TERNARY_ARM_RENAMED },
    .{ .label = "control/no-arm", .shadowing = NO_ARM, .renamed = NO_ARM_RENAMED },
};

fn compileScriptHex(
    allocator: std.mem.Allocator,
    source: []const u8,
    disable_constant_folding: bool,
) ![]const u8 {
    const result = try compiler_api.compileSourceWithOptions(
        allocator,
        source,
        "Probe.runar.ts",
        disable_constant_folding,
    );
    if (result.artifact_json) |json| allocator.free(json);
    return result.script_hex;
}

test "N-007: a property-shadowing param read inside a branch arm compiles like the alpha-renamed program" {
    const allocator = std.testing.allocator;
    for (CASES) |tc| {
        for ([_]bool{ true, false }) |disable| {
            const got = try compileScriptHex(allocator, tc.shadowing, disable);
            defer allocator.free(got);
            const want = try compileScriptHex(allocator, tc.renamed, disable);
            defer allocator.free(want);
            std.testing.expectEqualStrings(want, got) catch |err| {
                std.debug.print(
                    "{s} (disable_constant_folding={}): a parameter that shadows mutable property 'count' compiled differently from the renamed program -- the arm read the deserialized state slot, not the witness argument\n",
                    .{ tc.label, disable },
                );
                return err;
            };
        }
    }
}
