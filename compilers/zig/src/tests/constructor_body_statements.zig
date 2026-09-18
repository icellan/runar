//! R-040 — constructor-body statements must survive parsing in every format.
//!
//! Six of the nine surfaces carry an explicit constructor body the author
//! writes by hand: `.runar.ts`, `.runar.sol`, `.runar.py`, `.runar.rb`,
//! `.runar.java` and the `.runar.zig` `init()`. The Zig parsers for all six
//! reduced that body to two things — the `super(...)` argument list and the
//! plain `this.x = param` field assignments — and dropped everything else on
//! the floor with no diagnostic.
//!
//! The other six tiers keep the whole body: TS lowers
//! `contract.constructor.body` statement by statement, and Go / Rust / Python
//! / Ruby / Java each mirror that. So an `assert(...)` written in a
//! constructor appears in six tiers' constructor ANF and in none of Zig's:
//!
//!   ts go rust python ruby java   load_prop call load_prop load_const
//!                                 bin_op assert load_prop update_prop
//!   zig                           load_prop call load_prop update_prop
//!
//! measured on a probe contract in each of the six formats. CLAUDE.md makes
//! frontend parity a no-exceptions invariant, and the ANF IR is compared
//! byte-for-byte across tiers by the conformance suite, so the six-tier
//! majority is the contract Zig has to join: HONOUR the statements.
//!
//! The script hex is unaffected in every tier — the constructor body is not
//! stack-lowered — which is precisely why the divergence went unnoticed: it
//! lives only in the ANF IR, and no fixture exercised it.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const types = @import("../ir/types.zig");

// --- probes: `super(...)`, an assert on a constructor argument, the assignment

const TS_ASSERT =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\class ProbeAssert extends SmartContract {
    \\  readonly target: bigint;
    \\
    \\  constructor(target: bigint) {
    \\    super(target);
    \\    assert(target > 0n);
    \\    this.target = target;
    \\  }
    \\
    \\  public verify(a: bigint): void {
    \\    assert(a === this.target);
    \\  }
    \\}
;

const SOL_ASSERT =
    \\pragma runar ^0.1.0;
    \\
    \\contract ProbeAssert is SmartContract {
    \\    int immutable target;
    \\
    \\    constructor(int _target) {
    \\        require(_target > 0);
    \\        target = _target;
    \\    }
    \\
    \\    function verify(int a) public {
    \\        require(a == target);
    \\    }
    \\}
;

const PY_ASSERT =
    \\from runar import SmartContract, Bigint, public, assert_
    \\
    \\
    \\class ProbeAssert(SmartContract):
    \\    target: Bigint
    \\
    \\    def __init__(self, target: Bigint):
    \\        super().__init__(target)
    \\        assert_(target > 0)
    \\        self.target = target
    \\
    \\    @public
    \\    def verify(self, a: Bigint):
    \\        assert_(a == self.target)
;

const RB_ASSERT =
    \\require 'runar'
    \\
    \\class ProbeAssert < Runar::SmartContract
    \\  prop :target, Bigint
    \\
    \\  def initialize(target)
    \\    super(target)
    \\    assert target > 0
    \\    @target = target
    \\  end
    \\
    \\  runar_public a: Bigint
    \\  def verify(a)
    \\    assert a == @target
    \\  end
    \\end
;

const JAVA_ASSERT =
    \\package probe;
    \\
    \\import runar.lang.SmartContract;
    \\import runar.lang.annotations.Public;
    \\import runar.lang.annotations.Readonly;
    \\import runar.lang.types.Bigint;
    \\
    \\import static runar.lang.Builtins.assertThat;
    \\
    \\class ProbeAssert extends SmartContract {
    \\
    \\    @Readonly Bigint target;
    \\
    \\    ProbeAssert(Bigint target) {
    \\        super(target);
    \\        assertThat(target.gt(Bigint.of(0)));
    \\        this.target = target;
    \\    }
    \\
    \\    @Public
    \\    void verify(Bigint a) {
    \\        assertThat(a.eq(this.target));
    \\    }
    \\}
;

const ZIG_ASSERT =
    \\const runar = @import("runar");
    \\
    \\pub const ProbeAssert = struct {
    \\    pub const Contract = runar.SmartContract;
    \\
    \\    target: i64,
    \\
    \\    pub fn init(target: i64) ProbeAssert {
    \\        runar.assert(target > 0);
    \\        return .{ .target = target };
    \\    }
    \\
    \\    pub fn verify(self: *const ProbeAssert, a: i64) void {
    \\        runar.assert(a == self.target);
    \\    }
    \\};
;

/// The control: the same contract with an ordinary constructor body — nothing
/// but `super(...)` and a plain field assignment. Guards the common path
/// against being perturbed by the fix.
const TS_PLAIN =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\class ProbeCtl extends SmartContract {
    \\  readonly target: bigint;
    \\
    \\  constructor(target: bigint) {
    \\    super(target);
    \\    this.target = target;
    \\  }
    \\
    \\  public verify(a: bigint): void {
    \\    assert(a === this.target);
    \\  }
    \\}
;

/// The ANF binding kinds of the compiled contract's `constructor` method, as a
/// space-separated string. Allocated from `work` (the caller's arena).
fn constructorKinds(
    work: std.mem.Allocator,
    source: []const u8,
    file_name: []const u8,
) ![]const u8 {
    var diag: compiler_api.Diagnostics = .{};
    const pipeline = compiler_api.runPipeline(work, source, file_name, .{
        .disable_constant_folding = true,
    }, &diag) catch |err| {
        for (diag.errors.items) |line| std.debug.print("{s}\n", .{line});
        return err;
    };
    const program = pipeline.program orelse return error.ANFLowerFailed;

    for (program.methods) |m| {
        if (!std.mem.eql(u8, m.name, "constructor")) continue;
        var out: std.ArrayListUnmanaged(u8) = .empty;
        for (m.bindings, 0..) |b, i| {
            if (i > 0) try out.append(work, ' ');
            try out.appendSlice(work, @tagName(b.value));
        }
        return out.items;
    }
    return error.ANFLowerFailed;
}

/// The six-tier constructor ANF for the assert probe.
const EXPECTED_ASSERT = "load_prop call load_prop load_const bin_op assert load_prop update_prop";
/// The six-tier constructor ANF for the plain control.
const EXPECTED_PLAIN = "load_prop call load_prop update_prop";

fn expectConstructorKinds(
    source: []const u8,
    file_name: []const u8,
    expected: []const u8,
) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const kinds = try constructorKinds(arena.allocator(), source, file_name);
    try std.testing.expectEqualStrings(expected, kinds);
}

test "R-040 .runar.ts constructor keeps an assert on a constructor argument" {
    try expectConstructorKinds(TS_ASSERT, "ProbeAssert.runar.ts", EXPECTED_ASSERT);
}

test "R-040 .runar.sol constructor keeps a require on a constructor argument" {
    try expectConstructorKinds(SOL_ASSERT, "ProbeAssert.runar.sol", EXPECTED_ASSERT);
}

test "R-040 .runar.py constructor keeps an assert_ on a constructor argument" {
    try expectConstructorKinds(PY_ASSERT, "ProbeAssert.runar.py", EXPECTED_ASSERT);
}

test "R-040 .runar.rb constructor keeps an assert on a constructor argument" {
    try expectConstructorKinds(RB_ASSERT, "ProbeAssert.runar.rb", EXPECTED_ASSERT);
}

test "R-040 .runar.java constructor keeps an assertThat on a constructor argument" {
    try expectConstructorKinds(JAVA_ASSERT, "ProbeAssert.runar.java", EXPECTED_ASSERT);
}

test "R-040 .runar.zig init keeps an assert on a constructor argument" {
    try expectConstructorKinds(ZIG_ASSERT, "ProbeAssert.runar.zig", EXPECTED_ASSERT);
}

test "R-040 control: a plain constructor still lowers to super + update_prop" {
    try expectConstructorKinds(TS_PLAIN, "ProbeCtl.runar.ts", EXPECTED_PLAIN);
}

test "R-040 control: the assert probe's script hex is unchanged by the fix" {
    // The constructor body is never stack-lowered, so honouring the statement
    // must move the ANF and NOTHING else. This is the seven-tier agreed hex
    // for both the plain control and the assert probe.
    const allocator = std.testing.allocator;
    const plain = try compiler_api.compileSourceWithOptions(allocator, TS_PLAIN, "ProbeCtl.runar.ts", true);
    defer plain.deinit(allocator);
    const probe = try compiler_api.compileSourceWithOptions(allocator, TS_ASSERT, "ProbeAssert.runar.ts", true);
    defer probe.deinit(allocator);
    try std.testing.expectEqualStrings(plain.script_hex, probe.script_hex);
}
