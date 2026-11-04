//! A public method that reassigns one of its own PARAMETERS must lower the
//! write as a rebind of that parameter, exactly as the TS reference does
//! (`04-anf-lower.ts` `lowerAssignment`: a bare-identifier target is always
//! `emitNamed(localTarget(name), load_const @ref:<value>)`).
//!
//! `anf_lower.zig`'s `.assign` arm only knew two kinds of bare target — a
//! declared local, or a property — and parameters are neither (they live in
//! `param_names`, not `local_names`). So:
//!
//!   * a parameter that shares a property's name (`count = count + 1`) fell
//!     into the `isProperty` fallback and became `update_prop count`: a write
//!     into contract state the source never asked for (in a stateless
//!     contract, a write to a READONLY property);
//!   * any other parameter (`x = x + 2`) fell into the last `else`, which
//!     lowered a bare read of the target and DISCARDED the value — the
//!     reassignment vanished and every later read saw the caller's argument.
//!
//! The second one is a wrong-value miscompile: `x = x + 2; assert(x == t)`
//! accepted the argument `t`, not `t - 2`. Measured before the fix (fold OFF):
//!
//!     PR (stateful, every brace surface)  six tiers 1420 hex   zig 1436
//!     ShadowParam.runar.java (N-023 probe) six tiers 1404 hex   zig 1402
//!     SL (stateless, below)               ts/go 788b7852937c9d0000a07777
//!                                         zig   788b527a757852935279537a537a9d0000a07777
//!
//! N-360 then moved the reference itself. The six-tier 1420 / 1404 bytes above
//! bound the property-named parameter `count` under the property's own name,
//! and the PR spend they produce commits the UNINCREMENTED argument: on the
//! @bsv/sdk Spend engine `increment(5, 1)` from state 0 rejected the honest
//! continuation (count = 6) and accepted the stale one (count = 5). A
//! property-named public parameter that the method reassigns is now bound
//! under its `count@local` slot, and the TS reference is PR 1402 hex (1414 before
//! the C=1 binding blob of ports #170),
//! ShadowParam 1398 hex (`conformance/negatives/param-reassign-parity.test.ts`
//! executes the PR spend on-chain).
//!
//! The .runar.py / .runar.rb surfaces were never affected: their parsers turn
//! the first assignment of a name into a declaration, so it reaches the
//! `let_decl` arm, not this one.
//!
//! What this proves: for the stateful PR contract written in every brace
//! surface Zig parses (ts, sol, move, go, rs, zig, java), Zig's fold-OFF bytes
//! equal the TS reference's bytes (pinned by sha256, measured with the TS, Go,
//! Rust, Python, Ruby and Java CLIs, which all agree); and the short stateless
//! SL shape compiles to the TS reference hex literally.
//! What it does not prove: on-chain spend behaviour of those bytes, or fold-ON
//! output (the cross-tier vitest `conformance/negatives/param-reassign-parity
//! .test.ts` runs every tier's CLI in its fold-ON default).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

/// sha256 of the TS reference hex for PR, fold OFF (1402 hex chars; 1414 at
/// N-360, before the C=1 binding blob of ports #170).
const PR_TS_SHA256 = "2d439f924960c54527370c0c700e18807fb3acd634eed4dabd9876da29d7ec05";
const PR_TS_LEN: usize = 1402;

/// TS reference hex for SL, fold OFF.
const SL_TS_HEX = "788b7852937c9d0000a07777";

const PR_TS =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class PR extends StatefulSmartContract {
    \\  count: bigint;
    \\  constructor(count: bigint) { super(count); this.count = count; }
    \\  public increment(count: bigint, x: bigint) {
    \\    count = count + 1n;
    \\    x = x + 2n;
    \\    assert(x > 0n);
    \\    this.count = count;
    \\  }
    \\}
;

const PR_SOL =
    \\pragma runar ^0.1.0;
    \\contract PR is StatefulSmartContract {
    \\    int count;
    \\    constructor(int _count) { count = _count; }
    \\    function increment(int count, int x) public {
    \\        count = count + 1;
    \\        x = x + 2;
    \\        require(x > 0);
    \\        this.count = count;
    \\    }
    \\}
;

const PR_MOVE =
    \\module PR {
    \\    use runar::StatefulSmartContract;
    \\    resource struct PR {
    \\        count: &mut Int,
    \\    }
    \\    public fun increment(contract: &mut PR, count: Int, x: Int) {
    \\        count = count + 1;
    \\        x = x + 2;
    \\        assert!(x > 0, 0);
    \\        contract.count = count;
    \\    }
    \\}
;

const PR_GO =
    \\package contract
    \\
    \\import runar "github.com/icellan/runar/packages/runar-go"
    \\
    \\type PR struct {
    \\    runar.StatefulSmartContract
    \\    Count runar.Int
    \\}
    \\
    \\func (c *PR) Increment(Count runar.Int, x runar.Int) {
    \\    Count = Count + 1
    \\    x = x + 2
    \\    runar.Assert(x > 0)
    \\    c.Count = Count
    \\}
;

const PR_RS =
    \\use runar::prelude::*;
    \\
    \\#[runar::contract]
    \\struct PR {
    \\    count: Int,
    \\}
    \\
    \\impl PR {
    \\    pub fn increment(&mut self, count: Int, x: Int) {
    \\        count = count + 1;
    \\        x = x + 2;
    \\        assert!(x > 0);
    \\        self.count = count;
    \\    }
    \\}
;

const PR_ZIG =
    \\const runar = @import("runar");
    \\
    \\pub const PR = struct {
    \\    pub const Contract = runar.StatefulSmartContract;
    \\
    \\    count: i64 = 0,
    \\
    \\    pub fn init(count: i64) PR {
    \\        return .{ .count = count };
    \\    }
    \\
    \\    pub fn increment(self: *PR, count: i64, x: i64) void {
    \\        count = count + 1;
    \\        x = x + 2;
    \\        runar.assert(x > 0);
    \\        self.count = count;
    \\    }
    \\};
;

const PR_JAVA =
    \\package runar.examples.pr;
    \\
    \\import runar.lang.StatefulSmartContract;
    \\import runar.lang.annotations.Public;
    \\import runar.lang.types.Bigint;
    \\
    \\import static runar.lang.Builtins.assertThat;
    \\
    \\class PR extends StatefulSmartContract {
    \\
    \\    Bigint count;
    \\
    \\    PR(Bigint count) {
    \\        super(count);
    \\        this.count = count;
    \\    }
    \\
    \\    @Public
    \\    void increment(Bigint count, Bigint x) {
    \\        count = count.plus(Bigint.ONE);
    \\        x = x.plus(Bigint.TWO);
    \\        assertThat(x.gt(Bigint.ZERO));
    \\        this.count = count;
    \\    }
    \\}
;

const SL_TS =
    \\import { SmartContract, assert } from 'runar-lang';
    \\class SL extends SmartContract {
    \\  readonly count: bigint;
    \\  constructor(count: bigint) { super(count); this.count = count; }
    \\  public spend(count: bigint, x: bigint) {
    \\    count = count + 1n;
    \\    x = x + 2n;
    \\    assert(x == count);
    \\    assert(this.count > 0n);
    \\  }
    \\}
;

fn compileNoFold(a: std.mem.Allocator, src: []const u8, file_name: []const u8) ![]const u8 {
    const result = try compiler_api.compileSourceWithOptions(a, src, file_name, true);
    return result.script_hex;
}

fn expectPrMatchesTs(src: []const u8, file_name: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const hex = try compileNoFold(a, src, file_name);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(hex, &digest, .{});
    const got = std.fmt.bytesToHex(digest, .lower);
    if (hex.len != PR_TS_LEN or !std.mem.eql(u8, &got, PR_TS_SHA256)) {
        std.debug.print("{s}: len {d} sha256 {s}, TS reference len {d} sha256 {s}\n", .{ file_name, hex.len, got, PR_TS_LEN, PR_TS_SHA256 });
        return error.DivergesFromTsReference;
    }
}

test "param reassignment: .runar.ts matches the TS reference" {
    try expectPrMatchesTs(PR_TS, "PR.runar.ts");
}

test "param reassignment: .runar.sol matches the TS reference" {
    try expectPrMatchesTs(PR_SOL, "PR.runar.sol");
}

test "param reassignment: .runar.move matches the TS reference" {
    try expectPrMatchesTs(PR_MOVE, "PR.runar.move");
}

test "param reassignment: .runar.go matches the TS reference" {
    try expectPrMatchesTs(PR_GO, "PR.runar.go");
}

test "param reassignment: .runar.rs matches the TS reference" {
    try expectPrMatchesTs(PR_RS, "PR.runar.rs");
}

test "param reassignment: .runar.zig matches the TS reference" {
    try expectPrMatchesTs(PR_ZIG, "PR.runar.zig");
}

test "param reassignment: .runar.java matches the TS reference" {
    try expectPrMatchesTs(PR_JAVA, "PR.runar.java");
}

test "param reassignment: a stateless rebind is neither dropped nor a readonly write" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings(SL_TS_HEX, try compileNoFold(a, SL_TS, "SL.runar.ts"));
}
