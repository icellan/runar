//! F-017 — two distinct source identifiers that a surface's name conversion
//! maps to ONE Rúnar name are refused with one shared diagnostic.
//!
//! Before the rule, `tmp = n + 1; tmp_ = n + 2; assert_(tmp == tmp_)` in a
//! .runar.py contract (always false under Python semantics) bound both
//! spellings to one variable and compiled to `OP_DUP OP_DUP OP_NUMEQUAL`: an
//! always-TRUE guard.
//!
//! What this proves: the Zig tier's frontend refuses a collision on each of
//! the five renaming surfaces (.py/.rs/.rb/.move/.go) with exactly the text
//! the TS reference emits, picks the same pair regardless of declaration
//! order, and does not refuse `sum_` on its own or a local that reuses a
//! property's exact spelling.
//! What it does NOT prove: anything about the other tiers (their own suites
//! and conformance/negatives/N46-N50 cover that), or the semantics of a local
//! that shadows a property under the same spelling (N-016, a separate item).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const PY_HEAD =
    \\from runar import SmartContract, Bigint, public, assert_
    \\
    \\
    \\class Trail(SmartContract):
    \\    k: Bigint
    \\
    \\    def __init__(self, k: Bigint):
    \\        super().__init__(k)
    \\        self.k = k
    \\
    \\    @public
    \\    def unlock(self, n: Bigint):
    \\
;

const RS =
    \\use runar::prelude::*;
    \\
    \\#[runar::contract]
    \\struct Trail {
    \\    #[readonly]
    \\    k: Int,
    \\}
    \\
    \\impl Trail {
    \\    pub fn unlock(&self, n: Int) {
    \\        let n_ = n + 1;
    \\        assert!(n_ == n);
    \\    }
    \\}
    \\
;

const RB =
    \\require 'runar'
    \\
    \\class Trail < Runar::SmartContract
    \\  prop :k, Bigint
    \\
    \\  def initialize(k)
    \\    super(k)
    \\    @k = k
    \\  end
    \\
    \\  runar_public n: Bigint
    \\  def unlock(n)
    \\    k_ = n + 1
    \\    assert k_ == @k
    \\  end
    \\end
    \\
;

const MOVE =
    \\module Trail {
    \\    use runar::types::{Int};
    \\
    \\    struct Trail {
    \\        k: Int,
    \\    }
    \\
    \\    public fun unlock(contract: &Trail, n: Int) {
    \\        let tmp = n + 1;
    \\        let tmp_ = n + 2;
    \\        assert!(tmp == tmp_, 0);
    \\    }
    \\}
    \\
;

const GO = "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\n" ++
    "type Trail struct {\n\trunar.SmartContract\n\tK runar.Int `runar:\"readonly\"`\n}\n\n" ++
    "func (c *Trail) Unlock(n runar.Int) {\n\tk := n + 1\n\trunar.Assert(k == c.K)\n}\n";

fn msg(comptime a: []const u8, comptime b: []const u8, comptime name: []const u8) []const u8 {
    return "identifier collision: '" ++ a ++ "' and '" ++ b ++ "' both convert to '" ++ name ++ "'; rename one of them";
}

/// The identifier-collision diagnostics the frontend emits for `source`.
fn collisions(arena: std.mem.Allocator, source: []const u8, file_name: []const u8) ![]const []const u8 {
    const r = compiler_api.parseSource(arena, source, file_name);
    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    for (r.errors) |e| {
        if (std.mem.indexOf(u8, e, "identifier collision") != null) try out.append(arena, e);
    }
    return out.items;
}

fn expectRefused(source: []const u8, file_name: []const u8, expected: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const got = try collisions(arena_state.allocator(), source, file_name);
    try std.testing.expectEqual(@as(usize, 1), got.len);
    try std.testing.expectEqualStrings(expected, got[0]);
}

fn expectNoCollision(source: []const u8, file_name: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const got = try collisions(arena_state.allocator(), source, file_name);
    try std.testing.expectEqual(@as(usize, 0), got.len);
}

test "F-017 .runar.py refuses tmp / tmp_, _tmp / tmp, a__b / a_b and a loop variable" {
    try expectRefused(PY_HEAD ++ "        tmp = n + 1\n        tmp_ = n + 2\n        assert_(tmp == tmp_)\n", "Trail.runar.py", msg("tmp", "tmp_", "tmp"));
    try expectRefused(PY_HEAD ++ "        _tmp = n + 1\n        tmp = n + 2\n        assert_(_tmp == tmp)\n", "Trail.runar.py", msg("_tmp", "tmp", "tmp"));
    try expectRefused(PY_HEAD ++ "        a__b = n + 1\n        a_b = n + 2\n        assert_(a__b == a_b)\n", "Trail.runar.py", msg("a__b", "a_b", "aB"));
    try expectRefused(PY_HEAD ++ "        acc = n\n        for i_ in range(3):\n            acc = acc + 1\n        i = acc\n        assert_(i == n + 3)\n", "Trail.runar.py", msg("i", "i_", "i"));
}

test "F-017 .runar.rs / .runar.rb / .runar.move / .runar.go refuse a collision" {
    try expectRefused(RS, "Trail.runar.rs", msg("n", "n_", "n"));
    try expectRefused(RB, "Trail.runar.rb", msg("k", "k_", "k"));
    try expectRefused(MOVE, "Trail.runar.move", msg("tmp", "tmp_", "tmp"));
    try expectRefused(GO, "Trail.runar.go", msg("K", "k", "k"));
}

test "F-017 picks the smallest name, then its two smallest spellings" {
    try expectRefused(
        PY_HEAD ++ "        z_ = n + 1\n        z = n + 2\n        b__c = n + 3\n        b_c = n + 4\n        bC = n + 5\n        assert_(z + z_ + b__c + b_c + bC > 0)\n",
        "Trail.runar.py",
        msg("bC", "b__c", "bC"),
    );
}

test "F-017 accepts distinct names, sum_ on its own and a same-spelling local" {
    try expectNoCollision(PY_HEAD ++ "        x = n + 1\n        y = n + 2\n        assert_(x != y)\n", "Trail.runar.py");
    try expectNoCollision(PY_HEAD ++ "        sum_ = n + 1\n        sum_ = sum_ + 1\n        assert_(sum_ == n + 2)\n", "Trail.runar.py");
    try expectNoCollision(PY_HEAD ++ "        k = n + 1\n        assert_(k == self.k)\n", "Trail.runar.py");
}
