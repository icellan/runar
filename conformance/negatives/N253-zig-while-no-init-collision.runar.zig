const runar = @import("runar");

// N-009 — a user local spelled exactly like the `.runar.zig` while-merge
// placeholder must not be able to impersonate it.
//
// The reference `.runar.zig` parser (01-parse-zig.ts) lowers every
// `while (cond) : (upd) { ... }` to a for-statement whose init is a
// placeholder, and folds the preceding statement in as the init only when
// it declares the variable the UPDATE advances. An unfolded loop keeps the
// placeholder, whose name the condition never tests, so the
// condition-iterator rule refuses it (see N162, the plain non-adjacent-init
// case for a variable named `i`).
//
// Before N-009's fix the placeholder was the spellable literal
// `__while_no_init`, so a developer whose OWN non-adjacent loop variable
// happened to be named exactly `__while_no_init` defeated that rule: the
// unfolded placeholder's name and the user's real declaration were the same
// string, so "the condition's left-hand side equals the init's name" compared
// equal even though the init was the UNMERGED placeholder (start 0), not the
// user's real declaration (start 3). The loop compiled unrolled from 0
// instead of 3, and its script accepted expected = 10 (0+1+2+3+4) while
// rejecting the correct 7 under @bsv/sdk Spend.validate() — on whichever
// tiers still spelled the placeholder as a plain identifier.
//
// All seven tiers now refuse this contract identically.
pub const Collide = struct {
    pub const Contract = runar.SmartContract;

    target: i64,

    pub fn init(target: i64) Collide {
        return .{ .target = target };
    }

    pub fn check(self: *const Collide, expected: i64) void {
        var __while_no_init: i64 = 3;
        var sum: i64 = 0;
        while (__while_no_init < 5) : (__while_no_init += 1) {
            sum = sum + __while_no_init;
        }
        runar.assert(sum == expected);
        runar.assert(self.target == self.target);
    }
};
