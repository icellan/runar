const runar = @import("runar");

// N-008 — a while loop whose `var i` declaration is not the statement
// immediately before it has no folded start value.
//
// The reference `.runar.zig` parser folds the preceding statement into the
// loop as its iterator only when that statement declares the variable the
// continue expression advances; otherwise the iterator is the placeholder
// `__while_no_init`, which the condition never tests, and the
// condition-iterator rule refuses the program ("For loop condition must
// compare the loop variable '__while_no_init' ..."). TypeScript, Go, Rust,
// Python, Ruby and Java all refuse the contract below that way.
//
// The Zig tier folded on the name the CONDITION tests and, when nothing
// folded, kept that name with a start of 0. So this contract compiled, alone
// on that tier, unrolled from i = 0 instead of i = 3: its script accepted
// expected = 10 (0+1+2+3+4) and rejected the correct 7 under
// @bsv/sdk Spend.validate(). A silent miscompile, not just a parity break.
pub const ZigWhileNonAdjacentInit = struct {
    pub const Contract = runar.SmartContract;

    target: i64,

    pub fn init(target: i64) ZigWhileNonAdjacentInit {
        return .{ .target = target };
    }

    pub fn check(self: *const ZigWhileNonAdjacentInit, expected: i64) void {
        var i: i64 = 3;
        var sum: i64 = 0;
        while (i < 5) : (i += 1) {
            sum = sum + i;
        }
        runar.assert(sum == expected);
        runar.assert(self.target == self.target);
    }
};
