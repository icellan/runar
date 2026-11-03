const runar = @import("runar");

// N-116 — a while loop whose continue expression reads the iterator without
// advancing it.
//
// `i` stays 3 forever, so the source loop never terminates. The validator
// accepted the bare identifier as the "no-op sentinel" the while-shaped
// parsers synthesize, and the unrolled loop then stepped i by one from the
// comparison direction: TypeScript, Go, Rust, Python, Ruby and Java all
// compiled this to two laps over i = 3, 4
// (`005352797b7c937c93547b7b7c937c93009c`). A script that computes something
// the source does not say. The Zig tier refused it only because its parser
// dropped the bare continue expression, so the condition rule fired instead.
//
// All seven now refuse it with the shared R-065 sentence ("For loop update
// must advance the loop variable by one ...").
pub const ZigWhileContinueReadsIterator = struct {
    pub const Contract = runar.SmartContract;

    expectedSum: i64,

    pub fn init(expectedSum: i64) ZigWhileContinueReadsIterator {
        return .{ .expectedSum = expectedSum };
    }

    pub fn verify(self: *const ZigWhileContinueReadsIterator, start: i64) void {
        var sum: i64 = 0;
        var i: i64 = 3;
        while (i < 5) : (i) {
            sum = sum + start + i;
        }
        runar.assert(sum == self.expectedSum);
    }
};
