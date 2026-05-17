const runar = @import("runar");

pub const BranchedReadonlyLen = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,
    tag: runar.ByteString = "",

    pub fn init(count: i64, tag: runar.ByteString) BranchedReadonlyLen {
        return .{ .count = count, .tag = tag };
    }

    pub fn spend(self: *BranchedReadonlyLen, scratch: runar.ByteString) void {
        if (runar.len(scratch) > 0) {
            self.count = self.count + 1;
            self.tag = scratch;
        } else {
            self.count = self.count - 1;
            self.tag = "3030";
        }
        self.addOutput(1000, self.count, self.tag);
    }
};
