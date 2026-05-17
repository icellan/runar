const runar = @import("runar");

pub const IntentOutputP2PKH = struct {
    pub const Contract = runar.StatefulSmartContract;

    bondPKH: runar.ByteString,
    bondAmount: i64,
    count: i64 = 0,

    pub fn init(bondPKH: runar.ByteString, bondAmount: i64, count: i64) IntentOutputP2PKH {
        return .{ .bondPKH = bondPKH, .bondAmount = bondAmount, .count = count };
    }

    pub fn payBond(self: *IntentOutputP2PKH) void {
        runar.requireOutputP2PKH(0, self.bondPKH, self.bondAmount);
        self.count = self.count + 1;
    }
};
