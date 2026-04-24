const runar = @import("runar");

pub const HashRegistry = struct {
    pub const Contract = runar.StatefulSmartContract;

    currentHash: runar.Ripemd160 = "",

    pub fn init(currentHash: runar.Ripemd160) HashRegistry {
        return .{ .currentHash = currentHash };
    }

    pub fn update(self: *HashRegistry, newHash: runar.Ripemd160) void {
        self.currentHash = newHash;
        runar.assert(true);
    }
};
