// Anyone — minimal `asm` raw-script contract (Zig surface).
const runar = @import("runar");

pub const Anyone = struct {
    pub const Contract = runar.UnsafeSmartContract;

    pub fn init() Anyone {
        return .{};
    }

    pub fn unlock(self: *const Anyone) void {
        _ = self;
        runar.asm("51", 0, 1);
    }
};
