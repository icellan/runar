const runar = @import("runar");

// EcChainedRewrite -- two EC optimizer rules firing on one binding (F-115):
// ecAdd(ecMulGen(n - 7), ecMulGen(7)) -> ecMulGen(0) -> the point at infinity.
pub const EcChainedRewrite = struct {
    pub const Contract = runar.SmartContract;

    pub fn init() EcChainedRewrite {
        return .{};
    }

    pub fn unlock(self: *const EcChainedRewrite, p: runar.Point) void {
        _ = self;
        const r = runar.ecAdd(runar.ecMulGen(115792089237316195423570985008687907852837564279074904382605163141518161494330), runar.ecMulGen(7));
        runar.assert(r == p);
    }
};
