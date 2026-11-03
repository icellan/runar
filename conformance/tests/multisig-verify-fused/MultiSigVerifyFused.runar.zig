const runar = @import("runar");

pub const MultiSigVerifyFused = struct {
    pub const Contract = runar.SmartContract;

    pk1: runar.PubKey,
    pk2: runar.PubKey,
    pk3: runar.PubKey,

    pub fn init(pk1: runar.PubKey, pk2: runar.PubKey, pk3: runar.PubKey) MultiSigVerifyFused {
        return .{ .pk1 = pk1, .pk2 = pk2, .pk3 = pk3 };
    }

    pub fn unlock(self: *const MultiSigVerifyFused, sig1: runar.Sig, sig2: runar.Sig, amount: i64) void {
        runar.assert(runar.checkMultiSig(
            &.{ sig1, sig2 },
            &.{ self.pk1, self.pk2, self.pk3 },
        ));
        runar.assert(amount > 0);
    }
};
