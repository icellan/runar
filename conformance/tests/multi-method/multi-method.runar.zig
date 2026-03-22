const runar = @import("runar");

pub const MultiMethod = struct {
    pub const Contract = runar.SmartContract;

    owner: runar.PubKey,
    backup: runar.PubKey,

    pub fn init(owner: runar.PubKey, backup: runar.PubKey) MultiMethod {
        return .{ .owner = owner, .backup = backup };
    }

    fn computeThreshold(a: i64, b: i64) i64 {
        return a * b + 1;
    }

    pub fn spendWithOwner(self: *const MultiMethod, sig: runar.Sig, amount: i64) void {
        const threshold = computeThreshold(amount, 2);
        runar.assert(threshold > 10);
        runar.assert(runar.checkSig(sig, self.owner));
    }

    pub fn spendWithBackup(self: *const MultiMethod, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.backup));
    }
};
