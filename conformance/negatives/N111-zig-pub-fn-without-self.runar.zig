// N-050 (StaticSiphon): a static / class-level method is not a contract method.
// Pre-fix, `requirePositive` became a PUBLIC spending entry point in several
// tiers — a path anyone satisfies with `<1>` and no signature (@bsv/sdk
// Spend.validate accepted it against the TS artifact). Every tier must refuse:
//   static methods are not allowed in Rúnar contracts; method 'requirePositive' is declared static
// Shape: a `pub fn` without a receiver on the Zig surface.
const runar = @import("runar");

pub const Vault = struct {
    pub const Contract = runar.SmartContract;

    owner: runar.PubKey,

    pub fn init(owner: runar.PubKey) Vault {
        return .{ .owner = owner };
    }

    pub fn requirePositive(amount: i64) void {
        runar.assert(amount > 0);
    }

    pub fn withdraw(self: *const Vault, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.owner));
    }
};
