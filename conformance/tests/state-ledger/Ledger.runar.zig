// Ledger -- F-352 second witness for the mutable-state shape
// {PubKey, bigint, bigint}.
const runar = @import("runar");

pub const Ledger = struct {
    pub const Contract = runar.StatefulSmartContract;

    holder: runar.PubKey = "000000000000000000000000000000000000000000000000000000000000000000",
    balance: i64 = 0,
    nonce: i64 = 0,

    pub fn init(holder: runar.PubKey, balance: i64, nonce: i64) Ledger {
        return .{
            .holder = holder,
            .balance = balance,
            .nonce = nonce,
        };
    }

    pub fn spend(self: *Ledger, sig: runar.Sig, amount: i64) void {
        runar.assert(runar.checkSig(sig, self.holder));
        runar.assert(amount > 0);
        runar.assert(amount <= self.balance);
        self.balance = self.balance - amount;
        self.nonce = self.nonce + 1;
    }
};
