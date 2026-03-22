const runar = @import("runar");

pub const FunctionPatterns = struct {
    pub const Contract = runar.StatefulSmartContract;

    owner: runar.PubKey,
    balance: i64 = 0,

    pub fn init(owner: runar.PubKey, balance: i64) FunctionPatterns {
        return .{
            .owner = owner,
            .balance = balance,
        };
    }

    pub fn deposit(self: *FunctionPatterns, sig: runar.Sig, amount: i64) void {
        self.requireOwner(sig);
        runar.assert(amount > 0);
        self.balance = self.balance + amount;
    }

    pub fn withdraw(self: *FunctionPatterns, sig: runar.Sig, amount: i64, feeBps: i64) void {
        self.requireOwner(sig);
        runar.assert(amount > 0);

        const fee = self.computeFee(amount, feeBps);
        const total = amount + fee;
        runar.assert(total <= self.balance);
        self.balance = self.balance - total;
    }

    pub fn scale(self: *FunctionPatterns, sig: runar.Sig, numerator: i64, denominator: i64) void {
        self.requireOwner(sig);
        self.balance = self.scaleValue(self.balance, numerator, denominator);
    }

    pub fn normalize(self: *FunctionPatterns, sig: runar.Sig, lo: i64, hi: i64, step: i64) void {
        self.requireOwner(sig);
        const clamped = self.clampValue(self.balance, lo, hi);
        self.balance = self.roundDown(clamped, step);
    }

    fn requireOwner(self: *const FunctionPatterns, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.owner));
    }

    fn computeFee(self: *const FunctionPatterns, amount: i64, feeBps: i64) i64 {
        _ = self;
        return runar.percentOf(amount, feeBps);
    }

    fn scaleValue(self: *const FunctionPatterns, value: i64, numerator: i64, denominator: i64) i64 {
        _ = self;
        return runar.mulDiv(value, numerator, denominator);
    }

    fn clampValue(self: *const FunctionPatterns, value: i64, lo: i64, hi: i64) i64 {
        _ = self;
        return runar.clamp(value, lo, hi);
    }

    fn roundDown(self: *const FunctionPatterns, value: i64, step: i64) i64 {
        _ = self;
        const remainder = runar.safemod(value, step);
        return value - remainder;
    }
};
