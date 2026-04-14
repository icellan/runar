const runar = @import("runar");

pub const FungibleToken = struct {
    pub const Contract = runar.StatefulSmartContract;

    owner: runar.PubKey = "000000000000000000000000000000000000000000000000000000000000000000",
    balance: i64 = 0,
    mergeBalance: i64 = 0,
    tokenId: runar.ByteString,

    pub fn init(owner: runar.PubKey, balance: i64, mergeBalance: i64, tokenId: runar.ByteString) FungibleToken {
        return .{
            .owner = owner,
            .balance = balance,
            .mergeBalance = mergeBalance,
            .tokenId = tokenId,
        };
    }

    pub fn transfer(
        self: *FungibleToken,
        sig: runar.Sig,
        to: runar.PubKey,
        amount: i64,
        outputSatoshis: i64,
    ) void {
        runar.assert(runar.checkSig(sig, self.owner));
        runar.assert(outputSatoshis >= 1);
        const totalBalance = self.balance + self.mergeBalance;
        runar.assert(amount > 0);
        runar.assert(amount <= totalBalance);

        self.addOutput(outputSatoshis, to, amount, 0);
        if (amount < totalBalance) {
            self.addOutput(outputSatoshis, self.owner, totalBalance - amount, 0);
        }
    }

    pub fn send(self: *FungibleToken, sig: runar.Sig, to: runar.PubKey, outputSatoshis: i64) void {
        runar.assert(runar.checkSig(sig, self.owner));
        runar.assert(outputSatoshis >= 1);
        self.addOutput(outputSatoshis, to, self.balance + self.mergeBalance, 0);
    }

    pub fn merge(
        self: *FungibleToken,
        sig: runar.Sig,
        otherBalance: i64,
        allPrevouts: runar.ByteString,
        outputSatoshis: i64,
    ) void {
        runar.assert(runar.checkSig(sig, self.owner));
        runar.assert(outputSatoshis >= 1);
        runar.assert(otherBalance >= 0);
        runar.assert(runar.bytesEq(runar.hash256(allPrevouts), runar.extractHashPrevouts(self.txPreimage)));

        const myOutpoint = runar.extractOutpoint(self.txPreimage);
        const firstOutpoint = runar.substr(allPrevouts, 0, 36);
        const myBalance = self.balance + self.mergeBalance;

        if (runar.bytesEq(myOutpoint, firstOutpoint)) {
            self.addOutput(outputSatoshis, self.owner, myBalance, otherBalance);
        } else {
            self.addOutput(outputSatoshis, self.owner, otherBalance, myBalance);
        }
    }
};
