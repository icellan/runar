const runar = @import("runar");

pub const CovenantVault = struct {
    pub const Contract = runar.SmartContract;

    owner: runar.PubKey,
    recipient: runar.Addr,
    minAmount: i64,

    pub fn init(owner: runar.PubKey, recipient: runar.Addr, minAmount: i64) CovenantVault {
        return .{
            .owner = owner,
            .recipient = recipient,
            .minAmount = minAmount,
        };
    }

    pub fn spend(self: *const CovenantVault, sig: runar.Sig, txPreimage: runar.SigHashPreimage) void {
        runar.assert(runar.checkSig(sig, self.owner));
        runar.assert(runar.checkPreimage(txPreimage));

        const expectedOutput = runar.buildChangeOutput(self.recipient, self.minAmount);

        runar.assert(runar.bytesEq(runar.hash256(expectedOutput), runar.extractOutputHash(txPreimage)));
    }
};
