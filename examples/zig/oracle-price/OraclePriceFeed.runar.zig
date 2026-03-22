const runar = @import("runar");

pub const OraclePriceFeed = struct {
    pub const Contract = runar.SmartContract;

    oraclePubKey: runar.RabinPubKey,
    receiver: runar.PubKey,

    pub fn init(oraclePubKey: runar.RabinPubKey, receiver: runar.PubKey) OraclePriceFeed {
        return .{
            .oraclePubKey = oraclePubKey,
            .receiver = receiver,
        };
    }

    pub fn settle(
        self: *const OraclePriceFeed,
        price: i64,
        rabinSig: runar.RabinSig,
        padding: runar.ByteString,
        sig: runar.Sig,
    ) void {
        const msg = runar.num2bin(price, 8);
        runar.assert(runar.verifyRabinSig(msg, rabinSig, padding, self.oraclePubKey));
        runar.assert(price > 50000);
        runar.assert(runar.checkSig(sig, self.receiver));
    }
};
