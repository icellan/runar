const runar = @import("runar");

pub const SimpleNFT = struct {
    pub const Contract = runar.StatefulSmartContract;

    owner: runar.PubKey = "000000000000000000000000000000000000000000000000000000000000000000",
    tokenId: runar.ByteString,
    metadata: runar.ByteString,

    pub fn init(owner: runar.PubKey, tokenId: runar.ByteString, metadata: runar.ByteString) SimpleNFT {
        return .{
            .owner = owner,
            .tokenId = tokenId,
            .metadata = metadata,
        };
    }

    pub fn transfer(self: *SimpleNFT, sig: runar.Sig, newOwner: runar.PubKey, outputSatoshis: i64) void {
        runar.assert(runar.checkSig(sig, self.owner));
        runar.assert(outputSatoshis >= 1);
        self.addOutput(outputSatoshis, newOwner);
    }

    pub fn burn(self: *const SimpleNFT, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.owner));
    }
};
