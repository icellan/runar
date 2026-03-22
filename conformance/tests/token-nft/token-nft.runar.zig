const runar = @import("runar");

pub const NFTExample = struct {
    pub const Contract = runar.StatefulSmartContract;

    owner: runar.PubKey = "000000000000000000000000000000000000000000000000000000000000000000",
    tokenId: runar.ByteString,
    metadata: runar.ByteString,

    pub fn init(owner: runar.PubKey, tokenId: runar.ByteString, metadata: runar.ByteString) NFTExample {
        return .{
            .owner = owner,
            .tokenId = tokenId,
            .metadata = metadata,
        };
    }

    pub fn transfer(self: *NFTExample, ctx: runar.StatefulContext, sig: runar.Sig, newOwner: runar.PubKey, outputSatoshis: i64) void {
        runar.assert(runar.checkSig(sig, self.owner));
        runar.assert(outputSatoshis >= 1);
        ctx.addOutput(outputSatoshis, .{ newOwner });
    }

    pub fn burn(self: *const NFTExample, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.owner));
    }
};
