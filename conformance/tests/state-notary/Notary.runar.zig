// Notary -- F-352 second witness for the mutable-state shape
// {ByteString, PubKey, bigint}, with the PubKey declared first.
const runar = @import("runar");

pub const Notary = struct {
    pub const Contract = runar.StatefulSmartContract;

    signer: runar.PubKey = "000000000000000000000000000000000000000000000000000000000000000000",
    note: runar.ByteString = "",
    seq: i64 = 0,

    pub fn init(signer: runar.PubKey, note: runar.ByteString, seq: i64) Notary {
        return .{
            .signer = signer,
            .note = note,
            .seq = seq,
        };
    }

    pub fn notarize(self: *Notary, sig: runar.Sig, nextNote: runar.ByteString) void {
        runar.assert(runar.checkSig(sig, self.signer));
        self.note = nextNote;
        self.seq = self.seq + 1;
    }
};
