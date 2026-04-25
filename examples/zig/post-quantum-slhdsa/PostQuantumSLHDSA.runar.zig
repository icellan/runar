const runar = @import("runar");

pub const PostQuantumSLHDSA = struct {
    pub const Contract = runar.SmartContract;

    pubkey: runar.ByteString,

    pub fn init(pubkey: runar.ByteString) PostQuantumSLHDSA {
        return .{ .pubkey = pubkey };
    }

    pub fn spend(self: *const PostQuantumSLHDSA, msg: runar.ByteString, sig: runar.ByteString) void {
        runar.assert(runar.verifySLHDSA_SHA2_128s(msg, sig, self.pubkey));
    }
};
