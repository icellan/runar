const runar = @import("runar");

pub const PostQuantumWOTS = struct {
    pub const Contract = runar.SmartContract;

    pubkey: runar.ByteString,

    pub fn init(pubkey: runar.ByteString) PostQuantumWOTS {
        return .{ .pubkey = pubkey };
    }

    pub fn spend(self: *const PostQuantumWOTS, msg: runar.ByteString, sig: runar.ByteString) void {
        runar.assert(runar.verifyWOTS(msg, sig, self.pubkey));
    }
};
