// DigestLog -- F-352 second witness for the mutable-state shape {Ripemd160}.
const runar = @import("runar");

pub const DigestLog = struct {
    pub const Contract = runar.StatefulSmartContract;

    digest: runar.Ripemd160 = "",

    pub fn init(digest: runar.Ripemd160) DigestLog {
        return .{ .digest = digest };
    }

    pub fn replace(self: *DigestLog, newDigest: runar.Ripemd160, version: i64) void {
        runar.assert(version > 0);
        self.digest = newDigest;
    }
};
