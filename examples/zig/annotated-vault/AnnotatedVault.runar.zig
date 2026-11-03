// AnnotatedVault -- N-044 conformance fixture: a mutable variable-length
// ByteString state field (memo) BEFORE a mutable PubKey (owner). Anyone may
// replace the memo; only the owner may withdraw.
const runar = @import("runar");

pub const AnnotatedVault = struct {
    pub const Contract = runar.StatefulSmartContract;

    memo: runar.ByteString = "",
    owner: runar.PubKey = runar.hexToBytes("000000000000000000000000000000000000000000000000000000000000000000"),
    balance: i64 = 0,

    pub fn init(memo: runar.ByteString, owner: runar.PubKey, balance: i64) AnnotatedVault {
        return .{
            .memo = memo,
            .owner = owner,
            .balance = balance,
        };
    }

    pub fn annotate(self: *AnnotatedVault, nextMemo: runar.ByteString) void {
        self.memo = nextMemo;
    }

    pub fn withdraw(self: *const AnnotatedVault, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.owner));
    }
};
