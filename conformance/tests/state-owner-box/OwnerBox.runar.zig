// OwnerBox -- F-352 second witness for the mutable-state shape {PubKey}.
const runar = @import("runar");

pub const OwnerBox = struct {
    pub const Contract = runar.StatefulSmartContract;

    owner: runar.PubKey = "000000000000000000000000000000000000000000000000000000000000000000",

    pub fn init(owner: runar.PubKey) OwnerBox {
        return .{ .owner = owner };
    }

    pub fn rotate(self: *OwnerBox, sig: runar.Sig, newOwner: runar.PubKey) void {
        runar.assert(runar.checkSig(sig, self.owner));
        self.owner = newOwner;
    }
};
