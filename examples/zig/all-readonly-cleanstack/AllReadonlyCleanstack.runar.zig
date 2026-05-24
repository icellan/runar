const runar = @import("runar");

// AllReadonlyCleanstack — regression fixture for issue #44.
//
// A StatefulSmartContract with ZERO mutable fields (only a readonly `owner`)
// plus a readonly-field-binding in a terminal method. The `ownerCopy = owner`
// binding force-embeds the readonly field onto the stack; it is not consumed by
// the terminal checkSig assertion, leaving an excess stack item below the
// top-of-stack boolean. Before the fix, the leftover survived and the spend was
// rejected on mainnet with "Script did not clean its stack". The fix runs the
// stack cleanup for every public method, emitting the trailing OP_NIP.
pub const AllReadonlyCleanstack = struct {
    pub const Contract = runar.StatefulSmartContract;

    owner: runar.PubKey,

    pub fn init(owner: runar.PubKey) AllReadonlyCleanstack {
        return .{ .owner = owner };
    }

    pub fn claim(self: *const AllReadonlyCleanstack, sig: runar.Sig) void {
        const ownerCopy = self.owner;
        runar.assert(runar.checkSig(sig, self.owner));
    }
};
