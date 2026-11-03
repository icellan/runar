// F-286: verifyRabinSig's modulus (4th argument) is a spending-method parameter,
// so the spender picks n and forges any message (n = 1, sig = 0 passes real
// Spend). Every tier must refuse:
//   verifyRabinSig public key (4th argument) must be a contract property or a literal; a spender-supplied Rabin modulus lets anyone forge a signature
// Shape: Zig surface, pub fn parameter.
const runar = @import("runar");

pub const RabinParam = struct {
    pub const Contract = runar.SmartContract;

    pk: runar.RabinPubKey,

    pub fn init(pk: runar.RabinPubKey) RabinParam {
        return .{ .pk = pk };
    }

    pub fn settle(self: *const RabinParam, msg: runar.ByteString, sig: runar.RabinSig, padding: runar.ByteString, n: runar.RabinPubKey) void {
        runar.assert(runar.verifyRabinSig(msg, sig, padding, n));
    }
};
