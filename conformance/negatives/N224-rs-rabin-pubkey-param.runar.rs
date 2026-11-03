// F-286: verifyRabinSig's modulus (4th argument) is a spending-method parameter,
// so the spender picks n and forges any message (n = 1, sig = 0 passes real
// Spend). Every tier must refuse:
//   verifyRabinSig public key (4th argument) must be a contract property or a literal; a spender-supplied Rabin modulus lets anyone forge a signature
// Shape: Rust DSL surface, pub fn parameter.
use runar::prelude::*;

#[runar::contract]
pub struct RabinParam {
    #[readonly]
    pub pk: RabinPubKey,
}

impl RabinParam {
    pub fn settle(&self, msg: ByteString, sig: RabinSig, padding: ByteString, n: RabinPubKey) {
        assert!(verify_rabin_sig(&msg, sig, padding, &n));
    }
}
