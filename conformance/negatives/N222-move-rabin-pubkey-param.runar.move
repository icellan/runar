// F-286: verifyRabinSig's modulus (4th argument) is a spending-method parameter,
// so the spender picks n and forges any message (n = 1, sig = 0 passes real
// Spend). Every tier must refuse:
//   verifyRabinSig public key (4th argument) must be a contract property or a literal; a spender-supplied Rabin modulus lets anyone forge a signature
// Shape: Move surface, public-function parameter (property spelled contract.pk elsewhere).
module RabinParam {
    use runar::types::{ByteString, RabinSig, RabinPubKey};
    use runar::crypto::{verify_rabin_sig};

    resource struct RabinParam {
        pk: RabinPubKey,
    }

    public fun settle(contract: &RabinParam, msg: ByteString, sig: RabinSig, padding: ByteString, n: RabinPubKey) {
        assert!(verify_rabin_sig(msg, sig, padding, n), 0);
    }
}
