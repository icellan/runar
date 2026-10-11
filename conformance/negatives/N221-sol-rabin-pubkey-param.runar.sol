// F-286: verifyRabinSig's modulus (4th argument) is a spending-method parameter,
// so the spender picks n and forges any message (n = 1, sig = 0 passes real
// Spend). Every tier must refuse:
//   verifyRabinSig public key (4th argument) must be a contract property or a literal; a spender-supplied Rabin modulus lets anyone forge a signature
// Shape: Solidity-like surface, public-function parameter.
pragma runar ^0.1.0;

contract RabinParam is SmartContract {
    RabinPubKey immutable pk;

    constructor(RabinPubKey _pk) {
        pk = _pk;
    }

    function settle(bytes msg, RabinSig sig, bytes padding, RabinPubKey n) public {
        require(verifyRabinSig(msg, sig, padding, n));
    }
}
