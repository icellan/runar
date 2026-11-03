// N-205 (a): Solidity surface, a bare-name write (`key = newKey;`) of a
// spending-method parameter into the MUTABLE property verifyRabinSig uses as
// its public key. The bare target is an identifier, not `this.key`, and must
// still be read as the property write it is. Every tier must refuse:
//   verifyRabinSig public key property 'key' may only be assigned a contract property or a literal outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature
pragma runar ^0.1.0;

contract RabinKeyBareWrite is StatefulSmartContract {
    RabinPubKey key;

    constructor(RabinPubKey _key) {
        key = _key;
    }

    function settle(bytes msg, RabinSig sig, bytes padding) public {
        require(verifyRabinSig(msg, sig, padding, key));
    }

    function rotate(RabinPubKey newKey) public {
        key = newKey;
        require(true);
    }
}
