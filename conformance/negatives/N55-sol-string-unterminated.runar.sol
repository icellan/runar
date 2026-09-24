// F-011: an unterminated .runar.sol string literal. A quoted literal that
// reaches a line break before its closing quote is unterminated; tokenizers
// that scanned to the next quote swallowed the require on the next line.
// Every tier must refuse with:
//   unterminated string literal
pragma runar ^0.1.0;

contract Guarded is SmartContract {
    constructor() {
    }

    function unlock(bigint y) public {
        ByteString tag = "cafe
        require(y < 5);
        // ";
        require(y >= 0);
    }
}
