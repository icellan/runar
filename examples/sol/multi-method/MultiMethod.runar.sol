pragma runar ^0.1.0;

contract MultiMethod is SmartContract {
    PubKey immutable owner;
    PubKey immutable backup;

    constructor(PubKey _owner, PubKey _backup) {
        owner = _owner;
        backup = _backup;
    }

    function computeThreshold(int a, int b) private returns (int) {
        return a * b + 1;
    }

    function spendWithOwner(Sig sig, int amount) public {
        int threshold = this.computeThreshold(amount, 2);
        require(threshold > 10);
        require(checkSig(sig, owner));
    }

    function spendWithBackup(Sig sig) public {
        require(checkSig(sig, backup));
    }
}
