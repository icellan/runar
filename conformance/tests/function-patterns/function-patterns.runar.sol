pragma runar ^0.1.0;

contract FunctionPatterns is StatefulSmartContract {
    PubKey immutable owner;
    bigint balance;

    constructor(PubKey _owner, bigint _balance) {
        owner = _owner;
        balance = _balance;
    }

    function deposit(Sig sig, bigint amount) public {
        requireOwner(sig);
        require(amount > 0);
        balance = balance + amount;
    }

    function withdraw(Sig sig, bigint amount, bigint feeBps) public {
        requireOwner(sig);
        require(amount > 0);
        bigint fee = computeFee(amount, feeBps);
        bigint total = amount + fee;
        require(total <= balance);
        balance = balance - total;
    }

    function scale(Sig sig, bigint numerator, bigint denominator) public {
        requireOwner(sig);
        balance = scaleValue(balance, numerator, denominator);
    }

    function normalize(Sig sig, bigint lo, bigint hi, bigint step) public {
        requireOwner(sig);
        bigint clamped = clampValue(balance, lo, hi);
        balance = roundDown(clamped, step);
    }

    function requireOwner(Sig sig) private {
        require(checkSig(sig, owner));
    }

    function computeFee(bigint amount, bigint feeBps) private returns (bigint) {
        return percentOf(amount, feeBps);
    }

    function scaleValue(bigint value, bigint numerator, bigint denominator) private returns (bigint) {
        return mulDiv(value, numerator, denominator);
    }

    function clampValue(bigint value, bigint lo, bigint hi) private returns (bigint) {
        return clamp(value, lo, hi);
    }

    function roundDown(bigint value, bigint step) private returns (bigint) {
        bigint remainder = safemod(value, step);
        return value - remainder;
    }
}
