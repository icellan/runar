pragma runar ^0.1.0;

contract MathDemo is StatefulSmartContract {
    bigint value;

    constructor(bigint _value) {
        value = _value;
    }

    function divideBy(bigint divisor) public {
        this.value = safediv(this.value, divisor);
    }

    function withdrawWithFee(bigint amount, bigint feeBps) public {
        bigint fee = percentOf(amount, feeBps);
        bigint total = amount + fee;
        require(total <= this.value);
        this.value = this.value - total;
    }

    function clampValue(bigint lo, bigint hi) public {
        this.value = clamp(this.value, lo, hi);
    }

    function normalize() public {
        this.value = sign(this.value);
    }

    function exponentiate(bigint exp) public {
        this.value = pow(this.value, exp);
    }

    function squareRoot() public {
        this.value = sqrt(this.value);
    }

    function reduceGcd(bigint other) public {
        this.value = gcd(this.value, other);
    }

    function scaleByRatio(bigint numerator, bigint denominator) public {
        this.value = mulDiv(this.value, numerator, denominator);
    }

    function computeLog2() public {
        this.value = log2(this.value);
    }
}
