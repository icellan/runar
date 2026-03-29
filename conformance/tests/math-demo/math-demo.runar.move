module MathDemo {
    resource struct MathDemo {
        value: bigint,
    }

    public fun divide_by(contract: &mut MathDemo, divisor: bigint) {
        contract.value = safediv(contract.value, divisor);
    }

    public fun withdraw_with_fee(contract: &mut MathDemo, amount: bigint, fee_bps: bigint) {
        let fee: bigint = percentOf(amount, fee_bps);
        let total: bigint = amount + fee;
        assert!(total <= contract.value, 0);
        contract.value = contract.value - total;
    }

    public fun clamp_value(contract: &mut MathDemo, lo: bigint, hi: bigint) {
        contract.value = clamp(contract.value, lo, hi);
    }

    public fun normalize(contract: &mut MathDemo) {
        contract.value = sign(contract.value);
    }

    public fun exponentiate(contract: &mut MathDemo, exp: bigint) {
        contract.value = pow(contract.value, exp);
    }

    public fun square_root(contract: &mut MathDemo) {
        contract.value = sqrt(contract.value);
    }

    public fun reduce_gcd(contract: &mut MathDemo, other: bigint) {
        contract.value = gcd(contract.value, other);
    }

    public fun scale_by_ratio(contract: &mut MathDemo, numerator: bigint, denominator: bigint) {
        contract.value = mulDiv(contract.value, numerator, denominator);
    }

    public fun compute_log2(contract: &mut MathDemo) {
        contract.value = log2(contract.value);
    }
}
