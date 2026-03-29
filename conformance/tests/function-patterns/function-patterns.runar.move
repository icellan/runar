module FunctionPatterns {
    use runar::StatefulSmartContract;
    use runar::types::{PubKey, Sig, Int};
    use runar::crypto::{check_sig};
    use runar::math::{percent_of, mul_div, clamp, safemod};

    resource struct FunctionPatterns {
        owner: PubKey,
        balance: &mut Int,
    }

    public fun deposit(contract: &mut FunctionPatterns, sig: Sig, amount: Int) {
        require_owner(contract, sig);
        assert!(amount > 0, 0);
        contract.balance = contract.balance + amount;
    }

    public fun withdraw(contract: &mut FunctionPatterns, sig: Sig, amount: Int, fee_bps: Int) {
        require_owner(contract, sig);
        assert!(amount > 0, 0);
        let fee = compute_fee(amount, fee_bps);
        let total = amount + fee;
        assert!(total <= contract.balance, 0);
        contract.balance = contract.balance - total;
    }

    public fun scale(contract: &mut FunctionPatterns, sig: Sig, numerator: Int, denominator: Int) {
        require_owner(contract, sig);
        contract.balance = scale_value(contract.balance, numerator, denominator);
    }

    public fun normalize(contract: &mut FunctionPatterns, sig: Sig, lo: Int, hi: Int, step: Int) {
        require_owner(contract, sig);
        let clamped = clamp_value(contract.balance, lo, hi);
        contract.balance = round_down(clamped, step);
    }

    fun require_owner(contract: &FunctionPatterns, sig: Sig) {
        assert!(check_sig(sig, contract.owner), 0);
    }

    fun compute_fee(amount: Int, fee_bps: Int): Int {
        percent_of(amount, fee_bps)
    }

    fun scale_value(value: Int, numerator: Int, denominator: Int): Int {
        mul_div(value, numerator, denominator)
    }

    fun clamp_value(value: Int, lo: Int, hi: Int): Int {
        clamp(value, lo, hi)
    }

    fun round_down(value: Int, step: Int): Int {
        let remainder = safemod(value, step);
        value - remainder
    }
}
