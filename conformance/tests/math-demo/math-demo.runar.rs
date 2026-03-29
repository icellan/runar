use runar::prelude::*;

#[runar::contract]
struct MathDemo {
    value: Bigint,
}

#[runar::methods(MathDemo)]
impl MathDemo {
    #[public]
    fn divide_by(&mut self, divisor: Bigint) {
        self.value = safediv(self.value, divisor);
    }

    #[public]
    fn withdraw_with_fee(&mut self, amount: Bigint, fee_bps: Bigint) {
        let fee = percent_of(amount, fee_bps);
        let total = amount + fee;
        assert!(total <= self.value);
        self.value = self.value - total;
    }

    #[public]
    fn clamp_value(&mut self, lo: Bigint, hi: Bigint) {
        self.value = clamp(self.value, lo, hi);
    }

    #[public]
    fn normalize(&mut self) {
        self.value = sign(self.value);
    }

    #[public]
    fn exponentiate(&mut self, exp: Bigint) {
        self.value = pow(self.value, exp);
    }

    #[public]
    fn square_root(&mut self) {
        self.value = sqrt(self.value);
    }

    #[public]
    fn reduce_gcd(&mut self, other: Bigint) {
        self.value = gcd(self.value, other);
    }

    #[public]
    fn scale_by_ratio(&mut self, numerator: Bigint, denominator: Bigint) {
        self.value = mul_div(self.value, numerator, denominator);
    }

    #[public]
    fn compute_log2(&mut self) {
        self.value = log2(self.value);
    }
}
