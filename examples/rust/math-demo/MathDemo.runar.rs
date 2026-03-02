use runar::prelude::*;

#[runar::contract]
pub struct MathDemo {
    pub value: Bigint,
}

#[runar::methods(MathDemo)]
impl MathDemo {
    #[public]
    pub fn divide_by(&mut self, divisor: Bigint) {
        self.value = safediv(self.value, divisor);
    }

    #[public]
    pub fn withdraw_with_fee(&mut self, amount: Bigint, fee_bps: Bigint) {
        let fee = percent_of(amount, fee_bps);
        let total = amount + fee;
        assert!(total <= self.value);
        self.value = self.value - total;
    }

    #[public]
    pub fn clamp_value(&mut self, lo: Bigint, hi: Bigint) {
        self.value = clamp(self.value, lo, hi);
    }

    #[public]
    pub fn normalize(&mut self) {
        self.value = sign(self.value);
    }

    #[public]
    pub fn exponentiate(&mut self, exp: Bigint) {
        self.value = pow(self.value, exp);
    }

    #[public]
    pub fn square_root(&mut self) {
        self.value = sqrt(self.value);
    }

    #[public]
    pub fn reduce_gcd(&mut self, other: Bigint) {
        self.value = gcd(self.value, other);
    }

    #[public]
    pub fn scale_by_ratio(&mut self, numerator: Bigint, denominator: Bigint) {
        self.value = mul_div(self.value, numerator, denominator);
    }

    #[public]
    pub fn compute_log2(&mut self) {
        self.value = log2(self.value);
    }
}
