from runar import (
    StatefulSmartContract, Bigint, public, assert_,
    safediv, percent_of, clamp, sign, pow_, sqrt, gcd, mul_div, log2,
)

class MathDemo(StatefulSmartContract):
    value: Bigint

    def __init__(self, value: Bigint):
        super().__init__(value)
        self.value = value

    @public
    def divide_by(self, divisor: Bigint):
        self.value = safediv(self.value, divisor)

    @public
    def withdraw_with_fee(self, amount: Bigint, fee_bps: Bigint):
        fee = percent_of(amount, fee_bps)
        total = amount + fee
        assert_(total <= self.value)
        self.value = self.value - total

    @public
    def clamp_value(self, lo: Bigint, hi: Bigint):
        self.value = clamp(self.value, lo, hi)

    @public
    def normalize(self):
        self.value = sign(self.value)

    @public
    def exponentiate(self, exp: Bigint):
        self.value = pow_(self.value, exp)

    @public
    def square_root(self):
        self.value = sqrt(self.value)

    @public
    def reduce_gcd(self, other: Bigint):
        self.value = gcd(self.value, other)

    @public
    def scale_by_ratio(self, numerator: Bigint, denominator: Bigint):
        self.value = mul_div(self.value, numerator, denominator)

    @public
    def compute_log2(self):
        self.value = log2(self.value)
