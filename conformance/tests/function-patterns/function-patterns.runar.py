from runar import (
    StatefulSmartContract, PubKey, Sig, Bigint, Readonly,
    public, assert_, check_sig, percent_of, mul_div, clamp, safemod,
)

class FunctionPatterns(StatefulSmartContract):
    owner: Readonly[PubKey]
    balance: Bigint

    def __init__(self, owner: PubKey, balance: Bigint):
        super().__init__(owner, balance)
        self.owner = owner
        self.balance = balance

    @public
    def deposit(self, sig: Sig, amount: Bigint):
        self._require_owner(sig)
        assert_(amount > 0)
        self.balance = self.balance + amount

    @public
    def withdraw(self, sig: Sig, amount: Bigint, fee_bps: Bigint):
        self._require_owner(sig)
        assert_(amount > 0)
        fee = self._compute_fee(amount, fee_bps)
        total = amount + fee
        assert_(total <= self.balance)
        self.balance = self.balance - total

    @public
    def scale(self, sig: Sig, numerator: Bigint, denominator: Bigint):
        self._require_owner(sig)
        self.balance = self._scale_value(self.balance, numerator, denominator)

    @public
    def normalize(self, sig: Sig, lo: Bigint, hi: Bigint, step: Bigint):
        self._require_owner(sig)
        clamped = self._clamp_value(self.balance, lo, hi)
        self.balance = self._round_down(clamped, step)

    def _require_owner(self, sig: Sig):
        assert_(check_sig(sig, self.owner))

    def _compute_fee(self, amount: Bigint, fee_bps: Bigint) -> Bigint:
        return percent_of(amount, fee_bps)

    def _scale_value(self, value: Bigint, numerator: Bigint, denominator: Bigint) -> Bigint:
        return mul_div(value, numerator, denominator)

    def _clamp_value(self, value: Bigint, lo: Bigint, hi: Bigint) -> Bigint:
        return clamp(value, lo, hi)

    def _round_down(self, value: Bigint, step: Bigint) -> Bigint:
        remainder = safemod(value, step)
        return value - remainder
