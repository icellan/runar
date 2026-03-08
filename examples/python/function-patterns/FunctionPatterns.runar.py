# FunctionPatterns demonstrates every way functions and methods can be
# used inside a Runar Python contract.
#
# Runar contracts support three categories of callable code:
#
#   1. Public methods      -- decorated with @public. These are the
#                             spending entry points that appear in the
#                             compiled Bitcoin Script.
#
#   2. Private methods     -- prefixed with underscore (e.g. _helper).
#                             These can access contract state via self
#                             and are inlined by the compiler at call
#                             sites. Private methods may return a value.
#
#   3. Built-in functions  -- imported from runar (e.g. assert_,
#                             check_sig, percent_of, clamp). These map
#                             directly to Bitcoin Script opcodes.
#
# Note: Python contracts cannot define standalone functions outside
# the class. All helper logic must be private methods on the class.

from runar import (
    StatefulSmartContract, PubKey, Sig, Bigint, Readonly,
    public, assert_, check_sig, percent_of, mul_div, clamp, safemod,
)

class FunctionPatterns(StatefulSmartContract):
    """Stateful contract demonstrating all function call patterns in Runar Python."""

    owner: Readonly[PubKey]   # immutable: contract creator
    balance: Bigint           # stateful: current balance

    def __init__(self, owner: PubKey, balance: Bigint):
        super().__init__(owner, balance)
        self.owner = owner
        self.balance = balance

    # -------------------------------------------------------------------
    # 1. Public methods -- spending entry points
    # -------------------------------------------------------------------
    # @public methods become separate OP_IF branches in the compiled
    # locking script. The spending transaction selects which method to
    # execute via a method index pushed in the scriptSig.
    #
    # Public methods must not return a value.

    @public
    def deposit(self, sig: Sig, amount: Bigint):
        """Deposit adds funds. Calls a private method and a built-in."""
        # Private method: shared signature check
        self._require_owner(sig)

        # Built-in: assertion
        assert_(amount > 0)

        # Update state
        self.balance = self.balance + amount

    @public
    def withdraw(self, sig: Sig, amount: Bigint, fee_bps: Bigint):
        """Withdraw removes funds after applying a fee.

        Demonstrates chaining a private method that returns a value.
        """
        self._require_owner(sig)
        assert_(amount > 0)

        # Private method with return value
        fee = self._compute_fee(amount, fee_bps)
        total = amount + fee

        assert_(total <= self.balance)
        self.balance = self.balance - total

    @public
    def scale(self, sig: Sig, numerator: Bigint, denominator: Bigint):
        """Scale multiplies the balance by a rational number.

        Demonstrates calling a private method that wraps a built-in.
        """
        self._require_owner(sig)
        self.balance = self._scale_value(self.balance, numerator, denominator)

    @public
    def normalize(self, sig: Sig, lo: Bigint, hi: Bigint, step: Bigint):
        """Normalize clamps the balance to a range and rounds down.

        Demonstrates composing multiple private helper methods.
        """
        self._require_owner(sig)
        clamped = self._clamp_value(self.balance, lo, hi)
        self.balance = self._round_down(clamped, step)

    # -------------------------------------------------------------------
    # 2. Private methods -- inlined helpers
    # -------------------------------------------------------------------
    # Methods prefixed with underscore are private. They can read/write
    # contract state via self and may return a value. The compiler
    # inlines them at each call site -- they do not become separate
    # script functions.

    def _require_owner(self, sig: Sig):
        """Verify the caller is the contract owner. Shared by all public methods."""
        assert_(check_sig(sig, self.owner))

    def _compute_fee(self, amount: Bigint, fee_bps: Bigint) -> Bigint:
        """Compute a fee in basis points. Returns the fee amount."""
        return percent_of(amount, fee_bps)

    def _scale_value(self, value: Bigint, numerator: Bigint, denominator: Bigint) -> Bigint:
        """Multiply a value by a fraction using mul_div for precision."""
        return mul_div(value, numerator, denominator)

    def _clamp_value(self, value: Bigint, lo: Bigint, hi: Bigint) -> Bigint:
        """Clamp a value to [lo, hi]."""
        return clamp(value, lo, hi)

    def _round_down(self, value: Bigint, step: Bigint) -> Bigint:
        """Round down to the nearest multiple of step."""
        remainder = safemod(value, step)
        return value - remainder
