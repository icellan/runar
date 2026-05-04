"""ConditionalDataOutput -- Audit regression: a stateful method that
emits a data output on a conditional branch must keep the canonical
single-output ``compute_state_output`` state continuation on every path.

See ``conformance/tests/conditional-data-output-stateful/`` for the full
rationale; the cross-format ports must produce identical Bitcoin Script.
"""

from runar import StatefulSmartContract, Bigint, ByteString, public, assert_


class ConditionalDataOutput(StatefulSmartContract):
    amount: Bigint

    def __init__(self, amount: Bigint):
        super().__init__(amount)
        self.amount = amount

    @public
    def pay(self, flag: bool, payload: ByteString):
        """The canonical bug: ``add_data_output`` is wrapped in a branch."""
        self.amount = self.amount + 1
        if flag:
            self.add_data_output(0, payload)
        assert_(True)
