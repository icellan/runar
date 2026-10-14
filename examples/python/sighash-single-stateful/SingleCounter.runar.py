from runar import StatefulSmartContract, Bigint, public, assert_, extract_amount


class SingleCounter(StatefulSmartContract):
    """Python port of examples/ts/sighash-single-stateful/SingleCounter.runar.ts.

    bump is declared public(sighash="SINGLE|FORKID") (N-093), so its
    auto-injected continuation commits only the output at its own index: no
    change segment and no _changePKH / _changeAmount parameter (N-038). SINGLE
    does not pin the continuation's value, so bump re-creates it at the full
    input amount read from the preimage. reset keeps ALL|FORKID.
    """

    count: Bigint

    def __init__(self, count: Bigint):
        super().__init__(count)
        self.count = count

    @public(sighash="SINGLE|FORKID")
    def bump(self):
        self.add_output(extract_amount(self.tx_preimage), self.count + 1)

    @public
    def reset(self):
        assert_(self.count > 0)
        self.count = 0
