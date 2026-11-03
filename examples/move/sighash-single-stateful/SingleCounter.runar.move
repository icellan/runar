// SingleCounter — Move-style port of
// `examples/ts/sighash-single-stateful/SingleCounter.runar.ts`.
//
// `bump` carries the attribute sighash(SINGLE | FORKID) (N-093), so its
// auto-injected continuation commits only the output at its own index: no
// change segment and no `_changePKH` / `_changeAmount` parameter (N-038).
// SINGLE does not pin the continuation's value, so `bump` re-creates it at the
// full input amount read from the preimage. `reset` keeps ALL|FORKID.
module SingleCounter {
    resource struct SingleCounter {
        count: &mut bigint,
    }

    #[sighash(SINGLE | FORKID)]
    public fun bump(contract: &mut SingleCounter) {
        contract.addOutput(extract_amount(contract.tx_preimage), contract.count + 1);
    }

    public fun reset(contract: &mut SingleCounter) {
        assert!(contract.count > 0, 0);
        contract.count = 0;
    }
}
