use runar::prelude::*;

/// SingleCounter -- Rust DSL port of
/// `examples/ts/sighash-single-stateful/SingleCounter.runar.ts`.
///
/// `bump` carries the method attribute `sighash(SINGLE | FORKID)` (N-093), so
/// its auto-injected continuation commits only the output at its own index: no
/// change segment and no `_changePKH` / `_changeAmount` parameter (N-038).
/// SINGLE does not pin the continuation's value, so `bump` re-creates it at the
/// full input amount read from the preimage. `reset` keeps ALL|FORKID.
#[runar::contract]
pub struct SingleCounter {
    pub count: Bigint,
}

impl SingleCounter {
    #[sighash(SINGLE | FORKID)]
    pub fn bump(&mut self) {
        self.add_output(extract_amount(&self.tx_preimage), self.count + 1);
    }

    pub fn reset(&mut self) {
        assert!(self.count > 0);
        self.count = 0;
    }
}
