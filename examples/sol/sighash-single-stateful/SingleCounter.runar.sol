pragma runar ^0.1.0;

/// SingleCounter — Solidity-like port of
/// `examples/ts/sighash-single-stateful/SingleCounter.runar.ts`.
///
/// `bump` carries the function modifier `sighash(SINGLE | FORKID)` (N-093), so
/// its auto-injected continuation commits only the output at its own index: no
/// change segment and no `_changePKH` / `_changeAmount` parameter (N-038).
/// SINGLE does not pin the continuation's value, so `bump` re-creates it at the
/// full input amount read from the preimage. `reset` keeps ALL|FORKID.
contract SingleCounter is StatefulSmartContract {
    bigint count;

    constructor(bigint _count) {
        count = _count;
    }

    function bump() public sighash(SINGLE | FORKID) {
        this.addOutput(extractAmount(this.txPreimage), this.count + 1);
    }

    function reset() public {
        require(this.count > 0);
        this.count = 0;
    }
}
