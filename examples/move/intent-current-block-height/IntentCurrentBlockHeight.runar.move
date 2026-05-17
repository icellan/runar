// IntentCurrentBlockHeight -- exercises the `currentBlockHeight`
// shorthand, which is pure source-level sugar for
// `extractLocktime(self.tx_preimage)`.
module IntentCurrentBlockHeight {

    resource struct IntentCurrentBlockHeight {
        deadline: bigint,
        count: &mut bigint,
    }

    public fun spend(contract: &mut IntentCurrentBlockHeight) {
        let h: bigint = currentBlockHeight();
        assert!(h <= contract.deadline, 0);
        contract.count = contract.count + 1;
    }
}
