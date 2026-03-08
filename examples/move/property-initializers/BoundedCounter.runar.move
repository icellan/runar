// BoundedCounter — demonstrates property initializers in Move-like format.
//
// Properties with `= value` defaults are excluded from the auto-generated
// constructor. Only `max_count` needs to be provided at deploy time.
module BoundedCounter {
    use runar::StatefulSmartContract;

    resource struct BoundedCounter {
        count: &mut bigint = 0,
        max_count: bigint,
        active: Bool = true,
    }

    public fun increment(amount: bigint) {
        assert!(self.active);
        self.count = self.count + amount;
        assert!(self.count <= self.max_count);
    }

    public fun reset() {
        self.count = 0;
    }
}
