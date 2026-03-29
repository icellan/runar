module Counter {
    resource struct Counter {
        count: bigint,
    }

    public fun increment(contract: &mut Counter) {
        contract.count = contract.count + 1;
    }

    public fun decrement(contract: &mut Counter) {
        assert!(contract.count > 0, 0);
        contract.count = contract.count - 1;
    }
}
