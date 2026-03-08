module PropertyInitializers {
    use runar::StatefulSmartContract;

    resource struct PropertyInitializers {
        count: &mut Int = 0,
        max_count: Int,
        active: Bool = true,
    }

    public fun increment(contract: &mut PropertyInitializers, amount: Int) {
        assert!(contract.active, 0);
        contract.count = contract.count + amount;
        assert!(contract.count <= contract.max_count, 0);
    }

    public fun reset(contract: &mut PropertyInitializers) {
        contract.count = 0;
    }
}
