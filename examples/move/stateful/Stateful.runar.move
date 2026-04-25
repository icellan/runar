module Stateful {
    use runar::StatefulSmartContract;

    resource struct Stateful {
        count: &mut Int,
        max_count: Int,
    }

    public fun increment(contract: &mut Stateful, amount: Int) {
        contract.count = contract.count + amount;
        assert!(contract.count <= contract.max_count, 0);
    }

    public fun reset(contract: &mut Stateful) {
        contract.count = 0;
    }
}
