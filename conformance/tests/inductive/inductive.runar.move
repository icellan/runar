module Inductive {
    use runar::InductiveSmartContract;

    resource struct Inductive has inductive {
        count: &mut Int,
        max_count: Int,
    }

    public fun increment(contract: &mut Inductive, amount: Int) {
        contract.count = contract.count + amount;
        assert!(contract.count <= contract.max_count, 0);
    }

    public fun reset(contract: &mut Inductive) {
        contract.count = 0;
    }
}
