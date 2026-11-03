// PropertyShadow — N-016 conformance fixture. A local that shares a field's
// name never captures `contract.<field>`.
module PropertyShadow {
    use runar::StatefulSmartContract;

    resource struct PropertyShadow {
        target: Int,
        count: &mut Int,
    }

    public fun bump(contract: &mut PropertyShadow, n: Int) {
        let target = n + 1;
        assert!(target == contract.target, 0);
        let count = n;
        contract.count = contract.count + count;
        assert!(contract.count > count, 0);
    }
}
