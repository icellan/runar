// ParamShadowBranchArm — N-007 conformance fixture. The parameter `count`
// shares the field's name; inside the `if` arm it is still the parameter.
module ParamShadowBranchArm {
    use runar::StatefulSmartContract;

    resource struct ParamShadowBranchArm {
        count: &mut Int,
    }

    public fun set(contract: &mut ParamShadowBranchArm, count: Int, flag: bool) {
        if (flag) {
            assert!(count == 5, 0);
        };
        contract.count = count;
    }
}
