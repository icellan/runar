// ParamShadowBranchArm — N-007 conformance fixture. The parameter `count`
// shares the field's name; inside the `if` arm it is still the parameter.
use runar::prelude::*;

#[runar::contract]
struct ParamShadowBranchArm {
    count: Int,
}

impl ParamShadowBranchArm {
    pub fn set(&mut self, count: Int, flag: bool) {
        if flag {
            assert!(count == 5);
        }
        self.count = count;
    }
}
