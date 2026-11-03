// PropertyShadow — N-016 conformance fixture. A local that shares a field's
// name never captures `self.<field>`.
use runar::prelude::*;

#[runar::contract]
struct PropertyShadow {
    #[readonly]
    target: Int,
    count: Int,
}

impl PropertyShadow {
    pub fn bump(&mut self, n: Int) {
        let target = n + 1;
        assert!(target == self.target);
        let count = n;
        self.count = self.count + count;
        assert!(self.count > count);
    }
}
