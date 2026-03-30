module Arithmetic {
    use runar::types::{Int};

    struct Arithmetic {
        target: Int,
    }

    public fun verify(contract: &Arithmetic, a: Int, b: Int) {
        let sum = a + b;
        let diff = a - b;
        let prod = a * b;
        let quot = a / b;
        let result = sum + diff + prod + quot;
        assert_eq!(result, contract.target);
    }
}
