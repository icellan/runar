module BoundedLoop {
    use runar::types::{Int};

    resource struct BoundedLoop {
        expected_sum: Int,
    }

    public fun verify(contract: &BoundedLoop, start: Int) {
        let sum: Int = 0;
        let i: Int = 0;
        while (i < 5) {
            sum = sum + start + i;
            i = i + 1;
        };
        assert_eq!(sum, contract.expected_sum);
    }
}
