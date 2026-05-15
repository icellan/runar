use runar::prelude::*;

#[runar::contract]
struct BoundedLoop {
    #[readonly]
    expected_sum: Int,
}

impl BoundedLoop {
    pub fn verify(&self, start: Int) {
        let mut sum: Int = 0;
        for i in 0..5 {
            sum = sum + start + i;
        }
        assert!(sum == self.expected_sum);
    }
}
