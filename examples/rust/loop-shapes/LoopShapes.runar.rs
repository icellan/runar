use runar::prelude::*;

/// LoopShapes — Rust DSL port. A NON-ZERO loop start, ascending (R-102).
#[runar::contract]
struct LoopShapes {
    #[readonly]
    target: Int,
}

impl LoopShapes {
    pub fn verify(&self, seed: Int) {
        let mut acc: Int = seed;
        for i in 3..7 {
            acc = acc + i;
        }
        assert!(acc == self.target);
    }
}
