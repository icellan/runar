use runar::prelude::*;

/// CountdownLoop — Rust DSL port. `step = -1` (R-102).
///
/// A Rust range only ever ascends — `(5..2)` is empty — so the countdown is
/// spelled `(2..6).rev()`, which is `Iterator::rev` over the half-open range
/// and yields 5, 4, 3, 2. Before this fixture the surface had no descending
/// spelling at all (N-130). See CountdownLoop.runar.ts.
#[runar::contract]
struct CountdownLoop {
    #[readonly]
    target: Int,
}

impl CountdownLoop {
    pub fn verify(&self, seed: Int) {
        let mut acc: Int = seed;
        for i in (2..6).rev() {
            acc = acc + i;
        }
        assert!(acc == self.target);
    }
}
