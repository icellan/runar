// F-017 — a Rust local whose name converts to a PARAMETER's Rúnar name.
//
// The .runar.rs surface converts snake_case to camelCase and skips empty
// segments, so `n_` becomes `n` — the parameter. Rust semantics: `n_` is
// n + 1, never equal to n, so the guard is always false. Aliasing the two
// turns it into `n + 1 == n + 1`.
//
// The Ruby tier used to map `n_` to `n_` here (String#split drops trailing
// empty fields), so it compiled a DIFFERENT, non-aliased program from the six
// others. The converged mapping says `n` everywhere, and every tier refuses:
//   identifier collision: 'n' and 'n_' both convert to 'n'; rename one of them
use runar::prelude::*;

#[runar::contract]
struct IdentCollisionRs {
    #[readonly]
    k: Int,
}

impl IdentCollisionRs {
    pub fn unlock(&self, n: Int) {
        let n_ = n + 1;
        assert!(n_ == n);
    }
}
