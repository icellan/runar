// F-017 — two Move locals whose names convert to ONE Rúnar name.
//
// The .runar.move surface converts snake_case to camelCase and skips empty
// segments, so `tmp` and `tmp_` both become `tmp`. The guard is always false
// in the source (n + 1 != n + 2); aliased, it compared one binding with
// itself and always passed.
//
// The Java tier used to map `tmp_` to `tmp_` on this surface (String.split
// drops trailing empty fields) and so compiled a different program from the
// six others. The converged mapping says `tmp` everywhere, and every tier
// refuses:
//   identifier collision: 'tmp' and 'tmp_' both convert to 'tmp'; rename one of them
module IdentCollisionMove {
    use runar::types::{Int};

    struct IdentCollisionMove {
        k: Int,
    }

    public fun unlock(contract: &IdentCollisionMove, n: Int) {
        let tmp = n + 1;
        let tmp_ = n + 2;
        assert!(tmp == tmp_, 0);
    }
}
