// F-026: Move spells a hex literal `0x` (lower case); `0XA` is not a Move
// literal, and on this surface a lowercase `0x…` is a Rúnar ByteString. Pre-fix
// the go, python, zig and java tiers read `0XA` as the integer 10 while the
// others refused it. Every tier must refuse with:
//   invalid Move integer literal '0XA'
module T {
    use runar::types::{Int};

    struct T {
        target: Int,
    }

    public fun verify(contract: &T, a: Int) {
        assert!(a > 0XA);
    }
}
