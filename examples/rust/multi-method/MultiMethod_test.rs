// N-122: MultiMethod.runar.rs used a private (non-`pub`) struct and called
// `check_sig(sig, self.owner)` by value — neither accessible nor type-correct
// from a native `#[path] mod contract;` test. `pub struct` / `pub` fields and
// `check_sig(&sig, &self.owner)` are both inert to the Rúnar frontend:
// `parser_rustmacro.rs` strips a leading `pub` before `struct`/fields and a
// leading `&` on a call argument unconditionally (same pattern token-ft's
// `FungibleTokenExample.runar.rs` already uses), so neither changes the
// parsed AST or moves the compiled IR/hex goldens. This test now runs the
// real contract instead of only the Rúnar frontend.

#[path = "MultiMethod.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

fn new_multi_method() -> MultiMethod {
    MultiMethod { owner: ALICE.pub_key.to_vec(), backup: BOB.pub_key.to_vec() }
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("MultiMethod.runar.rs"), "MultiMethod.runar.rs").unwrap();
}

// The two public methods are separate spending paths bound to DIFFERENT
// keys. Crossing them is the failure that costs money, so each key is tried
// against both paths.
#[test]
fn spend_with_owner_accepts_only_the_owner_key() {
    let alice_sig = ALICE.sign_test_message();
    new_multi_method().spend_with_owner(alice_sig, 6);
}

#[test]
#[should_panic(expected = "check_sig(&sig, &self.owner)")]
fn spend_with_owner_rejects_the_backup_key() {
    let backup_sig = BOB.sign_test_message();
    new_multi_method().spend_with_owner(backup_sig, 6);
}

#[test]
fn spend_with_backup_accepts_only_the_backup_key() {
    let backup_sig = BOB.sign_test_message();
    new_multi_method().spend_with_backup(backup_sig);
}

#[test]
#[should_panic(expected = "check_sig(&sig, &self.backup)")]
fn spend_with_backup_rejects_the_owner_key() {
    let owner_sig = ALICE.sign_test_message();
    new_multi_method().spend_with_backup(owner_sig);
}

// `spend_with_owner` inlines the private helper `compute_threshold(a, b) = a
// * b + 1` and asserts the result exceeds 10. amount=6 gives 13 (accept) and
// amount=4 gives 9 (refuse); amount=5 gives exactly 11, and 4 is the largest
// amount that refuses -- so the pair pins both the formula and the strict
// `>`. The private helper itself is not reachable from this test file (it is
// private to the `contract` module), so it is pinned only through the public
// entry point it feeds.
#[test]
fn inlined_helper_accepts_above_the_threshold() {
    let sig = ALICE.sign_test_message();
    for amount in [5, 6, 100] {
        new_multi_method().spend_with_owner(sig.clone(), amount);
    }
}

#[test]
#[should_panic(expected = "threshold > 10")]
fn inlined_helper_rejects_at_the_threshold_boundary() {
    let sig = ALICE.sign_test_message();
    new_multi_method().spend_with_owner(sig, 4);
}
