#[path = "Escrow.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

fn new_escrow() -> Escrow {
    Escrow {
        buyer: mock_pub_key(),
        seller: mock_pub_key(),
        arbiter: mock_pub_key(),
    }
}

#[test] fn test_release_by_seller()  { new_escrow().release_by_seller(&mock_sig()); }
#[test] fn test_release_by_arbiter() { new_escrow().release_by_arbiter(&mock_sig()); }
#[test] fn test_refund_to_buyer()    { new_escrow().refund_to_buyer(&mock_sig()); }
#[test] fn test_refund_by_arbiter()  { new_escrow().refund_by_arbiter(&mock_sig()); }

#[test]
fn test_compile() {
    runar::compile_check(include_str!("Escrow.runar.rs"), "Escrow.runar.rs").unwrap();
}
