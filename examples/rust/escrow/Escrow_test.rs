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

#[test] fn test_release() { new_escrow().release(&mock_sig(), &mock_sig()); }
#[test] fn test_refund()  { new_escrow().refund(&mock_sig(), &mock_sig()); }

#[test]
fn test_compile() {
    runar::compile_check(include_str!("Escrow.runar.rs"), "Escrow.runar.rs").unwrap();
}
