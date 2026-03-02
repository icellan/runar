#[path = "CovenantVault.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

fn new_vault() -> CovenantVault {
    CovenantVault {
        owner: mock_pub_key(),
        recipient: hash160(&mock_pub_key()),
        min_amount: 1000,
    }
}

#[test]
fn test_spend() { new_vault().spend(&mock_sig(), 5000, &mock_preimage()); }

#[test]
fn test_spend_exact_minimum() { new_vault().spend(&mock_sig(), 1000, &mock_preimage()); }

#[test]
#[should_panic]
fn test_spend_below_minimum_fails() { new_vault().spend(&mock_sig(), 999, &mock_preimage()); }

#[test]
#[should_panic]
fn test_spend_zero_amount_fails() { new_vault().spend(&mock_sig(), 0, &mock_preimage()); }

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("CovenantVault.runar.rs"),
        "CovenantVault.runar.rs",
    ).unwrap();
}
