// Contract logic tests for FungibleToken.
//
// The contract struct is defined inline (not via #[path]) because the
// add_output output-tracking requires fields and methods that are test
// infrastructure, not part of the Rúnar contract.

use runar::prelude::*;

#[derive(Clone)]
struct FtOutput { satoshis: Bigint, owner: PubKey, balance: Bigint }

struct FungibleToken {
    owner: PubKey,
    balance: Bigint,
    token_id: ByteString,
    outputs: Vec<FtOutput>,
}

impl FungibleToken {
    fn add_output(&mut self, satoshis: Bigint, owner: PubKey, balance: Bigint) {
        self.outputs.push(FtOutput { satoshis, owner, balance });
    }

    fn transfer(&mut self, sig: &Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        assert!(amount > 0);
        assert!(amount <= self.balance);
        let change_owner = self.owner.clone();
        let change_balance = self.balance - amount;
        self.add_output(output_satoshis, to, amount);
        self.add_output(output_satoshis, change_owner, change_balance);
    }

    fn send(&mut self, sig: &Sig, to: PubKey, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        self.add_output(output_satoshis, to, self.balance);
    }

    fn merge(&mut self, sig: &Sig, total_balance: Bigint, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        assert!(total_balance >= self.balance);
        let owner = self.owner.clone();
        self.add_output(output_satoshis, owner, total_balance);
    }
}

fn alice() -> PubKey { b"alice_pubkey_33bytes_placeholder!".to_vec() }
fn bob() -> PubKey { b"bob___pubkey_33bytes_placeholder!".to_vec() }

fn new_token(owner: PubKey, balance: Bigint) -> FungibleToken {
    FungibleToken { owner, balance, token_id: b"test-token-001".to_vec(), outputs: vec![] }
}

#[test]
fn test_transfer() {
    let mut c = new_token(alice(), 100);
    c.transfer(&mock_sig(), bob(), 30, 1000);
    assert_eq!(c.outputs.len(), 2);
    assert_eq!(c.outputs[0].owner, bob());
    assert_eq!(c.outputs[0].balance, 30);
    assert_eq!(c.outputs[1].owner, alice());
    assert_eq!(c.outputs[1].balance, 70);
}

#[test]
#[should_panic]
fn test_transfer_zero_amount_fails() {
    new_token(alice(), 100).transfer(&mock_sig(), bob(), 0, 1000);
}

#[test]
#[should_panic]
fn test_transfer_exceeds_balance_fails() {
    new_token(alice(), 100).transfer(&mock_sig(), bob(), 101, 1000);
}

#[test]
fn test_send() {
    let mut c = new_token(alice(), 100);
    c.send(&mock_sig(), bob(), 1000);
    assert_eq!(c.outputs.len(), 1);
    assert_eq!(c.outputs[0].owner, bob());
    assert_eq!(c.outputs[0].balance, 100);
}

#[test]
fn test_merge() {
    let mut c = new_token(alice(), 50);
    c.merge(&mock_sig(), 200, 1000);
    assert_eq!(c.outputs.len(), 1);
    assert_eq!(c.outputs[0].balance, 200);
}

#[test]
#[should_panic]
fn test_merge_less_than_balance_fails() {
    new_token(alice(), 100).merge(&mock_sig(), 50, 1000);
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("FungibleTokenExample.runar.rs"),
        "FungibleTokenExample.runar.rs",
    ).unwrap();
}
