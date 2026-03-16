// Contract logic tests for FungibleToken.
//
// The contract struct is defined inline (not via #[path]) because the
// add_output output-tracking requires fields and methods that are test
// infrastructure, not part of the Runar contract.

use runar::prelude::*;

#[derive(Clone)]
struct FtOutput { satoshis: Bigint, owner: PubKey, balance: Bigint, merge_balance: Bigint }

struct FungibleToken {
    owner: PubKey,
    balance: Bigint,
    merge_balance: Bigint,
    token_id: ByteString,
    tx_preimage: SigHashPreimage,
    outputs: Vec<FtOutput>,
}

impl FungibleToken {
    fn add_output(&mut self, satoshis: Bigint, owner: PubKey, balance: Bigint, merge_balance: Bigint) {
        self.outputs.push(FtOutput { satoshis, owner, balance, merge_balance });
    }

    fn transfer(&mut self, sig: &Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        let total_balance = self.balance + self.merge_balance;
        assert!(amount > 0);
        assert!(amount <= total_balance);
        self.add_output(output_satoshis, to, amount, 0);
        if amount < total_balance {
            let change_owner = self.owner.clone();
            let change_balance = total_balance - amount;
            self.add_output(output_satoshis, change_owner, change_balance, 0);
        }
    }

    fn send(&mut self, sig: &Sig, to: PubKey, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        self.add_output(output_satoshis, to, self.balance + self.merge_balance, 0);
    }

    fn merge(&mut self, sig: &Sig, other_balance: Bigint, all_prevouts: ByteString, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        assert!(other_balance >= 0);
        assert!(hash256(&all_prevouts) == extract_hash_prevouts(&self.tx_preimage));
        let my_outpoint = extract_outpoint(&self.tx_preimage);
        let first_outpoint = substr(&all_prevouts, 0, 36);
        let my_balance = self.balance + self.merge_balance;
        let owner = self.owner.clone();
        if my_outpoint == first_outpoint {
            self.add_output(output_satoshis, owner, my_balance, other_balance);
        } else {
            self.add_output(output_satoshis, owner, other_balance, my_balance);
        }
    }
}

fn alice() -> PubKey { ALICE.pub_key.to_vec() }
fn bob() -> PubKey { BOB.pub_key.to_vec() }
fn alice_sig() -> Sig { ALICE.sign_test_message() }

fn new_token(owner: PubKey, balance: Bigint) -> FungibleToken {
    FungibleToken { owner, balance, merge_balance: 0, token_id: b"test-token-001".to_vec(), tx_preimage: vec![], outputs: vec![] }
}

#[test]
fn test_transfer() {
    let mut c = new_token(alice(), 100);
    c.transfer(&alice_sig(), bob(), 30, 1000);
    assert_eq!(c.outputs.len(), 2);
    assert_eq!(c.outputs[0].owner, bob());
    assert_eq!(c.outputs[0].balance, 30);
    assert_eq!(c.outputs[0].merge_balance, 0);
    assert_eq!(c.outputs[1].owner, alice());
    assert_eq!(c.outputs[1].balance, 70);
    assert_eq!(c.outputs[1].merge_balance, 0);
}

#[test]
#[should_panic]
fn test_transfer_zero_amount_fails() {
    new_token(alice(), 100).transfer(&alice_sig(), bob(), 0, 1000);
}

#[test]
#[should_panic]
fn test_transfer_exceeds_balance_fails() {
    new_token(alice(), 100).transfer(&alice_sig(), bob(), 101, 1000);
}

#[test]
fn test_send() {
    let mut c = new_token(alice(), 100);
    c.send(&alice_sig(), bob(), 1000);
    assert_eq!(c.outputs.len(), 1);
    assert_eq!(c.outputs[0].owner, bob());
    assert_eq!(c.outputs[0].balance, 100);
    assert_eq!(c.outputs[0].merge_balance, 0);
}

#[test]
fn test_merge() {
    let mut c = new_token(alice(), 50);
    // allPrevouts = 72 zero bytes (two 36-byte zero outpoints),
    // consistent with mock extract_hash_prevouts and extract_outpoint.
    let all_prevouts = vec![0u8; 72];
    c.merge(&alice_sig(), 150, all_prevouts, 1000);
    assert_eq!(c.outputs.len(), 1);
    // extract_outpoint returns 36 zero bytes == first outpoint, so we're input 0:
    // balance slot gets my_balance (50), merge_balance slot gets other_balance (150).
    assert_eq!(c.outputs[0].balance, 50);
    assert_eq!(c.outputs[0].merge_balance, 150);
}

#[test]
#[should_panic]
fn test_merge_negative_other_balance_fails() {
    let all_prevouts = vec![0u8; 72];
    new_token(alice(), 100).merge(&alice_sig(), -1, all_prevouts, 1000);
}

#[test]
#[should_panic]
fn test_merge_tampered_prevouts_fails() {
    let tampered_prevouts = vec![0xffu8; 72];
    new_token(alice(), 30).merge(&alice_sig(), 70, tampered_prevouts, 1000);
}

#[test]
fn test_merge_pre_existing_merge_balance() {
    let mut c = FungibleToken {
        owner: alice(), balance: 20, merge_balance: 10,
        token_id: b"test-token-001".to_vec(), tx_preimage: vec![], outputs: vec![],
    };
    let all_prevouts = vec![0u8; 72];
    c.merge(&alice_sig(), 50, all_prevouts, 1000);
    assert_eq!(c.outputs.len(), 1);
    // myBalance = 20 + 10 = 30
    assert_eq!(c.outputs[0].balance, 30);
    assert_eq!(c.outputs[0].merge_balance, 50);
}

#[test]
fn test_transfer_exact_balance() {
    let mut c = new_token(alice(), 100);
    c.transfer(&alice_sig(), bob(), 100, 1000);
    assert_eq!(c.outputs.len(), 1);
    assert_eq!(c.outputs[0].balance, 100);
}

#[test]
fn test_transfer_uses_merge_balance() {
    let mut c = FungibleToken {
        owner: alice(), balance: 60, merge_balance: 40,
        token_id: b"test-token-001".to_vec(), tx_preimage: vec![], outputs: vec![],
    };
    c.transfer(&alice_sig(), bob(), 80, 1000);
    assert_eq!(c.outputs.len(), 2);
    assert_eq!(c.outputs[0].balance, 80);
    assert_eq!(c.outputs[1].balance, 20);
    assert_eq!(c.outputs[0].merge_balance, 0);
    assert_eq!(c.outputs[1].merge_balance, 0);
}

#[test]
fn test_send_uses_merge_balance() {
    let mut c = FungibleToken {
        owner: alice(), balance: 60, merge_balance: 40,
        token_id: b"test-token-001".to_vec(), tx_preimage: vec![], outputs: vec![],
    };
    c.send(&alice_sig(), bob(), 1000);
    assert_eq!(c.outputs.len(), 1);
    assert_eq!(c.outputs[0].balance, 100);
    assert_eq!(c.outputs[0].merge_balance, 0);
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("FungibleTokenExample.runar.rs"),
        "FungibleTokenExample.runar.rs",
    ).unwrap();
}
