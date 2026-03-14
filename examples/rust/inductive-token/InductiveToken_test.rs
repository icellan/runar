use runar::prelude::*;

#[derive(Clone)]
struct ItOutput { satoshis: Bigint, owner: PubKey, balance: Bigint }

struct InductiveToken {
    owner: PubKey,
    balance: Bigint,
    token_id: ByteString,
    outputs: Vec<ItOutput>,
}

impl InductiveToken {
    fn add_output(&mut self, satoshis: Bigint, owner: PubKey, balance: Bigint) {
        self.outputs.push(ItOutput { satoshis, owner, balance });
    }

    fn transfer(&mut self, sig: &Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        assert!(amount > 0);
        assert!(amount <= self.balance);

        self.add_output(output_satoshis, to, amount);
        let change_owner = self.owner.clone();
        self.add_output(output_satoshis, change_owner, self.balance - amount);
    }

    fn send(&mut self, sig: &Sig, to: PubKey, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));

        self.add_output(output_satoshis, to, self.balance);
    }
}

fn alice() -> PubKey { b"alice_pubkey_33bytes_placeholder!".to_vec() }
fn bob() -> PubKey { b"bob___pubkey_33bytes_placeholder!".to_vec() }

fn new_token(owner: PubKey, balance: Bigint) -> InductiveToken {
    InductiveToken { owner, balance, token_id: b"test-token-001".to_vec(), outputs: vec![] }
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
fn test_transfer_exact_balance() {
    let mut c = new_token(alice(), 100);
    c.transfer(&mock_sig(), bob(), 100, 1000);
    assert_eq!(c.outputs.len(), 2);
    assert_eq!(c.outputs[0].balance, 100);
    assert_eq!(c.outputs[1].balance, 0);
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
fn test_compile() {
    runar::compile_check(
        include_str!("InductiveToken.runar.rs"),
        "InductiveToken.runar.rs",
    ).unwrap();
}
