// Contract logic tests for SimpleNFT.
//
// The contract struct is defined inline because add_output output-tracking
// requires test infrastructure not part of the Runar contract.

use runar::prelude::*;

#[derive(Clone)]
struct NftOutput { satoshis: Bigint, owner: PubKey }

struct SimpleNFT {
    owner: PubKey,
    token_id: ByteString,
    metadata: ByteString,
    outputs: Vec<NftOutput>,
}

impl SimpleNFT {
    fn add_output(&mut self, satoshis: Bigint, new_owner: PubKey) {
        self.outputs.push(NftOutput { satoshis, owner: new_owner });
    }

    fn transfer(&mut self, sig: &Sig, new_owner: PubKey, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        self.add_output(output_satoshis, new_owner);
    }

    fn burn(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.owner));
    }
}

fn alice() -> PubKey { ALICE.pub_key.to_vec() }
fn bob() -> PubKey { BOB.pub_key.to_vec() }
fn charlie() -> PubKey { CHARLIE.pub_key.to_vec() }

fn new_nft(owner: PubKey) -> SimpleNFT {
    SimpleNFT {
        owner,
        token_id: b"unique-nft-001".to_vec(),
        metadata: b"ipfs://QmTest".to_vec(),
        outputs: vec![],
    }
}

#[test]
fn test_transfer() {
    let mut c = new_nft(alice());
    c.transfer(&ALICE.sign_test_message(), bob(), 1000);
    assert_eq!(c.outputs.len(), 1);
    assert_eq!(c.outputs[0].owner, bob());
}

#[test]
fn test_transfer_chain() {
    let mut c = new_nft(alice());
    c.transfer(&ALICE.sign_test_message(), bob(), 1000);
    c.owner = bob();
    c.outputs.clear();
    c.transfer(&BOB.sign_test_message(), charlie(), 1000);
    assert_eq!(c.outputs[0].owner, charlie());
}

#[test]
fn test_burn() {
    let c = new_nft(alice());
    c.burn(&ALICE.sign_test_message());
    assert_eq!(c.outputs.len(), 0);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("NFTExample.runar.rs"), "NFTExample.runar.rs").unwrap();
}
