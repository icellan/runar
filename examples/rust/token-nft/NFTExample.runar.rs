use runar::prelude::*;

#[runar::contract]
pub struct SimpleNFT {
    pub owner: PubKey, // stateful
    #[readonly]
    pub token_id: ByteString,
    #[readonly]
    pub metadata: ByteString,
}

#[runar::methods(SimpleNFT)]
impl SimpleNFT {
    #[public]
    pub fn transfer(&mut self, sig: &Sig, new_owner: PubKey, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        self.add_output(output_satoshis, new_owner);
    }

    #[public]
    pub fn burn(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.owner));
        // No add_output = token destroyed
    }
}
