use runar::prelude::*;

#[runar::contract]
struct SimpleNFT {
    owner: PubKey,
    #[readonly]
    token_id: ByteString,
    #[readonly]
    metadata: ByteString,
}

#[runar::methods(SimpleNFT)]
impl SimpleNFT {
    #[public]
    fn transfer(&mut self, sig: Sig, new_owner: PubKey, output_satoshis: Bigint) {
        assert!(check_sig(sig, self.owner));
        assert!(output_satoshis >= 1);
        self.add_output(output_satoshis, new_owner);
    }

    #[public]
    fn burn(&mut self, sig: Sig) {
        assert!(check_sig(sig, self.owner));
    }
}
