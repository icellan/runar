use runar::prelude::*;

#[runar::contract]
struct MessageBoard {
    message: ByteString,
    #[readonly]
    owner: PubKey,
}

#[runar::methods(MessageBoard)]
impl MessageBoard {
    #[public]
    fn post(&mut self, new_message: ByteString) {
        self.message = new_message;
        assert!(true);
    }

    #[public]
    fn burn(&mut self, sig: Sig) {
        assert!(check_sig(sig, self.owner));
    }
}
