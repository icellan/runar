use runar::prelude::*;

#[runar::contract]
struct Stateful {
    count: Int,
    #[readonly]
    max_count: Int,
}

#[runar::methods(Stateful)]
impl Stateful {
    #[public]
    fn increment(&mut self, amount: Int, tx_preimage: SigHashPreimage) {
        assert!(check_preimage(tx_preimage));
        self.count = self.count + amount;
        assert!(self.count <= self.max_count);
        assert!(hash256(self.get_state_script()) == extract_output_hash(tx_preimage));
    }

    #[public]
    fn reset(&mut self, tx_preimage: SigHashPreimage) {
        assert!(check_preimage(tx_preimage));
        self.count = 0;
        assert!(hash256(self.get_state_script()) == extract_output_hash(tx_preimage));
    }
}
