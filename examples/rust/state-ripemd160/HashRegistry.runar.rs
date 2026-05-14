use runar::prelude::*;

#[runar::contract]
struct HashRegistry {
    current_hash: Ripemd160,
}

impl HashRegistry {
    pub fn update(&mut self, new_hash: Ripemd160) {
        self.current_hash = new_hash;
        assert!(true);
    }
}
