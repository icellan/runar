use runar::prelude::*;

#[runar::contract]
struct HashRegistry {
    current_hash: Ripemd160,
}

#[runar::methods(HashRegistry)]
impl HashRegistry {
    #[public]
    fn update(&mut self, new_hash: Ripemd160) {
        self.current_hash = new_hash;
        assert!(true);
    }
}
