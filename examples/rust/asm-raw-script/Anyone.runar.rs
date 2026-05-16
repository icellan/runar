// Anyone — minimal `asm` raw-script contract (Rust DSL surface).
use runar::prelude::*;

#[runar::unsafe_contract]
pub struct Anyone {}

impl Anyone {
    pub fn unlock(&self) {
        asm("51", 0, 1);
    }
}
