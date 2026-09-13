use runar_lang_macros::unsafe_contract;

#[unsafe_contract]
pub enum NotAStruct {
    A,
    B,
}

fn main() {}
