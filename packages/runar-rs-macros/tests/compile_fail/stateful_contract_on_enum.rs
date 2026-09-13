use runar_lang_macros::stateful_contract;

#[stateful_contract]
pub enum NotAStruct {
    A,
    B,
}

fn main() {}
