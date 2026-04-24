use runar_lang_macros::{contract, methods};

#[contract]
pub struct Foo {
    pub a: i64,
}

// `#[methods]` expects a single identifier; a string literal is invalid.
#[methods("not an ident")]
impl Foo {
    pub fn bar(&self) -> i64 {
        self.a
    }
}

fn main() {}
