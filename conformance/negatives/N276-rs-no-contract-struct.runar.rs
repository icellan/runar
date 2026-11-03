// N-284: a .runar.rs source with no `#[runar::contract]` struct (just a bare
// `impl Foo { ... }`) must be refused, not silently compiled as a placeholder
// contract. Go, Rust, Zig, Ruby, Python and Java already refused this shape
// with a "no [Rr]únar/Runar contract struct found..." diagnostic; the TS
// reference tier alone built a full contract named 'UnnamedContract' with no
// diagnostic at all (01-parse-rust.ts). The diagnostic wording has also been
// unified across all 7 tiers to "no Rúnar contract struct found in Rust
// source" as part of this fix.
impl Foo {
    pub fn bar(&self, x: i64) {
        assert!(x == 1);
    }
}
