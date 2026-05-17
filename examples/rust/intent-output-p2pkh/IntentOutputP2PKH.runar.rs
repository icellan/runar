use runar::prelude::*;

/// IntentOutputP2PKH -- exercises the `requireOutputP2PKH` intent
/// intrinsic. Asserts that output 0 of the spending transaction is a
/// standard P2PKH output paying exactly `bondAmount` satoshis to
/// `bondPKH`.
///
/// Note: the property `bondPKH` and the builtin `requireOutputP2PKH`
/// are spelled in camelCase here (rather than the usual Rust
/// snake_case) because the all-caps `PKH` token does not round-trip
/// through the naive snake_case <-> camelCase transform shared across
/// the cross-tier Rust parsers. Writing them in their canonical
/// camelCase form avoids the lossy conversion and keeps the AST
/// byte-identical to the Go-source AST after the Go parser lowercases
/// the leading char of `BondPKH` / `RequireOutputP2PKH`.
#[runar::contract]
pub struct IntentOutputP2PKH {
    #[readonly]
    pub bondPKH: ByteString,
    #[readonly]
    pub bondAmount: Bigint,
    pub count: Bigint,
}

impl IntentOutputP2PKH {
    pub fn payBond(&mut self) {
        requireOutputP2PKH(0, self.bondPKH, self.bondAmount);
        self.count = self.count + 1;
    }
}
