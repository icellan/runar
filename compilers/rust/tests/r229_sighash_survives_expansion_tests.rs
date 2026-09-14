//! R-229 (GK-GAP-008): the fixed-array expansion pass must not drop a method's
//! `@sighash` directive.
//!
//! The pass rebuilds method nodes while rewriting `this.arr[i]` reads, and a
//! rebuild that lists fields explicitly loses whatever it forgets to list.
//! `sighash_type` is the field that costs money when it goes: validate has
//! already ACCEPTED the directive by the time this pass runs, so losing it
//! silently reverts the method to ALL|FORKID and commits a different signature
//! hash than the author declared.
//!
//! This is not hypothetical in this repository. R-025/R-026 fixed exactly that
//! class of drop, and N-086 found four more fields going the same way in the Zig
//! port. The TS, Python and Zig tiers each assert it; rust, go, ruby and java did
//! not. This is the Rust half.

use runar_compiler_rust::frontend::expand_fixed_arrays::expand_fixed_arrays;
use runar_compiler_rust::frontend::parser::parse_source;

const SRC: &str = r#"
class Boardy extends StatefulSmartContract {
  board: FixedArray<bigint, 3>;
  n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  /** @sighash SINGLE|FORKID */
  public bump(): void {
    this.addOutput(1000n, this.board[0], this.board[1], this.board[2], this.n);
  }
}
"#;

#[test]
fn sighash_type_survives_fixed_array_expansion() {
    let parsed = parse_source(SRC, Some("Boardy.runar.ts"));
    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
    let contract = parsed.contract.expect("contract");

    let before = contract
        .methods
        .iter()
        .find(|m| m.name == "bump")
        .expect("method bump");
    assert_eq!(
        before.sighash_type,
        Some(0x43),
        "the directive did not reach the AST — this test would be vacuous"
    );

    let result = expand_fixed_arrays(&contract);
    assert!(result.errors.is_empty(), "{:?}", result.errors);

    // The pass must have actually expanded something, or the assertion below is
    // about a method nothing touched.
    assert!(
        result.contract.properties.len() >= 3,
        "expansion did not expand: {:?}",
        result
            .contract
            .properties
            .iter()
            .map(|p| &p.name)
            .collect::<Vec<_>>()
    );

    let after = result
        .contract
        .methods
        .iter()
        .find(|m| m.name == "bump")
        .expect("bump vanished during expansion");
    assert_eq!(
        after.sighash_type,
        Some(0x43),
        "expansion dropped sighash_type — the method silently reverts to ALL|FORKID"
    );
}
